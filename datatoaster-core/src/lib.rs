#![no_std]
#![feature(new_uninit, maybe_uninit_as_bytes, maybe_uninit_uninit_array_transpose)]
extern crate no_std_compat as std;

use std::prelude::v1::*;

use std::num::NonZeroU64;
use std::ops::Range;
use std::sync::Arc;

use bytemuck::Zeroable;
use filehandle::{OpenCounter, RawFileHandle};
use inode::{InodeHolder, InodeHolderMut, InodeReference};
use snafu::prelude::*;
use spin::lock_api::Mutex;

use datatoaster_traits::{BlockAccess, BlockIndex, Error as BlockError};

mod bitmap;
mod buffers;
mod directory;
mod filehandle;
mod inode;
mod superblock;

use crate::bitmap::{BitmapAllocator, BitmapBitIndex};
use crate::directory::{DirEntryBlock, DiskDirEntry};
use crate::inode::{Inode, InodeAllocator, RawInodeBlock, INODES_PER_BLOCK, ROOT_DIRECTORY_INODE};
use superblock::SuperBlock;

pub const BLOCK_SIZE: usize = 4096;
pub use directory::{DirEntry, MAX_FILENAME_LENGTH};
pub use filehandle::{DirectoryHandle, FileHandle};
pub use inode::{InodeType, Stat, ROOT_INODE};

#[derive(Debug, PartialEq, Eq, Snafu)]
pub enum Error {
    #[snafu(display("General FS failure"))]
    General,
    #[snafu(display("Invalid FS condition"))]
    Invalid,
    #[snafu(display("Invalid FS device bounds"))]
    DeviceBounds,
    #[snafu(display("No more space in FS"))]
    OutOfSpace,
    #[snafu(display("Invalid superblock"))]
    SuperBlock,
    #[snafu(display("Not a directory"))]
    NotDirectory,
    #[snafu(display("File or directory not found"))]
    NotFound,
    #[snafu(display("Name too long"))]
    NameTooLong,
    #[snafu(display("The file or directory already exists"))]
    AlreadyExists,
    #[snafu(display("A directory was found when expecting a file"))]
    IsDirectory,
    #[snafu(display("Block device error {e}"))]
    Block { e: BlockError },
}

impl From<BlockError> for Error {
    fn from(e: BlockError) -> Self {
        Error::Block { e }
    }
}

impl From<Error> for std::ffi::c_int {
    fn from(value: Error) -> Self {
        match value {
            Error::OutOfSpace => libc::ENOSPC,
            Error::NameTooLong => libc::ENAMETOOLONG,
            Error::NotDirectory => libc::ENOTDIR,
            Error::Block { e: _ } | Error::DeviceBounds => libc::EIO,
            Error::Invalid => libc::EINVAL,
            Error::NotFound => libc::ENOENT,
            Error::AlreadyExists => libc::EEXIST,
            Error::IsDirectory => libc::EISDIR,
            _ => libc::ENOSYS,
        }
    }
}

/// Index into the user data region
#[derive(Clone, Copy, Ord, PartialOrd, PartialEq, Eq, Debug)]
pub struct DataBlockIndex(NonZeroU64);

unsafe impl bytemuck::ZeroableInOption for DataBlockIndex {}
unsafe impl bytemuck::PodInOption for DataBlockIndex {}

impl DataBlockIndex {
    fn into_bitmap_bit_index(self, layout: &DeviceLayout) -> BitmapBitIndex {
        BitmapBitIndex(self.0.get() - layout.data_blocks.start.0)
    }
}

impl From<DataBlockIndex> for BlockIndex {
    fn from(value: DataBlockIndex) -> BlockIndex {
        BlockIndex(value.0.get())
    }
}

/// Disk data layout:
/// superblock
/// inode blocks
/// bitmap blocks
/// data blocks

#[derive(Clone, Debug)]
pub struct DeviceLayout {
    pub nb_inodes: u64,
    pub inode_blocks: Range<BlockIndex>,
    pub bitmap_blocks: Range<BlockIndex>,
    pub data_blocks: Range<BlockIndex>,
}

impl DeviceLayout {
    const MIN_BLOCKS: BlockIndex = BlockIndex(64);
    const INODE_RATIO: u64 = 16384; // bytes per inode

    fn new(total_blocks: BlockIndex) -> Result<Self, Error> {
        if total_blocks < Self::MIN_BLOCKS {
            return Err(Error::DeviceBounds);
        }
        // Substract superblock.
        let nb_data_and_metadata_blocks = total_blocks.0 - 1;
        let device_bytes = total_blocks
            .0
            .checked_mul(BLOCK_SIZE.try_into().unwrap())
            .ok_or(Error::DeviceBounds)?;
        let nb_inodes = device_bytes / Self::INODE_RATIO;
        let nb_inode_blocks = nb_inodes.div_ceil(INODES_PER_BLOCK.try_into().unwrap());
        // Use all the space in the inode blocks
        let nb_inodes = nb_inode_blocks * (u64::try_from(INODES_PER_BLOCK).unwrap());

        let nb_data_and_bitmap_blocks = nb_data_and_metadata_blocks
            .checked_sub(nb_inode_blocks)
            .ok_or(Error::DeviceBounds)?;
        let nb_bitmap_blocks: u64 =
            nb_data_and_bitmap_blocks.div_ceil(u64::try_from(BLOCK_SIZE).unwrap() * 8 - 1);
        let nb_data_blocks = nb_data_and_bitmap_blocks - nb_bitmap_blocks;

        let inode_blocks = BlockIndex(1)..BlockIndex(1 + nb_inode_blocks);
        let bitmap_blocks =
            BlockIndex(inode_blocks.end.0)..BlockIndex(inode_blocks.end.0 + nb_bitmap_blocks);
        let data_blocks =
            BlockIndex(bitmap_blocks.end.0)..BlockIndex(bitmap_blocks.end.0 + nb_data_blocks);

        assert!(data_blocks.end == total_blocks);

        Ok(Self {
            nb_inodes,
            inode_blocks,
            bitmap_blocks,
            data_blocks,
        })
    }

    pub fn from_device<D: BlockAccess<BLOCK_SIZE>>(device: &D) -> Result<Self, Error> {
        let blocks = device.device_size()?;
        Self::new(blocks)
    }

    pub fn nb_inodes(&self) -> u64 {
        (self.inode_blocks.end.0 - self.inode_blocks.start.0)
            * u64::try_from(INODES_PER_BLOCK).unwrap()
    }
}

pub(crate) struct FilesystemInner<D> {
    alloc: Mutex<BitmapAllocator>,
    inodes: InodeAllocator,
    open_counter: Mutex<OpenCounter>,
    device: D,
}

impl<D: BlockAccess<BLOCK_SIZE>> FilesystemInner<D> {
    pub fn new(device: D) -> Result<Self, Error> {
        let total_blocks = device.device_size()?;
        let layout = DeviceLayout::new(total_blocks)?;

        let alloc = Mutex::new(BitmapAllocator::new(&layout));
        let inodes = InodeAllocator::new(&layout);

        Ok(Self {
            alloc,
            inodes,
            open_counter: Mutex::new(OpenCounter::default()),
            device,
        })
    }

    pub(crate) fn sync(&self) -> Result<(), Error> {
        let mut alloc = self.alloc.lock();

        self.inodes.sync(&self.device)?;
        alloc.sync(&self.device)?;

        Ok(())
    }
}

pub struct Filesystem<D>(Arc<FilesystemInner<D>>);

impl<D: BlockAccess<BLOCK_SIZE>> Filesystem<D> {
    pub fn mount(device: D) -> Result<Self, Error> {
        SuperBlock::read(&device)?;

        Ok(Filesystem(Arc::new(FilesystemInner::new(device)?)))
    }

    pub fn sync(&self) -> Result<(), Error> {
        self.0.sync()
    }

    pub fn stat(&self, inode_index: u64) -> Result<Stat, Error> {
        let inode_index = self.0.inodes.inode_index_from_u64(inode_index)?;
        let inode = self.0.inodes.get_handle(inode_index, &self.0.device)?;
        let guard = inode.read();

        Stat::new(guard.index(), &guard)
    }

    pub fn opendir(&self, inode_index: u64) -> Result<DirectoryHandle<D>, Error> {
        let inode_index = self.0.inodes.inode_index_from_u64(inode_index)?;
        let raw = RawFileHandle::open(inode_index, self.0.clone())?;

        let inode = raw.inode().unwrap();
        let guard = inode.1.read();

        if InodeType::try_from(guard.kind)? != InodeType::Directory {
            return Err(Error::NotDirectory);
        }
        drop(guard);
        Ok(DirectoryHandle(raw))
    }

    pub fn open(&self, inode_index: u64) -> Result<FileHandle<D>, Error> {
        let inode_index = self.0.inodes.inode_index_from_u64(inode_index)?;
        let raw = RawFileHandle::open(inode_index, self.0.clone())?;

        let inode = raw.inode().unwrap();
        let guard = inode.1.read();

        if InodeType::try_from(guard.kind)? != InodeType::File {
            return Err(Error::IsDirectory);
        }
        drop(guard);
        Ok(FileHandle(raw))
    }

    pub fn lookup(&self, parent_inode: u64, name: &[u8]) -> Result<Stat, Error> {
        if name.len() > MAX_FILENAME_LENGTH {
            return Err(Error::NameTooLong);
        }

        let parent_inode = self.0.inodes.inode_index_from_u64(parent_inode)?;
        let inode = self.0.inodes.get_handle(parent_inode, &self.0.device)?;
        let guard = inode.read();

        let dir_inode = guard.as_dir()?;
        let (_, offset, block) = dir_inode.lookup(&self.0, name)?;
        let dirent = &block.0[offset];

        self.stat(dirent.inode().unwrap().get())
    }

    pub fn create(
        &self,
        parent_inode: u64,
        name: &[u8],
        mode: u32,
    ) -> Result<(FileHandle<D>, Stat), Error> {
        if name.len() > MAX_FILENAME_LENGTH {
            return Err(Error::NameTooLong);
        }

        let parent_inode = self.0.inodes.inode_index_from_u64(parent_inode)?;
        let inode = self.0.inodes.get_handle(parent_inode, &self.0.device)?;
        let guard = inode.upgradable_read();

        let dir_inode = guard.as_dir()?;

        if dir_inode.is_full() {
            return Err(Error::OutOfSpace);
        }

        match dir_inode.lookup(&self.0, name) {
            Ok(_) => return Err(Error::AlreadyExists),
            Err(Error::NotFound) => (),
            Err(e) => return Err(e),
        };

        let new_inode_value = Inode::new_file(mode as u16 /* lossy !*/);
        let new_inode = self.0.inodes.alloc(self.0.clone(), &new_inode_value)?;
        let new_dirent = DiskDirEntry::new_file(new_inode.index(), name)?;
        let stat = Stat::new(new_inode.index(), &new_inode_value)?;

        let mut guard = guard.upgrade(self.0.clone());
        let mut dir_inode = guard.as_dir_mut()?;

        dir_inode.insert_dirent(&self.0, &new_dirent)?;
        dir_inode.size = dir_inode.size.checked_add(1).unwrap();

        let fh = self.open(new_inode.index().into())?;
        Ok((fh, stat))
    }

    pub fn unlink(&self, parent_inode: u64, name: &[u8]) -> Result<(), Error> {
        if name.len() > MAX_FILENAME_LENGTH {
            return Err(Error::NameTooLong);
        }

        let parent_inode = self.0.inodes.inode_index_from_u64(parent_inode)?;
        let inode = self.0.inodes.get_handle(parent_inode, &self.0.device)?;
        let guard = inode.upgradable_read();

        let dir_inode = guard.as_dir()?;

        let (block_num, offset, mut block) = dir_inode.lookup(&self.0, name)?;
        let dirent = &block.0[offset];
        if dirent.kind() == Some(InodeType::Directory) {
            return Err(Error::IsDirectory);
        }

        let child_index = self
            .0
            .inodes
            .inode_index_from_u64(dirent.inode().map(NonZeroU64::get).unwrap_or(0))?;
        let child_inode = self.0.inodes.get_handle(child_index, &self.0.device)?;
        let mut guard = guard.upgrade(self.0.clone());
        let mut dir_inode = guard.as_dir_mut()?;

        let open_counter = self.0.open_counter.lock();
        let still_open = open_counter.is_open(child_inode.index());
        let mut child_guard = child_inode.write(self.0.clone());
        drop(open_counter);

        if child_guard.nlink == 0 {
            log::error!("Double unlink on {child_index:?}");
            return Err(Error::Invalid);
        }

        if dir_inode.size == 0 {
            log::error!("Invalid directory size in {parent_inode:?}");
            return Err(Error::Invalid);
        }

        dir_inode.size -= 1;
        child_guard.nlink -= 1;

        block.0[offset] = DiskDirEntry::zeroed();
        dir_inode.write_block(&self.0, block_num, bytemuck::must_cast_ref(&*block))?;

        if child_guard.nlink == 0 && !still_open {
            self.0
                .inodes
                .free(&mut child_guard, &self.0.alloc, &self.0.device)?;
        } else if child_guard.nlink == 0 {
            log::info!(
                "{:?} was unlinked and will be freed on close",
                dir_inode.index()
            );
        } else {
            log::info!(
                "{:?} unlink, still {} reference counts",
                dir_inode.index(),
                child_guard.nlink
            );
        }

        Ok(())
    }

    pub fn format(device: &D) -> Result<(), Error> {
        let total_blocks = device.device_size()?;
        let layout = DeviceLayout::new(total_blocks)?;

        // Wipe all metadata
        for block_idx in 0..layout.bitmap_blocks.end.0 {
            device.write(BlockIndex(block_idx), &[0; BLOCK_SIZE])?;
        }

        let mut alloc = BitmapAllocator::new(&layout);

        // Create the root directory contents
        let root_dir_data = alloc.alloc(device)?;
        alloc.sync(device)?;

        let root_dir_contents =
            DirEntryBlock::new_first_block(ROOT_DIRECTORY_INODE, ROOT_DIRECTORY_INODE);
        device.write(
            root_dir_data.into(),
            bytemuck::must_cast_ref(&root_dir_contents),
        )?;

        // Create the root directory inode
        let mut root_inode = Inode::zeroed();
        root_inode.kind = InodeType::Directory as _;
        root_inode.nlink = 2;
        root_inode.size = 2;
        root_inode.perm = 0x1ed; // 755 octal
        root_inode.direct_blocks[0] = Some(root_dir_data);

        let mut root_inode_block = RawInodeBlock::zeroed();
        root_inode_block.0[0] = root_inode;
        device.write(
            layout.inode_blocks.start,
            bytemuck::must_cast_ref(&root_inode_block),
        )?;

        // Create the superblock
        let sup = SuperBlock::new(ROOT_DIRECTORY_INODE);
        sup.write(device)?;

        Ok(())
    }
}
