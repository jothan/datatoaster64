#![no_std]
#![feature(new_uninit)]
extern crate no_std_compat as std;

use std::prelude::v1::*;

use std::num::NonZeroU64;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

use bytemuck::Zeroable;

use filehandle::{OpenCounter, RawFileHandle};
use inode::{
    FileBlockIndex, InodeHandle, InodeHandleUpgradableRead, InodeHandleWrite, InodeHolder,
    InodeReference,
};
use layout::DeviceLayout;
use snafu::prelude::*;
use spin::lock_api::Mutex;

use datatoaster_traits::{BlockAccess, BlockIndex, Error as BlockError};

mod bitmap;
mod buffers;
mod directory;
mod filehandle;
mod inode;
mod layout;
mod superblock;

use crate::bitmap::{BitmapAllocator, BitmapBitIndex};
use crate::directory::{DirEntryBlock, DiskDirEntry};
use crate::inode::{Inode, InodeAllocator, RawInodeBlock, ROOT_DIRECTORY_INODE};
use superblock::SuperBlock;

pub const BLOCK_SIZE: usize = 4096;
pub use directory::{DirEntry, MAX_FILENAME_LENGTH};
pub use filehandle::{DirectoryHandle, FileHandle};
pub use inode::{InodeType, Stat, ROOT_INODE};

#[derive(Debug, PartialEq, Eq, Snafu)]
pub enum Error {
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
    #[snafu(display("Something other that a directory was found"))]
    IsNotDirectory,
    #[snafu(display("Directory not empty"))]
    NotEmpty,
    #[snafu(display("Deadlock"))]
    Deadlock,
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
            Error::IsNotDirectory => libc::ENOTDIR,
            Error::NotEmpty => libc::ENOTEMPTY,
            Error::Deadlock => libc::EDEADLK,
            Error::SuperBlock => libc::ENODEV,
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

pub(crate) struct FilesystemInner<D> {
    alloc: Mutex<BitmapAllocator>,
    inodes: InodeAllocator,
    open_counter: Mutex<OpenCounter>,
    time_source: &'static (dyn Fn() -> Duration + Sync),
    device: D,
}

impl<D: BlockAccess<BLOCK_SIZE>> FilesystemInner<D> {
    pub fn new(
        device: D,
        time_source: &'static (dyn Fn() -> Duration + Sync),
    ) -> Result<Self, Error> {
        let sb = SuperBlock::read(&device)?;

        let total_blocks = device.device_size()?;
        let layout = DeviceLayout::new(total_blocks)?;

        let disk_layout = DeviceLayout::from_superblock(&sb);

        log::info!("{disk_layout:?}");

        if sb.device_blocks != total_blocks.0 || layout != disk_layout {
            return Err(Error::SuperBlock);
        }

        let alloc = Mutex::new(BitmapAllocator::new(&layout));
        let inodes = InodeAllocator::new(&layout);

        Ok(Self {
            alloc,
            inodes,
            open_counter: Mutex::new(OpenCounter::default()),
            device,
            time_source,
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
    pub fn mount(
        device: D,
        time_source: &'static (dyn Fn() -> Duration + Sync),
    ) -> Result<Self, Error> {
        Ok(Filesystem(Arc::new(FilesystemInner::new(
            device,
            time_source,
        )?)))
    }

    pub fn sync(&self) -> Result<(), Error> {
        self.0.sync()
    }

    pub fn stat(&self, inode_index: u64) -> Result<Stat, Error> {
        let inode = self.0.inodes.get_handle_u64(inode_index, &self.0.device)?;
        let guard = inode.read();

        Stat::new(guard.index(), &guard)
    }

    pub fn opendir(&self, inode_index: u64) -> Result<DirectoryHandle<D>, Error> {
        let inode = self.0.inodes.get_handle_u64(inode_index, &self.0.device)?;
        let guard = inode.read();
        log::error!("inode: {:?}", guard.deref());
        if InodeType::try_from(guard.kind)? != InodeType::Directory {
            return Err(Error::NotDirectory);
        }
        let raw = RawFileHandle::open(guard.index(), self.0.clone())?;
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
        DiskDirEntry::check_name(name)?;

        let inode = self.0.inodes.get_handle_u64(parent_inode, &self.0.device)?;
        let guard = inode.read();

        let dir_inode = guard.as_dir()?;
        let (_, offset, block) = dir_inode.lookup(&self.0, name)?;
        let dirent = &block.0[offset];

        self.stat(dirent.inode().unwrap().get())
    }

    fn create_check<H: InodeHolder>(&self, guard: &H, name: &[u8]) -> Result<(), Error> {
        DiskDirEntry::check_name(name)?;

        let dir_inode = guard.as_dir()?;

        if dir_inode.nlink == 0 {
            return Err(Error::NotFound);
        }

        if dir_inode.is_full() {
            return Err(Error::OutOfSpace);
        }

        match dir_inode.lookup(&self.0, name) {
            Ok(_) => Err(Error::AlreadyExists),
            Err(Error::NotFound) => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub fn create(
        &self,
        parent_inode: u64,
        name: &[u8],
        mode: u32,
    ) -> Result<(FileHandle<D>, Stat), Error> {
        let inode = self.0.inodes.get_handle_u64(parent_inode, &self.0.device)?;
        let guard = inode.upgradable_read();

        self.create_check(&guard, name)?;

        let new_inode_value = Inode::new_file(mode as u16 /* lossy !*/);
        let new_inode = self.0.inodes.alloc(self.0.clone(), &new_inode_value)?;
        let new_dirent = DiskDirEntry::new_file(new_inode.index(), name)?;

        let guard = guard.upgrade(self.0.clone());
        let mut dir_inode = guard.into_dir_mut()?;

        dir_inode.insert_dirent(&self.0, &new_dirent)?;
        dir_inode.size = dir_inode.size.checked_add(1).unwrap();
        let mut new_inode_guard = new_inode.write(self.0.clone());
        new_inode_guard.nlink = 1;

        let stat = Stat::new(new_inode.index(), &new_inode_guard)?;
        new_inode_guard.bump_atime();
        new_inode_guard.bump_mtime();
        new_inode_guard.bump_crtime();
        drop(new_inode_guard);

        let fh = self.open(new_inode.index().into())?;
        Ok((fh, stat))
    }

    pub fn mkdir(&self, parent_inode: u64, name: &[u8], mode: u32) -> Result<Stat, Error> {
        let inode = self.0.inodes.get_handle_u64(parent_inode, &self.0.device)?;
        let guard = inode.upgradable_read();

        self.create_check(&guard, name)?;

        let new_inode_value = Inode::new_directory(mode as u16 /* lossy !*/);
        let child_inode = self.0.inodes.alloc(self.0.clone(), &new_inode_value)?;
        let child_dirent = DiskDirEntry::new_directory(child_inode.index(), name)?;

        let parent_guard = guard.upgrade(self.0.clone());
        let mut parent_dir = parent_guard.into_dir_mut()?;

        let mut child_guard = child_inode.write(self.0.clone());

        parent_dir.insert_dirent(&self.0, &child_dirent)?;
        parent_dir.size = parent_dir.size.checked_add(1).unwrap();
        child_guard.nlink += 1;

        let block = DirEntryBlock::new_first_block(child_guard.index(), parent_dir.index());

        child_guard.write_block(
            FileBlockIndex::FIRST,
            bytemuck::must_cast_ref(block.deref()),
        )?;
        child_guard.size = 2;
        child_guard.nlink += 1;
        child_guard.bump_atime();
        child_guard.bump_mtime();
        child_guard.bump_crtime();

        parent_dir.nlink = parent_dir.nlink.checked_add(1).unwrap();

        Stat::new(child_guard.index(), &child_guard)
    }

    pub fn rmdir(&self, parent_inode: u64, name: &[u8]) -> Result<(), Error> {
        DiskDirEntry::check_name(name)?;

        let inode = self.0.inodes.get_handle_u64(parent_inode, &self.0.device)?;
        let parent_guard = inode.write(self.0.clone());
        let mut child_inode = None;

        let precheck = |dirent: &DiskDirEntry| {
            dirent
                .kind()
                .filter(|&t| t != InodeType::Directory)
                .map(|_| Error::IsNotDirectory)
        };

        let (still_open, mut child_guard) =
            self.unlink_from_dir(parent_guard, name, precheck, &mut child_inode)?;

        if child_guard.nlink == 0 {
            return Err(Error::NotFound);
        }

        if child_guard.size > 2 || child_guard.nlink > 2 {
            return Err(Error::NotEmpty);
        }

        if child_guard.size != 2 || child_guard.nlink != 2 {
            log::error!(
                "directory {:?} size and links are not conistent ({}, {})",
                child_guard.index(),
                child_guard.size,
                child_guard.nlink
            );
            return Err(Error::Invalid);
        }

        // Zap "." and ".."
        self.0
            .inodes
            .free_data_blocks(&mut child_guard, &self.0.alloc, &self.0.device)?;
        child_guard.size = 0;
        child_guard.nlink = 0;

        if !still_open {
            self.0
                .inodes
                .free(&mut child_guard, &self.0.alloc, &self.0.device)?;
        }

        Ok(())
    }

    pub fn link(&self, parent_inode: u64, child_inode: u64, name: &[u8]) -> Result<Stat, Error> {
        DiskDirEntry::check_name(name)?;

        let parent_inode = self.0.inodes.get_handle_u64(parent_inode, &self.0.device)?;
        let parent_guard = parent_inode.upgradable_read();

        let child_inode = self.0.inodes.get_handle_u64(child_inode, &self.0.device)?;
        let child_guard = child_inode.upgradable_read();

        if !parent_guard.is_kind(InodeType::Directory)? {
            return Err(Error::IsNotDirectory)?;
        }

        if child_guard.is_kind(InodeType::Directory)? {
            return Err(Error::IsDirectory)?;
        }

        self.create_check(&parent_guard, name)?;

        let parent_guard = parent_guard.upgrade(self.0.clone());
        let mut child_guard = child_guard.upgrade(self.0.clone());

        let mut parent_dir = parent_guard.into_dir_mut()?;

        let dirent = DiskDirEntry::for_inode(&child_guard, name)?;
        parent_dir.insert_dirent(&self.0, &dirent)?;
        child_guard.nlink += 1;

        Stat::new(child_inode.index(), &child_guard)
    }

    pub fn unlink(&self, parent_inode: u64, name: &[u8]) -> Result<(), Error> {
        DiskDirEntry::check_name(name)?;

        let inode = self.0.inodes.get_handle_u64(parent_inode, &self.0.device)?;
        let guard = inode.write(self.0.clone());
        let mut child_inode = None;

        let precheck = |dirent: &DiskDirEntry| {
            dirent
                .kind()
                .filter(|&t| t == InodeType::Directory)
                .map(|_| Error::IsDirectory)
        };

        let (still_open, mut child_guard) =
            self.unlink_from_dir(guard, name, precheck, &mut child_inode)?;

        if child_guard.nlink == 0 {
            log::error!("Double unlink on {:?}", child_guard.index());
            return Err(Error::Invalid);
        }
        child_guard.nlink -= 1;

        if child_guard.nlink == 0 && !still_open {
            self.0
                .inodes
                .free(&mut child_guard, &self.0.alloc, &self.0.device)?;
        } else if child_guard.nlink == 0 {
            log::info!(
                "{:?} was unlinked and will be freed on close",
                child_guard.index()
            );
        } else {
            log::info!(
                "{:?} unlink, still {} reference counts",
                child_guard.index(),
                child_guard.nlink
            );
        }

        Ok(())
    }

    fn unlink_from_dir<'a>(
        &self,
        guard: InodeHandleWrite<D>,
        name: &[u8],
        precheck: impl FnOnce(&DiskDirEntry) -> Option<Error>,
        out_child_handle: &'a mut Option<InodeHandle>,
    ) -> Result<(bool, InodeHandleWrite<'a, D>), Error> {
        let mut dir_inode = guard.into_dir_mut()?;

        let (block_num, offset, mut block) = dir_inode.as_ref().lookup(&self.0, name)?;
        let dirent = &block.0[offset];

        if let Some(error) = precheck(dirent) {
            return Err(error);
        }

        let child_index = dirent.inode().map(NonZeroU64::get).unwrap_or(0);
        let child_inode =
            out_child_handle.insert(self.0.inodes.get_handle_u64(child_index, &self.0.device)?);

        let open_counter = self.0.open_counter.lock();
        let still_open = open_counter.is_open(child_inode.index());
        let child_guard = child_inode.write(self.0.clone());
        drop(open_counter);

        if child_guard.is_kind(InodeType::Directory)? && child_guard.nlink > 2 {
            return Err(Error::NotEmpty);
        }

        if dir_inode.size == 0 {
            log::error!("Invalid directory size in {:?}", dir_inode.index());
            return Err(Error::Invalid);
        }

        block.0[offset] = DiskDirEntry::zeroed();
        dir_inode
            .deref_mut()
            .write_block(block_num, bytemuck::must_cast_ref(&*block))?;

        dir_inode.size -= 1;

        // ".." link to parent
        if child_guard.is_kind(InodeType::Directory)? {
            dir_inode.nlink -= 1;
        }

        Ok((still_open, child_guard))
    }

    fn rename_in_dir(
        &self,
        inode_handle: InodeHandle,
        src_name: &[u8],
        dst_name: &[u8],
    ) -> Result<(), Error> {
        let guard = inode_handle.upgradable_read();

        self.create_check(&guard, dst_name)?;
        let guard = guard.upgrade(self.0.clone());
        let mut dir_inode = guard.into_dir_mut()?;

        let (block_num, offset, mut block) = dir_inode.as_ref().lookup(&self.0, src_name)?;
        block.0[offset].set_name(dst_name)?;
        dir_inode.write_block(block_num, bytemuck::must_cast_ref(block.deref()))?;

        Ok(())
    }

    pub fn rename(
        &self,
        src: u64,
        src_name: &[u8],
        dst: u64,
        dst_name: &[u8],
    ) -> Result<(), Error> {
        DiskDirEntry::check_name(src_name)?;
        DiskDirEntry::check_name(dst_name)?;

        let src_handle = self.0.inodes.get_handle_u64(src, &self.0.device)?;
        if src == dst {
            return self.rename_in_dir(src_handle, src_name, dst_name);
        }

        let dst_handle = self.0.inodes.get_handle_u64(dst, &self.0.device)?;

        // Normally we lock from parent to child, the relationship between src and dst here is not
        // obvious and is dynamic, so this needs a special locking procedure.
        let (src_guard, dst_guard) = InodeHandleUpgradableRead::lock_two(&src_handle, &dst_handle)?;

        self.create_check(&dst_guard, dst_name)?;
        let src_guard = src_guard.upgrade(self.0.clone());

        let mut movee_handle = None;

        let (_, movee_guard) =
            self.unlink_from_dir(src_guard, src_name, |_| None, &mut movee_handle)?;

        let dst_guard = dst_guard.upgrade(self.0.clone());
        let mut dst_dir = dst_guard.into_dir_mut()?;
        let dirent = DiskDirEntry::for_inode(&movee_guard, dst_name)?;
        dst_dir.insert_dirent(&self.0, &dirent)?;

        if movee_guard.is_kind(InodeType::Directory)? {
            dst_dir.nlink += 1;
            let (block_num, offset, mut block) = dst_dir.as_ref().lookup(&self.0, b"..")?;
            block.0[offset].set_inode(dst_dir.index());
            dst_dir.write_block(block_num, bytemuck::must_cast_ref(block.deref()))?;
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
            bytemuck::must_cast_ref(root_dir_contents.deref()),
        )?;

        #[cfg(not(feature = "std"))]
        let now = Duration::new(0, 0).as_nanos();
        #[cfg(feature = "std")]
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        // Create the root directory inode
        let mut root_inode = Inode::zeroed();
        root_inode.kind = InodeType::Directory as _;
        root_inode.nlink = 2;
        root_inode.size = 2;
        root_inode.perm = 0x1ed; // 755 octal
        root_inode.direct_blocks[0] = Some(root_dir_data);
        root_inode.crtime = now;
        root_inode.ctime = now;
        root_inode.mtime = now;
        root_inode.atime = now;

        let mut root_inode_block = RawInodeBlock::zeroed();
        root_inode_block.0[0] = root_inode;
        device.write(
            layout.inode_blocks.start,
            bytemuck::must_cast_ref(&root_inode_block),
        )?;

        // Create the superblock
        let sup = SuperBlock::new(ROOT_DIRECTORY_INODE, &layout);
        sup.write(device)?;

        Ok(())
    }
}
