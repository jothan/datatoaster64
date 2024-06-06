#![no_std]
extern crate no_std_compat as std;

use std::prelude::v1::*;

use std::num::NonZeroU64;
use std::ops::Range;
use std::sync::Arc;

use bytemuck::Zeroable;
use directory::{DirEntry, DirEntryBlock};
use filehandle::{OpenCounter, RawFileHandle};
use snafu::prelude::*;
use spin::lock_api::Mutex;

use datatoaster_traits::{BlockAccess, BlockIndex, Error as BlockError};

pub mod bitmap;
pub mod directory;
pub mod filehandle;
pub mod inode;
pub mod superblock;

use bitmap::{BitmapAllocator, BitmapBitIndex};
use inode::{
    Inode, InodeAllocator, InodeHandle, InodeIndex, InodeType, RawInodeBlock, INODES_PER_BLOCK,
    ROOT_DIRECTORY_INODE,
};
use superblock::SuperBlock;

pub const BLOCK_SIZE: usize = 4096;

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
    #[snafu(display("Block device error {e}"))]
    Block { e: BlockError },
}

impl From<BlockError> for Error {
    fn from(e: BlockError) -> Self {
        Error::Block { e }
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

    pub(crate) fn raw_file_open(
        self: Arc<Self>,
        inode_index: InodeIndex,
    ) -> Result<RawFileHandle<D>, Error> {
        self.open_counter.lock().increment(inode_index)?;
        let inode = self.inodes.get_handle(inode_index, &self.device)?;
        Ok(RawFileHandle::new(self, inode_index, inode))
    }

    pub(crate) fn raw_file_close(
        &self,
        inode: InodeHandle,
        inode_index: InodeIndex,
    ) -> Result<(), Error> {
        let mut open_counter = self.open_counter.lock();
        let still_open = open_counter.decrement(inode_index)?.is_some();

        if !still_open {
            let mut inode = inode.write();
            if inode.nlink == 0 {
                self.inodes
                    .free(&mut inode, inode_index, &self.alloc, &self.device)?;
            }
        }

        Ok(())
    }

    pub(crate) fn alloc_data(&self, inode_index: InodeIndex) -> Result<DataBlockIndex, Error> {
        let block = self.alloc.lock().alloc(&self.device)?;
        self.inodes.dirty_inode_block(inode_index);
        Ok(block)
    }
}

pub struct Filesystem<D>(Arc<FilesystemInner<D>>);

impl<D: BlockAccess<BLOCK_SIZE>> Filesystem<D> {
    pub fn open(device: D) -> Result<Self, Error> {
        Ok(Filesystem(Arc::new(FilesystemInner::new(device)?)))
    }

    pub fn sync(&self) -> Result<(), Error> {
        self.0.sync()
    }

    pub fn format(device: &D) -> Result<(), Error> {
        let total_blocks = device.device_size()?;
        let layout = DeviceLayout::new(total_blocks)?;

        const ZERO_BLOCK: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];

        // Wipe all metadata
        for block_idx in 0..layout.bitmap_blocks.end.0 {
            device.write(BlockIndex(block_idx), &ZERO_BLOCK)?;
        }

        let mut alloc = BitmapAllocator::new(&layout);

        // Create the root directory contents
        let root_dir_data = alloc.alloc(device)?;
        alloc.sync(device)?;

        let root_dir_contents =
            DirEntryBlock::new_empty(ROOT_DIRECTORY_INODE, ROOT_DIRECTORY_INODE);
        device.write(
            root_dir_data.into(),
            bytemuck::bytes_of(&root_dir_contents).try_into().unwrap(),
        )?;

        // Create the root directory inode
        let mut root_inode = Inode::zeroed();
        root_inode.kind = InodeType::Directory as _;
        root_inode.nlink = 2;
        root_inode.size = (std::mem::size_of::<DirEntry>() * 2).try_into().unwrap();
        root_inode.mode = 0x1ed; // 755 octal
        root_inode.direct_blocks[0] = Some(root_dir_data);

        let mut root_inode_block = RawInodeBlock::zeroed();
        root_inode_block.0[0] = root_inode;
        device.write(
            layout.inode_blocks.start,
            bytemuck::bytes_of(&root_inode_block).try_into().unwrap(),
        )?;

        // Create the superblock
        let sup = SuperBlock::new(ROOT_DIRECTORY_INODE);
        sup.write(device)?;

        Ok(())
    }
}
