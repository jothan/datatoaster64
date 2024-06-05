#![no_std]
#![feature(array_chunks)]
extern crate no_std_compat as std;

use std::prelude::v1::*;

use std::ops::Range;
use std::sync::Arc;

use spin::lock_api::Mutex;

use datatoaster_traits::{BlockAccess, BlockIndex, Error as BlockError};

pub mod bitmap;
use bitmap::{BitmapAllocator, BitmapBitIndex};

pub const BLOCK_SIZE: usize = 4096;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    General,
    Invalid,
    DeviceBounds,
    OutOfSpace,
    Block(BlockError),
}

impl From<BlockError> for Error {
    fn from(value: BlockError) -> Self {
        Error::Block(value)
    }
}

/// Index into the user data region
#[derive(Clone, Copy, Ord, PartialOrd, PartialEq, Eq, Debug)]
pub struct DataBlockIndex(u64);

impl DataBlockIndex {
    fn into_bitmap_bit_index(self, layout: &DeviceLayout) -> BitmapBitIndex {
        BitmapBitIndex(self.0 - layout.data_blocks.start.0)
    }
}

impl From<DataBlockIndex> for BlockIndex {
    fn from(value: DataBlockIndex) -> BlockIndex {
        BlockIndex(value.0)
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
    const INODES_PER_BLOCK: u64 = 128; // TODO: only an approximation
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
        let nb_inode_blocks = nb_inodes.div_ceil(Self::INODES_PER_BLOCK);
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
}

struct FilesystemInner<D> {
    alloc: Mutex<BitmapAllocator>,
    device: D,
}

impl<D: BlockAccess<BLOCK_SIZE>> FilesystemInner<D> {
    pub fn new(device: D) -> Result<Self, Error> {
        let total_blocks = device.device_size()?;
        let layout = DeviceLayout::new(total_blocks)?;

        let alloc = Mutex::new(BitmapAllocator::new(&device, &layout));
        Ok(Self { alloc, device })
    }
}

pub struct Filesystem<D>(Arc<FilesystemInner<D>>);

impl<D: BlockAccess<BLOCK_SIZE>> Filesystem<D> {
    pub fn new(device: D) -> Result<Self, Error> {
        Ok(Filesystem(Arc::new(FilesystemInner::new(device)?)))
    }
}
