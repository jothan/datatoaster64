#![no_std]
extern crate no_std_compat as std;

use std::prelude::v1::*;

use std::ops::Range;
use datatoaster_traits::{BlockAccess, BlockIndex, Error as BlockError};

pub const BLOCK_SIZE: usize = 4096;
pub const MIN_BLOCKS: BlockIndex = 64;

mod bitmap;

#[derive(Debug)]
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

/// Disk data layout:
/// superblock
/// n bitmap blocks
/// m data blocks
pub struct BlockDevice<D> {
    device: D,
}

impl<D: BlockAccess<BLOCK_SIZE>> BlockDevice<D> {
    pub fn new(device: D) -> Self {
        Self { device }
    }

    pub fn bitmap_blocks(&self) -> Result<Range<BlockIndex>, Error> {
        let total_blocks = self.device.device_size()?;
        if total_blocks < MIN_BLOCKS {
            return Err(Error::DeviceBounds);
        }
        // Substract superblock.
        let data_and_bitmap_blocks = total_blocks.checked_sub(1).unwrap();
        let nb_bitmap_blocks: u64 =
            data_and_bitmap_blocks.div_ceil(u64::try_from(BLOCK_SIZE).unwrap() * 8 - 1);

        Ok(1..nb_bitmap_blocks + 1)
    }

    pub fn data_blocks(&self) -> Result<Range<BlockIndex>, Error> {
        let total_blocks = self.device.device_size()?;

        Ok(self.bitmap_blocks()?.end..total_blocks)
    }
}
