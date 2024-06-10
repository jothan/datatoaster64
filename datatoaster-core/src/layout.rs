use std::prelude::v1::*;

use std::ops::Range;

use datatoaster_traits::BlockIndex;

use crate::inode::INODES_PER_BLOCK;
use crate::superblock::SuperBlock;
use crate::{Error, BLOCK_SIZE};

/// Disk data layout:
/// superblock
/// inode blocks
/// bitmap blocks
/// data blocks

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceLayout {
    pub inode_blocks: Range<BlockIndex>,
    pub bitmap_blocks: Range<BlockIndex>,
    pub data_blocks: Range<BlockIndex>,
}

impl DeviceLayout {
    const MIN_BLOCKS: BlockIndex = BlockIndex(64);
    const INODE_RATIO: u64 = 16384; // bytes per inode

    pub(crate) fn new(total_blocks: BlockIndex) -> Result<Self, Error> {
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
            inode_blocks,
            bitmap_blocks,
            data_blocks,
        })
    }

    pub(crate) fn nb_inode_blocks(&self) -> u64 {
        range_blocks(&self.inode_blocks)
    }

    pub(crate) fn nb_bitmap_blocks(&self) -> u64 {
        range_blocks(&self.bitmap_blocks)
    }

    pub(crate) fn nb_data_blocks(&self) -> u64 {
        range_blocks(&self.data_blocks)
    }

    pub(crate) fn from_superblock(sb: &SuperBlock) -> Self {
        let inode_blocks = BlockIndex(1)..BlockIndex(1 + sb.inodes_blocks);

        let bitmap_blocks =
            BlockIndex(inode_blocks.end.0)..BlockIndex(inode_blocks.end.0 + sb.bitmap_blocks);

        let data_blocks =
            BlockIndex(bitmap_blocks.end.0)..BlockIndex(bitmap_blocks.end.0 + sb.data_blocks);

        DeviceLayout {
            inode_blocks,
            bitmap_blocks,
            data_blocks,
        }
    }
}

fn range_blocks(range: &Range<BlockIndex>) -> u64 {
    range.end.0 - range.start.0
}
