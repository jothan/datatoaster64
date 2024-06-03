use std::prelude::v1::*;

use datatoaster_traits::{BlockAccess, BlockIndex};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use crate::{BlockDevice, Error, BLOCK_SIZE};

const BITMAP_SEGMENTS: usize = BLOCK_SIZE / std::mem::size_of::<u64>();
struct BitmapChunk {
    data: [u64; BITMAP_SEGMENTS],
}

pub(crate) struct BitmapAllocator {
    bitmap_blocks: Range<BlockIndex>,
    data_blocks: Range<BlockIndex>,
    cursor: BlockIndex,
    chunks: BTreeMap<BlockIndex, BitmapChunk>,
    dirty_chunks: BTreeSet<BlockIndex>,
}

impl BitmapAllocator {
    pub(crate) fn new<D: BlockAccess<BLOCK_SIZE>>(device: &BlockDevice<D>) -> Result<Self, Error> {
        let bitmap_blocks = device.bitmap_blocks()?;
        let data_blocks = device.data_blocks()?;
        let cursor = data_blocks.start;

        Ok(Self {
            bitmap_blocks,
            data_blocks,
            cursor,
            chunks: Default::default(),
            dirty_chunks: Default::default(),
        })
    }
}
