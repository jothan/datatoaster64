use std::prelude::v1::*;

use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};
use std::mem::MaybeUninit;

use datatoaster_traits::{BlockAccess, BlockIndex};

use crate::{BlockDevice, DataBlockIndex, DeviceLayout, Error, BLOCK_SIZE};

const BITMAP_SEGMENTS: usize = BLOCK_SIZE / std::mem::size_of::<u64>();
const BITS_PER_BLOCK: u64 = BLOCK_SIZE as u64 * 8;

#[derive(bytemuck::NoUninit, bytemuck::AnyBitPattern, Clone, Copy)]
#[repr(transparent)]
struct BitmapBlock([u64; BITMAP_SEGMENTS]);

#[derive(Default)]
pub(crate) struct BitmapBlocks {
    blocks: BTreeMap<BitmapBlockIndex, BitmapBlock>,
    dirty_blocks: BTreeSet<BitmapBlockIndex>,
}

impl BitmapBlocks {
    fn get<D: BlockAccess<BLOCK_SIZE>>(
        &mut self,
        index: BitmapBlockIndex,
        device: &BlockDevice<D>,
    ) -> Result<&mut BitmapBlock, Error> {
        match self.blocks.entry(index) {
            Entry::Vacant(e) => {
                let block = BitmapAllocator::read_block(index, device)?;
                Ok(e.insert(block))
            }
            Entry::Occupied(e) => Ok(e.into_mut()),
        }
    }

    fn sync<D: BlockAccess<BLOCK_SIZE>>(&mut self, device: &BlockDevice<D>) -> Result<(), Error> {
        while let Some(block_idx) = self.dirty_blocks.first().copied() {
            let data = self.get(block_idx, device)?;
            BitmapAllocator::write_block(block_idx, device, data)?;
            self.dirty_blocks.remove(&block_idx);
        }

        Ok(())
    }
}

pub struct BitmapAllocator {
    layout: DeviceLayout,
    cursor: BitmapBitIndex,
    blocks: BitmapBlocks,
}

#[derive(Clone, Copy, Ord, PartialOrd, PartialEq, Eq)]
struct BitmapBlockIndex(u64);

impl From<BitmapBlockIndex> for BlockIndex {
    fn from(value: BitmapBlockIndex) -> BlockIndex {
        BlockIndex(value.0)
    }
}

/// User data block index, relative to the start of the data area.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) struct BitmapBitIndex(pub(crate) u64);

impl BitmapBitIndex {
    fn block(&self, layout: &DeviceLayout) -> BitmapBlockIndex {
        BitmapBlockIndex((self.0 / BITS_PER_BLOCK) + layout.bitmap_blocks.start.0)
    }

    fn segment(&self) -> usize {
        (self.0 as usize / 64) & (BITMAP_SEGMENTS - 1)
    }

    fn segment_bit(&self) -> u32 {
        self.0 as u32 & (u64::BITS - 1)
    }

    fn into_data_block_index(self, layout: &DeviceLayout) -> Option<DataBlockIndex> {
        let index = DataBlockIndex(self.0 + layout.data_blocks.start.0);

        if layout.data_blocks.contains(&index.into()) {
            Some(index)
        } else {
            None
        }
    }
}

impl BitmapAllocator {
    pub fn new<D: BlockAccess<BLOCK_SIZE>>(device: &BlockDevice<D>) -> Result<Self, Error> {
        let layout = device.layout().clone();
        let cursor = BitmapBitIndex(0);

        Ok(Self {
            layout,
            cursor,
            blocks: Default::default(),
        })
    }

    fn read_block<D: BlockAccess<BLOCK_SIZE>>(
        block_index: BitmapBlockIndex,
        device: &BlockDevice<D>,
    ) -> Result<BitmapBlock, Error> {
        let mut block: MaybeUninit<[u64; BITMAP_SEGMENTS]> = MaybeUninit::uninit();
        let bytes: &mut MaybeUninit<[u8; BLOCK_SIZE]> = unsafe { std::mem::transmute(&mut block) };
        device.inner.read(block_index.into(), bytes)?;

        let block = BitmapBlock(unsafe { block.assume_init() });

        Ok(block)
    }

    fn write_block<D: BlockAccess<BLOCK_SIZE>>(
        block_index: BitmapBlockIndex,
        device: &BlockDevice<D>,
        data: &BitmapBlock,
    ) -> Result<(), Error> {
        let bytes = bytemuck::bytes_of(data).try_into().unwrap();
        device.inner.write(block_index.into(), bytes)?;

        Ok(())
    }

    fn lowest_unset_bit(segment: u64) -> Option<u32> {
        if segment == u64::MAX {
            return None;
        }

        let mask = !segment & (segment + 1);
        Some(mask.ilog2())
    }

    /// Allocate a single block for file or directory data
    pub fn alloc<D: BlockAccess<BLOCK_SIZE>>(
        &mut self,
        device: &BlockDevice<D>,
    ) -> Result<DataBlockIndex, Error> {
        let nb_data_blocks =
            BitmapBitIndex(self.layout.data_blocks.end.0 - self.layout.data_blocks.start.0);

        assert!(self.cursor.segment_bit() == 0);
        let nb_segments = nb_data_blocks.0.div_ceil(64);
        let cursor_segment = self.cursor.0 / 64;

        // Dead simple linear scan with wrap-around.
        let segment_iter = (cursor_segment..nb_segments)
            .chain(0..cursor_segment)
            .map(|s| BitmapBitIndex(s * 64));

        for bit_index in segment_iter {
            self.cursor = bit_index;
            let block_index = bit_index.block(&self.layout);

            let block = self.blocks.get(block_index, device)?;
            let segment = &mut block.0[bit_index.segment()];
            if let Some(bit) = Self::lowest_unset_bit(*segment) {
                *segment |= 1 << bit;
                self.blocks.dirty_blocks.insert(block_index);

                let Some(data_block) =
                    BitmapBitIndex(self.cursor.0 + bit as u64).into_data_block_index(&self.layout)
                else {
                    // Not all bits may indicate a valid block at the last segment
                    continue;
                };

                return Ok(data_block);
            }
        }

        Err(Error::OutOfSpace)
    }

    pub fn free<D: BlockAccess<BLOCK_SIZE>>(
        &mut self,
        device: &BlockDevice<D>,
        data_index: DataBlockIndex,
    ) -> Result<(), Error> {
        let bit_index = data_index.into_bitmap_bit_index(&self.layout);
        let block_index = bit_index.block(&self.layout);

        let block = self.blocks.get(block_index, device)?;
        let segment = &mut block.0[bit_index.segment()];

        let mask = 1 << bit_index.segment_bit();

        if *segment & mask == 0 {
            // Double free
            return Err(Error::Invalid);
        }

        *segment &= !mask;
        self.blocks.dirty_blocks.insert(block_index);

        Ok(())
    }

    pub fn sync<D: BlockAccess<BLOCK_SIZE>>(
        &mut self,
        device: &BlockDevice<D>,
    ) -> Result<(), Error> {
        self.blocks.sync(device)
    }
}

#[cfg(test)]
mod tests {
    use std::prelude::v1::*;

    use std::mem::MaybeUninit;

    use datatoaster_traits::{BlockAccess, BlockIndex};

    use super::{BitmapAllocator, BitmapBlockIndex, Error, BLOCK_SIZE};
    use crate::BlockDevice;

    struct DummyDevice {
        size: u64,
    }

    impl BlockAccess<BLOCK_SIZE> for DummyDevice {
        fn read(
            &self,
            _block_idx: BlockIndex,
            buffer: &mut std::mem::MaybeUninit<[u8; BLOCK_SIZE]>,
        ) -> Result<(), datatoaster_traits::Error> {
            *buffer = MaybeUninit::zeroed();
            Ok(())
        }

        fn write(
            &self,
            _block_idx: BlockIndex,
            _buffer: &[u8; BLOCK_SIZE],
        ) -> Result<(), datatoaster_traits::Error> {
            todo!()
        }

        fn device_size(&self) -> Result<BlockIndex, datatoaster_traits::Error> {
            Ok(BlockIndex(self.size / BLOCK_SIZE as u64))
        }
    }

    #[test]
    fn fill_device() -> Result<(), Error> {
        let device = BlockDevice::new(DummyDevice {
            size: 256 * 1024 * 1024,
        })?;
        let mut alloc = BitmapAllocator::new(&device)?;

        for _ in 0..(device.layout.data_blocks.end.0 - device.layout.data_blocks.start.0) {
            assert!(alloc.alloc(&device).is_ok());
        }
        assert!(alloc.alloc(&device) == Err(Error::OutOfSpace));

        Ok(())
    }

    #[test]
    fn dirty_page() -> Result<(), Error> {
        let device = BlockDevice::new(DummyDevice {
            size: 256 * 1024 * 1024,
        })?;
        let mut alloc = BitmapAllocator::new(&device)?;
        assert!(alloc.blocks.dirty_blocks.len() == 0);
        let data_block = alloc.alloc(&device)?;
        assert!(alloc.blocks.dirty_blocks.len() == 1);
        assert!(alloc
            .blocks
            .dirty_blocks
            .contains(&BitmapBlockIndex(device.layout.bitmap_blocks.start.0)));

        alloc.free(&device, data_block)?;
        assert!(alloc.free(&device, data_block) == Err(Error::Invalid));

        Ok(())
    }
}
