use std::prelude::v1::*;

use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};
use std::mem::MaybeUninit;
use std::num::NonZeroU64;

use datatoaster_traits::{BlockAccess, BlockIndex};

use crate::buffers::BufferBox;
use crate::{DataBlockIndex, DeviceLayout, Error, BLOCK_SIZE};

const BITMAP_SEGMENTS: usize = BLOCK_SIZE / std::mem::size_of::<u64>();
const BITS_PER_BLOCK: u64 = BLOCK_SIZE as u64 * 8;

#[derive(bytemuck::NoUninit, bytemuck::AnyBitPattern, Clone, Copy)]
#[repr(transparent)]
struct BitmapBlock([u64; BITMAP_SEGMENTS]);

#[derive(Default)]
struct BitmapBlocks {
    blocks: BTreeMap<BitmapBlockIndex, BitmapBlock>,
    dirty_blocks: BTreeSet<BitmapBlockIndex>,
}

impl BitmapBlocks {
    fn get<D: BlockAccess<BLOCK_SIZE>>(
        &mut self,
        index: BitmapBlockIndex,
        device: &D,
    ) -> Result<&mut BitmapBlock, Error> {
        match self.blocks.entry(index) {
            Entry::Vacant(e) => {
                let block = BitmapAllocator::read_block(index, device)?;
                Ok(e.insert(*block))
            }
            Entry::Occupied(e) => Ok(e.into_mut()),
        }
    }

    fn sync<D: BlockAccess<BLOCK_SIZE>>(&mut self, device: &D) -> Result<(), Error> {
        while let Some(block_idx) = self.dirty_blocks.first().copied() {
            let data = self.get(block_idx, device)?;
            BitmapAllocator::write_block(block_idx, device, data)?;
            self.dirty_blocks.remove(&block_idx);
        }

        Ok(())
    }
}

pub(crate) struct BitmapAllocator {
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
        let index = DataBlockIndex(NonZeroU64::new(self.0 + layout.data_blocks.start.0)?);

        if layout.data_blocks.contains(&index.into()) {
            Some(index)
        } else {
            None
        }
    }
}

impl BitmapAllocator {
    pub fn new(layout: &DeviceLayout) -> Self {
        Self {
            layout: layout.clone(),
            cursor: BitmapBitIndex(0),
            blocks: Default::default(),
        }
    }

    fn read_block<D: BlockAccess<BLOCK_SIZE>>(
        block_index: BitmapBlockIndex,
        device: &D,
    ) -> Result<BufferBox<BitmapBlock>, Error> {
        let mut block = BufferBox::<BitmapBlock>::new_uninit();
        {
            let block_ptr: *mut MaybeUninit<BitmapBlock> = &mut *block;
            let block: &mut MaybeUninit<[u8; BLOCK_SIZE]> = unsafe { &mut *block_ptr.cast() };
            device.read(block_index.into(), block)?;
        }
        let bytes = unsafe { block.assume_init() };
        Ok(bytes)
    }

    fn write_block<D: BlockAccess<BLOCK_SIZE>>(
        block_index: BitmapBlockIndex,
        device: &D,
        data: &BitmapBlock,
    ) -> Result<(), Error> {
        let bytes = bytemuck::bytes_of(data).try_into().unwrap();
        device.write(block_index.into(), bytes)?;

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
    pub(crate) fn alloc<D: BlockAccess<BLOCK_SIZE>>(
        &mut self,
        device: &D,
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

                log::debug!("alloc {data_block:?}");
                return Ok(data_block);
            }
        }

        Err(Error::OutOfSpace)
    }

    pub(crate) fn free<D: BlockAccess<BLOCK_SIZE>>(
        &mut self,
        device: &D,
        data_block: DataBlockIndex,
    ) -> Result<(), Error> {
        log::debug!("free {data_block:?}");
        let bit_index = data_block.into_bitmap_bit_index(&self.layout);
        let block_index = bit_index.block(&self.layout);

        let block = self.blocks.get(block_index, device)?;
        let segment = &mut block.0[bit_index.segment()];

        let mask = 1 << bit_index.segment_bit();

        if *segment & mask == 0 {
            // Double free
            log::error!("invalid free {data_block:?}");
            return Err(Error::Invalid);
        }

        *segment &= !mask;
        self.blocks.dirty_blocks.insert(block_index);

        Ok(())
    }

    pub(crate) fn sync<D: BlockAccess<BLOCK_SIZE>>(&mut self, device: &D) -> Result<(), Error> {
        self.blocks.sync(device)
    }
}

#[cfg(test)]
mod tests {
    use std::prelude::v1::*;

    use std::mem::MaybeUninit;

    use datatoaster_traits::{BlockAccess, BlockIndex};

    use super::{BitmapAllocator, BitmapBlockIndex, Error, BLOCK_SIZE};
    use crate::DeviceLayout;

    struct DummyDevice {
        size: u64,
    }

    unsafe impl BlockAccess<BLOCK_SIZE> for DummyDevice {
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
        let device = DummyDevice {
            size: 256 * 1024 * 1024,
        };

        let layout = DeviceLayout::new(device.device_size()?)?;
        let mut alloc = BitmapAllocator::new(&layout);

        for _ in 0..(layout.data_blocks.end.0 - layout.data_blocks.start.0) {
            assert!(alloc.alloc(&device).is_ok());
        }
        assert!(alloc.alloc(&device) == Err(Error::OutOfSpace));

        Ok(())
    }

    #[test]
    fn dirty_page() -> Result<(), Error> {
        let device = DummyDevice {
            size: 256 * 1024 * 1024,
        };
        let layout = DeviceLayout::new(device.device_size()?)?;
        let mut alloc = BitmapAllocator::new(&layout);
        assert!(alloc.blocks.dirty_blocks.len() == 0);
        let data_block = alloc.alloc(&device)?;
        assert!(alloc.blocks.dirty_blocks.len() == 1);
        assert!(alloc
            .blocks
            .dirty_blocks
            .contains(&BitmapBlockIndex(layout.bitmap_blocks.start.0)));

        alloc.free(&device, data_block)?;
        assert!(alloc.free(&device, data_block) == Err(Error::Invalid));

        Ok(())
    }
}
