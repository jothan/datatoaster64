use std::prelude::v1::*;

use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};
use std::mem::MaybeUninit;
use std::num::NonZeroU64;
use std::ops::Range;
use std::sync::Arc;

use bytemuck::Zeroable;
use spin::lock_api::{Mutex, RwLock, RwLockReadGuard};

use datatoaster_traits::{BlockAccess, BlockIndex};

use crate::bitmap::BitmapAllocator;
use crate::{DataBlockIndex, DeviceLayout, Error, BLOCK_SIZE};

const NB_DIRECT_BLOCKS: usize = 13;
const FIRST_INODE: NonZeroU64 = unsafe { NonZeroU64::new_unchecked(2) };
pub(crate) const INODES_PER_BLOCK: usize = BLOCK_SIZE / std::mem::size_of::<Inode>();
pub(crate) const ROOT_DIRECTORY_INODE: InodeIndex = InodeIndex(FIRST_INODE);

#[derive(Clone, Copy, Ord, PartialOrd, PartialEq, Eq)]
struct InodeBlockIndex(u64);

impl From<InodeBlockIndex> for BlockIndex {
    fn from(value: InodeBlockIndex) -> BlockIndex {
        BlockIndex(value.0)
    }
}

#[derive(bytemuck::TransparentWrapper, Clone, Copy, Debug)]
#[repr(transparent)]
pub(crate) struct InodeIndex(NonZeroU64);

impl InodeIndex {
    fn location(&self, block_range: Range<InodeBlockIndex>) -> (InodeBlockIndex, usize) {
        let inode_ordinal = self.0.get().checked_sub(FIRST_INODE.get()).unwrap();
        let block =
            InodeBlockIndex((inode_ordinal / INODES_PER_BLOCK as u64) + block_range.start.0);
        assert!(block_range.contains(&block));
        let index = (inode_ordinal % INODES_PER_BLOCK as u64) as usize;

        (block, index)
    }
}

unsafe impl bytemuck::ZeroableInOption for InodeIndex {}
unsafe impl bytemuck::PodInOption for InodeIndex {}

#[derive(bytemuck::Zeroable, bytemuck::NoUninit, Clone, Copy, Debug)]
#[repr(u16)]
pub(crate) enum InodeType {
    Free = 0,
    Directory = 1,
    File = 2,
}

#[derive(bytemuck::Zeroable, bytemuck::Pod, Clone, Copy, Debug, Default)]
#[repr(C)]
pub(crate) struct Inode {
    pub(crate) kind: u16,
    pub(crate) nlink: u16,
    pub(crate) mode: libc::mode_t,
    pub(crate) uid: libc::uid_t,
    pub(crate) gid: libc::uid_t,
    pub(crate) size: u64,
    pub(crate) direct_blocks: [Option<DataBlockIndex>; NB_DIRECT_BLOCKS],
}

#[derive(bytemuck::Zeroable, bytemuck::NoUninit, bytemuck::TransparentWrapper, Clone, Copy)]
#[repr(transparent)]
pub(crate) struct RawInodeBlock(pub(crate) [Inode; INODES_PER_BLOCK]);

type InodeHandle = Arc<RwLock<Inode>>;
#[derive(Clone)]
struct InodeBlock(pub(crate) [InodeHandle; INODES_PER_BLOCK]);

impl InodeBlock {
    fn snapshot(&self) -> (RawInodeBlock, [RwLockReadGuard<Inode>; INODES_PER_BLOCK]) {
        let guards: [RwLockReadGuard<Inode>; INODES_PER_BLOCK] =
            std::array::from_fn(|i| self.0[i].read());
        let inodes = RawInodeBlock(std::array::from_fn(|i| *guards[i]));

        (inodes, guards)
    }
}

impl From<RawInodeBlock> for InodeBlock {
    fn from(value: RawInodeBlock) -> Self {
        InodeBlock(std::array::from_fn(|i| Arc::new(RwLock::new(value.0[i]))))
    }
}

pub(crate) struct InodeAllocator {
    blocks: Mutex<BTreeMap<InodeBlockIndex, InodeBlock>>,
    dirty_blocks: Mutex<BTreeSet<InodeBlockIndex>>,
    block_range: Range<InodeBlockIndex>,
}

impl InodeAllocator {
    pub(crate) fn new(layout: &DeviceLayout) -> Self {
        let block_range = InodeBlockIndex(layout.inode_blocks.start.0)
            ..InodeBlockIndex(layout.inode_blocks.end.0);

        Self {
            blocks: Default::default(),
            dirty_blocks: Default::default(),
            block_range,
        }
    }

    fn get<D: BlockAccess<BLOCK_SIZE>>(
        &self,
        index: InodeIndex,
        device: &D,
    ) -> Result<InodeHandle, Error> {
        let (block_index, block_offset) = index.location(self.block_range.clone());

        match self.blocks.lock().entry(block_index) {
            Entry::Vacant(e) => {
                let block = Self::read_block(block_index, device)?.into();
                let slot = Arc::clone(&e.insert(block).0[block_offset]);
                Ok(slot)
            }
            Entry::Occupied(e) => Ok(Arc::clone(&e.get().0[block_offset])),
        }
    }

    fn read_block<D: BlockAccess<BLOCK_SIZE>>(
        block_index: InodeBlockIndex,
        device: &D,
    ) -> Result<RawInodeBlock, Error> {
        let mut block: MaybeUninit<RawInodeBlock> = MaybeUninit::uninit();
        let bytes: &mut MaybeUninit<[u8; BLOCK_SIZE]> = unsafe { std::mem::transmute(&mut block) };
        device.read(block_index.into(), bytes)?;

        let block = unsafe { block.assume_init() };

        Ok(block)
    }

    fn write_block<D: BlockAccess<BLOCK_SIZE>>(
        block_index: InodeBlockIndex,
        device: &D,
        data: &RawInodeBlock,
    ) -> Result<(), Error> {
        let bytes = bytemuck::bytes_of(data).try_into().unwrap();
        device.write(block_index.into(), bytes)?;

        Ok(())
    }

    pub(super) fn sync<D: BlockAccess<BLOCK_SIZE>>(&self, device: &D) -> Result<(), Error> {
        loop {
            let mut dirty_guard = self.dirty_blocks.lock();
            let Some(block_index) = dirty_guard.first().copied() else {
                break Ok(());
            };
            drop(dirty_guard);

            // The lock order is very important here.
            let block = {
                let blocks = self.blocks.lock();
                blocks.get(&block_index).unwrap().clone()
            };
            let (snapshot, _lock_guards) = block.snapshot();

            dirty_guard = self.dirty_blocks.lock();

            Self::write_block(block_index, device, &snapshot)?;
            dirty_guard.remove(&block_index);
        }
    }

    fn free<D: BlockAccess<BLOCK_SIZE>>(
        &self,
        index: InodeIndex,
        block_alloc: &Mutex<BitmapAllocator>,
        device: &D,
    ) -> Result<(), Error> {
        let inode_handle = self.get(index, device)?;
        let mut inode = inode_handle.write();

        // FIXME: put a better condition here, make sure directories are empty.
        if inode.kind == InodeType::Free as _ || inode.nlink != 0 {
            return Err(Error::Invalid);
        }

        let mut block_alloc = block_alloc.lock();
        inode.direct_blocks.iter_mut().try_for_each(|b| {
            if let Some(data_block) = *b {
                block_alloc.free(device, data_block).inspect(|_| {
                    *b = None;
                })
            } else {
                Ok(())
            }
        })?;
        drop(block_alloc);

        *inode = Inode::zeroed();

        self.dirty_blocks
            .lock()
            .insert(index.location(self.block_range.clone()).0);

        Ok(())
    }
}
