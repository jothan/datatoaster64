use std::prelude::v1::*;

use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};
use std::mem::MaybeUninit;
use std::num::NonZeroU64;
use std::ops::Range;
use std::sync::Arc;

use bytemuck::Zeroable;
use lock_api::{ArcRwLockReadGuard, ArcRwLockWriteGuard};
use spin::lock_api::{Mutex, RwLock};

use datatoaster_traits::{BlockAccess, BlockIndex};

use crate::bitmap::BitmapAllocator;
use crate::{DataBlockIndex, DeviceLayout, Error, FilesystemInner, BLOCK_SIZE};

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

#[derive(bytemuck::TransparentWrapper, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub(crate) struct InodeIndex(NonZeroU64);

impl InodeIndex {
    fn ordinal(&self) -> u64 {
        self.0.get().checked_sub(ROOT_INODE.get()).unwrap()
    }
}

unsafe impl bytemuck::ZeroableInOption for InodeIndex {}
unsafe impl bytemuck::PodInOption for InodeIndex {}

#[derive(Clone, Copy, Ord, PartialOrd, PartialEq, Eq)]
struct FileBlockIndex(u64);

impl FileBlockIndex {
    fn new(block: u64) -> Result<FileBlockIndex, Error> {
        if block < INODES_PER_BLOCK as u64 {
            Ok(FileBlockIndex(block))
        } else {
            Err(Error::Invalid)
        }
    }
}

#[derive(bytemuck::Zeroable, bytemuck::NoUninit, Clone, Copy, Debug)]
#[repr(u16)]
pub enum InodeType {
    Free = 0,
    Directory = 1,
    File = 2,
}

impl TryFrom<u16> for InodeType {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Error> {
        Ok(match value {
            0 => InodeType::Free,
            1 => InodeType::Directory,
            2 => InodeType::File,
            _ => return Err(Error::Invalid),
        })
    }
}

pub struct Stat {
    pub inode: u64,
    pub kind: InodeType,
    pub nlink: u32,
    pub perm: u16,
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
    pub blksize: u32,
    pub blocks: u64,
    pub size: u64,
}

impl TryFrom<(InodeIndex, &Inode)> for Stat {
    type Error = Error;

    fn try_from(value: (InodeIndex, &Inode)) -> Result<Self, Self::Error> {
        let inode = value.0 .0.get();
        let kind = value.1.kind.try_into()?;
        let nlink = value.1.nlink;
        let perm = value.1.perm;
        let uid = value.1.uid;
        let gid = value.1.gid;
        let blksize = BLOCK_SIZE.try_into().map_err(|_| Error::Invalid)?;
        let blocks_raw = value
            .1
            .direct_blocks
            .iter()
            .filter_map(|b| b.as_ref())
            .count();

        let blocks = u64::try_from(blocks_raw).map_err(|_| Error::Invalid)? * 8; // Blocks of 512 bytes
        let size = match kind {
            InodeType::Free => 0,
            InodeType::Directory => (blocks_raw * BLOCK_SIZE)
                .try_into()
                .map_err(|_| Error::Invalid)?,
            InodeType::File => value.1.size,
        };

        Ok(Stat {
            inode,
            kind,
            nlink,
            perm,
            uid,
            gid,
            blksize,
            blocks,
            size,
        })
    }
}

#[derive(bytemuck::Zeroable, bytemuck::Pod, Clone, Copy, Debug)]
#[repr(C)]
pub(crate) struct Inode {
    // For files: the size in bytes
    // For directories: the number of directory entries (besides . and ..)
    pub(crate) size: u64,
    pub(crate) direct_blocks: [Option<DataBlockIndex>; NB_DIRECT_BLOCKS],

    pub(crate) uid: libc::uid_t,
    pub(crate) gid: libc::gid_t,
    pub(crate) kind: u16,
    pub(crate) perm: u16,
    pub(crate) nlink: u32,
}

impl Inode {
    // Returns None if reading a hole
    // FIXME: returning a big value.
    fn read_block<D: BlockAccess<BLOCK_SIZE>>(
        &self,
        fs: &FilesystemInner<D>,
        block: FileBlockIndex,
    ) -> Result<Option<[u8; BLOCK_SIZE]>, Error> {
        let Some(data_block) = self.direct_blocks[block.0 as usize] else {
            return Ok(None);
        };
        let mut buffer: MaybeUninit<[u8; BLOCK_SIZE]> = MaybeUninit::uninit();
        fs.device.read(data_block.into(), &mut buffer)?;
        Ok(Some(unsafe { buffer.assume_init() }))
    }

    fn write_block<D: BlockAccess<BLOCK_SIZE>>(
        &mut self,
        inode_index: InodeIndex,
        fs: &FilesystemInner<D>,
        block: FileBlockIndex,
        buffer: &[u8; BLOCK_SIZE],
    ) -> Result<(), Error> {
        let data_block = if let Some(data_block) = self.direct_blocks[block.0 as usize] {
            data_block
        } else {
            let data_block = fs.alloc_data(inode_index)?;
            self.direct_blocks[block.0 as usize] = Some(data_block);
            data_block
        };

        fs.device.write(data_block.into(), buffer)?;
        Ok(())
    }
}

#[derive(bytemuck::Zeroable, bytemuck::NoUninit, bytemuck::TransparentWrapper, Clone, Copy)]
#[repr(transparent)]
pub(crate) struct RawInodeBlock(pub(crate) [Inode; INODES_PER_BLOCK]);

type InodeBlockSnapshot = [ArcRwLockReadGuard<spin::RwLock<()>, Inode>; INODES_PER_BLOCK];

impl From<&InodeBlockSnapshot> for RawInodeBlock {
    fn from(value: &[ArcRwLockReadGuard<spin::RwLock<()>, Inode>; INODES_PER_BLOCK]) -> Self {
        RawInodeBlock(std::array::from_fn(|i| *value[i]))
    }
}

pub(crate) struct InodeHandle(pub(crate) InodeIndex, pub(crate) Arc<RwLock<Inode>>);
struct InodeBlock(pub(crate) [Arc<RwLock<Inode>>; INODES_PER_BLOCK]);

impl InodeBlock {
    fn snapshot(&self) -> InodeBlockSnapshot {
        std::array::from_fn(|i| self.0[i].read_arc())
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
    alloc_cursor: Mutex<InodeBlockIndex>,
    block_range: Range<InodeBlockIndex>,
}

impl InodeAllocator {
    pub(crate) fn new(layout: &DeviceLayout) -> Self {
        let block_range = InodeBlockIndex(layout.inode_blocks.start.0)
            ..InodeBlockIndex(layout.inode_blocks.end.0);

        Self {
            blocks: Default::default(),
            dirty_blocks: Default::default(),
            alloc_cursor: Mutex::new(block_range.start),
            block_range,
        }
    }

    pub(crate) fn get_handle<D: BlockAccess<BLOCK_SIZE>>(
        &self,
        index: InodeIndex,
        device: &D,
    ) -> Result<InodeHandle, Error> {
        let (block_index, block_offset) = self.inode_index_location(index);

        let h = self.get_block(block_index, device, |block| block.0[block_offset].clone())?;
        Ok(InodeHandle(index, h))
    }

    fn get_block<D: BlockAccess<BLOCK_SIZE>, T>(
        &self,
        block_index: InodeBlockIndex,
        device: &D,
        f: impl FnOnce(&InodeBlock) -> T,
    ) -> Result<T, Error> {
        match self.blocks.lock().entry(block_index) {
            Entry::Vacant(e) => {
                let block = Self::read_block(block_index, device)?.into();
                Ok(f(e.insert(block)))
            }
            Entry::Occupied(e) => Ok(f(e.get())),
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
            let snapshot = {
                let blocks = self.blocks.lock();
                blocks.get(&block_index).unwrap().snapshot()
            };

            dirty_guard = self.dirty_blocks.lock();

            Self::write_block(block_index, device, &(&snapshot).into())?;
            dirty_guard.remove(&block_index);
        }
    }

    fn alloc<D: BlockAccess<BLOCK_SIZE>>(
        &self,
        device: &D,
        init: impl FnOnce(InodeIndex) -> Inode,
    ) -> Result<InodeHandle, Error> {
        let cursor = *self.alloc_cursor.lock();
        let mut iter = (cursor.0..self.block_range.end.0).chain(self.block_range.start.0..cursor.0);

        for block_index in &mut iter {
            let block_index = InodeBlockIndex(block_index);
            let scan_result = self.get_block(block_index, device, move |block| {
                block.0.iter().enumerate().find_map(|(i, inode)| {
                    if Arc::strong_count(inode) == 1 {
                        let inode = inode.write_arc();
                        let index = self.inode_index_from_location(block_index, i);

                        Some((index, inode)).filter(|(_, inode)| inode.kind == InodeType::Free as _)
                    } else {
                        None
                    }
                })
            })?;

            let Some((index, mut inode)) = scan_result else {
                continue;
            };
            let inode_arc = ArcRwLockWriteGuard::rwlock(&inode).clone();

            *inode = init(index);
            assert!(inode.kind != InodeType::Free as _);
            self.dirty_blocks.lock().insert(block_index);
            drop(inode);

            *self.alloc_cursor.lock() = block_index;
            return Ok(InodeHandle(index, inode_arc));
        }

        Err(Error::OutOfSpace)
    }

    pub(crate) fn dirty_inode_block(&self, inode_index: InodeIndex) {
        let block = self.inode_index_location(inode_index).0;
        self.dirty_blocks.lock().insert(block);
    }

    pub(crate) fn free<D: BlockAccess<BLOCK_SIZE>>(
        &self,
        inode: &mut Inode,
        inode_index: InodeIndex,
        block_alloc: &Mutex<BitmapAllocator>,
        device: &D,
    ) -> Result<(), Error> {
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

        self.dirty_inode_block(inode_index);

        Ok(())
    }

    fn inode_index_from_location(&self, block: InodeBlockIndex, offset: usize) -> InodeIndex {
        assert!(self.block_range.contains(&block));
        assert!(offset < INODES_PER_BLOCK);
        let relative_block = block.0.checked_sub(self.block_range.start.0).unwrap();

        let inode_ordinal = relative_block * INODES_PER_BLOCK as u64 + offset as u64;
        InodeIndex(NonZeroU64::new(inode_ordinal + ROOT_INODE.get()).unwrap())
    }

    fn inode_index_location(&self, inode_index: InodeIndex) -> (InodeBlockIndex, usize) {
        let block = InodeBlockIndex(
            (inode_index.ordinal() / INODES_PER_BLOCK as u64) + self.block_range.start.0,
        );
        assert!(self.block_range.contains(&block));
        let index = (inode_index.ordinal() % INODES_PER_BLOCK as u64) as usize;

        (block, index)
    }

    // Called mostly by user code, so don't panic.
    pub(crate) fn inode_index_from_u64(&self, index: u64) -> Result<InodeIndex, Error> {
        let out = InodeIndex(NonZeroU64::new(index).ok_or(Error::Invalid)?);
        let block =
            InodeBlockIndex((out.ordinal() / INODES_PER_BLOCK as u64) + self.block_range.start.0);

        if !self.block_range.contains(&block) {
            return Err(Error::Invalid);
        }
        Ok(out)
    }
}
