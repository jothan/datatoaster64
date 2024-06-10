use std::prelude::v1::*;

use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};
use std::mem::MaybeUninit;
use std::num::NonZeroU64;
use std::ops::{Deref, DerefMut, Range};
use std::sync::Arc;
use std::time::Duration;

use bytemuck::Zeroable;
use lock_api::ArcRwLockReadGuard;
use spin::lock_api::{Mutex, RwLock, RwLockReadGuard, RwLockUpgradableReadGuard, RwLockWriteGuard};

use datatoaster_traits::{BlockAccess, BlockIndex};

use crate::bitmap::BitmapAllocator;
use crate::buffers::{BlockBuffer, BufferBox};
use crate::directory::{DirectoryInode, DirectoryInodeMut};
use crate::{DataBlockIndex, DeviceLayout, Error, FilesystemInner, BLOCK_SIZE};

// FIXME: implement indirect blocks
pub(crate) const NB_DIRECT_BLOCKS: usize = 53;
pub const ROOT_INODE: NonZeroU64 = NonZeroU64::MIN;
pub(crate) const INODES_PER_BLOCK: usize = BLOCK_SIZE / std::mem::size_of::<Inode>();
pub(crate) const ROOT_DIRECTORY_INODE: InodeIndex = InodeIndex(ROOT_INODE);
pub(crate) const MAX_FILE_SIZE: u64 = NB_DIRECT_BLOCKS as u64 * BLOCK_SIZE as u64;

#[derive(Clone, Copy, Ord, PartialOrd, PartialEq, Eq, Debug)]
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

impl From<InodeIndex> for u64 {
    fn from(value: InodeIndex) -> Self {
        value.0.get()
    }
}

impl From<InodeIndex> for NonZeroU64 {
    fn from(value: InodeIndex) -> Self {
        value.0
    }
}

pub(crate) trait InodeReference {
    fn index(&self) -> InodeIndex;
}

pub(crate) trait InodeHolder: InodeReference + Deref<Target = Inode> {
    fn as_dir(&self) -> Result<DirectoryInode<'_>, Error> {
        DirectoryInode::new(self)
    }
}

impl<T: InodeReference + Deref<Target = Inode>> InodeHolder for T {}

impl InodeReference for InodeHandleRead<'_> {
    fn index(&self) -> InodeIndex {
        self.0
    }
}

impl InodeReference for InodeHandleUpgradableRead<'_> {
    fn index(&self) -> InodeIndex {
        self.0
    }
}

impl<D> InodeReference for InodeHandleWrite<'_, D> {
    fn index(&self) -> InodeIndex {
        self.index
    }
}

unsafe impl bytemuck::ZeroableInOption for InodeIndex {}
unsafe impl bytemuck::PodInOption for InodeIndex {}

#[derive(Clone, Copy, Ord, PartialOrd, PartialEq, Eq, Debug)]
pub(crate) struct FileBlockIndex(usize);

impl FileBlockIndex {
    pub(crate) const FIRST: FileBlockIndex = FileBlockIndex(0);

    pub(crate) fn from_file_position(position: u64) -> Result<(FileBlockIndex, usize), Error> {
        if position > MAX_FILE_SIZE {
            return Err(Error::OutOfSpace);
        }

        let offset = position as usize % BLOCK_SIZE;
        Ok((
            FileBlockIndex((position / BLOCK_SIZE as u64) as usize),
            offset,
        ))
    }

    pub(crate) fn increment(&mut self) -> Result<(), Error> {
        if self.0 > NB_DIRECT_BLOCKS - 1 {
            return Err(Error::Invalid);
        }
        self.0 += 1;
        Ok(())
    }
}

impl From<FileBlockIndex> for u64 {
    fn from(value: FileBlockIndex) -> Self {
        value.0.try_into().unwrap()
    }
}

impl From<FileBlockIndex> for usize {
    fn from(value: FileBlockIndex) -> Self {
        value.0
    }
}

#[derive(bytemuck::Zeroable, bytemuck::NoUninit, Clone, Copy, Debug, PartialEq, Eq)]
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
    pub crtime: Duration,
    pub ctime: Duration,
    pub mtime: Duration,
    pub atime: Duration,
}

impl Stat {
    pub(crate) fn new(index: InodeIndex, inode: &Inode) -> Result<Self, Error> {
        let kind = inode.kind.try_into()?;
        let nlink = inode.nlink;
        let perm = inode.perm;
        let uid = inode.uid;
        let gid = inode.gid;
        let blksize = BLOCK_SIZE.try_into().map_err(|_| Error::Invalid)?;
        let blocks_raw = inode
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
            InodeType::File => inode.size,
        };

        Ok(Stat {
            inode: index.into(),
            kind,
            nlink,
            perm,
            uid,
            gid,
            blksize,
            blocks,
            size,
            crtime: u128_duration(inode.crtime),
            ctime: u128_duration(inode.ctime),
            mtime: u128_duration(inode.mtime),
            atime: u128_duration(inode.atime),
        })
    }
}

fn u128_duration(nanos: u128) -> Duration {
    let seconds = nanos / 1_000_000_000;
    let nanos = nanos % 1_000_000_000;
    Duration::new(seconds as u64, nanos as u32)
}

#[derive(bytemuck::Zeroable, bytemuck::Pod, Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub(crate) struct Inode {
    pub(crate) crtime: u128,
    pub(crate) atime: u128,
    pub(crate) mtime: u128,
    pub(crate) ctime: u128,
    // For files: the size in bytes
    // For directories: the number of directory entries
    pub(crate) size: u64,
    pub(crate) direct_blocks: [Option<DataBlockIndex>; NB_DIRECT_BLOCKS],

    pub(crate) uid: libc::uid_t,
    pub(crate) gid: libc::gid_t,
    pub(crate) kind: u16,
    pub(crate) perm: u16,
    pub(crate) nlink: u32,
}

impl Inode {
    pub(crate) fn new_file(perm: u16) -> Self {
        let mut f = Inode::zeroed();
        f.kind = InodeType::File as _;
        f.perm = perm;
        f
    }

    pub(crate) fn new_directory(perm: u16) -> Self {
        let mut f = Inode::zeroed();
        f.kind = InodeType::Directory as _;
        f.perm = perm;
        f
    }

    pub(crate) fn is_kind(&self, kind: InodeType) -> Result<bool, Error> {
        Ok(InodeType::try_from(self.kind)? == kind)
    }

    pub(crate) fn ensure_kind(&self, kind: InodeType) -> Result<(), Error> {
        if !self.is_kind(kind)? {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    pub(crate) fn ensure_is_file(&self) -> Result<(), Error> {
        self.ensure_kind(InodeType::File)
    }

    pub(crate) fn ensure_is_directory(&self) -> Result<(), Error> {
        self.ensure_kind(InodeType::Directory)
    }

    pub(crate) fn trim_read_op(&self, position: u64, length: usize) -> Result<usize, Error> {
        self.ensure_is_file()?;
        if position > MAX_FILE_SIZE {
            return Err(Error::OutOfSpace);
        }

        assert!(self.size <= MAX_FILE_SIZE);
        let position_end = std::cmp::min(
            position.checked_add(length.try_into().unwrap()).unwrap(),
            self.size,
        );
        Ok((position_end - position).try_into().unwrap())
    }

    pub(crate) fn trim_write_op(&self, position: u64, length: usize) -> Result<usize, Error> {
        self.ensure_is_file()?;
        if position > MAX_FILE_SIZE {
            return Err(Error::OutOfSpace);
        }

        let position_end = std::cmp::min(
            position.checked_add(length.try_into().unwrap()).unwrap(),
            MAX_FILE_SIZE,
        );
        Ok((position_end - position).try_into().unwrap())
    }

    pub(crate) fn read_block<D: BlockAccess<BLOCK_SIZE>>(
        &self,
        fs: &FilesystemInner<D>,
        block: FileBlockIndex,
    ) -> Result<Option<BlockBuffer>, Error> {
        let Some(data_block) = self.direct_blocks[block.0] else {
            return Ok(None);
        };
        let mut buffer = BlockBuffer::new_uninit();
        fs.device.read(data_block.into(), &mut buffer)?;
        Ok(Some(unsafe { buffer.assume_init() }))
    }

    pub(crate) fn data_block_iter<'a, D: BlockAccess<BLOCK_SIZE>>(
        &'a self,
        fs: &'a FilesystemInner<D>,
    ) -> impl Iterator<Item = Result<(FileBlockIndex, Option<BlockBuffer>), Error>> + '_ {
        (0..NB_DIRECT_BLOCKS).map(|block_num| {
            let block_num = FileBlockIndex(block_num);
            self.read_block(fs, block_num).map(|r| (block_num, r))
        })
    }

    pub(crate) fn nb_alloc_blocks(&self) -> usize {
        self.direct_blocks.iter().filter(|&&b| b.is_some()).count()
    }

    pub(crate) fn first_hole(&self) -> Option<FileBlockIndex> {
        self.direct_blocks
            .iter()
            .position(|b| b.is_none())
            .map(FileBlockIndex)
    }
}

#[derive(
    bytemuck::NoUninit, bytemuck::TransparentWrapper, bytemuck::AnyBitPattern, Clone, Copy,
)]
#[repr(transparent)]
pub(crate) struct RawInodeBlock(pub(crate) [Inode; INODES_PER_BLOCK]);

type InodeBlockSnapshot = [ArcRwLockReadGuard<spin::RwLock<()>, Inode>; INODES_PER_BLOCK];

impl From<&InodeBlockSnapshot> for RawInodeBlock {
    fn from(value: &[ArcRwLockReadGuard<spin::RwLock<()>, Inode>; INODES_PER_BLOCK]) -> Self {
        RawInodeBlock(std::array::from_fn(|i| *value[i]))
    }
}

#[derive(Clone)]
pub(crate) struct InodeHandle(pub(crate) InodeIndex, pub(crate) Arc<RwLock<Inode>>);
pub(crate) struct InodeHandleRead<'a>(InodeIndex, RwLockReadGuard<'a, Inode>);
pub(crate) struct InodeHandleUpgradableRead<'a>(InodeIndex, RwLockUpgradableReadGuard<'a, Inode>);
pub(crate) struct InodeHandleWrite<'a, D> {
    index: InodeIndex,
    guard: Option<RwLockWriteGuard<'a, Inode>>,
    snapshot: Option<BufferBox<Inode>>,
    fs: Arc<FilesystemInner<D>>,
    time: Option<Duration>,
}

impl<'a> Deref for InodeHandleRead<'a> {
    type Target = Inode;

    fn deref(&self) -> &Self::Target {
        &self.1
    }
}

impl<'a> InodeHandleUpgradableRead<'a> {
    pub(crate) fn upgrade<D>(self, fs: Arc<FilesystemInner<D>>) -> InodeHandleWrite<'a, D> {
        let guard = RwLockUpgradableReadGuard::upgrade(self.1);
        InodeHandleWrite::new(self.0, guard, fs)
    }

    pub(crate) fn lock_two<'p, 'q>(
        first: &'p InodeHandle,
        second: &'q InodeHandle,
    ) -> Result<(InodeHandleUpgradableRead<'p>, InodeHandleUpgradableRead<'q>), Error> {
        for i in 0..16 {
            let first_guard;
            let second_guard;

            if i & 1 == 0 {
                second_guard = Some(second.upgradable_read());
                first_guard = first.try_upgradable_read();
            } else {
                first_guard = Some(first.upgradable_read());
                second_guard = second.try_upgradable_read();
            }
            if let (Some(first), Some(second)) = (first_guard, second_guard) {
                return Ok((first, second));
            }
        }
        Err(Error::Deadlock)
    }
}

impl<'a> Deref for InodeHandleUpgradableRead<'a> {
    type Target = Inode;

    fn deref(&self) -> &Self::Target {
        &self.1
    }
}

impl<'a, D> InodeHandleWrite<'a, D> {
    fn new(
        index: InodeIndex,
        guard: RwLockWriteGuard<'a, Inode>,
        fs: Arc<FilesystemInner<D>>,
    ) -> Self {
        InodeHandleWrite {
            index,
            guard: Some(guard),
            fs,
            snapshot: None,
            time: None,
        }
    }

    fn flush_dirty(&mut self, current_value: &Inode) {
        if self
            .snapshot
            .as_ref()
            .is_some_and(|snap| current_value != snap.deref())
        {
            self.bump_ctime();
            self.fs.inodes.dirty_inode_block(self.index());
            self.snapshot = None;
        } else {
            log::debug!("{:?} is clean", self.index);
        }
        self.time = None;
    }

    #[allow(dead_code)]
    pub(crate) fn downgrade(mut self) -> InodeHandleRead<'a> {
        let guard = self.guard.take().expect("inode write handle gone");
        self.flush_dirty(guard.deref());
        let guard = RwLockWriteGuard::downgrade(guard);
        InodeHandleRead(self.index, guard)
    }

    fn get_time(&mut self) -> Duration {
        *self.time.get_or_insert_with(self.fs.time_source)
    }

    pub(crate) fn bump_crtime(&mut self) {
        self.crtime = self.get_time().as_nanos();
    }

    pub(crate) fn bump_atime(&mut self) {
        self.atime = self.get_time().as_nanos();
    }

    pub(crate) fn bump_mtime(&mut self) {
        self.mtime = self.get_time().as_nanos();
    }

    pub(crate) fn bump_ctime(&mut self) {
        self.ctime = self.get_time().as_nanos();
    }
}

impl<'a, D: BlockAccess<BLOCK_SIZE>> InodeHandleWrite<'a, D> {
    pub(crate) fn write_block(
        &mut self,
        block: FileBlockIndex,
        buffer: &[u8; BLOCK_SIZE],
    ) -> Result<(), Error> {
        let data_block = if let Some(data_block) = self.direct_blocks[block.0] {
            data_block
        } else {
            let data_block = self.fs.alloc.lock().alloc(&self.fs.device)?;
            self.direct_blocks[block.0] = Some(data_block);
            data_block
        };
        self.bump_mtime();
        self.bump_ctime();
        self.fs.device.write(data_block.into(), buffer)?;
        Ok(())
    }

    pub(crate) fn into_dir_mut(self) -> Result<DirectoryInodeMut<'a, D>, Error> {
        DirectoryInodeMut::new(self)
    }
}

impl<'a, D> Deref for InodeHandleWrite<'a, D> {
    type Target = Inode;

    fn deref(&self) -> &Self::Target {
        self.guard
            .as_ref()
            .expect("inode write handle gone in deref")
    }
}

impl<'a, D> DerefMut for InodeHandleWrite<'a, D> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let guard = self
            .guard
            .as_mut()
            .expect("inode write handle gone in deref_mut");
        self.snapshot.get_or_insert_with(|| BufferBox::new(**guard));

        guard
    }
}

impl<'a, D> Drop for InodeHandleWrite<'a, D> {
    fn drop(&mut self) {
        if let Some(guard) = self.guard.take() {
            self.flush_dirty(guard.deref());
        }
    }
}

impl InodeHandle {
    pub(crate) fn read(&self) -> InodeHandleRead<'_> {
        InodeHandleRead(self.0, self.1.read())
    }

    pub(crate) fn upgradable_read(&self) -> InodeHandleUpgradableRead<'_> {
        InodeHandleUpgradableRead(self.0, self.1.upgradable_read())
    }

    pub(crate) fn try_upgradable_read(&self) -> Option<InodeHandleUpgradableRead<'_>> {
        self.1
            .try_upgradable_read()
            .map(|g| InodeHandleUpgradableRead(self.0, g))
    }

    pub(crate) fn write<D>(&self, fs: Arc<FilesystemInner<D>>) -> InodeHandleWrite<'_, D> {
        InodeHandleWrite::new(self.0, self.1.write(), fs)
    }
}

impl InodeReference for InodeHandle {
    fn index(&self) -> InodeIndex {
        self.0
    }
}

struct InodeBlock(pub(crate) [Arc<RwLock<Inode>>; INODES_PER_BLOCK]);

impl InodeBlock {
    fn snapshot(&self) -> InodeBlockSnapshot {
        std::array::from_fn(|i| self.0[i].read_arc())
    }
}

impl From<&RawInodeBlock> for BufferBox<InodeBlock> {
    fn from(value: &RawInodeBlock) -> Self {
        BufferBox::new(InodeBlock(std::array::from_fn(|i| {
            Arc::new(RwLock::new(value.0[i]))
        })))
    }
}

#[derive(Default)]
struct InodeBlocks(BTreeMap<InodeBlockIndex, InodeBlock>);

impl InodeBlocks {
    fn get<D: BlockAccess<BLOCK_SIZE>>(
        &mut self,
        block_index: InodeBlockIndex,
        device: &D,
    ) -> Result<&mut InodeBlock, Error> {
        match self.0.entry(block_index) {
            Entry::Vacant(e) => {
                let raw_block = InodeAllocator::read_block(block_index, device)?;
                let block = BufferBox::<InodeBlock>::from(&*raw_block);
                Ok(e.insert(*block))
            }
            Entry::Occupied(e) => Ok(e.into_mut()),
        }
    }

    fn handle<D: BlockAccess<BLOCK_SIZE>>(
        &mut self,
        block_index: InodeBlockIndex,
        offset: usize,
        device: &D,
    ) -> Result<Arc<RwLock<Inode>>, Error> {
        let block = self.get(block_index, device)?;
        Ok(block.0[offset].clone())
    }
}

pub(crate) struct InodeAllocator {
    blocks: Mutex<InodeBlocks>,
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

    pub(crate) fn get_handle_u64<D: BlockAccess<BLOCK_SIZE>>(
        &self,
        index: u64,
        device: &D,
    ) -> Result<InodeHandle, Error> {
        self.get_handle(self.inode_index_from_u64(index)?, device)
    }

    pub(crate) fn get_handle<D: BlockAccess<BLOCK_SIZE>>(
        &self,
        index: InodeIndex,
        device: &D,
    ) -> Result<InodeHandle, Error> {
        let (block_index, offset) = self.inode_index_location(index);
        let arc = self.blocks.lock().handle(block_index, offset, device)?;
        Ok(InodeHandle(index, arc))
    }

    fn read_block<D: BlockAccess<BLOCK_SIZE>>(
        block_index: InodeBlockIndex,
        device: &D,
    ) -> Result<BufferBox<RawInodeBlock>, Error> {
        let mut block = BufferBox::<RawInodeBlock>::new_uninit();
        {
            let block_ptr: *mut MaybeUninit<RawInodeBlock> = &mut *block;
            let block: &mut MaybeUninit<[u8; BLOCK_SIZE]> = unsafe { &mut *block_ptr.cast() };
            device.read(block_index.into(), block)?;
        }
        let bytes = unsafe { block.assume_init() };
        Ok(bytes)
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
                let mut blocks = self.blocks.lock();
                blocks.get(block_index, device).unwrap().snapshot()
            };

            dirty_guard = self.dirty_blocks.lock();

            Self::write_block(block_index, device, &(&snapshot).into())?;
            dirty_guard.remove(&block_index);
        }
    }

    pub(crate) fn alloc<D: BlockAccess<BLOCK_SIZE>>(
        &self,
        fs: Arc<FilesystemInner<D>>,
        value: &Inode,
    ) -> Result<InodeHandle, Error> {
        if value.is_kind(InodeType::Free)? {
            return Err(Error::Invalid);
        }

        let cursor = *self.alloc_cursor.lock();
        let mut iter = (cursor.0..self.block_range.end.0).chain(self.block_range.start.0..cursor.0);

        for block_index in &mut iter {
            let block_index = InodeBlockIndex(block_index);
            let mut blocks = self.blocks.lock();
            let block = blocks.get(block_index, &fs.device)?;

            let scan_result = block.0.iter().enumerate().find_map(|(o, arc)| {
                arc.try_upgradable_read()
                    .filter(|g| g.is_kind(InodeType::Free) == Ok(true))
                    .map(|g| (o, arc, g))
            });

            let Some((offset, arc, guard)) = scan_result else {
                continue;
            };
            let index = self.inode_index_from_location(block_index, offset);

            let mut guard =
                InodeHandleWrite::new(index, RwLockUpgradableReadGuard::upgrade(guard), fs);

            *guard = *value;
            log::debug!("alloc {index:?}");

            *self.alloc_cursor.lock() = block_index;
            return Ok(InodeHandle(index, arc.clone()));
        }

        log::error!("alloc failed");
        Err(Error::OutOfSpace)
    }

    pub(crate) fn dirty_inode_block(&self, inode_index: InodeIndex) {
        let block = self.inode_index_location(inode_index).0;
        log::debug!("dirty inode {inode_index:?} {block:?}");
        self.dirty_blocks.lock().insert(block);
    }

    pub(crate) fn free<D: BlockAccess<BLOCK_SIZE>>(
        &self,
        inode: &mut InodeHandleWrite<D>,
        block_alloc: &Mutex<BitmapAllocator>,
        device: &D,
    ) -> Result<(), Error> {
        log::debug!("free {:?}", inode.index());
        if inode.is_kind(InodeType::Free)? || inode.nlink != 0 {
            log::error!("invalid free {:?}", inode.index());
            return Err(Error::Invalid);
        }

        self.free_data_blocks(inode, block_alloc, device)?;

        *inode.deref_mut() = Inode::zeroed();

        Ok(())
    }

    pub(crate) fn free_data_blocks<D: BlockAccess<BLOCK_SIZE>>(
        &self,
        inode: &mut InodeHandleWrite<D>,
        block_alloc: &Mutex<BitmapAllocator>,
        device: &D,
    ) -> Result<(), Error> {
        let mut block_alloc = block_alloc.lock();
        inode.direct_blocks.iter_mut().try_for_each(|b| {
            if let Some(data_block) = *b {
                block_alloc.free(device, data_block).inspect(|_| {
                    *b = None;
                })
            } else {
                Ok(())
            }
        })
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
        let out = InodeIndex(NonZeroU64::new(index).ok_or(Error::NotFound)?);
        let block =
            InodeBlockIndex((out.ordinal() / INODES_PER_BLOCK as u64) + self.block_range.start.0);

        if !self.block_range.contains(&block) {
            return Err(Error::NotFound);
        }
        Ok(out)
    }
}
