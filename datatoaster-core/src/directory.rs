use std::prelude::v1::*;

use std::num::NonZeroU64;
use std::ops::{Deref, DerefMut};

use bytemuck::Zeroable;
use itertools::Itertools;

use crate::buffers::BufferBox;
use crate::inode::{Inode, InodeHandleWrite, InodeHolder, InodeIndex, InodeReference, InodeType};
use crate::{
    inode::{FileBlockIndex, NB_DIRECT_BLOCKS},
    BlockAccess, Error, FilesystemInner, BLOCK_SIZE,
};

pub const MAX_FILENAME_LENGTH: usize = 54;
pub(crate) const DIRENTRY_SIZE: usize = std::mem::size_of::<DiskDirEntry>();
pub(crate) const DIRENTRY_PER_BLOCK: usize = BLOCK_SIZE / DIRENTRY_SIZE;

#[derive(bytemuck::Zeroable, bytemuck::Pod, Clone, Copy, Debug)]
#[repr(C)]
pub(crate) struct DiskDirEntry {
    inode: Option<InodeIndex>,
    kind: u16,
    name: [u8; MAX_FILENAME_LENGTH],
}

impl DiskDirEntry {
    fn new(inode: InodeIndex, name: &[u8], kind: InodeType) -> Result<DiskDirEntry, Error> {
        let mut dirent = DiskDirEntry {
            inode: Some(inode),
            kind: kind as _,
            name: [0; MAX_FILENAME_LENGTH],
        };

        dirent.set_name(name)?;
        Ok(dirent)
    }

    pub(crate) fn set_name(&mut self, name: &[u8]) -> Result<(), Error> {
        if name.len() > MAX_FILENAME_LENGTH {
            return Err(Error::NameTooLong);
        }
        self.name[..name.len()].copy_from_slice(name);
        self.name[name.len()..].fill(0);

        Ok(())
    }

    pub(crate) fn for_inode<H: InodeHolder>(inode: &H, name: &[u8]) -> Result<Self, Error> {
        let mut dirent = DiskDirEntry {
            inode: Some(inode.index()),
            kind: inode.kind as _,
            name: [0; MAX_FILENAME_LENGTH],
        };
        dirent.set_name(name)?;
        Ok(dirent)
    }

    pub(crate) fn new_file(inode: InodeIndex, name: &[u8]) -> Result<DiskDirEntry, Error> {
        Self::new(inode, name, InodeType::File)
    }

    pub(crate) fn new_directory(inode: InodeIndex, name: &[u8]) -> Result<DiskDirEntry, Error> {
        Self::new(inode, name, InodeType::Directory)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.inode.is_none()
    }

    pub(crate) fn name(&self) -> &[u8] {
        let zero = self
            .name
            .iter()
            .position(|c| *c == 0)
            .unwrap_or(MAX_FILENAME_LENGTH);

        &self.name[..zero]
    }

    pub(crate) fn kind(&self) -> Option<InodeType> {
        InodeType::try_from(self.kind).ok()
    }

    pub(crate) fn inode(&self) -> Option<NonZeroU64> {
        self.inode.map(Into::into)
    }

    pub(crate) fn set_inode(&mut self, index: InodeIndex) {
        self.inode = index.into();
    }

    pub(crate) fn check_name(name: &[u8]) -> Result<(), Error> {
        if name.len() > MAX_FILENAME_LENGTH {
            return Err(Error::NameTooLong);
        }

        if name.contains(&b'/') || name.contains(&0) {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct DirEntry {
    inode: NonZeroU64,
    kind: InodeType,
    name: heapless::Vec<u8, MAX_FILENAME_LENGTH>,
}

impl DirEntry {
    pub fn name(&self) -> &[u8] {
        self.name.as_slice()
    }

    pub fn kind(&self) -> InodeType {
        self.kind
    }

    pub fn inode(&self) -> u64 {
        self.inode.get()
    }
}

impl TryFrom<&DiskDirEntry> for DirEntry {
    type Error = Error;

    fn try_from(value: &DiskDirEntry) -> Result<Self, Error> {
        let Some(inode) = value.inode else {
            return Err(Error::Invalid);
        };
        let kind = value.kind.try_into()?;
        let mut name = heapless::Vec::new();

        name.extend_from_slice(value.name()).unwrap();

        Ok(DirEntry {
            inode: inode.into(),
            kind,
            name,
        })
    }
}

#[derive(
    bytemuck::AnyBitPattern, bytemuck::TransparentWrapper, bytemuck::NoUninit, Clone, Copy,
)]
#[repr(transparent)]
pub(crate) struct DirEntryBlock(pub(crate) [DiskDirEntry; DIRENTRY_PER_BLOCK]);

impl DirEntryBlock {
    pub(crate) fn new_first_block(
        inode: InodeIndex,
        parent: InodeIndex,
    ) -> BufferBox<DirEntryBlock> {
        let mut block: BufferBox<DirEntryBlock> = bytemuck::zeroed_box();

        block.0[0] = DiskDirEntry::new_directory(inode, b".").unwrap();
        block.0[1] = DiskDirEntry::new_directory(parent, b"..").unwrap();

        block
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &DiskDirEntry> {
        self.0.iter()
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut DiskDirEntry> {
        self.0.iter_mut()
    }

    pub(crate) fn first_free_entry(&mut self) -> Option<(usize, &mut DiskDirEntry)> {
        self.iter_mut()
            .enumerate()
            .find(|(_, dentry)| dentry.is_empty())
    }

    pub(crate) fn with_name(&self, name: &[u8]) -> Option<(usize, DiskDirEntry)> {
        self.iter().enumerate().find_map(|(offset, dentry)| {
            if !dentry.is_empty() && dentry.name() == name {
                Some((offset, *dentry))
            } else {
                None
            }
        })
    }
}

impl IntoIterator for DirEntryBlock {
    type Item = DiskDirEntry;
    type IntoIter = std::array::IntoIter<DiskDirEntry, DIRENTRY_PER_BLOCK>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[derive(Clone, Copy)]
pub(crate) struct DirectoryInode<'inode>(InodeIndex, &'inode Inode);

impl<'inode> InodeReference for DirectoryInode<'inode> {
    fn index(&self) -> InodeIndex {
        self.0
    }
}

impl<'inode> DirectoryInode<'inode> {
    pub(crate) fn new<H: InodeHolder + ?Sized>(holder: &'inode H) -> Result<Self, Error> {
        holder.deref().ensure_is_directory()?;
        Ok(DirectoryInode(holder.index(), holder.deref()))
    }

    fn block_iter<D: BlockAccess<BLOCK_SIZE>>(
        self,
        fs: &'inode FilesystemInner<D>,
    ) -> Result<
        impl Iterator<Item = Result<(FileBlockIndex, Option<BufferBox<DirEntryBlock>>), Error>> + 'inode,
        Error,
    > {
        Ok(self
            .1
            .data_block_iter(fs)
            .map_ok(|(block_num, byte_block)| {
                (
                    block_num,
                    // The alignments don't match up, this reallocation is a bit clumsy.
                    byte_block.map(|bb| BufferBox::new(bytemuck::pod_read_unaligned(&*bb))),
                )
            }))
    }

    fn alloc_block_iter<D: BlockAccess<BLOCK_SIZE>>(
        self,
        fs: &'inode FilesystemInner<D>,
    ) -> Result<
        impl Iterator<Item = Result<(FileBlockIndex, BufferBox<DirEntryBlock>), Error>> + '_,
        Error,
    > {
        Ok(
            self.block_iter(fs)?
                .filter_map_ok(|(block_num, block_data)| block_data.map(|bd| (block_num, bd))), // Take out the option
        )
    }

    pub(crate) fn readdir_iter<D: BlockAccess<BLOCK_SIZE>>(
        self,
        fs: &'inode FilesystemInner<D>,
        start: u64,
    ) -> Result<impl Iterator<Item = Result<(u64, DiskDirEntry), Error>> + '_, Error> {
        let skip_blocks = usize::try_from(start / DIRENTRY_PER_BLOCK as u64).unwrap();
        let skip_entries = usize::try_from(start % DIRENTRY_PER_BLOCK as u64).unwrap();
        let base_iter = self.block_iter(fs)?;

        // Yes, this is deranged.
        let iter = base_iter
            .skip(skip_blocks)
            .filter_map_ok(|(block_num, block_data)| block_data.map(|bd| (block_num, bd))) // Take out the option
            .map_ok(move |(block_num, block)| {
                let skip = if usize::from(block_num) == skip_blocks {
                    skip_entries
                } else {
                    0
                };
                block
                    .into_iter()
                    .enumerate()
                    .skip(skip)
                    .map(move |(offset, dent)| {
                        (
                            ((usize::from(block_num) * DIRENTRY_PER_BLOCK) + offset) as u64,
                            dent,
                        )
                    })
                    .filter(|(_, dent)| !dent.is_empty())
            })
            .flatten_ok();

        Ok(iter)
    }

    pub(crate) fn lookup<D: BlockAccess<BLOCK_SIZE>>(
        self,
        fs: &FilesystemInner<D>,
        name: &[u8],
    ) -> Result<(FileBlockIndex, usize, BufferBox<DirEntryBlock>), Error> {
        self.alloc_block_iter(fs)?
            .filter_map_ok(move |(block_num, block)| {
                block
                    .with_name(name)
                    .map(|(offset, _)| (block_num, offset, block))
            })
            .next()
            .ok_or(Error::NotFound)?
    }

    pub(crate) fn free_slot<D: BlockAccess<BLOCK_SIZE>>(
        self,
        fs: &FilesystemInner<D>,
    ) -> Result<(FileBlockIndex, usize, BufferBox<DirEntryBlock>), Error> {
        self.alloc_block_iter(fs)?
            .filter_map_ok(|(block_num, mut block)| {
                block
                    .first_free_entry()
                    .map(|(offset, _)| offset)
                    .map(|offset| (block_num, offset, block))
            })
            .next()
            .ok_or(Error::OutOfSpace)?
    }

    pub(crate) fn nb_slots_free(self) -> usize {
        let nb_alloc_slots = self.nb_alloc_blocks() * DIRENTRY_PER_BLOCK;
        nb_alloc_slots.checked_sub(self.size as usize).unwrap()
    }

    pub(crate) fn is_full(self) -> bool {
        self.nb_alloc_blocks() == NB_DIRECT_BLOCKS && self.nb_slots_free() == 0
    }
}

impl<'inode> Deref for DirectoryInode<'inode>
where
    Self: 'inode,
{
    type Target = Inode;

    fn deref(&self) -> &Self::Target {
        self.1
    }
}

pub(crate) struct DirectoryInodeMut<'inode, D>(InodeIndex, InodeHandleWrite<'inode, D>);

impl<'inode, D> InodeReference for DirectoryInodeMut<'inode, D> {
    fn index(&self) -> InodeIndex {
        self.0
    }
}

impl<'inode, D> Deref for DirectoryInodeMut<'inode, D> {
    type Target = InodeHandleWrite<'inode, D>;

    fn deref(&self) -> &Self::Target {
        &self.1
    }
}

impl<'inode, D> DerefMut for DirectoryInodeMut<'inode, D> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.1
    }
}

impl<'inode, D: BlockAccess<BLOCK_SIZE>> DirectoryInodeMut<'inode, D> {
    pub(crate) fn new(holder: InodeHandleWrite<'inode, D>) -> Result<Self, Error> {
        holder.ensure_is_directory()?;
        Ok(DirectoryInodeMut(holder.index(), holder))
    }

    pub(crate) fn as_ref(&self) -> DirectoryInode<'_> {
        DirectoryInode(self.index(), self.deref())
    }

    pub(crate) fn insert_dirent(
        &mut self,
        fs: &FilesystemInner<D>,
        new_dirent: &DiskDirEntry,
    ) -> Result<(), Error> {
        if self.as_ref().nb_slots_free() == 0 {
            // Allocate a fresh directory block
            let new_block = self.first_hole().ok_or(Error::Invalid)?;

            let mut block_data = DirEntryBlock::zeroed();
            block_data.0[0] = *new_dirent;

            self.write_block(new_block, bytemuck::must_cast_ref(&block_data))?;
        } else {
            // Insert into an existing block
            let (block_num, offset, mut block_data) = self.as_ref().free_slot(fs)?;
            block_data.0[offset] = *new_dirent;
            self.write_block(block_num, bytemuck::must_cast_ref(&*block_data))?;
        }

        Ok(())
    }
}
