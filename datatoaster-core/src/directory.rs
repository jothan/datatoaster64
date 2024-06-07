use std::prelude::v1::*;

use std::num::NonZeroU64;

use bytemuck::Zeroable;
use itertools::Itertools;

use crate::inode::{Inode, InodeIndex, InodeType};
use crate::{
    inode::{FileBlockIndex, NB_DIRECT_BLOCKS},
    BlockAccess, Error, FilesystemInner, BLOCK_SIZE,
};

pub(crate) const MAX_FILENAME_LENGTH: usize = 54;
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
        if name.len() > MAX_FILENAME_LENGTH {
            return Err(Error::NameTooLong);
        }

        let mut dirent = DiskDirEntry {
            inode: Some(inode),
            kind: kind as _,
            name: [0; MAX_FILENAME_LENGTH],
        };

        dirent.name[..name.len()].copy_from_slice(name);
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

    pub(crate) fn inode(&self) -> Option<NonZeroU64> {
        self.inode.map(|i| i.0)
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
            inode: inode.0,
            kind,
            name,
        })
    }
}

#[derive(bytemuck::Zeroable, bytemuck::Pod, bytemuck::TransparentWrapper, Clone, Copy)]
#[repr(transparent)]
pub(crate) struct DirEntryBlock(pub(crate) [DiskDirEntry; DIRENTRY_PER_BLOCK]);

impl DirEntryBlock {
    pub(crate) fn new_first_block(inode: InodeIndex, parent: InodeIndex) -> DirEntryBlock {
        let mut block = [Zeroable::zeroed(); DIRENTRY_PER_BLOCK];

        block[0] = DiskDirEntry::new_directory(inode, b".").unwrap();
        block[1] = DiskDirEntry::new_directory(parent, b"..").unwrap();

        DirEntryBlock(block)
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
pub(crate) struct DirectoryInode<'inode>(&'inode Inode);

impl<'inode> TryFrom<&'inode Inode> for DirectoryInode<'inode> {
    type Error = Error;

    fn try_from(value: &'inode Inode) -> Result<Self, Self::Error> {
        if InodeType::try_from(value.kind)? != InodeType::Directory {
            return Err(Error::NotDirectory);
        }
        Ok(DirectoryInode(value))
    }
}

impl<'inode> DirectoryInode<'inode> {
    fn block_iter<D: BlockAccess<BLOCK_SIZE>>(
        self,
        fs: &'inode FilesystemInner<D>,
    ) -> Result<
        impl Iterator<Item = Result<(FileBlockIndex, Option<DirEntryBlock>), Error>> + '_,
        Error,
    > {
        Ok(self
            .0
            .data_block_iter(fs)
            .map_ok(|(block_num, byte_block)| (block_num, byte_block.map(bytemuck::cast))))
    }

    fn alloc_block_iter<D: BlockAccess<BLOCK_SIZE>>(
        self,
        fs: &'inode FilesystemInner<D>,
    ) -> Result<impl Iterator<Item = Result<(FileBlockIndex, DirEntryBlock), Error>> + '_, Error>
    {
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
    ) -> Result<(FileBlockIndex, usize, DiskDirEntry), Error> {
        self.alloc_block_iter(fs)?
            .filter_map_ok(move |(block_num, block)| {
                block
                    .with_name(name)
                    .map(|(offset, dentry)| (block_num, offset, dentry))
            })
            .next()
            .ok_or(Error::NotFound)?
    }

    pub(crate) fn free_slot<D: BlockAccess<BLOCK_SIZE>>(
        self,
        fs: &FilesystemInner<D>,
    ) -> Result<(FileBlockIndex, usize, DirEntryBlock), Error> {
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
        let nb_alloc_slots = self.0.nb_alloc_blocks() * DIRENTRY_PER_BLOCK;
        nb_alloc_slots.checked_sub(self.0.size as usize).unwrap()
    }

    pub(crate) fn is_full(self) -> bool {
        self.0.nb_alloc_blocks() == NB_DIRECT_BLOCKS && self.nb_slots_free() == 0
    }

    pub(crate) fn as_inner(self) -> &'inode Inode {
        self.0
    }
}

pub(crate) struct DirectoryInodeMut<'inode>(&'inode mut Inode);

impl<'inode> TryFrom<&'inode mut Inode> for DirectoryInodeMut<'inode> {
    type Error = Error;

    fn try_from(value: &'inode mut Inode) -> Result<Self, Self::Error> {
        if InodeType::try_from(value.kind)? != InodeType::Directory {
            return Err(Error::NotDirectory);
        }
        Ok(DirectoryInodeMut(value))
    }
}

impl<'inode> DirectoryInodeMut<'inode> {
    pub(crate) fn as_ref(&self) -> DirectoryInode<'_> {
        DirectoryInode(self.0)
    }

    pub(crate) fn as_inner(&mut self) -> &mut Inode {
        self.0
    }
}
