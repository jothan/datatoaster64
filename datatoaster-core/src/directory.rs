use std::prelude::v1::*;

use std::num::NonZeroU64;

use bytemuck::Zeroable;

use super::inode::{InodeIndex, InodeType};
use crate::{Error, BLOCK_SIZE};

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
