use std::prelude::v1::*;

use std::num::NonZeroU64;

use bytemuck::Zeroable;

use super::inode::{InodeIndex, InodeType};
use crate::{Error, BLOCK_SIZE};

const MAX_FILENAME_LENGTH: usize = 54;
pub(crate) const DIRENTRY_PER_BLOCK: usize = BLOCK_SIZE / std::mem::size_of::<DiskDirEntry>();

#[derive(bytemuck::Zeroable, bytemuck::Pod, Clone, Copy, Debug)]
#[repr(C)]
pub(crate) struct DiskDirEntry {
    inode: Option<InodeIndex>,
    kind: u16,
    name: [u8; MAX_FILENAME_LENGTH],
}

impl DiskDirEntry {
    pub(crate) fn is_empty(&self) -> bool {
        self.inode.is_none()
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

        let zero = value
            .name
            .iter()
            .position(|c| *c == 0)
            .unwrap_or(MAX_FILENAME_LENGTH);
        name.extend_from_slice(&value.name[..zero]).unwrap();

        Ok(DirEntry {
            inode: inode.0,
            kind,
            name,
        })
    }
}

#[derive(
    bytemuck::NoUninit, bytemuck::AnyBitPattern, bytemuck::TransparentWrapper, Clone, Copy,
)]
#[repr(transparent)]
pub(crate) struct DirEntryBlock(pub(crate) [DiskDirEntry; DIRENTRY_PER_BLOCK]);

const EMPTY_NAME: [u8; MAX_FILENAME_LENGTH] = [0; MAX_FILENAME_LENGTH];

impl DirEntryBlock {
    pub(crate) fn new_empty(inode: InodeIndex, parent: InodeIndex) -> DirEntryBlock {
        let mut block = [Zeroable::zeroed(); DIRENTRY_PER_BLOCK];
        let mut self_name = EMPTY_NAME;
        self_name[0] = b'.';

        let mut parent_name = EMPTY_NAME;
        parent_name[0] = b'.';
        parent_name[1] = b'.';

        block[0] = DiskDirEntry {
            inode: Some(inode),
            kind: InodeType::Directory as _,
            name: self_name,
        };
        block[1] = DiskDirEntry {
            inode: Some(parent),
            kind: InodeType::Directory as _,
            name: parent_name,
        };

        DirEntryBlock(block)
    }
}
