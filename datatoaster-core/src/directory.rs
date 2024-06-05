use std::prelude::v1::*;

use bytemuck::Zeroable;

use super::inode::{InodeIndex, InodeType};
use crate::BLOCK_SIZE;

const MAX_FILENAME_LENGTH: usize = 54;
pub(crate) const DIRENTRY_PER_BLOCK: usize = BLOCK_SIZE / std::mem::size_of::<DirEntry>();

#[derive(bytemuck::Zeroable, bytemuck::Pod, Clone, Copy, Debug)]
#[repr(C)]
pub(crate) struct DirEntry {
    inode: Option<InodeIndex>,
    kind: u16,
    name: [u8; MAX_FILENAME_LENGTH],
}

#[derive(bytemuck::Zeroable, bytemuck::NoUninit, bytemuck::TransparentWrapper, Clone, Copy)]
#[repr(transparent)]
pub(crate) struct DirEntryBlock([DirEntry; DIRENTRY_PER_BLOCK]);

const EMPTY_NAME: [u8; MAX_FILENAME_LENGTH] = [0; MAX_FILENAME_LENGTH];

impl DirEntryBlock {
    pub(crate) fn new_empty(inode: InodeIndex, parent: InodeIndex) -> DirEntryBlock {
        let mut block = [Zeroable::zeroed(); DIRENTRY_PER_BLOCK];
        let mut self_name = EMPTY_NAME;
        self_name[0] = b'.';

        let mut parent_name = EMPTY_NAME;
        parent_name[0] = b'.';
        parent_name[1] = b'.';

        block[0] = DirEntry {
            inode: Some(inode),
            kind: InodeType::Directory as _,
            name: self_name,
        };
        block[1] = DirEntry {
            inode: Some(parent),
            kind: InodeType::Directory as _,
            name: parent_name,
        };

        DirEntryBlock(block)
    }
}
