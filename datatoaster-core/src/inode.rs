use std::prelude::v1::*;

use std::num::NonZeroU64;

use crate::{DataBlockIndex, BLOCK_SIZE};

const NB_DIRECT_BLOCKS: usize = 13;
pub(crate) const INODES_PER_BLOCK: usize = BLOCK_SIZE / std::mem::size_of::<Inode>();

#[derive(bytemuck::TransparentWrapper, Clone, Copy, Debug)]
#[repr(transparent)]
pub(crate) struct InodeIndex(NonZeroU64);

pub(crate) const ROOT_DIRECTORY_INODE: InodeIndex =
    InodeIndex(unsafe { NonZeroU64::new_unchecked(2) });

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
pub(crate) struct InodeBlock(pub(crate) [Inode; INODES_PER_BLOCK]);
