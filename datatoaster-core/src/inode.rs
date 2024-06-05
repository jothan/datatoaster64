use std::prelude::v1::*;

use std::num::NonZeroU64;

use crate::{DataBlockIndex, BLOCK_SIZE};

const NB_DIRECT_BLOCKS: usize = 13;
pub(crate) const INODES_PER_BLOCK: usize = BLOCK_SIZE / std::mem::size_of::<Inode>();

#[derive(bytemuck::TransparentWrapper, Clone, Copy, Debug)]
#[repr(transparent)]
pub(crate) struct InodeIndex(NonZeroU64);

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
struct Inode {
    kind: u16,
    nlink: u16,
    mode: libc::mode_t,
    uid: libc::uid_t,
    gid: libc::uid_t,
    size: u64,
    direct_blocks: [Option<DataBlockIndex>; NB_DIRECT_BLOCKS],
}

#[derive(bytemuck::Zeroable, bytemuck::NoUninit, bytemuck::TransparentWrapper, Clone, Copy)]
#[repr(transparent)]
struct InodeBlock([Inode; INODES_PER_BLOCK]);
