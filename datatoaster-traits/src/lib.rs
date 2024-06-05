#![no_std]

extern crate no_std_compat as std;
use std::prelude::v1::*;

use std::mem::MaybeUninit;

#[derive(Clone, Copy, PartialEq, PartialOrd, Ord, Eq, Debug)]
pub struct BlockIndex(pub u64);

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    General,
    IO,
    Invalid,
}

pub trait BlockAccess<const BLOCK_SIZE: usize> {
    fn read(
        &self,
        block_idx: BlockIndex,
        buffer: &mut MaybeUninit<[u8; BLOCK_SIZE]>,
    ) -> Result<(), Error>;
    fn write(&self, block_idx: BlockIndex, buffer: &[u8; BLOCK_SIZE]) -> Result<(), Error>;
    /// Returns the size of the device in blocks, must be constant.
    fn device_size(&self) -> Result<BlockIndex, Error>;
}
