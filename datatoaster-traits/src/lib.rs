#![no_std]

extern crate no_std_compat as std;
use std::prelude::v1::*;

use std::mem::MaybeUninit;

use snafu::prelude::*;

#[derive(Clone, Copy, PartialEq, PartialOrd, Ord, Eq, Debug)]
pub struct BlockIndex(pub u64);

#[derive(Debug, PartialEq, Eq, Snafu)]
pub enum Error {
    #[snafu(display("General block device error"))]
    General,
    #[snafu(display("Block device I/O error"))]
    IO,
    #[snafu(display("Invalid block device condition"))]
    Invalid,
}

/// # Safety
/// read() function must completely initialize the buffer.
pub unsafe trait BlockAccess<const BLOCK_SIZE: usize> {
    fn read(
        &self,
        block_idx: BlockIndex,
        buffer: &mut MaybeUninit<[u8; BLOCK_SIZE]>,
    ) -> Result<(), Error>;
    fn write(&self, block_idx: BlockIndex, buffer: &[u8; BLOCK_SIZE]) -> Result<(), Error>;
    /// Returns the size of the device in blocks, must be constant.
    fn device_size(&self) -> Result<BlockIndex, Error>;
}
