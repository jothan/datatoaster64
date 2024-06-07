use std::prelude::v1::*;

use std::mem::MaybeUninit;

use datatoaster_traits::BlockAccess;

use super::inode::InodeIndex;
use crate::{BlockIndex, Error, BLOCK_SIZE};

const MAGIC: u64 = 0x90d18c516db2bce7;
const ENDIAN_CHECK: u64 = 0x0807060504030201;

#[derive(bytemuck::Zeroable, bytemuck::Pod, Clone, Copy, Debug)]
#[repr(C)]
pub(crate) struct SuperBlock {
    magic: u64,
    endian_check: u64,
    root_directory: Option<InodeIndex>,
}

impl SuperBlock {
    pub(crate) fn new(root_directory: InodeIndex) -> Self {
        SuperBlock {
            magic: MAGIC,
            endian_check: ENDIAN_CHECK,
            root_directory: Some(root_directory),
        }
    }

    pub(crate) fn write<D: BlockAccess<BLOCK_SIZE>>(&self, device: &D) -> Result<(), Error> {
        let mut block = [0u8; BLOCK_SIZE];
        block[0..std::mem::size_of::<SuperBlock>()].copy_from_slice(bytemuck::bytes_of(self));

        device.write(BlockIndex(0), &block)?;

        Ok(())
    }

    pub(crate) fn read<D: BlockAccess<BLOCK_SIZE>>(device: &D) -> Result<SuperBlock, Error> {
        let mut block: MaybeUninit<[u8; BLOCK_SIZE]> = MaybeUninit::uninit();
        device.read(BlockIndex(0), &mut block)?;
        let block = unsafe { block.assume_init() };

        (&block).try_into()
    }
}

impl TryFrom<&[u8; BLOCK_SIZE]> for SuperBlock {
    type Error = Error;

    fn try_from(value: &[u8; BLOCK_SIZE]) -> Result<Self, Self::Error> {
        let slice = &value.as_slice()[0..std::mem::size_of::<SuperBlock>()];
        let array: &[u8; std::mem::size_of::<SuperBlock>()] = slice.try_into().unwrap();
        let block: SuperBlock = bytemuck::pod_read_unaligned(array);

        if block.magic != MAGIC
            || block.endian_check != ENDIAN_CHECK
            || block.root_directory.is_none()
        {
            return Err(Error::SuperBlock);
        }

        Ok(block)
    }
}
