use std::prelude::v1::*;

use std::collections::{btree_map::Entry, BTreeMap};
use std::mem::MaybeUninit;
use std::num::NonZeroU16;
use std::sync::Arc;

use datatoaster_traits::BlockAccess;

use crate::inode::{InodeHandle, InodeIndex, INODES_PER_BLOCK};
use crate::{Error, FilesystemInner, BLOCK_SIZE};

#[derive(Clone, Copy, Ord, PartialOrd, PartialEq, Eq)]
struct FileBlockIndex(u64);

impl FileBlockIndex {
    fn new(block: u64) -> Result<FileBlockIndex, Error> {
        if block < INODES_PER_BLOCK as u64 {
            Ok(FileBlockIndex(block))
        } else {
            Err(Error::Invalid)
        }
    }
}

pub(crate) struct RawFileHandle<D: BlockAccess<BLOCK_SIZE>> {
    fs: Arc<FilesystemInner<D>>,
    inode: Option<InodeHandle>,
    inode_index: InodeIndex,
}

impl<D: BlockAccess<BLOCK_SIZE>> RawFileHandle<D> {
    pub(crate) fn new(
        fs: Arc<FilesystemInner<D>>,
        inode_index: InodeIndex,
        inode: InodeHandle,
    ) -> Self {
        RawFileHandle {
            fs,
            inode: Some(inode),
            inode_index,
        }
    }

    // Returns None if reading a hole
    // FIXME: returning a big value.
    fn read_block(&self, block: FileBlockIndex) -> Result<Option<[u8; BLOCK_SIZE]>, Error> {
        let Some(inode) = self.inode.as_ref() else {
            return Err(Error::Invalid);
        };

        let inode = inode.read();
        let Some(data_block) = inode.direct_blocks[block.0 as usize] else {
            return Ok(None);
        };
        let mut buffer: MaybeUninit<[u8; BLOCK_SIZE]> = MaybeUninit::uninit();
        self.fs.device.read(data_block.into(), &mut buffer)?;
        Ok(Some(unsafe { buffer.assume_init() }))
    }

    fn write_block(&self, block: FileBlockIndex, buffer: &[u8; BLOCK_SIZE]) -> Result<(), Error> {
        let Some(inode) = self.inode.as_ref() else {
            return Err(Error::Invalid);
        };

        let mut inode = inode.write();
        let data_block = if let Some(data_block) = inode.direct_blocks[block.0 as usize] {
            data_block
        } else {
            let data_block = self.fs.alloc_data(self.inode_index)?;
            inode.direct_blocks[block.0 as usize] = Some(data_block);
            data_block
        };

        self.fs.device.write(data_block.into(), buffer)?;
        Ok(())
    }

    fn close(&mut self) -> Result<(), Error> {
        let Some(inode) = self.inode.take() else {
            return Ok(());
        };

        self.fs.raw_file_close(inode, self.inode_index)
    }
}

impl<D: BlockAccess<BLOCK_SIZE>> Drop for RawFileHandle<D> {
    fn drop(&mut self) {
        self.close().expect("close error on inode");
    }
}

#[derive(Default, Debug)]
pub(crate) struct OpenCounter(BTreeMap<InodeIndex, NonZeroU16>);

impl OpenCounter {
    pub(crate) fn increment(&mut self, index: InodeIndex) -> Result<NonZeroU16, Error> {
        let count = match self.0.entry(index) {
            Entry::Occupied(mut e) => {
                *e.get_mut() = e.get().checked_add(1).ok_or(Error::Invalid)?;
                *e.get()
            }
            Entry::Vacant(e) => *e.insert(NonZeroU16::MIN),
        };

        Ok(count)
    }

    // Returns the count or None if the count is zero.
    pub(crate) fn decrement(&mut self, index: InodeIndex) -> Result<Option<NonZeroU16>, Error> {
        match self.0.entry(index) {
            Entry::Occupied(mut e) => match *e.get() {
                NonZeroU16::MIN => {
                    e.remove();
                    Ok(None)
                }
                _ => {
                    *e.get_mut() = NonZeroU16::new(e.get().get() - 1).unwrap();
                    Ok(Some(*e.get()))
                }
            },
            Entry::Vacant(_) => Err(Error::Invalid),
        }
    }
}
