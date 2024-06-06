use std::prelude::v1::*;

use std::collections::{btree_map::Entry, BTreeMap};
use std::num::NonZeroU16;
use std::sync::Arc;

use datatoaster_traits::BlockAccess;

use crate::inode::{InodeHandle, InodeIndex};
use crate::{Error, FilesystemInner, BLOCK_SIZE};

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
