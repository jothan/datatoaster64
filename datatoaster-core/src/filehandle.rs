use std::prelude::v1::*;

use std::collections::{btree_map::Entry, BTreeMap};
use std::num::NonZeroU16;
use std::sync::Arc;

use datatoaster_traits::BlockAccess;

use crate::inode::{DirectoryInode, InodeHandle, InodeIndex};
use crate::{DirEntry, Error, FilesystemInner, BLOCK_SIZE};

pub(crate) struct RawFileHandle<D: BlockAccess<BLOCK_SIZE>> {
    pub(crate) fs: Arc<FilesystemInner<D>>,
    pub(crate) inode: Option<InodeHandle>,
}

impl<D: BlockAccess<BLOCK_SIZE>> RawFileHandle<D> {
    pub(crate) fn new(fs: Arc<FilesystemInner<D>>, inode: InodeHandle) -> Self {
        RawFileHandle {
            fs,
            inode: Some(inode),
        }
    }

    fn close(&mut self) -> Result<(), Error> {
        let Some(inode) = self.inode.take() else {
            return Ok(());
        };

        self.fs.raw_file_close(inode)
    }

    fn is_closed(&self) -> bool {
        self.inode.is_none()
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

pub struct DirectoryHandle<D: BlockAccess<BLOCK_SIZE>>(pub(crate) RawFileHandle<D>);

impl<D: BlockAccess<BLOCK_SIZE>> DirectoryHandle<D> {
    pub fn readdir(
        &self,
        start: u64,
        mut f: impl FnMut(u64, DirEntry) -> bool,
    ) -> Result<(), Error> {
        let Some(InodeHandle(_, inode)) = self.0.inode.as_ref() else {
            return Err(Error::Invalid);
        };
        let guard = inode.read();

        // Summon the ancient one
        let dir_inode = DirectoryInode::try_from(&*guard)?;
        let mut chutulu = dir_inode.readdir_iter(&self.0.fs, start)?;

        while let Some((offset, direntry)) = chutulu.next().transpose()? {
            if f(offset, (&direntry).try_into()?) {
                break;
            }
        }

        Ok(())
    }

    pub fn close(&mut self) -> Result<(), Error> {
        if self.0.is_closed() {
            return Err(Error::Invalid);
        }
        self.0.close()
    }
}
