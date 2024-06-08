use std::prelude::v1::*;

use std::collections::{btree_map::Entry, BTreeMap};
use std::num::NonZeroU16;
use std::sync::Arc;

use datatoaster_traits::BlockAccess;

use crate::directory::DirectoryInode;
use crate::inode::{FileBlockIndex, InodeHandle, InodeIndex};
use crate::{DirEntry, Error, FilesystemInner, BLOCK_SIZE};

pub(crate) struct RawFileHandle<D: BlockAccess<BLOCK_SIZE>> {
    pub(crate) fs: Arc<FilesystemInner<D>>,
    pub(crate) inode: Option<InodeHandle>,
}

impl<D: BlockAccess<BLOCK_SIZE>> RawFileHandle<D> {
    fn inode(&self) -> Option<&InodeHandle> {
        self.inode.as_ref()
    }
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
        if let Err(e) = self.close() {
            log::error!("Error closing raw file handle in drop: {e}")
        }
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
        let Some(InodeHandle(_, inode)) = self.0.inode() else {
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

pub struct FileHandle<D: BlockAccess<BLOCK_SIZE>>(pub(crate) RawFileHandle<D>);

impl<D: BlockAccess<BLOCK_SIZE>> FileHandle<D> {
    pub fn pwrite(&mut self, position: i64, mut data: &[u8]) -> Result<(), Error> {
        // TODO: truncate large writes and return the number of bytes written.
        let Some(InodeHandle(inode_index, inode)) = self.0.inode() else {
            return Err(Error::Invalid);
        };
        let position = u64::try_from(position).map_err(|_| Error::Invalid)?;

        let data_length = data.len();
        let (mut data_block, mut offset) = FileBlockIndex::from_operation(position, data.len())?;

        let mut guard = inode.write();

        while !data.is_empty() {
            let op_len = std::cmp::min(BLOCK_SIZE - offset, data.len());
            let op_data;
            (op_data, data) = data.split_at(op_len);

            if let Ok(op_data) = op_data.try_into() {
                log::debug!("{inode_index:?} full write to {data_block:?}");
                guard.write_block(*inode_index, &self.0.fs, data_block, op_data)?;
            } else {
                let mut buffer = if let Some(buffer) = guard.read_block(&self.0.fs, data_block)? {
                    log::debug!(
                        "{inode_index:?} RMW write to {data_block:?} offset {offset} length {}",
                        op_data.len()
                    );

                    buffer
                } else {
                    log::debug!(
                        "{inode_index:?} partial zero write to {data_block:?} offset {offset} length {}",
                        op_data.len()
                    );

                    [0u8; BLOCK_SIZE]
                };

                buffer[offset..offset + op_data.len()].copy_from_slice(op_data);
                guard.write_block(*inode_index, &self.0.fs, data_block, &buffer)?;
            }

            if !data.is_empty() {
                offset = 0;
                data_block.increment()?;
            }
        }

        guard.size = std::cmp::max(guard.size, position + data_length as u64);
        self.0.fs.inodes.dirty_inode_block(*inode_index);

        Ok(())
    }
    pub fn close(&mut self) -> Result<(), Error> {
        if self.0.is_closed() {
            return Err(Error::Invalid);
        }
        self.0.close()
    }
}
