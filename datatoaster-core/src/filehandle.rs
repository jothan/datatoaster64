use std::prelude::v1::*;

use std::collections::{btree_map::Entry, BTreeMap};
use std::num::NonZeroU16;
use std::sync::Arc;

use datatoaster_traits::BlockAccess;

use crate::directory::DirectoryInode;
use crate::inode::{FileBlockIndex, InodeHandle, InodeHolder, InodeIndex, InodeReference};
use crate::{DirEntry, Error, FilesystemInner, BLOCK_SIZE};

pub(crate) struct RawFileHandle<D: BlockAccess<BLOCK_SIZE>> {
    pub(crate) fs: Arc<FilesystemInner<D>>,
    pub(crate) inode: Option<InodeHandle>,
}

impl<D: BlockAccess<BLOCK_SIZE>> RawFileHandle<D> {
    pub(crate) fn inode(&self) -> Option<InodeHandle> {
        self.inode.clone()
    }
}

impl<D: BlockAccess<BLOCK_SIZE>> RawFileHandle<D> {
    pub(crate) fn open(
        inode_index: InodeIndex,
        fs: Arc<FilesystemInner<D>>,
    ) -> Result<Self, Error> {
        fs.open_counter.lock().increment(inode_index)?;
        let inode = fs.inodes.get_handle(inode_index, &fs.device)?;

        Ok(RawFileHandle {
            fs,
            inode: Some(inode),
        })
    }

    fn close(&mut self) -> Result<(), Error> {
        let Some(inode) = self.inode.take() else {
            return Ok(());
        };

        let mut open_counter = self.fs.open_counter.lock();
        let open_count = open_counter.decrement(inode.0)?;

        let guard = inode.upgradable_read();
        drop(open_counter);
        if guard.nlink == 0 && open_count.is_none() {
            let mut guard = guard.upgrade(self.fs.clone());
            self.fs
                .inodes
                .free(&mut guard, &self.fs.alloc, &self.fs.device)?;

            log::info!("{:?} unlink on close", inode.index())
        } else if guard.nlink == 0 {
            log::warn!(
                "{:?} is dangling (0 links and still open {} times), unlinking on close",
                inode.index(),
                open_count.unwrap()
            )
        }
        Ok(())
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
    pub(crate) fn is_open(&self, index: InodeIndex) -> bool {
        self.0.contains_key(&index)
    }

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
        let Some(inode_handle) = self.0.inode() else {
            return Err(Error::Invalid);
        };
        let guard = inode_handle.read();

        // Summon the ancient one
        let dir_inode: DirectoryInode = guard.as_dir()?;
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
    pub fn pread(&self, position: i64, data: &mut [u8]) -> Result<usize, Error> {
        let Some(inode) = self.0.inode() else {
            return Err(Error::Invalid);
        };
        let position = position.try_into().unwrap();
        let guard = inode.read();
        let data_length = guard.trim_read_op(position, data.len())?;
        let data = &mut data[..data_length];

        let (mut data_block, mut offset) = FileBlockIndex::from_file_position(position)?;

        let mut data_remaining = data;

        while !data_remaining.is_empty() {
            let op_len = std::cmp::min(BLOCK_SIZE - offset, data_remaining.len());
            let op_data;
            (op_data, data_remaining) = data_remaining.split_at_mut(op_len);

            if let Some(buffer) = guard.read_block(&self.0.fs, data_block)? {
                op_data.copy_from_slice(&buffer[offset..offset + op_data.len()]);
            } else {
                op_data.fill(0);
            }

            if !data_remaining.is_empty() {
                offset = 0;
                data_block.increment()?;
            }
        }

        Ok(data_length)
    }

    pub fn pwrite(&self, position: i64, data: &[u8]) -> Result<usize, Error> {
        let Some(inode) = self.0.inode() else {
            return Err(Error::Invalid);
        };
        let position = position.try_into().unwrap();
        let mut guard = inode.write(self.0.fs.clone());

        let data_length = guard.trim_write_op(position, data.len())?;
        let data = &data[..data_length];

        let (mut data_block, mut offset) = FileBlockIndex::from_file_position(position)?;

        let mut data_remaining = data;

        while !data_remaining.is_empty() {
            let op_len = std::cmp::min(BLOCK_SIZE - offset, data_remaining.len());
            let op_data;
            (op_data, data_remaining) = data_remaining.split_at(op_len);

            if let Ok(op_data) = op_data.try_into() {
                log::debug!("{:?} full write to {data_block:?}", inode.index());
                guard.write_block(&self.0.fs, data_block, op_data)?;
            } else {
                let mut buffer = if let Some(buffer) = guard.read_block(&self.0.fs, data_block)? {
                    log::debug!(
                        "{:?} RMW write to {data_block:?} offset {offset} length {}",
                        inode.index(),
                        op_data.len()
                    );

                    buffer
                } else {
                    log::debug!(
                        "{:?} partial zero write to {data_block:?} offset {offset} length {}",
                        inode.index(),
                        op_data.len()
                    );

                    bytemuck::zeroed_box()
                };

                buffer[offset..offset + op_data.len()].copy_from_slice(op_data);
                guard.write_block(&self.0.fs, data_block, &buffer)?;
            }

            if !data_remaining.is_empty() {
                offset = 0;
                data_block.increment()?;
            }
        }

        guard.size = std::cmp::max(guard.size, position + data.len() as u64);

        Ok(data.len())
    }

    pub fn close(&mut self) -> Result<(), Error> {
        if self.0.is_closed() {
            return Err(Error::Invalid);
        }
        self.0.close()
    }
}
