use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::{Duration, SystemTime};

#[cfg(feature = "notify")]
use std::{collections::BTreeMap, path::PathBuf};

use datatoaster_core::{DirectoryHandle, Error, FileHandle, Filesystem, InodeType, BLOCK_SIZE};
use datatoaster_traits::BlockAccess;

use signal_hook::consts::signal::*;
use signal_hook::iterator::Signals;
use slotmap::{new_key_type, Key, KeyData, SlotMap};

pub use fuser;

macro_rules! key64 {
    ($t:ident) => {
        new_key_type! { struct $t; }
        impl From<u64> for $t {
            fn from(value: u64) -> Self {
                KeyData::from_ffi(value).into()
            }
        }
        impl From<$t> for u64 {
            fn from(value: $t) -> Self {
                value.data().as_ffi()
            }
        }
    };
}

key64!(FileKey);
key64!(DirKey);

pub struct FuseFilesystem<D: BlockAccess<BLOCK_SIZE>> {
    inner: Filesystem<D>,
    open_files: SlotMap<FileKey, FileHandle<D>>,
    open_dirs: SlotMap<DirKey, DirectoryHandle<D>>,
    // For notifications: remember what name each inode was used with
    // (and the parent directory inode).
    #[cfg(feature = "notify")]
    file_names: BTreeMap<u64, (u64, Box<OsStr>)>,
    #[cfg(feature = "notify")]
    notify: bool,
}

impl<D: BlockAccess<BLOCK_SIZE>> FuseFilesystem<D> {
    #[allow(unused_variables)]
    pub fn new(device: D, notify: bool) -> Result<Self, Error> {
        assert!(fuser::FUSE_ROOT_ID == datatoaster_core::ROOT_INODE.get());

        #[allow(unused_mut)]
        let mut fs = Self {
            inner: Filesystem::mount(device)?,
            open_files: SlotMap::with_key(),
            open_dirs: SlotMap::with_key(),
            #[cfg(feature = "notify")]
            file_names: Default::default(),
            #[cfg(feature = "notify")]
            notify,
        };

        #[cfg(feature = "notify")]
        if fs.notify {
            fs.notify_init();
        }

        Ok(fs)
    }

    #[cfg(feature = "notify")]
    fn inode_to_name(&self, mut ino: u64) -> Box<Path> {
        let mut segments = Vec::<&OsStr>::new();
        loop {
            let Some((parent, name)) = self.file_names.get(&ino) else {
                break;
            };
            segments.push(name);
            ino = *parent;
        }

        if segments.is_empty() {
            segments.push(OsStrExt::from_bytes(
                b"?? a file with no name (with no horse)??",
            ));
        }

        segments.iter().rev().collect::<PathBuf>().into_boxed_path()
    }

    #[cfg(feature = "notify")]
    fn notify_init(&mut self) {
        if !self.notify {
            return;
        }

        if let Err(e) = libnotify::init("datatoaster-fuse") {
            log::error!("Could not initialize libnotify: {e:?}");
            self.notify = false;
        }
    }

    #[cfg(feature = "notify")]
    fn notify_open(&self, _ino: u64) {
        if !self.notify {
            return;
        }

        let file_name = self.inode_to_name(_ino);
        let notification = libnotify::Notification::new(
            format!("{file_name:?} was opened").as_str(),
            "Just so you know",
            "drive-harddisk",
        );
        notification.set_category("device.added");

        if let Err(e) = notification.show() {
            log::error!("Notify error: {e:?}");
        }
    }

    #[cfg(feature = "notify")]
    fn notify_closed(&self, _ino: u64) {
        if !self.notify {
            return;
        }

        let file_name = self.inode_to_name(_ino);
        let notification = libnotify::Notification::new(
            format!("{file_name:?} was closed").as_str(),
            "You might want to check that the lid is screwed on properly.",
            "face-worried",
        );
        notification.set_category("device.removed");

        if let Err(e) = notification.show() {
            log::error!("Notify error: {e:?}");
        }
    }

    #[cfg(feature = "notify")]
    fn record_name(&mut self, ino: u64, parent_ino: u64, name: &OsStr) {
        if self.notify {
            self.file_names.insert(ino, (parent_ino, name.into()));
        }
    }
}

impl<D: BlockAccess<BLOCK_SIZE> + Send + Sync + 'static> FuseFilesystem<D> {
    pub fn run(
        self,
        mountpoint: impl AsRef<Path>,
        options: &[fuser::MountOption],
    ) -> anyhow::Result<()> {
        let session = fuser::spawn_mount2(self, mountpoint, options)?;

        let mut signals = Signals::new([SIGHUP, SIGTERM, SIGINT, SIGQUIT])?;
        signals.wait();

        session.join();

        Ok(())
    }
}

impl<D: BlockAccess<BLOCK_SIZE>> fuser::Filesystem for FuseFilesystem<D> {
    fn destroy(&mut self) {
        log::info!("Syncing");
        if let Err(e) = self.inner.sync() {
            log::error!("Sync error: {e:}");
        }
    }

    fn opendir(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        _flags: i32,
        reply: fuser::ReplyOpen,
    ) {
        match self.inner.opendir(ino) {
            Ok(handle) => {
                let fh = self.open_dirs.insert(handle).into();
                log::debug!("OPENDIR fh {fh}");
                reply.opened(fh, 0)
            }
            Err(e) => reply.error(e.into()),
        }
    }

    fn release(
        &mut self,
        _req: &fuser::Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: fuser::ReplyEmpty,
    ) {
        let Some(mut handle) = self.open_files.remove(fh.into()) else {
            reply.error(libc::EBADF);
            return;
        };

        let res = handle.close().and_then(|_| self.inner.sync());

        #[cfg(feature = "notify")]
        self.notify_closed(_ino);

        match res {
            Ok(_) => reply.ok(),
            Err(e) => reply.error(e.into()),
        }
    }

    fn releasedir(
        &mut self,
        _req: &fuser::Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        reply: fuser::ReplyEmpty,
    ) {
        if self
            .open_dirs
            .remove(fh.into())
            .and_then(|mut h| h.close().ok())
            .is_some()
        {
            reply.ok()
        } else {
            reply.error(libc::EBADF)
        }
    }

    fn readdir(
        &mut self,
        _req: &fuser::Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        mut reply: fuser::ReplyDirectory,
    ) {
        let Some(handle) = self.open_dirs.get(fh.into()) else {
            reply.error(libc::EBADF);
            return;
        };

        let res = handle.readdir(offset.try_into().unwrap(), |offset, dirent| {
            let offset = i64::try_from(offset).unwrap() + 1;
            reply.add(
                dirent.inode(),
                offset,
                FileType::from(dirent.kind()).into(),
                OsStr::from_bytes(dirent.name()),
            )
        });

        match res {
            Ok(_) => reply.ok(),
            Err(e) => reply.error(e.into()),
        }
    }

    fn access(
        &mut self,
        _req: &fuser::Request<'_>,
        _ino: u64,
        _mask: i32,
        reply: fuser::ReplyEmpty,
    ) {
        reply.ok()
    }

    fn lookup(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        reply: fuser::ReplyEntry,
    ) {
        match self.inner.lookup(parent, name.as_bytes()) {
            Ok(stat) => {
                let attr = Stat::from(stat).into();
                reply.entry(&Duration::new(0, 0), &attr, 0);

                #[cfg(feature = "notify")]
                self.record_name(attr.ino, parent, name);
            }
            Err(e) => reply.error(e.into()),
        }
    }

    fn setattr(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        _size: Option<u64>,
        _atime: Option<fuser::TimeOrNow>,
        _mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: fuser::ReplyAttr,
    ) {
        // FIXME
        match self.inner.stat(ino) {
            Ok(s) => reply.attr(&Duration::new(0, 0), &Stat::from(s).into()),
            Err(e) => reply.error(e.into()),
        }
    }

    fn open(&mut self, _req: &fuser::Request<'_>, ino: u64, _flags: i32, reply: fuser::ReplyOpen) {
        match self.inner.open(ino) {
            Ok(handle) => {
                let fh = self.open_files.insert(handle).into();
                log::debug!("OPEN fh {fh}");
                reply.opened(fh, 0);

                #[cfg(feature = "notify")]
                self.notify_open(ino);
            }
            Err(e) => reply.error(e.into()),
        }
    }

    fn create(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _flags: i32,
        reply: fuser::ReplyCreate,
    ) {
        let res = self.inner.create(parent, name.as_bytes(), mode);
        let res = res.and_then(|r| {
            self.inner.sync()?;
            Ok(r)
        });

        match res {
            Ok((handle, stat)) => {
                let attr = Stat::from(stat).into();
                let fh = self.open_files.insert(handle).into();
                log::debug!("CREATE fh {fh}");
                reply.created(&Duration::new(0, 0), &attr, 0, fh, 0);

                #[cfg(feature = "notify")]
                self.record_name(attr.ino, parent, name);
            }
            Err(e) => {
                log::error!("CREATE error: {e:?}");
                reply.error(e.into())
            }
        }
    }

    fn link(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        newparent: u64,
        newname: &OsStr,
        reply: fuser::ReplyEntry,
    ) {
        let res = self.inner.link(newparent, ino, newname.as_bytes());
        let res = res.and_then(|r| {
            self.inner.sync()?;
            Ok(r)
        });

        match res {
            Ok(stat) => {
                let attr = Stat::from(stat).into();
                reply.entry(&Duration::new(0, 0), &attr, 0);
            }
            Err(e) => reply.error(e.into()),
        }
    }

    fn unlink(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &OsStr,
        reply: fuser::ReplyEmpty,
    ) {
        match self.inner.unlink(parent, name.as_bytes()) {
            Ok(_) => reply.ok(),
            Err(e) => reply.error(e.into()),
        }
    }

    fn mkdir(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: fuser::ReplyEntry,
    ) {
        let res = self
            .inner
            .mkdir(parent, name.as_bytes(), mode)
            .and_then(|r| {
                self.inner.sync()?;
                Ok(r)
            });

        match res {
            Ok(stat) => {
                let attr = Stat::from(stat).into();
                reply.entry(&Duration::new(0, 0), &attr, 0);

                #[cfg(feature = "notify")]
                self.record_name(attr.ino, parent, name);
            }
            Err(e) => {
                log::error!("MKDIR error: {e:?}");
                reply.error(e.into())
            }
        }
    }

    fn rmdir(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &OsStr,
        reply: fuser::ReplyEmpty,
    ) {
        let res = self.inner.rmdir(parent, name.as_bytes()).and_then(|r| {
            self.inner.sync()?;
            Ok(r)
        });

        match res {
            Ok(_) => reply.ok(),
            Err(e) => reply.error(e.into()),
        }
    }

    fn getattr(&mut self, _req: &fuser::Request<'_>, ino: u64, reply: fuser::ReplyAttr) {
        match self.inner.stat(ino) {
            Ok(s) => reply.attr(&Duration::new(0, 0), &Stat::from(s).into()),
            Err(e) => reply.error(e.into()),
        }
    }

    fn read(
        &mut self,
        _req: &fuser::Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: fuser::ReplyData,
    ) {
        let Some(handle) = self.open_files.get(fh.into()) else {
            reply.error(libc::EBADF);
            return;
        };

        let mut buffer = bytemuck::zeroed_slice_box(size as usize);

        match handle.pread(offset, &mut buffer) {
            Ok(read) => reply.data(&buffer[..read]),
            Err(e) => reply.error(e.into()),
        }
    }

    fn write(
        &mut self,
        _req: &fuser::Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: fuser::ReplyWrite,
    ) {
        let Some(handle) = self.open_files.get(fh.into()) else {
            reply.error(libc::EBADF);
            return;
        };

        match handle.pwrite(offset, data) {
            Ok(written) => reply.written(written as u32),
            Err(e) => reply.error(e.into()),
        }
    }

    fn rename(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: fuser::ReplyEmpty,
    ) {
        let res = self
            .inner
            .rename(parent, name.as_bytes(), newparent, newname.as_bytes())
            .and_then(|r| {
                self.inner.sync()?;
                Ok(r)
            });

        match res {
            Ok(_) => reply.ok(),
            Err(e) => reply.error(e.into()),
        }
    }
}

struct Stat(datatoaster_core::Stat);

impl From<datatoaster_core::Stat> for Stat {
    fn from(value: datatoaster_core::Stat) -> Self {
        Stat(value)
    }
}

impl From<Stat> for fuser::FileAttr {
    fn from(s: Stat) -> Self {
        fuser::FileAttr {
            ino: s.0.inode,
            size: s.0.size,
            blocks: s.0.blocks,
            perm: s.0.perm,
            nlink: s.0.nlink,
            uid: s.0.uid,
            gid: s.0.gid,
            blksize: s.0.blksize,
            kind: FileType::from(s.0.kind).into(),
            atime: SystemTime::UNIX_EPOCH,
            mtime: SystemTime::UNIX_EPOCH,
            ctime: SystemTime::UNIX_EPOCH,
            crtime: SystemTime::UNIX_EPOCH,
            rdev: 0,
            flags: 0,
        }
    }
}

struct FileType(datatoaster_core::InodeType);

impl From<datatoaster_core::InodeType> for FileType {
    fn from(value: datatoaster_core::InodeType) -> Self {
        FileType(value)
    }
}

impl From<FileType> for fuser::FileType {
    fn from(value: FileType) -> Self {
        match value.0 {
            InodeType::File => fuser::FileType::RegularFile,
            InodeType::Directory => fuser::FileType::Directory,
            // Should not happen
            _ => fuser::FileType::Socket,
        }
    }
}
