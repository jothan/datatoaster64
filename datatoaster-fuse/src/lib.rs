use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::{Duration, SystemTime};

use datatoaster_core::{DirectoryHandle, Error, Filesystem, InodeType, BLOCK_SIZE};
use datatoaster_traits::BlockAccess;

use signal_hook::consts::signal::*;
use signal_hook::iterator::Signals;
use slotmap::{new_key_type, Key, KeyData, SlotMap};

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
    open_files: SlotMap<FileKey, ()>,
    open_dirs: SlotMap<DirKey, DirectoryHandle<D>>,
}

impl<D: BlockAccess<BLOCK_SIZE>> FuseFilesystem<D> {
    pub fn new(device: D) -> Result<Self, Error> {
        assert!(fuser::FUSE_ROOT_ID == datatoaster_core::ROOT_INODE.get());
        Ok(Self {
            inner: Filesystem::open(device)?,
            open_files: SlotMap::with_key(),
            open_dirs: SlotMap::with_key(),
        })
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
        eprintln!("Syncing");
        self.inner.sync().expect("sync error");
    }

    fn opendir(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        flags: i32,
        reply: fuser::ReplyOpen,
    ) {
        eprintln!("opendir ino:{ino} flags:{flags}");

        match self.inner.opendir(ino) {
            Ok(handle) => {
                let fh = self.open_dirs.insert(handle).into();
                reply.opened(fh, 0)
            }
            Err(e) => reply.error(e.into()),
        }
    }

    fn releasedir(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        flags: i32,
        reply: fuser::ReplyEmpty,
    ) {
        eprintln!("releasedir ino:{ino} fh:{fh} flags:{flags}");

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
        ino: u64,
        fh: u64,
        offset: i64,
        mut reply: fuser::ReplyDirectory,
    ) {
        eprintln!("readdir ino:{ino} fh:{fh} offset:{offset}");

        let Some(handle) = self.open_dirs.get(fh.into()) else {
            reply.error(libc::EBADF);
            return;
        };

        let res = handle.readdir(offset.try_into().unwrap(), |offset, dirent| {
            eprintln!(
                "add #{offset} {dirent:?} {:?}",
                String::from_utf8_lossy(dirent.name())
            );
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

    fn readdirplus(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        reply: fuser::ReplyDirectoryPlus,
    ) {
        eprintln!("readdirplus ino:{ino} fh:{fh} offset:{offset}");
        reply.error(libc::ENOSYS)
    }

    fn lookup(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        reply: fuser::ReplyEntry,
    ) {
        eprintln!("lookup parent:{parent} name:{name:?}");

        match self.inner.lookup(parent, name.as_bytes()) {
            Ok(stat) => reply.entry(&Duration::new(0, 0), &Stat::from(stat).into(), 0),
            Err(e) => reply.error(e.into()),
        }
    }

    fn create(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        reply: fuser::ReplyCreate,
    ) {
        eprintln!("create:{parent} name:{name:?} mode:{mode} umask:{umask} flags:{flags}");
        reply.error(libc::ENOSYS);
    }

    fn getattr(&mut self, _req: &fuser::Request<'_>, ino: u64, reply: fuser::ReplyAttr) {
        eprintln!("getattr ino:{ino}");

        match self.inner.stat(ino) {
            Ok(s) => reply.attr(&Duration::new(0, 0), &Stat::from(s).into()),
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
