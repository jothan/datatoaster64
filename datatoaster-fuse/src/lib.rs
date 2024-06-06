use std::path::Path;
use std::time::{Duration, SystemTime};

use datatoaster_core::{Error, Filesystem, InodeType, BLOCK_SIZE};
use datatoaster_traits::BlockAccess;

use signal_hook::consts::signal::*;
use signal_hook::iterator::Signals;

pub struct FuseFilesystem<D> {
    inner: Filesystem<D>,
    fhcounter: u64,
}

impl<D: BlockAccess<BLOCK_SIZE>> FuseFilesystem<D> {
    pub fn new(device: D) -> Result<Self, Error> {
        assert!(fuser::FUSE_ROOT_ID == datatoaster_core::ROOT_INODE.get());
        Ok(Self {
            inner: Filesystem::open(device)?,
            fhcounter: 0,
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
    fn opendir(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        flags: i32,
        reply: fuser::ReplyOpen,
    ) {
        eprintln!("opendir ino:{ino} flags:{flags}");
        self.fhcounter += 1;
        reply.opened(self.fhcounter, 0)
        //reply.error(libc::ENOSYS)
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
        reply.error(libc::ENOSYS)
    }

    fn readdir(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        reply: fuser::ReplyDirectory,
    ) {
        eprintln!("readdir ino:{ino} fh:{fh} offset:{offset}");
        reply.error(libc::ENOSYS)
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
        reply.error(libc::ENOSYS);
    }

    fn getattr(&mut self, _req: &fuser::Request<'_>, ino: u64, reply: fuser::ReplyAttr) {
        eprintln!("getattr ino:{ino}");

        match self.inner.stat(ino) {
            Ok(s) => reply.attr(&Duration::new(0, 0), &Stat::from(s).into()),
            Err(_) => reply.error(libc::ENOSYS),
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
