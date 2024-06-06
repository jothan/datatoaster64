use std::path::Path;

use datatoaster_core::{Error, Filesystem, BLOCK_SIZE};
use datatoaster_traits::BlockAccess;

use signal_hook::consts::signal::*;
use signal_hook::iterator::Signals;

pub struct FuseFilesystem<D>(Filesystem<D>);

impl<D: BlockAccess<BLOCK_SIZE>> FuseFilesystem<D> {
    pub fn new(device: D) -> Result<Self, Error> {
        Ok(Self(Filesystem::open(device)?))
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

impl<D: BlockAccess<BLOCK_SIZE>> fuser::Filesystem for FuseFilesystem<D> {}
