use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::num::NonZeroU64;
use std::path::Path;

use clap::Parser;
use datatoaster_core::{Filesystem, BLOCK_SIZE};
use datatoaster_fuse::{fuser::MountOption, FuseFilesystem};
use datatoaster_traits::{BlockAccess, BlockIndex, Error as BlockError};
use nix::sys::uio::{pread, pwrite};

#[derive(Debug, clap::Parser)]
#[command(name = "datatoaster64")]
struct Args {
    #[arg(long, short, default_value =  OsStr::new("data.toast"))]
    data_path: Box<Path>,
    #[cfg(feature = "notify")]
    #[arg(short, long)]
    quiet: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    Format {
        #[arg(short, long, default_value_t = NonZeroU64::new(256).unwrap())]
        device_size_mb: NonZeroU64,
    },
    Mount {
        #[arg()]
        mountpoint: Box<Path>,
    },
}

struct FileDevice {
    file: File,
    block_length: BlockIndex,
}

impl FileDevice {
    fn file_length(file: &File) -> anyhow::Result<BlockIndex> {
        let md = file.metadata()?;
        if md.len() % BLOCK_SIZE as u64 != 0 {
            return Err(anyhow::Error::msg(
                "file is not a mulitple of the block size",
            ));
        }

        Ok(BlockIndex(md.len() / BLOCK_SIZE as u64))
    }

    fn open_for_mount<P: AsRef<Path>>(path: P) -> anyhow::Result<FileDevice> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;

        let block_length = Self::file_length(&file)?;

        Ok(FileDevice { file, block_length })
    }

    fn open_for_format<P: AsRef<Path>>(
        path: P,
        size_in_mb: NonZeroU64,
    ) -> anyhow::Result<FileDevice> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)?;

        let byte_length = size_in_mb.get() * 1024 * 1024;
        file.set_len(byte_length)?;

        Ok(FileDevice {
            file,
            block_length: BlockIndex(byte_length / BLOCK_SIZE as u64),
        })
    }

    fn block_position(block: BlockIndex) -> i64 {
        i64::try_from(block.0)
            .unwrap()
            .checked_mul(BLOCK_SIZE as i64)
            .unwrap()
    }
}

unsafe impl BlockAccess<BLOCK_SIZE> for FileDevice {
    fn read(
        &self,
        block_idx: BlockIndex,
        buffer: &mut std::mem::MaybeUninit<[u8; BLOCK_SIZE]>,
    ) -> Result<(), BlockError> {
        let position = Self::block_position(block_idx);
        let buffer = buffer.write([0; BLOCK_SIZE]);

        let read = pread(&self.file, buffer, position).map_err(|_| BlockError::IO)?;
        if read != BLOCK_SIZE {
            return Err(BlockError::Invalid);
        }
        Ok(())
    }

    fn write(&self, block_idx: BlockIndex, buffer: &[u8; BLOCK_SIZE]) -> Result<(), BlockError> {
        let position = Self::block_position(block_idx);

        let written = pwrite(&self.file, buffer, position).map_err(|_| BlockError::IO)?;
        if written != BLOCK_SIZE {
            return Err(BlockError::Invalid);
        }
        Ok(())
    }

    fn device_size(&self) -> Result<BlockIndex, BlockError> {
        Ok(self.block_length)
    }
}

fn mount_device(path: Box<Path>, mountpoint: Box<Path>, notify: bool) -> anyhow::Result<()> {
    log::info!("Opening {path:?}");
    let device = FileDevice::open_for_mount(path)?;
    log::info!("Opening file system");
    let fs = FuseFilesystem::new(device, notify)?;

    log::info!("File system started at {mountpoint:?}, waiting for Ctrl-C");
    fs.run(mountpoint, &[MountOption::FSName("datatoaster64".into())])?;

    log::info!("File system done");

    Ok(())
}

fn format_device(path: Box<Path>, size_in_mb: NonZeroU64) -> anyhow::Result<()> {
    let device = FileDevice::open_for_format(path, size_in_mb)?;
    Filesystem::format(&device)?;
    Ok(())
}

fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    #[cfg(feature = "notify")]
    let notify = !args.quiet;
    #[cfg(not(feature = "notify"))]
    let notify = false;

    match args.command {
        Command::Mount { mountpoint } => mount_device(args.data_path, mountpoint, notify)?,
        Command::Format { device_size_mb } => format_device(args.data_path, device_size_mb)?,
    }

    Ok(())
}
