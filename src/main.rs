use std::{
    ffi::OsStr,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    mem::MaybeUninit,
    num::NonZeroU64,
    ops::DerefMut,
    path::{Path, PathBuf},
    sync::Mutex,
};

use clap::Parser;
use datatoaster_core::{DeviceLayout, Error, Filesystem, BLOCK_SIZE};
use datatoaster_traits::{BlockAccess, BlockIndex};

#[derive(Debug, clap::Parser)]
#[command(name = "datatoaster64")]
struct Args {
    #[arg(long, short, default_value =  OsStr::new("data.toast"))]
    data_path: Box<Path>,
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    Format {
        #[arg(short, long, default_value_t = NonZeroU64::new(256).unwrap())]
        device_size_mb: NonZeroU64,
    },
    Mount,
}

struct FileDevice {
    file: Mutex<File>,
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

        Ok(FileDevice {
            file: Mutex::new(file),
            block_length,
        })
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
            file: Mutex::new(file),
            block_length: BlockIndex(byte_length / BLOCK_SIZE as u64),
        })
    }

    fn seek(file: &mut File, position: BlockIndex) -> Result<(), datatoaster_traits::Error> {
        file.seek(SeekFrom::Start(position.0 * BLOCK_SIZE as u64))
            .map_err(|_| datatoaster_traits::Error::IO)?;

        Ok(())
    }
}

unsafe impl BlockAccess<BLOCK_SIZE> for FileDevice {
    fn read(
        &self,
        block_idx: datatoaster_traits::BlockIndex,
        buffer: &mut std::mem::MaybeUninit<[u8; BLOCK_SIZE]>,
    ) -> Result<(), datatoaster_traits::Error> {
        let mut file = self.file.lock().unwrap();
        Self::seek(&mut file, block_idx)?;

        *buffer = MaybeUninit::zeroed();
        let buffer = unsafe { buffer.assume_init_mut() };

        file.read_exact(buffer.as_mut_slice())
            .map_err(|_| datatoaster_traits::Error::IO)?;

        Ok(())
    }

    fn write(
        &self,
        block_idx: datatoaster_traits::BlockIndex,
        buffer: &[u8; BLOCK_SIZE],
    ) -> Result<(), datatoaster_traits::Error> {
        let mut file = self.file.lock().unwrap();
        Self::seek(&mut file, block_idx)?;
        file.write_all(buffer.as_slice())
            .map_err(|_| datatoaster_traits::Error::IO)?;

        Ok(())
    }

    fn device_size(&self) -> Result<datatoaster_traits::BlockIndex, datatoaster_traits::Error> {
        Ok(self.block_length)
    }
}

fn format_device(path: Box<Path>, size_in_mb: NonZeroU64) -> anyhow::Result<()> {
    let device = FileDevice::open_for_format(path, size_in_mb)?;
    Filesystem::format(&device)?;
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    match args.command {
        Command::Mount => todo!(),
        Command::Format { device_size_mb } => format_device(args.data_path, device_size_mb)?,
    }

    Ok(())
}
