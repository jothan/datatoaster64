use datatoaster_core::{BlockDevice, Error};
use datatoaster_traits::{BlockAccess, BlockIndex};

struct DummyDevice;

const BLOCK_SIZE: usize = 4096;

impl BlockAccess<4096> for DummyDevice {
    fn read(
        &self,
        _block_idx: datatoaster_traits::BlockIndex,
        _buffer: &mut std::mem::MaybeUninit<[u8; BLOCK_SIZE]>,
    ) -> Result<(), datatoaster_traits::Error> {
        todo!()
    }

    fn write(
        &self,
        _block_idx: datatoaster_traits::BlockIndex,
        _buffer: &[u8; BLOCK_SIZE],
    ) -> Result<(), datatoaster_traits::Error> {
        todo!()
    }

    fn device_size(&self) -> Result<datatoaster_traits::BlockIndex, datatoaster_traits::Error> {
        Ok(BlockIndex(1024 * 1024 * 1024 / BLOCK_SIZE as u64))
    }
}

fn main() -> Result<(), Error> {
    let dev = BlockDevice::new(DummyDevice)?;

    println!("Device layout: {:?}", dev.layout());

    Ok(())
}
