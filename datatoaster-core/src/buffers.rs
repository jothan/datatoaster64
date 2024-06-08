use std::prelude::v1::*;

use crate::BLOCK_SIZE;

// This type can be switched to another allocator if needed.
pub(crate) type BufferBox<T> = Box<T>;
pub(crate) type BlockBuffer = BufferBox<[u8; BLOCK_SIZE]>;
