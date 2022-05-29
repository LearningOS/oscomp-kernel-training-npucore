#![no_std]

extern crate alloc;

mod bitmap;
pub mod block_cache;
mod block_dev;
mod efs;
pub mod layout;
mod vfs;

pub const BLOCK_SZ: usize = 512;
use bitmap::Fat;
//pub use block_cache::get_block_cache;
pub use block_cache::{CacheManager, FileCache};
pub use block_dev::BlockDevice;
pub use efs::EasyFileSystem;
pub use layout::DataBlock;
use layout::*;
pub use vfs::Inode;
