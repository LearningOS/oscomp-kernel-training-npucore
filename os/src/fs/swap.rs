use alloc::vec::Vec;
use easy_fs::BLOCK_SZ;
use spin::Mutex;

use crate::drivers::BLOCK_DEVICE;

use super::directory_tree::FILE_SYSTEM;
use lazy_static::*;

lazy_static! {
    pub static ref SWAP_DEVICE: Mutex<Swap> = Mutex::new(
        Swap::new(16)
    );
}

pub struct Swap {
    bitmap: Vec<u64>,
    block_ids: Vec<usize>,
}

impl Swap {
    /// size: the number of megabytes in swap
    pub fn new(size: usize) -> Self {
        let bit = size * 256;
        let vec_len = bit / 64;
        let mut bitmap = Vec::<u64>::with_capacity(vec_len);
        bitmap.resize(bitmap.capacity(), 0);
        let blocks = size * 2048;
        Self {
            bitmap,
            block_ids: FILE_SYSTEM.alloc_blocks(blocks)
        }
    }
    fn read_page(block_ids: &[usize], buf: &mut [u8]) {
        for (i, buf) in buf.chunks_mut(BLOCK_SZ).enumerate() {
            BLOCK_DEVICE.read_block(block_ids[i], buf);
        }
    }
    fn write_page(block_ids: &[usize], buf: &[u8]) {
        for (i, buf) in buf.chunks(BLOCK_SZ).enumerate() {
            BLOCK_DEVICE.write_block(block_ids[i], buf);
        }
    }
    fn set_bit(&mut self, pos: usize) {
        self.bitmap[pos / 64] |= 1 << (pos % 64);
    }
    fn clear_bit(&mut self, pos: usize) {
        self.bitmap[pos / 64] &= !(1 << (pos % 64));
    }
    fn alloc_page(&self) -> Option<usize> {
        for (i, bit) in self.bitmap.iter().enumerate() {
            if !*bit == 0 {
                continue;
            }
            return Some(i * 64 + (!*bit).trailing_zeros() as usize);
        }
        None
    }
    fn get_block_ids(&self, swap_id: usize) -> &[usize] {
        &self.block_ids[swap_id * 8 + 0..swap_id * 8 + 8]
    }
    pub fn read(&mut self, swap_id: usize, buf: &mut [u8]) {
        Self::read_page(self.get_block_ids(swap_id), buf);
        self.clear_bit(swap_id);
    }
    pub fn write(&mut self, buf: &[u8]) -> usize {
        let swap_id = self.alloc_page().unwrap();
        Self::write_page(self.get_block_ids(swap_id), buf);
        self.set_bit(swap_id);
        swap_id
    }
}