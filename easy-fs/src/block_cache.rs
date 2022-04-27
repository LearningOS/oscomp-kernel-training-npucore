use super::BlockDevice;
use alloc::{sync::Arc, vec::Vec};
use spin::Mutex;

pub trait Cache {
    /// The read-only mapper to the block cache
    fn read<T, V>(&self, offset: usize, f: impl FnOnce(&T) -> V) -> V;
    /// The mutable mapper to the block cache
    fn modify<T, V>(&mut self, offset: usize, f: impl FnOnce(&mut T) -> V) -> V;
}

pub trait CacheManager {
    /// The constant to mark the cache size.
    const CACHE_SZ: usize;

    type CacheType: Cache;

    /// Constructor to the struct.
    fn new(fst_block_id: usize) -> Mutex<Self>
    where
        Self: Sized;

    /// Try to get the block cache and return `None` if not found.
    /// # Argument
    /// `block_id`: The demanded block.
    /// `inner_blk_id`: The ordinal number of the block inside the block.
    /// `inode_id`: The inode_id the block cache belongs to.
    fn try_get_block_cache(
        &mut self,
        block_id: usize,
        inner_cache_id: usize,
    ) -> Option<Arc<Mutex<Self::CacheType>>>;

    /// Attempt to get block cache from the cache.
    /// If failed, the manager should try to copy the block from sdcard.
    /// # Argument
    /// `block_id`: The demanded block.
    /// `inner_blk_id`: The ordinal number of the block inside the block.
    /// `inode_id`: The inode_id the block cache belongs to.
    /// `block_device`: The pointer to the block_device.
    fn get_block_cache<FUNC>(
        &mut self,
        block_id: usize,
        inner_cache_id: usize,
        neighbor: FUNC,
        block_device: Arc<dyn BlockDevice>,
    ) -> Arc<Mutex<Self::CacheType>>
    where
        FUNC: Fn() -> Vec<usize>;
}
