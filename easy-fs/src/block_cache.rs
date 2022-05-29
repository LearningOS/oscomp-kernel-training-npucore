use super::BlockDevice;
use alloc::sync::Arc;
use spin::Mutex;

pub trait FileCache {
    /// The read-only mapper to the block cache
    fn read<T, V>(&self, offset: usize, f: impl FnOnce(&T) -> V) -> V;
    /// The mutable mapper to the block cache
    fn modify<T, V>(&mut self, offset: usize, f: impl FnOnce(&mut T) -> V) -> V;
    /// Synchronize the cache with the external storage, i.e. write it back to the disk.
    fn sync(&mut self);
}

pub trait CacheManager {
    type CacheType: FileCache;
    /// Constructor
    fn new() -> Self;

    /// Try to get the block cache and return `None` if not found.
    /// # Argument
    /// `block_id`: The demanded block.
    fn try_get_block_cache(&self, block_id: usize) -> Option<Arc<Mutex<Self::CacheType>>>;

    /// Get a demanded block cache.
    /// Replace one cache with the demanded one if it is not currently in the cache vector.
    /// # Arguments
    /// `block_id`: The demanded block.
    /// `block_device`: The block to run on.
    fn get_block_cache(
        &self,
        block_id: usize,
        block_device: Arc<dyn BlockDevice>,
    ) -> Arc<Mutex<Self::CacheType>>;
}
