use super::BlockDevice;
use alloc::sync::Arc;
use spin::Mutex;

pub trait Cache {
    /// The read-only mapper to the block cache
    fn read<T, V>(&self, offset: usize, f: impl FnOnce(&T) -> V) -> V;
    /// The mutable mapper to the block cache
    fn modify<T, V>(&mut self, offset: usize, f: impl FnOnce(&mut T) -> V) -> V;
    /// Synchronize the cache with the external storage, i.e. write it back to the disk.
    fn sync(&mut self);
}

pub trait CacheManager {
    type CacheType: Cache;

    /// Try to get the block cache and return `None` if not found.
    /// # Argument
    /// `block_id`: The demanded block.
    /// `inner_blk_id`: The ordinal number of the block inside the block.
    /// `inode_id`: The inode_id the block cache belongs to.
    fn try_get_block_cache(
        &self,
        block_id: usize,
        inner_blk_id: Option<usize>,
        inode_id: Option<usize>,
    ) -> Option<Arc<Mutex<Self::CacheType>>>;

    /// Attempt to get block cache from the cache.
    /// If failed, the manager should try to copy the block from sdcard.
    /// # Argument
    /// `block_id`: The demanded block.
    /// `inner_blk_id`: The ordinal number of the block inside the block.
    /// `inode_id`: The inode_id the block cache belongs to.
    /// `block_device`: The pointer to the block_device.
    fn get_block_cache(
        &self,
        block_id: usize,
        inner_blk_id: Option<usize>,
        inode_id: Option<usize>,
        block_device: Arc<dyn BlockDevice>,
    ) -> Arc<Mutex<Self::CacheType>>;
}
