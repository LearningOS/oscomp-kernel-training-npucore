use super::{BlockDevice, BLOCK_SZ};
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use lazy_static::*;
use spin::Mutex;

pub trait FileCache {
    /// Load a new BlockCache from disk.
    fn new(block_id: usize, block_device: Arc<dyn BlockDevice>) -> Self;
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
    fn try_get_block_cache(&mut self, block_id: usize) -> Option<Arc<Mutex<Self::CacheType>>>;

    /// Get a demanded block cache.
    /// Replace one cache with the demanded one if it is not currently in the cache vector.
    /// # Arguments
    /// `block_id`: The demanded block.
    /// `block_device`: The block to run on.
    fn get_block_cache(
        &mut self,
        block_id: usize,
        block_device: Arc<dyn BlockDevice>,
    ) -> Arc<Mutex<Self::CacheType>>;
}

pub struct BlockCache {
    cache: [u8; BLOCK_SZ],
    block_id: usize,
    block_device: Arc<dyn BlockDevice>,
    modified: bool,
}

impl Drop for BlockCache {
    fn drop(&mut self) {
        self.sync()
    }
}

impl BlockCache {
    /// Private function.
    /// Get the address at the `offset` in the cache to the cache for later access.
    /// # Argument
    /// * `offset`: The offset from the beginning of the block
    fn addr_of_offset(&self, offset: usize) -> usize {
        &self.cache[offset] as *const _ as usize
    }

    /// Get a reference to the block at required `offset`, casting the in the coming area as an instance of type `&T`
    /// # Argument
    /// * `offset`: The offset from the beginning of the block
    fn get_ref<T>(&self, offset: usize) -> &T
    where
        T: Sized,
    {
        let type_size = core::mem::size_of::<T>();
        assert!(offset + type_size <= BLOCK_SZ);
        let addr = self.addr_of_offset(offset);
        unsafe { &*(addr as *const T) }
    }

    /// The mutable version of `get_ref()`
    fn get_mut<T>(&mut self, offset: usize) -> &mut T
    where
        T: Sized,
    {
        let type_size = core::mem::size_of::<T>();
        assert!(offset + type_size <= BLOCK_SZ);
        self.modified = true;
        let addr = self.addr_of_offset(offset);
        unsafe { &mut *(addr as *mut T) }
    }
}
impl FileCache for BlockCache {
    /// Load a new BlockCache from disk.
    fn new(block_id: usize, block_device: Arc<dyn BlockDevice>) -> Self {
        let mut cache = [0u8; BLOCK_SZ];
        block_device.read_block(block_id, &mut cache);
        Self {
            cache,
            block_id,
            block_device,
            modified: false,
        }
    }

    /// The read-only mapper to the block cache
    fn read<T, V>(&self, offset: usize, f: impl FnOnce(&T) -> V) -> V {
        f(self.get_ref(offset))
    }

    /// The mutable mapper to the block cache    
    fn modify<T, V>(&mut self, offset: usize, f: impl FnOnce(&mut T) -> V) -> V {
        f(self.get_mut(offset))
    }

    /// Synchronize the cache with the external storage, i.e. write it back to the disk.
    fn sync(&mut self) {
        if self.modified {
            self.modified = false;
            self.block_device.write_block(self.block_id, &self.cache);
        }
    }
}

const BLOCK_CACHE_SIZE: usize = 16;

pub struct BlockCacheManager {
    queue: VecDeque<(usize, Arc<Mutex<BlockCache>>)>,
}

impl CacheManager for BlockCacheManager {
    type CacheType = BlockCache;
    fn new() -> Self {
        Self {
            queue: VecDeque::new(),
        }
    }

    fn try_get_block_cache(&mut self, block_id: usize) -> Option<Arc<Mutex<BlockCache>>> {
        if let Some(pair) = self.queue.iter().find(|pair| pair.0 == block_id) {
            Some(Arc::clone(&pair.1))
        } else {
            None
        }
    }

    fn get_block_cache(
        &mut self,
        block_id: usize,
        block_device: Arc<dyn BlockDevice>,
    ) -> Arc<Mutex<BlockCache>> {
        if let Some(i) = self.try_get_block_cache(block_id) {
            i
        } else {
            // substitute
            if self.queue.len() == BLOCK_CACHE_SIZE {
                // from front to tail
                if let Some((idx, _)) = self
                    .queue
                    .iter()
                    .enumerate()
                    .find(|(_, pair)| Arc::strong_count(&pair.1) == 1)
                {
                    self.queue.drain(idx..=idx);
                } else {
                    panic!("Run out of BlockCache!");
                }
            }
            // load block into mem and push back
            let block_cache = Arc::new(Mutex::new(BlockCache::new(
                block_id,
                Arc::clone(&block_device),
            )));
            self.queue.push_back((block_id, Arc::clone(&block_cache)));
            block_cache
        }
    }
}

lazy_static! {
    pub static ref BLOCK_CACHE_MANAGER: Mutex<BlockCacheManager> =
        Mutex::new(BlockCacheManager::new());
}

pub fn get_block_cache(
    block_id: usize,
    block_device: Arc<dyn BlockDevice>,
) -> Arc<Mutex<BlockCache>> {
    BLOCK_CACHE_MANAGER
        .lock()
        .get_block_cache(block_id, block_device)
}
#[allow(unused)]
pub fn try_get_block_cache(block_id: usize) -> Option<Arc<Mutex<BlockCache>>> {
    BLOCK_CACHE_MANAGER.lock().try_get_block_cache(block_id)
}
