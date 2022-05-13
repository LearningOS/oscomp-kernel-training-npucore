use super::frame_allocator::*;
use crate::config::PAGE_SIZE_BITS;
use crate::drivers::BLOCK_DEVICE;
use alloc::sync::Arc;
use alloc::vec::Vec;
use easy_fs::{BlockDevice, Cache, CacheManager};
use spin::Mutex;

const PAGE_BUFFERS: usize = 8;
const BUFFER_SIZE: usize = 512;
const CACHEPOOLSIZE: usize = 16;
const CACHEPOOLPAGE: usize = CACHEPOOLSIZE >> 3;
const PRIORITY_UPPERBOUND: usize = 3;

pub struct BufferCache {
    /// Every time kernel tried to alloc this buffer this number will increase 1(at most 3)
    /// When no free cache lefted this number will decrease 1(at least 0)
    /// When it's 0 and Arc's strong count is 1, this buffer will be writed back
    priority: usize,
    /// ***If block_id is usize::Max***, we assume it is an unused buffer.
    block_id: usize,
    buffer: &'static mut [u8; BUFFER_SIZE],
}

impl Cache for BufferCache {
    fn read<T, V>(&self, offset: usize, f: impl FnOnce(&T) -> V) -> V {
        assert!(offset.saturating_add(core::mem::size_of::<T>()) <= BUFFER_SIZE);
        f(unsafe {
            self.buffer
                .as_ptr()
                .add(offset)
                .cast::<T>()
                .as_ref()
                .unwrap()
        })
    }

    fn modify<T, V>(&mut self, offset: usize, f: impl FnOnce(&mut T) -> V) -> V {
        assert!(offset.saturating_add(core::mem::size_of::<T>()) <= BUFFER_SIZE);
        f(unsafe {
            self.buffer
                .as_mut_ptr()
                .add(offset)
                .cast::<T>()
                .as_mut()
                .unwrap()
        })
    }
}

impl BufferCache {
    pub fn new(buffer_ptr: *mut [u8; BUFFER_SIZE]) -> Self {
        let buffer = unsafe { buffer_ptr.as_mut().unwrap() };
        Self {
            priority: 0,
            block_id: usize::MAX,
            buffer,
        }
    }
    pub fn read_block(&mut self, block_id: usize, block_device: Arc<dyn BlockDevice>) {
        self.block_id = block_id;
        let buf = self.buffer.as_mut();
        block_device.read_block(block_id, buf);
    }
}

pub struct BlockCacheManager {
    /// just hold all pages alloced
    _hold: Vec<Arc<FrameTracker>>,
    cache_pool: Vec<Arc<Mutex<BufferCache>>>,
}

impl BlockCacheManager {
    fn oom(&self) {
        for buffer_cache in &self.cache_pool {
            if Arc::strong_count(buffer_cache) > 1 {
                continue;
            }
            let mut locked = buffer_cache.lock();
            if locked.priority > 0 {
                locked.priority -= 1;
            } else {
                let block_id = locked.block_id;
                let buf = locked.buffer.as_ref();
                BLOCK_DEVICE.write_block(block_id, buf);
                locked.block_id = usize::MAX;
            }
        }
    }
    fn alloc_buffer_cache(&self) -> Arc<Mutex<BufferCache>> {
        loop {
            for buffer_cache in &self.cache_pool {
                let mut locked = buffer_cache.lock();
                if locked.block_id == usize::MAX {
                    return buffer_cache.clone();
                }
            }
            self.oom();
        }
    }

    fn try_get_block_cache(
        &self,
        block_id: usize,
        inner_cache_id: usize,
    ) -> Option<Arc<Mutex<BufferCache>>> {
        for buffer_cache in &self.cache_pool {
            let mut locked = buffer_cache.lock();
            if locked.block_id == block_id {
                if locked.priority < PRIORITY_UPPERBOUND {
                    locked.priority += 1;
                }
                return Some(buffer_cache.clone());
            }
        }
        None
    }
}

impl CacheManager for BlockCacheManager {
    const CACHE_SZ: usize = BUFFER_SIZE;
    type CacheType = BufferCache;

    fn new() -> Self {
        let mut hold: Vec<Arc<FrameTracker>> = Vec::new();
        let mut cache_pool: Vec<Arc<Mutex<BufferCache>>> = Vec::new();
        for i in 0..CACHEPOOLPAGE {
            hold.push(frame_alloc().unwrap());
            let page_ptr = (hold[i].ppn.0 << PAGE_SIZE_BITS) as *mut [u8; BUFFER_SIZE];
            for j in 0..PAGE_BUFFERS {
                let buffer_ptr = unsafe { page_ptr.add(j) };
                cache_pool.push(Arc::new(Mutex::new(BufferCache::new(buffer_ptr))))
            }
        }
        Self {
            _hold: hold,
            cache_pool,
        }
    }
    fn try_get_block_cache(
        &mut self,
        block_id: usize,
        inner_cache_id: usize,
    ) -> Option<Arc<Mutex<Self::CacheType>>> {
        for buffer_cache in &self.cache_pool {
            let mut locked = buffer_cache.lock();
            if locked.block_id == block_id {
                if locked.priority < PRIORITY_UPPERBOUND {
                    locked.priority += 1;
                }
                return Some(buffer_cache.clone());
            }
        }
        None
    }

    fn get_block_cache<FUNC>(
        &mut self,
        block_id: usize,
        inner_cache_id: usize,
        neighbor: FUNC,
        block_device: Arc<dyn BlockDevice>,
    ) -> Arc<Mutex<Self::CacheType>>
    where
        FUNC: Fn() -> Vec<usize>,
    {
        let try_get = self.try_get_block_cache(block_id, inner_cache_id);
        if try_get.is_some() {
            return try_get.unwrap();
        }
        let buffer_cache = self.alloc_buffer_cache();
        let mut locked = buffer_cache.lock();
        locked.read_block(block_id, block_device);
        if locked.priority < PRIORITY_UPPERBOUND {
            locked.priority += 1;
        }
        buffer_cache.clone()
    }
}
