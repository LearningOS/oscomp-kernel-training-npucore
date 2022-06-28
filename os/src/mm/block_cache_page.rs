use super::address::*;
use super::frame_allocator::*;
use super::page_table::*;
use super::KERNEL_SPACE;
use crate::config::{PAGE_SIZE, PAGE_SIZE_BITS};
use alloc::sync::Arc;
use alloc::vec::Vec;
use easy_fs::{BlockDevice, Cache, CacheManager};
use spin::Mutex;

const BUFFER_SIZE: usize = 512;
const PAGE_BUFFERS: usize = 8;
const PRIORITY_UPPERBOUND: usize = 3;

/// PageCache is used for kernel.
/// Each PageCache contains PAGE_BUFFERS(8) BufferCache.
pub struct PageCache {
    /// Priority is used for out of memory
    /// Every time kernel tried to alloc this pagecache this number will increase 1(at most 3)
    /// Every time out of memory occurred this number will decrease 1(at least 0)
    /// When it's 0 and Arc's strong count is 1(one in inode) this PageCache will be dropped
    priority: usize,
    page_ptr: &'static mut [u8; PAGE_SIZE],
    tracker: Arc<FrameTracker>,
}

impl Cache for PageCache {
    fn read<T, V>(&self, offset: usize, f: impl FnOnce(&T) -> V) -> V {
        assert!(offset.saturating_add(core::mem::size_of::<T>()) <= PAGE_SIZE);
        f(unsafe {
            self.page_ptr
                .as_ptr()
                .add(offset)
                .cast::<T>()
                .as_ref()
                .unwrap()
        })
    }

    fn modify<T, V>(&mut self, offset: usize, f: impl FnOnce(&mut T) -> V) -> V {
        assert!(offset.saturating_add(core::mem::size_of::<T>()) <= PAGE_SIZE);
        f(unsafe {
            self.page_ptr
                .as_mut_ptr()
                .add(offset)
                .cast::<T>()
                .as_mut()
                .unwrap()
        })
    }
    
    fn sync(&self, block_ids: Vec<usize>, block_device: &Arc<dyn BlockDevice>) {
        self.write_back(block_ids, &block_device);
    }
}

impl PageCache {
    pub fn new() -> Self {
        let tracker = frame_alloc().unwrap();
        let page_ptr = (tracker.ppn.0 << PAGE_SIZE_BITS) as *mut [u8; PAGE_SIZE];
        let page_ptr = unsafe { page_ptr.as_mut().unwrap() };
        Self {
            priority: 0,
            page_ptr,
            tracker,
        }
    }

    pub fn get_ppn(&self) -> PhysPageNum {
        self.tracker.ppn
    }

    pub fn get_pte(&self) -> PageTableEntry {
        KERNEL_SPACE
            .lock()
            .translate(self.get_ppn().0.into())
            .unwrap()
    }

    pub fn read_in(
        &mut self, 
        block_ids: Vec<usize>, 
        block_device: &Arc<dyn BlockDevice>
    ) {
        assert!(block_ids.len() <= PAGE_BUFFERS);
        for (i, block_id) in block_ids.iter().enumerate() {
            let buf = unsafe {
                self.page_ptr
                    .as_mut_ptr()
                    .add(i * BUFFER_SIZE)
                    .cast::<[u8; BUFFER_SIZE]>()
                    .as_mut()
                    .unwrap()
            };
            block_device.read_block(*block_id, buf);
        }
    }

    pub fn write_back(
        &self, 
        block_ids: Vec<usize>,
        block_device: &Arc<dyn BlockDevice>
    ) {
        for (i, block_id) in block_ids.iter().enumerate() {
            let buf = unsafe {
                self.page_ptr
                    .as_ptr()
                    .add(i * BUFFER_SIZE)
                    .cast::<[u8; BUFFER_SIZE]>()
                    .as_ref()
                    .unwrap()
            };
            block_device.write_block(*block_id, buf);
        }
    }
}

pub struct PageCacheManager {
    cache_pool: Mutex<Vec<Option<Arc<Mutex<PageCache>>>>>,
}
impl CacheManager for PageCacheManager {
    const CACHE_SZ: usize = PAGE_SIZE;
    type CacheType = PageCache;

    fn new() -> Self {
        Self {
            cache_pool: Mutex::new(Vec::new()),
        }
    }

    fn try_get_block_cache(
        &self,
        block_id: usize,
        inner_cache_id: usize,
    ) -> Option<Arc<Mutex<PageCache>>> {
        let lock = self.cache_pool.lock();
        if inner_cache_id >= lock.len() {
            return None;
        }
        let page_cache = lock[inner_cache_id].clone();
        if page_cache.is_some() {
            let mut locked = page_cache.as_ref().unwrap().lock();
            if locked.priority < PRIORITY_UPPERBOUND {
                locked.priority += 1;
            }
        }
        page_cache
    }

    fn get_block_cache<FUNC>(
        &self,
        block_id: usize,
        inner_cache_id: usize,
        neighbor: FUNC,
        block_device: Arc<dyn BlockDevice>,
    ) -> Arc<Mutex<Self::CacheType>>
    where
        FUNC: Fn() -> Vec<usize>,
    {
        let mut lock = self.cache_pool.lock();
        while inner_cache_id >= lock.len() {
            lock.push(None);
        }
        let mut page_cache = lock[inner_cache_id].clone();
        if page_cache.is_none() {
            let mut new_page_cache = PageCache::new();
            new_page_cache.read_in(neighbor(), &block_device);
            let new_page_cache = Arc::new(Mutex::new(new_page_cache));
            page_cache = Some(new_page_cache.clone());
            lock[inner_cache_id] = Some(new_page_cache);
        }
        let page_cache = page_cache.unwrap();
        let mut inner_lock = page_cache.lock();
        if inner_lock.priority < PRIORITY_UPPERBOUND {
            inner_lock.priority += 1;
        }
        drop(inner_lock);
        page_cache
    }

    fn oom<FUNC>(
        &self,
        neighbor: FUNC,
        block_device: &Arc<dyn BlockDevice>,
    ) -> usize
    where
        FUNC: Fn(usize) -> Vec<usize> {
        let lock = self.cache_pool.try_lock();
        if lock.is_none() {
            return 0;
        }
        let mut lock = lock.unwrap();
        let mut dropped = 0;

        for (i, cache) in lock.iter_mut().enumerate() {
            if cache.is_none() {
                continue;
            }
            let inner = cache.as_ref().unwrap();
            if Arc::strong_count(inner) > 1 {
                continue;
            }
            let mut inner_lock = inner.lock();
            if inner_lock.priority > 0 {
                inner_lock.priority -= 1;
            } else {
                let block_ids = neighbor(i);
                inner_lock.sync(block_ids, block_device);
                dropped += 1;
                drop(inner_lock);
                *cache = None;
            }
        }
        dropped
    }
}
