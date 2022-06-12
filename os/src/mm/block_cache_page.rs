use super::address::*;
use super::frame_allocator::*;
use super::page_table::*;
use super::KERNEL_SPACE;
use crate::config::{PAGE_SIZE, PAGE_SIZE_BITS};
use crate::drivers::BLOCK_DEVICE;
use alloc::sync::Arc;
use alloc::sync::Weak;
use alloc::vec::Vec;
use easy_fs::{BlockDevice, Cache, CacheManager};
use lazy_static::*;
use log::warn;
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
    /// If block_id is usize::Max, content in this block won't be writed back
    block_ids: [usize; PAGE_BUFFERS],
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
}

impl PageCache {
    pub fn new() -> Self {
        let tracker = frame_alloc().unwrap();
        let page_ptr = (tracker.ppn.0 << PAGE_SIZE_BITS) as *mut [u8; PAGE_SIZE];
        let page_ptr = unsafe { page_ptr.as_mut().unwrap() };
        Self {
            priority: 0,
            block_ids: [usize::MAX; PAGE_BUFFERS],
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

    pub fn read_in(&mut self, block_ids: Vec<usize>, block_device: &Arc<dyn BlockDevice>) {
        assert!(block_ids.len() <= PAGE_BUFFERS);
        for (i, block_id) in block_ids.iter().enumerate() {
            self.block_ids[i] = *block_id;
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

    pub fn write_back(&mut self) {
        for (i, block_id) in self.block_ids.iter_mut().enumerate() {
            if *block_id == usize::MAX {
                continue;
            }
            let buf = unsafe {
                self.page_ptr
                    .as_ptr()
                    .add(i * BUFFER_SIZE)
                    .cast::<[u8; BUFFER_SIZE]>()
                    .as_ref()
                    .unwrap()
            };
            BLOCK_DEVICE.write_block(*block_id, buf);
            *block_id = usize::MAX;
        }
    }
}

impl Drop for PageCache {
    fn drop(&mut self) {
        if self.get_pte().is_dirty() == false {
            return;
        }
        self.write_back();
    }
}

lazy_static! {
    pub static ref PAGECACHE_MANAGER: Arc<Mutex<Vec<Arc<Mutex<PageCache>>>>> =
        Arc::new(Mutex::new(Vec::new()));
}

/// !!! remember to connect oom with frame_allocator
pub fn oom() {
    let mut page_caches = PAGECACHE_MANAGER.lock();
    let mut lose_times = 0;
    loop {
        let mut dropped: usize = 0;
        let mut undropped: Vec<Arc<Mutex<PageCache>>> = Vec::new();
        for page_cache in page_caches.to_vec() {
            let mut locked = page_cache.lock();
            if Arc::strong_count(&page_cache) > 1 {
                drop(locked);
                undropped.push(page_cache);
            } else if locked.priority > 0 {
                locked.priority -= 1;
                drop(locked);
                undropped.push(page_cache);
            } else {
                dropped += 1;
            }
        }
        if dropped > 0 {
            page_caches.clear();
            page_caches.append(&mut undropped);
            warn!("oom: add info here");
            break;
        } else {
            lose_times = lose_times + 1;
            if lose_times == PRIORITY_UPPERBOUND {
                panic!("No free cache spaces!");
            }
        }
    }
}

pub struct PageCacheManager {
    cache_pool: Vec<Weak<Mutex<PageCache>>>,
}
impl CacheManager for PageCacheManager {
    const CACHE_SZ: usize = PAGE_SIZE;
    type CacheType = PageCache;

    fn new() -> Self {
        Self {
            cache_pool: Vec::new(),
        }
    }

    fn try_get_block_cache(
        &self,
        block_id: usize,
        inner_cache_id: usize,
    ) -> Option<Arc<Mutex<PageCache>>> {
        if inner_cache_id >= self.cache_pool.len() {
            return None;
        }
        // A situation may will require this lock
        // When another process is executing oom, it may misjudge that the target page_cache should be dropped,
        // and when oom finished, the ownership of the page_cache will not belong to PAGECACHE_MANAGER,
        // which is a 'fake' memory leak(it will eventually be dropped)
        let page_caches = PAGECACHE_MANAGER.lock();
        let page_cache = self.cache_pool[inner_cache_id].upgrade();
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
        // while inner_cache_id >= self.cache_pool.len() {
        //     self.cache_pool.push(Weak::new());
        // }
        // let page_caches = PAGECACHE_MANAGER.lock();
        // let mut page_cache = self.cache_pool[inner_cache_id].upgrade();
        // if page_cache.is_none() {
        //     let mut new_page_cache = PageCache::new();
        //     new_page_cache.read_in(neighbor(), &block_device);
        //     let new_page_cache = Arc::new(Mutex::new(new_page_cache));
        //     self.cache_pool[inner_cache_id] = Arc::downgrade(&new_page_cache);
        //     page_cache = Some(new_page_cache.clone());
        //     PAGECACHE_MANAGER.lock().push(new_page_cache);
        // }
        // let page_cache = page_cache.unwrap();
        // let mut locked = page_cache.lock();
        // if locked.priority < PRIORITY_UPPERBOUND {
        //     locked.priority += 1;
        // }
        // drop(locked);
        // page_cache
        todo!()
    }
}
