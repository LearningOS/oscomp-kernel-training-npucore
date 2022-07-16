use crate::config::{PAGE_SIZE, PAGE_SIZE_BITS};
use crate::mm::{frame_alloc, FrameTracker, KERNEL_SPACE, PageTableEntry};
use alloc::sync::Arc;
use alloc::vec::Vec;
use easy_fs::{BlockDevice, Cache, CacheManager};
use spin::Mutex;

const PAGE_BUFFERS: usize = 8;
const BUFFER_SIZE: usize = 512;
const CACHEPOOLSIZE: usize = 16;
const CACHEPOOLPAGE: usize = CACHEPOOLSIZE >> 3;
const PRIORITY_UPPERBOUND: usize = 1;

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
    pub fn read_block(&mut self, block_id: usize, block_device: &Arc<dyn BlockDevice>) {
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
    fn oom(&self, block_device: &Arc<dyn BlockDevice>) {
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
                block_device.write_block(block_id, buf);
                locked.block_id = usize::MAX;
            }
        }
    }
    fn alloc_buffer_cache(&self, block_device: &Arc<dyn BlockDevice>) -> Arc<Mutex<BufferCache>> {
        loop {
            for buffer_cache in &self.cache_pool {
                let locked = buffer_cache.lock();
                if locked.block_id == usize::MAX {
                    return buffer_cache.clone();
                }
            }
            self.oom(block_device);
        }
    }

    fn try_get_block_cache(
        &self,
        block_id: usize,
        _inner_cache_id: usize,
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
        &self,
        block_id: usize,
        _inner_cache_id: usize,
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
        &self,
        block_id: usize,
        inner_cache_id: usize,
        _neighbor: FUNC,
        block_device: &Arc<dyn BlockDevice>,
    ) -> Arc<Mutex<Self::CacheType>>
    where
        FUNC: Fn() -> Vec<usize>,
    {
        let try_get = self.try_get_block_cache(block_id, inner_cache_id);
        if try_get.is_some() {
            return try_get.unwrap();
        }
        let buffer_cache = self.alloc_buffer_cache(block_device);
        let mut locked = buffer_cache.lock();
        locked.read_block(block_id, block_device);
        if locked.priority < PRIORITY_UPPERBOUND {
            locked.priority += 1;
        }
        buffer_cache.clone()
    }
}

/// PageCache is used for kernel.
/// Each PageCache contains PAGE_BUFFERS(8) BufferCache.
pub struct PageCache {
    /// Priority is used for out of memory
    /// Every time kernel tried to alloc this pagecache this number will increase 1(at most 1)
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
        match self.get_pte() {
            Some(pte) => {if !pte.is_dirty() {return;}},
            None => {},
        }
        self.write_back(block_ids, block_device)
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

    pub fn get_tracker(&self) -> Arc<FrameTracker> {
        self.tracker.clone()
    }

    fn get_pte(&self) -> Option<PageTableEntry> {
        let lock = KERNEL_SPACE.try_lock();
        match lock {
            Some(lock) => {
                Some(lock.translate(self.tracker.ppn.0.into())).unwrap()
            },
            None => None,
        }
    }

    pub fn read_in(&mut self, block_ids: Vec<usize>, block_device: &Arc<dyn BlockDevice>) {
        if block_ids.is_empty() {
            return;
        }
        assert!(block_ids.len() <= PAGE_BUFFERS);

        let mut start_block_id = usize::MAX;
        let mut con_length = 0;
        let mut start_buf_id = 0;
        for block_id in block_ids.iter() {
            if con_length == 0 {
                start_block_id = *block_id;
                con_length = 1;
            } else if *block_id != start_block_id + con_length {
                let buf = unsafe {
                    core::slice::from_raw_parts_mut(
                        self.page_ptr.as_mut_ptr().add(start_buf_id * BUFFER_SIZE),
                        con_length * BUFFER_SIZE,
                    )
                };
                block_device.read_block(start_block_id, buf);
                start_buf_id += con_length;
                start_block_id = *block_id;
                con_length = 1;
            } else {
                con_length += 1;
            }
        }
        let buf = unsafe {
            core::slice::from_raw_parts_mut(
                self.page_ptr.as_mut_ptr().add(start_buf_id * BUFFER_SIZE),
                con_length * BUFFER_SIZE,
            )
        };
        block_device.read_block(start_block_id, buf);
    }

    pub fn write_back(&self, block_ids: Vec<usize>, block_device: &Arc<dyn BlockDevice>) {
        if block_ids.is_empty() {
            return;
        }

        let mut start_block_id = usize::MAX;
        let mut con_length = 0;
        let mut start_buf_id = 0;
        for block_id in block_ids.iter() {
            if con_length == 0 {
                start_block_id = *block_id;
                con_length = 1;
            } else if *block_id != start_block_id + con_length {
                let buf = unsafe {
                    core::slice::from_raw_parts(
                        self.page_ptr.as_ptr().add(start_buf_id * BUFFER_SIZE),
                        con_length * BUFFER_SIZE,
                    )
                };
                block_device.write_block(start_block_id, buf);

                start_buf_id += con_length;
                start_block_id = *block_id;
                con_length = 1;
            } else {
                con_length += 1;
            }
        }
        let buf = unsafe {
            core::slice::from_raw_parts(
                self.page_ptr.as_ptr().add(start_buf_id * BUFFER_SIZE),
                con_length * BUFFER_SIZE,
            )
        };
        block_device.write_block(start_block_id, buf);
    }
}

pub struct PageCacheManager {
    cache_pool: Mutex<Vec<Option<Arc<Mutex<PageCache>>>>>,
    allocated_cache: Mutex<Vec<usize>>,
}
impl CacheManager for PageCacheManager {
    const CACHE_SZ: usize = PAGE_SIZE;
    type CacheType = PageCache;

    fn new() -> Self {
        Self {
            cache_pool: Mutex::new(Vec::new()),
            allocated_cache: Mutex::new(Vec::new()),
        }
    }

    fn try_get_block_cache(
        &self,
        _block_id: usize,
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
        _block_id: usize,
        inner_cache_id: usize,
        neighbor: FUNC,
        block_device: &Arc<dyn BlockDevice>,
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
            self.allocated_cache.lock().push(inner_cache_id);
        }
        let page_cache = page_cache.unwrap();
        let mut inner_lock = page_cache.lock();
        if inner_lock.priority < PRIORITY_UPPERBOUND {
            inner_lock.priority += 1;
        }
        drop(inner_lock);
        page_cache
    }

    fn oom<FUNC>(&self, neighbor: FUNC, block_device: &Arc<dyn BlockDevice>) -> usize
    where
        FUNC: Fn(usize) -> Vec<usize>,
    {
        let lock = self.cache_pool.try_lock();
        if lock.is_none() {
            return 0;
        }
        let mut lock = lock.unwrap();
        let mut dropped = 0;
        let mut new_allocated_cache = Vec::<usize>::new();

        for inner_cache_id in &*self.allocated_cache.lock() {
            let inner_cache_id = *inner_cache_id;
            let inner = lock[inner_cache_id].as_ref().unwrap();
            if Arc::strong_count(inner) > 1 {
                new_allocated_cache.push(inner_cache_id);
                continue;
            }
            let mut inner_lock = inner.lock();
            if Arc::strong_count(&inner_lock.tracker) > 1 {
                new_allocated_cache.push(inner_cache_id);
            } else if inner_lock.priority > 0 {
                inner_lock.priority -= 1;
                new_allocated_cache.push(inner_cache_id);
            } else {
                let block_ids = neighbor(inner_cache_id);
                inner_lock.sync(block_ids, block_device);
                dropped += 1;
                drop(inner_lock);
                lock[inner_cache_id] = None;
            }
        }
        *self.allocated_cache.lock() = new_allocated_cache;
        dropped
    }

    fn notify_new_size(&self, new_size: usize) {
        let mut lock = self.cache_pool.lock();
        let new_pages = (new_size + PAGE_SIZE - 1) / PAGE_SIZE;
        while lock.len() > new_pages {
            lock.pop().unwrap().map(|cache| {
                if Arc::strong_count(&cache) > 1 {
                    panic!("page cache was used by others");
                }
            });
        }
        lock.shrink_to_fit();

        let mut new_allocated_cache = Vec::<usize>::new();
        for inner_cache_id in &*self.allocated_cache.lock() {
            if *inner_cache_id < new_pages {
                new_allocated_cache.push(*inner_cache_id);
            }
        }
        *self.allocated_cache.lock() = new_allocated_cache;
    }
}
