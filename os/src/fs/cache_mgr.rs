use alloc::sync::Arc;
use alloc::vec::Vec;
use core::alloc::Layout;
use easy_fs::{BlockDevice, Cache, CacheManager};
use spin::Mutex;
use alloc::alloc::{alloc, dealloc};
use alloc::collections::BTreeMap;
use easy_fs::BLOCK_SZ;
use lazy_static::*;
use spin::RwLock;
use crate::config::{PAGE_SIZE_BITS, PAGE_SIZE};
use crate::drivers::BLOCK_DEVICE;
use crate::mm::{FrameTracker, frame_alloc, PhysPageNum, KERNEL_SPACE, PageTableEntry};

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
                let locked = buffer_cache.lock();
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
        &self,
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
        &self,
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
        log::trace!("[PageCache :: read_in], block_ids {:?}", block_ids);
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


/*
pub struct BlockCache {
    pub cache: &'static mut [u8; BLOCK_SZ],
    block_id: usize,
    block_device: Arc<dyn BlockDevice>,
    modified: bool,
}

const BLOCK_CACHE_LAYOUT: Layout = unsafe { Layout::from_size_align_unchecked(BLOCK_SZ, 1) };

impl BlockCache {
    /// Load a new BlockCache from disk.
    pub fn new(block_id: usize, block_device: Arc<dyn BlockDevice>) -> Self {
        let cache: &'static mut [u8; BLOCK_SZ] = unsafe {
            (alloc(BLOCK_CACHE_LAYOUT) as *mut [u8; BLOCK_SZ])
                .as_mut()
                .unwrap()
        };
        //crate::println!("cache ptr: {:?}", cache.as_ptr());
        block_device.read_block(block_id, cache.as_mut_slice());
        Self {
            cache,
            block_id,
            block_device,
            modified: false,
        }
    }

    fn addr_of_offset(&self, offset: usize) -> usize {
        &self.cache[offset] as *const _ as usize
    }

    pub fn get_ref<T>(&self, offset: usize) -> &T
    where
        T: Sized,
    {
        let type_size = core::mem::size_of::<T>();
        assert!(offset + type_size <= BLOCK_SZ);
        let addr = self.addr_of_offset(offset);
        unsafe { &*(addr as *const T) }
    }

    pub fn get_mut<T>(&mut self, offset: usize) -> &mut T
    where
        T: Sized,
    {
        let type_size = core::mem::size_of::<T>();
        assert!(offset + type_size <= BLOCK_SZ);
        self.modified = true;
        let addr = self.addr_of_offset(offset);
        unsafe { &mut *(addr as *mut T) }
    }

    pub fn read<T, V>(&self, offset: usize, f: impl FnOnce(&T) -> V) -> V {
        f(self.get_ref(offset))
    }

    pub fn modify<T, V>(&mut self, offset: usize, f: impl FnOnce(&mut T) -> V) -> V {
        f(self.get_mut(offset))
    }

    pub fn sync(&mut self) {
        if self.modified {
            //println!("drop cache, id = {}", self.block_id);
            self.modified = false;
            self.block_device
                .write_block(self.block_id, self.cache.as_slice());
        }
    }
}

impl Drop for BlockCache {
    fn drop(&mut self) {
        self.sync();
        unsafe { dealloc(self.cache.as_mut_ptr(), BLOCK_CACHE_LAYOUT) };
    }
}

// 0-info扇区
// 1-2 FAT1
// 3-4 FAT2
// 5-7 DirEntry
// 8-19 DATA

//const DIRENT_CACHE_SIZE: usize = 4;
pub struct BlockCacheManager {
    start_sec: usize,
    limit: usize,
    map: BTreeMap<usize, Arc<RwLock<BlockCache>>>,
}

impl BlockCacheManager {
    pub fn new(limit: usize) -> Self {
        Self {
            start_sec: 0,
            limit,
            map: BTreeMap::new(),
        }
    }

    pub fn read_block_cache(
        &self,
        block_id: usize,
        //block_device: Arc<dyn BlockDevice>,
    ) -> Option<Arc<RwLock<BlockCache>>> {
        if let Some(block_cache) = self.map.get(&block_id) {
            Some(block_cache.clone())
        } else {
            None
        }
    }

    pub fn get_block_cache(
        &mut self,
        block_id: usize,
        block_device: Arc<dyn BlockDevice>,
    ) -> Arc<RwLock<BlockCache>> {
        if let Some(block_cache) = self.map.get(&block_id) {
            block_cache.clone()
        } else {
            // substitute
            if self.map.len() == self.limit
            /*BLOCK_CACHE_SIZE*/
            {
                // from front to tail
                let idx = match self.map.iter().find(|(_, arc)| Arc::strong_count(arc) == 1) {
                    Some((&idx, _)) => idx,
                    None => panic!("Run out of BlockCache!"),
                };
                //crate::println!("incoming_block: {}, replaced_block: {}", block_id, idx);
                self.map.remove(&idx);
            }
            // load block into mem and push back
            let block_cache = Arc::new(RwLock::new(BlockCache::new(
                block_id,
                Arc::clone(&block_device),
            )));
            self.map.insert(block_id, Arc::clone(&block_cache));
            //println!("blkcache: {:?}", block_cache.read().cache);
            block_cache
        }
    }

    pub fn drop_all(&mut self) {
        self.map.clear();
    }
}

lazy_static! {
    pub static ref DATA_BLOCK_CACHE_MANAGER: RwLock<BlockCacheManager> =
        RwLock::new(BlockCacheManager::new(1024));
}

lazy_static! {
    pub static ref INFO_CACHE_MANAGER: RwLock<BlockCacheManager> =
        RwLock::new(BlockCacheManager::new(128));
}

#[derive(PartialEq, Copy, Clone, Debug)]
pub enum CacheMode {
    READ,
    WRITE,
}

//pub fn read_block_cache(block_id:usize, rw_mode:CacheMode);

/* 仅用于访问文件数据块，不包括目录项 */
pub fn get_block_cache(
    block_id: usize,
    block_device: Arc<dyn BlockDevice>,
    rw_mode: CacheMode,
) -> Arc<RwLock<BlockCache>> {
    if rw_mode == CacheMode::READ {
        // make sure the blk is in cache
        if let Some(blk) = INFO_CACHE_MANAGER.read().read_block_cache(block_id) {
            return blk;
        }
        DATA_BLOCK_CACHE_MANAGER
            .write()
            .get_block_cache(block_id, block_device);
        DATA_BLOCK_CACHE_MANAGER
            .read()
            .read_block_cache(block_id)
            .unwrap()
    } else {
        if let Some(blk) = INFO_CACHE_MANAGER.read().read_block_cache(block_id) {
            return blk;
        }
        DATA_BLOCK_CACHE_MANAGER
            .write()
            .get_block_cache(block_id, block_device)
    }
}

/* 用于访问保留扇区，以及目录项 */
pub fn get_info_cache(
    block_id: usize,
    block_device: Arc<dyn BlockDevice>,
    rw_mode: CacheMode,
) -> Arc<RwLock<BlockCache>> {
    if rw_mode == CacheMode::READ {
        // make sure the blk is in cache
        if let Some(blk) = DATA_BLOCK_CACHE_MANAGER.read().read_block_cache(block_id) {
            return blk;
        }
        INFO_CACHE_MANAGER
            .write()
            .get_block_cache(block_id, block_device);
        INFO_CACHE_MANAGER
            .read()
            .read_block_cache(block_id)
            .unwrap()
    } else {
        if let Some(blk) = DATA_BLOCK_CACHE_MANAGER.read().read_block_cache(block_id) {
            return blk;
        }
        INFO_CACHE_MANAGER
            .write()
            .get_block_cache(block_id, block_device)
    }
}

pub fn write_to_dev() {
    INFO_CACHE_MANAGER.write().drop_all();
    DATA_BLOCK_CACHE_MANAGER.write().drop_all();
}
/*
那个谁别问我为什么这段代码写的这么难看也别动这些代码
这都是你害得
*/
pub struct InfoCacheMgrWrapper {
    empty: (),
}

pub struct DataCacheMgrWrapper {
    empty: (),
}

pub struct InfoBlockCacheWrapper {
    block_id: usize,
}
pub struct DataBlockCacheWrapper {
    block_id: usize,
}
impl DataBlockCacheWrapper {
    fn new(block_id: usize) -> Self {
        Self { block_id }
    }
}
impl InfoBlockCacheWrapper {
    fn new(block_id: usize) -> Self {
        Self { block_id }
    }
}

macro_rules! BlockCacheImpl {
    ($cache:ident,$func:ident) => {
        impl Cache for $cache {
            fn read<T, V>(&self, offset: usize, f: impl FnOnce(&T) -> V) -> V {
                $func(self.block_id, BLOCK_DEVICE.clone(), CacheMode::READ)
                    .read()
                    .read(offset, f)
            }

            fn modify<T, V>(&mut self, offset: usize, f: impl FnOnce(&mut T) -> V) -> V {
                $func(self.block_id, BLOCK_DEVICE.clone(), CacheMode::READ)
                    .write()
                    .modify(offset, f)
            }
        }
    };
}
macro_rules! CacheMgrImpl {
    ($mgr:ident,$cache:ident) => {
        impl CacheManager for $mgr {
            const CACHE_SZ: usize = BLOCK_SZ;

            type CacheType = $cache;

            fn new() -> Self
            where
                Self: Sized,
            {
                Self { empty: () }
            }
            fn try_get_block_cache(
                &self,
                block_id: usize,
                inner_cache_id: usize,
            ) -> Option<Arc<Mutex<Self::CacheType>>> {
                None
            }
            fn get_block_cache<FUNC>(
                &self,
                block_id: usize,
                inner_cache_id: usize,
                neighbor: FUNC,
                block_device: Arc<dyn BlockDevice>,
            ) -> Arc<spin::Mutex<Self::CacheType>>
            where
                FUNC: Fn() -> Vec<usize>,
            {
                Arc::new(Mutex::new($cache::new(block_id)))
            }
        }
    };
}

CacheMgrImpl!(DataCacheMgrWrapper, DataBlockCacheWrapper);

BlockCacheImpl!(DataBlockCacheWrapper, get_block_cache);

CacheMgrImpl!(InfoCacheMgrWrapper, InfoBlockCacheWrapper);

BlockCacheImpl!(InfoBlockCacheWrapper, get_info_cache);

*/