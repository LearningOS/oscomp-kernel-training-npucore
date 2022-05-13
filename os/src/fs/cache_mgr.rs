use alloc::sync::Arc;
use alloc::vec::Vec;
use core::alloc::Layout;
use easy_fs::{BlockDevice, Cache, CacheManager};
use spin::Mutex;

use alloc::alloc::{alloc, dealloc};
use alloc::collections::BTreeMap;
use easy_fs::BLOCK_SZ;
use lazy_static::*;
#[allow(unused)]
use spin::RwLock;

use crate::board::BlockDeviceImpl;
use crate::drivers::BLOCK_DEVICE;

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
                &mut self,
                block_id: usize,
                inner_cache_id: usize,
            ) -> Option<Arc<Mutex<Self::CacheType>>> {
                None
            }
            fn get_block_cache<FUNC>(
                &mut self,
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
