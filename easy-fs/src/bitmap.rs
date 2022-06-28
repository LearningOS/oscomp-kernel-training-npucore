use crate::{
    block_cache::{Cache, CacheManager},
    layout::BAD_BLOCK,
};

use super::{BlockDevice, BLOCK_SZ};
use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use log::error;
use spin::{Mutex, MutexGuard};

const BLOCK_BITS: usize = BLOCK_SZ * 8;
const VACANT_CLUS_CACHE_SIZE: usize = 64;
const FAT_ENTRY_FREE: u32 = 0;
const FAT_ENTRY_RESERVED_TO_END: u32 = 0x0FFF_FFF8;
pub const EOC: u32 = 0x0FFF_FFFF;
/// *In-memory* data structure
/// In FAT32, there are 2 FATs by default. We use ONLY the first one.

pub struct Fat<T> {
    pub fat_cache_mgr: Arc<Mutex<T>>,
    /// The first block id of FAT.
    /// In FAT32, this is equal to bpb.rsvd_sec_cnt
    start_block_id: usize,
    /// size fo sector in bytes copied from BPB
    byts_per_sec: usize,
    /// The total number of FAT entries
    tot_ent: usize,
    /// The queue used to store known vacant clusters
    vacant_clus: Mutex<VecDeque<u32>>,
    /// The final unused cluster id we found
    hint: Mutex<usize>,
}

impl<T: CacheManager> Fat<T> {
    fn get_eight_blk(&self, start: u32) -> Vec<usize> {
        let v = (((self.this_fat_inner_sec_num(start)) & (!7)) + self.start_block_id
            ..self.start_block_id + (self.this_fat_inner_sec_num(start)) & (!7))
            .collect();
        return v;
    }
    /// Get the next cluster number pointed by current fat entry.
    pub fn get_next_clus_num(&self, start: u32, block_device: &Arc<dyn BlockDevice>) -> u32 {
        self.fat_cache_mgr
            .lock()
            .get_block_cache(
                self.this_fat_sec_num(start) as usize,
                self.this_fat_inner_cache_num(start),
                || -> Vec<usize> { self.get_eight_blk(start) },
                block_device,
            )
            .lock()
            .read(
                self.this_fat_ent_offset(start) as usize,
                |fat_entry: &u32| -> u32 { *fat_entry },
            )
            & EOC
    }

    /// In theory, there may also be one function that only reads the first parts, or the needed FAT entries of the file.
    pub fn get_all_clus_num(
        &self,
        mut start: u32,
        block_device: &Arc<dyn BlockDevice>,
    ) -> Vec<u32> {
        let mut v = Vec::new();
        loop {
            v.push(start);
            start = self.get_next_clus_num(start, &block_device);
            if [BAD_BLOCK, FAT_ENTRY_FREE].contains(&start) || start >= FAT_ENTRY_RESERVED_TO_END {
                break;
            }
        }
        v
    }

    /// Create a new FAT object in memory.
    /// # Argument
    /// * `rsvd_sec_cnt`: size of BPB
    /// * `byts_per_sec`: literal meaning
    /// * `clus`: the total numebr of FAT entries
    pub fn new(
        rsvd_sec_cnt: usize,
        byts_per_sec: usize,
        clus: usize,
        fat_cache_mgr: Arc<Mutex<T>>,
    ) -> Self {
        Self {
            //used_marker: Default::default(),
            fat_cache_mgr,
            start_block_id: rsvd_sec_cnt,
            byts_per_sec,
            tot_ent: clus,
            vacant_clus: spin::Mutex::new(VecDeque::new()),
            hint: Mutex::new(0),
        }
    }

    #[inline(always)]
    /// Given any valid cluster number N,
    /// where in the FAT(s) is the entry for that cluster number
    /// Return the sector number of the FAT sector that contains the entry for
    /// cluster N in the first FAT
    pub fn this_fat_inner_cache_num(&self, n: u32) -> usize {
        let fat_offset = n * 4;
        fat_offset as usize / T::CACHE_SZ
    }

    #[inline(always)]
    /// Given any valid cluster number N,
    /// where in the FAT(s) is the entry for that cluster number
    /// Return the sector number of the FAT sector that contains the entry for
    /// cluster N in the first FAT
    pub fn this_fat_inner_sec_num(&self, n: u32) -> usize {
        let fat_offset = n * 4;
        (fat_offset / (self.byts_per_sec as u32)) as usize
    }
    #[inline(always)]
    /// Given any valid cluster number N,
    /// where in the FAT(s) is the entry for that cluster number
    /// Return the sector number of the FAT sector that contains the entry for
    /// cluster N in the first FAT
    pub fn this_fat_sec_num(&self, n: u32) -> usize {
        let fat_offset = n * 4;
        (self.start_block_id as u32 + (fat_offset / (self.byts_per_sec as u32))) as usize
    }
    #[inline(always)]
    /// Return the offset (measured by bytes) of the entry from the first bit of the sector of the
    /// n is the ordinal number of the cluster
    pub fn this_fat_ent_offset(&self, n: u32) -> usize {
        let fat_offset = n * 4;
        (fat_offset % (T::CACHE_SZ as u32)) as usize
    }
    /// Assign the cluster entry to `current` to `next`
    fn set_next_clus(&self, block_device: &Arc<dyn BlockDevice>, current: Option<u32>, next: u32) {
        if current.is_none() {
            return;
        }
        let current = current.unwrap();
        self.fat_cache_mgr
            .lock()
            .get_block_cache(
                self.this_fat_sec_num(current) as usize,
                self.this_fat_inner_cache_num(current as u32),
                || -> Vec<usize> { self.get_eight_blk(current) },
                block_device,
            )
            .lock()
            .modify(
                self.this_fat_ent_offset(current as u32),
                |bitmap_block: &mut u32| {
                    //println!("[set_next_clus]bitmap_block:{}->{}", *bitmap_block, next);
                    *bitmap_block = next;
                },
            )
    }

    pub fn cnt_all_fat(&self, block_device: &Arc<dyn BlockDevice>) -> usize {
        let mut sum = 0;
        /* println!("[cnt_all_fat] self.clus{:?}", self.vacant_clus); */
        for i in 0..self.tot_ent as u32 {
            if self.get_next_clus_num(i, block_device) == FAT_ENTRY_FREE {
                sum += 1;
            }
        }
        sum
    }

    /// Allocate as many clusters (but not greater than alloc_num) as possible.
    /// `block_device`: The target block_device.
    /// `alloc_num`: The number of clusters to allocate.
    /// `last`: The preceding cluster of the one to be allocated.
    pub fn alloc(
        &self,
        block_device: &Arc<dyn BlockDevice>,
        alloc_num: usize,
        mut last: Option<u32>,
    ) -> Vec<u32> {
        let mut allocated_cluster = Vec::new();
        // A lock is required to guarantee mutual exclusion between processes.
        let mut hlock = self.hint.lock();
        for _ in 0..alloc_num {
            last = self.alloc_one(block_device, last, &mut hlock);
            if last.is_none() {
                // There is no more free cluster.
                // Or `last` next cluster is valid.
                error!("[alloc]: alloc error, last: {:?}", last);
                break;
            }
            allocated_cluster.push(last.unwrap());
        }
        allocated_cluster
    }

    
    /// Find and allocate an cluster from data area.
    /// `block_device`: The target block_device.
    /// `last`: The preceding cluster of the one to be allocated.
    /// `hlock`: The lock of hint(Fat). This guarantees mutual exclusion between processes.
    fn alloc_one(
        &self,
        block_device: &Arc<dyn BlockDevice>,
        last: Option<u32>,
        hlock: &mut MutexGuard<usize>
    ) -> Option<u32> {
        if last.is_some() {
            // If next cluster is invalid, return None. 
            let next_cluster_of_current = self.get_next_clus_num(last.unwrap(), block_device);
            if next_cluster_of_current < FAT_ENTRY_RESERVED_TO_END {
                return None;
            }            
        }
        // Now we can allocate clusters freely

        // Get a free cluster from `vacant_clus`
        if let Some(free_clus_id) = self.vacant_clus.lock().pop_back() {
            self.set_next_clus(block_device, last, free_clus_id);
            self.set_next_clus(block_device, Some(free_clus_id), EOC);
            return Some(free_clus_id);
        }

        // Allocate a free cluster starts with `hint`
        let start = **hlock;
        let free_clus_id = self.get_next_free_clus(start as u32, block_device);
        if free_clus_id.is_none() {
            return None;
        }
        let free_clus_id = free_clus_id.unwrap();
        **hlock = (free_clus_id + 1) as usize % self.tot_ent;

        self.set_next_clus(block_device, last, free_clus_id);
        self.set_next_clus(block_device, Some(free_clus_id), EOC);
        Some(free_clus_id)
    }

    /// Find next free cluster from data area.
    /// `start`: The cluster id to traverse to find the next free cluster
    /// `block_device`: The target block_device.
    fn get_next_free_clus(
        &self, 
        start: u32, 
        block_device: &Arc<dyn BlockDevice>
    ) -> Option<u32> {
        for clus_id in start..self.tot_ent as u32 {
            if FAT_ENTRY_FREE == self.get_next_clus_num(clus_id, block_device) {
                return Some(clus_id);
            }
        }
        for clus_id in 0..start {
            if FAT_ENTRY_FREE == self.get_next_clus_num(clus_id, block_device) {
                return Some(clus_id);
            }
        }
        None
    }

    /// Free multiple clusters from the data area.
    /// `block_device`: The target block_device.
    /// `cluster_list`: The clusters that need to be freed
    pub fn free(
        &self, 
        block_device: &Arc<dyn BlockDevice>, 
        cluster_list: Vec<u32>
    ) {
        // Before freeing, a lock 
        let mut lock = self.vacant_clus.lock();
        for cluster_id in cluster_list {
            self.set_next_clus(block_device, Some(cluster_id), FAT_ENTRY_FREE);
            if lock.len() < VACANT_CLUS_CACHE_SIZE {
                lock.push_back(cluster_id);
            }
        }
    }

    pub fn maximum(&self) -> usize {
        self.tot_ent * BLOCK_BITS
    }
}
