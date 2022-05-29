use crate::{
    block_cache::{Cache, CacheManager},
    layout::BAD_BLOCK,
};

use super::{BlockDevice, BLOCK_SZ};
use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use spin::Mutex;

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
    /// The final unused clus id we found
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
                Arc::clone(block_device),
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
        (fat_offset % (self.byts_per_sec as u32)) as usize
    }
    /// Assign the cluster entry to `current` to `next`
    fn set_next_clus(&self, block_device: &Arc<dyn BlockDevice>, current: u32, next: u32) {
        self.fat_cache_mgr
            .lock()
            .get_block_cache(
                self.this_fat_sec_num(current) as usize,
                self.this_fat_inner_cache_num(current as u32),
                || -> Vec<usize> { self.get_eight_blk(current) },
                block_device.clone(),
            )
            .lock()
            .modify(
                self.this_fat_ent_offset(current as u32),
                |bitmap_block: &mut u32| {
                    println!("[set_next_clus]bitmap_block:{}->{}", *bitmap_block, next);
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
    pub fn alloc_mult(
        &self,
        block_device: &Arc<dyn BlockDevice>,
        alloc_num: usize,
        attach: Option<u32>,
    ) -> Vec<u32> {
        let mut v = Vec::new();
        let mut last = attach;
        for _ in 0..alloc_num {
            last = self.alloc_one(block_device, last);
            if last.is_none() {
                println!("why here?");
                break;
            }
            v.push(last.unwrap());
        }
        v
    }

    /// Find and allocate an cluster from data area.
    /// `block_device`: The target block_device
    /// `cache_mgr`: The cache manager
    /// `attach`: The preceding cluster of the one to be allocated
    pub fn alloc_one(
        &self,
        block_device: &Arc<dyn BlockDevice>,
        attach: Option<u32>,
    ) -> Option<u32> {
        if attach.is_some()
            && self.get_next_clus_num(attach.unwrap(), block_device) < FAT_ENTRY_RESERVED_TO_END
        {
            return None;
        }
        // now we can alloc freely
        if let Some(next_clus_id) = self.alloc_one_no_attach_locked(block_device) {
            if attach.is_some() {
                self.set_next_clus(block_device, attach.unwrap(), next_clus_id);
            }
            return Some(next_clus_id);
        }
        None
    }
    fn alloc_one_no_attach_locked(&self, block_device: &Arc<dyn BlockDevice>) -> Option<u32> {
        // get from vacant_clus
        if let Some(clus_id) = self.vacant_clus.lock().pop_back() {
            // modify cached
            self.set_next_clus(block_device, clus_id, EOC);
            return Some(clus_id);
        }

        let mut hlock = self.hint.lock();
        let start = *hlock;
        let free_clus_id = self.get_next_free_clus(start as u32, block_device);
        if free_clus_id.is_none() {
            return None;
        }
        let free_clus_id = free_clus_id.unwrap();
        *hlock = (free_clus_id + 1) as usize % self.tot_ent;
        drop(hlock);

        self.fat_cache_mgr
            .lock()
            .get_block_cache(
                self.this_fat_sec_num(free_clus_id as u32) as usize,
                self.this_fat_inner_cache_num(free_clus_id as u32),
                || -> Vec<usize> { self.get_eight_blk(free_clus_id as u32) },
                Arc::clone(block_device),
            )
            .lock()
            .modify(
                self.this_fat_ent_offset(free_clus_id as u32) as usize,
                |bitmap_block: &mut u32| {
                    assert_eq!((*bitmap_block & EOC), FAT_ENTRY_FREE);
                    println!("[alloc_one]bitmap_block:{}->{}", *bitmap_block, EOC);
                    *bitmap_block = EOC;
                    Some(free_clus_id)
                },
            )
    }

    fn get_next_free_clus(&self, start: u32, block_device: &Arc<dyn BlockDevice>) -> Option<u32> {
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

    /// Find and allocate an empty block from data area.
    /// This function must be changed into a cluster-based one in the future.
    pub fn dealloc(&self, block_device: &Arc<dyn BlockDevice>, bit: u32) {
        self.set_next_clus(block_device, bit as u32, FAT_ENTRY_FREE);
        let mut lock = self.vacant_clus.lock();
        if lock.len() < VACANT_CLUS_CACHE_SIZE {
            lock.push_back(bit as u32);
        }
    }
    pub fn mult_dealloc(&self, block_device: &Arc<dyn BlockDevice>, v: Vec<u32>) {
        for i in v {
            self.dealloc(block_device, i);
        }
    }

    pub fn maximum(&self) -> usize {
        self.tot_ent * BLOCK_BITS
    }
}
