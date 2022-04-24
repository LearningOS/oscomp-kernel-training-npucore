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
    pub fat_cache_mgr: Arc<T>,
    /// The first block id of FAT.
    /// In FAT32, this is equal to bpb.rsvd_sec_cnt
    start_block_id: usize,
    /// size fo sector in bytes copied from BPB
    byts_per_sec: usize,
    /// The total number of FAT entries
    tot_ent: usize,
    /// The queue used to store known vacant clusters
    vacant_clus: spin::Mutex<VecDeque<u32>>,
    /// The final unused clus id we found
    hint: Mutex<usize>,
}

impl<T: CacheManager> Fat<T> {
    /// Get the next cluster number pointed by current fat entry.
    pub fn get_next_clus_num(&self, start: u32, block_device: &Arc<dyn BlockDevice>) -> u32 {
        self.fat_cache_mgr
            .get_block_cache(
                self.this_fat_sec_num(start) as usize,
                Some(self.this_fat_inner_sec_num(start)),
                Some(self.start_block_id),
                Some(
                    (((self.this_fat_inner_sec_num(start)) & (!7)) + self.start_block_id
                        ..self.start_block_id + (self.this_fat_inner_sec_num(start)) & (!7))
                        .collect(),
                ),
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
    pub fn try_get_clus(
        &self,
        start: u32,
        block_device: &Arc<dyn BlockDevice>,
        cache_mgr: &Arc<T>,
    ) -> Option<u32> {
        self.get_next_clus_num(start, block_device);
        todo!();
    }

    /// Create a new FAT object in memory.
    /// # Argument
    /// * `rsvd_sec_cnt`: size of BPB
    /// * `byts_per_sec`: literal meaning
    /// * `clus`: the total numebr of FAT entries
    pub fn new(rsvd_sec_cnt: usize, byts_per_sec: usize, clus: usize) -> Self {
        Self {
            //used_marker: Default::default(),
            fat_cache_mgr: (T::new(rsvd_sec_cnt)),
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
            .get_block_cache(
                self.this_fat_sec_num(current) as usize,
                Some(self.this_fat_inner_sec_num(current as u32)),
                Some(self.start_block_id),
                Some(
                    (((self.this_fat_inner_sec_num(current)) & (!7)) + self.start_block_id
                        ..8 + (self.this_fat_inner_sec_num(current)) & (!7) + self.start_block_id)
                        .collect(),
                ),
                block_device.clone(),
            )
            .lock()
            .modify(
                self.this_fat_ent_offset(current as u32),
                |bitmap_block: &mut u32| {
                    *bitmap_block = next;
                },
            )
    }

    pub fn alloc_mult(
        &self,
        block_device: &Arc<dyn BlockDevice>,
        alloc_num: usize,
        attach: Option<u32>,
    ) -> Option<Vec<u32>> {
        todo!();
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
        if attach.is_none()
            || self.get_next_clus_num(attach.unwrap(), block_device) >= FAT_ENTRY_RESERVED_TO_END
        {
            if let Some(i) = self.alloc_one_no_attach(block_device) {
                if attach.is_some() {
                    self.set_next_clus(block_device, attach.unwrap(), i);
                }
                Some(i)
            } else {
                None
            }
        } else {
            None
        }
    }

    fn alloc_one_no_attach(&self, block_device: &Arc<dyn BlockDevice>) -> Option<u32> {
        let mut vacant_lock = self.vacant_clus.lock();
        // get from vacant_clus
        if let Some(clus_id) = vacant_lock.pop_back() {
            // modify cached
            self.set_next_clus(block_device, clus_id, EOC);
            return Some(clus_id);
        } else {
            let hlock = self.hint.lock();
            let start: usize = *hlock;
            drop(hlock);
            for clus_id in start..self.tot_ent {
                let pos = self
                    .fat_cache_mgr
                    .get_block_cache(
                        self.this_fat_sec_num(clus_id as u32) as usize,
                        Some(self.this_fat_inner_sec_num(clus_id as u32)),
                        Some(self.start_block_id),
                        Some(
                            (((self.this_fat_inner_sec_num(clus_id as u32)) & (!7))
                                + self.start_block_id
                                ..8 + self.start_block_id
                                    + (self.this_fat_inner_sec_num(clus_id as u32))
                                    & (!7))
                                .collect(),
                        ),
                        Arc::clone(block_device),
                    )
                    .lock()
                    .modify(
                        self.this_fat_ent_offset(clus_id as u32) as usize,
                        |bitmap_block: &mut u32| {
                            if (*bitmap_block & EOC) == FAT_ENTRY_FREE {
                                *bitmap_block = EOC;
                                Some(clus_id as u32)
                            } else {
                                None
                            }
                        },
                    );
                if let Some(unused_id) = pos {
                    let mut hlock = self.hint.lock();
                    *hlock = unused_id as usize + 1;
                    drop(hlock);
                    for clus_id in (unused_id + 1) as usize
                        ..((unused_id as usize % (BLOCK_SZ >> 2)) + BLOCK_SZ >> 2)
                    {
                        if FAT_ENTRY_FREE == self.get_next_clus_num(clus_id as u32, block_device) {
                            vacant_lock.push_back(clus_id as u32)
                        };
                    }
                    return Some(unused_id);
                }
            }
        }

        // get from vacant_clus
        if let Some(i) = vacant_lock.pop_back() {
            // modify cached
            self.set_next_clus(block_device, i, EOC);
            return Some(i);
        } else {
            None
        }
    }

    /// Find and allocate an empty block from data area.
    /// This function must be changed into a cluster-based one in the future.
    pub fn dealloc(&self, block_device: &Arc<dyn BlockDevice>, bit: usize) {
        self.set_next_clus(block_device, bit as u32, FAT_ENTRY_FREE);
        let mut lock = self.vacant_clus.lock();
        if lock.len() < VACANT_CLUS_CACHE_SIZE {
            lock.push_back(bit as u32);
        }
    }

    pub fn maximum(&self) -> usize {
        self.tot_ent * BLOCK_BITS
    }
}
