use crate::{
    block_cache::FileCache,
    layout::{BAD_BLOCK, EOC},
};

use super::{block_cache::get_block_cache, BlockDevice, BLOCK_SZ};
use alloc::{collections::VecDeque, sync::Arc, vec::Vec};

const BLOCK_BITS: usize = BLOCK_SZ * 8;
const VACANT_CLUS_CACHE_SIZE: usize = 64;
/// *In-memory* data structure
/// In FAT32, there are 2 FATs by default. We use ONLY the first one.
pub struct Fat {
    /// The first block id of FAT.
    /// In FAT32, this is equal to bpb.rsvd_sec_cnt
    start_block_id: usize,
    /// size fo sector in bytes copied from BPB
    byts_per_sec: usize,
    /// The total number of FAT entries
    tot_ent: usize,
    /// The queue used to store known vacant clusters
    vacant_clus: spin::Mutex<VecDeque<u32>>,
}

impl Fat {
    /// Get the next cluster number pointed by current fat entry.
    pub fn get_next_clus_num(&self, start: u32, block_device: &Arc<dyn BlockDevice>) -> u32 {
        get_block_cache(
            self.this_fat_sec_num(start) as usize,
            Arc::clone(block_device),
        )
        .lock()
        .read(
            self.this_fat_ent_offset(start) as usize,
            |fat_entry: &u32| -> u32 { *fat_entry },
        ) & 0x0FFFFFF
    }

    /// In theory, there may also be one function that only reads the first parts, or the needed FAT entries of the file.
    pub fn get_all_clus_num(&self, mut start: u32, block_device: Arc<dyn BlockDevice>) -> Vec<u32> {
        let mut v = Vec::new();
        loop {
            v.push(start);
            start = self.get_next_clus_num(start, &block_device);
            if [BAD_BLOCK, EOC, 0].contains(&start) {
                break;
            }
        }
        v
    }
    pub fn try_get_clus(&self, start: u32, block_device: &Arc<dyn BlockDevice>) -> Option<u32> {
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
            start_block_id: rsvd_sec_cnt,
            byts_per_sec,
            tot_ent: clus,
            vacant_clus: spin::Mutex::new(VecDeque::new()),
        }
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

    /// Find and allocate an cluster from data area.
    /// This function must be changed into a cluster-based one in the future.
    pub fn alloc(&mut self, block_device: &Arc<dyn BlockDevice>) -> Option<u32> {
        let mut lock = self.vacant_clus.lock();
        if lock.is_empty() {
            for clus_id in 0..self.tot_ent {
                let pos = get_block_cache(
                    self.this_fat_sec_num(clus_id as u32) as usize,
                    Arc::clone(block_device),
                )
                .lock()
                .modify(
                    self.this_fat_ent_offset(clus_id as u32) as usize,
                    |bitmap_block: &mut u32| {
                        if (*bitmap_block & EOC) == 0 {
                            *bitmap_block = EOC;
                            Some(clus_id as u32)
                        } else {
                            None
                        }
                    },
                );
                if pos.is_some() {
                    if let Some(id) = pos {
                        for clus_id in
                            (id + 1) as usize..((id as usize % (BLOCK_SZ >> 2)) + BLOCK_SZ >> 2)
                        {
                            get_block_cache(
                                self.this_fat_sec_num(id) as usize,
                                block_device.clone(),
                            )
                            .lock()
                            .read(
                                self.this_fat_ent_offset(clus_id as u32),
                                |bitmap_block: &u32| {
                                    if (*bitmap_block & EOC) == 0 {
                                        lock.push_back(clus_id as u32);
                                    }
                                },
                            );
                        }
                    }
                    return pos;
                }
            }
        }

        // get from vacant_clus
        if let Some(i) = lock.pop_back() {
            // modify cached
            get_block_cache(self.this_fat_sec_num(i) as usize, block_device.clone())
                .lock()
                .modify(
                    self.this_fat_ent_offset(i as u32),
                    |bitmap_block: &mut u32| {
                        *bitmap_block = crate::layout::EOC;
                    },
                );
            return Some(i);
        } else {
            None
        }
    }

    /// Find and allocate an empty block from data area.
    /// This function must be changed into a cluster-based one in the future.
    pub fn dealloc(&mut self, block_device: &Arc<dyn BlockDevice>, bit: usize) {
        get_block_cache(
            self.this_fat_sec_num(bit as u32) as usize,
            Arc::clone(block_device),
        )
        .lock()
        .modify(
            self.this_fat_ent_offset(bit as u32) as usize,
            |bitmap_block: &mut u32| {
                //assert!(bitmap_block!=0 && bitmap_block!=BAD_BLOCK);
                *bitmap_block = 0;
            },
        );
        let mut lock = self.vacant_clus.lock();
        if lock.len() < VACANT_CLUS_CACHE_SIZE {
            lock.push_back(bit as u32);
        }
    }

    pub fn maximum(&self) -> usize {
        self.tot_ent * BLOCK_BITS
    }
}
