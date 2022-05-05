use core::marker::PhantomData;

use super::{BlockDevice, Fat};
use crate::{
    block_cache::{Cache, CacheManager},
    layout::{DiskInodeType, BPB},
    Inode, BLOCK_SZ,
};
use alloc::sync::Arc;

pub struct EasyFileSystem<T: CacheManager, F: CacheManager> {
    used_marker: PhantomData<T>,
    /// Partition/Device the FAT32 is hosted on.
    pub block_device: Arc<dyn BlockDevice>,

    /// FAT information
    pub fat: Fat<F>,

    /// The first data sector beyond the root directory
    pub data_area_start_block: u32,

    /// This is set to the cluster number of the first cluster of the root directory,
    /// usually 2 but not required to be 2.
    pub root_clus: u32,

    /// sector per cluster, usually 8 for SD card
    pub sec_per_clus: u8,

    /// Bytes per sector, 512 for SD card
    pub byts_per_sec: u16,
}
#[allow(unused)]
type DataBlock = [u8; crate::BLOCK_SZ];

// export implementation of methods from FAT.
impl<T: CacheManager, F: CacheManager> EasyFileSystem<T, F> {
    #[inline(always)]
    pub fn this_fat_ent_offset(&self, n: u32) -> u32 {
        self.fat.this_fat_ent_offset(n) as u32
    }
    #[inline(always)]
    pub fn this_fat_sec_num(&self, n: u32) -> u32 {
        self.fat.this_fat_sec_num(n) as u32
    }
    #[inline(always)]
    pub fn get_next_clus_num(&self, result: u32) -> u32 {
        self.fat.get_next_clus_num(result, &self.block_device)
    }
}

// All sorts of accessors
impl<T: CacheManager, F: CacheManager> EasyFileSystem<T, F> {
    pub fn first_data_sector(&self) -> u32 {
        self.data_area_start_block
    }
    #[inline(always)]
    pub fn clus_size(&self) -> u32 {
        self.byts_per_sec as u32 * self.sec_per_clus as u32 
    }
}

impl<T: CacheManager, F: CacheManager> EasyFileSystem<T, F> {
    /// n is the ordinal number of the cluster.
    #[inline(always)]
    pub fn first_sector_of_cluster(&self, n: u32) -> u32 {
        assert_eq!(self.sec_per_clus.count_ones(), 1);
        assert!(n >= 2);
        let start_block = self.data_area_start_block;
        let offset_blocks = (n - 2) * self.sec_per_clus as u32;
        start_block + offset_blocks
    }
    #[inline(always)]
    pub fn in_cluster(&self, block_id: u32) -> u32 {
        ((block_id - self.first_data_sector()) >> self.sec_per_clus.trailing_zeros()) + 2
    }
    /// Open the filesystem object.
    pub fn open(
        block_device: Arc<dyn BlockDevice>,
        bpb_fat_cache_mgr: Arc<spin::Mutex<F>>,
    ) -> Arc<Self> {
        assert!(F::CACHE_SZ % BLOCK_SZ == 0);
        assert!(T::CACHE_SZ % BLOCK_SZ == 0);
        // read SuperBlock
        let fat_cache_mgr = bpb_fat_cache_mgr.clone();
        bpb_fat_cache_mgr
            .lock()
            .get_block_cache(
                0,
                0,
                || -> alloc::vec::Vec<usize> { alloc::vec::Vec::new() },
                Arc::clone(&block_device),
            )
            .lock()
            .read(0, |super_block: &BPB| {
                assert!(super_block.is_valid(), "Error loading EFS!");
                let efs = Self {
                    used_marker: Default::default(),
                    block_device,
                    fat: Fat::new(
                        super_block.rsvd_sec_cnt as usize,
                        super_block.byts_per_sec as usize,
                        (super_block.data_sector_count() / super_block.clus_size()) as usize,
                        fat_cache_mgr,
                    ),
                    root_clus: super_block.root_clus,
                    sec_per_clus: super_block.sec_per_clus,
                    byts_per_sec: super_block.byts_per_sec,
                    data_area_start_block: super_block.first_data_sector(),
                };
                Arc::new(efs)
            })
    }
    /// Open the root directory
    pub fn root_inode(efs: &Arc<Self>) -> Inode<T, F> {
        let rt_clus = efs.root_clus;
        // release efs lock
        Inode::new(
            rt_clus as usize,
            DiskInodeType::Directory,
            None,
            None,
            Arc::clone(efs),
        )
    }
    /// Look up the first sector denoted by inode_id
    /// Inode is not natively supported in FAT32. However, fst_clus may be used as the inode_id
    /// Only path is an UNIQUE id to a file in FAT32.
    pub fn get_disk_fat_pos(&self, n: u32) -> (u32, usize) {
        (
            self.fat.this_fat_sec_num(n) as u32,
            self.fat.this_fat_ent_offset(n) as usize,
        )
    }
}
