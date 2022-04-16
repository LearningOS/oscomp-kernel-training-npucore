use super::{BlockDevice, Fat};
use crate::{
    block_cache::{CacheManager, FileCache},
    layout::{DiskInodeType, BPB},
    Inode,
};
use alloc::sync::Arc;

pub struct EasyFileSystem<T: CacheManager> {
    /// Partition/Device the FAT32 is hosted on.
    pub block_device: Arc<dyn BlockDevice>,

    /// Block Cache Manager
    pub cache_mgr: Arc<T>,
    /// FAT information
    pub fat: Fat<T>,

    /// The first data sector beyond the root directory
    pub data_area_start_block: u32,

    /// This is set to the cluster number of the first cluster of the root directory,
    /// usually 2 but not required to be 2.
    pub root_clus: u32,

    /// sector per cluster, usually 8 for SD card
    pub sec_per_clus: u8,

    /// Bytes per sector, 512 for SD card
    pub byts_per_clus: u16,
}
#[allow(unused)]
type DataBlock = [u8; crate::BLOCK_SZ];

// export implementation of methods from FAT.
impl<T: CacheManager> EasyFileSystem<T> {
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
        self.fat
            .get_next_clus_num(result, &self.block_device, self.cache_mgr.clone())
    }
}

// All sorts of accessors
impl<T: CacheManager> EasyFileSystem<T> {
    pub fn first_data_sector(&self) -> u32 {
        self.data_area_start_block
    }
    pub fn clus_size(&self) -> u32 {
        self.byts_per_clus.into()
    }
}

impl<T: CacheManager> EasyFileSystem<T> {
    /// n is the ordinal number of the cluster.
    #[inline(always)]
    pub fn first_sector_of_cluster(&self, n: u32) -> u32 {
        assert_eq!(self.sec_per_clus.count_ones(), 1);
        (if n > 2 {
            (n - 2) << (self.sec_per_clus as u32).trailing_zeros()
        } else {
            0
        }) as u32
            + self.data_area_start_block as u32
    }
    #[inline(always)]
    pub fn in_cluster(&self, block_id: u32) -> u32 {
        ((block_id - self.first_data_sector()) >> self.sec_per_clus.trailing_zeros()) + 2
    }
    /// Open the filesystem object.
    pub fn open(block_device: Arc<dyn BlockDevice>, cache_mgr: Arc<T>) -> Arc<Self> {
        // read SuperBlock
        cache_mgr
            .get_block_cache(0, Arc::clone(&block_device))
            .lock()
            .read(0, |super_block: &BPB| {
                assert!(super_block.is_valid(), "Error loading EFS!");
                let efs = Self {
                    block_device,
                    cache_mgr,
                    fat: Fat::new(
                        super_block.rsvd_sec_cnt as usize,
                        super_block.byts_per_sec as usize,
                        (super_block.data_sector_count() / super_block.clus_size()) as usize,
                    ),
                    root_clus: super_block.root_clus,
                    sec_per_clus: super_block.sec_per_clus,
                    byts_per_clus: super_block.byts_per_sec,
                    data_area_start_block: super_block.first_data_sector(),
                };
                Arc::new(efs)
            })
    }
    /// Open the root directory
    pub fn root_inode(efs: &Arc<Self>) -> Inode<T> {
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

    /// Note: "Inode" does NOT exist in FAT, but directory entry DOES.
    /// So, keep it anyway.
    pub fn alloc_inode(&mut self) -> u32 {
        self.fat.alloc(&self.block_device, self.cache_mgr.clone());
        todo!();
    }

    /// Return a block ID instead of an ID in the data area.
    pub fn alloc_data(&mut self) -> u32 {
        self.fat
            .alloc(&self.block_device, self.cache_mgr.clone())
            .unwrap() as u32
            + self.data_area_start_block
    }

    pub fn dealloc_data(&mut self, clus_id: u32) {
        //!!!! We ASSUMED that the data is NOT zero-inited.
        /* get_block_cache(clus_id as usize, Arc::clone(&self.block_device))
         *     .lock()
         *     .modify(0, |data_block: &mut DataBlock| {
         *         data_block.iter_mut().for_each(|p| {
         *             *p = 0;
         *         })
         *     }); */
        self.fat
            .dealloc(&self.block_device, self.cache_mgr.clone(), clus_id as usize)
    }
}
