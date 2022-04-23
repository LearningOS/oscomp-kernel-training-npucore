use core::mem;
use core::ops::{AddAssign, SubAssign};

use super::{DiskInodeType, EasyFileSystem};

use alloc::string::String;

use crate::block_cache::{Cache, CacheManager};
use crate::layout::{FATDirEnt, FATDirShortEnt};
use crate::{DataBlock, BLOCK_SZ};

use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::{Mutex, MutexGuard};
/// The functionality of ClusLi & Inode can be merged.
/// The struct for file information
/* *ClusLi was DiskInode*
 * Even old New York, was New Amsterdam...
 * Why they changed it I can't say.
 * People just like it better that way.*/
pub struct Inode<T: CacheManager> {
    /// For FAT32, size is a value computed from FAT.
    /// You should iterate around the FAT32 to get the size.
    pub size: Mutex<u32>,
    /// The cluster list.
    pub direct: Mutex<Vec<u32>>,
    pub type_: DiskInodeType,
    pub parent_dir: Option<Arc<Self>>,
    file_cache_mgr: Arc<T>,
    fs: Arc<EasyFileSystem<T>>,
    //    block_device: Arc<dyn BlockDevice>,
}

impl<T: CacheManager> Inode<T> {
    pub fn first_sector(&self) -> Option<u32> {
        if !self.direct.lock().is_empty() {
            Some(self.fs.first_sector_of_cluster(self.direct.lock()[0]))
        } else {
            None
        }
    }
    #[inline(always)]
    pub fn get_inode_num(&self) -> Option<u32> {
        self.first_sector()
    }
    /// Get the neighboring 8 or fewer(the trailing mod-of-eight blocks of the file) blocks
    /// of `inner_block_id`,
    /// _LOCKING_ the direct every time it adds a block.
    /// THIS FUNCTION MAY RESULT IN A DEAD LOCK!
    pub fn get_neighboring_sec(&self, inner_block_id: u32) -> Vec<u32> {
        let mut v = Vec::new();
        for i in inner_block_id & (!0b111u32)..=(inner_block_id | (0b111u32)) {
            if let Some(j) = self.get_block_id(i) {
                v.push(j)
            } else {
                break;
            }
        }
        v
    }

    pub fn from_ent(parent_dir: Arc<Self>, ent: &FATDirShortEnt) -> Self {
        Self::new(
            ent.get_first_clus() as usize,
            if ent.is_dir() {
                DiskInodeType::Directory
            } else {
                DiskInodeType::File
            },
            if ent.is_file() {
                Some(ent.file_size as usize)
            } else {
                None
            },
            Some(parent_dir.clone()),
            parent_dir.fs.clone(),
        )
    }
    /// Constructor for Inodes
    /// # Arguments
    /// `fst_clus`: The first cluster of the file
    /// `type_`: The type of the inode determined by the file
    /// `size`: NOTE: the `size` field should be set to `None` for a directory
    /// `parent_dir`: parent directory
    /// `fs`: The pointer to the file system
    pub fn new(
        fst_clus: usize,
        type_: DiskInodeType,
        size: Option<usize>,
        parent_dir: Option<Arc<Self>>,
        fs: Arc<EasyFileSystem<T>>,
    ) -> Self {
        let mut clus_size_as_size = false;
        let i = Inode {
            file_cache_mgr: (T::new(fs.first_sector_of_cluster(fst_clus as u32) as usize)),
            direct: Mutex::new(fs.fat.get_all_clus_num(fst_clus as u32, &fs.block_device)),
            type_,
            size: if let Some(size) = size {
                clus_size_as_size = true;
                Mutex::new(size as u32)
            } else {
                Mutex::new(0 as u32)
            },
            parent_dir,
            fs,
        };
        if !clus_size_as_size {
            i.size
                .lock()
                .add_assign(i.direct.lock().len() as u32 * i.fs.clus_size());
        }
        return i;
    }
    pub fn file_size(&self) -> usize {
        *self.size.lock() as usize
    }
    pub fn is_dir(&self) -> bool {
        self.type_ == DiskInodeType::Directory
    }
    #[allow(unused)]
    pub fn is_file(&self) -> bool {
        self.type_ == DiskInodeType::File
    }
    /// Return clus number correspond to size.
    pub fn data_clus(&self) -> u32 {
        self._data_clus(*self.size.lock())
    }
    pub fn _data_clus(&self, file_size: u32) -> u32 {
        (file_size + self.fs.byts_per_clus as u32 - 1) / self.fs.byts_per_clus as u32
    }
    /// Return number of blocks needed after rounding according to the cluster number.
    pub fn total_clus(&self, size: u32) -> u32 {
        let data_blocks = self._data_clus(size) as usize;
        let mut total = data_blocks as usize;
        total = (total + self.fs.clus_size() as usize - 1) / (self.fs.clus_size() as usize);
        total as u32
    }
    /// Get the addition of clusters needed to increase the file size.
    pub fn clus_num_needed(&self, new_size: u32) -> u32 {
        let lock = self.size.lock();
        let size = *lock;
        drop(lock);
        assert!(new_size >= size);
        self.total_clus(new_size) - self.total_clus(size)
    }
    /// Return the corresponding
    /// (`cluster_id`, `nth_block_in_that_cluster`, `byts_offset_in_last_block`)
    /// to `byte`
    #[inline(always)]
    #[allow(unused)]
    fn clus_offset(&self, byte: usize) -> (usize, usize, usize) {
        (
            byte / self.fs.clus_size() as usize,
            (byte % self.fs.clus_size() as usize) / BLOCK_SZ as usize,
            byte % BLOCK_SZ,
        )
    }
    #[inline(always)]
    fn get_block_id(&self, blk: u32) -> Option<u32> {
        let lock = self.direct.lock();
        let clus = blk as usize / self.fs.sec_per_clus as usize;
        if clus < lock.len() {
            Some(
                self.fs.first_sector_of_cluster(lock[clus])
                    + (blk as usize % self.fs.sec_per_clus as usize) as u32,
            )
        } else {
            None
        }
    }

    /// The `get_block_cache` version of read_at
    /// Read the inode(file) denoted by self, starting from offset.
    /// read till the minor of `buf.len()` and `self.size`
    /// # Arguments    
    /// * `buf`: The destination buffer of the read data
    /// * `offset`: The offset
    /// * `block_device`: the block_dev
    pub fn read_at_block_cache(&self, offset: usize, buf: &mut [u8]) -> usize {
        let mut start = offset;
        let size = { *self.size.lock() };
        let end = (offset + buf.len()).min(size as usize);
        if start >= end {
            return 0;
        }
        let mut start_block = start / BLOCK_SZ;
        let mut read_size = 0usize;
        loop {
            // calculate end of current block
            let mut end_current_block = (start / BLOCK_SZ + 1) * BLOCK_SZ;
            end_current_block = end_current_block.min(end);
            // read and update read size
            let block_read_size = end_current_block - start;
            let dst = &mut buf[read_size..read_size + block_read_size];
            self.file_cache_mgr
                .get_block_cache(
                    self.get_block_id(start_block as u32).unwrap() as usize,
                    Some(start_block),
                    self.get_inode_num().map(|i| i as usize),
                    Arc::clone(&self.fs.block_device),
                )
                .lock()
                .read(0, |data_block: &DataBlock| {
                    let src = &data_block[start % BLOCK_SZ..start % BLOCK_SZ + block_read_size];
                    dst.copy_from_slice(src);
                });
            read_size += block_read_size;
            // move to next block
            if end_current_block == end {
                break;
            }
            start_block += 1;
            start = end_current_block;
        }
        read_size
    }
    pub fn write_at_block_cache(&self, offset: usize, buf: &[u8]) -> usize {
        let mut start = offset;
        let lock = self.size.lock();
        let size = *lock;
        drop(lock);
        let diff_len = buf.len() as isize + offset as isize - size as isize;
        if diff_len > 0 as isize {
            if self.modify_size(diff_len).is_none() {
                return 0;
            }
        }
        let end = (offset + buf.len()).min(size as usize);
        assert!(start <= end);
        let mut start_block = start / BLOCK_SZ;
        let mut write_size = 0usize;
        loop {
            // calculate end of current block
            let mut end_current_block = (start / BLOCK_SZ + 1) * BLOCK_SZ;
            end_current_block = end_current_block.min(end);
            // write and update write size
            let block_write_size = end_current_block - start;
            self.file_cache_mgr
                .get_block_cache(
                    self.get_block_id(start_block as u32).unwrap() as usize,
                    Some(start_block),
                    self.get_inode_num().map(|i| i as usize),
                    Arc::clone(&self.fs.block_device),
                )
                .lock()
                .modify(0, |data_block: &mut DataBlock| {
                    let src = &buf[write_size..write_size + block_write_size];
                    let dst =
                        &mut data_block[start % BLOCK_SZ..start % BLOCK_SZ + block_write_size];
                    dst.copy_from_slice(src);
                });
            write_size += block_write_size;
            // move to next block
            if end_current_block == end {
                break;
            }
            start_block += 1;
            start = end_current_block;
        }
        write_size
    }

    /// * Clear size to zero
    /// * Return blocks that should be deallocated.
    /// # Warning
    /// We will clear the block contents to zero later.
    pub fn clear_size(&self) -> Vec<u32> {
        let mut lock = self.size.lock();
        let rhs = *lock;
        lock.sub_assign(rhs);
        drop(lock);
        // direct is storing the CLUSTERS!
        let mut lock = self.direct.lock();
        // you haven't cleared the directory entry in the self.parent_dir
        todo!();
        mem::take(&mut lock)
    }
    #[inline(always)]
    fn get_size(&self) -> usize {
        self.file_size()
    }

    pub fn ls(&self) -> Vec<(String, FATDirShortEnt)> {
        if !self.is_dir() {
            return Vec::new();
        } else {
            let mut v = Vec::with_capacity(30);
            let mut name = Vec::with_capacity(3);
            for i in self.iter() {
                if i.is_long() {
                    if true
                    //i.ord() == (LAST_LONG_ENTRY | (name.len() + 1))
                    /*order_correct*/
                    {
                        name.insert(0, i.get_name());
                    } else {
                        /*order_wrong/missing*/
                        name.clear();
                        name.insert(0, i.get_name());
                    }
                } else {
                    if !name.is_empty() {
                        //then match the name to see if it's correct.
                        if true {
                            //if correct, push the concatenated name
                            v.push((name.concat(), i.get_short_ent().unwrap().clone()));
                            name.clear();
                            continue;
                        } else {
                            // short name doesn't match... The previous long entries are not correct.
                            name.clear();
                        }
                    }
                    // only one short
                    v.push((i.get_name(), i.get_short_ent().unwrap().clone()));
                }
            }
            return v;
        }
    }

    pub fn iter(&self) -> DirIter<T> {
        DirIter {
            dir: self,
            offset: 0,
            mode: Mutex::new(DirIterMode::AllIter),
        }
    }

    /// Change the size of current file.
    /// # Return Value
    /// If failed, return `None`, otherwise return `Some(())`
    pub fn modify_size(&self, diff: isize) -> Option<()> {
        if diff.abs() as usize > self.get_size() {
            return None;
        }
        if diff > 0 {
            let ch_clus_num = diff / self.fs.clus_size() as isize;
            let lock = self.direct.lock();
            let last = lock.last().map(|s| {
                let i: u32 = *s;
                i
            });
            if let Some(mut i) =
                self.fs
                    .fat
                    .alloc_mult(&self.fs.block_device, ch_clus_num as usize, last)
            {
                self.direct.lock().append(&mut i);
            } else {
                return None;
            }
        } else {
            // size_diff<0
            let diff = diff.abs();
            if diff == *self.size.lock() as isize {
                //should clear the dir_ent here.
                todo!();
            }
            let ch_clus_num = diff / self.fs.clus_size() as isize;
            let mut lock = self.direct.lock();
            for _ in 0..ch_clus_num {
                self.fs
                    .fat
                    .dealloc(&self.fs.block_device, lock.pop().unwrap() as usize);
            }
        }
        if diff > 0 {
            *self.size.lock() += diff as u32;
        } else {
            let mut slock = self.size.lock();
            let mut s = *slock;
            s -= (-diff) as u32;
            *slock = s;
        }
        Some(())
    }
}

pub fn find_local<T: CacheManager>(
    inode: Arc<Inode<T>>,
    target_name: String,
) -> Option<Arc<Inode<T>>> {
    if inode.is_dir() {
        let mut name = Vec::with_capacity(3);
        for i in inode.iter() {
            if i.is_long() {
                if true {
                    name.insert(0, i.get_name());
                } else {
                    /*order_wrong/missing*/
                    name.clear();
                    name.insert(0, i.get_name());
                }
            } else {
                if !name.is_empty() {
                    //then match the name to see if it's correct.
                    if true {
                        //if correct, test the concatenated name
                        if name.concat() == target_name {
                            return Some(Arc::new(Inode::<T>::from_ent(
                                inode,
                                i.get_short_ent().unwrap(),
                            )));
                        };
                        name.clear();
                        continue;
                    } else {
                        // short name doesn't match... The previous long entries are not correct.
                        name.clear();
                    }
                }
                // only one short
            }
        }
        None
    } else {
        None
    }
}

pub enum DirIterMode {
    LongIter,
    ShortIter,
    AllIter,
}

#[allow(unused)]
impl DirIterMode {
    /// Returns `true` if the dir iter mode is [`LongIter`].
    ///
    /// [`LongIter`]: DirIterMode::LongIter
    pub fn is_long_iter(&self) -> bool {
        matches!(self, Self::LongIter)
    }

    /// Returns `true` if the dir iter mode is [`ShortIter`].
    ///
    /// [`ShortIter`]: DirIterMode::ShortIter
    pub fn is_short_iter(&self) -> bool {
        matches!(self, Self::ShortIter)
    }

    /// Returns `true` if the dir iter mode is [`AllIter`].
    ///
    /// [`AllIter`]: DirIterMode::AllIter
    pub fn is_all_iter(&self) -> bool {
        matches!(self, Self::AllIter)
    }
}

pub struct DirIter<T: CacheManager> {
    dir: *const Inode<T>,
    offset: usize,
    mode: Mutex<DirIterMode>,
}

impl<T: CacheManager> DirIter<T> {
    fn is_file(&self) -> bool {
        unsafe { (*self.dir).is_file() }
    }
    pub fn get_offset(&self) -> usize {
        self.offset
    }
    pub fn short(self) -> Self {
        *self.mode.lock() = DirIterMode::ShortIter;
        self
    }
    pub fn long(self) -> Self {
        *self.mode.lock() = DirIterMode::LongIter;
        self
    }
    pub fn all(self) -> Self {
        *self.mode.lock() = DirIterMode::AllIter;
        self
    }
}
impl<T: CacheManager> Iterator for DirIter<T> {
    type Item = FATDirEnt;
    fn next(&mut self) -> Option<Self::Item> {
        if self.is_file() {
            None
        } else {
            let mut i: FATDirEnt = FATDirEnt::empty();
            (unsafe { (*self.dir).read_at_block_cache(self.offset, i.as_bytes_mut()) });
            self.offset += core::mem::size_of::<FATDirEnt>();
            let lock = self.mode.lock();
            while (i.unused_not_last()
            // used for skipping the last
		||  (// for non-all iter mode 
		    !lock.is_all_iter() && !i.last_and_unused()
		     // skipping long or short
                && if lock.is_short_iter() {i.is_long()}else{!i.is_long()}))
                && self.offset < unsafe { (*self.dir).get_size() }
            {
                (unsafe { (*self.dir).read_at_block_cache(self.offset, i.as_bytes_mut()) });
                self.offset += core::mem::size_of::<FATDirEnt>();
            }
            if !i.last_and_unused() && self.offset < unsafe { (*self.dir).file_size() } {
                Some(i)
            } else {
                None
            }
        }
    }
}
