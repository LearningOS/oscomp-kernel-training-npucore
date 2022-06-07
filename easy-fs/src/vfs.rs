use alloc::collections::BTreeMap;
use alloc::vec;
use core::convert::TryInto;
use core::mem;
use core::ops::Mul;
use volatile::ReadOnly;
use super::{DiskInodeType, EasyFileSystem};
use alloc::string::String;

use crate::block_cache::{Cache, CacheManager};
use crate::dir_iter::*;
use crate::layout::{
    FATDirEnt, FATDiskInodeType, FATLongDirEnt, FATShortDirEnt, LONG_DIR_ENT_NAME_CAPACITY,
};
use crate::DataBlock;

use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::{Mutex, MutexGuard};

pub struct FileContent<T: CacheManager> {
    /// For FAT32, size is a value computed from FAT.
    /// You should iterate around the FAT32 to get the size.
    pub size: u32,
    /// The cluster list.
    pub clus_list: Vec<u32>,
    /// File cache manager corresponding to this inode.
    pub file_cache_mgr: T,
    /// If this file is a directory, hint will record the position of last directory entry(the first byte is 0x00).
    pub hint: u32,
}

/// The functionality of ClusLi & Inode can be merged.
/// The struct for file information

pub enum OpenTabCmd<T: CacheManager, F: CacheManager> {
    InsertFile(Arc<Inode<T, F>>),
    GetFileByInode(u64),
    DropFileByInode(u64),
    /// The former is the previous ino and the latter is the new.
    ChInode(u64, u64),
}

#[allow(unused)]
impl<T: CacheManager, F: CacheManager> OpenTabCmd<T, F> {
    /// Returns `true` if the file or inode is [`Inode`].
    ///
    /// [`Inode`]: FileOrInode::Inode
    fn is_inode(&self) -> bool {
        matches!(self, Self::GetFileByInode(..))
    }
    /// Returns `true` if the file or inode is [`File`].
    ///
    /// [`File`]: FileOrInode::File
    fn is_file(&self) -> bool {
        matches!(self, Self::InsertFile(..))
    }
    fn as_file(&self) -> Option<&Inode<T, F>> {
        if let Self::InsertFile(v) = self {
            Some(v)
        } else {
            None
        }
    }

    fn as_inode(&self) -> Option<&u64> {
        if let Self::GetFileByInode(v) = self {
            Some(v)
        } else {
            None
        }
    }
}

pub struct InodeTime {
    create_time: u64,
    access_time: u64,
    modify_time: u64,
}

impl InodeTime {
    /// Set the inode time's create time.
    pub fn set_create_time(&mut self, create_time: u64) {
        self.create_time = create_time;
    }

    /// Get a reference to the inode time's create time.
    pub fn create_time(&self) -> &u64 {
        &self.create_time
    }

    /// Set the inode time's access time.
    pub fn set_access_time(&mut self, access_time: u64) {
        self.access_time = access_time;
    }

    /// Get a reference to the inode time's access time.
    pub fn access_time(&self) -> &u64 {
        &self.access_time
    }

    /// Set the inode time's modify time.
    pub fn set_modify_time(&mut self, modify_time: u64) {
        self.modify_time = modify_time;
    }

    /// Get a reference to the inode time's modify time.
    pub fn modify_time(&self) -> &u64 {
        &self.modify_time
    }
}

/* *ClusLi was DiskInode*
 * Even old New York, was New Amsterdam...
 * Why they changed it I can't say.
 * People just like it better that way.*/
/// The functionality of ClusLi & Inode can be merged.
/// The struct for file information
pub struct Inode<T: CacheManager, F: CacheManager> {
    /// File Content
    pub file_content: Mutex<FileContent<T>>,
    /// File type
    pub file_type: ReadOnly<DiskInodeType>,
    /// The parent directory of this inode
    pub parent_dir: Option<(Arc<Self>, u32)>,
    /// file system
    pub fs: Arc<EasyFileSystem<T, F>>,
    /// Struct to hold time related information
    pub time: Mutex<InodeTime>,
}

impl<T: CacheManager, F: CacheManager> Drop for Inode<T, F> {
    fn drop(&mut self) {
        //todo!();
    }
}

/// Constructor
impl<T: CacheManager, F: CacheManager> Inode<T, F> {
    /// Constructor for Inodes
    /// # Arguments
    /// `fst_clus`: The first cluster of the file
    /// `type_`: The type of the inode determined by the file
    /// `size`: NOTE: the `size` field should be set to `None` for a directory
    /// `parent_dir`: parent directory
    /// `fs`: The pointer to the file system
    pub fn new(
        fst_clus: u32,
        file_type: DiskInodeType,
        size: Option<u32>,
        parent_dir: Option<(Arc<Self>, u32)>,
        fs: Arc<EasyFileSystem<T, F>>,
    ) -> Arc<Self> {
        let file_cache_mgr = T::new();
        let clus_list = match fst_clus {
            0 => Vec::new(),
            _ => fs.fat.get_all_clus_num(fst_clus, &fs.block_device),
        };

        let size = size.unwrap_or_else(|| clus_list.len() as u32 * fs.clus_size());
        let hint = 0;

        let file_content = Mutex::new(FileContent {
            size,
            clus_list,
            file_cache_mgr,
            hint,
        });
        let time = InodeTime {
            create_time: 0,
            access_time: 0,
            modify_time: 0,
        };
        let inode = Arc::new(Inode {
            file_content,
            file_type: ReadOnly::new(file_type),
            parent_dir,
            fs,
            time: Mutex::new(time),
        });
        
        // Init hint
        if file_type == DiskInodeType::Directory {
            inode.set_hint();
        }
        inode
    }
}

/// Basic Funtions
impl<T: CacheManager, F: CacheManager> Inode<T, F> {
    /// Get first cluster of inode.
    /// If cluster list is empty, it will return None.
    /// # Warning
    /// This function is an external interface.
    /// May cause DEADLOCK if called on internal interface
    pub fn get_first_clus(&self) -> Option<u32> {
        let lock = self.file_content.lock();
        let clus_list = &lock.clus_list;
        if !clus_list.is_empty() {
            Some(clus_list[0])
        } else {
            None
        }
    }
    /// Get inode number of inode.
    /// See first sector number as inode number.
    #[inline(always)]
    pub fn get_inode_num(&self) -> Option<u32> {
        self.get_first_clus()
            .map(|clus| self.fs.first_sector_of_cluster(clus))
    }
    /// !!! This function have many bugs
    /// Get the neighboring 8 or fewer(the trailing mod-of-eight blocks of the file) blocks
    /// of `inner_block_id`,
    pub fn get_neighboring_sec(&self, inner_cache_id: usize) -> Vec<usize> {
        Vec::new()
        // let inner_block_id = inner_cache_id * T::CACHE_SZ / BLOCK_SZ;
        // let mut v = Vec::new();
        // for i in inner_block_id & (!0b111usize)..=(inner_block_id | (0b111usize)) {
        //     if let Some(j) = self.get_block_id(i as u32) {
        //         v.push(j as usize)
        //     } else {
        //         break;
        //     }
        // }
        // v
    }
    /// Check if file type is directory
    #[inline(always)]
    pub fn is_dir(&self) -> bool {
        self.file_type.read() == DiskInodeType::Directory
    }
    /// Check if file type is file
    #[inline(always)]
    pub fn is_file(&self) -> bool {
        self.file_type.read() == DiskInodeType::File
    }
    /// Get file size
    /// # Warning
    /// This function is an external interface.
    /// May cause DEADLOCK if called on internal interface
    pub fn get_file_size(&self) -> u32 {
        self.file_content.lock().size
    }
    /// Get the number of clusters corresponding to the size.
    pub fn get_file_clus(&self) -> u32 {
        self.total_clus(self.get_file_size())
    }
    /// Get the number of clusters needed after rounding up according to size.
    fn total_clus(&self, size: u32) -> u32 {
        size.div_ceil(self.fs.clus_size())
    }
    /// Get block id corresponding to the blk
    #[inline(always)]
    fn get_block_id(&self, lock: &MutexGuard<FileContent<T>>, blk: u32) -> Option<u32> {
        let idx = blk as usize / self.fs.sec_per_clus as usize;
        let clus_list = &lock.clus_list;
        if idx >= clus_list.len() {
            return None;
        }
        let base = self.fs.first_sector_of_cluster(clus_list[idx]);
        let offset = blk % self.fs.sec_per_clus as u32;
        Some(base + offset)
    }
}

/// File Content Operation
impl<T: CacheManager, F: CacheManager> Inode<T, F> {
    /// Allocate required clusters
    fn alloc_clus(&self, lock: &mut MutexGuard<FileContent<T>>, alloc_num: usize) {
        log::trace!("[alloc_clus] alloc_num: {}", alloc_num);
        let clus_list = &mut lock.clus_list;
        let mut new_clus_list = self.fs.fat.alloc_mult(
            &self.fs.block_device,
            alloc_num,
            clus_list.last().map(|clus| *clus),
        );
        clus_list.append(&mut new_clus_list);
    }
    /// Deallocate required cluster
    /// If the required number is greater than the number of clusters in the file, all clusters will be deallocated
    fn dealloc_clus(&self, lock: &mut MutexGuard<FileContent<T>>, dealloc_num: usize) {
        let clus_list = &mut lock.clus_list;
        let dealloc_num = dealloc_num.min(clus_list.len());
        log::trace!("[dealloc_clus]: dealloc_num: {}", dealloc_num);
        let mut dealloc_list = Vec::<u32>::new();
        for _ in 0..dealloc_num {
            self.fs
                .fat
                .dealloc(&self.fs.block_device, clus_list.pop().unwrap())
        }
    }
    /// Change the size of current file.
    /// This operation is ignored if the result size is negative
    /// # Warning
    /// This function will lock parent's file content. May cause DEADLOCK
    pub fn modify_size(&self, lock: &mut MutexGuard<FileContent<T>>, diff: isize) {
        log::trace!("[modify_size] diff: {}", diff);
        let mut dir_ent = FATDirEnt::empty();

        // Get parent lock and get directory entry of current file
        let mut may_par_lock: Option<MutexGuard<FileContent<T>>> = None;
        if let Some((par_inode, offset)) = &self.parent_dir {
            log::trace!("[modify_size] par_inode's offset: {}", offset);
            let mut lock = par_inode.file_content.lock();
            par_inode.read_at_block_cache(&mut lock, *offset as usize, dir_ent.as_bytes_mut());
            may_par_lock = Some(lock);
        }
        // This operation is ignored if the result size is negative
        if diff.saturating_add(lock.size as isize) <= 0 {
            return;
        }
        let old_size = lock.size;
        let new_size = (lock.size as isize + diff) as u32;

        let old_clus_num = self.total_clus(old_size) as usize;
        let new_clus_num = self.total_clus(new_size) as usize;

        if diff > 0 {
            self.alloc_clus(lock, new_clus_num - old_clus_num);
            lock.size = new_size;
            // If old size is 0, set first cluster bits in directory entry
            if old_size == 0 {
                dir_ent.set_fst_clus(lock.clus_list[0]);
            }
        } else {
            lock.size = new_size;
            self.dealloc_clus(lock, old_clus_num - new_clus_num);
            // If new size is 0, clear first cluster bits in directory entry
            if new_size == 0 {
                dir_ent.set_fst_clus(0);
            }
        }
        dir_ent.set_size(new_size);
        log::trace!("[modify_size] new_size: {}", new_size);
        
        // Write back
        if let Some((par_inode, offset)) = &self.parent_dir {
            par_inode.write_at_block_cache(
                &mut may_par_lock.unwrap(),
                *offset as usize,
                dir_ent.as_bytes_mut(),
            );
        }
    }
}

/// Open File Table
impl<T: CacheManager, F: CacheManager> Inode<T, F> {
    /// Open file table static operation function.
    pub fn open_tab(file: OpenTabCmd<T, F>) -> Option<Arc<Self>> {
        static mut ORG_LI: usize = 0;
        static mut V: Vec<(u64, u64)> = Vec::new(); // (pre,now)
        unsafe {
            if ORG_LI == 0 {
                ORG_LI = &mut (Mutex::new(BTreeMap::new())) as *mut Mutex<BTreeMap<u64, Arc<Self>>>
                    as usize;
            }
            /// The macro is a must.
            /// It's an error to use `let` construct to instanitiate a variable with generic parameters.
            macro_rules! tree {
                () => {
                    *(ORG_LI as *mut Mutex<BTreeMap<u64, Arc<Self>>>)
                };
            }
            match file {
                OpenTabCmd::InsertFile(f) => {
                    let ino = f.get_inode_num();
                    let arc = tree!().lock().insert(ino.unwrap_or(0) as u64, f.clone());
                    return None;
                }
                OpenTabCmd::GetFileByInode(i) => {
                    let lock = tree!().lock();
                    lock.get(&i).map(|i| i.clone()).or_else(|| {
                        if let Some((_, next)) = V.iter().find(|(pre, _)| *pre == i) {
                            lock.get(next).map(|i| i.clone())
                        } else {
                            None
                        }
                    })
                }
                OpenTabCmd::DropFileByInode(i) => {
                    // Should panic if file isn't found.
                    let mut lock = tree!().lock();
                    if let Some((_, next)) = V.iter().find(|&(pre, _)| *pre == i) {
                        lock.remove(next);
                    }
                    lock.remove(&i)
                }
                OpenTabCmd::ChInode(pre, next) => {
                    let mut lock = tree!().lock();
                    V.push((pre, next));
                    let arc = lock.remove(&pre).unwrap();
                    lock.insert(next, arc);
                    return None;
                }
            }
        }
    }
}

/// IO
impl<T: CacheManager, F: CacheManager> Inode<T, F> {
    /// The `get_block_cache` version of read_at
    /// Read the inode(file) denoted by self, starting from offset.
    /// read till the minor of `buf.len()` and `self.size`
    /// # Arguments    
    /// * `buf`: The destination buffer of the read data
    /// * `offset`: The offset
    /// * `block_device`: the block_dev
    pub fn read_at_block_cache(
        &self,
        lock: &mut MutexGuard<FileContent<T>>,
        offset: usize,
        buf: &mut [u8],
    ) -> usize {
        let mut start = offset;
        let size = lock.size as usize;
        let end = (offset + buf.len()).min(size);
        if start >= end {
            return 0;
        }
        let mut start_cache = start / T::CACHE_SZ;
        let mut read_size = 0;
        log::trace!(
            "[rd_at_blk_cache] st,end,st_ch,buf.len:{:?}",
            (start, end, start_cache, buf.len())
        );
        loop {
            // calculate end of current block
            let mut end_current_block = (start / T::CACHE_SZ + 1) * T::CACHE_SZ;
            end_current_block = end_current_block.min(end);
            // read and update read size
            let block_read_size = end_current_block - start;
            let dst = &mut buf[read_size..read_size + block_read_size];
            let block_id = self.get_block_id(lock, start_cache as u32).unwrap() as usize;
            lock.file_cache_mgr
                .get_block_cache(
                    block_id,
                    start_cache,
                    || -> Vec<usize> { self.get_neighboring_sec(start_cache) },
                    Arc::clone(&self.fs.block_device),
                )
                .lock()
                .read(0, |data_block: &DataBlock| {
                    let src =
                        &data_block[start % T::CACHE_SZ..start % T::CACHE_SZ + block_read_size];
                    dst.copy_from_slice(src);
                });
            read_size += block_read_size;
            // move to next block
            if end_current_block == end {
                break;
            }
            start_cache += 1;
            start = end_current_block;
        }
        read_size
    }
    pub fn write_at_block_cache(
        &self,
        lock: &mut MutexGuard<FileContent<T>>,
        offset: usize,
        buf: &[u8],
    ) -> usize {
        let mut start = offset;
        let old_size = lock.size as usize;
        let diff_len = buf.len() as isize + offset as isize - old_size as isize;
        log::trace!("[wr_at_blk_cache] diff{},size{}", diff_len, old_size);
        if diff_len > 0 as isize {
            // allocate as many blocks as possible.
            log::trace!("[wr_at_blk_cache] trying to modify size...");
            log::trace!("[wr_at_blk_cache] diff{},size{}", diff_len, old_size);
            self.modify_size(lock, diff_len);
            log::trace!("[wr_at_blk_cache] \"file.size\":{}", lock.size);
        }
        let end = (offset + buf.len()).min(lock.size as usize);

        assert!(start <= end);
        let mut start_cache = start / T::CACHE_SZ;
        let mut write_size = 0;
        log::trace!(
            "[wr_at_blk_cache] st,end,st_ch,wr_sz, buf.len:{:?}",
            (start, end, start_cache, write_size, buf.len())
        );
        loop {
            // calculate end of current block
            let mut end_current_block = (start / T::CACHE_SZ + 1) * T::CACHE_SZ;
            end_current_block = end_current_block.min(end);
            // write and update write size
            let block_write_size = end_current_block - start;
            let block_id = self.get_block_id(lock, start_cache as u32).unwrap() as usize;
            lock.file_cache_mgr
                .get_block_cache(
                    block_id,
                    start_cache,
                    || -> Vec<usize> { self.get_neighboring_sec(start_cache) },
                    Arc::clone(&self.fs.block_device),
                )
                .lock()
                .modify(0, |data_block: &mut DataBlock| {
                    let src = &buf[write_size..write_size + block_write_size];
                    let dst = &mut data_block
                        [start % T::CACHE_SZ..start % T::CACHE_SZ + block_write_size];
                    dst.copy_from_slice(src);
                });
            write_size += block_write_size;
            log::trace!(
                "[wr_at_blk_cache] end_cur_blk blk_wr_sz,blk_id,wr_sz:{:?}",
                (end_current_block, block_write_size, block_id, write_size)
            );
            // move to next block
            if end_current_block == end {
                break;
            }
            start_cache += 1;
            start = end_current_block;
        }
        write_size
    }
}

/// Directory Operation
impl<T: CacheManager, F: CacheManager> Inode<T, F> {
    /// Iter Construct
    fn dir_iter<'a>(
        &'a self,
        lock: MutexGuard<'a, FileContent<T>>,
        offset: Option<u32>,
        mode: DirIterMode,
        forward: bool,
    ) -> DirIter<'a, T, F> {
        if self.file_type.read() != DiskInodeType::Directory {
            panic!("this isn't a directory")
        }
        let inode = self;
        DirIter::new(lock, offset, mode, forward, inode)
    }
    /// Set the offset of the last entry in the directory file(first byte is 0x00) to hint 
    /// # Warning
    /// This function will lock self's file_content, may cause deadlock
    fn set_hint(&self) {
        let lock = self.file_content.lock();
        let mut iter = self.dir_iter(lock, None, DirIterMode::Enum, FORWARD);
        loop {
            let dir_ent = iter.next();
            if dir_ent.is_none() {
                // Means iter reachs the end of file
                iter.lock.hint = iter.lock.size;
                log::trace!("[set_hint] hint: {}", iter.lock.hint);
                return;
            }
            let dir_ent = dir_ent.unwrap();
            if dir_ent.last_and_unused() {
                iter.lock.hint = iter.get_offset().unwrap();
                log::trace!("[set_hint] hint: {}", iter.lock.hint);
                return;
            }
        }
    }
    /// Expand directory file's size(a cluster)
    /// # Arguments
    /// `lock`: The lock of FileContent
    fn expand_dir_size(
        &self, 
        lock: &mut MutexGuard<FileContent<T>>
    ) -> core::fmt::Result {
        let diff_size = self.fs.clus_size();
        self.modify_size(lock, diff_size as isize);
        log::debug!("[expand_dir_size] new_size: {}", lock.size);
        Ok(())
    }
    /// Shrink directory file's size to fit **hint**(the offset from end of file)
    /// For directory files, it has at least one cluster and should care
    /// # Arguments
    /// `lock`: The lock of FileContent
    fn shrink_dir_size(
        &self,
        lock: &mut MutexGuard<FileContent<T>>
    ) -> core::fmt::Result {
        let new_size = 
            lock.hint
                .div_ceil(self.fs.clus_size())
                .mul(self.fs.clus_size())
                // For directory file, it has at least one cluster
                .max(self.fs.clus_size());
        let diff_size = new_size as isize - lock.size as isize;
        self.modify_size(lock, diff_size as isize);
        log::debug!("[shrink_dir_size] new_size: {}", lock.size);
        Ok(())
    }
    /// Allocate directory entries required for new file.
    /// Return the offset of the last entry and the lock.
    /// # Arguments
    /// `parent_dir`: The parent directory inode pointer
    /// `lock`: The lock of FileContent
    /// `alloc_num`: The number of directory entries required
    fn alloc_dir_ent<'a>(
        parent_dir: &'a Arc<Self>,
        lock: MutexGuard<'a, FileContent<T>>,
        alloc_num: usize,
    ) -> Result<(u32, MutexGuard<'a, FileContent<T>>), ()> {
        log::debug!("[alloc_dir_ent]alloc num:{:?}", alloc_num);
        let offset = lock.hint;
        let mut iter = parent_dir.dir_iter(lock, None, DirIterMode::Enum, FORWARD);
        iter.set_iter_offset(offset);
        let mut found_free_dir_ent = 0;
        loop {
            let dir_ent = iter.next();
            if dir_ent.is_none() {
                if parent_dir.expand_dir_size(&mut iter.lock).is_err() {
                    log::error!("[alloc_dir_ent]expand directory size error");
                    return Err(());
                }
                continue;
            }
            // We assume that all entries after `hint` are valid
            // That's why we use `hint`. It can reduce the cost of iterating over used entries
            found_free_dir_ent += 1;
            log::trace!("[alloc_dir_ent]{:?}", iter.get_offset());
            if found_free_dir_ent >= alloc_num {
                let offset = iter.get_offset().unwrap();
                // Set hint
                // Set next entry to last_and_unused
                if iter.next().is_some() {
                    iter.write_to_current_ent(&FATDirEnt::unused_and_last_entry());
                    iter.lock.hint = iter.get_offset().unwrap();
                } else {
                    // Means iter reachs the end of file
                    iter.lock.hint = iter.lock.size;
                }
                
                let lock = iter.lock;
                log::debug!("[alloc_dir_ent]found! end offset: {}, hint: {}", offset, lock.hint);
                return Ok((offset, lock));
            }
        }
    }
}

/// Delete
/// The real delete operation is done by unlink syscall(this maybe a big problem)
/// So we don't care about atomic deletes in the filesystem
/// We can recycle resources at will, and don't care about the resource competition of this inode
impl<T: CacheManager, F: CacheManager> Inode<T, F> {
    /// Delete the short and the long entry of `self` from `parent_dir`
    fn delete_self_dir_ent(&self) {
        let (inode, offset) = self.parent_dir.as_ref().unwrap();
        let lock = inode.file_content.lock();
        let mut iter = inode.dir_iter(lock, Some(*offset), DirIterMode::UsedIter, BACKWARD);

        iter.write_to_current_ent(&FATDirEnt::unused_not_last_entry());

        log::debug!("[delete_self_dir_ent] offset: {:?}", iter.get_offset());

        // Check this dir_ent is a short dir_ent
        {
            let dir_ent = iter.next();

            if dir_ent.is_none() {
                return;
            }
            let dir_ent = dir_ent.unwrap();
            if !dir_ent.is_long() {
                return;
            }
        }

        // Remove long dir_ents
        loop {
            let dir_ent = iter.current_clone();
            if dir_ent.is_none() {
                panic!("invalid long dir_ent");
            }
            let dir_ent = dir_ent.unwrap();
            if !dir_ent.is_long() {
                panic!("invalid long dir_ent");
            }
            log::trace!("[delete_self_dir_ent] offset: {:?}, dir_ent: {:?}, name: {:?}", 
                iter.get_offset(), dir_ent, dir_ent.get_name());
            iter.write_to_current_ent(&FATDirEnt::unused_not_last_entry());
            iter.next();
            if dir_ent.is_last_long_dir_ent() {
                break;
            }
        }
        
        // Modify hint
        // We use new iterate mode
        let old_hint = iter.lock.hint;
        let mut iter = 
            inode.dir_iter(
                iter.lock, 
                Some(old_hint),
                DirIterMode::Enum,
                BACKWARD);
        loop {
            let dir_ent = iter.next();
            if dir_ent.is_none() {
                // Indicates that the file is empty
                iter.lock.hint = 0;
                break;
            }
            let dir_ent = dir_ent.unwrap();
            if dir_ent.unused() {
                iter.lock.hint = iter.get_offset().unwrap();
                iter.write_to_current_ent(&FATDirEnt::unused_and_last_entry());
            }
            else {
                // Represents `iter` pointer to a used entry
                break;
            }
        }
        log::debug!("[delete_self_dir_ent] hint: {:?}", iter.lock.hint);

        // Modify file size
        let mut lock = iter.lock;
        inode.shrink_dir_size(&mut lock).unwrap();
    }
    /// Delete the file from the disk,
    /// deallocating both the directory entries (whether long or short),
    /// and the occupied clusters.
    pub fn delete_from_disk(trash: Arc<Self>) -> Result<(), ()> {
        if trash.is_dir() {
            // See if the dir is empty
            let v = trash.ls().unwrap();
            if v.len() > 2 {
                return Err(());
            }
            for (name, _) in v {
                if ![".", ".."].contains(&name.as_str()) {
                    return Err(());
                }
            }
        }
        log::debug!("[delete_from_disk] inode: {:?}, type: {:?}", trash.get_inode_num(), trash.file_type);
        let mut lock = trash.file_content.lock();
        // Clear size
        lock.size = 0;
        // Before deallocating the cluster, we should sync cache data with disk.
        // Or we may found data is written by global cache manager(non-repeatable read in database).
        // Sync cache (todo!!!)

        // Deallocate clusters
        let clus_list = mem::take(&mut lock.clus_list);
        trash.fs.fat.mult_dealloc(&trash.fs.block_device, clus_list);
        // Remove directory entries
        trash.delete_self_dir_ent();
        return Ok(());
    }
}

/// Create
impl<T: CacheManager, F: CacheManager> Inode<T, F> {
    /// Create a file or a directory from the parent.
    pub fn create(
        parent_dir: &Arc<Self>,
        name: String,
        file_type: DiskInodeType,
    ) -> Result<Arc<Inode<T, F>>, ()> {
        if parent_dir.is_file()
            || name.len() >= 256
            || parent_dir
                .ls()
                .unwrap()
                .iter()
                .find(|(existed_name, _)| existed_name.to_uppercase() == name.to_uppercase())
                .is_some()
        {
            Err(())
        } else {
            log::debug!("[create] par_inode: {:?}, name: {:?}, file_type: {:?}", 
                        parent_dir.get_inode_num(),&name, file_type);
            //get short name slice
            let mut short_name_slice: [u8; 11] = [' ' as u8; 11];
            if Self::gen_short_name_slice(&parent_dir, &name, &mut short_name_slice).is_err() {
                return Err(());
            }
            log::trace!("[create] short_name_slice: {:?}", short_name_slice);
            //alloc parent's directory entries
            let lock = parent_dir.file_content.lock();
            let long_ent_num = name.len().div_ceil(LONG_DIR_ENT_NAME_CAPACITY);
            let short_ent_num = 1;
            log::trace!("[create] long_ent_num: {}, short_ent_num: {}", long_ent_num, short_ent_num);
            let short_ent_offset =
                Self::alloc_dir_ent(&parent_dir, lock, long_ent_num + short_ent_num);

            if short_ent_offset.is_err() {
                return Err(());
            }
            let (short_ent_offset, lock) = short_ent_offset.unwrap();
            log::trace!("[create] short_ent_offset: {}", short_ent_offset);
            //if file_type is Directory, alloc first cluster
            let fst_clus = if file_type == DiskInodeType::Directory {
                let fst_clus = parent_dir
                    .fs
                    .fat
                    .alloc_one(&parent_dir.fs.block_device, None);
                if fst_clus.is_none() {
                    return Err(());
                }
                fst_clus.unwrap()
            } else {
                0
            };
            // Generate short entry
            let short_ent = FATShortDirEnt::from_name(short_name_slice, fst_clus, file_type);
            // Generate long entries
            let mut long_ents = Vec::<FATLongDirEnt>::new();
            for i in 1..=long_ent_num {
                long_ents.push(FATLongDirEnt::from_name_slice(
                    i == long_ent_num,
                    i,
                    Self::get_long_name_slice(&name, i),
                ))
            }
            // Write back parent's directory entry
            Self::write_back_dir_ent(&parent_dir, short_ent_offset, lock, short_ent, long_ents);
            //generate current directory
            let current_dir = Inode::from_ent(&parent_dir, &short_ent, short_ent_offset);
            //if file_type is Directory, set first 3 directory entry
            if file_type == DiskInodeType::Directory {
                let mut lock = current_dir.file_content.lock();
                // Set hint
                lock.hint = 2 * core::mem::size_of::<FATDirEnt>() as u32;
                // Fill content
                Self::fill_empty_dir(&parent_dir, &current_dir, lock, fst_clus);
            }
            Ok(current_dir)
        }
    }

    /// Construct a \[u16,13\] corresponding to the `long_ent_num`'th 13-u16 or shorter name slice
    /// _NOTE_: the first entry is of number 1 for `long_ent_num`
    fn get_long_name_slice(
        name: &String,
        long_ent_num: usize,
    ) -> [u16; LONG_DIR_ENT_NAME_CAPACITY] {
        let mut v: Vec<u16> = name.encode_utf16().collect();
        assert!(long_ent_num >= 1);
        let long_ent_num = long_ent_num - 1;
        assert!(long_ent_num * LONG_DIR_ENT_NAME_CAPACITY < v.len());
        while v.len() < (long_ent_num + 1) * LONG_DIR_ENT_NAME_CAPACITY {
            v.push(0);
        }
        let start = long_ent_num * LONG_DIR_ENT_NAME_CAPACITY;
        let end = (long_ent_num + 1) * LONG_DIR_ENT_NAME_CAPACITY;
        v[start..end].try_into().expect("should be able to cast")
    }

    fn gen_short_name_slice(
        parent_dir: &Arc<Self>,
        name: &String,
        short_name_slice: &mut [u8; 11],
    ) -> Result<(), ()> {
        let short_name = FATDirEnt::gen_short_name_prefix(name.clone());
        if short_name.len() == 0 || short_name.find(' ').unwrap_or(8) == 0 {
            return Err(());
        }
        short_name_slice.copy_from_slice(&short_name.as_bytes()[0..11]);

        let lock = parent_dir.file_content.lock();
        let iter = parent_dir.dir_iter(lock, None, DirIterMode::ShortIter, FORWARD);
        FATDirEnt::gen_short_name_numtail(iter.collect(), short_name_slice);
        Ok(())
    }

    /// Create a file from directory entry.
    /// # Arguments
    /// `parent_dir`: the parent directory inode pointer
    /// `ent`: the short entry as the source of information
    /// `offset`: the offset of the short directory entry in the `parent_dir`
    pub fn from_ent(parent_dir: &Arc<Self>, ent: &FATShortDirEnt, offset: u32) -> Arc<Self> {
        Self::new(
            ent.get_first_clus(),
            if ent.is_dir() {
                DiskInodeType::Directory
            } else {
                DiskInodeType::File
            },
            if ent.is_file() {
                Some(ent.file_size)
            } else {
                None
            },
            Some((parent_dir.clone(), offset)),
            parent_dir.fs.clone(),
        )
    }

    /// Write back both long and short directories.
    /// The short directory is created from the `fst_clus` and the `name`.
    fn write_back_dir_ent(
        parent_dir: &Arc<Self>,
        short_ent_offset: u32,
        lock: MutexGuard<FileContent<T>>,
        short_ent: FATShortDirEnt,
        long_ents: Vec<FATLongDirEnt>,
    ) {
        //we have graranteed we have alloc enough entries
        //so we use Enum mode
        let mut iter =
            parent_dir.dir_iter(lock, Some(short_ent_offset), DirIterMode::Enum, BACKWARD);
        iter.write_to_current_ent(&FATDirEnt {
            short_entry: short_ent,
        });
        log::trace!("[wr_back_dir_ent]{:?}", iter.current_clone());
        for long_ent in long_ents {
            iter.next();
            let n = iter.current_clone();
            log::trace!("[wr_back_dir_ent]{:?}", iter.get_offset());
            assert!(n.is_some() && n.unwrap().unused());
            iter.write_to_current_ent(&FATDirEnt {
                long_entry: long_ent,
            });
        }
    }

    /// Fill out an empty directory with only the '.' & '..' entries.
    fn fill_empty_dir(
        parent_dir: &Arc<Inode<T, F>>,
        current_dir: &Arc<Inode<T, F>>,
        mut current_lock: MutexGuard<FileContent<T>>,
        fst_clus: u32,
    ) {
        let buf = vec![0; current_lock.size as usize];
        current_dir.write_at_block_cache(&mut current_lock, 0, buf.as_ref());
        let mut iter = current_dir.dir_iter(current_lock, None, DirIterMode::Enum, FORWARD);
        let mut short_name: [u8; 11] = [' ' as u8; 11];
        //.
        iter.next();
        short_name[0] = '.' as u8;
        iter.write_to_current_ent(&FATDirEnt {
            short_entry: FATShortDirEnt::from_name(
                short_name,
                fst_clus as u32,
                DiskInodeType::Directory,
            ),
        });
        //..
        iter.next();
        short_name[1] = '.' as u8;
        iter.write_to_current_ent(&FATDirEnt {
            short_entry: FATShortDirEnt::from_name(
                short_name,
                parent_dir.get_file_clus(),
                DiskInodeType::Directory,
            ),
        });
        //add "unused and last" sign
        iter.next();
        iter.write_to_current_ent(&FATDirEnt::unused_and_last_entry());
    }
}

// ls and find local
impl<T: CacheManager, F: CacheManager> Inode<T, F> {
    ////
    #[inline(always)]
    /// ls - General Purose file filterer
    /// # Argument/Modes
    /// Apart from `None` mode, all modes will quit IMMEDIATELY returning a vector of one after the first successful match.
    /// Modes are conveyed through enum `DirFilter`. Four modes are provided, namely:
    /// * `Name(String)`: Used for exact match of names.
    /// * `FstClus(u64)`: First Cluster matching. Note that this shouldn't be used for zero-sized files for they MAY contain NO by specification.
    /// For this mode, it returns an Err(()) for the next of reaching the last item.
    /// * `DirentBegOffset(u32)`: Search should begin with the
    /// * `None`: List all files in `self`.
    ///
    /// # WARNING
    /// The definition of OFFSET is CHANGED for this item.
    /// It should point to the NEXT USED entry whether it as a long entry whenever possible or a short entry if no long ones exist.
    /// # Return value
    /// On success, the function returns `Ok(_)`. On failure, multiple chances exist: either the Vec is empty, or the Result is `Err(())`.
    /// # Implementation Information
    /// The iterator stops at the last available item when it reaches the end,
    /// returning `None` from then on,
    /// so relying on the offset of the last item to decide whether it has reached an end is not recommended.
    pub fn ls(&self) -> Result<Vec<(String, FATShortDirEnt)>, ()> {
        if !self.is_dir() {
            return Err(());
        }
        let lock = self.file_content.lock();
        Ok(self
            .dir_iter(lock, None, DirIterMode::UsedIter, FORWARD)
            .walk()
            .collect())
    }
    pub fn find_local(
        &self,
        req_name: String,
    ) -> Result<Option<(String, FATShortDirEnt, u32)>, ()> {
        if !self.is_dir() {
            return Err(());
        }
        log::debug!("[find_local] name: {:?}", req_name);
        let lock = self.file_content.lock();
        let mut walker = self
            .dir_iter(lock, None, DirIterMode::UsedIter, FORWARD)
            .walk();
        match walker.find(|(name, _)| name.as_str() == req_name.as_str()) {
            Some((name, short_ent)) => {
                log::trace!("[easy-fs: find_local] Query name: {} found", req_name);
                Ok(Some((name, short_ent, walker.iter.get_offset().unwrap())))
            }
            None => {
                log::trace!("[easy-fs: find_local] Query name: {} not found", req_name);
                Ok(None)
            }
        }
    }
}

// metadata
impl<T: CacheManager, F: CacheManager> Inode<T, F> {
    /// Return the `stat` structure to `self` file.
    pub fn stat(&self) -> (i64, i64, i64, i64, u64) {
        let time = self.time.lock();
        (
            self.get_file_size() as i64,
            time.access_time as i64,
            time.modify_time as i64,
            time.create_time as i64,
            self.get_inode_num().unwrap_or(0) as u64,
        )
    }

    /// Get a dirent information from the `self` at `offset`
    /// Return `None` if `self` is not a directory.
    /// # Argument
    /// `offset` The offset within the `self` directory.
    /// `length` The length of required vector
    pub fn dirent_info(
        &self,
        offset: u32,
        length: usize,
    ) -> Result<Vec<(String, usize, u64, FATDiskInodeType)>, ()> {
        if !self.is_dir() {
            return Err(());
        }
        log::debug!("[dirent_info] offset: {}, length: {}", offset, length);
        let lock = self.file_content.lock();
        let size = lock.size;
        let mut walker = self
            .dir_iter(lock, None, DirIterMode::UsedIter, FORWARD)
            .walk();
        walker.iter.set_iter_offset(offset);
        let mut v = Vec::with_capacity(length);

        let (mut last_name, mut last_short_ent) = match walker.next() {
            Some(tuple) => tuple,
            None => return Ok(v),
        };
        for _ in 0..length {
            let next_dirent_offset =
                walker.iter.get_offset().unwrap() as usize + core::mem::size_of::<FATDirEnt>();
            let (name, short_ent) = match walker.next() {
                Some(tuple) => tuple,
                None => {
                    v.push((
                        last_name,
                        size as usize,
                        last_short_ent.get_first_clus() as u64,
                        last_short_ent.attr,
                    ));
                    return Ok(v);
                }
            };
            log::trace!(
                "{}, offset: {}",
                last_name,
                walker.iter.get_offset().unwrap() as usize
            );
            v.push((
                last_name,
                next_dirent_offset,
                last_short_ent.get_first_clus() as u64,
                last_short_ent.attr,
            ));
            last_name = name;
            last_short_ent = short_ent;
        }
        log::trace!("[dirent_info] v: {:?}", v);
        Ok(v)
    }
}
