use core::convert::TryInto;
use core::mem;
use core::ops::{AddAssign, SubAssign};
use std::error::Error;

//use core::panicking::panic;
//use core::panicking::panic;

use super::{DiskInodeType, EasyFileSystem};
//use proc_macro::bridge::server::Types;

use alloc::string::String;

use crate::block_cache::{Cache, CacheManager};
use crate::layout::{FATDirEnt, FATDirShortEnt, FATLongDirEnt, LONG_DIR_ENT_NAME_CAPACITY};
use crate::{DataBlock, BLOCK_SZ};

use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::{Mutex, RwLock};

pub enum DirFilter {
    Name(String),
    FstClus(u64),
    None,
}

impl DirFilter {
    /// Returns `true` if the dir filter is [`None`].
    ///
    /// [`None`]: DirFilter::None
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }
}

/// The functionality of ClusLi & Inode can be merged.
/// The struct for file information
/* *ClusLi was DiskInode*
 * Even old New York, was New Amsterdam...
 * Why they changed it I can't say.
 * People just like it better that way.*/
pub struct Inode<T: CacheManager, F: CacheManager> {
    /// For FAT32, size is a value computed from FAT.
    /// You should iterate around the FAT32 to get the size.
    pub size: RwLock<u32>,
    /// The cluster list.
    pub direct: Mutex<Vec<u32>>,
    /// File type
    pub type_: DiskInodeType,
    /// The parent directory of this inode
    pub parent_dir: Option<(Arc<Self>, usize)>,
    /// File cache manager corresponding to this inode.
    file_cache_mgr: Mutex<T>,
    /// The file system this inode is on.
    pub fs: Arc<EasyFileSystem<T, F>>,
}

impl<T: CacheManager, F: CacheManager> Inode<T, F> {
    pub fn first_sector(&self) -> Option<u32> {
        self.first_clus()
            .map(|clus| self.fs.first_sector_of_cluster(clus))
    }

    pub fn first_clus(&self) -> Option<u32> {
        let lock = self.direct.lock();
        if !lock.is_empty() {
            Some(lock[0])
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
    pub fn get_neighboring_sec(&self, inner_cache_id: usize) -> Vec<usize> {
        let inner_block_id = inner_cache_id * T::CACHE_SZ / BLOCK_SZ;
        let mut v = Vec::new();
        for i in inner_block_id & (!0b111usize)..=(inner_block_id | (0b111usize)) {
            if let Some(j) = self.get_block_id(i as u32) {
                v.push(j as usize)
            } else {
                break;
            }
        }
        v
    }
    /// Create a file from directory entry.
    /// # Arguments
    /// `parent_dir`: `Arc<Self>`, the parent directory inode pointer
    /// `ent`: `&FATDirShortEnt`, the short entry as the source of information
    /// `offset`: `usize`, the offset of the short directory entry in the `parent_dir`
    pub fn from_ent(parent_dir: &Arc<Self>, ent: &FATDirShortEnt, offset: usize) -> Self {
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
            Some((parent_dir.clone(), offset)),
            parent_dir.fs.clone(),
        )
    }
    /// Construct a \[u16,13\] corresponding to the `long_ent_num`'th 13-u16 or shorter name slice
    /// _NOTE_: the first entry is of number 1 for `long_ent_num`
    fn get_long_name_slice(
        name: &String,
        long_ent_num: usize,
    ) -> [u16; LONG_DIR_ENT_NAME_CAPACITY] {
        let mut v: Vec<u16> = name.encode_utf16().collect();
        assert!(long_ent_num >= 1);
        assert!((long_ent_num - 1) * LONG_DIR_ENT_NAME_CAPACITY < v.len());
        while v.len() < long_ent_num * LONG_DIR_ENT_NAME_CAPACITY {
            v.push(0);
        }
        let start = (long_ent_num - 1) * LONG_DIR_ENT_NAME_CAPACITY;
        v[start..]
        .try_into()
        .expect("should be able to cast")
    }
    pub fn rename(&self, new_name: String) -> core::fmt::Result {
        Err(core::fmt::Error)
    }
    /* pub fn open_li() -> Result<Arc<Self>, core::fmt::Error> {
     *     static file_li: BTreeMap<usize, Arc<Self>> = BTreeMap::new();
     * } */
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
        parent_dir: Option<(Arc<Self>, usize)>,
        fs: Arc<EasyFileSystem<T, F>>,
    ) -> Self {

        let fst_block_id = 
            if fst_clus != 0 {
                fs.first_sector_of_cluster(fst_clus as u32) as usize
            } else {
                ((parent_dir.as_ref().unwrap().0.get_inode_num().unwrap() as usize) << 32)
                    | (parent_dir.as_ref().unwrap().1 as usize)
            };
        
        let file_cache_mgr = T::new(fst_block_id);

        let direct = Mutex::new(
            if fst_clus != 0 {
                fs.fat.get_all_clus_num(fst_clus as u32, &fs.block_device)
            } else {
                Vec::new()
            }
        );

        let size = size.unwrap_or_else(||{
            direct.lock().len() as usize
            * fs.clus_size() as usize
        });
        let size = RwLock::new(size as u32);

        Inode { size, direct, type_, parent_dir, file_cache_mgr, fs }
    }
    pub fn file_size(&self) -> usize {
        *self.size.read() as usize
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
        self.total_clus(self.file_size() as u32)
    }
    /// Return number of blocks needed after rounding according to the cluster number.
    pub fn total_clus(&self, size: u32) -> u32 {
        size.div_ceil(self.fs.clus_size())
    }

    /// Delete the short and the long entry of `self` from `parent_dir`
    pub fn delete_self_dir_ent(&self){
        let (dir, offset) = self.parent_dir.as_ref().unwrap();
        let mut iter = dir.iter(DirIterMode::UsedIter);
        iter.set_offset(*offset);
        println!(
            "deleting short: {:?},name:{}",
            iter.current_clone(),
            iter.current_clone().unwrap().get_name()
        );
        iter.write_to_current_ent(&FATDirEnt::unused_not_last_entry());
        iter = iter.backward();

        //check this dir_ent is a short dir_ent 
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

        //remove long dir_ents
        loop{
            let dir_ent = iter.current_clone();
            if dir_ent.is_none() {
                panic!("illegal long dir_ent");
            }
            let dir_ent = dir_ent.unwrap();
            if !dir_ent.is_long() {
                panic!("illegal long dir_ent");
            }
            println!(
                "deleting long: {:?},name:{}",
                dir_ent,
                dir_ent.get_name()
            );
            iter.write_to_current_ent(&FATDirEnt::unused_not_last_entry());
            iter.next();
            if dir_ent.is_last_long_dir_ent() {
                return;
            }
        }
    }
    /// Delete the file from the disk,
    /// deallocating both the directory entries (whether long or short),
    /// and the occupied clusters.
    pub fn delete_from_disk(trash: Arc<Self>) -> core::fmt::Result {
        if trash.is_dir() {
            //see if the dir is empty
            let v = trash.ls(DirFilter::None);
            if v.len() > 2 {
                return Err(core::fmt::Error);
            }
            for item in v {
                if ![".", ".."].contains(&item.0.as_str()) {
                    return Err(core::fmt::Error);
                }
            }
        }
        trash
            .fs
            .fat
            .mult_dealloc(&trash.fs.block_device, trash.clear_size());
        trash.delete_self_dir_ent();
        return Ok(());
    }
    fn expand_dir_size(&self, exp_num: usize) -> core::fmt::Result {
        let buf = FATDirEnt::unused_not_last_entry();
        //fill with "unused not last" sign
        for _ in 0..exp_num {
            if self.write_at_block_cache(self.file_size(), buf.as_bytes()) != buf.as_bytes().len() {
                return Err(core::fmt::Error);
            }
        }
        Ok(())
    }

    #[inline(always)]
    fn gen_short_name_slice(
        parent_dir: &Arc<Self>,
        name: &String,
        short_name_slice: &mut [u8; 11],
    ) -> core::fmt::Result {
        let short_name = FATDirEnt::gen_short_name_prefix(name.clone());
        if short_name.len() == 0 || short_name.find(' ').unwrap_or(8) == 0 {
            return Err(core::fmt::Error);
        }
        short_name_slice.copy_from_slice(&short_name.as_bytes()[0..11]);
        FATDirEnt::gen_short_name_numtail(
            parent_dir
                .iter(DirIterMode::ShortIter)
                .collect(), 
            short_name_slice);
        Ok(())
    }
    /// return the offset of last free entry
    fn alloc_dir_ent(
        parent_dir: &Arc<Self>,
        num: usize,
    ) -> Result<usize, core::fmt::Error> {
        let mut iter = parent_dir.iter(DirIterMode::Enum);
        if let Err(matched) = iter.alloc_dir_ent(num) {
            if let Err(_) = parent_dir.expand_dir_size(num - matched) {
                return Err(core::fmt::Error);
            }
            // now iterator points to the last found directory entry
            // we just need iterate left entries ^-^
            if let Err(_) = iter.alloc_dir_ent(num - matched) {
                return Err(core::fmt::Error);
            }
        }
        println!("found {:?}", iter.get_offset());
        Ok(iter.get_offset().unwrap())
    }

    /// Create a file or a directory from the parent.
    pub fn create(
        parent_dir: Arc<Self>,
        name: String,
        file_type: DiskInodeType,
    ) -> Result<Arc<Inode<T, F>>, core::fmt::Error> {
        if parent_dir.is_file()
            || name.len() >= 256
            || parent_dir
                .ls(DirFilter::None)
                .iter()
                .find(|s| s.0.to_uppercase() == name.to_uppercase())
                .is_some()
        {
            Err(core::fmt::Error)
        } else {
            //get short name slice
            let mut short_name_slice: [u8; 11] = [' ' as u8; 11];
            if Self::gen_short_name_slice(&parent_dir, &name, &mut short_name_slice).is_err() {
                return Err(core::fmt::Error);
            }
            //alloc parent's directory entries
            let long_ent_num = name.len().div_ceil(LONG_DIR_ENT_NAME_CAPACITY);
            let short_ent_num = 1;
            let short_ent_offset = 
                Self::alloc_dir_ent(&parent_dir,long_ent_num + short_ent_num);
            if short_ent_offset.is_err() {
                return Err(core::fmt::Error);
            }
            let short_ent_offset = short_ent_offset.unwrap();
            //if file_type is Directory, alloc first cluster
            let fst_clus = 
                if file_type == DiskInodeType::Directory {
                    let fst_clus = parent_dir.fs.fat.alloc_one(&parent_dir.fs.block_device, None);
                    if fst_clus.is_none() {
                        return Err(core::fmt::Error);
                    }
                    fst_clus.unwrap()
                } else {
                    0
                };
            //write back parent's directory entry
            let short = 
                Self::write_back_dir_ent(
                    &parent_dir, 
                    short_ent_offset, 
                    &name, 
                    long_ent_num, 
                    short_name_slice, 
                    fst_clus, 
                    &file_type);
            //generate arc
            let arc = Arc::new(Inode::from_ent(&parent_dir, &short, short_ent_offset));
            //if file_type is Directory, set first 3 directory entry
            if file_type == DiskInodeType::Directory {
                //set size
                *arc.size.write() = 3 * core::mem::size_of::<FATDirEnt>() as u32;
                //fill content
                Self::fill_empty_dir(fst_clus, &parent_dir, &arc);
            }
            Ok(arc)
        }
    }

    #[inline(always)]
    /// Write back both long and short directories.
    /// The short directory is created from the `fst_clus` and the `name`.
    fn write_back_dir_ent(
        parent_dir: &Arc<Self>,
        short_ent_offset: usize,
        name: &String,
        long_ent_num: usize,
        short_name_slice: [u8; 11],
        fst_clus: u32,
        file_type: &DiskInodeType,
    ) -> FATDirShortEnt {
        //we have graranteed we have alloc enough entries
        //so we use Enum mode
        let mut iter = parent_dir.iter(DirIterMode::Enum);
        iter.set_offset(short_ent_offset);
        iter.to_backward();
        let short = FATDirShortEnt::from_name(short_name_slice, fst_clus, *file_type);
        iter.write_to_current_ent(&FATDirEnt { short_entry: short });
        
        for i in 1..long_ent_num {
            iter.next();
            iter.write_to_current_ent(&FATDirEnt {
                long_entry: FATLongDirEnt::from_name_slice(
                    false,
                    i,
                    Self::get_long_name_slice(name, i),
                ),
            });
        }
        iter.next();
        iter.write_to_current_ent(&FATDirEnt {
            long_entry: FATLongDirEnt::from_name_slice(
                true,
                long_ent_num,
                Self::get_long_name_slice(name, long_ent_num),
            ),
        });
        short
    }

    /// Fill out an empty directory with only the '.' & '..' entries.
    #[inline(always)]
    fn fill_empty_dir(fst_clus: u32, parent_dir: &Arc<Inode<T, F>>, arc: &Arc<Inode<T, F>>) {

        let mut iter = arc.iter(DirIterMode::Enum);
        let mut short_name: [u8; 11] = [' ' as u8; 11];
        //.
        iter.next();
        short_name[0] = '.' as u8;
        iter.write_to_current_ent(&FATDirEnt {
            short_entry: FATDirShortEnt::from_name(
                short_name,
                fst_clus as u32,
                DiskInodeType::Directory,
            ),
        });
        //..
        iter.next();
        short_name[1] = '.' as u8;
        iter.write_to_current_ent(&FATDirEnt {
            short_entry: FATDirShortEnt::from_name(
                short_name,
                parent_dir.get_inode_num().unwrap(),
                DiskInodeType::Directory,
            ),
        });
        //add "unused and last" sign
        iter.next();
        iter.write_to_current_ent(&FATDirEnt::unused_and_last_entry());
    }
    /// Get the addition of clusters needed to increase the file size.
    pub fn clus_num_needed(&self, new_size: u32) -> u32 {
        let lock = self.size.read();
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
        let size = *self.size.read();
        let end = (offset + buf.len()).min(size as usize);
        if start >= end {
            return 0;
        }
        let mut start_cache = start / T::CACHE_SZ;
        let mut read_size = 0usize;
        loop {
            // calculate end of current block
            let mut end_current_block = (start / T::CACHE_SZ + 1) * T::CACHE_SZ;
            end_current_block = end_current_block.min(end);
            // read and update read size
            let block_read_size = end_current_block - start;
            let dst = &mut buf[read_size..read_size + block_read_size];
            self.file_cache_mgr
                .lock()
                .get_block_cache(
                    self.get_block_id(start_cache as u32).unwrap() as usize,
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
    pub fn write_at_block_cache(&self, offset: usize, buf: &[u8]) -> usize {
        let mut start = offset;
        let lock = self.size.read();
        let size = *lock;
        drop(lock);
        let diff_len = buf.len() as isize + offset as isize - size as isize;
        if diff_len > 0 as isize {
            // allocate as many blocks as possible.
            self.modify_size(diff_len);
        }
        let slock = self.size.read();
        let end = (offset + buf.len()).min(*slock as usize);
        drop(slock);
        assert!(start <= end);
        let mut start_cache = start / T::CACHE_SZ;
        let mut write_size = 0usize;
        loop {
            // calculate end of current block
            let mut end_current_block = (start / T::CACHE_SZ + 1) * T::CACHE_SZ;
            end_current_block = end_current_block.min(end);
            // write and update write size
            let block_write_size = end_current_block - start;
            self.file_cache_mgr
                .lock()
                .get_block_cache(
                    self.get_block_id(start_cache as u32).unwrap() as usize,
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
            // move to next block
            if end_current_block == end {
                break;
            }
            start_cache += 1;
            start = end_current_block;
        }
        write_size
    }

    /// * Clear size to zero
    /// * Return blocks that should be deallocated.
    /// # Warning
    /// * The directory entry is NOT cleared and should be cleared manually.
    /// * We will clear the block contents to zero later.
    fn clear_size(&self) -> Vec<u32> {
        let mut lock = self.size.write();
        let rhs = *lock;
        lock.sub_assign(rhs);
        drop(lock);
        // direct is storing the CLUSTERS!
        let mut lock = self.direct.lock();
        // you haven't cleared the directory entry in the self.parent_dir
        mem::take(&mut lock)
    }

    pub fn ls(&self, cond: DirFilter) -> Vec<(String, FATDirShortEnt, usize)> {
        if !self.is_dir() {
            return Vec::new();
        }
        let mut v = Vec::with_capacity(30);
        let mut name = Vec::with_capacity(3);
        let mut iter = self.iter(DirIterMode::UsedIter);

        let mut should_be_ord = usize::MAX;
        while let Some(dir_ent) = iter.next() {
            if dir_ent.is_long() {
                if dir_ent.is_last_long_dir_ent() {
                    if !name.is_empty() {
                        //be warn future
                        panic!("why name isn't empty???");
                    }
                    name.push(dir_ent.get_name());
                    should_be_ord = dir_ent.ord() - 1;
                }
                else if dir_ent.ord() == should_be_ord {
                    name.push(dir_ent.get_name());
                    should_be_ord -= 1;
                }
                else {
                    unreachable!()
                }
            } else if dir_ent.is_short() {
                let filename: String; 
                if name.is_empty() {
                    filename = dir_ent.get_name();
                }
                else {
                    name.reverse();
                    filename = name.concat();
                    name.clear();
                    //then match the name to see if it's correct.
                    //todo
                };
                if match cond {
                    DirFilter::None => true,
                    DirFilter::Name(ref req_name) => *req_name == filename,
                    DirFilter::FstClus(inum) => {
                        inum as u32 == dir_ent.get_short_ent().unwrap().get_first_clus()
                    }
                } {
                    v.push((
                        filename,
                        dir_ent.get_short_ent().unwrap().clone(),
                        iter.get_offset().unwrap(),
                    ));
                    if !cond.is_none() {
                        break;
                    }
                }
            }
        } 
        return v;
    }

    pub fn iter(&self, mode: DirIterMode) -> DirIter<T, F> {
        DirIter {
            dir: self,
            offset: None,
            forward: true,
            mode,
        }
    }

    /// Change the size of current file.
    /// # Return Value
    /// If failed, return `None`, otherwise return `Some(())`
    pub fn modify_size(&self, diff: isize) {
        //println!("hi2");
        let mut take = FATDirEnt::empty();
        if let Some((inode, offset)) = &self.parent_dir {
            inode.read_at_block_cache(*offset, take.as_bytes_mut());
        }
        let size = self.file_size();
        if diff.abs() as usize > size && diff < 0 {
            return;
        }
        
        if diff > 0 {
            // clus_sz: 512, fsz:512, diff:32, should: true
            // clus_sz: 1024, fsz:512, diff:32, should: false
            // clus_sz: 1024, fsz:512, diff:513, should: true
            let mut lock = self.direct.lock();
            let ch_clus_num = (size as isize + diff + self.fs.clus_size() as isize - 1)
                / self.fs.clus_size() as isize
                - lock.len() as isize;
            let last = lock.last().map(|s| {
                let i: u32 = *s;
                i
            });
            let new_alloc = lock.len() == 0;
            let mut v = self
                .fs
                .fat
                .alloc_mult(&self.fs.block_device, ch_clus_num as usize, last);
            lock.append(&mut v);
            if new_alloc {
                take.set_fst_clus(lock[0]);
            }
        } else {
            // size_diff<0
            let diff = diff.abs();
            if diff == *self.size.read() as isize {
                //should clear the dir_ent here.
                take.set_fst_clus(0);
                self.fs
                    .fat
                    .mult_dealloc(&self.fs.block_device, self.clear_size());
            }
            let ch_clus_num = diff / self.fs.clus_size() as isize;
            let mut lock = self.direct.lock();
            for _ in 0..ch_clus_num {
                self.fs
                    .fat
                    .dealloc(&self.fs.block_device, lock.pop().unwrap());
            }
        }
        *self.size.write() += diff as u32;
        take.set_size(self.file_size() as u32);
        println!("{}", self.file_size());
        if let Some(ref par) = self.parent_dir {
            par.0.write_at_block_cache(par.1, take.as_bytes());
        }
    }
}

#[allow(unused)]
pub fn find_local<T: CacheManager, F: CacheManager>(
    inode: &Arc<Inode<T, F>>,
    target_name: String,
) -> Option<Arc<Inode<T, F>>> {
    let v = inode.ls(DirFilter::Name(target_name));
    if v.is_empty() {
        None
    } else {
        Some(Arc::new(Inode::from_ent(inode, &v[0].1, v[0].2)))
    }
}

pub enum DirIterMode {
    LongIter,
    ShortIter,
    UsedIter,
    Unused,
    Enum,
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
        matches!(self, Self::UsedIter)
    }

    /// Returns `true` if the dir iter mode is [`Unused`].
    ///
    /// [`Unused`]: DirIterMode::Unused
    pub fn is_unused(&self) -> bool {
        matches!(self, Self::Unused)
    }
}

pub struct DirIter<T: CacheManager, F: CacheManager> {
    dir: *const Inode<T, F>,
    offset: Option<usize>,
    mode: DirIterMode,
    forward: bool,
}
const STEP_SIZE: usize = core::mem::size_of::<FATDirEnt>();
impl<T: CacheManager, F: CacheManager> DirIter<T, F> {
    fn is_file(&self) -> bool {
        unsafe { (*self.dir).is_file() }
    }
    fn file_size(&self) -> usize {
        unsafe { (*self.dir).file_size() } 
    }
    pub fn get_offset(&self) -> Option<usize> {
        self.offset
    }
    pub fn set_offset(&mut self, offset: usize) {
        self.offset = Some(offset);
    }
    pub fn set_iter_offset(&mut self, offset: usize) {
        if self.forward {
            if offset == 0 {
                self.offset = None;
            }
            else {
                self.offset = Some(offset - STEP_SIZE);
            }
        }
        else {
            self.offset = Some(offset + STEP_SIZE);            
        }
    }
    pub fn current_clone(&self) -> Option<FATDirEnt> {
        let mut dir_ent = FATDirEnt::empty();
        unsafe {
            if  self.offset.is_some()
                && self.offset.unwrap() < (*(self.dir)).file_size()
                && (*self.dir).read_at_block_cache(self.offset.unwrap(), dir_ent.as_bytes_mut()) != 0
            {
                Some(dir_ent)
            } else {
                None
            }
        }
    }
    #[inline(always)]
    pub fn backward(mut self) -> Self {
        self.forward = false;
        self
    }
    pub fn to_backward(&mut self) {
        self.forward = false;
    }
    #[inline(always)]
    pub fn forward(mut self) -> Self {
        self.forward = true;
        self
    }
    #[inline(always)]
    pub fn toggle_direction(mut self) -> Self {
        self.forward = !self.forward;
        self
    }
    pub fn short(mut self) -> Self {
        self.mode = DirIterMode::ShortIter;
        self
    }
    pub fn long(mut self) -> Self {
        self.mode = DirIterMode::LongIter;
        self
    }
    pub fn everything(mut self) -> Self {
        self.mode = DirIterMode::Enum;
        self
    }
    pub fn all(mut self) -> Self {
        self.mode = DirIterMode::UsedIter;
        self
    }
    pub fn unused(mut self) -> Self {
        self.mode = DirIterMode::Unused;
        self
    }
    pub fn write_to_current_ent(&self, ent: &FATDirEnt) {
        let len = unsafe {
            (*(self.dir)).write_at_block_cache(self.offset.unwrap(), ent.as_bytes())
        };
        if len != ent.as_bytes().len() {
            panic!("failed!");
        }
        println!("[write_to_current_ent] offset:{}, content:{:?}", self.offset.unwrap(), ent.as_bytes());
    }
    /// Allocate unused directory entries for future use without expanding file size
    /// The search starts from the current offset of `self`.
    /// You should manually `self.set_offset(...)` if necessary.
    /// # Arguments
    /// * `num`: Intended number of allocation
    /// # Return Value
    /// * On success, return Ok(()),
    /// and keep the `self.offset` at the place of the last entry found.
    /// * On failure, return Err(Error).
    pub fn alloc_dir_ent(&mut self, num: usize) -> Result<(), usize> {
        let mut found = 0;
        self.forward = true;
        self.mode = DirIterMode::Enum;
        println!("[alloc_dir_ent] num{}", num);
        loop {
            let dir_ent = self.step();
            if dir_ent.is_none() {
                break;
            }
            let dir_ent = dir_ent.unwrap();
            if dir_ent.unused() {
                println!("[alloc_dir_ent] found free {:?}", self.offset);
                found += 1;
                if found >= num {
                    println!("[alloc_dir_ent] ok");
                    return Ok(());
                }
            }
            else {
                found = 0;
            }
        }
        
        println!("[alloc_dir_ent] Error unmatched {}", found);
        Err(found)
    }
    pub fn step(&mut self) -> Option<FATDirEnt> {
        let mut dir_ent: FATDirEnt = FATDirEnt::empty();
        if self.forward {
            // if offset is None => 0
            // if offset is non-negative => offset + STEP_SIZE
            let offset = 
                self.offset
                .map(|offset| offset + STEP_SIZE)
                .unwrap_or(0);
            if offset >= self.file_size() {
                return None;
            } 
            (unsafe { (*self.dir).read_at_block_cache(offset, dir_ent.as_bytes_mut()) });
            match self.mode {
                DirIterMode::Enum => (),
                _ => {
                    // if directory entry is "last and unused", next is unavailable
                    if dir_ent.last_and_unused() {
                        return None;
                    }
                }
            }
            self.offset = Some(offset);
        } else {
            if self.offset.is_none() {
                return None;
            }
            if self.offset.unwrap() == 0 {
                self.offset = None;
                return None;
            }
            self.offset = self.offset.map(|offset| offset - STEP_SIZE);
            (unsafe { (*self.dir).read_at_block_cache(self.offset.unwrap(), dir_ent.as_bytes_mut()) });
        }
        // println!("offset {:?}, unused: {:?}, {:?}", self.offset, dir_ent.unused(), dir_ent);
        Some(dir_ent)
    }
}
impl<T: CacheManager, F: CacheManager> Iterator for DirIter<T, F> {
    type Item = FATDirEnt;
    fn next(&mut self) -> Option<Self::Item> {
        if self.is_file() {
            return None;
        }
        while let Some(dir_ent) = self.step() {
            fn check_dir_ent_legality(mode: &DirIterMode, dir_ent: &FATDirEnt) -> bool {
                match mode {
                    DirIterMode::Unused => dir_ent.unused_not_last(),
                    DirIterMode::UsedIter => !dir_ent.unused(),
                    DirIterMode::LongIter => !dir_ent.unused() && dir_ent.is_long(),
                    DirIterMode::ShortIter => !dir_ent.unused() && dir_ent.is_short(),
                    DirIterMode::Enum => true
                }
            }
            if check_dir_ent_legality(&self.mode, &dir_ent) {
                return Some(dir_ent);
            }
        }
        None
    }
}
