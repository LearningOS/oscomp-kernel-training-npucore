use core::convert::TryInto;
use core::mem;
use core::ops::{AddAssign, SubAssign};
//use core::panicking::panic;
//use core::panicking::panic;

use super::{DiskInodeType, EasyFileSystem};

use alloc::string::String;

use crate::block_cache::{Cache, CacheManager};
use crate::layout::{FATDirEnt, FATDirShortEnt, FATLongDirEnt, LONG_DIR_ENT_NAME_CAPACITY};
use crate::{DataBlock, BLOCK_SZ};

use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::{Mutex, RwLock};
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
        let lock = self.direct.lock();
        if !lock.is_empty() {
            Some(self.fs.first_sector_of_cluster(lock[0]))
        } else {
            None
        }
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
        let v: Vec<u16> = name.encode_utf16().collect();
        assert!(long_ent_num >= 1);
        assert!((long_ent_num - 1) * LONG_DIR_ENT_NAME_CAPACITY < v.len());
        if LONG_DIR_ENT_NAME_CAPACITY * long_ent_num <= v.len() {
            return v[LONG_DIR_ENT_NAME_CAPACITY * (long_ent_num - 1)
                ..(LONG_DIR_ENT_NAME_CAPACITY * long_ent_num)]
                .try_into()
                .expect("should be able to cast");
        } else {
            let mut ret = [0u16; LONG_DIR_ENT_NAME_CAPACITY];
            ret[0..v.len() % LONG_DIR_ENT_NAME_CAPACITY]
                .copy_from_slice(&v[LONG_DIR_ENT_NAME_CAPACITY * (long_ent_num - 1)..v.len()]);
            return ret;
        }
    }
    pub fn rename(&self, new_name: String) -> core::fmt::Result {
        Err(core::fmt::Error)
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
        parent_dir: Option<(Arc<Self>, usize)>,
        fs: Arc<EasyFileSystem<T, F>>,
    ) -> Self {
        let mut clus_size_as_size = false;
        let i = Inode {
            file_cache_mgr: (T::new(if fst_clus != 0 {
                fs.first_sector_of_cluster(fst_clus as u32) as usize
            } else {
                ((parent_dir.as_ref().unwrap().0.get_inode_num().unwrap() as usize) << 32)
                    | (parent_dir.as_ref().unwrap().1 as usize)
            })),
            direct: Mutex::new(if fst_clus != 0 {
                fs.fat.get_all_clus_num(fst_clus as u32, &fs.block_device)
            } else {
                Vec::new()
            }),
            type_,
            size: if let Some(size) = size {
                clus_size_as_size = true;
                RwLock::new(size as u32)
            } else {
                RwLock::new(0 as u32)
            },
            parent_dir,
            fs,
        };
        if !clus_size_as_size {
            i.size
                .write()
                .add_assign(i.direct.lock().len() as u32 * i.fs.clus_size());
        }
        return i;
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
        (*self.size.read())
        .div_ceil(self.fs.clus_size())
    }
    /// Return number of blocks needed after rounding according to the cluster number.
    pub fn total_clus(&self, size: u32) -> u32 {
        size.div_ceil(self.fs.clus_size())
    }

    /// Delete the short and the long entry of `self` from `parent_dir`
    pub fn delete_self_dir_ent(&self) -> DirIter<T, F> {
        let (dir, offset) = self.parent_dir.as_ref().unwrap();
        let mut iter = dir.iter();
        iter.set_offset(*offset);
        if *offset >= self.parent_dir.as_ref().unwrap().0.get_size() {
            iter.write_to_current_ent(&FATDirEnt::unused_and_last_entry());
        } else {
            iter.write_to_current_ent(&FATDirEnt::unused_not_last_entry());
        }
        iter = iter.backward();
        iter.set_offset(*offset);
        iter.next();
        let mut after_last_fat_dir_ent = false;
        loop {
            if after_last_fat_dir_ent
                || iter.current_clone().is_none()
                || iter.current_clone().unwrap().is_short()
            {
                break iter;
            }
            if iter.current_clone().unwrap().is_last_long_dir_ent() {
                after_last_fat_dir_ent = true;
            }
            iter.write_to_current_ent(&FATDirEnt::unused_not_last_entry());
            iter.next();
        }
    }
    /// Delete the file from the disk,
    /// deallocating both the directory entries (whether long or short),
    /// and the occupied clusters.
    pub fn delete_from_disk(trash: Arc<Self>) -> core::fmt::Result {
        if trash.is_dir() {
            //see if the dir is empty
            let v = trash.ls();
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
        for _ in 0..exp_num - 1 {
            if self.write_at_block_cache(self.get_size(), buf.as_bytes()) != buf.as_bytes().len() {
                return Err(core::fmt::Error);
            }
        }
        let buf = FATDirEnt::unused_and_last_entry();
        if self.write_at_block_cache(self.get_size(), buf.as_bytes()) != buf.as_bytes().len() {
            return Err(core::fmt::Error);
        }
        Ok(())
    }

    #[inline(always)]
    fn gen_short_name_slice(
        dir_iter: DirIter<T, F>,
        name: &String,
        short_name_slice: &mut [u8; 11],
    ) -> core::fmt::Result {
        {
            let short_name = FATDirEnt::gen_short_name_prefix(name.clone());
            if short_name.len() == 0 || short_name.find(' ').unwrap_or(8) == 0 {
                return Err(core::fmt::Error);
            }
            short_name_slice.copy_from_slice(&short_name.as_bytes()[0..11]);
            FATDirEnt::gen_short_name_numtail(dir_iter.short().collect(), short_name_slice);
        }
        Ok(())
    }

    fn alloc_dir_ent(
        parent_dir: &Arc<Self>,
        iter: &mut DirIter<T, F>,
        long_ent_num: usize,
        fst_clus: &mut u32,
        file_type: &DiskInodeType,
    ) -> bool {
        true && match iter.alloc_dir_ent(long_ent_num + 1) {
            Ok(_) => {
                true // allocate the directory in current size
            }
            Err(trailing_unused) => {
                if parent_dir
                    .expand_dir_size(1 + long_ent_num - trailing_unused)
                    .is_ok()
                // or succeed in expanding the dir size...
                {
                    for _ in 0..long_ent_num - trailing_unused {
                        iter.next();
                    }
                    true
                } else {
                    false
                }
            }
        } && (*file_type != DiskInodeType::Directory // the directory should be allocated ahead of use for a new directory.
                || if let Some(i) = parent_dir
                    .fs
                    .fat
                    .alloc_one(&parent_dir.fs.block_device, None)
                {
                    *fst_clus = i;
                    true
                } else {
                    false
                })
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
                .ls()
                .iter()
                .find(|s| s.0.to_uppercase() == name.to_uppercase())
                .is_some()
        {
            Err(core::fmt::Error)
        } else {
            let mut short_name_slice: [u8; 11] = [32u8; 11];
            if Self::gen_short_name_slice(parent_dir.iter(), &name, &mut short_name_slice).is_err()
            {
                return Err(core::fmt::Error);
            }
            let long_ent_num =
                (name.len() + LONG_DIR_ENT_NAME_CAPACITY - 1) / LONG_DIR_ENT_NAME_CAPACITY;
            let mut iter = parent_dir.iter();
            let mut fst_clus = 0;
            if Self::alloc_dir_ent(
                &parent_dir,
                &mut iter,
                long_ent_num,
                &mut fst_clus,
                &file_type,
            ) {
                // write the directory entries
                let offset = iter.offset;
                let short = Self::write_back_dir_ent(
                    &mut iter,
                    &name,
                    long_ent_num,
                    short_name_slice,
                    fst_clus,
                    &file_type,
                );
                let arc = Arc::new(Inode::from_ent(&parent_dir, &short, offset));
                if fst_clus != 0 {
                    Self::fill_empty_dir(fst_clus, &parent_dir, &arc);
                }
                // create an empty directory.
                return Ok(arc);
            } else {
                return Err(core::fmt::Error);
            };
        }
    }

    #[inline(always)]
    /// Write back both long and short directories.
    /// The short directory is created from the `fst_clus` and the `name`.
    fn write_back_dir_ent(
        iter: &mut DirIter<T, F>,
        name: &String,
        long_ent_num: usize,
        short_name_slice: [u8; 11],
        fst_clus: u32,
        file_type: &DiskInodeType,
    ) -> FATDirShortEnt {
        iter.to_backward();
        let short = FATDirShortEnt::from_name(short_name_slice, fst_clus, *file_type);
        iter.write_to_current_ent(&FATDirEnt { short_entry: short });
        iter.next();
        for i in 1..long_ent_num {
            iter.write_to_current_ent(&FATDirEnt {
                long_entry: FATLongDirEnt::from_name_slice(
                    false,
                    i,
                    Self::get_long_name_slice(name, i),
                ),
            });
            iter.next();
        }
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
        let sz = arc.get_size();
        let mut buf = FATDirEnt::empty();
        buf.as_bytes_mut()[11] = 0;

        let mut new_iter = arc.iter();
        let mut short_name: [u8; 11] = [32u8; 11];

        short_name[0] = '.' as u8;
        new_iter.write_to_current_ent(&FATDirEnt {
            short_entry: FATDirShortEnt::from_name(
                short_name,
                fst_clus as u32,
                DiskInodeType::Directory,
            ),
        });
        new_iter.next();
        short_name[1] = '.' as u8;
        new_iter.write_to_current_ent(&FATDirEnt {
            short_entry: FATDirShortEnt::from_name(
                short_name,
                parent_dir.get_inode_num().unwrap(),
                DiskInodeType::Directory,
            ),
        });
        new_iter.next();
        new_iter.write_to_current_ent(&FATDirEnt::unused_and_last_entry());
        new_iter.next();
        loop {
            if new_iter.offset == sz {
                break;
            }
            new_iter.write_to_current_ent(&buf);
            new_iter.offset += buf.as_bytes().len();
        }
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
        let size = { *self.size.read() };
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
    #[inline(always)]
    fn get_size(&self) -> usize {
        self.file_size()
    }

    pub fn ls(&self) -> Vec<(String, FATDirShortEnt, usize)> {
        if !self.is_dir() {
            return Vec::new();
        } else {
            let mut v = Vec::with_capacity(30);
            let mut name = Vec::with_capacity(3);
            let mut iter = self.iter();

            let mut should_be_ord = 0;
            loop {
                let offset = iter.get_offset();
                if let Some(i) = iter.next() {
                    if i.is_long() {
                        if (name.is_empty() && i.is_last_long_dir_ent())
                            || (i.ord() == should_be_ord)
                        {
                            should_be_ord = i.ord() - 1;
                            name.insert(0, i.get_name());
                        } else {
                            name.clear();
                            name.insert(0, i.get_name());
                        }
                    } else {
                        if !name.is_empty() {
                            //then match the name to see if it's correct.
                            if true {
                                //if correct, push the concatenated name
                                v.push((name.concat(), i.get_short_ent().unwrap().clone(), offset));
                                name.clear();
                                continue;
                            } else {
                                // short name doesn't match... The previous long entries are not correct.
                                name.clear();
                            }
                        }
                        // only one short
                        v.push((i.get_name(), i.get_short_ent().unwrap().clone(), offset));
                    }
                } else {
                    break;
                }
            }
            return v;
        }
    }

    pub fn iter(&self) -> DirIter<T, F> {
        DirIter {
            dir: self,
            offset: 0,
            forward: true,
            mode: Mutex::new(DirIterMode::UsedIter),
        }
    }

    /// Change the size of current file.
    /// # Return Value
    /// If failed, return `None`, otherwise return `Some(())`
    pub fn modify_size(&self, diff: isize) {
        //println!("hi2");
        let mut take = FATDirEnt::empty();
        if let Some(ref par) = self.parent_dir {
            par.0.read_at_block_cache(par.1, take.as_bytes_mut());
        }
        let size = self.get_size();
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
        take.set_size(self.get_size() as u32);
        println!("{}", self.get_size());
        if let Some(ref par) = self.parent_dir {
            par.0.write_at_block_cache(par.1, take.as_bytes());
        }
    }
}

#[allow(unused)]
pub fn find_local<T: CacheManager, F: CacheManager>(
    inode: Arc<Inode<T, F>>,
    target_name: String,
) -> Option<Arc<Inode<T, F>>> {
    if inode.is_dir() {
        let mut name = Vec::with_capacity(3);
        let mut iter = inode.iter();
        let mut wrap = iter.next();
        let mut offset = 0;
        let mut should_be_ord = 0;

        while wrap.is_some() {
            let i = wrap.unwrap();
            offset = iter.get_offset();
            wrap = iter.next();

            if i.is_long() {
                if (name.is_empty() && i.is_last_long_dir_ent()) || (i.ord() == should_be_ord) {
                    should_be_ord = i.ord() - 1;
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
                            return Some(Arc::new(Inode::<T, F>::from_ent(
                                &inode,
                                i.get_short_ent().unwrap(),
                                offset,
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
    offset: usize,
    mode: Mutex<DirIterMode>,
    forward: bool,
}

impl<T: CacheManager, F: CacheManager> DirIter<T, F> {
    fn is_file(&self) -> bool {
        unsafe { (*self.dir).is_file() }
    }
    pub fn get_offset(&self) -> usize {
        self.offset
    }
    pub fn set_offset(&mut self, offset: usize) {
        self.offset = offset;
    }
    pub fn current_clone(&self) -> Option<FATDirEnt> {
        let mut i = FATDirEnt::empty();
        unsafe {
            if self.offset < (*(self.dir)).get_size()
                && (*self.dir).read_at_block_cache(self.offset, i.as_bytes_mut()) != 0
            {
                Some(i)
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
    pub fn short(self) -> Self {
        *self.mode.lock() = DirIterMode::ShortIter;
        self
    }
    pub fn long(self) -> Self {
        *self.mode.lock() = DirIterMode::LongIter;
        self
    }
    pub fn everything(self) -> Self {
        *self.mode.lock() = DirIterMode::Enum;
        self
    }
    pub fn all(self) -> Self {
        *self.mode.lock() = DirIterMode::UsedIter;
        self
    }
    pub fn unused(self) -> Self {
        *self.mode.lock() = DirIterMode::Unused;
        self
    }
    pub fn write_to_current_ent(&self, ent: &FATDirEnt) {
        if unsafe {
            let i = (*(self.dir)).write_at_block_cache(self.offset, ent.as_bytes());
            println!("[write_to_current_ent]i:{}", i);
            i
        } != ent.as_bytes().len()
        {
            panic!("Failed!");
        }
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
        *self.mode.lock() = DirIterMode::Enum;
        println!("[alloc_dir_ent] num{}", num);
        loop {
            if let Some(ref i) = self.current_clone() {
                if i.unused() {
                    found += 1;
                    println!(
                        "[alloc_dir_ent]found+=1->{} @ offset:{}",
                        found, self.offset
                    );
                } else {
                    found = 0;
                }
            }
            if found >= num {
                println!("[alloc_dir_ent] Ok");
                break Ok(());
            } else if self.next().is_none() {
                break Err(found);
            };
        }
    }
}
impl<T: CacheManager, F: CacheManager> Iterator for DirIter<T, F> {
    type Item = FATDirEnt;
    fn next(&mut self) -> Option<Self::Item> {
        if self.is_file() {
            None
        } else {
            let mut i: FATDirEnt = FATDirEnt::empty();
            /// Move one step forward or backward depending on `self.forward`
            macro_rules! step {
                () => {
                    /* println!("step one to {}", self.offset); */
                    (unsafe { (*self.dir).read_at_block_cache(self.offset, i.as_bytes_mut()) });
                    if self.forward {
                        self.offset += core::mem::size_of::<FATDirEnt>();
                    } else {
                        self.offset -= core::mem::size_of::<FATDirEnt>();
                    }
                };
            }

            if !self.forward && self.offset == 0 || unsafe { *(*(self.dir)).size.read() == 0 } {
                return None;
            }

            step!();

            let lock = self.mode.lock();
            while {
                if self.forward {
                    self.offset < unsafe { (*self.dir).get_size() }
                } else {
                    self.offset != 0
                }
            } && match *lock {
                DirIterMode::Unused => !i.unused(),
                DirIterMode::UsedIter => i.unused_not_last(),
                DirIterMode::LongIter => i.unused_not_last() || i.is_short(),
                DirIterMode::ShortIter => i.unused_not_last() || i.is_long(),
                DirIterMode::Enum => false,
            } {
                step!();
            }

            if {
                if self.forward {
                    self.offset <= unsafe { (*self.dir).get_size() }
                } else {
                    self.offset != 0
                }
            } && match *lock {
                DirIterMode::Unused => i.unused(),
                DirIterMode::UsedIter => !i.unused(),
                DirIterMode::LongIter => !i.unused() && i.is_long(),
                DirIterMode::ShortIter => !i.unused() && i.is_short(),
                DirIterMode::Enum => !i.last_and_unused() || !self.forward,
            } {
                Some(i)
            } else {
                None
            }
        }
    }
}
