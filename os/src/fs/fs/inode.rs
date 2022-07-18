use super::cache_mgr::*;
use crate::fs::directory_tree::DirectoryTreeNode;
use crate::fs::file_trait::File;
use crate::fs::layout::{Dirent, OpenFlags, Stat, StatMode};
use crate::mm::UserBuffer;
use crate::syscall::errno::*;
use crate::syscall::fs::SeekWhence;
use core::panic;

use alloc::string::ToString;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use easy_fs::layout::FATDiskInodeType;
pub use easy_fs::DiskInodeType;
use easy_fs::Inode;
use spin::Mutex;

pub type InodeImpl = Inode<PageCacheManager, BlockCacheManager>;

pub struct OSInode {
    readable: bool,
    writable: bool,
    /// See `DirectoryTreeNode` for more details
    special_use: bool,
    append: bool,
    inner: Arc<InodeImpl>,
    offset: Mutex<usize>,
    dirnode_ptr: Arc<Mutex<Weak<DirectoryTreeNode>>>,
}

impl OSInode {
    pub fn new(root_inode: Arc<InodeImpl>) -> Arc<dyn File> {
        Arc::new(Self {
            readable: true,
            writable: true,
            special_use: true,
            append: false,
            inner: root_inode,
            offset: Mutex::new(0),
            dirnode_ptr: Arc::new(Mutex::new(Weak::new())),
        })
    }
}

impl Drop for OSInode {
    fn drop(&mut self) {
        if self.special_use {
            let inode = self.get_dirtree_node();
            match inode {
                Some(inode) => inode.sub_special_use(),
                None => {}
            }
        }
    }
}
#[allow(unused)]
impl File for OSInode {
    fn deep_clone(&self) -> Arc<dyn File> {
        if self.special_use {
            let inode = self.get_dirtree_node();
            match inode {
                Some(inode) => inode.add_special_use(),
                None => {}
            }
        }
        Arc::new(Self {
            readable: self.readable,
            writable: self.writable,
            special_use: self.special_use,
            append: self.append,
            inner: self.inner.clone(),
            offset: Mutex::new(*self.offset.lock()),
            dirnode_ptr: self.dirnode_ptr.clone(),
        })
    }
    fn readable(&self) -> bool {
        self.readable
    }
    fn writable(&self) -> bool {
        self.writable
    }
    /// If offset is not `None`, `kread()` will start reading file from `*offset`,
    /// the `*offset` is adjusted to reflect the number of bytes written to the buffer,
    /// and the file offset won't be modified.
    /// Otherwise `kread()` will start reading file from file offset,
    /// the file offset is adjusted to reflect the number of bytes written to the buffer.
    /// # Warning
    /// Buffer must be in kernel space
    fn read(&self, offset: Option<&mut usize>, buffer: &mut [u8]) -> usize {
        let mut file_cont_lock = self.inner.lock();
        match offset {
            Some(offset) => {
                let len = self
                    .inner
                    .read_at_block_cache_lock(&mut file_cont_lock, *offset, buffer);
                drop(file_cont_lock);
                *offset += len;
                len
            }
            None => {
                let mut offset = self.offset.lock();
                let len = self
                    .inner
                    .read_at_block_cache_lock(&mut file_cont_lock, *offset, buffer);
                drop(file_cont_lock);
                *offset += len;
                len
            }
        }
    }
    /// If offset is not `None`, `kwrite()` will start writing file from `*offset`,
    /// the `*offset` is adjusted to reflect the number of bytes read from the buffer,
    /// and the file offset won't be modified.
    /// Otherwise `kwrite()` will start writing file from file offset,
    /// the file offset is adjusted to reflect the number of bytes read from the buffer.
    /// # Warning
    /// Buffer must be in kernel space
    fn write(&self, offset: Option<&mut usize>, buffer: &[u8]) -> usize {
        let mut file_cont_lock = self.inner.lock();
        match offset {
            Some(offset) => {
                let len =
                    self.inner
                        .write_at_block_cache_lock(&mut file_cont_lock, *offset, buffer);
                drop(file_cont_lock);
                *offset += len;
                len
            }
            None => {
                let mut offset = self.offset.lock();
                if self.append {
                    *offset = file_cont_lock.get_file_size() as usize;
                }
                let len =
                    self.inner
                        .write_at_block_cache_lock(&mut file_cont_lock, *offset, buffer);
                drop(file_cont_lock);
                *offset += len;
                len
            }
        }
    }
    fn r_ready(&self) -> bool {
        true
    }
    fn w_ready(&self) -> bool {
        true
    }
    fn read_user(&self, offset: Option<usize>, mut buf: UserBuffer) -> usize {
        let mut total_read_size = 0usize;

        let mut file_cont_lock = self.inner.lock();
        match offset {
            Some(mut offset) => {
                let mut offset = &mut offset;
                for slice in buf.buffers.iter_mut() {
                    let read_size =
                        self.inner
                            .read_at_block_cache_lock(&mut file_cont_lock, *offset, *slice);
                    if read_size == 0 {
                        break;
                    }
                    *offset += read_size;
                    total_read_size += read_size;
                }
            },
            None => {
                let mut offset = self.offset.lock();
                for slice in buf.buffers.iter_mut() {
                    let read_size =
                        self.inner
                            .read_at_block_cache_lock(&mut file_cont_lock, *offset, *slice);
                    if read_size == 0 {
                        break;
                    }
                    *offset += read_size;
                    total_read_size += read_size;
                }
            },
        }
        total_read_size
    }
    fn write_user(&self, offset: Option<usize>, buf: UserBuffer) -> usize {
        let mut total_write_size = 0usize;

        let mut file_cont_lock = self.inner.lock();
        match offset {
            Some(mut offset) => {
                let mut offset = &mut offset;
                for slice in buf.buffers.iter() {
                    let write_size =
                        self.inner
                            .write_at_block_cache_lock(&mut file_cont_lock, *offset, *slice);
                    assert_eq!(write_size, slice.len());
                    *offset += write_size;
                    total_write_size += write_size;
                }
            },
            None => {
                let mut offset = self.offset.lock();
                if self.append {
                    *offset = file_cont_lock.get_file_size() as usize;
                }
                for slice in buf.buffers.iter() {
                    let write_size =
                        self.inner
                            .write_at_block_cache_lock(&mut file_cont_lock, *offset, *slice);
                    assert_eq!(write_size, slice.len());
                    *offset += write_size;
                    total_write_size += write_size;
                }
            },
        }
        total_write_size
    }
    fn get_stat(&self) -> Stat {
        let (size, atime, mtime, ctime, ino) = self.inner.stat_lock(&mut self.inner.lock());
        let st_mod: u32 = {
            if self.inner.is_dir() {
                (StatMode::S_IFDIR | StatMode::S_IRWXU | StatMode::S_IRWXG | StatMode::S_IRWXO)
                    .bits()
            } else {
                (StatMode::S_IFREG | StatMode::S_IRWXU | StatMode::S_IRWXG | StatMode::S_IRWXO)
                    .bits()
            }
        };
        Stat::new(0, ino, st_mod, 1, 0, size, atime, mtime, ctime)
    }
    fn get_file_type(&self) -> DiskInodeType {
        self.inner.get_file_type()
    }

    fn info_dirtree_node(&self, dirnode_ptr: Weak<DirectoryTreeNode>) {
        *self.dirnode_ptr.lock() = dirnode_ptr;
    }

    fn get_dirtree_node(&self) -> Option<Arc<DirectoryTreeNode>> {
        self.dirnode_ptr.lock().upgrade()
    }

    fn open(&self, flags: OpenFlags, special_use: bool) -> Arc<dyn File> {
        Arc::new(Self {
            readable: flags.contains(OpenFlags::O_RDONLY) || flags.contains(OpenFlags::O_RDWR),
            writable: flags.contains(OpenFlags::O_WRONLY) || flags.contains(OpenFlags::O_RDWR),
            special_use,
            append: flags.contains(OpenFlags::O_APPEND),
            inner: self.inner.clone(),
            offset: Mutex::new(0),
            dirnode_ptr: self.dirnode_ptr.clone(),
        })
    }
    fn open_subfile(&self, name: &str) -> Result<Arc<dyn File>, isize> {
        let mut lock = self.inner.lock();
        if let Ok(Some((_, short_ent, offset))) =
            self.inner.find_local_lock(&mut lock, name.to_string())
        {
            Ok(Arc::new(Self {
                readable: true,
                writable: true,
                special_use: false,
                append: false,
                inner: Inode::from_ent(&self.inner, &short_ent, offset),
                offset: Mutex::new(0),
                dirnode_ptr: Arc::new(Mutex::new(Weak::new())),
            }))
        } else {
            Err(ENOENT)
        }
    }
    fn create(&self, name: &str, file_type: DiskInodeType) -> Result<Arc<dyn File>, isize> {
        let mut lock = self.inner.lock();
        let new_file = Inode::create_lock(&self.inner, &mut lock, name.to_string(), file_type);
        if let Ok(inner) = new_file {
            Ok(Arc::new(Self {
                readable: true,
                writable: true,
                special_use: false,
                append: false,
                inner,
                offset: Mutex::new(0),
                dirnode_ptr: Arc::new(Mutex::new(Weak::new())),
            }))
        } else {
            panic!()
        }
    }
    fn link_son(&self, name: &str, son: &Self) -> Result<(), isize>
    where
        Self: Sized,
    {
        let mut par_lock = self.inner.lock();
        let mut son_lock = son.inner.lock();
        if son
            .inner
            .link_par_lock(&mut son_lock, &self.inner, &mut par_lock, name.to_string())
            .is_err()
        {
            panic!();
        }
        Ok(())
    }
    fn unlink(&self, delete: bool) -> Result<(), isize> {
        let mut lock = self.inner.lock();
        if self.inner.is_dir() && !self.inner.is_empty_dir_lock(&mut lock) {
            return Err(ENOTEMPTY);
        }
        match self.inner.unlink_lock(&mut lock, delete) {
            Ok(_) => Ok(()),
            Err(errno) => Err(errno),
        }
    }
    fn get_dirent(&self, count: usize) -> Vec<Dirent> {
        const DT_UNKNOWN: u8 = 0;
        const DT_DIR: u8 = 4;
        const DT_REG: u8 = 8;

        assert!(self.inner.is_dir());
        let mut offset = self.offset.lock();
        let mut lock = self.inner.lock();
        log::debug!(
            "[get_dirent] tot size: {}, offset: {}, count: {}",
            lock.get_file_size(),
            offset,
            count
        );

        let vec = self
            .inner
            .dirent_info_lock(
                &mut lock,
                *offset as u32,
                count / core::mem::size_of::<Dirent>(),
            )
            .unwrap();
        if let Some((_, next_offset, _, _)) = vec.last() {
            *offset = *next_offset;
        }
        vec.iter()
            .map(|(name, offset, first_clus, type_)| {
                let d_type = match type_ {
                    FATDiskInodeType::AttrDirectory | FATDiskInodeType::AttrVolumeID => DT_DIR,
                    FATDiskInodeType::AttrArchive => DT_REG,
                    _ => DT_UNKNOWN,
                };
                Dirent::new(
                    *first_clus as usize,
                    *offset as isize,
                    d_type,
                    name.as_str(),
                )
            })
            .collect()
    }
    fn lseek(&self, offset: isize, whence: SeekWhence) -> Result<usize, isize> {
        let lock = self.inner.lock();
        let new_offset = match whence {
            SeekWhence::SEEK_SET => offset,
            SeekWhence::SEEK_CUR => *self.offset.lock() as isize + offset,
            SeekWhence::SEEK_END => lock.get_file_size() as isize + offset,
            // whence is duplicated
            _ => return Err(EINVAL),
        };
        let new_offset = match new_offset < 0 {
            true => return Err(EINVAL),
            false => new_offset as usize,
        };
        *self.offset.lock() = new_offset;
        Ok(new_offset)
    }
    fn modify_size(&self, diff: isize) -> Result<(), isize> {
        let mut lock = self.inner.lock();
        self.inner.modify_size_lock(&mut lock, diff);
        Ok(())
    }
    fn truncate_size(&self, new_size: usize) -> Result<(), isize> {
        let mut lock = self.inner.lock();
        let old_size = lock.get_file_size();
        self.inner
            .modify_size_lock(&mut lock, new_size as isize - old_size as isize);
        Ok(())
    }
    fn set_timestamp(&self, ctime: Option<usize>, atime: Option<usize>, mtime: Option<usize>) {
        let mut inode_time = self.inner.time();
        if let Some(ctime) = ctime {
            inode_time.set_create_time(ctime as u64);
        }
        if let Some(atime) = atime {
            inode_time.set_access_time(atime as u64);
        }
        if let Some(mtime) = mtime {
            inode_time.set_modify_time(mtime as u64);
        }
    }
    fn get_single_cache(&self, offset: usize) -> Result<Arc<Mutex<PageCache>>, ()> {
        if offset & 0xfff != 0 {
            return Err(());
        }
        let mut lock = self.inner.lock();
        let inner_cache_id = offset >> 12;
        Ok(self.inner.get_single_cache_lock(&mut lock, inner_cache_id))
    }
    fn get_all_caches(&self) -> Result<Vec<Arc<Mutex<PageCache>>>, ()> {
        Ok(self.inner.get_all_cache())
    }
    fn oom(&self) -> usize {
        self.inner.oom()
    }

    fn hang_up(&self) -> bool {
        todo!()
    }

    fn fcntl(&self, cmd: u32, arg: u32) -> isize {
        todo!()
    }
}
