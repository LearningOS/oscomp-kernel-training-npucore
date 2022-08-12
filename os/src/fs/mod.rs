mod cache;
mod dev;
pub mod directory_tree;
mod fat32;
pub mod file_trait;
mod filesystem;
mod layout;
pub mod poll;
pub mod swap;

pub use self::dev::{hwclock::*, null::*, pipe::*, socket::*, tty::*, zero::*};
use core::{
    ops::{Index, IndexMut},
    slice::{Iter, IterMut},
};

pub use self::layout::*;

pub use self::fat32::{BlockDevice, DiskInodeType, BLOCK_SZ};

use self::{cache::PageCache, directory_tree::DirectoryTreeNode, file_trait::File};
use crate::{
    mm::{Frame, UserBuffer},
    syscall::errno::*,
};
use alloc::{
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use lazy_static::*;
use spin::Mutex;

lazy_static! {
    pub static ref ROOT_FD: Arc<FileDescriptor> = Arc::new(FileDescriptor::new(
        false,
        false,
        self::directory_tree::ROOT
            .open(".", OpenFlags::O_RDONLY | OpenFlags::O_DIRECTORY, true)
            .unwrap()
    ));
}

pub fn is_relative(path: &str) -> bool {
    !path.starts_with('/') && path != "" && path != "."
}

#[derive(Clone)]
pub struct FileDescriptor {
    cloexec: bool,
    nonblock: bool,
    pub file: Arc<dyn File>,
}
#[allow(unused)]
impl FileDescriptor {
    pub fn new(cloexec: bool, nonblock: bool, file: Arc<dyn File>) -> Self {
        Self {
            cloexec,
            nonblock,
            file,
        }
    }
    pub fn set_cloexec(&mut self, flag: bool) {
        self.cloexec = flag;
    }
    pub fn get_cloexec(&self) -> bool {
        self.cloexec
    }

    pub fn get_nonblock(&self) -> bool {
        self.nonblock
    }

    pub fn get_cwd(&self) -> Option<String> {
        let inode = self.file.get_dirtree_node();
        let inode = match inode {
            Some(inode) => inode,
            None => return None,
        };
        Some(inode.get_cwd())
    }
    /// Just used for cwd
    pub fn cd(&self, path: &str) -> Result<Arc<Self>, isize> {
        match self.open(path, OpenFlags::O_DIRECTORY | OpenFlags::O_RDONLY, true) {
            Ok(fd) => Ok(Arc::new(fd)),
            Err(errno) => Err(errno),
        }
    }
    pub fn readable(&self) -> bool {
        self.file.readable()
    }
    pub fn writable(&self) -> bool {
        self.file.writable()
    }
    pub fn read(&self, offset: Option<&mut usize>, buf: &mut [u8]) -> usize {
        self.file.read(offset, buf)
    }
    pub fn write(&self, offset: Option<&mut usize>, buf: &[u8]) -> usize {
        self.file.write(offset, buf)
    }
    pub fn r_ready(&self) -> bool {
        self.file.r_ready()
    }
    pub fn w_ready(&self) -> bool {
        self.file.w_ready()
    }
    pub fn read_user(&self, offset: Option<usize>, buf: UserBuffer) -> usize {
        self.file.read_user(offset, buf)
    }
    pub fn write_user(&self, offset: Option<usize>, buf: UserBuffer) -> usize {
        self.file.write_user(offset, buf)
    }
    pub fn get_stat(&self) -> Stat {
        self.file.get_stat()
    }
    pub fn open(&self, path: &str, flags: OpenFlags, special_use: bool) -> Result<Self, isize> {
        if path == "" {
            return Ok(self.clone());
        }
        if self.file.is_file() && is_relative(path) {
            return Err(ENOTDIR);
        }
        let inode = self.file.get_dirtree_node();
        let inode = match inode {
            Some(inode) => inode,
            None => return Err(ENOENT),
        };
        let file = match inode.open(path, flags, special_use) {
            Ok(file) => file,
            Err(errno) => return Err(errno),
        };
        let cloexec = flags.contains(OpenFlags::O_CLOEXEC);
        Ok(Self::new(cloexec, false, file))
    }
    pub fn mkdir(&self, path: &str) -> Result<(), isize> {
        if self.file.is_file() && is_relative(path) {
            return Err(ENOTDIR);
        }
        let inode = self.file.get_dirtree_node();
        let inode = match inode {
            Some(inode) => inode,
            None => return Err(ENOENT),
        };
        inode.mkdir(path)
    }
    pub fn delete(&self, path: &str, delete_directory: bool) -> Result<(), isize> {
        if self.file.is_file() && is_relative(path) {
            return Err(ENOTDIR);
        }
        let inode = self.file.get_dirtree_node();
        let inode = match inode {
            Some(inode) => inode,
            None => return Err(ENOENT),
        };
        inode.delete(path, delete_directory)
    }
    pub fn rename(
        old_fd: &Self,
        old_path: &str,
        new_fd: &Self,
        new_path: &str,
    ) -> Result<(), isize> {
        if old_fd.file.is_file() && is_relative(old_path) {
            return Err(ENOTDIR);
        }
        if new_fd.file.is_file() && is_relative(new_path) {
            return Err(ENOTDIR);
        }
        let old_inode = old_fd.file.get_dirtree_node();
        let old_inode = match old_inode {
            Some(inode) => inode,
            None => return Err(ENOENT),
        };
        let new_inode = new_fd.file.get_dirtree_node();
        let new_inode = match new_inode {
            Some(inode) => inode,
            None => return Err(ENOENT),
        };

        let old_abs_path = [old_inode.get_cwd(), old_path.to_string()].join("/");
        let new_abs_path = [new_inode.get_cwd(), new_path.to_string()].join("/");
        DirectoryTreeNode::rename(&old_abs_path, &new_abs_path)
    }
    pub fn get_dirent(&self, count: usize) -> Result<Vec<Dirent>, isize> {
        if !self.file.is_dir() {
            return Err(ENOTDIR);
        }
        Ok(self.file.get_dirent(count))
    }
    pub fn get_offset(&self) -> usize {
        self.lseek(0, SeekWhence::SEEK_CUR).unwrap()
    }
    pub fn lseek(&self, offset: isize, whence: SeekWhence) -> Result<usize, isize> {
        self.file.lseek(offset, whence)
    }
    pub fn get_size(&self) -> usize {
        self.file.get_size()
    }
    pub fn modify_size(&self, diff: isize) -> Result<(), isize> {
        self.file.modify_size(diff)
    }
    pub fn truncate_size(&self, new_size: usize) -> Result<(), isize> {
        self.file.truncate_size(new_size)
    }
    pub fn set_timestamp(
        &self,
        ctime: Option<usize>,
        atime: Option<usize>,
        mtime: Option<usize>,
    ) -> Result<(), isize> {
        self.file.set_timestamp(ctime, atime, mtime);
        Ok(())
    }
    pub fn get_single_cache(&self, offset: usize) -> Result<Arc<Mutex<PageCache>>, ()> {
        self.file.get_single_cache(offset)
    }
    pub fn get_all_caches(&self) -> Result<Vec<Arc<Mutex<PageCache>>>, ()> {
        self.file.get_all_caches()
    }
    pub fn ioctl(&self, cmd: u32, argp: usize) -> isize {
        self.file.ioctl(cmd, argp)
    }
    // for execve
    pub fn map_to_kernel_space(&self, addr: usize) -> &'static [u8] {
        let caches = self.get_all_caches().unwrap();
        let frames = caches
            .iter()
            .map(|cache| Frame::InMemory(cache.try_lock().unwrap().get_tracker()))
            .collect();

        crate::mm::KERNEL_SPACE
            .lock()
            .insert_program_area(
                addr.into(),
                crate::mm::MapPermission::R | crate::mm::MapPermission::W,
                frames,
            )
            .unwrap();
        unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, self.get_size()) }
    }
}

#[derive(Clone)]
pub struct FdTable {
    inner: Vec<Option<FileDescriptor>>,
    soft_limit: usize,
    hard_limit: usize,
}

impl<I: core::slice::SliceIndex<[Option<FileDescriptor>]>> Index<I> for FdTable {
    type Output = I::Output;

    #[inline(always)]
    fn index(&self, index: I) -> &Self::Output {
        &self.inner[index]
    }
}

impl<I: core::slice::SliceIndex<[Option<FileDescriptor>]>> IndexMut<I> for FdTable {
    #[inline(always)]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        &mut self.inner[index]
    }
}

#[allow(unused)]
impl FdTable {
    pub const SYSTEM_FD_LIMIT: usize = 256;
    pub const DEFAULT_FD_LIMIT: usize = 64;
    pub fn new(inner: Vec<Option<FileDescriptor>>) -> Self {
        Self {
            inner,
            soft_limit: FdTable::DEFAULT_FD_LIMIT,
            hard_limit: FdTable::SYSTEM_FD_LIMIT,
        }
    }
    pub fn get_soft_limit(&self) -> usize {
        self.soft_limit
    }
    pub fn set_soft_limit(&mut self, limit: usize) {
        if limit < self.soft_limit {
            log::warn!(
                "[FdTable::set_limit] new limit: {} is smaller than old limit: {}",
                limit,
                self.soft_limit
            );
        }
        self.soft_limit = limit;
    }
    pub fn get_hard_limit(&self) -> usize {
        self.hard_limit
    }
    pub fn set_hard_limit(&mut self, limit: usize) {
        if limit < self.hard_limit {
            log::warn!(
                "[FdTable::set_limit] new limit: {} is smaller than old limit: {}",
                limit,
                self.hard_limit
            );
        }
        self.hard_limit = limit;
    }
    pub fn get_fd(&self, fd: usize) -> Result<&FileDescriptor, isize> {
        if fd >= self.inner.len() {
            return Err(EBADF);
        }
        match &self.inner[fd] {
            Some(file_descriptor) => Ok(file_descriptor),
            None => Err(EBADF),
        }
    }
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.inner.len()
    }
    #[inline(always)]
    pub fn iter(&self) -> Iter<Option<FileDescriptor>> {
        self.inner.iter()
    }
    #[inline(always)]
    pub fn iter_mut(&mut self) -> IterMut<Option<FileDescriptor>> {
        self.inner.iter_mut()
    }
    /// Try to alloc the lowest valid fd in `fd_table`
    pub fn alloc_fd(&mut self) -> Option<usize> {
        self.alloc_fd_at(0)
    }
    /// Try to alloc fd at `hint`, if `hint` is allocated, will alloc lowest valid fd above.
    pub fn alloc_fd_at(&mut self, hint: usize) -> Option<usize> {
        if hint >= self.soft_limit {
            return None;
        }
        let limit = self.inner.len().min(self.soft_limit);
        match (hint..limit).find(|fd| self.inner[*fd].is_none()) {
            Some(fd) => Some(fd),
            None => {
                if hint <= limit {
                    if limit < self.soft_limit {
                        if limit == self.inner.len() {
                            self.inner.push(None);
                        }
                        Some(limit)
                    } else {
                        None
                    }
                } else {
                    self.inner.resize(hint + 1, None);
                    Some(hint)
                }
            }
        }
    }
}
