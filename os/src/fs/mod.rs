mod dev;
mod fs;
pub mod poll;
pub mod file_trait;
mod layout;
pub mod directory_tree;
mod filesystem;

pub use {
    self::dev::null::*,
    self::dev::tty::*,
    self::dev::zero::*,
    self::dev::pipe::*,
};
pub use self::layout::*;

use lazy_static::*;
use alloc::{sync::{Arc}, string::{String, ToString}, vec::Vec, boxed::Box};
use spin::Mutex;
use crate::{mm::UserBuffer, syscall::{errno::*, fs::SeekWhence}};
use self::{fs::{inode::OSInode, cache_mgr::PageCache}, file_trait::{File}, directory_tree::DirectoryTreeNode};

lazy_static!{
    pub static ref ROOT_FD: Arc<FileDescriptor> = Arc::new(FileDescriptor::new(
        false,
        self::directory_tree::ROOT.open(".", OpenFlags::O_RDONLY | OpenFlags::O_DIRECTORY, true, false).unwrap()
    ));
}
#[derive(Clone)]
pub struct FileDescriptor {
    cloexec: bool,
    pub file: Arc<dyn File>,
}

impl FileDescriptor {
    pub fn new(cloexec: bool, file: Arc<dyn File>) -> Self {
        Self { cloexec, file }
    }
    pub fn set_cloexec(&mut self, flag: bool) {
        self.cloexec = flag;
    }

    pub fn get_cloexec(&self) -> bool {
        self.cloexec
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
    pub fn cd(
        &self,
        path: &str
    ) -> Result<Arc<Self>, isize> {
        match self.open(path, OpenFlags::O_DIRECTORY | OpenFlags::O_RDONLY, true, false) {
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
    pub fn read_user(&self, buf: UserBuffer) -> usize {
        self.file.read_user(buf)
    }
    pub fn write_user(&self, buf: UserBuffer) -> usize {
        self.file.write_user(buf)
    }
    pub fn get_stat(&self) -> Box<Stat> {
        Box::new(self.file.get_stat())
    }
    pub fn open(
        &self,
        path: &str,
        flags: OpenFlags,
        special_use: bool,
        ignore_file_type: bool,
    ) -> Result<Self, isize> {
        if self.file.is_file() && !path.starts_with('/') {
            return Err(ENOTDIR);
        }
        let inode = self.file.get_dirtree_node();
        let inode = match inode {
            Some(inode) => inode,
            None => return Err(ENOENT),
        };
        let file = match inode.open(path, flags, special_use, ignore_file_type) {
            Ok(file) => file,
            Err(errno) => return Err(errno),
        };
        let cloexec = flags.contains(OpenFlags::O_CLOEXEC);
        Ok(Self::new(cloexec, file))
    }
    pub fn mkdir(
        &self,
        path: &str,
    ) -> Result<(), isize> {
        if self.file.is_file() && !path.starts_with('/') {
            return Err(ENOTDIR);
        }
        let inode = self.file.get_dirtree_node();
        let inode = match inode {
            Some(inode) => inode,
            None => return Err(ENOENT),
        };
        inode.mkdir(path)
    }
    pub fn delete(
        &self,
        path: &str,
        delete_directory: bool
    ) -> Result<(), isize> {
        if self.file.is_file() && !path.starts_with('/') {
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
        if old_fd.file.is_file() && !old_path.starts_with('/') {
            return Err(ENOTDIR);
        }
        if new_fd.file.is_file() && !new_path.starts_with('/') {
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
        DirectoryTreeNode::rename(&old_abs_path,&new_abs_path)
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
        self.get_stat().get_size()
    }
    pub fn modify_size(&self, diff: isize) -> Result<(), isize> {
        self.file.modify_size(diff)
    }
    pub fn truncate_size(&self, new_size: usize) -> Result<(), isize> {
        self.file.truncate_size(new_size)
    }
    pub fn set_timestamp(&self, ctime: Option<usize>, atime: Option<usize>, mtime: Option<usize>) -> Result<(), isize> {
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
}


