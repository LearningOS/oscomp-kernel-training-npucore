use alloc::sync::Arc;
use easy_fs::DiskInodeType;

use crate::{fs::{file_trait::{File}, layout::{Stat}, directory_tree::DirectoryTreeNode}, mm::UserBuffer};

/// Data Sink
/// Data written to the `/dev/null` special files is discarded.
/// Reads  from `/dev/null` always return end of file (i.e., read(2) returns 0)
pub struct Null;

impl File for Null {
    fn deep_clone(&self) -> Arc<dyn File> {
        todo!()
    }
    fn readable(&self) -> bool {
        true
    }
    fn writable(&self) -> bool {
        true
    }
    fn read(&self, offset: Option<&mut usize>, buf: &mut [u8]) -> usize {
        unreachable!()
    }
    fn write(&self, offset: Option<&mut usize>, buf: &[u8]) -> usize {
        unreachable!()
    }
    fn r_ready(&self) -> bool {
        true
    }
    fn w_ready(&self) -> bool {
        true
    }
    fn get_stat(&self) -> Stat {
        Stat::new(
            5,
            1,
            0o100777,
            1,
            0x0000000400000040,
            0,
            0,
            0,
            0,
        )
    }
    fn read_user(&self, buf: UserBuffer) -> usize {
        0
    }
    fn write_user(&self, buf: UserBuffer) -> usize {
        buf.len()
    }
    fn get_file_type(&self) -> DiskInodeType {
        DiskInodeType::File
    }

    fn info_dirtree_node(&self, dirnode_ptr: alloc::sync::Weak<crate::fs::directory_tree::DirectoryTreeNode>) {
        
    }

    fn get_dirtree_node(&self) -> Option<Arc<DirectoryTreeNode>> {
        todo!()
    }

    fn open(&self, flags: crate::fs::layout::OpenFlags, special_use: bool) -> Arc<dyn File> {
        todo!()
    }

    fn open_subfile(&self, name: &str) -> Result<Arc<dyn File>, isize> {
        todo!()
    }

    fn create(&self, name: &str, file_type: DiskInodeType) -> Result<Arc<dyn File>, isize> {
        todo!()
    }

    fn link_son(&self, name: &str, son: &Self) -> Result<(), isize> where Self: Sized {
        todo!()
    }

    fn unlink(&self, delete: bool) -> Result<(), isize> {
        todo!()
    }

    fn get_dirent(&self, count: usize) -> alloc::vec::Vec<crate::fs::layout::Dirent> {
        todo!()
    }

    fn lseek(&self, offset: isize, whence: crate::syscall::fs::SeekWhence) -> Result<usize, isize> {
        todo!()
    }

    fn modify_size(&self, diff: isize) -> Result<(), isize> {
        todo!()
    }

    fn truncate_size(&self, new_size: usize) -> Result<(), isize> {
        todo!()
    }

    fn set_timestamp(&self, ctime: Option<usize>, atime: Option<usize>, mtime: Option<usize>) {
        todo!()
    }

    fn get_single_cache(&self, offset: usize) -> Result<Arc<spin::Mutex<crate::fs::fs::cache_mgr::PageCache>>, ()> {
        todo!()
    }

    fn get_all_caches(&self) -> Result<alloc::vec::Vec<Arc<spin::Mutex<crate::fs::fs::cache_mgr::PageCache>>>, ()> {
        todo!()
    }

    fn oom(&self) -> usize {
        0
    }

    fn hang_up(&self) -> bool {
        todo!()
    }

}