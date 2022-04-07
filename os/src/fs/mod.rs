mod dev_fs;
pub mod finfo;
mod inode;
mod mount;
mod pipe;
mod poll;
pub mod stdio;

use crate::mm::UserBuffer;
use alloc::sync::Arc;
pub use poll::{ppoll, pselect, FdSet, PollFd};

#[derive(Clone)]
pub struct FileDescriptor {
    cloexec: bool,
    pub file: FileLike,
}

impl FileDescriptor {
    pub fn new(cloexec: bool, file: FileLike) -> Self {
        Self { cloexec, file }
    }

    pub fn set_cloexec(&mut self, flag: bool) {
        self.cloexec = flag;
    }

    pub fn get_cloexec(&self) -> bool {
        self.cloexec
    }
}

#[derive(Clone)]
pub enum FileLike {
    Regular(Arc<OSInode>),
    Abstract(Arc<dyn File + Send + Sync>),
}

pub trait File: Send + Sync {
    fn readable(&self) -> bool;
    fn writable(&self) -> bool;
    fn read(&self, buf: UserBuffer) -> usize;
    fn write(&self, buf: UserBuffer) -> usize;
    fn kread(&self, _offset: Option<&mut usize>, _buffer: &mut [u8]) -> usize {
        todo!()
    }
    fn kwrite(&self, _offset: Option<&mut usize>, _buffer: &[u8]) -> usize {
        todo!()
    }
    fn ioctl(&self, _cmd: u32, _arg: usize) -> isize {
        0
    }
    fn r_ready(&self) -> bool {
        true
    }
    fn w_ready(&self) -> bool {
        true
    }
    fn hang_up(&self) -> bool {
        false
    }
}

pub use dev_fs::*;
pub use finfo::*; //{Dirent, FdSet, Kstat, NewStat, DT_DIR, DT_REG, DT_UNKNOWN, *};
pub use inode::{
    /*find_par_inode_id, */ ch_dir, clear_cache, init_rootfs, list_apps, list_files, open,
    DiskInodeType, OSInode, OpenFlags,
};
//pub use iovec::{IoVec, IoVecs};
pub use mount::MNT_TABLE;
pub use pipe::{make_pipe, Pipe};
pub use stdio::{Stdin, Stdout};
