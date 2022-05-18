mod cache_mgr;
mod dev;
mod inode;
mod pipe;
mod poll;

use core::mem::size_of;

use crate::{mm::UserBuffer, syscall::errno::ENOTTY, timer::TimeSpec};
use alloc::{boxed::Box, sync::Arc};
pub use dev::*;
pub use inode::{list_apps, open, DiskInodeType, OSInode, open_root_inode};
pub use pipe::{make_pipe, Pipe};
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
        log::warn!("[ioctl] NOTTY");
        ENOTTY
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
    // The generic implementation for abstract file
    fn stat(&self) -> Box<Stat> {
        Box::new(Stat::new(
            // st_dev: u64
            5,
            //st_ino: u64
            1,
            //st_mode: u32
            0o100777,
            //st_nlink: u32
            1,
            //st_rdev: u64
            0x0000000400000040,
            //st_size: i64
            0,
            //st_atime_sec: i64
            0,
            //st_mtime_sec: i64
            0,
            //st_ctime_sec: i64
            0,
        ))
    }
}

bitflags! {
    pub struct OpenFlags: u32 {
        const O_RDONLY      =   0o0;
        const O_WRONLY      =   0o1;
        const O_RDWR        =   0o2;

        const O_CREAT       =   0o100;
        const O_EXCL        =   0o200;
        const O_NOCTTY      =   0o400;
        const O_TRUNC       =   0o1000;

        const O_APPEND      =   0o2000;
        const O_NONBLOCK    =   0o4000;
        const O_DSYNC       =   0o10000;
        const O_SYNC        =   0o4010000;
        const O_RSYNC       =   0o4010000;
        const O_DIRECTORY   =   0o200000;
        const O_NOFOLLOW    =   0o400000;
        const O_CLOEXEC     =   0o2000000;
        const O_ASYNC       =   0o20000;
        const O_DIRECT      =   0o40000;
        const O_LARGEFILE   =   0o100000;
        const O_NOATIME     =   0o1000000;
        const O_PATH        =   0o10000000;
        const O_TMPFILE     =   0o20200000;
    }
}

impl OpenFlags {
    /// Do not check validity for simplicity
    /// Return (readable, writable)
    pub fn read_write(&self) -> (bool, bool) {
        if self.is_empty() {
            (true, false)
        } else if self.contains(Self::O_WRONLY) {
            (false, true)
        } else {
            (true, true)
        }
    }
}

bitflags! {
    pub struct StatMode: u32 {
        const S_IFMT    =   0o170000; //bit mask for the file type bit field
        const S_IFSOCK  =   0o140000; //socket
        const S_IFLNK   =   0o120000; //symbolic link
        const S_IFREG   =   0o100000; //regular file
        const S_IFBLK   =   0o060000; //block device
        const S_IFDIR   =   0o040000; //directory
        const S_IFCHR   =   0o020000; //character device
        const S_IFIFO   =   0o010000; //FIFO

        const S_ISUID   =   0o4000; //set-user-ID bit (see execve(2))
        const S_ISGID   =   0o2000; //set-group-ID bit (see below)
        const S_ISVTX   =   0o1000; //sticky bit (see below)

        const S_IRWXU   =   0o0700; //owner has read, write, and execute permission
        const S_IRUSR   =   0o0400; //owner has read permission
        const S_IWUSR   =   0o0200; //owner has write permission
        const S_IXUSR   =   0o0100; //owner has execute permission

        const S_IRWXG   =   0o0070; //group has read, write, and execute permission
        const S_IRGRP   =   0o0040; //group has read permission
        const S_IWGRP   =   0o0020; //group has write permission
        const S_IXGRP   =   0o0010; //group has execute permission

        const S_IRWXO   =   0o0007; //others (not in group) have read, write,and execute permission
        const S_IROTH   =   0o0004; //others have read permission
        const S_IWOTH   =   0o0002; //others have write permission
        const S_IXOTH   =   0o0001; //others have execute permission
    }
}

const NAME_LIMIT: usize = 128;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Dirent {
    /// Inode number
    pub d_ino: usize,
    /// Offset to next `linux_dirent`
    pub d_off: isize,
    /// Length of this `linux_dirent`
    pub d_reclen: u16,
    /// Type of the file
    pub d_type: u8,
    /// The Filename (null-terminated)
    pub d_name: [u8; NAME_LIMIT],
}

impl Dirent {
    /// Offset to next `linux_dirent`
    pub fn new(d_ino: usize, d_off: isize, d_type: u8, d_name: &str) -> Self {
        let mut dirent = Self {
            d_ino,
            d_off,
            d_reclen: size_of::<Self>() as u16,
            d_type,
            d_name: [0; NAME_LIMIT],
        };
        dirent.d_name[0..d_name.len()].copy_from_slice(d_name.as_bytes());
        dirent
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Stat {
    st_dev: u64,   /* ID of device containing file */
    st_ino: u64,   /* Inode number */
    st_mode: u32,  /* File type and mode */
    st_nlink: u32, /* Number of hard links */
    st_uid: u32,
    st_gid: u32,
    st_rdev: u64, /* Device ID (if special file) */
    __pad: u64,
    st_size: i64,
    st_blksize: u32,
    __pad2: i32,
    st_blocks: u64,
    st_atime: TimeSpec,
    st_mtime: TimeSpec,
    st_ctime: TimeSpec,
    __unused: u64,
}

impl Stat {
    pub fn get_ino(&self) -> usize {
        self.st_ino as usize
    }

    pub fn new(
        st_dev: u64,
        st_ino: u64,
        st_mode: u32,
        st_nlink: u32,
        st_rdev: u64,
        st_size: i64,
        st_atime_sec: i64,
        st_mtime_sec: i64,
        st_ctime_sec: i64,
    ) -> Self {
        const BLK_SIZE: u32 = 512;
        Self {
            st_dev,
            st_ino,
            st_mode,
            st_nlink,
            st_uid: 0,
            st_gid: 0,
            st_rdev,
            __pad: 0,
            st_size,
            st_blksize: BLK_SIZE as u32,
            __pad2: 0,
            st_blocks: (st_size as u64 + BLK_SIZE as u64 - 1) / BLK_SIZE as u64,
            st_atime: TimeSpec {
                tv_sec: st_atime_sec as usize,
                tv_nsec: 0,
            },
            st_mtime: TimeSpec {
                tv_sec: st_mtime_sec as usize,
                tv_nsec: 0,
            },
            st_ctime: TimeSpec {
                tv_sec: st_ctime_sec as usize,
                tv_nsec: 0,
            },
            __unused: 0,
        }
    }
}
