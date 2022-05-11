use super::{Dirent, File, OpenFlags, Stat, StatMode};
use crate::mm::UserBuffer;
use crate::syscall::errno::*;
use crate::syscall::fs::SeekWhence;
use crate::timer::TimeSpec;
use crate::{drivers::BLOCK_DEVICE, println};

use _core::convert::TryInto;
use _core::usize;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::vec::Vec;
use bitflags::*;
use easy_fs::layout::FATDiskInodeType;
pub use easy_fs::DiskInodeType;
use easy_fs::{DirFilter, EasyFileSystem, Inode};
use lazy_static::*;
use spin::Mutex;

type InodeImpl = Inode;

// 此inode实际被当作文件
pub struct OSInode {
    readable: bool,
    writable: bool,
    //fd_cloexec: bool,
    inner: Mutex<OSInodeInner>,
}

pub struct OSInodeInner {
    offset: usize,         // 当前读写的位置
    inode: Arc<InodeImpl>, // inode引用
}

impl OSInode {
    pub fn new(readable: bool, writable: bool, inode: Arc<InodeImpl>) -> Self {
        Self {
            readable,
            writable,
            //fd_cloexec:false,
            inner: Mutex::new(OSInodeInner { offset: 0, inode }),
        }
    }

    pub fn is_dir(&self) -> bool {
        let inner = self.inner.lock();
        inner.inode.is_dir()
    }

    /* this func will not influence the file offset
     * @parm: if offset == -1, file offset will be used
     */
    pub fn read_vec(&self, offset: isize, len: usize) -> Vec<u8> {
        let mut inner = self.inner.lock();
        let mut len = len;
        let ori_off = inner.offset;
        if offset >= 0 {
            inner.offset = offset as usize;
        }
        let mut buffer = [0u8; 512];
        let mut v: Vec<u8> = Vec::new();
        loop {
            let rlen = inner.inode.read_at_block_cache(inner.offset, &mut buffer);
            if rlen == 0 {
                break;
            }
            inner.offset += rlen;
            v.extend_from_slice(&buffer[..rlen.min(len)]);
            if len > rlen {
                len -= rlen;
            } else {
                break;
            }
        }
        if offset >= 0 {
            inner.offset = ori_off;
        }
        v
    }

    pub fn read_all(&self) -> Vec<u8> {
        let mut inner = self.inner.lock();
        let mut buffer = [0u8; 512];
        let mut v: Vec<u8> = Vec::new();
        loop {
            let len = inner.inode.read_at_block_cache(inner.offset, &mut buffer);
            if len == 0 {
                break;
            }
            inner.offset += len;
            v.extend_from_slice(&buffer[..len]);
        }
        v
    }

    pub fn read_into(&self, buffer: &mut [u8]) {
        unsafe {
            let mut inner = self.inner.lock();
            loop {
                let len = inner.inode.read_into(inner.offset, buffer);
                if len == 0 {
                    break;
                }
                inner.offset += len;
            }
        }
    }
    pub fn write_all(&self, str_vec: &Vec<u8>) -> usize {
        let mut inner = self.inner.lock();
        let mut remain = str_vec.len();
        let mut base = 0;
        loop {
            let len = remain.min(512);
            inner
                .inode
                .write_at_block_cache(inner.offset, &str_vec.as_slice()[base..base + len]);
            inner.offset += len;
            base += len;
            remain -= len;
            if remain == 0 {
                break;
            }
        }
        return base;
    }

    pub fn find(&self, path: &str, flags: OpenFlags) -> Option<Arc<OSInode>> {
        let inner = self.inner.lock();
        let pathv: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        match inner.inode.find_vfile_bypath(pathv) {
            Some(vfile) => {
                let (readable, writable) = flags.read_write();
                Some(Arc::new(OSInode::new(readable, writable, vfile)))
            }
            None => None,
        }
    }

    pub fn get_dirent(&self) -> Option<Box<Dirent>> {
        const DT_UNKNOWN: u8 = 0;
        const DT_DIR: u8 = 4;
        const DT_REG: u8 = 8;

        let mut inner = self.inner.lock();
        let offset = inner.offset as u32;
        if let Some((name, off, first_clu, attri)) = inner.inode.dirent_info(offset as usize) {
            let mut d_type: u8 = 0;
            if attri & FATDiskInodeType::AttrDirectory != 0 {
                d_type = DT_DIR;
            } else if attri & FATDiskInodeType::AttrArchive != 0 {
                d_type = DT_REG;
            } else {
                DT_UNKNOWN
            };
            let dirent = Box::new(Dirent::new(
                first_clu as usize,
                (off - offset) as isize,
                d_type,
                name.as_str(),
            ));
            inner.offset = off as usize;
            Some(dirent)
        } else {
            None
        }
    }

    pub fn get_ino(&self) -> usize {
        self.stat().get_ino()
    }

    pub fn size(&self) -> usize {
        let inner = self.inner.lock();
        let (size, _, _, _, _) = inner.inode.stat();
        return size as usize;
    }

    pub fn create(&self, path: &str, type_: DiskInodeType) -> Option<Arc<OSInode>> {
        let inner = self.inner.lock();
        let cur_inode = inner.inode.clone();
        if !cur_inode.is_dir() {
            println!("[create] {} is not a directory!", path);
            return None;
        }
        let mut pathv: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        let (readable, writable) = (true, true);

        if cur_inode.find_vfile_bypath(pathv.clone()).is_none() {
            let name = pathv.pop().unwrap();
            if let Some(dir_file) = cur_inode.find_vfile_bypath(pathv.clone()) {
                if !dir_file.is_dir() {
                    return None;
                }
                let attribute = {
                    match type_ {
                        DiskInodeType::Directory => ATTRIBUTE_DIRECTORY,
                        DiskInodeType::File => ATTRIBUTE_ARCHIVE,
                    }
                };
                return Some(Arc::new(OSInode::new(
                    readable,
                    writable,
                    dir_file.create(name, attribute).unwrap(),
                )));
            }
        }
    }

    pub fn clear(&self) {
        let inner = self.inner.lock();
        inner.inode.clear_size();
    }

    pub fn delete(self) {
        let inner = self.inner.lock();
        Inode::delete_from_disk(inner.inode.clone())
    }

    pub fn get_head_cluster(&self) -> u32 {
        let inner = self.inner.lock();
        let vfile = &inner.inode;
        vfile.first_cluster()
    }

    pub fn set_offset(&self, off: usize) {
        let mut inner = self.inner.lock();
        inner.offset = off;
    }

    pub fn lseek(&self, offset: isize, whence: i32) -> isize {
        let mut inner = self.inner.lock();
        let old_offset = inner.offset;
        match whence {
            SeekWhence::SEEK_SET => {
                if offset < 0 {
                    return EINVAL;
                }
                inner.offset = offset as usize;
            }
            SeekWhence::SEEK_CUR => {
                let new_offset = inner.offset as isize + offset;
                if new_offset >= 0 {
                    inner.offset = new_offset as usize;
                } else {
                    return EINVAL;
                }
            }
            SeekWhence::SEEK_END => {
                let new_offset = inner.inode.get_size() as isize + offset;
                if new_offset >= 0 {
                    inner.offset = new_offset as usize;
                } else {
                    return EINVAL;
                }
            }
            // whence is duplicated
            _ => return EINVAL,
        }
        log::info!(
            "[lseek] old offset: {}, new offset: {}, file size: {}",
            old_offset,
            inner.offset,
            inner.inode.get_size()
        );
        inner.offset as isize
    }

    /// todo
    pub fn set_timestamp(&self, times: &[TimeSpec; 2]) {
        log::trace!("[set_timestamp] times: {:?}", times);
        log::warn!("[set_timestamp] not implemented yet!");
    }
}

lazy_static! {
    // 通过ROOT_INODE可以实现对efs的操作
    pub static ref ROOT_INODE: Arc<InodeImpl> = {
        // 此处载入文件系统
        let fat32_manager = EasyFileSystem::open(BLOCK_DEVICE.clone());
        let manager_reader = fat32_manager.read();
        Arc::new(manager_reader.get_root_vfile(& fat32_manager) )
    };
}

pub fn list_apps() {
    println!("/**** APPS ****");
    for app in ROOT_INODE.ls(DirFilter::None) {
        if !app.1.is_dir() {
            println!("{}", app.0);
        }
    }
    println!("**************/");
}

/// If `path` is absolute path, `working_dir` will be ignored.
pub fn open(
    working_dir: &str,
    path: &str,
    flags: OpenFlags,
    type_: DiskInodeType,
) -> Result<Arc<OSInode>, isize> {
    // DEBUG: 相对路径
    const BUSYBOX_PATH: &str = "/busybox";
    const REDIRECT_TO_BUSYBOX: [&str; 3] = ["/touch", "/rm", "/ls"];
    let path = if REDIRECT_TO_BUSYBOX.contains(&path) {
        BUSYBOX_PATH
    } else {
        path
    };
    let cur_inode = {
        if working_dir == "/" || path.starts_with("/") {
            ROOT_INODE.clone()
        } else {
            let components: Vec<&str> = working_dir.split('/').collect();
            ROOT_INODE.find_vfile_bypath(components).unwrap()
        }
    };
    let mut components: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
    let (readable, writable) = flags.read_write();

    if let Some(inode) = cur_inode.find_vfile_bypath(components.clone()) {
        if flags.contains(OpenFlags::O_CREAT | OpenFlags::O_EXCL) {
            return Err(EEXIST);
        }
        if flags.contains(OpenFlags::O_TRUNC) {
            // clear size
            inode.clear();
        }
        let os_inode = Arc::new(OSInode::new(readable, writable, inode));
        if flags.contains(OpenFlags::O_APPEND) {
            os_inode.lseek(0, SeekWhence::SEEK_END);
        }
        Ok(os_inode)
    } else {
        if flags.contains(OpenFlags::O_CREAT) {
            // create file
            let name = components.pop().unwrap();
            if let Some(dir_file) = cur_inode.find_vfile_bypath(components.clone()) {
                if !dir_file.is_dir() {
                    return Err(ENOTDIR);
                }
                let attribute = {
                    match type_ {
                        DiskInodeType::Directory => ATTRIBUTE_DIRECTORY,
                        DiskInodeType::File => ATTRIBUTE_ARCHIVE,
                    }
                };
                return Ok(Arc::new(OSInode::new(
                    readable,
                    writable,
                    dir_file.create(name, attribute).unwrap(),
                )));
            }
        }
        Err(ENOENT)
    }
}

impl File for OSInode {
    fn readable(&self) -> bool {
        self.readable
    }
    fn writable(&self) -> bool {
        self.writable
    }
    fn read(&self, mut buf: UserBuffer) -> usize {
        let mut inner = self.inner.lock();
        let mut total_read_size = 0usize;
        for slice in buf.buffers.iter_mut() {
            // buffer存放的元素是[u8]而不是u8
            let read_size = inner.inode.read_at_block_cache(inner.offset, *slice);
            if read_size == 0 {
                break;
            }
            inner.offset += read_size;
            total_read_size += read_size;
        }
        total_read_size
    }
    fn write(&self, buf: UserBuffer) -> usize {
        //println!("ino_write");
        let mut inner = self.inner.lock();
        let mut total_write_size = 0usize;
        for slice in buf.buffers.iter() {
            let write_size = inner.inode.write_at_block_cache(inner.offset, *slice);
            assert_eq!(write_size, slice.len());
            inner.offset += write_size;
            total_write_size += write_size;
        }
        total_write_size
    }
    /// If offset is not `None`, `kread()` will start reading file from `*offset`,
    /// the `*offset` is adjusted to reflect the number of bytes written to the buffer,
    /// and the file offset won't be modified.
    /// Otherwise `kread()` will start reading file from file offset,
    /// the file offset is adjusted to reflect the number of bytes written to the buffer.
    /// # Warning
    /// Buffer must be in kernel space
    fn kread(&self, offset: Option<&mut usize>, buffer: &mut [u8]) -> usize {
        let mut inner = self.inner.lock();
        match offset {
            Some(offset) => {
                let len = inner.inode.read_at(*offset, buffer);
                *offset += len;
                len
            }
            None => {
                let len = inner.inode.read_at(inner.offset, buffer);
                inner.offset += len;
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
    fn kwrite(&self, offset: Option<&mut usize>, buffer: &[u8]) -> usize {
        let mut inner = self.inner.lock();
        match offset {
            Some(offset) => {
                let len = inner.inode.write_at(*offset, buffer);
                *offset += len;
                len
            }
            None => {
                let len = inner.inode.write_at(inner.offset, buffer);
                inner.offset += len;
                len
            }
        }
    }
    fn stat(&self) -> Box<Stat> {
        let inner = self.inner.lock();
        let vfile = inner.inode.clone();
        let (size, atime, mtime, ctime, ino) = vfile.stat();
        let st_mod: u32 = {
            if vfile.is_dir() {
                (StatMode::S_IFDIR | StatMode::S_IRWXU | StatMode::S_IRWXG | StatMode::S_IRWXO)
                    .bits()
            } else {
                (StatMode::S_IFREG | StatMode::S_IRWXU | StatMode::S_IRWXG | StatMode::S_IRWXO)
                    .bits()
            }
        };
        Box::new(Stat::new(0, ino, st_mod, 1, 0, size, atime, mtime, ctime))
    }
}
