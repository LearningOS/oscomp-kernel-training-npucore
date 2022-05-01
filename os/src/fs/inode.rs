use super::{Dirent, File, OpenFlags, Stat, StatMode};
use crate::mm::UserBuffer;
use crate::syscall::errno::*;
use crate::syscall::fs::SeekWhence;
use crate::timer::TimeSpec;
use crate::{drivers::BLOCK_DEVICE, println};

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use lazy_static::*;
use simple_fat32::{FAT32Manager, VFile, ATTRIBUTE_ARCHIVE, ATTRIBUTE_DIRECTORY};
use spin::Mutex;

#[derive(PartialEq, Copy, Clone, Debug)]
pub enum DiskInodeType {
    File,
    Directory,
}

// 此inode实际被当作文件
pub struct OSInode {
    readable: bool,
    writable: bool,
    //fd_cloexec: bool,
    inner: Mutex<OSInodeInner>,
}

pub struct OSInodeInner {
    offset: usize,     // 当前读写的位置
    inode: Arc<VFile>, // inode引用
}

impl OSInode {
    pub fn new(readable: bool, writable: bool, inode: Arc<VFile>) -> Self {
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
            let d_type: u8 = if attri & ATTRIBUTE_DIRECTORY != 0 {
                DT_DIR
            } else if attri & ATTRIBUTE_ARCHIVE != 0 {
                DT_REG
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
        None
    }

    pub fn delete(&self) -> usize {
        let inner = self.inner.lock();
        inner.inode.remove()
    }

    pub fn lseek(&self, offset: isize, whence: SeekWhence) -> isize {
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
    pub static ref ROOT_INODE: Arc<VFile> = {
        // 此处载入文件系统
        let fat32_manager = FAT32Manager::open(BLOCK_DEVICE.clone());
        let manager_reader = fat32_manager.read();
        Arc::new( manager_reader.get_root_vfile(& fat32_manager) )
    };
}

pub fn list_apps() {
    println!("/**** APPS ****");
    for app in ROOT_INODE.ls_lite().unwrap() {
        if app.1 & ATTRIBUTE_DIRECTORY == 0 {
            println!("{}", app.0);
        }
    }
    println!("**************/")
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
            let read_size = inner.inode.read_at(inner.offset, *slice);
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
            let write_size = inner.inode.write_at(inner.offset, *slice);
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
