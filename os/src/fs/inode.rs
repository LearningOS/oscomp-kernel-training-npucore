use super::{finfo, Dirent, File, Kstat, NewStat, DT_DIR, DT_REG, DT_UNKNOWN};
use crate::color_text;
use crate::mm::UserBuffer;
use crate::syscall::errno::*;
use crate::syscall::fs::SeekWhence;
use crate::{drivers::BLOCK_DEVICE, println};
use _core::usize;
use alloc::sync::Arc;
use alloc::vec::Vec;
use bitflags::*;
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
        let mut pathv: Vec<&str> = path.split('/').collect();
        let vfile = inner.inode.find_vfile_bypath(pathv);
        if vfile.is_none() {
            return None;
        } else {
            let (readable, writable) = flags.read_write();
            return Some(Arc::new(OSInode::new(readable, writable, vfile.unwrap())));
        }
    }

    pub fn getdirent(&self, dirent: &mut Dirent /*, offset:isize*/) -> isize {
        let mut inner = self.inner.lock();
        let offset = inner.offset as u32;
        if let Some((name, off, first_clu, attri)) = inner.inode.dirent_info(offset as usize) {
            let mut d_type: u8 = 0;
            if attri & ATTRIBUTE_DIRECTORY != 0 {
                d_type = DT_DIR;
            } else if attri & ATTRIBUTE_ARCHIVE != 0 {
                d_type = DT_REG;
            } else {
                d_type = DT_UNKNOWN;
            }
            //println!("name = {}", name.as_str());
            dirent.fill_info(
                name.as_str(),
                first_clu as usize,
                (off - offset) as isize,
                name.len() as u16,
                d_type,
            );
            inner.offset = off as usize;
            let len = (name.len() + 8 * 4) as isize;
            len
        } else {
            -1
        }
    }
    pub fn get_ino(&self) -> usize {
        let mut i = Kstat::new_abstract();
        self.get_fstat(&mut i);
        i.get_ino()
    }
    pub fn get_fstat(&self, kstat: &mut Kstat) {
        let inner = self.inner.lock();
        let vfile = inner.inode.clone();
        let (size, atime, mtime, ctime, ino) = vfile.stat();
        let st_mod: u32 = {
            if vfile.is_dir() {
                //println!("is dir");
                finfo::S_IFDIR | finfo::S_IRWXU | finfo::S_IRWXG | finfo::S_IRWXO
            } else {
                finfo::S_IFREG | finfo::S_IRWXU | finfo::S_IRWXG | finfo::S_IRWXO
            }
        };
        kstat.fill_info(0, ino, st_mod, 1, size, atime, mtime, ctime);
    }

    pub fn get_newstat(&self, stat: &mut NewStat) {
        let inner = self.inner.lock();
        let vfile = inner.inode.clone();
        let (size, atime, mtime, ctime, ino) = vfile.stat();
        let st_mod: u32 = {
            if vfile.is_dir() {
                finfo::S_IFDIR | finfo::S_IRWXU | finfo::S_IRWXG | finfo::S_IRWXO
            } else {
                finfo::S_IFREG | finfo::S_IRWXU | finfo::S_IRWXG | finfo::S_IRWXO
            }
        };
        stat.fill_info(0, ino, st_mod, 1, size, atime, mtime, ctime);
    }

    pub fn get_size(&self) -> usize {
        let inner = self.inner.lock();
        let (size, _, mt_me, _, _) = inner.inode.stat();
        return size as usize;
    }

    pub fn create(&self, path: &str, type_: DiskInodeType) -> Option<Arc<OSInode>> {
        let inner = self.inner.lock();
        let cur_inode = inner.inode.clone();
        if !cur_inode.is_dir() {
            println!("[create]:{} is not a directory!", path);
            return None;
        }
        let mut pathv: Vec<&str> = path.split('/').collect();
        let (readable, writable) = (true, true);
        if let Some(inode) = cur_inode.find_vfile_bypath(pathv.clone()) {
            // already exists, clear
            inode.remove();
        }
        {
            // create file
            let name = pathv.pop().unwrap();
            if let Some(temp_inode) = cur_inode.find_vfile_bypath(pathv.clone()) {
                let attribute = {
                    match type_ {
                        DiskInodeType::Directory => ATTRIBUTE_DIRECTORY,
                        DiskInodeType::File => ATTRIBUTE_ARCHIVE,
                    }
                };
                temp_inode
                    .create(name, attribute)
                    .map(|inode| Arc::new(OSInode::new(readable, writable, inode)))
            } else {
                None
            }
        }
    }

    pub fn clear(&self) {
        let inner = self.inner.lock();
        inner.inode.clear();
    }

    pub fn delete(&self) -> usize {
        let inner = self.inner.lock();
        inner.inode.remove()
    }

    pub fn set_head_cluster(&self, cluster: u32) {
        let inner = self.inner.lock();
        let vfile = &inner.inode;
        vfile.set_first_cluster(cluster);
    }

    pub fn get_head_cluster(&self) -> u32 {
        let inner = self.inner.lock();
        let vfile = &inner.inode;
        vfile.first_cluster()
    }

    pub fn set_delete_bit(&self) {
        let inner = self.inner.lock();
        inner.inode.set_delete_bit();
    }

    // pub fn set_offset(&self, off: usize) {
    //     let mut inner = self.inner.lock();
    //     inner.offset = off;
    // }

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
/*
lazy_static! {
    // 目录栈
    pub static ref DIR_STACK: Vec<Arc<Inode>> = vec![ROOT_INODE.clone()];
}
*/

pub fn init_rootfs() {
    println!("[fs] build rootfs ... start");
    println!("[fs] build rootfs: creating /proc");
    let file = open("/", "proc", OpenFlags::CREATE, DiskInodeType::Directory).unwrap();
    println!("[fs] build rootfs: init /proc");
    let file = open("/proc", "mounts", OpenFlags::CREATE, DiskInodeType::File).unwrap();
    let meminfo = open("/proc", "meminfo", OpenFlags::CREATE, DiskInodeType::File).unwrap();
    let file = open("/", "ls", OpenFlags::CREATE, DiskInodeType::File).unwrap();
    println!("[fs] build rootfs ... finish");
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

// TODO: 对所有的Inode加锁！
// 在这一层实现互斥访问
pub fn list_files(work_path: &str, path: &str) {
    let work_inode = {
        if work_path == "/" || (path.len() > 0 && path.chars().nth(0).unwrap() == '/') {
            //println!("curr is root");
            ROOT_INODE.clone()
        } else {
            let wpath: Vec<&str> = work_path.split('/').collect();
            ROOT_INODE.find_vfile_bypath(wpath).unwrap()
        }
    };
    let mut pathv: Vec<&str> = path.split('/').collect();
    let cur_inode = work_inode.find_vfile_bypath(pathv).unwrap();

    let mut file_vec = cur_inode.ls_lite().unwrap();
    file_vec.sort();
    for i in 0..file_vec.len() {
        if file_vec[i].1 & ATTRIBUTE_DIRECTORY != 0 {
            println!("{}  ", color_text!(file_vec[i].0, 96));
        } else {
            // TODO: 统一配色！
            println!("{}  ", file_vec[i].0);
        }
    }
}

bitflags! {
    pub struct OpenFlags: u32 {
        const RDONLY = 0;
        const WRONLY = 1 << 0;
        const RDWR = 1 << 1;
        const CREATE = 1 << 6;
        const TRUNC = 1 << 10;
        const DIRECTROY = 0200000;
        const LARGEFILE  = 0100000;
        const CLOEXEC = 02000000;
    }
}

impl OpenFlags {
    /// Do not check validity for simplicity
    /// Return (readable, writable)
    pub fn read_write(&self) -> (bool, bool) {
        if self.is_empty() {
            (true, false)
        } else if self.contains(Self::WRONLY) {
            (false, true)
        } else {
            (true, true)
        }
    }
}

pub fn open(
    work_path: &str,
    path: &str,
    flags: OpenFlags,
    type_: DiskInodeType,
) -> Option<Arc<OSInode>> {
    // DEBUG: 相对路径
    let cur_inode = {
        if work_path == "/" {
            ROOT_INODE.clone()
        } else {
            let wpath: Vec<&str> = work_path.split('/').collect();
            ROOT_INODE.find_vfile_bypath(wpath).unwrap()
        }
    };
    let mut pathv: Vec<&str> = path.split('/').collect();
    //println!("[open] pathv = {:?}", pathv);
    // print!("\n");
    // shell应当保证此处输入的path不为空
    let (readable, writable) = flags.read_write();
    if flags.contains(OpenFlags::CREATE) {
        if let Some(inode) = cur_inode.find_vfile_bypath(pathv.clone()) {
            // clear size
            inode.remove();
        }
        {
            // create file
            let name = pathv.pop().unwrap();
            if let Some(temp_inode) = cur_inode.find_vfile_bypath(pathv.clone()) {
                let attribute = {
                    match type_ {
                        DiskInodeType::Directory => ATTRIBUTE_DIRECTORY,
                        DiskInodeType::File => ATTRIBUTE_ARCHIVE,
                    }
                };
                temp_inode
                    .create(name, attribute)
                    .map(|inode| Arc::new(OSInode::new(readable, writable, inode)))
            } else {
                None
            }
        }
    } else {
        cur_inode.find_vfile_bypath(pathv).map(|inode| {
            if flags.contains(OpenFlags::TRUNC) {
                inode.clear();
            }
            Arc::new(OSInode::new(readable, writable, inode))
        })
    }
}

pub fn ch_dir(work_path: &str, path: &str) -> isize {
    // 切换工作路径
    // 切换成功，返回inode_id，否则返回-1
    let cur_inode = {
        if work_path == "/" || (path.len() > 0 && path.chars().nth(0).unwrap() == '/') {
            ROOT_INODE.clone()
        } else {
            let wpath: Vec<&str> = work_path.split('/').collect();
            //println!("in cd, work_pathv = {:?}", wpath);
            ROOT_INODE.find_vfile_bypath(wpath).unwrap()
        }
    };
    let pathv: Vec<&str> = path.split('/').collect();
    if let Some(tar_dir) = cur_inode.find_vfile_bypath(pathv) {
        // ! 当inode_id > 2^16 时，有溢出的可能（目前不会发生。。
        0
    } else {
        -1
    }
}

pub fn clear_cache() {
    ROOT_INODE.clear_cache();
}

// TODO: 不急
// 复制文件/目录
//pub fn fcopy(src_inode_id: u32, src_path: &str, dst_inode_id: u32, dst_path: &str )->bool{
//    let spathv:Vec<&str> = src_path.split('/').collect();
//    let dpathv:Vec<&str> = dst_path.split('/').collect();
//    let src_ino = EasyFileSystem::get_inode(&ROOT_INODE.get_fs(), src_inode_id);
//    src_ino.fcopy(spathv, dst_inode_id,dpathv)
//}

// 移动文件/目录
//pub fn fmove(src_inode_id: u32, src_path: &str, dst_inode_id: u32, dst_path: &str )->bool{
//    let spathv:Vec<&str> = src_path.split('/').collect();
//    let dpathv:Vec<&str> = dst_path.split('/').collect();
//    let src_ino = EasyFileSystem::get_inode(&ROOT_INODE.get_fs(), src_inode_id);
//    src_ino.fmove(spathv, dst_inode_id,dpathv)
//}

// pub fn remove(inode_id: u32, path: &str, type_: DiskInodeType)->bool{
//     // type_确认要删除的文件类型，如果是目录，递归删除
//     let curr_inode = EasyFileSystem::get_inode(
//         &ROOT_INODE.get_fs().clone(),
//         inode_id
//     );
//     let pathv:Vec<&str> = path.split('/').collect();
//     curr_inode.remove(pathv,type_)
// }

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
}
