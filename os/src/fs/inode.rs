use super::cache_mgr::DataCacheMgrWrapper;
use super::{Dirent, File, OpenFlags, Stat, StatMode};
use crate::fs::cache_mgr::InfoCacheMgrWrapper;
use crate::mm::UserBuffer;
use crate::syscall::errno::*;
use crate::syscall::fs::SeekWhence;
use crate::timer::TimeSpec;
use crate::{drivers::BLOCK_DEVICE, println};

use _core::usize;
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use bitflags::*;
//use easy_fs::block_cache::BlockCacheManagerWrapper;
use easy_fs::layout::FATDiskInodeType;
pub use easy_fs::DiskInodeType;
use easy_fs::{CacheManager, DirFilter, EasyFileSystem, Inode};
use lazy_static::*;
use spin::Mutex;

type InodeImpl =
    Inode<crate::fs::cache_mgr::DataCacheMgrWrapper, crate::fs::cache_mgr::InfoCacheMgrWrapper>;

// 此inode实际被当作文件
pub struct OSInode {
    readable: bool,
    writable: bool,
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

    // /* this func will not influence the file offset
    //  * @parm: if offset == -1, file offset will be used
    //  */
    // pub fn read_vec(&self, offset: isize, len: usize) -> Vec<u8> {
    //     let mut inner = self.inner.lock();
    //     let mut file_content_lock = inner.inode.file_content.lock();
    //     let mut len = len;
    //     let ori_off = inner.offset;
    //     if offset >= 0 {
    //         inner.offset = offset as usize;
    //     }
    //     let mut buffer = [0u8; 512];
    //     let mut v: Vec<u8> = Vec::new();
    //     loop {
    //         let rlen =
    //             inner
    //                 .inode
    //                 .read_at_block_cache(&mut file_content_lock, inner.offset, &mut buffer);
    //         if rlen == 0 {
    //             break;
    //         }
    //         inner.offset += rlen;
    //         v.extend_from_slice(&buffer[..rlen.min(len)]);
    //         if len > rlen {
    //             len -= rlen;
    //         } else {
    //             break;
    //         }
    //     }
    //     if offset >= 0 {
    //         inner.offset = ori_off;
    //     }
    //     v
    // }

    // pub fn read_all(&self) -> Vec<u8> {
    //     let mut inner = self.inner.lock();
    //     let mut file_content_lock = inner.inode.file_content.lock();
    //     let mut buffer = [0u8; 512];
    //     let mut v: Vec<u8> = Vec::new();
    //     loop {
    //         let len =
    //             inner
    //                 .inode
    //                 .read_at_block_cache(&mut file_content_lock, inner.offset, &mut buffer);
    //         if len == 0 {
    //             break;
    //         }
    //         inner.offset += len;
    //         v.extend_from_slice(&buffer[..len]);
    //     }
    //     v
    // }

    // pub fn write_all(&self, str_vec: &Vec<u8>) -> usize {
    //     let mut inner = self.inner.lock();
    //     let mut file_content_lock = inner.inode.file_content.lock();
    //     let mut remain = str_vec.len();
    //     let mut base = 0;
    //     loop {
    //         let len = remain.min(512);
    //         inner.inode.write_at_block_cache(
    //             &mut file_content_lock,
    //             inner.offset,
    //             &str_vec.as_slice()[base..base + len],
    //         );
    //         inner.offset += len;
    //         base += len;
    //         remain -= len;
    //         if remain == 0 {
    //             break;
    //         }
    //     }
    //     return base;
    // }
    pub fn open_by_relative_path(
        &self,
        path: &str,
        flags: OpenFlags,
        type_: DiskInodeType,
    ) -> Result<Arc<OSInode>, isize> {
        let inner = self.inner.lock();
        let mut components: VecDeque<&str> = path.split('/').fold(VecDeque::new(), |mut v, s| {
            if !s.is_empty() {
                match s {
                    "." => {}
                    ".." => {
                        v.pop_back();
                    }
                    s => {
                        v.push_back(s);
                    }
                };
            }
            v
        });
        let (readable, writable) = flags.read_write();

        let mut current_inode = inner.inode.clone();
        while let Some(component) = components.pop_front() {
            if !current_inode.is_dir() {
                return Err(ENOTDIR);
            }
            if let Some((_, short_ent, offset)) =
                current_inode.find_local(component.to_string()).unwrap()
            {
                current_inode = Inode::from_ent(&current_inode, &short_ent, offset)
            } else {
                if components.is_empty() && flags.contains(OpenFlags::O_CREAT) {
                    return Ok(Arc::new(OSInode::new(readable, writable, {
                        log::error!("create: {}", component);
                        let arc = Inode::<DataCacheMgrWrapper, InfoCacheMgrWrapper>::create(
                            &current_inode,
                            component.to_string(),
                            type_,
                        )
                        .unwrap();
                        log::debug!(
                            "[create] result: {:?}",
                            current_inode.find_local(component.to_string())
                        );
                        arc
                    })));
                } else {
                    return Err(ENOENT);
                }
            }
        }

        if flags.contains(OpenFlags::O_CREAT | OpenFlags::O_EXCL) {
            return Err(EEXIST);
        }
        if flags.contains(OpenFlags::O_TRUNC) {
            let mut file_content = current_inode.file_content.lock();
            let diff = -(file_content.size as isize);
            current_inode.modify_size(&mut file_content, diff);
        }
        let os_inode = Arc::from(OSInode::new(readable, writable, current_inode));
        if flags.contains(OpenFlags::O_APPEND) {
            os_inode.lseek(0, SeekWhence::SEEK_END);
        }
        Ok(os_inode)
    }

    pub fn get_dirent(&self, count: usize) -> Vec<Dirent> {
        const DT_UNKNOWN: u8 = 0;
        const DT_DIR: u8 = 4;
        const DT_REG: u8 = 8;

        let mut inner = self.inner.lock();
        assert!(inner.inode.is_dir());
        let offset = inner.offset as u32;
        log::debug!(
            "[get_dirent] tot size: {}, offset: {}, count: {}",
            inner.inode.get_file_size(),
            offset,
            count
        );

        let vec = inner
            .inode
            .dirent_info(offset, count / core::mem::size_of::<Dirent>())
            .unwrap();
        if let Some((_, offset, _, _)) = vec.last() {
            inner.offset = *offset;
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
    // let d_type: u8 = if [
    //     FATDiskInodeType::AttrDirectory,
    //     FATDiskInodeType::AttrVolumeID,
    // ]
    // .contains(&attri)
    // {
    //     DT_DIR
    // } else if attri == (FATDiskInodeType::AttrArchive) {
    //     DT_REG
    // } else {
    //     DT_UNKNOWN
    // };

    // let dirent = Box::new(Dirent::new(
    //     first_clu as usize,
    //     off as isize,
    //     d_type,
    //     name.as_str(),
    // ));
    // /* if off == inner.offset {
    //  *     return None;
    //  * } */
    // } else {
    //     None
    // }

    pub fn get_ino(&self) -> usize {
        self.stat().get_ino()
    }

    pub fn size(&self) -> usize {
        let inner = self.inner.lock();
        let (size, _, _, _, _) = inner.inode.stat();
        return size as usize;
    }

    pub fn clear(&self) {
        let inner = self.inner.lock();
        let mut file_content_lock = inner.inode.file_content.lock();
        let sz = inner.inode.get_file_size();
        inner
            .inode
            .modify_size(&mut file_content_lock, -(sz as i64) as isize);
    }

    pub fn delete(&self) {
        let inner = self.inner.lock();
        Inode::delete_from_disk(inner.inode.clone());
    }

    pub fn get_head_cluster(&self) -> u32 {
        let inner = self.inner.lock();
        inner.inode.get_file_clus()
    }

    pub fn set_offset(&self, off: usize) {
        let mut inner = self.inner.lock();
        inner.offset = off;
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
                let new_offset = inner.inode.get_file_size() as isize + offset;
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
            inner.inode.get_file_size()
        );
        inner.offset as isize
    }

    pub fn set_timestamp(&self, ctime: Option<usize>, atime: Option<usize>, mtime: Option<usize>) {
        log::trace!("[set_timestamp] ctime: {:?}, atime: {:?}, mtime: {:?}", ctime, atime, mtime);
        let inner = self.inner.lock();
        let mut inode_time = inner.inode.time.lock();
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
}

lazy_static! {
    // 通过ROOT_INODE可以实现对efs的操作

        // 此处载入文件系统
    pub static ref FILE_SYSTEM: Arc<EasyFileSystem<crate::fs::cache_mgr::DataCacheMgrWrapper, crate::fs::cache_mgr::InfoCacheMgrWrapper>> =
        EasyFileSystem::open(
        BLOCK_DEVICE.clone(),
            Arc::new(Mutex::new(InfoCacheMgrWrapper::new()))
        );
    pub static ref ROOT_INODE: Arc<InodeImpl> = Inode::new(
        FILE_SYSTEM.root_clus,
        DiskInodeType::Directory,
        None,
        None,
        FILE_SYSTEM.clone(),
    );
}

pub fn open_root_inode() -> Arc<OSInode> {
    Arc::new(OSInode::new(true,true,ROOT_INODE.clone()))
}

pub fn list_apps() {
    println!("/**** APPS ****");
    for (name, short_ent) in ROOT_INODE.ls().unwrap() {
        if !short_ent.is_dir() {
            println!("{}", name);
        }
    }
    println!("**************/");
}
pub fn open(
    working_inode: &Arc<OSInode>,
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
    if path.starts_with("/") {
        open_root_inode().open_by_relative_path(path, flags, type_)
    } else {
        working_inode.open_by_relative_path(path, flags, type_)
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

        let mut offset = inner.offset;
        let mut file_cont_lock = inner.inode.file_content.lock();
        for slice in buf.buffers.iter_mut() {
            let read_size = inner
                .inode
                .read_at_block_cache(&mut file_cont_lock, offset, *slice);
            if read_size == 0 {
                break;
            }
            offset += read_size;
            total_read_size += read_size;
        }
        drop(file_cont_lock);
        inner.offset = offset;
        total_read_size
    }
    fn write(&self, buf: UserBuffer) -> usize {
        let mut inner = self.inner.lock();
        let mut total_write_size = 0usize;

        let mut offset = inner.offset;
        let mut file_cont_lock = inner.inode.file_content.lock();
        for slice in buf.buffers.iter() {
            let write_size = inner
                .inode
                .write_at_block_cache(&mut file_cont_lock, offset, *slice);
            assert_eq!(write_size, slice.len());
            offset += write_size;
            total_write_size += write_size;
        }
        drop(file_cont_lock);
        inner.offset = offset;
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
        let mut file_cont_lock = inner.inode.file_content.lock();
        match offset {
            Some(offset) => {
                let len = inner
                    .inode
                    .read_at_block_cache(&mut file_cont_lock, *offset, buffer);
                *offset += len;
                len
            }
            None => {
                let len =
                    inner
                        .inode
                        .read_at_block_cache(&mut file_cont_lock, inner.offset, buffer);
                drop(file_cont_lock);
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
        let mut file_cont_lock = inner.inode.file_content.lock();
        match offset {
            Some(offset) => {
                let len = inner
                    .inode
                    .write_at_block_cache(&mut file_cont_lock, *offset, buffer);
                *offset += len;
                len
            }
            None => {
                let len =
                    inner
                        .inode
                        .write_at_block_cache(&mut file_cont_lock, inner.offset, buffer);
                drop(file_cont_lock);
                inner.offset += len;
                len
            }
        }
    }
    fn stat(&self) -> Box<Stat> {
        let inner = self.inner.lock();
        let (size, atime, mtime, ctime, ino) = inner.inode.stat();
        let st_mod: u32 = {
            if inner.inode.is_dir() {
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
