use super::cache_mgr::*;
use super::{Dirent, File, OpenFlags, Stat, StatMode};
use crate::mm::{FrameTracker, UserBuffer};
use crate::syscall::errno::*;
use crate::syscall::fs::SeekWhence;
use crate::{drivers::BLOCK_DEVICE, println};
use core::panic;

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use easy_fs::layout::FATDiskInodeType;
pub use easy_fs::DiskInodeType;
use easy_fs::{CacheManager, EasyFileSystem, Inode};
use lazy_static::*;
use spin::{Mutex, RwLock};

type InodeImpl = Inode<PageCacheManager, BlockCacheManager>;

pub struct OSInode {
    readable: bool,
    writable: bool,
    inner: Arc<DirectoryTreeNode>,
    offset: Mutex<usize>,
}

impl OSInode {
    pub fn new(readable: bool, writable: bool, node: Arc<DirectoryTreeNode>) -> Self {
        Self {
            readable,
            writable,
            inner: node,
            offset: Mutex::new(0),
        }
    }

    pub fn is_dir(&self) -> bool {
        self.inner.inode.is_dir()
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

        let mut current_treenode = self.inner.clone();
        while let Some(component) = components.pop_front() {
            if !current_treenode.inode.is_dir() {
                return Err(ENOTDIR);
            }
            let result = current_treenode.children.read().get(component).cloned();
            current_treenode = if let Some(treenode) = result {
                log::trace!("[open_by_relative_path] found in directory tree");
                treenode
            } else {
                let find_result = current_treenode
                    .inode
                    .find_local_lock(&mut current_treenode.inode.lock(), component.to_string())
                    .unwrap();
                if let Some((_, short_ent, offset)) = find_result {
                    let new_treenode = Arc::new(DirectoryTreeNode::new(Inode::from_ent(
                        &current_treenode.inode,
                        &short_ent,
                        offset,
                    )));
                    current_treenode
                        .children
                        .write()
                        .insert(component.to_string(), new_treenode.clone());
                    new_treenode
                } else {
                    if components.is_empty() && flags.contains(OpenFlags::O_CREAT) {
                        return Ok(Arc::new(OSInode::new(readable, writable, {
                            log::trace!("[open_by_relative_path] create: {}", component);
                            let new_treenode = Arc::new(DirectoryTreeNode::new(
                                InodeImpl::create_lock(
                                    &current_treenode.inode,
                                    &mut current_treenode.inode.lock(),
                                    component.to_string(),
                                    type_,
                                )
                                .unwrap(),
                            ));
                            current_treenode
                                .children
                                .write()
                                .insert(component.to_string(), new_treenode.clone());
                            log::debug!(
                                "[create] result: {:?}",
                                current_treenode.inode.find_local_lock(
                                    &mut current_treenode.inode.lock(),
                                    component.to_string()
                                )
                            );
                            new_treenode
                        })));
                    } else {
                        return Err(ENOENT);
                    }
                }
            };
        }

        if flags.contains(OpenFlags::O_CREAT | OpenFlags::O_EXCL) {
            return Err(EEXIST);
        }
        if flags.contains(OpenFlags::O_TRUNC) {
            let mut file_content = current_treenode.inode.lock();
            let diff = -(file_content.get_file_size() as isize);
            current_treenode
                .inode
                .modify_size_lock(&mut file_content, diff);
        }
        let os_inode = Arc::from(OSInode::new(readable, writable, current_treenode));
        if flags.contains(OpenFlags::O_APPEND) {
            os_inode.lseek(0, SeekWhence::SEEK_END);
        }
        Ok(os_inode)
    }

    pub fn get_dirent(&self, count: usize) -> Vec<Dirent> {
        const DT_UNKNOWN: u8 = 0;
        const DT_DIR: u8 = 4;
        const DT_REG: u8 = 8;

        assert!(self.inner.inode.is_dir());
        let mut offset = self.offset.lock();
        let mut file_cont_lock = self.inner.inode.lock();
        log::debug!(
            "[get_dirent] tot size: {}, offset: {}, count: {}",
            file_cont_lock.get_file_size(),
            offset,
            count
        );

        let vec = self
            .inner
            .inode
            .dirent_info_lock(
                &mut file_cont_lock,
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
    pub fn get_all_cache_frame(&self) -> Vec<Option<Arc<FrameTracker>>> {
        self.inner
            .inode
            .get_all_cache()
            .iter()
            .map(|cache| {
                assert!(!cache.is_locked());
                Some(cache.lock().get_tracker())
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
        let (size, _, _, _, _) = self.inner.inode.stat_lock(&self.inner.inode.lock());
        return size as usize;
    }

    pub fn clear(&self) {
        let mut file_cont_lock = self.inner.inode.lock();
        let sz = file_cont_lock.get_file_size();
        self.inner
            .inode
            .modify_size_lock(&mut file_cont_lock, -(sz as i64) as isize);
    }

    pub fn delete(&self) {
        Inode::delete_from_disk(self.inner.inode.clone()).unwrap();
    }

    pub fn get_offset(&self) -> usize {
        *self.offset.lock()
    }

    pub fn set_offset(&self, off: usize) {
        *self.offset.lock() = off;
    }

    pub fn lseek(&self, offset: isize, whence: SeekWhence) -> isize {
        let old_offset = *self.offset.lock();
        let new_offset = match whence {
            SeekWhence::SEEK_SET => {
                if offset < 0 {
                    return EINVAL;
                }
                offset
            }
            SeekWhence::SEEK_CUR => {
                let new_offset = old_offset as isize + offset;
                if new_offset >= 0 {
                    new_offset
                } else {
                    return EINVAL;
                }
            }
            SeekWhence::SEEK_END => {
                let new_offset = self.inner.inode.lock().get_file_size() as isize + offset;
                if new_offset >= 0 {
                    new_offset
                } else {
                    return EINVAL;
                }
            }
            // whence is duplicated
            _ => return EINVAL,
        };

        log::info!(
            "[lseek] old offset: {}, new offset: {}, file size: {}",
            old_offset,
            new_offset,
            self.inner.inode.lock().get_file_size()
        );

        *self.offset.lock() = new_offset as usize;
        new_offset as isize
    }

    pub fn set_timestamp(&self, ctime: Option<usize>, atime: Option<usize>, mtime: Option<usize>) {
        log::trace!(
            "[set_timestamp] ctime: {:?}, atime: {:?}, mtime: {:?}",
            ctime,
            atime,
            mtime
        );
        let mut inode_time = self.inner.inode.time();
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
    pub static ref FILE_SYSTEM: Arc<EasyFileSystem<BlockCacheManager>> = EasyFileSystem::open(
        BLOCK_DEVICE.clone(),
        Arc::new(Mutex::new(BlockCacheManager::new()))
    );
    pub static ref ROOT: Arc<DirectoryTreeNode> = Arc::new(DirectoryTreeNode::new(Inode::new(
        FILE_SYSTEM.root_clus,
        DiskInodeType::Directory,
        None,
        None,
        FILE_SYSTEM.clone(),
    )));
}

pub struct DirectoryTreeNode {
    pub inode: Arc<InodeImpl>,
    pub children: RwLock<BTreeMap<String, Arc<DirectoryTreeNode>>>,
}

impl DirectoryTreeNode {
    pub fn new(inode: Arc<InodeImpl>) -> Self {
        Self {
            inode,
            children: RwLock::new(BTreeMap::new()),
        }
    }
}

pub fn open_root_inode() -> Arc<OSInode> {
    Arc::new(OSInode::new(true, true, ROOT.clone()))
}

pub fn list_apps() {
    println!("/**** APPS ****");
    for (name, short_ent) in ROOT.inode.ls_lock(&mut ROOT.inode.lock()).unwrap() {
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
    const BUSYBOX_PATH: &str = "/busybox";
    const REDIRECT_TO_BUSYBOX: [&str; 3] = ["/touch", "/rm", "/ls"];
    let path = if REDIRECT_TO_BUSYBOX.contains(&path) {
        BUSYBOX_PATH
    } else {
        path
    };
    const LIBC_PATH: &str = "/lib/libc.so";
    const REDIRECT_TO_LIBC: [&str; 2] =
        ["/lib/ld-musl-riscv64.so.1", "/lib/ld-musl-riscv64-sf.so.1"];
    let path = if REDIRECT_TO_LIBC.contains(&path) {
        LIBC_PATH
    } else {
        path
    };
    if path.starts_with("/") {
        open_root_inode().open_by_relative_path(path, flags, type_)
    } else {
        working_inode.open_by_relative_path(path, flags, type_)
    }
}

pub fn oom() {
    const MAX_FAIL_TIME: usize = 6;
    let mut fail_time = 0;
    fn dfs(u: &Arc<DirectoryTreeNode>) -> usize {
        let mut dropped = u.inode.oom();
        let read_lock = u.children.try_read();
        if read_lock.is_none() {
            return dropped;
        }
        let read_lock = read_lock.unwrap();
        for (_, v) in read_lock.iter() {
            dropped += dfs(v);
        }
        dropped
    }
    log::warn!("[oom] start oom");
    loop {
        let dropped = dfs(&ROOT);
        if dropped > 0 {
            log::warn!("[oom] recycle pages: {}", dropped);
            break;
        }
        fail_time += 1;
        if fail_time >= MAX_FAIL_TIME {
            panic!("oom error");
        }
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
        let mut total_read_size = 0usize;

        let mut offset = self.offset.lock();
        let mut file_cont_lock = self.inner.inode.lock();
        for slice in buf.buffers.iter_mut() {
            let read_size =
                self.inner
                    .inode
                    .read_at_block_cache_lock(&mut file_cont_lock, *offset, *slice);
            if read_size == 0 {
                break;
            }
            *offset += read_size;
            total_read_size += read_size;
        }
        total_read_size
    }
    fn write(&self, buf: UserBuffer) -> usize {
        let mut total_write_size = 0usize;

        let mut offset = self.offset.lock();
        let mut file_cont_lock = self.inner.inode.lock();
        for slice in buf.buffers.iter() {
            let write_size =
                self.inner
                    .inode
                    .write_at_block_cache_lock(&mut file_cont_lock, *offset, *slice);
            assert_eq!(write_size, slice.len());
            *offset += write_size;
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
        let mut file_cont_lock = self.inner.inode.lock();
        match offset {
            Some(offset) => {
                let len =
                    self.inner
                        .inode
                        .read_at_block_cache_lock(&mut file_cont_lock, *offset, buffer);
                drop(file_cont_lock);
                *offset += len;
                len
            }
            None => {
                let mut offset = self.offset.lock();
                let len =
                    self.inner
                        .inode
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
    fn kwrite(&self, offset: Option<&mut usize>, buffer: &[u8]) -> usize {
        let mut file_cont_lock = self.inner.inode.lock();
        match offset {
            Some(offset) => {
                let len = self.inner.inode.write_at_block_cache_lock(
                    &mut file_cont_lock,
                    *offset,
                    buffer,
                );
                drop(file_cont_lock);
                *offset += len;
                len
            }
            None => {
                let mut offset = self.offset.lock();
                let len = self.inner.inode.write_at_block_cache_lock(
                    &mut file_cont_lock,
                    *offset,
                    buffer,
                );
                drop(file_cont_lock);
                *offset += len;
                len
            }
        }
    }
    fn stat(&self) -> Box<Stat> {
        let (size, atime, mtime, ctime, ino) =
            self.inner.inode.stat_lock(&mut self.inner.inode.lock());
        let st_mod: u32 = {
            if self.inner.inode.is_dir() {
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
