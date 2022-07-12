use alloc::{sync::{Arc, Weak}, collections::{BTreeMap}, string::{String, ToString}, vec::Vec};
use easy_fs::{EasyFileSystem, DiskInodeType, CacheManager};
use spin::{RwLock, Mutex, RwLockWriteGuard};
use lazy_static::*;

use crate::{fs::{fs::{cache_mgr::BlockCacheManager, inode::{InodeImpl, OSInode}}, filesystem::FS}, drivers::BLOCK_DEVICE};
use crate::syscall::errno::*;
use super::{layout::{OpenFlags, Dirent}, dev::{null:: Null, zero::Zero, tty::Teletype}, file_trait::File, filesystem::FileSystem};

lazy_static! {
    pub static ref FILE_SYSTEM: Arc<EasyFileSystem<BlockCacheManager>> = EasyFileSystem::open(
        BLOCK_DEVICE.clone(),
        Arc::new(Mutex::new(BlockCacheManager::new()))
    );
    pub static ref ROOT: Arc<DirectoryTreeNode> = DirectoryTreeNode::new(
        "".to_string(),
        Arc::new(FileSystem::new(FS::Fat32)),
        OSInode::new(InodeImpl::root_inode(&FILE_SYSTEM)),
        None
    );
}

pub struct DirectoryTreeNode {
    /// If this is a directory
    /// 1. pwd
    /// 2. mount point
    /// 3. root node
    /// If this is a file
    /// 1. executed by some processes
    /// This parameter will add 1 when opening
    spe_usage: Mutex<usize>,
    name: String,
    filesystem: Arc<FileSystem>,
    file: Arc<dyn File>,
    selfptr: Mutex<Weak<Self>>,
    father: Mutex<Weak<Self>>,
    children: RwLock<BTreeMap<String, Arc<Self>>>,
}

impl DirectoryTreeNode {
    pub fn new(
        name: String, 
        filesystem: Arc<FileSystem>,
        file: Arc<dyn File>, 
        father: Option<&Arc<Self>>
    ) -> Arc<Self>{
        let node = 
        Arc::new(DirectoryTreeNode { 
            spe_usage: Mutex::new(if father.is_none() {1} else {0}),
            name,
            filesystem, 
            file, 
            selfptr: Mutex::new(Weak::new()),
            father: Mutex::new(
                father.map_or_else(
                    ||Weak::new(), 
                    |x|Arc::downgrade(x)
                )
            ),
            children: RwLock::new(BTreeMap::new()),
        });
        *node.selfptr.lock() = Arc::downgrade(&node);
        node.file.info_dirtree_node(Arc::downgrade(&node));
        node
    }
    pub fn add_special_use(&self) {
        *self.spe_usage.lock() += 1;
    }
    pub fn sub_special_use(&self) {
        *self.spe_usage.lock() -= 1;
    }
    pub fn get_cwd(&self) -> String {
        let mut pathv = Vec::<String>::new();
        let mut current_inode = self.get_arc();
        loop {
            let lock = current_inode.father.lock();
            let par_inode = match lock.upgrade() {
                Some(inode) => inode.clone(),
                None => break,
            };
            drop(lock);
            pathv.push(current_inode.name.clone());
            current_inode = par_inode;
        }
        pathv.push(current_inode.name.clone());
        pathv.reverse();
        if pathv.len() == 1 {
            "/".to_string()
        } else {
            pathv.join("/")
        }
    }
    fn get_arc(&self) -> Arc<Self> {
        self.selfptr.lock().upgrade().unwrap().clone()
    }
    fn parse_dir_path (path: &str) -> Vec<&str> {
        path.split('/')
            .fold(Vec::new(), |mut v, s|{
                match s {
                    "" | "." => {}
                    ".." => {
                        if v.last().map_or(true, |s|{*s == ".."}) {
                            v.push(s);
                        } else {
                            v.pop();
                        }
                    }
                    _ => {v.push(s);}
                }
                v
            })
    }
    fn try_to_open_subfile(
        &self,
        name: &str,
        lock: &mut RwLockWriteGuard<BTreeMap<String, Arc<Self>>>
    ) -> Result<Arc<Self>, isize> {
        if lock.len() == 0 && !self.file.is_dir() {
            return Err(ENOTDIR);
        }
        log::error!("try to open {}", name);
        match lock.get(&name.to_string()) {
            Some(inode) => {
                Ok(inode.clone())
            },
            None => {
                match self.file.open_subfile(name) {
                    Ok(new_file) => {
                        let key = name.to_string();
                        let value = Self::new(
                            key.clone(), 
                            self.filesystem.clone(),
                            new_file, 
                            Some(&self.get_arc())
                        );
                        let res_inode = value.clone();
                        lock.insert(key, value);
                        Ok(res_inode)
                    },
                    Err(errno) => Err(errno),
                }
            },
        }
    }
    pub fn cd_comp(
        &self,
        components: &Vec<&str>
    ) -> Result<Arc<Self>, isize> {
        let mut current_inode = self.get_arc();
        for component in components {
            log::error!("current: {}", current_inode.name);
            if *component == ".." {
                let lock = current_inode.father.lock();
                let par_inode = lock.upgrade().unwrap().clone();
                drop(lock);
                current_inode = par_inode;
                continue;
            }
            let lock = current_inode.children.upgradeable_read();
            if let Some(son) = lock.get(*component) {
                let son_inode = son.clone();
                drop(son);
                drop(lock);
                current_inode = son_inode;
            } else {
                let mut lock = lock.upgrade();
                let son_inode = match current_inode.try_to_open_subfile(component, &mut lock) {
                    Ok(inode) => inode,
                    Err(errno) => return Err(errno),
                };
                drop(lock);
                current_inode = son_inode;
            }
        }
        log::error!("current: {}", current_inode.name);
        Ok(current_inode)
    }
    pub fn cd_path(
        &self,
        path: &str
    ) -> Result<Arc<Self>, isize> {
        let components = Self::parse_dir_path(path);
        let inode = if path.starts_with("/") {
            &**ROOT
        } else {
            &self
        };
        inode.cd_comp(&components)
    }
    fn create(
        &self,
        name: &str,
        file_type: DiskInodeType,
    ) -> Result<Arc<dyn File>, isize> {
        if name == "" || !self.file.is_dir() {
            panic!();
        }
        self.file.create(name, file_type)
    }
    pub fn open(
        &self,
        path: &str,
        flags: OpenFlags,
        special_use: bool,
    ) -> Result<Arc<dyn File>, isize> {
        if path == "" {
            return Err(ENOENT);
        }
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
        
        let inode = if path.starts_with("/") {
            &**ROOT
        } else {
            &self
        };
        
        let mut components = Self::parse_dir_path(path);
        let last_comp = components.pop();
        let inode = match inode.cd_comp(&components) {
            Ok(inode) => inode,
            Err(errno) => return Err(errno),
        };
        let inode = if let Some(last_comp) = last_comp {
            log::error!("last_comp: {}", last_comp);
            let mut lock = inode.children.write();
            match inode.try_to_open_subfile(last_comp, &mut lock) {
                Ok(inode) => {
                    log::error!("ok!!!");
                    if flags.contains(OpenFlags::O_CREAT | OpenFlags::O_EXCL) {
                        return Err(EEXIST);
                    }
                    inode
                },
                Err(ENOENT) => {
                    if !flags.contains(OpenFlags::O_CREAT) {
                        return Err(ENOENT);
                    }
                    let new_file = match inode.create(last_comp, DiskInodeType::File) {
                        Ok(file) => file,
                        Err(errno) => return Err(errno),
                    };
                    let key = (*last_comp).to_string();
                    let value = Self::new(
                        key.clone(), 
                        inode.filesystem.clone(),
                        new_file, 
                        Some(&self.get_arc())
                    );
                    let new_inode = value.clone();
                    lock.insert(key, value);
                    new_inode
                },
                Err(errno) => {
                    return Err(errno);
                } 
            }
        } else {
            inode
        };

        if flags.contains(OpenFlags::O_TRUNC) {
            match self.file.truncate_size(0) {
                Ok(_) => {},
                Err(errno) => return Err(errno),
            }
        }

        if  inode.file.is_file() && 
            *inode.spe_usage.lock() > 0 && 
            (flags.contains(OpenFlags::O_WRONLY) || flags.contains(OpenFlags::O_RDWR)) {
            return Err(ETXTBSY);
        }

        if inode.file.is_dir() && (flags.contains(OpenFlags::O_WRONLY) || flags.contains(OpenFlags::O_RDWR)) {
            return Err(EISDIR);
        }

        // if inode.file.is_dir() && !flags.contains(OpenFlags::O_DIRECTORY) {
        //     return Err(ENOTDIR);
        // }

        if special_use {
            *inode.spe_usage.lock() += 1;
        }

        Ok(inode.file.open(flags, special_use))
    }
    
    pub fn mkdir(
        &self,
        path: &str,
    ) -> Result<(), isize> {
        if path == "" {
            return Err(ENOENT);
        }
        let inode = if path.starts_with("/") {
            &**ROOT
        } else {
            &self
        };
        
        let mut components = Self::parse_dir_path(path);
        let last_comp = components.pop();
        let inode = match inode.cd_comp(&components) {
            Ok(inode) => inode,
            Err(errno) => return Err(errno),
        };

        if let Some(last_comp) = last_comp {
            let mut lock = inode.children.write();
            match inode.try_to_open_subfile(last_comp, &mut lock) {
                Ok(_) => { return Err(EEXIST); },
                Err(ENOENT) => {
                    let new_file = match inode.create(last_comp, DiskInodeType::Directory) {
                        Ok(file) => file,
                        Err(errno) => return Err(errno),
                    };
                    let key = (*last_comp).to_string();
                    let value = Self::new(
                        key.clone(), 
                        inode.filesystem.clone(),
                        new_file, 
                        Some(&self.get_arc())
                    );
                    let new_inode = value.clone();
                    lock.insert(key, value);
                    new_inode
                },
                Err(errno) => {
                    return Err(errno);
                }
            }
        } else {
            return Err(EEXIST);
        };

        Ok(())
    } 
    
    pub fn delete(
        &self,
        path: &str,
        delete_directory: bool
    ) -> Result<(), isize> {
        if path == "" {
            return Err(ENOENT);
        }
        if path.split('/').last().map_or(true, |x|{x == "."}) {
            return Err(EINVAL);
        }

        let inode = if path.starts_with("/") {
            &**ROOT
        } else {
            &self
        };
        
        let components = Self::parse_dir_path(path);
        let last_comp = *components.last().unwrap();
        let inode = match inode.cd_comp(&components) {
            Ok(inode) => inode,
            Err(errno) => return Err(errno),
        };

        if *inode.spe_usage.lock() > 0 {
            return Err(EBUSY);
        }

        if !delete_directory && inode.file.is_dir() {
            return Err(EISDIR);
        }
        
        if delete_directory && !inode.file.is_dir() {
            return Err(ENOTDIR);
        }

        match inode.father.lock().upgrade() {
            Some(par_inode) => {
                let mut lock = par_inode.children.write();
                match inode.file.unlink(true) {
                    Ok(_) => {
                        let key = (*last_comp).to_string();
                        lock.remove(&key);
                    },
                    Err(errno) => return Err(errno),
                }
            },
            None => return Err(EACCES),
        }
        Ok(())
    }

    pub fn rename(
        old_path: &str,
        new_path: &str,
    ) -> Result<(), isize> {
        assert!(old_path.starts_with('/'));
        assert!(new_path.starts_with('/'));

        if old_path == "" || new_path == "" {
            return Err(ENOENT);
        }
        if old_path == "/" || new_path == "/" {
            return Err(EBUSY);
        }

        let mut old_comps = Self::parse_dir_path(old_path);
        let mut new_comps = Self::parse_dir_path(new_path);

        if old_comps == new_comps {
            return Ok(());
        }

        if new_comps.starts_with(&old_comps) {
            return Err(EINVAL);
        }
        // We gurantee that last component isn't empty
        let old_last_comp = old_comps.pop().unwrap();
        let new_last_comp = new_comps.pop().unwrap();

        let old_par_inode = match ROOT.cd_comp(&old_comps) {
            Ok(inode) => inode,
            Err(errno) => return Err(errno),
        };
        let new_par_inode = match ROOT.cd_comp(&new_comps) {
            Ok(inode) => inode,
            Err(errno) => return Err(errno),
        };

        let mut old_lock: RwLockWriteGuard<BTreeMap<String, Arc<DirectoryTreeNode>>>;
        let mut new_lock: RwLockWriteGuard<BTreeMap<String, Arc<DirectoryTreeNode>>>;
        // Be careful about the lock ordering
        if old_comps < new_comps {
            old_lock = old_par_inode.children.write();
            new_lock = new_par_inode.children.write();
        } else {
            new_lock = new_par_inode.children.write();
            old_lock = old_par_inode.children.write();
        }

        let old_inode = match old_par_inode.try_to_open_subfile(old_last_comp, &mut old_lock) {
            Ok(inode) => inode,
            Err(errno) => return Err(errno),
        };

        if *old_inode.spe_usage.lock() > 0 {
            return Err(EBUSY);
        }

        if old_inode.filesystem.fs_id != new_par_inode.filesystem.fs_id {
            return Err(EXDEV);
        }

        let key = (*new_last_comp).to_string();
        match new_par_inode.try_to_open_subfile(new_last_comp, &mut new_lock) {
            Ok(new_inode) => {
                if new_inode.file.is_dir() && !old_inode.file.is_dir() {
                    return Err(EISDIR);
                }
                if old_inode.file.is_dir() && !new_inode.file.is_dir() {
                    return Err(ENOTDIR);
                }
                if *new_inode.spe_usage.lock() > 0 {
                    return Err(EBUSY);
                }
                // delete
                match new_par_inode.file.unlink(true) {
                    Ok(_) => {new_lock.remove(&key);},
                    Err(errno) => return Err(errno),
                }
            },
            Err(ENOENT) => {},
            Err(errno) => return Err(errno),
        }

        let value = old_lock.remove(&key).unwrap();
        match old_inode.file.unlink(false) {
            Ok(_) => {},
            Err(errno) => return Err(errno),
        };
        match old_inode.filesystem.fs_type {
            FS::Fat32 => {
                let old_file = old_inode.file.downcast_ref::<OSInode>().unwrap();
                let new_par_file = new_par_inode.file.downcast_ref::<OSInode>().unwrap();
                new_par_file.link_son(old_last_comp, old_file)?;
            },
            FS::Null => return Err(EACCES),
        }
        *value.father.lock() = Arc::downgrade(&new_par_inode.get_arc());
        new_lock.insert(key, value);
        
        Ok(())
    }
    pub fn get_dirent(&self, count: usize) -> Result<Vec<Dirent>, isize> {
        if !self.file.is_dir() {
            return Err(ENOTDIR);
        }
        Ok(self.file.get_dirent(count))
    }
}

pub fn oom() {
    const MAX_FAIL_TIME: usize = 6;
    let mut fail_time = 0;
    fn dfs(u: &Arc<DirectoryTreeNode>) -> usize {
        let mut dropped = u.file.oom();
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

pub fn init_fs()
{
    init_device_directory();
    init_tmp_directory();
}
fn init_device_directory()
{
    ROOT.mkdir("/dev").unwrap();
    
    let dev_inode = match ROOT.cd_path("/dev") {
        Ok(inode) => inode,
        Err(_) => panic!("dev directory doesn't exist"),
    };

    let null_dev = DirectoryTreeNode::new(
        "null".to_string(), 
        Arc::new(FileSystem::new(FS::Null)),
        Arc::new(Null{}), 
        Some(&dev_inode.get_arc())
    );
    let zero_dev = DirectoryTreeNode::new(
        "zero".to_string(), 
        Arc::new(FileSystem::new(FS::Null)),
        Arc::new(Zero{}), 
        Some(&dev_inode.get_arc())
    );
    let tty_dev = DirectoryTreeNode::new(
        "tty".to_string(), 
        Arc::new(FileSystem::new(FS::Null)),
        Arc::new(Teletype::new()),
        Some(&dev_inode.get_arc())
    );

    let mut lock = dev_inode.children.write();
    lock.insert("null".to_string(), null_dev);
    lock.insert("zero".to_string(), zero_dev);
    lock.insert("tty".to_string(), tty_dev);
}
fn init_tmp_directory()
{
    ROOT.mkdir("/tmp").unwrap();
}