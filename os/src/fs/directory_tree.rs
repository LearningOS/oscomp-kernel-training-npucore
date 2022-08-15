use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    sync::{Arc, Weak},
    vec::Vec,
};
use super::fat32::{DiskInodeType, EasyFileSystem};
use lazy_static::*;
use spin::{Mutex, RwLock, RwLockWriteGuard, MutexGuard};

use super::{
    dev::{null::Null, tty::Teletype, zero::Zero},
    file_trait::File,
    filesystem::FileSystem,
    layout::OpenFlags, swap::SWAP_DEVICE, Hwclock,
    cache::{BlockCacheManager}
};
use crate::{syscall::errno::*, mm::tlb_invalidate};
use crate::{
    drivers::BLOCK_DEVICE,
    fs::{
        filesystem::FS,
        fat32::{
            inode::{InodeImpl, OSInode},
        },
    },
};

lazy_static! {
    pub static ref FILE_SYSTEM: Arc<EasyFileSystem> = EasyFileSystem::open(
        BLOCK_DEVICE.clone(),
        Arc::new(Mutex::new(BlockCacheManager::new()))
    );
    pub static ref ROOT: Arc<DirectoryTreeNode> = DirectoryTreeNode::new(
        "".to_string(),
        Arc::new(FileSystem::new(FS::Fat32)),
        OSInode::new(InodeImpl::root_inode(&FILE_SYSTEM)),
        None
    );
    static ref DIRECTORY_VEC: Mutex<(Vec<Weak<DirectoryTreeNode>>, usize)> = Mutex::new((Vec::new(), 0));
}

fn insert_directory_vec(inode: Weak<DirectoryTreeNode>) {
    DIRECTORY_VEC.lock().0.push(inode);
}
fn delete_directory_vec() {
    let mut lock = DIRECTORY_VEC.lock();
    lock.1 += 1;
    if lock.1 >= lock.0.len() / 2 {
        update_directory_vec(&mut lock);
    }
}
fn update_directory_vec(lock: &mut MutexGuard<(Vec<Weak<DirectoryTreeNode>>, usize)>) {
    let mut new_vec: Vec<Weak<DirectoryTreeNode>> = Vec::new();
    for inode in &lock.0 {
        if inode.upgrade().is_some() {
            new_vec.push(inode.clone());
        }
    }
    **lock = (new_vec, 0);
}

pub struct DirectoryTreeNode {
    /// If this is a directory
    /// 1. cwd
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

impl Drop for DirectoryTreeNode {
    fn drop(&mut self) {
        delete_directory_vec();
    }
}

impl DirectoryTreeNode {
    pub fn new(
        name: String,
        filesystem: Arc<FileSystem>,
        file: Arc<dyn File>,
        father: Option<&Arc<Self>>,
    ) -> Arc<Self> {
        let node = Arc::new(DirectoryTreeNode {
            spe_usage: Mutex::new(if father.is_none() { 1 } else { 0 }),
            name,
            filesystem,
            file,
            selfptr: Mutex::new(Weak::new()),
            father: Mutex::new(father.map_or_else(|| Weak::new(), |x| Arc::downgrade(x))),
            children: RwLock::new(BTreeMap::new()),
        });
        *node.selfptr.lock() = Arc::downgrade(&node);
        node.file.info_dirtree_node(Arc::downgrade(&node));
        insert_directory_vec(Arc::downgrade(&node));
        node
    }
    pub fn add_special_use(&self) {
        *self.spe_usage.lock() += 1;
    }
    pub fn sub_special_use(&self) {
        *self.spe_usage.lock() -= 1;
    }
    pub fn get_cwd(&self) -> String {
        let mut pathv = Vec::<String>::with_capacity(8);
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
    fn parse_dir_path(path: &str) -> Vec<&str> {
        path.split('/').fold(Vec::with_capacity(8), |mut v, s| {
            match s {
                "" | "." => {}
                ".." => {
                    if v.last().map_or(true, |s| *s == "..") {
                        v.push(s);
                    } else {
                        v.pop();
                    }
                }
                _ => {
                    v.push(s);
                }
            }
            v
        })
    }
    fn try_to_open_subfile(
        &self,
        name: &str,
        lock: &mut RwLockWriteGuard<BTreeMap<String, Arc<Self>>>,
    ) -> Result<Arc<Self>, isize> {
        if lock.len() == 0 && !self.file.is_dir() {
            return Err(ENOTDIR);
        }
        match lock.get(&name.to_string()) {
            Some(inode) => Ok(inode.clone()),
            None => match self.file.open_subfile(name) {
                Ok(new_file) => {
                    let key = name.to_string();
                    let value = Self::new(
                        key.clone(),
                        self.filesystem.clone(),
                        new_file,
                        Some(&self.get_arc()),
                    );
                    let res_inode = value.clone();
                    lock.insert(key, value);
                    Ok(res_inode)
                }
                Err(errno) => Err(errno),
            },
        }
    }
    pub fn cd_comp(&self, components: &Vec<&str>) -> Result<Arc<Self>, isize> {
        let mut current_inode = self.get_arc();
        for component in components {
            if *component == ".." {
                let lock = current_inode.father.lock();
                let par_inode = lock.upgrade();
                match par_inode {
                    Some(par_inode) => {
                        drop(lock);
                        current_inode = par_inode;
                    },
                    None => {},
                }
                continue;
            }
            let lock = current_inode.children.upgradeable_read();
            if let Some(child) = lock.get(*component) {
                let child_inode = child.clone();
                drop(child);
                drop(lock);
                current_inode = child_inode;
            } else {
                let mut lock = lock.upgrade();
                let child_inode = match current_inode.try_to_open_subfile(component, &mut lock) {
                    Ok(inode) => inode,
                    Err(errno) => return Err(errno),
                };
                drop(lock);
                current_inode = child_inode;
            }
        }
        Ok(current_inode)
    }
    pub fn cd_path(&self, path: &str) -> Result<Arc<Self>, isize> {
        let components = Self::parse_dir_path(path);
        let inode = if path.starts_with("/") {
            &**ROOT
        } else {
            &self
        };
        inode.cd_comp(&components)
    }
    fn create(&self, name: &str, file_type: DiskInodeType) -> Result<Arc<dyn File>, isize> {
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
        log::debug!("[open]: cwd: {}, path: {}", self.get_cwd(), path);
        const BUSYBOX_PATH: &str = "/busybox";
        const REDIRECT_TO_BUSYBOX: [&str; 3] = ["/touch", "/rm", "/ls"];
        let path = if REDIRECT_TO_BUSYBOX.contains(&path) {
            BUSYBOX_PATH
        } else {
            path
        };
        const LIBC_PATH: &str = "/lib/libc.so";
        const REDIRECT_TO_LIBC: [&str; 3] = [
            "/lib/ld-musl-riscv64.so.1",
            "/lib/ld-musl-riscv64-sf.so.1",
            "/lib/ld-linux-riscv64-lp64d.so.1",
        ];
        let path = if REDIRECT_TO_LIBC.contains(&path) {
            LIBC_PATH
        } else {
            path
        };
        // let path = if path == "./dlopen_dso.so" {
        //     "libdlopen_dso.so"
        // } else {
        //     path
        // };
        let path = if path == "/usr/lib/tls_get_new-dtv_dso.so" {
            "./libtls_get_new-dtv_dso.so"
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
            let mut lock = inode.children.write();
            match inode.try_to_open_subfile(last_comp, &mut lock) {
                Ok(inode) => {
                    if flags.contains(OpenFlags::O_CREAT | OpenFlags::O_EXCL) {
                        return Err(EEXIST);
                    }
                    inode
                }
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
                        Some(&inode.get_arc()),
                    );
                    let new_inode = value.clone();
                    lock.insert(key, value);
                    new_inode
                }
                Err(errno) => {
                    return Err(errno);
                }
            }
        } else {
            inode
        };

        if flags.contains(OpenFlags::O_TRUNC) {
            match inode.file.truncate_size(0) {
                Ok(_) => {}
                Err(errno) => return Err(errno),
            }
        }

        if inode.file.is_file()
            && *inode.spe_usage.lock() > 0
            && (flags.contains(OpenFlags::O_WRONLY) || flags.contains(OpenFlags::O_RDWR))
        {
            return Err(ETXTBSY);
        }

        if inode.file.is_dir()
            && (flags.contains(OpenFlags::O_WRONLY) || flags.contains(OpenFlags::O_RDWR))
        {
            return Err(EISDIR);
        }

        if !inode.file.is_dir() && flags.contains(OpenFlags::O_DIRECTORY) {
            return Err(ENOTDIR);
        }

        if special_use {
            *inode.spe_usage.lock() += 1;
        }

        Ok(inode.file.open(flags, special_use))
    }

    pub fn mkdir(&self, path: &str) -> Result<(), isize> {
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
                Ok(_) => {
                    return Err(EEXIST);
                }
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
                        Some(&inode.get_arc()),
                    );
                    let new_inode = value.clone();
                    lock.insert(key, value);
                    new_inode
                }
                Err(errno) => {
                    return Err(errno);
                }
            }
        } else {
            return Err(EEXIST);
        };

        Ok(())
    }

    pub fn delete(&self, path: &str, delete_directory: bool) -> Result<(), isize> {
        if path.split('/').last().map_or(true, |x| x == ".") {
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
                        let key = last_comp.to_string();
                        lock.remove(&key);
                    }
                    Err(errno) => return Err(errno),
                }
            }
            None => return Err(EACCES),
        }
        Ok(())
    }

    pub fn rename(old_path: &str, new_path: &str) -> Result<(), isize> {
        assert!(old_path.starts_with('/'));
        assert!(new_path.starts_with('/'));

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
        type ChildLockType<'a> = RwLockWriteGuard<'a, BTreeMap<String, Arc<DirectoryTreeNode>>>;

        let old_lock: Arc<Mutex<ChildLockType<'_>>>;
        let new_lock: Arc<Mutex<ChildLockType<'_>>>;

        // Be careful about the lock ordering
        if old_comps == new_comps {
            old_lock = Arc::new(Mutex::new(old_par_inode.children.write()));
            new_lock = old_lock.clone();
        } else if old_comps < new_comps {
            old_lock = Arc::new(Mutex::new(old_par_inode.children.write()));
            new_lock = Arc::new(Mutex::new(new_par_inode.children.write()));
        } else {
            new_lock = Arc::new(Mutex::new(new_par_inode.children.write()));
            old_lock = Arc::new(Mutex::new(old_par_inode.children.write()));
        }

        let old_inode =
            match old_par_inode.try_to_open_subfile(old_last_comp, &mut (*old_lock.lock())) {
                Ok(inode) => inode,
                Err(errno) => return Err(errno),
            };

        if *old_inode.spe_usage.lock() > 0 {
            return Err(EBUSY);
        }

        if old_inode.filesystem.fs_id != new_par_inode.filesystem.fs_id {
            return Err(EXDEV);
        }
        let old_key = old_last_comp.to_string();
        let new_key = new_last_comp.to_string();
        match new_par_inode.try_to_open_subfile(new_last_comp, &mut (*new_lock.lock())) {
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
                    Ok(_) => {
                        new_lock.lock().remove(&new_key);
                    }
                    Err(errno) => return Err(errno),
                }
            }
            Err(ENOENT) => {}
            Err(errno) => return Err(errno),
        }

        let value = old_lock.lock().remove(&old_key).unwrap();
        match old_inode.file.unlink(false) {
            Ok(_) => {}
            Err(errno) => return Err(errno),
        };
        match old_inode.filesystem.fs_type {
            FS::Fat32 => {
                let old_file = old_inode.file.downcast_ref::<OSInode>().unwrap();
                let new_par_file = new_par_inode.file.downcast_ref::<OSInode>().unwrap();
                new_par_file.link_child(old_last_comp, old_file)?;
            }
            FS::Null => return Err(EACCES),
        }
        *value.father.lock() = Arc::downgrade(&new_par_inode.get_arc());
        new_lock.lock().insert(new_key, value);

        Ok(())
    }
}

pub fn oom() -> usize {
    tlb_invalidate();
    const MAX_FAIL_TIME: usize = 3;
    let mut fail_time = 0;
    log::warn!("[oom] start oom");
    let mut lock = DIRECTORY_VEC.lock();
    update_directory_vec(&mut lock);
    loop {
        let mut dropped = 0;
        for inode in &lock.0 {
            let inode = inode.upgrade().unwrap();
            dropped += inode.file.oom();
        }
        if dropped > 0 {
            log::warn!("[oom] recycle pages: {}", dropped);
            return dropped;
        }
        fail_time += 1;
        if fail_time >= MAX_FAIL_TIME {
            return dropped;
        }
    }
}

pub fn init_fs() {
    init_device_directory();
    init_tmp_directory();
    init_proc_directory();
    init_swap_device();
}
#[allow(unused)]
fn init_device_directory() {
    ROOT.mkdir("/dev");

    let dev_inode = match ROOT.cd_path("/dev") {
        Ok(inode) => inode,
        Err(_) => panic!("dev directory doesn't exist"),
    };

    dev_inode.mkdir("shm");
    dev_inode.mkdir("misc");

    let null_dev = DirectoryTreeNode::new(
        "null".to_string(),
        Arc::new(FileSystem::new(FS::Null)),
        Arc::new(Null {}),
        Some(&dev_inode.get_arc()),
    );
    let zero_dev = DirectoryTreeNode::new(
        "zero".to_string(),
        Arc::new(FileSystem::new(FS::Null)),
        Arc::new(Zero {}),
        Some(&dev_inode.get_arc()),
    );
    let tty_dev = DirectoryTreeNode::new(
        "tty".to_string(),
        Arc::new(FileSystem::new(FS::Null)),
        Arc::new(Teletype::new()),
        Some(&dev_inode.get_arc()),
    );
    let mut lock = dev_inode.children.write();
    lock.insert("null".to_string(), null_dev);
    lock.insert("zero".to_string(), zero_dev);
    lock.insert("tty".to_string(), tty_dev);
    drop(lock);

    let misc_inode = match dev_inode.cd_path("./misc") {
        Ok(inode) => inode,
        Err(_) => panic!("misc directory doesn't exist"),
    };
    let hwclock_dev = DirectoryTreeNode::new(
        "rtc".to_string(),
        Arc::new(FileSystem::new(FS::Null)),
        Arc::new(Hwclock {}),
        Some(&misc_inode.get_arc()),
    );
    let mut lock = misc_inode.children.write();
    lock.insert("rtc".to_string(), hwclock_dev);
    drop(lock);
}
fn init_tmp_directory() {
    match ROOT.mkdir("/tmp") {
        _ => {}
    }
}
fn init_proc_directory() {
    match ROOT.mkdir("/proc") {
        _ => {}
    }
    match ROOT.open("/proc/meminfo", OpenFlags::O_CREAT, false) {
        _ => {}
    }
    match ROOT.open("/proc/mounts", OpenFlags::O_CREAT, false) {
        _ => {}
    }
}
fn init_swap_device() {
    SWAP_DEVICE.lock();
}
