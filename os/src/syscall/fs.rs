use crate::fs::{ch_dir, list_files, make_pipe, open, DiskInodeType, OpenFlags};
use crate::fs::{Dirent, FdSet, File, FileClass, FileDescripter, IoVec, IoVecs, Kstat, MNT_TABLE, NewStat, TTY, NullZero};
use crate::mm::{translated_byte_buffer, translated_refmut, translated_str, UserBuffer};
use crate::task::{current_task, current_user_token};
use alloc::sync::Arc;
use core::mem::size_of;

const AT_FDCWD:isize = -100;
pub const FD_LIMIT:usize = 128;

pub fn sys_write(fd: usize, buf: *const u8, len: usize) -> isize {
    let token = current_user_token();
    let task = current_task().unwrap();
    let inner = task.acquire_inner_lock();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if let Some(file) = &inner.fd_table[fd] {
        let file: Arc<dyn File + Send + Sync> = match &file.fclass {
            FileClass::Abstr(f)=> {f.clone()},
            FileClass::File(f)=>{/*print!("\n");*/f.clone()},
            _ => return -1,
        };
        if !file.writable() {
            return -1;
        }
        drop(inner);
        file.write(UserBuffer::new(translated_byte_buffer(token, buf, len))) as isize
    } else {
        -1
    }
}

pub fn sys_read(fd: usize, buf: *const u8, len: usize) -> isize {
    let token = current_user_token();
    let task = current_task().unwrap();
    let inner = task.acquire_inner_lock();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if let Some(file) = &inner.fd_table[fd] {
        let file: Arc<dyn File + Send + Sync> = match &file.fclass {
            FileClass::Abstr(f)=> {f.clone()},
            FileClass::File(f)=>{/*print!("\n");*/f.clone()},
            _ => return -1,
        };
        if !file.readable() {
            return -1;
        }
        // release Task lock manually to avoid deadlock
        drop(inner);
        file.read(UserBuffer::new(translated_byte_buffer(token, buf, len))) as isize
    } else {
        -1
    }
}

pub fn sys_open(path: *const u8, flags: u32) -> isize {
    let task = current_task().unwrap();
    let token = current_user_token();
    let path = translated_str(token, path);
    let mut inner = task.acquire_inner_lock();
    if let Some(inode) = open(
        inner.get_work_path().as_str(),
        path.as_str(),
        OpenFlags::from_bits(flags).unwrap(),
        DiskInodeType::File,
    ) {
        let fd = inner.alloc_fd();

        inner.fd_table[fd] = Some(FileDescripter::new(
            OpenFlags::from_bits(flags).unwrap().contains(OpenFlags::CLOEXEC),
            FileClass::File(inode)
        ));
        drop(inner);
        fd as isize
    } else {
        -1
    }
}

pub fn sys_close(fd: usize) -> isize {
    let task = current_task().unwrap();
    let mut inner = task.acquire_inner_lock();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if inner.fd_table[fd].is_none() {
        return -1;
    }
    inner.fd_table[fd].take();
    0
}

pub fn sys_pipe(pipe: *mut usize) -> isize {
    let task = current_task().unwrap();
    let token = current_user_token();
    let mut inner = task.acquire_inner_lock();
    let (pipe_read, pipe_write) = make_pipe();
    let read_fd = inner.alloc_fd();
    inner.fd_table[read_fd] = Some(FileDescripter::new(
        false,
        FileClass::Abstr(pipe_read)
    ));
    let write_fd = inner.alloc_fd();
    inner.fd_table[write_fd] = Some(FileDescripter::new(
        false,
        FileClass::Abstr(pipe_write)
    ));
    *translated_refmut(token, pipe) = read_fd;
    *translated_refmut(token, unsafe { pipe.add(1) }) = write_fd;
    0
}

pub fn sys_dup(fd: usize) -> isize {
    let task = current_task().unwrap();
    let mut inner = task.acquire_inner_lock();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if inner.fd_table[fd].is_none() {
        return -1;
    }
    let new_fd = inner.alloc_fd();
    inner.fd_table[new_fd] = Some(inner.fd_table[fd].as_ref().unwrap().clone());
    new_fd as isize
}

pub fn sys_newfstatat(fd:isize, path: *const u8, buf: *mut u8, flag: u32)->isize{
    let token = current_user_token();
    let task = current_task().unwrap();
    let mut buf_vec = translated_byte_buffer(token, buf, size_of::<NewStat>());
    let inner = task.acquire_inner_lock();
    //println!("size = {}", size_of::<NewStat>());
    // 使用UserBuffer结构，以便于跨页读写
    let mut userbuf = UserBuffer::new(buf_vec);
    let mut stat = NewStat::empty();
    //let mut stat = Kstat::empty();
    let path = translated_str(token, path);
    
    if fd == AT_FDCWD {
        let work_path = inner.current_path.clone();
        if let Some(file) = open(
            work_path.as_str(),
            path.as_str(),
            OpenFlags::RDONLY,
            DiskInodeType::Directory
        ) {
            file.get_newstat(&mut stat);
            //file.get_fstat(&mut stat);
            println!("[sys_fstatat](fd:{}, path = {:?}, buff addr = 0x{:X},  [size = {}]) ", fd, path, buf as usize, stat.st_size );
            userbuf.write(stat.as_bytes());
            return 0;
        } else {
            return -2
        }
    } else {
        let fd_usz = fd as usize;
        if fd_usz >= inner.fd_table.len() && fd_usz > FD_LIMIT {
            return -1
        }
        if let Some(file) = &inner.fd_table[fd_usz] {
            match &file.fclass {
                FileClass::File(f) => {
                    f.get_newstat(&mut stat);
                    //f.get_fstat(&mut stat);
                    userbuf.write(stat.as_bytes());
                    return 0
                },
                _ => return -1,
            }
        } else {
            return -2
        }
    }
}

pub fn sys_fstat(fd:isize, buf: *mut u8)->isize{
    let token = current_user_token();
    let task = current_task().unwrap();
    let mut buf_vec = translated_byte_buffer(token, buf, size_of::<Kstat>());
    let inner = task.acquire_inner_lock();
    // 使用UserBuffer结构，以便于跨页读写
    let mut userbuf = UserBuffer::new(buf_vec);
    let mut kstat = Kstat::empty();
    if fd == AT_FDCWD {
        let work_path = inner.current_path.clone();
        if let Some(file) = open(
            "/",
            work_path.as_str(),
            OpenFlags::RDONLY,
            DiskInodeType::Directory
        ) {
            file.get_fstat(&mut kstat);
            println!("syscall_fstat(fd:{}, [size = {}]) ", fd, kstat.st_size );
            userbuf.write(kstat.as_bytes());
            return 0
        } else {
            return -1
        }
    } else {
        let fd_usz = fd as usize;
        if fd_usz >= inner.fd_table.len() && fd_usz > FD_LIMIT {
            return -1
        }
        if let Some(file) = &inner.fd_table[fd_usz] {
            match &file.fclass {
                FileClass::File(f) => {
                    f.get_fstat(&mut kstat);
                    userbuf.write(kstat.as_bytes());
                    println!("syscall_fstat(fd:{}, [size = {}]) ", fd, kstat.st_size );
                    return 0
                },
                _ => {
                    userbuf.write(Kstat::new_abstract().as_bytes());
                    println!("syscall_fstat(fd:{}, [size = {}]) ", fd, kstat.st_size );
                    return 0 //warning
                },
            }
        } else {
            return -1
        }
    }
}

pub fn sys_open_at(dirfd: isize, path: *const u8, flags: u32, mode: u32) -> isize {
    let task = current_task().unwrap();
    let token = current_user_token();
    // 这里传入的地址为用户的虚地址，因此要使用用户的虚地址进行映射
    let path = translated_str(token, path);
    println!("sys_openat: path = {}", path);
    let mut inner = task.acquire_inner_lock();
    
    /////////////////////////////// WARNING ////////////////////////////////
    // 只是测试用的临时处理
    if path.contains("/dev") {
        let fd = inner.alloc_fd();
        
        let fclass = {
            if path.contains("tty") {
                FileClass::Abstr(TTY.clone())
            } else if path.contains("null") {
                FileClass::Abstr(Arc::new(NullZero::new(true)))
            } else if path.contains("zero") {
                FileClass::Abstr(Arc::new(NullZero::new(false)))
            } else {
                return -1
            }
        };

        inner.fd_table[fd] = Some( FileDescripter::new(
            false,
            fclass
        ));
        return fd as isize
    }
    //if path.contains("|") {
    //    let fd = inner.alloc_fd();
    //    inner.fd_table[fd] = Some( FileDescripter::new(
    //        false,
    //        FileClass::Abstr(  )
    //    ));
    //    return fd as isize
    //}

    ////////////////////////////////////////////////////////////////////////

    let oflags = OpenFlags::from_bits(flags).unwrap();
    if dirfd == AT_FDCWD {
        if let Some(inode) = open(
            inner.get_work_path().as_str(),
            path.as_str(),
            oflags,
            DiskInodeType::File
        ) {
            let fd = inner.alloc_fd();
            inner.fd_table[fd] = Some( FileDescripter::new(
                oflags.contains(OpenFlags::CLOEXEC),
                FileClass::File(inode)
            ));
            fd as isize
        } else {
            //panic!("open failed");
            -1
        }
    } else {    
        let fd_usz = dirfd as usize;
        if fd_usz >= inner.fd_table.len() && fd_usz > FD_LIMIT {
            return -1
        }
        if let Some(file) = &inner.fd_table[fd_usz] {
            match &file.fclass {
                FileClass::File(f) => {
                    //let oflags = OpenFlags::from_bits(flags).unwrap();
                    // 需要新建文件
                    if oflags.contains(OpenFlags::CREATE){ 
                        if let Some(tar_f) = f.create(path.as_str(), DiskInodeType::File){ 
                            let fd = inner.alloc_fd();
                            inner.fd_table[fd] = Some( FileDescripter::new(
                                oflags.contains(OpenFlags::CLOEXEC),
                                FileClass::File(tar_f)
                            ));
                            return fd as isize
                        }else{
                            //panic!("open failed");
                            return -1;
                        }
                    }
                    // 正常打开文件
                    if let Some(tar_f) = f.find(path.as_str(), oflags){
                        let fd = inner.alloc_fd();
                        inner.fd_table[fd] = Some( FileDescripter::new(
                            oflags.contains(OpenFlags::CLOEXEC),
                            FileClass::File(tar_f)
                        ));
                        fd as isize
                    }else{
                        //panic!("open failed");
                        return -1;
                    }
                },
                _ => return -1, // 如果是抽象类文件，不能open
            }
        } else {
            return -1
        }
    }
    
}

pub fn sys_ioctl(fd:usize, cmd:u32, arg:usize)->isize{
    let token = current_user_token();
    let task = current_task().unwrap();
    let inner = task.acquire_inner_lock();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if let Some(file) = &inner.fd_table[fd] {
        let file: Arc<dyn File + Send + Sync> = match &file.fclass {
            FileClass::Abstr(f)=> {f.clone()},
            FileClass::File(f)=>{f.clone()},
            _ => return -1,
        };
        drop(inner);
        return file.ioctl(cmd, arg)
    } else {
        return -1
    }
}

pub fn sys_mkdir(dirfd:isize, path: *const u8, mode:u32)->isize{
    let token = current_user_token();
    let task = current_task().unwrap();
    let inner = task.acquire_inner_lock();
    let path = translated_str(token, path);
    if dirfd == AT_FDCWD {
        let work_path = inner.current_path.clone();
        if let Some(inode) = open(
            inner.get_work_path().as_str(),
            path.as_str(),
            OpenFlags::CREATE,
            DiskInodeType::Directory
        ) {
            return 0
        } else {
            return -1
        }
    } else {
        // DEBUG: 获取dirfd的OSInode
        let fd_usz = dirfd as usize;
        if fd_usz >= inner.fd_table.len() && fd_usz > FD_LIMIT {
            return -1
        }
        if let Some(file) = &inner.fd_table[fd_usz] {
            match &file.fclass {
                FileClass::File(f) => {
                    if let Some(new_dir) = f.create(path.as_str(), DiskInodeType::Directory){
                        return 0;
                    }else{
                        return -1;
                    }
                },
                _ => return -1,
            }
        } else {
            return -1
        }
    }
}