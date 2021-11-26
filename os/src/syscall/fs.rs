use crate::fs::{ch_dir, list_files, make_pipe, open, DiskInodeType, OpenFlags};
use crate::fs::{Dirent, FdSet, File, FileClass, FileDescripter, IoVec, IoVecs, Kstat, MNT_TABLE, NewStat, TTY, NullZero};
use crate::mm::{translated_byte_buffer, translated_refmut, translated_str, UserBuffer};
use crate::task::{current_task, current_user_token};
use alloc::sync::Arc;
use core::mem::size_of;
use crate::task::FdTable;

const AT_FDCWD:isize = -100;
pub const FD_LIMIT:usize = 128;

pub fn sys_getcwd(buf: *mut u8, len: usize) -> isize {
    let token = current_user_token();
    let task = current_task().unwrap();
    let buf_vec = translated_byte_buffer(token, buf, len);
    let inner = task.acquire_inner_lock();
    
    let mut userbuf = UserBuffer::new(buf_vec);
    let current_offset:usize = 0;
    if buf as usize == 0 {
        return 0
    } else {
        let cwd = inner.current_path.as_bytes();
        userbuf.write( cwd );
        return buf as isize
    }
}

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

pub fn sys_writev(fd:usize, iov_ptr: usize, iov_num:usize)->isize{
    let iov_head = iov_ptr as *mut IoVec;
    
    let token = current_user_token();
    let task = current_task().unwrap();
    let inner = task.acquire_inner_lock();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if let Some(file) = &inner.fd_table[fd] {
        let f: Arc<dyn File + Send + Sync> = match &file.fclass {
            FileClass::Abstr(f)=> {f.clone()},
            FileClass::File(f)=>{f.clone()},
            _ => return -1,
        };
        if !f.writable() {
            return -1;
        }
        drop(inner);
        unsafe {
            let buf = UserBuffer::new( IoVecs::new(
                iov_head,
                iov_num,
                token
            ).0);
            f.write(buf) as isize
        }   
    } else {
        -1
    }
}

/* return the num of bytes */
pub fn sys_sendfile(out_fd:isize, in_fd:isize, offset_ptr: *mut usize, count: usize)->isize {
    /* 
        If offset is not NULL, then it points to a variable holding the
        file offset from which sendfile() will start reading data from
        in_fd.  

        When sendfile() returns, 
        *** this variable will be set to the offset of the byte following 
        the last byte that was read. ***  
        
        If offset is not NULL, then sendfile() does not modify the file
        offset of in_fd; otherwise the file offset is adjusted to reflect
        the number of bytes read from in_fd.

        If offset is NULL, then data will be read from in_fd starting at
        the file offset, and the file offset will be updated by the call.
    */
    let task = current_task().unwrap();
    let token = current_user_token();
    let inner = task.acquire_inner_lock();
    
    if let Some(file_in) = &inner.fd_table[in_fd as usize]{
        // file_in exists
        match &file_in.fclass {
            FileClass::File(fin)=>{
                if let Some(file_out) = &inner.fd_table[out_fd as usize]{
                    //file_out exists
                    match &file_out.fclass {
                        FileClass::File(fout)=>{
                            if offset_ptr as usize != 0 { //won't influence file.offset                            
                                let offset = translated_refmut(token, offset_ptr);
                                let data = fin.read_vec(*offset as isize, count);
                                let wlen =  fout.write_all(&data);
                                *offset += wlen;
                                return wlen as isize
                            } else {  //use file.offset
                                let data = fin.read_vec(-1, count);
                                let wlen =  fout.write_all(&data);
                                return wlen as isize
                            }
                        }
                        _=> return -1
                    }
                } else {
                    return -1
                }
            }
            _=> return -1
        }
    } else {
        return -1
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

// This syscall is not complete at all, only /read proc/self/exe
pub fn sys_readlinkat(dirfd: isize, pathname: *const u8, buf: *mut u8, bufsiz: usize) -> isize{
    if dirfd == AT_FDCWD{
        let task = current_task().unwrap();
        let token = current_user_token();
        let path = translated_str(token, pathname);
        if path.as_str() != "/proc/self/exe" {
            panic!("sys_readlinkat: pathname not support");
        }
        let mut userbuf = UserBuffer::new(translated_byte_buffer(token, buf, bufsiz));
        //let procinfo = "/lmbench_all\0";
        let procinfo = "/busybox\0";
        let buff = procinfo.as_bytes();
        userbuf.write(buff);
        let len = procinfo.len()-1;
        println!("sys_readlinkat(dirfd = {}, pathname = {}, *buf = 0x{:X}, bufsiz = {}) = {}", dirfd, path, buf as usize, bufsiz, len);
        return len as isize;
    }
    else{
        panic!("sys_readlinkat: fd not support");
    }
    
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
                    println!("[sys_fstat] fd:{}; size:{}", fd, kstat.st_size );
                    return 0
                },
                _ => {
                    userbuf.write(Kstat::new_abstract().as_bytes());
                    println!("[sys_fstat] fd:{}; size:{}", fd, kstat.st_size );
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
    println!("[sys_openat] path:{}", path);
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

/* fcntl */
/* cmd */
pub const F_DUPFD: u32 = 0; /*  dup the fd using the lowest-numbered
                            available file descriptor greater than or equal to arg.
                            on success, return new fd*/
pub const F_GETFD: u32 = 1; /* fd flag */
pub const F_SETFD: u32 = 2;
pub const F_GETFL: u32 = 3;
pub const F_DUPFD_CLOEXEC: u32 = 1030;  /* Duplicate file descriptor with close-on-exit set.*/
/* arg */
pub const FD_CLOEXEC: u32 = 1;

pub fn fcntl(fd: usize, cmd: u32, arg: usize) -> isize {
    let task = current_task().unwrap();
    let mut inner = task.acquire_inner_lock();
    
    if fd > inner.fd_table.len() {
        return -1;
    }

    println!("fd:{}, cmd:{}, arg:{}", fd, cmd, arg);

    if let Some(file) = &mut inner.fd_table[fd] {
        match cmd {
            
            F_DUPFD => {
                return dup_inc(fd, arg, &mut inner.fd_table)
            },
            F_GETFD=> { 
                return file.get_cloexec() as isize
            }
            F_SETFD=> {
                file.set_cloexec((arg & 1) == 1);
                return 0;
            }
            F_DUPFD_CLOEXEC =>{
                let new_fd = dup_inc(fd, arg, &mut inner.fd_table);
                if let Some (new_file) = &mut inner.fd_table[new_fd as usize] {
                    new_file.set_cloexec(true);
                    return new_fd
                } else {
                    return -1
                }
            }
            _=> return 0, // WARNING!!!
        }
    } else {
        return -1;
    }    
}

/* dup the fd using the lowest-numbered available fd >= new_fd */
fn dup_inc(old_fd:usize, new_fd:usize, fd_table: &mut FdTable) -> isize {
    if old_fd >= fd_table.len() || new_fd > FD_LIMIT {
        return -1;
    }
    if fd_table[old_fd].is_none() {
        return -1;
    }
    if new_fd >= fd_table.len() {
        for i in fd_table.len()..(new_fd + 1) {
            fd_table.push(None);
        }
    }

    let mut act_fd = new_fd;
    if fd_table[new_fd].is_some() {
        act_fd = if let Some(fd) = (0..fd_table.len()).find(|fd| fd_table[*fd].is_none()) {
            fd
        } else {
            fd_table.push(None);
            fd_table.len() - 1
        }
    }
    fd_table[act_fd] = Some(fd_table[old_fd].as_ref().unwrap().clone());
    act_fd as isize
}