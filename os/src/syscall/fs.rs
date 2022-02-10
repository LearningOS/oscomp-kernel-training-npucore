use crate::fs::{ch_dir, list_files, make_pipe, open, pselect, DiskInodeType, OpenFlags, PollFd};
use crate::fs::{
    ppoll, Dirent, FdSet, File, FileClass, FileDescripter, IoVec, IoVecs, Kstat, NewStat, NullZero,
    MNT_TABLE, TTY,
};
use crate::lang_items::Bytes;
use crate::mm::{
    copy_from_user, translated_byte_buffer, translated_ref, translated_refmut, translated_str,
    UserBuffer,
};
use crate::task::FdTable;
use crate::task::{current_task, current_user_token};
use crate::timer::{TimeSpec, TimeVal};
use crate::{move_ptr_to_opt, ptr_to_opt_ref, ptr_to_opt_ref_mut};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::size_of;
use core::ptr::{null, null_mut};
use core::slice::from_raw_parts_mut;
use log::{debug, error, info, trace, warn};

const AT_FDCWD: isize = -100;
pub const FD_LIMIT: usize = 128;

pub fn sys_getcwd(buf: *mut u8, len: usize) -> isize {
    let token = current_user_token();
    let task = current_task().unwrap();
    let buf_vec = translated_byte_buffer(token, buf, len);
    let inner = task.acquire_inner_lock();

    let mut userbuf = UserBuffer::new(buf_vec);
    let current_offset: usize = 0;
    if buf as usize == 0 {
        return 0;
    } else {
        let cwd = inner.current_path.as_bytes();
        userbuf.write(cwd);
        return buf as isize;
    }
}
pub fn sys_lseek(fd: usize, offset: usize, whence: usize) -> isize {
    let token = current_user_token();
    let task = current_task().unwrap();
    let inner = task.acquire_inner_lock();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if let Some(file) = &inner.fd_table[fd] {
        let ret = match &file.fclass {
            FileClass::File(f) => {
                /*print!("\n");*/
                info!("lseek(fd={},offset={},whence={}), ", fd, offset, whence);
                //f.clone();

                f.lseek(offset as isize, whence as i32) as isize
            }
            _ => -1,
        };
        drop(inner);
        ret
    } else {
        -1
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
            FileClass::Abstr(f) => f.clone(),
            FileClass::File(f) => {
                /*print!("\n");*/
                f.clone()
            }
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

pub fn sys_writev(fd: usize, iov_ptr: usize, iov_num: usize) -> isize {
    let iov_head = iov_ptr as *mut IoVec;

    let token = current_user_token();
    let task = current_task().unwrap();
    let inner = task.acquire_inner_lock();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if let Some(file) = &inner.fd_table[fd] {
        let f: Arc<dyn File + Send + Sync> = match &file.fclass {
            FileClass::Abstr(f) => f.clone(),
            FileClass::File(f) => f.clone(),
            _ => return -1,
        };
        if !f.writable() {
            return -1;
        }
        drop(inner);
        unsafe {
            let buf = UserBuffer::new(IoVecs::new(iov_head, iov_num, token).0);
            f.write(buf) as isize
        }
    } else {
        -1
    }
}

/* return the num of bytes */
pub fn sys_sendfile(out_fd: isize, in_fd: isize, offset_ptr: *mut usize, count: usize) -> isize {
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

    if let Some(file_in) = &inner.fd_table[in_fd as usize] {
        // file_in exists
        match &file_in.fclass {
            FileClass::File(fin) => {
                if let Some(file_out) = &inner.fd_table[out_fd as usize] {
                    //file_out exists
                    match &file_out.fclass {
                        FileClass::File(fout) => {
                            if offset_ptr as usize != 0 {
                                //won't influence file.offset
                                let offset = translated_refmut(token, offset_ptr);
                                let data = fin.read_vec(*offset as isize, count);
                                let wlen = fout.write_all(&data);
                                *offset += wlen;
                                return wlen as isize;
                            } else {
                                //use file.offset
                                let data = fin.read_vec(-1, count);
                                let wlen = fout.write_all(&data);
                                return wlen as isize;
                            }
                        }
                        _ => return -1,
                    }
                } else {
                    return -1;
                }
            }
            _ => return -1,
        }
    } else {
        return -1;
    }
}
/// A read mirror to writev(). Read the file denoted by fd according to what was recorded in vector [IoVec;iovcnt].
///
/// The  readv()  system call reads iovcnt buffers from the file associated with the file descriptor fd into the buffers described by iov ("scatter input").
pub fn sys_readv(fd: usize, iov: *const IoVec, iovcnt: usize) -> isize {
    let iov_head = iov as *mut IoVec;
    let token = current_user_token();
    let task = current_task().unwrap();
    let inner = task.acquire_inner_lock();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if let Some(file) = &inner.fd_table[fd] {
        let mut sum: isize = 0;
        let f: Arc<dyn File + Send + Sync> = match &file.fclass {
            FileClass::Abstr(f) => f.clone(),
            FileClass::File(f) => f.clone(),
            _ => return -1,
        };
        if !f.writable() {
            return -1;
        }
        drop(inner);
        unsafe {
            let buf = UserBuffer::new(IoVecs::new(iov_head, iovcnt, token).0);
            f.read(buf) as isize
        }
    } else {
        -1
    }
}

pub fn sys_crosselect(
    nfds: usize,
    read_fds: *mut u8,
    write_fds: *mut u8,
    exception_fds: *mut u8,
    timeout: *mut usize,
) -> isize {
    if nfds < 0 {
        return -1;
    }
    let token = current_user_token();
    sys_crossselect1(nfds, read_fds, write_fds, exception_fds, timeout)
}

pub fn sys_crossselect1(
    nfds: usize,
    readfds: *mut u8,
    writefds: *mut u8,
    exceptfds: *mut u8,
    timeout: *mut usize,
) -> isize {
    let task = current_task().unwrap();
    let token = current_user_token();

    let mut r_ready_count = 0;
    let mut w_ready_count = 0;
    let mut e_ready_count = 0;

    let mut timer_interval = crate::timer::TimeVal::new();
    unsafe {
        let sec = translated_ref(token, timeout);
        let usec = translated_ref(token, timeout.add(1));
        timer_interval.tv_sec = *sec as u32;
        timer_interval.tv_usec = *usec as u32;
    }
    log::info!("timeout {:?}", timer_interval);
    let mut timer = timer_interval + crate::timer::TimeVal::now();
    let mut time_up = false;
    let mut r_has_nready = false;
    let mut r_all_ready = false;
    let mut w_has_nready = false;
    let mut w_all_ready = false;

    let mut rfd_set = FdSet::empty();
    let mut wfd_set = FdSet::empty();

    let mut ubuf_rfds = {
        if readfds as usize != 0 {
            UserBuffer::new(translated_byte_buffer(token, readfds, size_of::<FdSet>()))
        } else {
            UserBuffer::empty()
        }
    };
    ubuf_rfds.read(rfd_set.as_bytes_mut());

    let mut ubuf_wfds = {
        if writefds as usize != 0 {
            UserBuffer::new(translated_byte_buffer(token, writefds, size_of::<FdSet>()))
        } else {
            UserBuffer::empty()
        }
    };
    ubuf_wfds.read(wfd_set.as_bytes_mut());

    let mut ubuf_efds = {
        if exceptfds as usize != 0 {
            UserBuffer::new(translated_byte_buffer(token, exceptfds, size_of::<FdSet>()))
        } else {
            UserBuffer::empty()
        }
    };

    drop(task);
    let mut done = false;
    let mut ret = 0isize;
    let mut r_type = 0;
    let mut trg = crate::timer::TimeVal::now() + timer_interval;
    loop {
        /* handle read fd set */

        let task = current_task().unwrap();
        let inner = task.acquire_inner_lock();
        let fd_table = &inner.fd_table;
        macro_rules! do_chk {
            ($func:ident,$file:ident,$i:ident,$r:literal) => {
                if $file.$func() {
                    done = true;
                    r_type = $r;
                    ret = $i as isize;
                    break;
                }
            };
        }
        macro_rules! chk_fds {
            ($fds:ident,$fd_set:ident,$func:ident,$ubuf:ident,$r:literal) => {
                if $fds as usize != 0 {
                    for i in 0..nfds {
                        if i == 1024 || !$fd_set.is_set(i) || fd_table[i].is_none() {
                            continue;
                        }
                        if i > fd_table.len() {
                            return -1; // invalid fd
                        }
                        log::warn!("[ultra_select] i: {}", i);
                        let fds = fd_table[i].as_ref().unwrap();
                        match &fds.fclass {
                            FileClass::Abstr(file) => {
                                do_chk!($func, file, i, $r);
                            }
                            FileClass::File(file) => {
                                do_chk!($func, file, i, $r);
                            }
                        }
                    }
                }
            };
        }

        chk_fds!(readfds, rfd_set, r_ready, ubuf_rfds, 1);

        /* chk_fds!(
         *     writefds,
         *     wfd_set,
         *     wfd_vec,
         *     w_all_ready,
         *     w_has_nready,
         *     w_ready_count,
         *     w_ready,
         *     ubuf_wfds
         * ); */

        /* Cannot handle exceptfds for now */
        if exceptfds as usize != 0 {
            //let mut ubuf_efds = UserBuffer::new(
            //    translated_byte_buffer(token, exceptfds, size_of::<FdSet>())
            //);
            let mut efd_set = FdSet::empty();
            ubuf_efds.read(efd_set.as_bytes_mut());
            e_ready_count = efd_set.set_num() as isize;
            efd_set.clr_all();
            ubuf_efds.write(efd_set.as_bytes());
        }

        // return anyway
        //return r_ready_count + w_ready_count + e_ready_count;
        // if there are some fds not ready, just wait until time up
        if done {
            //println!("timer = {}", timer );
            ret = 1;
            if readfds as usize != 0 {
                rfd_set.clr_all();
                if r_type == 1 {
                    rfd_set.set(ret as usize);
                }
            }
            if writefds as usize != 0 {
                wfd_set.clr_all();
                if r_type == 2 {
                    rfd_set.set(ret as usize);
                }
            }
            ubuf_rfds.write(rfd_set.as_bytes());
            ubuf_wfds.write(wfd_set.as_bytes());
            break;
        }
        ret = 0;
        if (trg - TimeVal::now()).to_us() == 0 {
            break;
        }
        drop(fd_table);
        drop(inner);
        drop(task);
        crate::task::suspend_current_and_run_next();
    }
    println!("[ultrasel] ret: {}", ret);
    return ret;
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
            FileClass::Abstr(f) => f.clone(),
            FileClass::File(f) => {
                /*print!("\n");*/
                f.clone()
            }
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
            OpenFlags::from_bits(flags)
                .unwrap()
                .contains(OpenFlags::CLOEXEC),
            FileClass::File(inode),
        ));
        drop(inner);
        fd as isize
    } else {
        -1
    }
}

pub fn sys_close(fd: usize) -> isize {
    info!("[sys_close] fd:{}", fd);
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
    let pipe = unsafe { pipe as *mut i32 };
    let task = current_task().unwrap();
    let token = current_user_token();
    let mut inner = task.acquire_inner_lock();
    let (pipe_read, pipe_write) = make_pipe();
    let read_fd = inner.alloc_fd();
    inner.fd_table[read_fd] = Some(FileDescripter::new(false, FileClass::Abstr(pipe_read)));
    let write_fd = inner.alloc_fd();
    inner.fd_table[write_fd] = Some(FileDescripter::new(false, FileClass::Abstr(pipe_write)));
    *translated_refmut(token, pipe) = read_fd as i32;
    *translated_refmut(token, unsafe { pipe.add(1) }) = write_fd as i32;
    0
}

pub fn sys_getdents64(fd: isize, buf: *mut u8, len: usize) -> isize {
    //return 0;
    //println!("=====================================");
    let token = current_user_token();
    let task = current_task().unwrap();
    let buf_vec = translated_byte_buffer(token, buf, len);
    let inner = task.acquire_inner_lock();
    let dent_len = size_of::<Dirent>();
    //let max_num = len / dent_len;
    let mut total_len: usize = 0;
    // 使用UserBuffer结构，以便于跨页读写
    let mut userbuf = UserBuffer::new(buf_vec);
    let mut dirent = Dirent::empty();
    if fd == AT_FDCWD {
        let work_path = inner.current_path.clone();
        if let Some(file) = open(
            "/",
            work_path.as_str(),
            OpenFlags::RDONLY,
            DiskInodeType::Directory,
        ) {
            loop {
                if total_len + dent_len > len {
                    break;
                }
                if file.getdirent(&mut dirent) > 0 {
                    userbuf.write_at(total_len, dirent.as_bytes());
                    total_len += dent_len;
                } else {
                    break;
                }
            }
            info!("[sys_getdents64] fd:{}, len:{} = {}", fd, len, total_len);
            return total_len as isize; //warning
        } else {
            info!("[sys_getdents64] fd:{}, len:{} = {}", fd, len, -1);
            return -1;
        }
    } else {
        let fd_usz = fd as usize;
        if fd_usz >= inner.fd_table.len() && fd_usz > FD_LIMIT {
            return -1;
        }
        if let Some(file) = &inner.fd_table[fd_usz] {
            match &file.fclass {
                FileClass::File(f) => {
                    loop {
                        if total_len + dent_len > len {
                            break;
                        }
                        if f.getdirent(&mut dirent) > 0 {
                            userbuf.write_at(total_len, dirent.as_bytes());
                            total_len += dent_len;
                        } else {
                            break;
                        }
                    }
                    info!("[sys_getdents64] fd:{}, len:{} = {}", fd, len, total_len);
                    return total_len as isize; //warning
                }
                _ => {
                    info!("[sys_getdents64] fd:{} = {}", fd, -1);
                    return -1;
                }
            }
        } else {
            return -1;
        }
    }
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
pub fn sys_readlinkat(dirfd: isize, pathname: *const u8, buf: *mut u8, bufsiz: usize) -> isize {
    if dirfd == AT_FDCWD {
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

        let len = procinfo.len() - 1;
        info!(
            "[sys_readlinkat] dirfd = {}, pathname = {}, *buf = 0x{:X}, bufsiz = {}, len = {}",
            dirfd, path, buf as usize, bufsiz, len
        );

        return len as isize;
    } else {
        panic!("sys_readlinkat: fd not support");
    }
}

pub fn sys_newfstatat(fd: isize, path: *const u8, buf: *mut u8, flag: u32) -> isize {
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
            DiskInodeType::Directory,
        ) {
            file.get_newstat(&mut stat);
            //file.get_fstat(&mut stat);

            info!(
                "[sys_newfstatat] fd = {}, path = {:?}, buff addr = 0x{:X}, size = {}",
                fd, path, buf as usize, stat.st_size
            );

            userbuf.write(stat.as_bytes());
            return 0;
        } else {
            return -2;
        }
    } else {
        let fd_usz = fd as usize;
        if fd_usz >= inner.fd_table.len() && fd_usz > FD_LIMIT {
            return -1;
        }
        if let Some(file) = &inner.fd_table[fd_usz] {
            match &file.fclass {
                FileClass::File(f) => {
                    f.get_newstat(&mut stat);
                    //f.get_fstat(&mut stat);
                    userbuf.write(stat.as_bytes());
                    return 0;
                }
                _ => return -1,
            }
        } else {
            return -2;
        }
    }
}

pub fn sys_fstat(fd: isize, buf: *mut u8) -> isize {
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
            DiskInodeType::Directory,
        ) {
            file.get_fstat(&mut kstat);

            info!("[syscall_fstat] fd = {}, size = {}", fd, kstat.st_size);

            userbuf.write(kstat.as_bytes());
            return 0;
        } else {
            return -1;
        }
    } else {
        let fd_usz = fd as usize;
        if fd_usz >= inner.fd_table.len() && fd_usz > FD_LIMIT {
            return -1;
        }
        if let Some(file) = &inner.fd_table[fd_usz] {
            match &file.fclass {
                FileClass::File(f) => {
                    f.get_fstat(&mut kstat);
                    userbuf.write(kstat.as_bytes());

                    info!("[sys_fstat] fd:{}; size:{}", fd, kstat.st_size);
                    return 0;
                }
                _ => {
                    let kstat = Kstat::new_abstract();
                    userbuf.write(kstat.as_bytes());
                    info!("[sys_fstat] fd:{}; size:{}", fd, kstat.st_size);
                    return 0; //warning
                }
            }
        } else {
            return -1;
        }
    }
}

pub fn sys_open_at(dirfd: isize, path: *const u8, flags: u32, mode: u32) -> isize {
    let task = current_task().unwrap();
    let token = current_user_token();
    // 这里传入的地址为用户的虚地址，因此要使用用户的虚地址进行映射
    let path = translated_str(token, path);
    info!("[sys_openat] path:{}", path);
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
                return -1;
            }
        };

        inner.fd_table[fd] = Some(FileDescripter::new(false, fclass));
        return fd as isize;
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
            DiskInodeType::File,
        ) {
            let fd = inner.alloc_fd();
            inner.fd_table[fd] = Some(FileDescripter::new(
                oflags.contains(OpenFlags::CLOEXEC),
                FileClass::File(inode),
            ));
            fd as isize
        } else {
            //panic!("open failed");
            -1
        }
    } else {
        let fd_usz = dirfd as usize;
        if fd_usz >= inner.fd_table.len() && fd_usz > FD_LIMIT {
            return -1;
        }
        if let Some(file) = &inner.fd_table[fd_usz] {
            match &file.fclass {
                FileClass::File(f) => {
                    //let oflags = OpenFlags::from_bits(flags).unwrap();
                    // 需要新建文件
                    if oflags.contains(OpenFlags::CREATE) {
                        if let Some(tar_f) = f.create(path.as_str(), DiskInodeType::File) {
                            let fd = inner.alloc_fd();
                            inner.fd_table[fd] = Some(FileDescripter::new(
                                oflags.contains(OpenFlags::CLOEXEC),
                                FileClass::File(tar_f),
                            ));
                            return fd as isize;
                        } else {
                            //panic!("open failed");
                            return -1;
                        }
                    }
                    // 正常打开文件
                    if let Some(tar_f) = f.find(path.as_str(), oflags) {
                        let fd = inner.alloc_fd();
                        inner.fd_table[fd] = Some(FileDescripter::new(
                            oflags.contains(OpenFlags::CLOEXEC),
                            FileClass::File(tar_f),
                        ));
                        fd as isize
                    } else {
                        //panic!("open failed");
                        return -1;
                    }
                }
                _ => return -1, // 如果是抽象类文件，不能open
            }
        } else {
            return -1;
        }
    }
}

pub fn sys_ioctl(fd: usize, cmd: u32, arg: usize) -> isize {
    let token = current_user_token();
    let task = current_task().unwrap();
    let inner = task.acquire_inner_lock();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if let Some(file) = &inner.fd_table[fd] {
        let file: Arc<dyn File + Send + Sync> = match &file.fclass {
            FileClass::Abstr(f) => f.clone(),
            FileClass::File(f) => f.clone(),
            _ => return -1,
        };
        drop(inner);
        return file.ioctl(cmd, arg);
    } else {
        return -1;
    }
}
pub fn sys_ppoll(poll_fd: usize, nfds: usize, time_spec: usize, sigmask: usize) -> isize {
    let token = current_user_token();
    let sig = if sigmask != 0 {
        let j = *translated_ref(token, unsafe {
            sigmask as *const crate::task::signal::Signals
        });
        Some(j)
    } else {
        None
    };
    ppoll(poll_fd, nfds, time_spec, sig)
}
pub fn sys_mkdir(dirfd: isize, path: *const u8, mode: u32) -> isize {
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
            DiskInodeType::Directory,
        ) {
            return 0;
        } else {
            return -1;
        }
    } else {
        // DEBUG: 获取dirfd的OSInode
        let fd_usz = dirfd as usize;
        if fd_usz >= inner.fd_table.len() && fd_usz > FD_LIMIT {
            return -1;
        }
        if let Some(file) = &inner.fd_table[fd_usz] {
            match &file.fclass {
                FileClass::File(f) => {
                    if let Some(new_dir) = f.create(path.as_str(), DiskInodeType::Directory) {
                        return 0;
                    } else {
                        return -1;
                    }
                }
                _ => return -1,
            }
        } else {
            return -1;
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
pub const F_DUPFD_CLOEXEC: u32 = 1030; /* Duplicate file descriptor with close-on-exit set.*/
/* arg */
pub const FD_CLOEXEC: u32 = 1;

pub fn fcntl(fd: usize, cmd: u32, arg: usize) -> isize {
    let task = current_task().unwrap();
    let mut inner = task.acquire_inner_lock();

    if fd > inner.fd_table.len() {
        return -1;
    }

    info!("[sys_fcntl] fd:{}, cmd:{}, arg:{}", fd, cmd, arg);

    if let Some(file) = &mut inner.fd_table[fd] {
        match cmd {
            F_DUPFD => return dup_inc(fd, arg, &mut inner.fd_table),
            F_GETFD => return file.get_cloexec() as isize,
            F_SETFD => {
                file.set_cloexec((arg & 1) == 1);
                return 0;
            }
            F_DUPFD_CLOEXEC => {
                let new_fd = dup_inc(fd, arg, &mut inner.fd_table);
                if let Some(new_file) = &mut inner.fd_table[new_fd as usize] {
                    new_file.set_cloexec(true);
                    return new_fd;
                } else {
                    return -1;
                }
            }
            _ => return 0, // WARNING!!!
        }
    } else {
        return -1;
    }
}

/* dup the fd using the lowest-numbered available fd >= new_fd */
fn dup_inc(old_fd: usize, new_fd: usize, fd_table: &mut FdTable) -> isize {
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

pub fn sys_mypselect(
    nfds: usize,
    read_fds: *mut FdSet,
    write_fds: *mut FdSet,
    exception_fds: *mut FdSet,
    timeout: *const TimeSpec,
    sigmask: *const crate::task::signal::Signals,
) -> isize {
    if nfds < 0 {
        return -1;
    }
    let token = current_user_token();
    pselect(
        nfds,
        ptr_to_opt_ref_mut!(token, read_fds),
        ptr_to_opt_ref_mut!(token, write_fds),
        ptr_to_opt_ref_mut!(token, exception_fds),
        ptr_to_opt_ref!(token, timeout),
        ptr_to_opt_ref!(token, sigmask),
    )
}
