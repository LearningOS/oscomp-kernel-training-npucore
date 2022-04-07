use crate::fs::{ch_dir, list_files, make_pipe, open, pselect, DiskInodeType, OpenFlags, PollFd};
use crate::fs::{
    ppoll, Dirent, FdSet, File, FileDescriptor, FileLike, Kstat, NewStat, NullZero, MNT_TABLE, TTY,
};
use crate::lang_items::Bytes;
use crate::mm::{
    copy_from_user, copy_from_user_array, copy_to_user_array, translated_byte_buffer,
    translated_byte_buffer_append_to_existed_vec, translated_ref, translated_refmut,
    translated_str, MapPermission, UserBuffer,
};
use crate::task::FdTable;
use crate::task::{current_task, current_user_token};
use crate::timer::{TimeSpec, TimeVal};
use crate::{move_ptr_to_opt, ptr_to_opt_ref, ptr_to_opt_ref_mut};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::size_of;
use core::ptr::{null, null_mut};
use log::{debug, error, info, trace, warn};

use super::errno::*;

const AT_FDCWD: isize = -100;
pub const FD_LIMIT: usize = 128;

pub fn sys_getcwd(buf: usize, size: usize) -> isize {
    let task = current_task().unwrap();
    let inner = task.acquire_inner_lock();
    if !inner
        .memory_set
        .contains_valid_buffer(buf, size, MapPermission::W)
    {
        // buf points to a bad address.
        return EFAULT;
    }
    if size == 0 && buf != 0 {
        // The size argument is zero and buf is not a NULL pointer.
        return EINVAL;
    }
    if inner.current_path.len() >= size {
        // The size argument is less than the length of the absolute pathname of the working directory,
        // including the terminating null byte.
        return ERANGE;
    }
    let token = inner.get_user_token();
    UserBuffer::new(translated_byte_buffer(token, buf as *const u8, size))
        .write(inner.current_path.as_bytes());
    buf as isize
}

bitflags! {
    pub struct SeekWhence: usize {
        const SEEK_SET  =   0; /* set to offset bytes.  */
        const SEEK_CUR  =   1; /* set to its current location plus offset bytes.  */
        const SEEK_END  =   2; /* set to the size of the file plus offset bytes.  */
    }
}

pub fn sys_lseek(fd: usize, offset: usize, whence: usize) -> isize {
    // whence is not valid
    let whence = match SeekWhence::from_bits(whence) {
        Some(whence) => whence,
        None => return EINVAL,
    };
    info!(
        "[sys_lseek] fd: {}, offset: {}, whence: {:?}",
        fd, offset, whence,
    );
    let task = current_task().unwrap();
    let inner = task.acquire_inner_lock();
    // fd is not a valid file descriptor
    if fd >= inner.fd_table.len() || inner.fd_table[fd].is_none() {
        return EBADF;
    }
    let file_descriptor = inner.fd_table[fd].as_ref().unwrap();
    match &file_descriptor.file {
        // On Linux, using lseek() on a terminal device returns ESPIPE
        FileLike::Abstract(_) => return ESPIPE,
        // whence should be check in lseek
        FileLike::Regular(file) => file.lseek(offset as isize, whence),
    }
}

pub fn sys_read(fd: usize, buf: usize, count: usize) -> isize {
    let task = current_task().unwrap();
    let inner = task.acquire_inner_lock();
    // fd is not a valid file descriptor
    if fd >= inner.fd_table.len() || inner.fd_table[fd].is_none() {
        return EBADF;
    }
    let file_descriptor = inner.fd_table[fd].as_ref().unwrap();
    let file: Arc<dyn File + Send + Sync> = match &file_descriptor.file {
        FileLike::Abstract(file) => file.clone(),
        FileLike::Regular(file) => file.clone(),
    };
    // fd is not open for reading
    if !file.readable() {
        return EBADF;
    }
    // buf is outside your accessible address space.
    if !inner
        .memory_set
        .contains_valid_buffer(buf, count, MapPermission::W)
    {
        return EFAULT;
    }
    let token = inner.get_user_token();
    drop(inner);
    file.read(UserBuffer::new(translated_byte_buffer(
        token,
        buf as *const u8,
        count,
    ))) as isize
}

pub fn sys_write(fd: usize, buf: usize, count: usize) -> isize {
    let task = current_task().unwrap();
    let inner = task.acquire_inner_lock();
    // fd is not a valid file descriptor
    if fd >= inner.fd_table.len() || inner.fd_table[fd].is_none() {
        return EBADF;
    }
    let file_descriptor = inner.fd_table[fd].as_ref().unwrap();
    let file: Arc<dyn File + Send + Sync> = match &file_descriptor.file {
        FileLike::Abstract(file) => file.clone(),
        FileLike::Regular(file) => file.clone(),
    };
    // fd is not open for writing
    if !file.writable() {
        return EBADF;
    }
    // buf is outside your accessible address space.
    if !inner
        .memory_set
        .contains_valid_buffer(buf, count, MapPermission::R)
    {
        return EFAULT;
    }
    let token = inner.get_user_token();
    drop(inner);
    file.write(UserBuffer::new(translated_byte_buffer(
        token,
        buf as *const u8,
        count,
    ))) as isize
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IOVec {
    iov_base: *const u8, /* Starting address */
    iov_len: usize,      /* Number of bytes to transfer */
}

pub fn sys_readv(fd: usize, iov: usize, iovcnt: usize) -> isize {
    let task = current_task().unwrap();
    let inner = task.acquire_inner_lock();
    // fd is not a valid file descriptor
    if fd >= inner.fd_table.len() || inner.fd_table[fd].is_none() {
        return EBADF;
    }
    let file_descriptor = inner.fd_table[fd].as_ref().unwrap();
    let file: Arc<dyn File + Send + Sync> = match &file_descriptor.file {
        FileLike::Abstract(file) => file.clone(),
        FileLike::Regular(file) => file.clone(),
    };
    // fd is not open for reading
    if !file.readable() {
        return EBADF;
    }
    let token = inner.get_user_token();
    drop(inner);
    let mut iovecs = Vec::<IOVec>::with_capacity(iovcnt);
    copy_from_user_array(token, iov as *const IOVec, iovecs.as_mut_ptr(), iovcnt);
    unsafe { iovecs.set_len(iovcnt) };
    file.read(UserBuffer::new(iovecs.iter().fold(
        Vec::new(),
        |buffer, iovec| {
            // This function aims to avoid the extra cost caused by `Vec::append` (it moves data on heap)
            translated_byte_buffer_append_to_existed_vec(
                Some(buffer),
                token,
                iovec.iov_base,
                iovec.iov_len,
            )
        },
    ))) as isize
}

pub fn sys_writev(fd: usize, iov: usize, iovcnt: usize) -> isize {
    let task = current_task().unwrap();
    let inner = task.acquire_inner_lock();
    // fd is not a valid file descriptor
    if fd >= inner.fd_table.len() || inner.fd_table[fd].is_none() {
        return EBADF;
    }
    let file_descriptor = inner.fd_table[fd].as_ref().unwrap();
    let file: Arc<dyn File + Send + Sync> = match &file_descriptor.file {
        FileLike::Abstract(file) => file.clone(),
        FileLike::Regular(file) => file.clone(),
    };
    // fd is not open for writing
    if !file.writable() {
        return EBADF;
    }
    let token = inner.get_user_token();
    drop(inner);
    let mut iovecs = Vec::<IOVec>::with_capacity(iovcnt);
    copy_from_user_array(token, iov as *const IOVec, iovecs.as_mut_ptr(), iovcnt);
    unsafe { iovecs.set_len(iovcnt) };
    file.write(UserBuffer::new(iovecs.iter().fold(
        Vec::new(),
        |buffer, iovec| {
            // This function aims to avoid the extra cost caused by `Vec::append` (it moves data on heap)
            translated_byte_buffer_append_to_existed_vec(
                Some(buffer),
                token,
                iovec.iov_base,
                iovec.iov_len,
            )
        },
    ))) as isize
}

/// If offset is not NULL, then it points to a variable holding the
/// file offset from which sendfile() will start reading data from
/// in_fd.
///
/// When sendfile() returns,
/// this variable will be set to the offset of the byte following
/// the last byte that was read.
///
/// If offset is not NULL, then sendfile() does not modify the file
/// offset of in_fd; otherwise the file offset is adjusted to reflect
/// the number of bytes read from in_fd.
///
/// If offset is NULL, then data will be read from in_fd starting at
/// the file offset, and the file offset will be updated by the call.
pub fn sys_sendfile(out_fd: usize, in_fd: usize, offset: usize, count: usize) -> isize {
    let task = current_task().unwrap();
    let inner = task.acquire_inner_lock();
    if in_fd >= inner.fd_table.len()
        || inner.fd_table[in_fd].is_none()
        || out_fd >= inner.fd_table.len()
        || inner.fd_table[out_fd].is_none()
    {
        return EBADF;
    }
    info!("[sys_sendfile] outfd: {}, in_fd: {}", out_fd, in_fd);
    let in_file = match &inner.fd_table[in_fd].as_ref().unwrap().file {
        // The in_fd argument must correspond to a file which supports mmap-like operations
        FileLike::Abstract(_) => return EINVAL,
        FileLike::Regular(file) => {
            // fd is not open for reading
            if !file.readable() {
                return EBADF;
            }
            file.clone()
        }
    };
    let out = inner.fd_table[out_fd].as_ref().unwrap();
    let out_file = match &out.file {
        FileLike::Abstract(file) => {
            // fd is not open for writing
            if !file.writable() {
                return EBADF;
            }
            file.clone()
        }
        FileLike::Regular(file) => {
            // fd is not open for writing
            if !file.writable() {
                return EBADF;
            }
            file.clone()
        }
    };
    let token = inner.get_user_token();
    drop(inner);

    let mut _foo : usize = 0;
    let mut user_offset_ptr : &mut usize = &mut _foo;
    let mut offset = if offset == 0 {
        None
    } else {
        user_offset_ptr = translated_refmut(token, offset as *mut usize);
        Some(*user_offset_ptr)
    };
    // a buffer in kernel
    const BUFFER_SIZE : usize = 4096;
    let mut buffer = Vec::<u8>::with_capacity(BUFFER_SIZE);

    let mut left_bytes = count;
    let mut write_size = 0;
    loop {
        unsafe { buffer.set_len(left_bytes.min(BUFFER_SIZE));}
        let read_size = in_file.kread(offset.as_mut(), buffer.as_mut_slice());
        if read_size == 0 {break;}
        unsafe { buffer.set_len(read_size);}
        write_size += out_file.kwrite(None, buffer.as_slice());
        left_bytes -= read_size;
    }

    if let Some(offset) = offset {
        *user_offset_ptr = offset;
    }
    
    info!("[sys_sendfile] written bytes: {}", write_size);
    write_size as isize
}

pub fn sys_open(path: *const u8, flags: usize) -> isize {
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

        inner.fd_table[fd] = Some(FileDescriptor::new(
            OpenFlags::from_bits(flags)
                .unwrap()
                .contains(OpenFlags::O_CLOEXEC),
            FileLike::Regular(inode),
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
    if fd >= inner.fd_table.len() || inner.fd_table[fd].is_none() {
        return EBADF;
    }
    inner.fd_table[fd].take();
    SUCCESS
}

bitflags! {
    struct PipeFlags: usize {
        const O_CLOEXEC     =   02000000;
        const O_DIRECT	    =   00040000;
        const O_NONBLOCK    =   00004000;
    }
}

/// # Warning
/// Only O_CLOEXEC is supported now
pub fn sys_pipe2(pipefd: usize, flags: usize) -> isize {
    let flags = match PipeFlags::from_bits(flags) {
        Some(flags) => flags,
        None => return EINVAL,
    };
    let task = current_task().unwrap();
    let mut inner = task.acquire_inner_lock();
    let (pipe_read, pipe_write) = make_pipe();
    let read_fd = inner.alloc_fd();
    inner.fd_table[read_fd] = Some(FileDescriptor::new(
        flags.contains(PipeFlags::O_CLOEXEC),
        FileLike::Abstract(pipe_read),
    ));
    let write_fd = inner.alloc_fd();
    inner.fd_table[write_fd] = Some(FileDescriptor::new(
        flags.contains(PipeFlags::O_CLOEXEC),
        FileLike::Abstract(pipe_write),
    ));
    let token = inner.get_user_token();
    drop(inner);
    copy_to_user_array(
        token,
        [read_fd as u32, write_fd as u32].as_ptr(),
        pipefd as *mut u32,
        2,
    );
    info!(
        "[sys_pipe2] read_fd: {}, write_fd: {}, flags: {:?}",
        read_fd, write_fd, flags
    );
    SUCCESS
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
            OpenFlags::O_RDONLY,
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
            match &file.file {
                FileLike::Regular(f) => {
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

pub fn sys_dup(oldfd: usize) -> isize {
    let task = current_task().unwrap();
    let mut inner = task.acquire_inner_lock();
    if oldfd >= inner.fd_table.len() || inner.fd_table[oldfd].is_none() {
        return EBADF;
    }
    let newfd = inner.alloc_fd();
    inner.fd_table[newfd] = Some(inner.fd_table[oldfd].as_ref().unwrap().clone());
    newfd as isize
}

pub fn sys_dup3(oldfd: usize, newfd: usize, flags: usize) -> isize {
    let task = current_task().unwrap();
    let mut inner = task.acquire_inner_lock();
    if oldfd >= inner.fd_table.len() || inner.fd_table[oldfd].is_none() {
        return EBADF;
    }
    if oldfd == newfd {
        return EINVAL;
    }
    inner.fd_table[newfd] = Some(inner.fd_table[oldfd].as_ref().unwrap().clone());
    newfd as isize
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
            OpenFlags::O_RDONLY,
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
            match &file.file {
                FileLike::Regular(f) => {
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
            OpenFlags::O_RDONLY,
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
            match &file.file {
                FileLike::Regular(f) => {
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

pub fn sys_open_at(dirfd: isize, path: *const u8, flags: usize, mode: u32) -> isize {
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
                FileLike::Abstract(TTY.clone())
            } else if path.contains("null") {
                FileLike::Abstract(Arc::new(NullZero::new(true)))
            } else if path.contains("zero") {
                FileLike::Abstract(Arc::new(NullZero::new(false)))
            } else {
                return -1;
            }
        };

        inner.fd_table[fd] = Some(FileDescriptor::new(false, fclass));
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
            inner.fd_table[fd] = Some(FileDescriptor::new(
                oflags.contains(OpenFlags::O_CLOEXEC),
                FileLike::Regular(inode),
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
            match &file.file {
                FileLike::Regular(f) => {
                    //let oflags = OpenFlags::from_bits(flags).unwrap();
                    // 需要新建文件
                    if oflags.contains(OpenFlags::O_CREAT) {
                        if let Some(tar_f) = f.create(path.as_str(), DiskInodeType::File) {
                            let fd = inner.alloc_fd();
                            inner.fd_table[fd] = Some(FileDescriptor::new(
                                oflags.contains(OpenFlags::O_CLOEXEC),
                                FileLike::Regular(tar_f),
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
                        inner.fd_table[fd] = Some(FileDescriptor::new(
                            oflags.contains(OpenFlags::O_CLOEXEC),
                            FileLike::Regular(tar_f),
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
        let file: Arc<dyn File + Send + Sync> = match &file.file {
            FileLike::Abstract(f) => f.clone(),
            FileLike::Regular(f) => f.clone(),
            _ => return -1,
        };
        drop(inner);
        return file.ioctl(cmd, arg);
    } else {
        return -1;
    }
}
pub fn sys_ppoll(poll_fd: usize, nfds: usize, time_spec: usize, sigmask: usize) -> isize {
    ppoll(
        poll_fd,
        nfds,
        time_spec,
        sigmask as *const crate::task::Signals,
    )
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
            OpenFlags::O_CREAT,
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
            match &file.file {
                FileLike::Regular(f) => {
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
                if arg != 1 && arg != 0 {
                    warn!("[fcntl] Unsupported flag exists.{}", arg);
                }
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
            _ => {
                warn!("[fcntl] Unsupported command!");
                return 0;
            } // WARNING!!!
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

pub fn sys_pselect(
    nfds: usize,
    read_fds: *mut FdSet,
    write_fds: *mut FdSet,
    exception_fds: *mut FdSet,
    timeout: *const TimeSpec,
    sigmask: *const crate::task::signal::Signals,
) -> isize {
    if (nfds as isize) < 0 {
        return -1;
    }
    let token = current_user_token();
    pselect(
        nfds,
        ptr_to_opt_ref_mut!(token, read_fds),
        ptr_to_opt_ref_mut!(token, write_fds),
        ptr_to_opt_ref_mut!(token, exception_fds),
        ptr_to_opt_ref!(token, timeout),
        sigmask,
    )
}

/// umask() sets the calling process's file mode creation mask (umask) to
/// mask & 0777 (i.e., only the file permission bits of mask are used),
/// and returns the previous value of the mask.
/// # WARNING
/// Fake implementation
pub fn sys_umask(mask: usize) -> isize {
    warn!("[sys_umask] fake implementation! Do nothing and return 0.");
    0
}
