use crate::fs::{make_pipe, open, pselect, DiskInodeType, OpenFlags, StatMode};
use crate::fs::{
    ppoll, Dirent, FdSet, File, FileDescriptor, FileLike, Kstat, NewStat, Null, Zero, MNT_TABLE,
    TTY,
};
use crate::mm::{
    copy_from_user, copy_from_user_array, copy_to_user_array, translated_byte_buffer,
    translated_byte_buffer_append_to_existed_vec, translated_ref, translated_refmut,
    translated_str, MapPermission, UserBuffer,
};
use crate::task::{current_task, current_user_token};
use crate::timer::{TimeSpec, TimeVal};
use crate::{move_ptr_to_opt, ptr_to_opt_ref, ptr_to_opt_ref_mut};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::size_of;
use core::ptr::{null, null_mut};
use log::{debug, error, info, trace, warn};
use num_enum::FromPrimitive;

use super::errno::*;

const AT_FDCWD: usize = 100usize.wrapping_neg();

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
            // for debug
            {
                if !iovec.iov_base.is_null() {
                    let mut temp = Vec::<u8>::with_capacity(iovec.iov_len);
                    copy_from_user_array(token, iovec.iov_base, temp.as_mut_ptr(), iovec.iov_len);
                    unsafe {
                        temp.set_len(iovec.iov_len);
                    }
                    info!(
                        "[sys_writev] Iterating... content: {:?}, iovlen: {}",
                        core::str::from_utf8(temp.as_slice()),
                        iovec.iov_len
                    );
                }
            }
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
pub fn sys_sendfile(out_fd: usize, in_fd: usize, offset: *mut usize, count: usize) -> isize {
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
    let out_file = match &inner.fd_table[out_fd].as_ref().unwrap().file {
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

    // turn a pointer in user space into a pointer in kernel space if it is not null
    let offset = if offset.is_null() {
        offset
    } else {
        translated_refmut(token, offset) as *mut usize
    };

    // a buffer in kernel
    const BUFFER_SIZE: usize = 4096;
    let mut buffer = Vec::<u8>::with_capacity(BUFFER_SIZE);

    let mut left_bytes = count;
    let mut write_size = 0;
    loop {
        unsafe {
            buffer.set_len(left_bytes.min(BUFFER_SIZE));
        }
        let read_size = in_file.kread(unsafe { offset.as_mut() }, buffer.as_mut_slice());
        if read_size == 0 {
            break;
        }
        unsafe {
            buffer.set_len(read_size);
        }
        write_size += out_file.kwrite(None, buffer.as_slice());
        left_bytes -= read_size;
    }
    info!("[sys_sendfile] written bytes: {}", write_size);
    write_size as isize
}

pub fn sys_open(path: *const u8, flags: u32) -> isize {
    let task = current_task().unwrap();
    let mut inner = task.acquire_inner_lock();
    let token = inner.get_user_token();
    let path = translated_str(token, path);

    match open(
        inner.get_work_path().as_str(),
        path.as_str(),
        OpenFlags::from_bits(flags).unwrap(),
        DiskInodeType::File,
    ) {
        Ok(inode) => {
            let fd = match inner.alloc_fd() {
                Some(fd) => fd,
                None => return EMFILE,
            };
            inner.fd_table[fd] = Some(FileDescriptor::new(
                OpenFlags::from_bits(flags)
                    .unwrap()
                    .contains(OpenFlags::O_CLOEXEC),
                FileLike::Regular(inode),
            ));
            drop(inner);
            fd as isize
        }
        Err(errno) => {
            warn!("[sys_open] open failed with errno: {}", errno);
            errno
        }
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

/// # Warning
/// Only O_CLOEXEC is supported now
pub fn sys_pipe2(pipefd: usize, flags: u32) -> isize {
    let flags = match OpenFlags::from_bits(flags) {
        Some(flags) => {
            // only O_CLOEXEC | O_DIRECT | O_NONBLOCK are valid in pipe2()
            if flags
                .difference(OpenFlags::O_CLOEXEC | OpenFlags::O_DIRECT | OpenFlags::O_NONBLOCK)
                .is_empty()
            {
                flags
            // some flags are invalid in pipe2(), they are all valid OpenFlags though
            } else {
                warn!(
                    "[sys_pipe2] invalid flags: {:?}",
                    flags.difference(
                        OpenFlags::O_CLOEXEC | OpenFlags::O_DIRECT | OpenFlags::O_NONBLOCK
                    )
                );
                return EINVAL;
            }
        }
        // contains invalid OpenFlags
        None => return EINVAL,
    };
    let task = current_task().unwrap();
    let mut inner = task.acquire_inner_lock();
    let (pipe_read, pipe_write) = make_pipe();
    let read_fd = match inner.alloc_fd() {
        Some(fd) => fd,
        None => return EMFILE,
    };
    inner.fd_table[read_fd] = Some(FileDescriptor::new(
        flags.contains(OpenFlags::O_CLOEXEC),
        FileLike::Abstract(pipe_read),
    ));
    let write_fd = match inner.alloc_fd() {
        Some(fd) => fd,
        None => return EMFILE,
    };
    inner.fd_table[write_fd] = Some(FileDescriptor::new(
        flags.contains(OpenFlags::O_CLOEXEC),
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

pub fn sys_getdents64(fd: usize, dirp: *mut u8, count: usize) -> isize {
    let task = current_task().unwrap();
    let inner = task.acquire_inner_lock();
    let token = inner.get_user_token();
    let buf = translated_byte_buffer(token, dirp, count);

    let dirent_size = size_of::<Dirent>();
    let mut total_len: usize = 0;
    let mut userbuf = UserBuffer::new(buf);
    let mut dirent = Dirent::empty();
    if fd == AT_FDCWD {
        let work_path = inner.current_path.clone();
        if let Ok(file) = open(
            "/",
            work_path.as_str(),
            OpenFlags::O_RDONLY,
            DiskInodeType::Directory,
        ) {
            loop {
                if total_len + dirent_size > count {
                    break;
                }
                if file.getdirent(&mut dirent) > 0 {
                    userbuf.write_at(total_len, dirent.as_bytes());
                    total_len += dirent_size;
                } else {
                    break;
                }
            }
            info!("[sys_getdents64] fd: AT_FDCWD, count: {}", count);
            total_len as isize //warning
        } else {
            info!("[sys_getdents64] fd: AT_FDCWD, count: {}", count);
            ENOENT
        }
    } else {
        if fd >= inner.fd_table.len() || inner.fd_table[fd].is_none() {
            return EBADF;
        }
        let file_descriptor = inner.fd_table[fd].as_ref().unwrap();
        match &file_descriptor.file {
            FileLike::Regular(file) => {
                loop {
                    if total_len + dirent_size > count {
                        break;
                    }
                    if file.getdirent(&mut dirent) > 0 {
                        userbuf.write_at(total_len, dirent.as_bytes());
                        total_len += dirent_size;
                    } else {
                        break;
                    }
                }
                info!("[sys_getdents64] fd: {}, count: {}", fd, count);
                total_len as isize //warning
            }
            _ => ENOTDIR,
        }
    }
}

pub fn sys_dup(oldfd: usize) -> isize {
    let task = current_task().unwrap();
    let mut inner = task.acquire_inner_lock();
    if oldfd >= inner.fd_table.len() || inner.fd_table[oldfd].is_none() {
        return EBADF;
    }
    let newfd = match inner.alloc_fd() {
        Some(fd) => fd,
        None => return EMFILE,
    };
    inner.fd_table[newfd] = Some(inner.fd_table[oldfd].as_ref().unwrap().clone());
    newfd as isize
}

pub fn sys_dup3(oldfd: usize, newfd: usize, flags: u32) -> isize {
    info!(
        "[sys_dup3] oldfd: {}, newfd: {}, flags: {:?}",
        oldfd,
        newfd,
        OpenFlags::from_bits(flags)
    );
    let task = current_task().unwrap();
    let mut inner = task.acquire_inner_lock();
    if oldfd >= inner.fd_table.len() || inner.fd_table[oldfd].is_none() {
        return EBADF;
    }
    let is_cloexec = match OpenFlags::from_bits(flags) {
        Some(OpenFlags::O_CLOEXEC) => true,
        // `O_RDONLY == 0`, so it means *NO* cloexec in fact
        Some(OpenFlags::O_RDONLY) => false,
        // flags contain an invalid value
        _ => return EINVAL,
    };
    if oldfd == newfd {
        return EINVAL;
    }
    if newfd >= inner.fd_table.len() {
        match inner.alloc_fd_at(newfd) {
            // `newfd` is not allocated in this case, so `fd` should never differ from `newfd`
            Some(fd) => assert_eq!(fd, newfd),
            // newfd is out of the allowed range for file descriptors
            None => return EBADF,
        };
    }
    inner.fd_table[newfd] = Some(inner.fd_table[oldfd].as_ref().unwrap().clone());
    inner.fd_table[newfd]
        .as_mut()
        .unwrap()
        .set_cloexec(is_cloexec);
    newfd as isize
}

// This syscall is not complete at all, only /read proc/self/exe
pub fn sys_readlinkat(dirfd: usize, pathname: *const u8, buf: *mut u8, bufsiz: usize) -> isize {
    if dirfd == AT_FDCWD {
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

pub fn sys_newfstatat(fd: usize, path: *const u8, buf: *mut u8, flags: u32) -> isize {
    let task = current_task().unwrap();
    let inner = task.acquire_inner_lock();
    let token = inner.get_user_token();
    let path = translated_str(token, path);
    let mut userbuf = UserBuffer::new(translated_byte_buffer(token, buf, size_of::<NewStat>()));
    let mut stat = NewStat::empty();
    info!(
        "[sys_newfstatat] fd = {}, path = {:?}, flags: {:?}",
        fd,
        path,
        StatMode::from_bits(flags)
    );
    if fd == AT_FDCWD {
        let work_path = inner.current_path.clone();
        if let Ok(file) = open(
            work_path.as_str(),
            path.as_str(),
            OpenFlags::O_RDONLY,
            DiskInodeType::Directory,
        ) {
            file.get_newstat(&mut stat);
            userbuf.write(stat.as_bytes());
            SUCCESS
        } else {
            ENOENT
        }
    } else {
        if fd >= inner.fd_table.len() || inner.fd_table[fd].is_none() {
            return EBADF;
        }
        let file_descriptor = inner.fd_table[fd].as_ref().unwrap();
        match &file_descriptor.file {
            FileLike::Regular(file) => {
                file.get_newstat(&mut stat);
                userbuf.write(stat.as_bytes());
                SUCCESS
            }
            _ => todo!(),
        }
    }
}

pub fn sys_fstat(fd: usize, statbuf: *mut u8) -> isize {
    let task = current_task().unwrap();
    let inner = task.acquire_inner_lock();
    let token = inner.get_user_token();
    let buf = translated_byte_buffer(token, statbuf, size_of::<Kstat>());
    let mut userbuf = UserBuffer::new(buf);
    let mut kstat = Kstat::empty();

    if fd == AT_FDCWD {
        let work_path = inner.current_path.clone();
        if let Ok(file) = open(
            "/",
            work_path.as_str(),
            OpenFlags::O_RDONLY,
            DiskInodeType::Directory,
        ) {
            file.get_fstat(&mut kstat);
            info!("[syscall_fstat] fd = {}, size = {}", fd, kstat.st_size);
            userbuf.write(kstat.as_bytes());
            SUCCESS
        } else {
            ENOENT
        }
    } else {
        if fd >= inner.fd_table.len() || inner.fd_table[fd].is_none() {
            return EBADF;
        }
        let file_descriptor = inner.fd_table[fd].as_ref().unwrap();
        match &file_descriptor.file {
            FileLike::Regular(f) => {
                f.get_fstat(&mut kstat);
                userbuf.write(kstat.as_bytes());
                info!("[sys_fstat] fd:{}; size:{}", fd, kstat.st_size);
                SUCCESS
            }
            _ => {
                let kstat = Kstat::new_abstract();
                userbuf.write(kstat.as_bytes());
                info!("[sys_fstat] fd:{}; size:{}", fd, kstat.st_size);
                SUCCESS
            }
        }
    }
}

pub fn sys_openat(dirfd: usize, path: *const u8, flags: u32, mode: u32) -> isize {
    let task = current_task().unwrap();
    let mut inner = task.acquire_inner_lock();
    let token = inner.get_user_token();
    let path = translated_str(token, path);
    // TODO: should check flags and mode here
    let flags = OpenFlags::from_bits(flags).unwrap();
    let mode = StatMode::from_bits(mode);

    if path.contains("/dev") {
        info!(
            "[sys_openat] dirfd: {}, path:{}, flags:{:?}, mode:{:?}",
            dirfd, path, flags, mode
        );
        let fd = match inner.alloc_fd() {
            Some(fd) => fd,
            None => return EMFILE,
        };
        let file = {
            if path.contains("tty") {
                FileLike::Abstract(TTY.clone())
            } else if path.contains("null") {
                FileLike::Abstract(Arc::new(Null))
            } else if path.contains("zero") {
                FileLike::Abstract(Arc::new(Zero))
            } else {
                warn!("[sys_openat] device file not supported: {}", path);
                return ENOENT;
            }
        };
        inner.fd_table[fd] = Some(FileDescriptor::new(false, file));
        return fd as isize;
    }

    if dirfd == AT_FDCWD {
        info!(
            "[sys_openat] dirfd: AT_FDCWD, path:{}, flags:{:?}, mode:{:?}",
            path, flags, mode
        );
        match open(
            inner.get_work_path().as_str(),
            path.as_str(),
            flags,
            DiskInodeType::File,
        ) {
            Ok(inode) => {
                let fd = match inner.alloc_fd() {
                    Some(fd) => fd,
                    None => return EMFILE,
                };
                inner.fd_table[fd] = Some(FileDescriptor::new(
                    flags.contains(OpenFlags::O_CLOEXEC),
                    FileLike::Regular(inode),
                ));
                fd as isize
            }
            Err(errno) => {
                warn!("[sys_openat] open failed with errno: {}", errno);
                errno
            }
        }
    } else {
        info!(
            "[sys_openat] dirfd:{}, path:{}, flags:{:?}, mode:{:?}",
            dirfd, path, flags, mode
        );
        if dirfd >= inner.fd_table.len() || inner.fd_table[dirfd].is_none() {
            return EBADF;
        }
        let file_descriptor = inner.fd_table[dirfd].as_ref().unwrap();
        match &file_descriptor.file {
            FileLike::Regular(dir_file) => {
                // [Warning] if file with same name exists, it will be removed
                if flags.contains(OpenFlags::O_CREAT) {
                    if let Some(created) = dir_file.create(path.as_str(), DiskInodeType::File) {
                        let fd = match inner.alloc_fd() {
                            Some(fd) => fd,
                            None => return EMFILE,
                        };
                        inner.fd_table[fd] = Some(FileDescriptor::new(
                            flags.contains(OpenFlags::O_CLOEXEC),
                            FileLike::Regular(created),
                        ));
                        return fd as isize;
                    } else {
                        warn!("[sys_openat] file not found: {}", path);
                        return ENOENT;
                    }
                }
                // open directly
                if let Some(dir_file) = dir_file.find(path.as_str(), flags) {
                    let fd = match inner.alloc_fd() {
                        Some(fd) => fd,
                        None => return EMFILE,
                    };
                    inner.fd_table[fd] = Some(FileDescriptor::new(
                        flags.contains(OpenFlags::O_CLOEXEC),
                        FileLike::Regular(dir_file),
                    ));
                    fd as isize
                } else {
                    warn!("[sys_openat] file not found: {}", path);
                    return ENOENT;
                }
            }
            FileLike::Abstract(_) => ENOTDIR,
        }
    }
}

pub fn sys_ioctl(fd: usize, cmd: u32, arg: usize) -> isize {
    let task = current_task().unwrap();
    let inner = task.acquire_inner_lock();
    if fd >= inner.fd_table.len() || inner.fd_table[fd].is_none() {
        return EBADF;
    }
    let file_descriptor = inner.fd_table[fd].as_ref().unwrap();
    let file: Arc<dyn File + Send + Sync> = match &file_descriptor.file {
        FileLike::Abstract(f) => f.clone(),
        FileLike::Regular(f) => f.clone(),
    };
    drop(inner);
    return file.ioctl(cmd, arg);
}

pub fn sys_ppoll(poll_fd: usize, nfds: usize, time_spec: usize, sigmask: usize) -> isize {
    ppoll(
        poll_fd,
        nfds,
        time_spec,
        sigmask as *const crate::task::Signals,
    )
}

pub fn sys_mkdirat(dirfd: usize, path: *const u8, mode: u32) -> isize {
    let task = current_task().unwrap();
    let inner = task.acquire_inner_lock();
    let token = inner.get_user_token();
    let path = translated_str(token, path);
    info!(
        "[sys_mkdirat] dirfd: {}, path: {}, mode: {:?}",
        dirfd,
        path,
        StatMode::from_bits(mode)
    );
    if dirfd == AT_FDCWD {
        if let Ok(_) = open(
            inner.get_work_path().as_str(),
            path.as_str(),
            OpenFlags::O_CREAT,
            DiskInodeType::Directory,
        ) {
            SUCCESS
        } else {
            ENOENT
        }
    } else {
        if dirfd >= inner.fd_table.len() || inner.fd_table[dirfd].is_none() {
            return EBADF;
        }
        let file_descriptor = inner.fd_table[dirfd].as_ref().unwrap();
        match &file_descriptor.file {
            FileLike::Regular(dir_file) => {
                // should we check InodeType of `dir_file` here?
                if let Some(_) = dir_file.create(path.as_str(), DiskInodeType::Directory) {
                    SUCCESS
                } else {
                    // possibly, not for sure
                    ENOENT
                }
            }
            _ => ENOTDIR,
        }
    }
}

bitflags! {
    pub struct UnlinkatFlags: u32 {
        const AT_REMOVEDIR = 0x200;
    }
}

/// # Warning
/// Currently we have no hard-link so this syscall will remove file directly.
/// `AT_REMOVEDIR` is not supported yet.
pub fn sys_unlinkat(dirfd: usize, path: *const u8, flags: u32) -> isize {
    let task = current_task().unwrap();
    let inner = task.acquire_inner_lock();
    let token = inner.get_user_token();
    let path = translated_str(token, path);
    let flags = match UnlinkatFlags::from_bits(flags) {
        Some(flags) => flags,
        None => {
            warn!("[sys_unlinkat] unknown flags");
            return EINVAL;
        }
    };
    info!(
        "[sys_unlinkat] dirfd: {}, path: {}, flags: {:?}",
        dirfd, path, flags
    );
    let inode = if path.starts_with("/") {
        if let Ok(inode) = open("/", path.as_str(), OpenFlags::O_RDONLY, DiskInodeType::File) {
            inode
        } else {
            return ENOENT;
        }
    } else {
        if dirfd == AT_FDCWD {
            if let Ok(inode) = open(
                inner.get_work_path().as_str(),
                path.as_str(),
                OpenFlags::O_RDONLY,
                DiskInodeType::File,
            ) {
                inode
            } else {
                return ENOENT;
            }
        } else {
            if dirfd >= inner.fd_table.len() || inner.fd_table[dirfd].is_none() {
                return EBADF;
            }
            let file_descriptor = inner.fd_table[dirfd].as_ref().unwrap();
            match &file_descriptor.file {
                FileLike::Regular(dir_file) => {
                    if !dir_file.is_dir() {
                        return ENOTDIR;
                    }
                    if let Some(inode) = dir_file.find(path.as_str(), OpenFlags::O_RDONLY) {
                        inode
                    } else {
                        return ENOENT;
                    }
                }
                _ => return ENOTDIR,
            }
        }
    };
    if inode.is_dir() {
        if flags.contains(UnlinkatFlags::AT_REMOVEDIR) {
            todo!();
        } else {
            return EISDIR;
        }
    }
    inode.delete();
    SUCCESS
}

#[allow(non_camel_case_types)]
#[derive(Debug, Eq, PartialEq, FromPrimitive)]
#[repr(u32)]
pub enum Command {
    DUPFD = 0,
    GETFD = 1,
    SETFD = 2,
    GETFL = 3,
    SETFL = 4,
    GETLK = 5,
    SETLK = 6,
    SETLKW = 7,
    SETOWN = 8,
    GETOWN = 9,
    SETSIG = 10,
    GETSIG = 11,
    SETOWN_EX = 15,
    GETOWN_EX = 16,
    GETOWNER_UIDS = 17,
    OFD_GETLK = 36,
    OFD_SETLK = 37,
    OFD_SETLKW = 38,
    SETLEASE = 1024,
    GETLEASE = 1025,
    NOTIFY = 1026,
    CANCELLK = 1029,
    DUPFD_CLOEXEC = 1030,
    SETPIPE_SZ = 1031,
    GETPIPE_SZ = 1032,
    ADD_SEALS = 1033,
    GET_SEALS = 1034,
    GET_RW_HINT = 1035,
    SET_RW_HINT = 1036,
    GET_FILE_RW_HINT = 1037,
    SET_FILE_RW_HINT = 1038,
    #[num_enum(default)]
    ILLEAGAL,
}

pub fn sys_fcntl(fd: usize, cmd: u32, arg: usize) -> isize {
    const FD_CLOEXEC: usize = 1;

    let task = current_task().unwrap();
    let mut inner = task.acquire_inner_lock();

    if fd >= inner.fd_table.len() || inner.fd_table[fd].is_none() {
        return EBADF;
    }

    info!(
        "[sys_fcntl] fd:{}, cmd:{:?}, arg:{:X}",
        fd,
        Command::from_primitive(cmd),
        arg
    );
    let file_descriptor = inner.fd_table[fd].as_mut().unwrap();
    match Command::from_primitive(cmd) {
        Command::DUPFD | Command::DUPFD_CLOEXEC => {
            let newfd = match inner.alloc_fd_at(arg) {
                Some(fd) => fd,
                // cmd is F_DUPFD and arg is negative or is greater than the maximum allowable value
                None => return EINVAL,
            };
            drop(inner);
            // take advantage of `DUPFD == 0`
            sys_dup3(fd, newfd, OpenFlags::O_CLOEXEC.bits() & cmd)
        }
        Command::GETFD => file_descriptor.get_cloexec() as isize,
        Command::SETFD => {
            file_descriptor.set_cloexec((arg & FD_CLOEXEC) != 0);
            if (arg & !FD_CLOEXEC) != 0 {
                warn!("[fcntl] Unsupported flag exists: {:X}", arg);
            }
            SUCCESS
        }
        Command::GETFL => {
            match &file_descriptor.file {
                // for regular file, we don't check access permission now
                FileLike::Regular(_) => OpenFlags::O_RDWR.bits() as isize,
                FileLike::Abstract(file) => {
                    // I think for most abstract file, they are either readable or writable
                    OpenFlags::O_RDWR.bits() as isize
                }
            }
        }
        command => {
            warn!("[fcntl] Unsupported command: {:?}", command);
            SUCCESS
        } // WARNING!!!
    }
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
    info!("[sys_umask] mask: {:o}", mask);
    warn!("[sys_umask] fake implementation! Do nothing and return 0.");
    0
}

bitflags! {
    pub struct FaccessatFlags: u32 {
        const AT_SYMLINK_NOFOLLOW = 0x100;
        const AT_EACCESS = 0x200;
    }
}

pub fn sys_faccessat2(dirfd: u32, pathname: *const u8, mode: u32, flags: u32) -> isize {
    let task = current_task().unwrap();
    let inner = task.acquire_inner_lock();
    let token = inner.get_user_token();
    let pathname = translated_str(token, pathname);
    let mode = StatMode::from_bits(mode);
    let flags = FaccessatFlags::from_bits(flags);
    info!(
        "[sys_faccessat2] dirfd: {}, pathname: {}, mode: {:?}, flags: {:?}",
        dirfd, pathname, mode, flags
    );
    warn!("[sys_faccessat2] fake implementation! Do nothing and return 0.");
    SUCCESS
}
