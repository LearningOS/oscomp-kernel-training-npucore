use crate::fs::poll::pselect;
use crate::fs::{make_pipe, OpenFlags, StatMode};
use crate::fs::{
    poll::{ppoll, FdSet},
    Dirent, FileDescriptor, Null, Stat, Zero, TTY,
};
use crate::mm::{
    copy_from_user, copy_from_user_array, copy_to_user, copy_to_user_array, translated_byte_buffer,
    translated_byte_buffer_append_to_existing_vec, translated_refmut, translated_str,
    MapPermission, UserBuffer,
};
use crate::task::{current_task, current_user_token};
use crate::timer::TimeSpec;
use alloc::alloc::{alloc, dealloc, Layout};
use alloc::vec::Vec;
use core::mem::size_of;
use log::{debug, error, info, trace, warn};
use num_enum::FromPrimitive;

use super::errno::*;

pub const AT_FDCWD: usize = 100usize.wrapping_neg();

pub fn sys_getcwd(buf: usize, size: usize) -> isize {
    let task = current_task().unwrap();
    if !task
        .vm
        .lock()
        .contains_valid_buffer(buf, size, MapPermission::W)
    {
        // buf points to a bad address.
        return EFAULT;
    }
    if size == 0 && buf != 0 {
        // The size argument is zero and buf is not a NULL pointer.
        return EINVAL;
    }
    let working_dir = task.fs.lock().working_inode.get_cwd().unwrap();
    log::error!("cwd: {}", working_dir);
    if working_dir.len() >= size {
        // The size argument is less than the length of the absolute pathname of the working directory,
        // including the terminating null byte.
        return ERANGE;
    }
    let token = task.get_user_token();
    UserBuffer::new(translated_byte_buffer(token, buf as *const u8, size))
        .write(working_dir.as_bytes());
    buf as isize
}

bitflags! {
    pub struct SeekWhence: u32 {
        const SEEK_SET  =   0; /* set to offset bytes.  */
        const SEEK_CUR  =   1; /* set to its current location plus offset bytes.  */
        const SEEK_END  =   2; /* set to the size of the file plus offset bytes.  */
    }
}

pub fn sys_lseek(fd: usize, offset: usize, whence: u32) -> isize {
    // whence is not valid
    let whence = match SeekWhence::from_bits(whence) {
        Some(whence) => whence,
        None => {
            warn!("[sys_lseek] unknown flags");
            return EINVAL;
        }
    };
    info!(
        "[sys_lseek] fd: {}, offset: {}, whence: {:?}",
        fd, offset, whence,
    );
    let task = current_task().unwrap();
    let fd_table = task.files.lock();
    // fd is not a valid file descriptor
    if fd >= fd_table.len() || fd_table[fd].is_none() {
        return EBADF;
    }
    match fd_table[fd]
        .as_ref()
        .unwrap()
        .lseek(offset as isize, whence)
    {
        Ok(pos) => pos as isize,
        Err(errno) => errno,
    }
}

pub fn sys_read(fd: usize, buf: usize, count: usize) -> isize {
    let task = current_task().unwrap();
    let fd_table = task.files.lock();
    // fd is not a valid file descriptor
    if fd >= fd_table.len() || fd_table[fd].is_none() {
        return EBADF;
    }
    let file_descriptor = fd_table[fd].as_ref().unwrap();
    // fd is not open for reading
    if !file_descriptor.readable() {
        return EBADF;
    }
    // buf is outside your accessible address space.
    if !task
        .vm
        .lock()
        .contains_valid_buffer(buf, count, MapPermission::W)
    {
        return EFAULT;
    }
    let token = task.get_user_token();
    file_descriptor.read_user(UserBuffer::new(translated_byte_buffer(
        token,
        buf as *const u8,
        count,
    ))) as isize
}

pub fn sys_write(fd: usize, buf: usize, count: usize) -> isize {
    let task = current_task().unwrap();
    let fd_table = task.files.lock();
    // fd is not a valid file descriptor
    if fd >= fd_table.len() || fd_table[fd].is_none() {
        return EBADF;
    }
    let file_descriptor = fd_table[fd].as_ref().unwrap();
    // fd is not open for writing
    if !file_descriptor.writable() {
        return EBADF;
    }
    // buf is outside your accessible address space.
    if !task
        .vm
        .lock()
        .contains_valid_buffer(buf, count, MapPermission::R)
    {
        return EFAULT;
    }
    let token = task.get_user_token();
    file_descriptor.write_user(UserBuffer::new(translated_byte_buffer(
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
    let fd_table = task.files.lock();
    // fd is not a valid file descriptor
    if fd >= fd_table.len() || fd_table[fd].is_none() {
        return EBADF;
    }
    let file_descriptor = fd_table[fd].as_ref().unwrap();
    // fd is not open for reading
    if !file_descriptor.readable() {
        return EBADF;
    }
    let token = task.get_user_token();
    let mut iovecs = Vec::<IOVec>::with_capacity(iovcnt);
    copy_from_user_array(token, iov as *const IOVec, iovecs.as_mut_ptr(), iovcnt);
    unsafe { iovecs.set_len(iovcnt) };
    file_descriptor.read_user(UserBuffer::new(iovecs.iter().fold(
        Vec::new(),
        |buffer, iovec| {
            // This function aims to avoid the extra cost caused by `Vec::append` (it moves data on heap)
            translated_byte_buffer_append_to_existing_vec(
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
    let fd_table = task.files.lock();
    // fd is not a valid file descriptor
    if fd >= fd_table.len() || fd_table[fd].is_none() {
        return EBADF;
    }
    let file_descriptor = fd_table[fd].as_ref().unwrap();
    // fd is not open for writing
    if !file_descriptor.writable() {
        return EBADF;
    }
    let token = task.get_user_token();
    let mut iovecs = Vec::<IOVec>::with_capacity(iovcnt);
    copy_from_user_array(token, iov as *const IOVec, iovecs.as_mut_ptr(), iovcnt);
    unsafe { iovecs.set_len(iovcnt) };
    file_descriptor.write_user(UserBuffer::new(iovecs.iter().fold(
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
                    debug!(
                        "[sys_writev] Iterating... content: {:?}, iovlen: {}",
                        core::str::from_utf8(temp.as_slice()),
                        iovec.iov_len
                    );
                }
            }
            // This function aims to avoid the extra cost caused by `Vec::append` (it moves data on heap)
            translated_byte_buffer_append_to_existing_vec(
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
    let fd_table = task.files.lock();
    if in_fd >= fd_table.len()
        || fd_table[in_fd].is_none()
        || out_fd >= fd_table.len()
        || fd_table[out_fd].is_none()
    {
        return EBADF;
    }
    info!("[sys_sendfile] outfd: {}, in_fd: {}", out_fd, in_fd);
    let in_file = fd_table[in_fd].as_ref().unwrap();
    let out_file = fd_table[out_fd].as_ref().unwrap();
    if !in_file.readable() || !out_file.readable() {
        return EBADF;
    }

    let token = task.get_user_token();
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
        let read_size = in_file.read(unsafe { offset.as_mut() }, buffer.as_mut_slice());
        if read_size == 0 {
            break;
        }
        unsafe {
            buffer.set_len(read_size);
        }
        write_size += out_file.write(None, buffer.as_slice());
        left_bytes -= read_size;
    }
    info!("[sys_sendfile] written bytes: {}", write_size);
    write_size as isize
}

pub fn sys_close(fd: usize) -> isize {
    info!("[sys_close] fd:{}", fd);
    let task = current_task().unwrap();
    let mut fd_table = task.files.lock();
    if fd >= fd_table.len() || fd_table[fd].is_none() {
        return EBADF;
    }
    fd_table[fd].take();
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
        None => {
            warn!("[sys_pipe2] unknown flags");
            return EINVAL;
        }
    };
    let task = current_task().unwrap();
    let mut fd_table = task.files.lock();
    let (pipe_read, pipe_write) = make_pipe();
    let read_fd = match fd_table.alloc_fd() {
        Some(fd) => fd,
        None => return EMFILE,
    };
    fd_table[read_fd] = Some(FileDescriptor::new(
        flags.contains(OpenFlags::O_CLOEXEC),
        pipe_read,
    ));
    let write_fd = match fd_table.alloc_fd() {
        Some(fd) => fd,
        None => return EMFILE,
    };
    fd_table[write_fd] = Some(FileDescriptor::new(
        flags.contains(OpenFlags::O_CLOEXEC),
        pipe_write,
    ));
    let token = task.get_user_token();
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
    let token = task.get_user_token();

    let file_descriptor = match fd {
        AT_FDCWD => task.fs.lock().working_inode.as_ref().clone(),
        fd => {
            let fd_table = task.files.lock();
            if fd >= fd_table.len() || fd_table[fd].is_none() {
                return EBADF;
            }
            fd_table[fd].as_ref().unwrap().clone()
        }
    };
    let dirent_vec = match file_descriptor.get_dirent(count) {
        Ok(vec) => vec,
        Err(errno) => return errno,
    };
    copy_to_user_array(
        token,
        dirent_vec.as_ptr(),
        dirp as *mut Dirent,
        dirent_vec.len(),
    );
    info!("[sys_getdents64] fd: {}, count: {}", fd, count);
    (dirent_vec.len() * size_of::<Dirent>()) as isize
}

pub fn sys_dup(oldfd: usize) -> isize {
    let task = current_task().unwrap();
    let mut fd_table = task.files.lock();
    if oldfd >= fd_table.len() || fd_table[oldfd].is_none() {
        return EBADF;
    }
    let newfd = match fd_table.alloc_fd() {
        Some(fd) => fd,
        None => return EMFILE,
    };
    fd_table[newfd] = Some(fd_table[oldfd].as_ref().unwrap().clone());
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
    let mut fd_table = task.files.lock();
    if oldfd >= fd_table.len() || fd_table[oldfd].is_none() {
        return EBADF;
    }
    let is_cloexec = match OpenFlags::from_bits(flags) {
        Some(OpenFlags::O_CLOEXEC) => true,
        // `O_RDONLY == 0`, so it means *NO* cloexec in fact
        Some(OpenFlags::O_RDONLY) => false,
        // flags contain an invalid value
        Some(flags) => {
            warn!("[sys_dup3] invalid flags: {:?}", flags);
            return EINVAL;
        }
        None => {
            warn!("[sys_dup3] unknown flags");
            return EINVAL;
        }
    };
    if oldfd == newfd {
        return EINVAL;
    }
    if newfd >= fd_table.len() {
        match fd_table.alloc_fd_at(newfd) {
            // `newfd` is not allocated in this case, so `fd` should never differ from `newfd`
            Some(fd) => assert_eq!(fd, newfd),
            // newfd is out of the allowed range for file descriptors
            None => return EBADF,
        };
    }
    fd_table[newfd] = Some(fd_table[oldfd].as_ref().unwrap().clone());
    fd_table[newfd].as_mut().unwrap().set_cloexec(is_cloexec);
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

bitflags! {
    pub struct FstatatFlags: u32 {
        const AT_EMPTY_PATH = 0x1000;
        const AT_NO_AUTOMOUNT = 0x800;
        const AT_SYMLINK_NOFOLLOW = 0x100;
    }
}

pub fn sys_fstatat(dirfd: usize, path: *const u8, buf: *mut u8, flags: u32) -> isize {
    let token = current_user_token();
    let path = translated_str(token, path);
    let flags = match FstatatFlags::from_bits(flags) {
        Some(flags) => flags,
        None => {
            warn!("[sys_fstatat] unknown flags");
            return EINVAL;
        }
    };

    info!(
        "[sys_fstatat] dirfd = {}, path = {:?}, flags: {:?}",
        dirfd, path, flags,
    );

    let task = current_task().unwrap();
    let file_descriptor = match dirfd {
        AT_FDCWD => task.fs.lock().working_inode.as_ref().clone(),
        fd => {
            let fd_table = task.files.lock();
            if fd >= fd_table.len() || fd_table[fd].is_none() {
                return EBADF;
            }
            fd_table[fd].as_ref().unwrap().clone()
        }
    };

    match file_descriptor.open(&path, OpenFlags::O_RDONLY, false) {
        Ok(file_descriptor) => {
            copy_to_user(token, file_descriptor.get_stat().as_ref(), buf as *mut Stat);
            SUCCESS
        }
        Err(errno) => errno,
    }
}

pub fn sys_fstat(fd: usize, statbuf: *mut u8) -> isize {
    let task = current_task().unwrap();
    let token = task.get_user_token();

    info!("[syscall_fstat] fd = {}", fd);
    let file_descriptor = match fd {
        AT_FDCWD => task.fs.lock().working_inode.as_ref().clone(),
        fd => {
            let fd_table = task.files.lock();
            if fd >= fd_table.len() || fd_table[fd].is_none() {
                return EBADF;
            }
            fd_table[fd].as_ref().unwrap().clone()
        }
    };
    copy_to_user(
        token,
        file_descriptor.get_stat().as_ref(),
        statbuf as *mut Stat,
    );
    SUCCESS
}

pub fn sys_chdir(path: *const u8) -> isize {
    let task = current_task().unwrap();
    let token = task.get_user_token();
    let path = translated_str(token, path);
    info!("[sys_chdir] path: {}", path);

    let mut lock = task.fs.lock();

    match lock.working_inode.cd(&path) {
        Ok(new_working_inode) => {
            lock.working_inode = new_working_inode;
            SUCCESS
        }
        Err(errno) => errno,
    }
}

pub fn sys_openat(dirfd: usize, path: *const u8, flags: u32, mode: u32) -> isize {
    let task = current_task().unwrap();
    let token = task.get_user_token();
    let path = translated_str(token, path);
    let flags = match OpenFlags::from_bits(flags) {
        Some(flags) => flags,
        None => {
            warn!("[sys_openat] unknown flags");
            return EINVAL;
        }
    };
    let mode = StatMode::from_bits(mode);
    info!(
        "[sys_openat] dirfd: {}, path:{}, flags:{:?}, mode:{:?}",
        dirfd, path, flags, mode
    );
    let mut fd_table = task.files.lock();
    let file_descriptor = match dirfd {
        AT_FDCWD => task.fs.lock().working_inode.as_ref().clone(),
        fd => {
            if fd >= fd_table.len() || fd_table[fd].is_none() {
                return EBADF;
            }
            fd_table[fd].as_ref().unwrap().clone()
        }
    };

    let new_file_descriptor = match file_descriptor.open(&path, flags, false) {
        Ok(file_descriptor) => file_descriptor,
        Err(errno) => return errno,
    };

    let new_fd = match fd_table.alloc_fd() {
        Some(fd) => fd,
        None => return EMFILE,
    };
    fd_table[new_fd] = Some(new_file_descriptor);
    new_fd as isize
}

pub fn sys_renameat2(
    olddirfd: usize,
    oldpath: *const u8,
    newdirfd: usize,
    newpath: *const u8,
    flags: u32,
) -> isize {
    let task = current_task().unwrap();
    let token = task.get_user_token();
    let oldpath = translated_str(token, oldpath);
    let newpath = translated_str(token, newpath);

    info!(
        "[sys_renameat2] olddirfd: {}, oldpath:{}, newdirfd: {}, newpath: {}, flags:{}",
        olddirfd, oldpath, newdirfd, newpath, flags
    );

    let old_file_descriptor = match olddirfd {
        AT_FDCWD => task.fs.lock().working_inode.as_ref().clone(),
        fd => {
            let fd_table = task.files.lock();
            if fd >= fd_table.len() || fd_table[fd].is_none() {
                return EBADF;
            }
            fd_table[fd].as_ref().unwrap().clone()
        }
    };
    let new_file_descriptor = match newdirfd {
        AT_FDCWD => task.fs.lock().working_inode.as_ref().clone(),
        fd => {
            let fd_table = task.files.lock();
            if fd >= fd_table.len() || fd_table[fd].is_none() {
                return EBADF;
            }
            fd_table[fd].as_ref().unwrap().clone()
        }
    };

    match FileDescriptor::rename(
        &old_file_descriptor,
        &oldpath,
        &new_file_descriptor,
        &newpath,
    ) {
        Ok(_) => SUCCESS,
        Err(errno) => errno,
    }
}

pub fn sys_ioctl(fd: usize, cmd: u32, arg: usize) -> isize {
    let task = current_task().unwrap();
    let fd_table = task.files.lock();
    if fd >= fd_table.len() || fd_table[fd].is_none() {
        return EBADF;
    }
    let file_descriptor = fd_table[fd].as_ref().unwrap();
    file_descriptor.ioctl(cmd, arg)
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
    let token = task.get_user_token();
    let path = translated_str(token, path);
    info!(
        "[sys_mkdirat] dirfd: {}, path: {}, mode: {:?}",
        dirfd,
        path,
        StatMode::from_bits(mode)
    );
    let file_descriptor = match dirfd {
        AT_FDCWD => task.fs.lock().working_inode.as_ref().clone(),
        fd => {
            let fd_table = task.files.lock();
            if fd >= fd_table.len() || fd_table[fd].is_none() {
                return EBADF;
            }
            fd_table[fd].as_ref().unwrap().clone()
        }
    };
    match file_descriptor.mkdir(&path) {
        Ok(_) => SUCCESS,
        Err(errno) => errno,
    }
}

bitflags! {
    pub struct UnlinkatFlags: u32 {
        const AT_REMOVEDIR = 0x200;
    }
}

/// # Warning
/// Currently we have no hard-link so this syscall will remove file directly.
pub fn sys_unlinkat(dirfd: usize, path: *const u8, flags: u32) -> isize {
    let task = current_task().unwrap();
    let token = task.get_user_token();
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

    let file_descriptor = match dirfd {
        AT_FDCWD => task.fs.lock().working_inode.as_ref().clone(),
        fd => {
            let fd_table = task.files.lock();
            if fd >= fd_table.len() || fd_table[fd].is_none() {
                return EBADF;
            }
            fd_table[fd].as_ref().unwrap().clone()
        }
    };
    match file_descriptor.delete(&path, flags.contains(UnlinkatFlags::AT_REMOVEDIR)) {
        Ok(_) => SUCCESS,
        Err(errno) => errno,
    }
}

bitflags! {
    pub struct UmountFlags: u32 {
        const MNT_FORCE           =   1;
        const MNT_DETACH          =   2;
        const MNT_EXPIRE          =   4;
        const UMOUNT_NOFOLLOW     =   8;
    }
}

pub fn sys_umount2(target: *const u8, flags: u32) -> isize {
    if target.is_null() {
        return EINVAL;
    }
    let token = current_user_token();
    let target = translated_str(token, target);
    let flags = match UmountFlags::from_bits(flags) {
        Some(flags) => flags,
        None => return EINVAL,
    };
    info!("[sys_umount2] target: {}, flags: {:?}", target, flags);
    warn!("[sys_umount2] fake implementation!");
    SUCCESS
}

bitflags! {
    pub struct MountFlags: usize {
        const MS_RDONLY         =   1;
        const MS_NOSUID         =   2;
        const MS_NODEV          =   4;
        const MS_NOEXEC         =   8;
        const MS_SYNCHRONOUS    =   16;
        const MS_REMOUNT        =   32;
        const MS_MANDLOCK       =   64;
        const MS_DIRSYNC        =   128;
        const MS_NOATIME        =   1024;
        const MS_NODIRATIME     =   2048;
        const MS_BIND           =   4096;
        const MS_MOVE           =   8192;
        const MS_REC            =   16384;
        const MS_SILENT         =   32768;
        const MS_POSIXACL       =   (1<<16);
        const MS_UNBINDABLE     =   (1<<17);
        const MS_PRIVATE        =   (1<<18);
        const MS_SLAVE          =   (1<<19);
        const MS_SHARED         =   (1<<20);
        const MS_RELATIME       =   (1<<21);
        const MS_KERNMOUNT      =   (1<<22);
        const MS_I_VERSION      =   (1<<23);
        const MS_STRICTATIME    =   (1<<24);
        const MS_LAZYTIME       =   (1<<25);
        const MS_NOREMOTELOCK   =   (1<<27);
        const MS_NOSEC          =   (1<<28);
        const MS_BORN           =   (1<<29);
        const MS_ACTIVE         =   (1<<30);
        const MS_NOUSER         =   (1<<31);
    }
}

pub fn sys_mount(
    source: *const u8,
    target: *const u8,
    filesystemtype: *const u8,
    mountflags: usize,
    data: *const u8,
) -> isize {
    if source.is_null() || target.is_null() || filesystemtype.is_null() {
        return EINVAL;
    }
    let token = current_user_token();
    let source = translated_str(token, source);
    let target = translated_str(token, target);
    let filesystemtype = translated_str(token, filesystemtype);
    // infallible
    let mountflags = MountFlags::from_bits(mountflags).unwrap();
    info!(
        "[sys_mount] source: {}, target: {}, filesystemtype: {}, mountflags: {:?}, data: {:?}",
        source, target, filesystemtype, mountflags, data
    );
    warn!("[sys_mount] fake implementation!");
    SUCCESS
}

bitflags! {
    pub struct UtimensatFlags: u32 {
        const AT_SYMLINK_NOFOLLOW = 0x100;
    }
}

pub fn sys_utimensat(
    dirfd: usize,
    pathname: *const u8,
    times: *const [TimeSpec; 2],
    flags: u32,
) -> isize {
    const UTIME_NOW: usize = 0x3fffffff;
    const UTIME_OMIT: usize = 0x3ffffffe;

    let token = current_user_token();
    let path = translated_str(token, pathname);
    let flags = match UtimensatFlags::from_bits(flags) {
        Some(flags) => flags,
        None => {
            warn!("[sys_utimensat] unknown flags");
            return EINVAL;
        }
    };

    info!(
        "[sys_utimensat] dirfd: {}, path: {}, times: {:?}, flags: {:?}",
        dirfd, path, times, flags
    );

    let inode = match __openat(dirfd, &path) {
        Ok(inode) => inode,
        Err(errno) => return errno,
    };

    let now = TimeSpec::now();
    let timespec = &mut [now; 2];
    let mut atime = Some(now.tv_sec);
    let mut mtime = Some(now.tv_sec);
    if !times.is_null() {
        copy_from_user(token, times, timespec);
        match timespec[0].tv_nsec {
            UTIME_NOW => (),
            UTIME_OMIT => atime = None,
            _ => atime = Some(timespec[0].tv_sec),
        }
        match timespec[1].tv_nsec {
            UTIME_NOW => (),
            UTIME_OMIT => mtime = None,
            _ => mtime = Some(timespec[1].tv_sec),
        }
    }

    inode.set_timestamp(None, atime, mtime);
    SUCCESS
}

/// # Warning
/// `acquire_inner_lock()` is called in this function
fn __openat(dirfd: usize, path: &str) -> Result<FileDescriptor, isize> {
    let task = current_task().unwrap();
    let file_descriptor = match dirfd {
        AT_FDCWD => task.fs.lock().working_inode.as_ref().clone(),
        fd => {
            let fd_table = task.files.lock();
            if fd >= fd_table.len() || fd_table[fd].is_none() {
                return Err(EBADF);
            }
            fd_table[fd].as_ref().unwrap().clone()
        }
    };
    file_descriptor.open(path, OpenFlags::O_RDONLY, false)
}

#[allow(non_camel_case_types)]
#[derive(Debug, Eq, PartialEq, FromPrimitive)]
#[repr(u32)]
pub enum Fcntl_Command {
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
    let mut fd_table = task.files.lock();

    if fd >= fd_table.len() || fd_table[fd].is_none() {
        return EBADF;
    }

    info!(
        "[sys_fcntl] fd:{}, cmd:{:?}, arg:{:X}",
        fd,
        Fcntl_Command::from_primitive(cmd),
        arg
    );
    let file_descriptor = fd_table[fd].as_mut().unwrap();
    match Fcntl_Command::from_primitive(cmd) {
        Fcntl_Command::DUPFD | Fcntl_Command::DUPFD_CLOEXEC => {
            let newfd = match fd_table.alloc_fd_at(arg) {
                Some(fd) => fd,
                // cmd is F_DUPFD and arg is negative or is greater than the maximum allowable value
                None => return EINVAL,
            };
            drop(fd_table);
            // take advantage of `DUPFD == 0`
            sys_dup3(fd, newfd, OpenFlags::O_CLOEXEC.bits() & cmd)
        }
        Fcntl_Command::GETFD => file_descriptor.get_cloexec() as isize,
        Fcntl_Command::SETFD => {
            file_descriptor.set_cloexec((arg & FD_CLOEXEC) != 0);
            if (arg & !FD_CLOEXEC) != 0 {
                warn!("[fcntl] Unsupported flag exists: {:X}", arg);
            }
            SUCCESS
        }
        Fcntl_Command::GETFL => {
            // Access control is not fully implemented
            OpenFlags::O_RDWR.bits() as isize
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
    timeout: *mut TimeSpec,
    sigmask: *const crate::task::signal::Signals,
) -> isize {
    pub fn copy_from_user_refmut<T: Copy>(
        token: usize,
        user_ptr: *mut T,
    ) -> Option<&'static mut T> {
        if !user_ptr.is_null() {
            let layout = Layout::new::<T>();
            let kernel_ptr = unsafe { alloc(layout).cast::<T>() };
            copy_from_user(token, user_ptr, kernel_ptr);
            unsafe { kernel_ptr.as_mut() }
        } else {
            None
        }
    }
    pub fn write_back_and_release<T: Copy>(
        token: usize,
        kernel_ref: Option<&'static mut T>,
        user_ptr: *mut T,
    ) {
        if let Some(kernel_ref) = kernel_ref {
            copy_to_user(token, kernel_ref, user_ptr);
            let layout = Layout::new::<T>();
            unsafe { dealloc((kernel_ref as *mut T).cast::<u8>(), layout) };
        }
    }
    if (nfds as isize) < 0 {
        return -1;
    }
    let token = current_user_token();
    let mut kread_fds = copy_from_user_refmut(token, read_fds);
    let mut kwrite_fds = copy_from_user_refmut(token, write_fds);
    let mut kexception_fds = copy_from_user_refmut(token, exception_fds);
    let ktimeout = copy_from_user_refmut(token, timeout);
    let ret = pselect(
        nfds,
        &mut kread_fds,
        &mut kwrite_fds,
        &mut kexception_fds,
        &ktimeout,
        sigmask,
    );
    if let Some(kread_fds) = &kread_fds {
        trace!("[pselect] read_fds: {:?}", kread_fds);
    }
    write_back_and_release(token, kread_fds, read_fds);
    if let Some(kwrite_fds) = &kwrite_fds {
        trace!("[pselect] write_fds: {:?}", kwrite_fds);
    }
    write_back_and_release(token, kwrite_fds, write_fds);
    if let Some(kexception_fds) = &kexception_fds {
        trace!("[pselect] exception_fds: {:?}", kexception_fds);
    }
    write_back_and_release(token, kexception_fds, exception_fds);
    ret
}

/// umask() sets the calling process's file mode creation mask (umask) to
/// mask & 0777 (i.e., only the file permission bits of mask are used),
/// and returns the previous value of the mask.
/// # WARNING
/// In current implementation, umask is always 0. This syscall won't do anything.
pub fn sys_umask(mask: u32) -> isize {
    info!("[sys_umask] mask: {:o}", mask);
    warn!(
        "[sys_umask] In current implementation, umask is always 0. This syscall won't do anything."
    );
    0
}

bitflags! {
    pub struct FaccessatMode: u32 {
        const F_OK = 0;
        const R_OK = 4;
        const W_OK = 2;
        const X_OK = 1;
    }
    pub struct FaccessatFlags: u32 {
        const AT_SYMLINK_NOFOLLOW = 0x100;
        const AT_EACCESS = 0x200;
    }
}

pub fn sys_faccessat2(dirfd: usize, pathname: *const u8, mode: u32, flags: u32) -> isize {
    let token = current_user_token();
    let pathname = translated_str(token, pathname);
    let mode = match FaccessatMode::from_bits(mode) {
        Some(mode) => mode,
        None => {
            warn!("[sys_faccessat2] unknown mode");
            return EINVAL;
        }
    };
    let flags = match FaccessatFlags::from_bits(flags) {
        Some(flags) => flags,
        None => {
            warn!("[sys_faccessat2] unknown flags");
            return EINVAL;
        }
    };

    info!(
        "[sys_faccessat2] dirfd: {}, pathname: {}, mode: {:?}, flags: {:?}",
        dirfd, pathname, mode, flags
    );

    // Do not check user's authority, because user group is not implemented yet.
    // All existing files can be accessed.
    match __openat(dirfd, pathname.as_str()) {
        Ok(_) => SUCCESS,
        Err(errno) => errno,
    }
}
