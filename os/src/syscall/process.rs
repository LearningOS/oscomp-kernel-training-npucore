use crate::fs::{open, DiskInodeType, OpenFlags};
use crate::mm::{translated_ref, translated_refmut, translated_str, UserBuffer, translated_byte_buffer};
use crate::task::{
    add_task, current_task, current_user_token, exit_current_and_run_next,
    suspend_current_and_run_next,
};
use crate::timer::get_time_ms;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::size_of;

pub struct utsname{
    sysname: [u8; 65],
    nodename: [u8; 65],
    release: [u8; 65],
    version: [u8; 65],
    machine: [u8; 65],
    domainname: [u8; 65],
}

impl utsname{
    pub fn new() -> Self{
        Self{
            sysname: utsname::str2u8("Linux"),
            nodename: utsname::str2u8("debian"),
            release: utsname::str2u8("5.10.0-7-riscv64"),
            version: utsname::str2u8("#1 SMP Debian 5.10.40-1 (2021-05-28)"),
            machine: utsname::str2u8("riscv64"),
            domainname: utsname::str2u8(""),
        }
    }

    fn str2u8(str: &str) -> [u8;65]{
        let mut arr:[u8;65] = [0;65];
        let str_bytes = str.as_bytes();
        let len = str.len();
        for i in 0..len{
            arr[i] = str_bytes[i];
        }
        arr
    }
    
    pub fn as_bytes(&self) -> &[u8] {
        let size = core::mem::size_of::<Self>();
        unsafe {
            core::slice::from_raw_parts(
                self as *const _ as usize as *const u8,
                size,
            )
        }
    }
}

pub fn sys_exit(exit_code: i32) -> ! {
    exit_current_and_run_next(exit_code);
    panic!("Unreachable in sys_exit!");
}

pub fn sys_yield() -> isize {
    suspend_current_and_run_next();
    0
}

pub fn sys_get_time() -> isize {
    get_time_ms() as isize
}

pub fn sys_uname(buf: *mut u8) -> isize {
    let token = current_user_token();
    let mut buf_vec = translated_byte_buffer(token, buf, size_of::<utsname>());
    let uname = utsname::new();
    // 使用UserBuffer结构，以便于跨页读写
    let mut userbuf = UserBuffer::new(buf_vec);
    userbuf.write(uname.as_bytes());
    0
}

pub fn sys_getpid() -> isize {
    current_task().unwrap().pid.0 as isize
}

pub fn sys_getuid() -> isize {
    0 // root user
}

pub fn sys_geteuid() -> isize {
    0 // root user
}

pub fn sys_getgid() -> isize {
    0 // root group
}

pub fn sys_getegid() -> isize {
    0 // root group
}

// For user, tid is pid in kernel
pub fn sys_gettid() -> isize {
    current_task().unwrap().pid.0 as isize
}

pub fn sys_sbrk(increment: isize) -> isize {
    current_task().unwrap().sbrk(increment) as isize
}

pub fn sys_brk(brk_addr: usize) -> isize{
    let mut new_addr = 0;
    if brk_addr == 0 {
        new_addr = current_task().unwrap().sbrk(0);
    }
    else{
        let former_addr = current_task().unwrap().sbrk(0);
        let grow_size: isize = (brk_addr - former_addr) as isize;
        new_addr = current_task().unwrap().sbrk(grow_size);
    }
    
    println!("[sys_brk] brk_addr:{:X}; new_addr:{:X}", brk_addr, new_addr);
    new_addr as isize
}

pub fn sys_fork() -> isize {
    let current_task = current_task().unwrap();
    let new_task = current_task.fork();
    let new_pid = new_task.pid.0;
    // modify trap context of new_task, because it returns immediately after switching
    let trap_cx = new_task.acquire_inner_lock().get_trap_cx();
    // we do not have to move to next instruction since we have done it before
    // for child process, fork returns 0
    trap_cx.x[10] = 0;
    // add new task to scheduler
    add_task(new_task);
    new_pid as isize
}

pub fn sys_exec(path: *const u8, mut args: *const usize) -> isize {
    let token = current_user_token();
    let path = translated_str(token, path);
    let mut args_vec: Vec<String> = Vec::new();
    loop {
        let arg_str_ptr = *translated_ref(token, args);
        if arg_str_ptr == 0 {
            break;
        }
        args_vec.push(translated_str(token, arg_str_ptr as *const u8));
        unsafe {
            args = args.add(1);
        }
    }
    let task = current_task().unwrap();
    let mut inner = task.acquire_inner_lock();
    if let Some(app_inode) = open(
        inner.get_work_path().as_str(),
        path.as_str(),
        OpenFlags::RDONLY,
        crate::fs::DiskInodeType::File,
    ) {
        drop(inner);
        let len = app_inode.get_size();
        println!("[sys_exec] File size: {} bytes", len);
        let all_data = app_inode.read_all();
        println!("[sys_exec] read_all() DONE.");

        let argc = args_vec.len();
        task.exec(all_data.as_slice(), args_vec);
        println!("[sys_exec] exec() DONE.");
        // return argc because cx.x[10] will be covered with it later
        //argc as isize
        0
    } else {
        -1
    }
}

/// If there is not a child process whose pid is same as given, return -1.
/// Else if there is a child process but it is still running, return -2.
pub fn sys_waitpid(pid: isize, exit_code_ptr: *mut i32) -> isize {
    let task = current_task().unwrap();
    // find a child process

    // ---- hold current PCB lock
    let mut inner = task.acquire_inner_lock();
    if inner
        .children
        .iter()
        .find(|p| pid == -1 || pid as usize == p.getpid())
        .is_none()
    {
        return -1;
        // ---- release current PCB lock
    }
    let pair = inner.children.iter().enumerate().find(|(_, p)| {
        // ++++ temporarily hold child PCB lock
        p.acquire_inner_lock().is_zombie() && (pid == -1 || pid as usize == p.getpid())
        // ++++ release child PCB lock
    });
    if let Some((idx, _)) = pair {
        let child = inner.children.remove(idx);
        // confirm that child will be deallocated after being removed from children list
        assert_eq!(Arc::strong_count(&child), 1);
        let found_pid = child.getpid();
        // ++++ temporarily hold child lock
        let exit_code = child.acquire_inner_lock().exit_code;
        // ++++ release child PCB lock
        *translated_refmut(inner.memory_set.token(), exit_code_ptr) = exit_code;
        found_pid as isize
    } else {
        -2
    }
    // ---- release current PCB lock automatically
}

pub fn sys_set_tid_address(tidptr: usize) -> isize {
    current_task().unwrap().acquire_inner_lock().address.clear_child_tid = tidptr;
    sys_gettid()
}

pub fn sys_mmap(
    start: usize,
    len: usize,
    prot: usize,
    flags: usize,
    fd: usize,
    offset: usize,
) -> isize {
    let task = current_task().unwrap();
    task.mmap(start, len, prot, flags, fd, offset) as isize
}

pub fn sys_munmap(start: usize, len: usize) -> isize {
    let task = current_task().unwrap();
    task.munmap(start, len) as isize
}
