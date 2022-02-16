use crate::config::{CLOCK_FREQ, PAGE_SIZE, MMAP_BASE};
use crate::fs::{open, DiskInodeType, OpenFlags};
use crate::mm::{
    translated_byte_buffer, translated_ref, translated_refmut, translated_str, UserBuffer, copy_from_user, copy_to_user, MapPermission, MapFlags, mmap, munmap, sbrk,
};
use crate::task::{
    add_task, current_task, current_user_token, exit_current_and_run_next,
    suspend_current_and_run_next, Rusage,
};
use crate::task::{block_current_and_run_next, signal::*};
use crate::timer::{get_time, get_time_ms, TimeSpec, TimeVal, ITimerVal, TimeZone};
use crate::trap::TrapContext;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::size_of;
use log::{debug, error, info, trace, warn};

pub struct utsname {
    sysname: [u8; 65],
    nodename: [u8; 65],
    release: [u8; 65],
    version: [u8; 65],
    machine: [u8; 65],
    domainname: [u8; 65],
}

impl utsname {
    pub fn new() -> Self {
        Self {
            sysname: utsname::str2u8("Linux"),
            nodename: utsname::str2u8("debian"),
            release: utsname::str2u8("5.10.0-7-riscv64"),
            version: utsname::str2u8("#1 SMP Debian 5.10.40-1 (2021-05-28)"),
            machine: utsname::str2u8("riscv64"),
            domainname: utsname::str2u8(""),
        }
    }

    fn str2u8(str: &str) -> [u8; 65] {
        let mut arr: [u8; 65] = [0; 65];
        let str_bytes = str.as_bytes();
        let len = str.len();
        for i in 0..len {
            arr[i] = str_bytes[i];
        }
        arr
    }

    pub fn as_bytes(&self) -> &[u8] {
        let size = core::mem::size_of::<Self>();
        unsafe { core::slice::from_raw_parts(self as *const _ as usize as *const u8, size) }
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

pub fn sys_nano_sleep(
    req: *const TimeSpec,
    rem: *mut TimeSpec,
) -> isize {
    if req as usize == 0 {
        return -1;
    }
    let token = current_user_token();
    let start = TimeSpec::now();
    let len = &mut TimeSpec::new();
    copy_from_user(token, req, len);
    let end = start + *len;
    if rem as usize == 0 {
        while !(end - TimeSpec::now()).is_zero() {
            suspend_current_and_run_next();
        }
    }
    else {
        let task = current_task().unwrap();
        let mut remain = end - TimeSpec::now();
        while !remain.is_zero() {
            let inner = task.acquire_inner_lock();
            if inner.siginfo.signal_pending.difference(inner.sigmask).is_empty() {
                suspend_current_and_run_next();
            }
            else {
                // this will ensure that *rem > 0
                copy_to_user(token, &remain, rem);
                return -1;
            }
            remain = end - TimeSpec::now();
        }
    }
    0
}

pub fn sys_setitimer(
    which: usize,
    new_value: *const ITimerVal,
    old_value: *mut ITimerVal,
) -> isize {
    info!("[sys_setitimer] which: {}, new_value: {:?}, old_value: {:?}", which, new_value, old_value);
    match which {
        0..=2 => {
            let task = current_task().unwrap();
            let mut inner = task.acquire_inner_lock();
            let token = inner.get_user_token();
            if old_value as usize != 0 {
                copy_to_user(token, &inner.timer[which], old_value);
                trace!("[sys_setitimer] *old_value: {:?}", inner.timer[which]);
            }
            if new_value as usize != 0 {
                copy_from_user(token, new_value, &mut inner.timer[which]);
                trace!("[sys_setitimer] *new_value: {:?}", inner.timer[which]);
            }
            0
        }
        _ => -1
    }
}

pub fn sys_get_time_of_day(
    time_val: *mut TimeVal,
    time_zone: *mut TimeZone,
) -> isize {
    // Timezone is currently NOT supported.
    let ans = &TimeVal::now();
    if time_val as usize != 0 {
        copy_to_user(current_user_token(), ans, time_val);
    }
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
    let pid = current_task().unwrap().pid.0;
    //info!("[sys_getpid] pid:{}", pid);
    pid as isize
}

pub fn sys_getppid() -> isize {
    let task = current_task().unwrap();
    let inner = task.acquire_inner_lock();
    let ppid = inner.parent.as_ref().unwrap().upgrade().unwrap().pid.0;
    //info!("[sys_getppid] ppid:{}", ppid);
    ppid as isize
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

// Warning, we don't support this syscall in fact, task.setpgid() won't take effect for some reason
// So it just pretend to do this work.
// Fortunately, that won't make difference when we just try to run busybox sh so far.
pub fn sys_setpgid(pid: usize, pgid: usize) -> isize {
    /* An attempt.*/
    let mut task = crate::task::find_process_by_pid(pid);
    match task {
        Some(i) => i.setpgid(pgid),
        None => -1,
    }
}

pub fn sys_getpgid(pid: usize) -> isize {
    /* An attempt.*/
    let mut task = crate::task::find_process_by_pid(pid);
    match task {
        Some(i) => i.getpgid() as isize,
        None => -1,
    }
}

// For user, tid is pid in kernel
pub fn sys_gettid() -> isize {
    current_task().unwrap().pid.0 as isize
}

pub fn sys_sbrk(increment: isize) -> isize {
    sbrk(increment) as isize
}

pub fn sys_brk(brk_addr: usize) -> isize {
    let mut new_addr = 0;
    if brk_addr == 0 {
        new_addr = sbrk(0);
    } else {
        let former_addr = sbrk(0);
        let grow_size: isize = (brk_addr - former_addr) as isize;
        new_addr = sbrk(grow_size);
    }

    info!("[sys_brk] brk_addr: {:X}; new_addr: {:X}", brk_addr, new_addr);
    new_addr as isize
}

pub fn sys_fork() -> isize {
    let current_task = current_task().unwrap();
    let before_fork = crate::mm::unallocated_frames();
    let new_task = current_task.fork();
    let after_fork = crate::mm::unallocated_frames();
    let new_pid = new_task.pid.0;
    // modify trap context of new_task, because it returns immediately after switching
    let trap_cx = new_task.acquire_inner_lock().get_trap_cx();
    // we do not have to move to next instruction since we have done it before
    // for child process, fork returns 0
    trap_cx.x[10] = 0;
    // add new task to scheduler
    add_task(new_task);
    debug!("[sys_fork] consumed frames: {}, last frames: {}", before_fork - after_fork, after_fork);
    new_pid as isize
}

pub fn sys_exec(path: *const u8, mut args: *const usize, who: usize) -> isize {
    info!("[sys_exec] Called from: {}", who);
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
    let i = match open(
        inner.get_work_path().as_str(),
        path.as_str(),
        OpenFlags::RDONLY,
        crate::fs::DiskInodeType::File,
    ) {
        Some(app_inode) => {
            drop(inner);
            let len = app_inode.get_size();
            debug!("[sys_exec] File size: {} bytes", len);
            let start: usize = MMAP_BASE;
            let before_read = crate::mm::unallocated_frames();
            crate::mm::KERNEL_SPACE.lock().insert_framed_area(
                start.into(),
                (start + len).into(),
                MapPermission::R | MapPermission::W,
            );
            unsafe {
                app_inode.read_into(&mut core::slice::from_raw_parts_mut(start as *mut u8, len));
            }
            let after_read = crate::mm::unallocated_frames();

            // return argc because cx.x[10] will be covered with it later
            debug!("[sys_exec] read_all() DONE. consumed frames:{}, last frames:{}", before_read - after_read, after_read);
            let task = current_task().unwrap();
            let argc = args_vec.len();
            info!("[sys_exec] argc = {}", argc);
            let before_exec = crate::mm::unallocated_frames();
            unsafe {
                task.exec(core::slice::from_raw_parts(start as *const u8, len), args_vec);
            }
            let after_exec = crate::mm::unallocated_frames();
            debug!("[sys_exec] exec() DONE. consumed frames:{}, last frames:{}", (before_exec - after_exec) as isize, after_exec);

            //remember to UNMAP here!
            // return argc because cx.x[10] will be covered with it later

            argc as isize
        }
        None => -1,
    };
    0
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
        if exit_code_ptr as usize != 0 {
            // this may NULL!!!
            *translated_refmut(inner.memory_set.token(), exit_code_ptr) = exit_code << 8;
        }
        found_pid as isize
    } else {
        drop(inner);
        block_current_and_run_next();
        let task = current_task().unwrap();
        let mut inner = task.acquire_inner_lock();
        let (idx, _) = inner.children.iter().enumerate().find(|(_, p)| {
            // ++++ temporarily hold child PCB lock
            p.acquire_inner_lock().is_zombie() && (pid == -1 || pid as usize == p.getpid())
            // ++++ release child PCB lock
        }).unwrap();
        let child = inner.children.remove(idx);
        // confirm that child will be deallocated after being removed from children list
        assert_eq!(Arc::strong_count(&child), 1);
        let found_pid = child.getpid();
        // ++++ temporarily hold child lock
        let exit_code = child.acquire_inner_lock().exit_code;
        // ++++ release child PCB lock
        if exit_code_ptr as usize != 0 {
            // this may NULL!!!
            *translated_refmut(inner.memory_set.token(), exit_code_ptr) = exit_code;
        }
        found_pid as isize
    }
    // ---- release current PCB lock automatically
}

pub fn sys_set_tid_address(tidptr: usize) -> isize {
    current_task()
        .unwrap()
        .acquire_inner_lock()
        .address
        .clear_child_tid = tidptr;
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
    let prot = MapPermission::from_bits(((prot as u8) << 1) | (1 << 4)).unwrap();
    let flags = MapFlags::from_bits(flags).unwrap();
    info!(
        "[mmap] start:{:X}; len:{:X}; prot:{:?}; flags:{:?}; fd:{}; offset:{:X}",
        start,
        len,
        prot,
        flags,
        fd as isize,
        offset
    );
    mmap(start, len, prot, flags, fd, offset) as isize
}

pub fn sys_munmap(start: usize, len: usize) -> isize {
    
    munmap(start, len) as isize
}

pub fn sys_mprotect(addr: usize, len: usize, prot: usize) -> isize {
    if (addr % PAGE_SIZE != 0) || (len % PAGE_SIZE != 0) {
        // Not align
        warn!("[sys_mprotect] not align");
        return -1;
    }
    let prot = MapPermission::from_bits((prot << 1) as u8).unwrap();
    warn!("[sys_mprotect] addr: {:X}, len: {:X}, prot: {:?}", addr, len, prot);
    assert!(!prot.contains(MapPermission::W));
    let task = current_task().unwrap();
    let memory_set = &mut task.acquire_inner_lock().memory_set;
    let start_vpn = addr / PAGE_SIZE;
    for i in 0..(len / PAGE_SIZE) {
        // here (prot << 1) is identical to BitFlags of X/W/R in pte flags
        // if memory_set.set_pte_flags(start_vpn.into(), MapPermission::from_bits((prot as u8) << 1).unwrap()) == -1 {
            // if fail
        //     panic!("sys_mprotect: No such pte");
        // }
    }
    // fence here if we have multi harts
    0
}

pub const TICKS_PER_SEC: usize = 100;
pub const MSEC_PER_SEC: usize = 1000;
pub const USEC_PER_SEC: usize = 1000_000;
pub const NSEC_PER_SEC: usize = 1000_000_000;

pub fn sys_clock_get_time(clk_id: usize, tp: *mut u64) -> isize {
    if tp as usize == 0 {
        // point is null
        return 0;
    }

    let token = current_user_token();
    let mut ticks = get_time();
    let sec = (ticks / CLOCK_FREQ) as u64;
    let nsec = ((ticks % CLOCK_FREQ) * NSEC_PER_SEC / CLOCK_FREQ) as u64;
    *translated_refmut(token, tp) = sec;
    *translated_refmut(token, unsafe { tp.add(1) }) = nsec;
    info!(
        "sys_get_time(clk_id: {}, tp: (sec: {}, nsec: {}) = {}",
        clk_id, sec, nsec, 0
    );
    0
}

// int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
pub fn sys_sigaction(signum: usize, act: usize, oldact: usize) -> isize {
    info!(
        "[sys_sigaction] signum: {:?}, act: {:X}, oldact: {:X}",
        signum, act, oldact
    );
    sigaction(signum, act as *const SigAction, oldact as *mut SigAction)
}

/// Note: code translation should be done in syscall rather than the call handler as the handler may be reused by kernel code which use kernel structs
pub fn sys_sigprocmask(how: usize, set: usize, oldset: usize) -> isize {
    info!(
        "[sys_sigprocmask] how: {:?}; set: {:X}, oldset: {:X}",
        how, set, oldset
    );
    sigprocmask(how, set as *const Signals, oldset as *mut Signals)
}

pub fn sys_sigreturn() -> isize {
    // mark not processing signal handler
    let current_task = current_task().unwrap();
    info!("[sys_sigreturn] pid: {}", current_task.pid.0);
    let mut inner = current_task.acquire_inner_lock();
    // restore trap_cx
    let trap_cx = inner.get_trap_cx();
    let sp = trap_cx.x[2];
    copy_from_user(inner.get_user_token(), sp as *const TrapContext, trap_cx);
    return trap_cx.x[10] as isize; //return a0: not modify any of trap_cx
}

pub fn sys_getrusage(who: isize, usage: *mut Rusage) -> isize {
    if who != 0 {
        panic!("[sys_getrusage] parameter 'who' is not RUSAGE_SELF.");
    }
    let task = current_task().unwrap();
    let inner = task.acquire_inner_lock();
    let token = inner.get_user_token();
    copy_to_user(token, &inner.rusage, usage);
    //info!("[sys_getrusage] who: RUSAGE_SELF, usage: {:?}", inner.rusage);
    0
}
