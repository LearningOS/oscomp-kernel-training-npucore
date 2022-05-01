use crate::config::{CLOCK_FREQ, MMAP_BASE, PAGE_SIZE};
use crate::mm::{
    copy_from_user, copy_to_user, mmap, munmap, sbrk, translated_byte_buffer, translated_ref,
    translated_refmut, translated_str, MapFlags, MapPermission, UserBuffer,
};
use crate::show_frame_consumption;
use crate::syscall::errno::*;
use crate::task::{
    add_task, block_current_and_run_next, current_task, current_user_token,
    exit_current_and_run_next, find_task_by_pid, signal::*, suspend_current_and_run_next,
    wake_interruptible, Rusage, TaskStatus,
};
use crate::timer::{get_time, get_time_ms, ITimerVal, TimeSpec, TimeVal, TimeZone, NSEC_PER_SEC, Times};
use crate::trap::TrapContext;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::size_of;
use log::{debug, error, info, trace, warn};
use num_enum::FromPrimitive;

pub fn sys_exit(exit_code: u32) -> ! {
    exit_current_and_run_next((exit_code & 0xff) << 8);
}

pub fn sys_yield() -> isize {
    suspend_current_and_run_next();
    0
}

pub fn sys_kill(pid: usize, sig: usize) -> isize {
    let signal = match Signals::from_signum(sig) {
        Ok(signal) => signal,
        Err(_) => return EINVAL,
    };
    if pid > 0 {
        if let Some(task) = find_task_by_pid(pid) {
            if let Some(signal) = signal {
                let mut inner = task.acquire_inner_lock();
                inner.add_signal(signal);
                // wake up target process if it is sleeping
                if inner.task_status == TaskStatus::Interruptible {
                    inner.task_status = TaskStatus::Ready;
                    wake_interruptible(task.clone());
                }
            }
            SUCCESS
        } else {
            ESRCH
        }
    } else if pid == 0 {
        todo!()
    } else if (pid as isize) == -1 {
        todo!()
    } else {
        // (pid as isize) < -1
        todo!()
    }
}

pub fn sys_nanosleep(req: *const TimeSpec, rem: *mut TimeSpec) -> isize {
    if req as usize == 0 {
        return EINVAL;
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
    } else {
        let task = current_task().unwrap();
        let mut remain = end - TimeSpec::now();
        while !remain.is_zero() {
            let inner = task.acquire_inner_lock();
            if inner
                .siginfo
                .signal_pending
                .difference(inner.sigmask)
                .is_empty()
            {
                drop(inner);
                suspend_current_and_run_next();
            } else {
                // this will ensure that *rem > 0
                copy_to_user(token, &remain, rem);
                return EINTR;
            }
            remain = end - TimeSpec::now();
        }
    }
    SUCCESS
}

pub fn sys_setitimer(
    which: usize,
    new_value: *const ITimerVal,
    old_value: *mut ITimerVal,
) -> isize {
    info!(
        "[sys_setitimer] which: {}, new_value: {:?}, old_value: {:?}",
        which, new_value, old_value
    );
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
        _ => -1,
    }
}

pub fn sys_get_time_of_day(time_val: *mut TimeVal, time_zone: *mut TimeZone) -> isize {
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

#[allow(unused)]
pub struct UTSName {
    sysname: [u8; 65],
    nodename: [u8; 65],
    release: [u8; 65],
    version: [u8; 65],
    machine: [u8; 65],
    domainname: [u8; 65],
}

pub fn sys_uname(buf: *mut u8) -> isize {
    let token = current_user_token();
    let mut buffer = UserBuffer::new(translated_byte_buffer(token, buf, size_of::<UTSName>()));
    // A little stupid but still efficient.
    const FIELD_OFFSET: usize = 65;
    buffer.write_at(FIELD_OFFSET * 0, b"Linux\0");
    buffer.write_at(FIELD_OFFSET * 1, b"debian\0");
    buffer.write_at(FIELD_OFFSET * 2, b"5.10.0-7-riscv64\0");
    buffer.write_at(FIELD_OFFSET * 3, b"#1 SMP Debian 5.10.40-1 (2021-05-28)\0");
    buffer.write_at(FIELD_OFFSET * 4, b"riscv64\0");
    buffer.write_at(FIELD_OFFSET * 5, b"\0");
    SUCCESS
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
    let task = crate::task::find_task_by_pid(pid);
    match task {
        Some(task) => task.setpgid(pgid),
        None => -1,
    }
}

pub fn sys_getpgid(pid: usize) -> isize {
    /* An attempt.*/
    let task = crate::task::find_task_by_pid(pid);
    match task {
        Some(task) => task.getpgid() as isize,
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
    let new_addr: usize;
    if brk_addr == 0 {
        new_addr = sbrk(0);
    } else {
        let former_addr = sbrk(0);
        let grow_size: isize = (brk_addr - former_addr) as isize;
        new_addr = sbrk(grow_size);
    }

    info!(
        "[sys_brk] brk_addr: {:X}; new_addr: {:X}",
        brk_addr, new_addr
    );
    new_addr as isize
}

bitflags! {
    struct CloneFlags: u32 {
        //const CLONE_NEWTIME         =   0x00000080;
        const CLONE_VM              =   0x00000100;
        const CLONE_FS              =   0x00000200;
        const CLONE_FILES           =   0x00000400;
        const CLONE_SIGHAND         =   0x00000800;
        const CLONE_PIDFD           =   0x00001000;
        const CLONE_PTRACE          =   0x00002000;
        const CLONE_VFORK           =   0x00004000;
        const CLONE_PARENT          =   0x00008000;
        const CLONE_THREAD          =   0x00010000;
        const CLONE_NEWNS           =   0x00020000;
        const CLONE_SYSVSEM         =   0x00040000;
        const CLONE_SETTLS          =   0x00080000;
        const CLONE_PARENT_SETTID   =   0x00100000;
        const CLONE_CHILD_CLEARTID  =   0x00200000;
        const CLONE_DETACHED        =   0x00400000;
        const CLONE_UNTRACED        =   0x00800000;
        const CLONE_CHILD_SETTID    =   0x01000000;
        const CLONE_NEWCGROUP       =   0x02000000;
        const CLONE_NEWUTS          =   0x04000000;
        const CLONE_NEWIPC          =   0x08000000;
        const CLONE_NEWUSER         =   0x10000000;
        const CLONE_NEWPID          =   0x20000000;
        const CLONE_NEWNET          =   0x40000000;
        const CLONE_IO              =   0x80000000;
    }
}

/// # Explanation of Parameters
/// Mainly about `ptid`, `tls` and `ctid`: \
/// `CLONE_SETTLS`: The TLS (Thread Local Storage) descriptor is set to `tls`. \
/// `CLONE_PARENT_SETTID`: Store the child thread ID at the location pointed to by `ptid` in the parent's memory. \
/// `CLONE_CHILD_SETTID`: Store the child thread ID at the location pointed to by `ctid` in the child's memory. \
/// `ptid` is also used in `CLONE_PIDFD` (since Linux 5.2) \
/// Since user programs rarely use these, we could do lazy implementation.
pub fn sys_clone(
    flags: u32,
    stack: *const u8,
    ptid: *const u32,
    tls: *const usize,
    ctid: *const u32,
) -> isize {
    let current_task = current_task().unwrap();
    // This signal will be sent to its parent when it exits
    // we need to add a field in TCB to support this feature, but not now.
    let exit_signal = match Signals::from_signum((flags & 0xff) as usize) {
        Ok(signal) => signal,
        Err(_) => {
            // This is permitted by standard, but we only support 64 signals
            todo!()
        }
    };
    // Sure to succeed, because all bits are valid (See `CloneFlags`)
    let flags = CloneFlags::from_bits(flags & !0xff).unwrap();
    info!(
        "[sys_clone] flags: {:?}, exit_signal: {:?}, ptid: {:?}, tls: {:?}, ctid: {:?}",
        flags, exit_signal, ptid, tls, ctid
    );
    show_frame_consumption! {
        "fork";
        let new_task = current_task.fork();
    }
    let new_pid = new_task.pid.0;
    // modify trap context of new_task, because it returns immediately after switching
    let trap_cx = new_task.acquire_inner_lock().get_trap_cx();
    // we do not have to move to next instruction since we have done it before
    // we also do not need to prepare parameters on stack, musl has done it for us
    if !stack.is_null() {
        trap_cx.x[2] = stack as usize;
    }
    // for child process, fork returns 0
    trap_cx.x[10] = 0;
    // add new task to scheduler
    add_task(new_task);
    new_pid as isize
}

pub fn sys_execve(
    pathname: *const u8,
    mut argv: *const *const u8,
    mut envp: *const *const u8,
) -> isize {
    let token = current_user_token();
    let path = translated_str(token, pathname);
    let mut argv_vec: Vec<String> = Vec::new();
    let mut envp_vec: Vec<String> = Vec::new();
    if !argv.is_null() {
        loop {
            let arg_ptr = *translated_ref(token, argv);
            if arg_ptr.is_null() {
                break;
            }
            argv_vec.push(translated_str(token, arg_ptr));
            unsafe {
                argv = argv.add(1);
            }
        }
    }
    if !envp.is_null() {
        loop {
            let env_ptr = *translated_ref(token, envp);
            if env_ptr.is_null() {
                break;
            }
            envp_vec.push(translated_str(token, env_ptr));
            unsafe {
                envp = envp.add(1);
            }
        }
    }
    crate::task::execve(path, argv_vec, envp_vec)
}

bitflags! {
    struct WaitOption: u32 {
        const WNOHANG    = 1;
        const WSTOPPED   = 2;
        const WEXITED    = 4;
        const WCONTINUED = 8;
        const WNOWAIT    = 0x1000000;
    }
}
/// If there is not a child process whose pid is same as given, return -1.
/// Else if there is a child process but it is still running, return -2.
pub fn sys_wait4(pid: isize, status: *mut u32, option: u32, ru: *mut Rusage) -> isize {
    let option = WaitOption::from_bits(option).unwrap();
    info!("[sys_waitpid] pid: {}, option: {:?}", pid, option);
    let task = current_task().unwrap();
    loop {
        // find a child process

        // ---- hold current PCB lock
        let mut inner = task.acquire_inner_lock();
        if inner
            .children
            .iter()
            .find(|p| pid == -1 || pid as usize == p.getpid())
            .is_none()
        {
            return ECHILD;
            // ---- release current PCB lock
        }
        inner
            .children
            .iter()
            .filter(|p| pid == -1 || pid as usize == p.getpid())
            .for_each(|p| {
                info!(
                    "pid: {}, status: {:?}",
                    p.pid.0,
                    p.acquire_inner_lock().task_status
                )
            });
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
            if status as usize != 0 {
                // this may NULL!!!
                *translated_refmut(inner.memory_set.token(), status) = exit_code;
            }
            return found_pid as isize;
        } else {
            drop(inner);
            if option.contains(WaitOption::WNOHANG) {
                return SUCCESS;
            } else {
                block_current_and_run_next();
            }
        }
    }
}

#[allow(unused)]
#[derive(Clone, Copy, Debug)]
pub struct RLimit {
    rlim_cur: usize, /* Soft limit */
    rlim_max: usize, /* Hard limit (ceiling for rlim_cur) */
}

#[derive(Debug, Eq, PartialEq, FromPrimitive)]
#[repr(u32)]
pub enum Resource {
    CPU = 0,
    FSIZE = 1,
    DATA = 2,
    STACK = 3,
    CORE = 4,
    RSS = 5,
    NPROC = 6,
    NOFILE = 7,
    MEMLOCK = 8,
    AS = 9,
    LOCKS = 10,
    SIGPENDING = 11,
    MSGQUEUE = 12,
    NICE = 13,
    RTPRIO = 14,
    RTTIME = 15,
    NLIMITS = 16,
    #[num_enum(default)]
    ILLEAGAL,
}

/// It can be used to both set and get the resource limits of an arbitrary process.
/// # WARNING
/// Partial implementation
pub fn sys_prlimit(
    pid: usize,
    resource: u32,
    new_limit: *const RLimit,
    old_limit: *mut RLimit,
) -> isize {
    if pid == 0 {
        let task = current_task().unwrap();
        let inner = task.acquire_inner_lock();
        let token = inner.get_user_token();
        let resource = Resource::from_primitive(resource);
        info!("[sys_prlimit] pid: {}, resource: {:?}", pid, resource);

        drop(inner);
        if !old_limit.is_null() {
            match resource {
                Resource::NPROC => {
                    copy_to_user(
                        token,
                        &(RLimit {
                            rlim_cur: 32,
                            rlim_max: 32,
                        }),
                        old_limit,
                    );
                }
                Resource::NOFILE => {
                    copy_to_user(
                        token,
                        &(RLimit {
                            rlim_cur: 64,
                            rlim_max: 128,
                        }),
                        old_limit,
                    );
                }
                Resource::ILLEAGAL => return EINVAL,
                _ => todo!(),
            }
        }
        if !new_limit.is_null() {
            let rlimit = &mut RLimit {rlim_cur: 0, rlim_max: 0};
            copy_from_user(
                token,
                new_limit,
                rlimit,
            );
            warn!("[sys_prlimit] new_limit is not implemented yet, but it's not null! new_limit: {:?}", rlimit);
            match resource {
                Resource::NOFILE => {
                    // Not implemented yet, for the sake of test we don't panic.
                }
                Resource::ILLEAGAL => return EINVAL,
                _ => todo!(),
            }
        }
    } else {
        todo!();
    }
    SUCCESS
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
        start, len, prot, flags, fd as isize, offset
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
    warn!(
        "[sys_mprotect] addr: {:X}, len: {:X}, prot: {:?}",
        addr, len, prot
    );
    assert!(!prot.contains(MapPermission::W));
    // let task = current_task().unwrap();
    // let memory_set = &mut task.acquire_inner_lock().memory_set;
    // let start_vpn = addr / PAGE_SIZE;
    // for i in 0..(len / PAGE_SIZE) {
    // here (prot << 1) is identical to BitFlags of X/W/R in pte flags
    // if memory_set.set_pte_flags(start_vpn.into(), MapPermission::from_bits((prot as u8) << 1).unwrap()) == -1 {
    // if fail
    //     panic!("sys_mprotect: No such pte");
    // }
    // }
    // fence here if we have multi harts
    0
}

pub fn sys_clock_get_time(clk_id: usize, tp: *mut u64) -> isize {
    if tp as usize == 0 {
        // point is null
        return 0;
    }

    let token = current_user_token();
    let ticks = get_time();
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
pub fn sys_sigprocmask(how: u32, set: usize, oldset: usize) -> isize {
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
    let inner = current_task.acquire_inner_lock();
    // restore trap_cx
    let trap_cx = inner.get_trap_cx();
    let sp = trap_cx.x[2];
    copy_from_user(inner.get_user_token(), sp as *const TrapContext, trap_cx);
    return trap_cx.x[10] as isize; //return a0: not modify any of trap_cx
}

pub fn sys_times(buf: *mut Times) -> isize {
    let task = current_task().unwrap();
    let inner = task.acquire_inner_lock();
    let token = inner.get_user_token();
    let times = Times {
        tms_utime: inner.rusage.ru_utime.to_tick(),
        tms_stime: inner.rusage.ru_stime.to_tick(),
        tms_cutime: 0,
        tms_cstime: 0,
    };
    copy_to_user(token, &times, buf);
    // return clock ticks that have elapsed since an arbitrary point in the past
    get_time() as isize
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
