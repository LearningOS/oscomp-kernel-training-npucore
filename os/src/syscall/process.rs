use crate::config::{CLOCK_FREQ, MMAP_BASE, PAGE_SIZE, USER_STACK_SIZE};
use crate::fs::{FdTable, OpenFlags};
use crate::mm::{
    copy_from_user, copy_to_user, copy_to_user_string, get_from_user, translated_byte_buffer,
    translated_ref, translated_refmut, translated_str, MapFlags, MapPermission, UserBuffer,
    VirtAddr,
};
use crate::show_frame_consumption;
use crate::syscall::errno::*;
use crate::task::threads::{futex, FUTEX_CLOCK_REALTIME, FUTEX_PRIVATE};
use crate::task::{
    add_task, block_current_and_run_next, current_task, current_user_token,
    exit_current_and_run_next, find_task_by_pid, find_task_by_tgid, procs_count, signal::*,
    suspend_current_and_run_next, threads, wake_interruptible, Rusage, TaskStatus,
};
use crate::timer::{
    get_time, get_time_ms, get_time_sec, ITimerVal, TimeSpec, TimeVal, TimeZone, Times,
    NSEC_PER_SEC,
};
use crate::trap::TrapContext;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::size_of;
use log::{debug, error, info, trace, warn};
use num_enum::FromPrimitive;

pub fn sys_exit(exit_code: u32) -> ! {
    exit_current_and_run_next((exit_code & 0xff) << 8);
}

#[allow(non_camel_case_types)]
#[derive(Debug, Eq, PartialEq, FromPrimitive)]
#[repr(u32)]
pub enum SyslogAction {
    CLOSE = 0,
    OPEN = 1,
    READ = 2,
    READ_ALL = 3,
    READ_CLEAR = 4,
    CLEAR = 5,
    CONSOLE_OFF = 6,
    CONSOLE_ON = 7,
    CONSOLE_LEVEL = 8,
    SIZE_UNREAD = 9,
    SIZE_BUFFER = 10,
    #[default]
    ILLEAGAL,
}

pub fn sys_syslog(type_: u32, buf: *mut u8, len: u32) -> isize {
    const LOG_BUF_LEN: usize = 4096;
    const LOG: &str = "<5>[    0.000000] Linux version 5.10.102.1-microsoft-standard-WSL2 (rtrt@TEAM-NPUCORE) (gcc (Ubuntu 9.4.0-1ubuntu1~20.04) 9.4.0, GNU ld (GNU Binutils for Ubuntu) 2.34) #1 SMP Thu Mar 10 13:31:47 CST 2022";
    let token = current_user_token();
    let type_ = SyslogAction::from(type_);
    let len = LOG.len().min(len as usize);
    match type_ {
        SyslogAction::CLOSE | SyslogAction::OPEN => SUCCESS,
        SyslogAction::READ => {
            copy_to_user_string(token, &LOG[..len], buf);
            len as isize
        }
        SyslogAction::READ_ALL => {
            copy_to_user_string(token, &LOG[LOG.len() - len..], buf);
            len as isize
        }
        SyslogAction::READ_CLEAR => todo!(),
        SyslogAction::CLEAR => todo!(),
        SyslogAction::CONSOLE_OFF => todo!(),
        SyslogAction::CONSOLE_ON => todo!(),
        SyslogAction::CONSOLE_LEVEL => todo!(),
        SyslogAction::SIZE_UNREAD => todo!(),
        SyslogAction::SIZE_BUFFER => LOG_BUF_LEN as isize,
        SyslogAction::ILLEAGAL => EINVAL,
    }
}

pub fn sys_yield() -> isize {
    suspend_current_and_run_next();
    SUCCESS
}

pub fn sys_kill(pid: usize, sig: usize) -> isize {
    let signal = match Signals::from_signum(sig) {
        Ok(signal) => signal,
        Err(_) => return EINVAL,
    };
    if pid > 0 {
        // [Warning] in current implementation,
        // signal will be sent to an arbitrary task with target `pid` (`tgid` more precisely).
        // But manual also require that the target task should not mask this signal.
        if let Some(task) = find_task_by_tgid(pid) {
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

pub fn sys_tkill(tid: usize, sig: usize) -> isize {
    let signal = match Signals::from_signum(sig) {
        Ok(signal) => signal,
        Err(_) => return EINVAL,
    };
    if tid > 0 {
        if let Some(task) = find_task_by_pid(tid) {
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
    } else if tid == 0 {
        todo!()
    } else if (tid as isize) == -1 {
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
            if inner.sigpending.difference(inner.sigmask).is_empty() {
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
            let token = task.get_user_token();
            if old_value as usize != 0 {
                copy_to_user(token, &inner.timer[which], old_value);
                trace!("[sys_setitimer] *old_value: {:?}", inner.timer[which]);
            }
            if new_value as usize != 0 {
                copy_from_user(token, new_value, &mut inner.timer[which]);
                trace!("[sys_setitimer] *new_value: {:?}", inner.timer[which]);
            }
            SUCCESS
        }
        _ => EINVAL,
    }
}

pub fn sys_gettimeofday(tv: *mut TimeVal, tz: *mut TimeZone) -> isize {
    // Timezone is currently NOT supported.
    if !tv.is_null() {
        let token = current_user_token();
        let timeval = &TimeVal::now();
        copy_to_user(token, timeval, tv);
    }
    SUCCESS
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
    let pid = current_task().unwrap().tgid;
    pid as isize
}

pub fn sys_getppid() -> isize {
    let task = current_task().unwrap();
    let inner = task.acquire_inner_lock();
    let ppid = inner.parent.as_ref().unwrap().upgrade().unwrap().tgid;
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
    let task = crate::task::find_task_by_tgid(pid);
    match task {
        Some(task) => task.setpgid(pgid),
        None => ESRCH,
    }
}

pub fn sys_getpgid(pid: usize) -> isize {
    /* An attempt.*/
    let task = crate::task::find_task_by_tgid(pid);
    match task {
        Some(task) => task.getpgid() as isize,
        None => ESRCH,
    }
}

// For user, tid is pid in kernel
pub fn sys_gettid() -> isize {
    current_task().unwrap().pid.0 as isize
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Sysinfo {
    uptime: usize,     /* Seconds since boot */
    loads: [usize; 3], /* 1, 5, and 15 minute load averages */
    totalram: usize,   /* Total usable main memory size */
    freeram: usize,    /* Available memory size */
    sharedram: usize,  /* Amount of shared memory */
    bufferram: usize,  /* Memory used by buffers */
    totalswap: usize,  /* Total swap space size */
    freeswap: usize,   /* Swap space still available */
    procs: u16,        /* Number of current processes */
    totalhigh: usize,  /* Total high memory size */
    freehigh: usize,   /* Available high memory size */
    mem_unit: u32,     /* Memory unit size in bytes */
                       //char __reserved[256];
                       // In the above structure, sizes of the memory and swap fields are given as multiples of mem_unit bytes.
}

pub fn sys_sysinfo(info: *mut Sysinfo) -> isize {
    const LINUX_SYSINFO_LOADS_SCALE: usize = 65536;
    const SEC_1_MIN: usize = 60;
    const SEC_5_MIN: usize = SEC_1_MIN * 5;
    const SEC_15_MIN: usize = SEC_1_MIN * 15;
    const UNIMPLEMENT: usize = 0;
    let token = current_user_token();
    let procs = procs_count();
    copy_to_user(
        token,
        &Sysinfo {
            uptime: get_time_sec(),
            // Use only current sample (as average) to evaluate
            loads: [
                procs as usize * LINUX_SYSINFO_LOADS_SCALE / SEC_1_MIN,
                procs as usize * LINUX_SYSINFO_LOADS_SCALE / SEC_5_MIN,
                procs as usize * LINUX_SYSINFO_LOADS_SCALE / SEC_15_MIN,
            ],
            totalram: crate::config::MEMORY_END - crate::config::MEMORY_START,
            freeram: crate::mm::unallocated_frames() * PAGE_SIZE,
            sharedram: UNIMPLEMENT,
            bufferram: UNIMPLEMENT,
            totalswap: 0,
            freeswap: 0,
            procs: procs,
            totalhigh: 0,
            freehigh: 0,
            mem_unit: 1,
        },
        info,
    );
    SUCCESS
}

pub fn sys_sbrk(increment: isize) -> isize {
    let task = current_task().unwrap();
    let mut inner = task.acquire_inner_lock();
    let mut memory_set = task.vm.lock();
    inner.heap_pt = memory_set.sbrk(inner.heap_pt, inner.heap_bottom, increment);
    inner.heap_pt as isize
}

pub fn sys_brk(brk_addr: usize) -> isize {
    let task = current_task().unwrap();
    let mut inner = task.acquire_inner_lock();
    let mut memory_set = task.vm.lock();
    if brk_addr == 0 {
        inner.heap_pt = memory_set.sbrk(inner.heap_pt, inner.heap_bottom, 0);
    } else {
        let former_addr = memory_set.sbrk(inner.heap_pt, inner.heap_bottom, 0);
        let grow_size: isize = (brk_addr - former_addr) as isize;
        inner.heap_pt = memory_set.sbrk(inner.heap_pt, inner.heap_bottom, grow_size);
    }

    info!(
        "[sys_brk] brk_addr: {:X}; new_addr: {:X}",
        brk_addr, inner.heap_pt
    );
    inner.heap_pt as isize
}

bitflags! {
    pub struct CloneFlags: u32 {
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
    ptid: *mut u32,
    tls: usize,
    ctid: *mut u32,
) -> isize {
    let parent = current_task().unwrap();
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
        "[sys_clone] flags: {:?}, stack: {:?}, exit_signal: {:?}, ptid: {:?}, tls: {:?}, ctid: {:?}",
        flags, stack, exit_signal, ptid, tls, ctid
    );
    show_frame_consumption! {
        "clone";
        let child = parent.sys_clone(flags, stack, tls);
    }
    let new_pid = child.pid.0;
    if flags.contains(CloneFlags::CLONE_PARENT_SETTID) {
        *translated_refmut(parent.get_user_token(), ptid) = child.pid.0 as u32;
    }
    if flags.contains(CloneFlags::CLONE_CHILD_SETTID) {
        child.acquire_inner_lock().address.set_child_tid = ctid as usize;
        *translated_refmut(child.get_user_token(), ctid) = child.pid.0 as u32;
    }
    if flags.contains(CloneFlags::CLONE_CHILD_CLEARTID) {
        child.acquire_inner_lock().address.clear_child_tid = ctid as usize;
        *translated_refmut(child.get_user_token(), ctid) = 0u32;
    }
    // add new task to scheduler
    add_task(child);
    new_pid as isize
}

pub fn sys_execve(
    pathname: *const u8,
    mut argv: *const *const u8,
    mut envp: *const *const u8,
) -> isize {
    const DEFAULT_SHELL: &str = "/bin/bash";
    let task = current_task().unwrap();
    let token = task.get_user_token();
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
    debug!(
        "[exec] argv: {:?} /* {} vars */, envp: {:?} /* {} vars */",
        argv_vec,
        argv_vec.len(),
        envp_vec,
        envp_vec.len()
    );
    let working_inode = &task.fs.lock().working_inode;

    match working_inode.open(&path, OpenFlags::O_RDONLY, false) {
        Ok(file) => {
            if file.get_size() < 4 {
                return ENOEXEC;
            }
            let mut magic_number = Box::<[u8; 4]>::new([0; 4]);
            // this operation may be expensive... I'm not sure
            file.read(Some(&mut 0usize), magic_number.as_mut_slice());
            let elf = match magic_number.as_slice() {
                b"\x7fELF" => file,
                b"#!" => {
                    let shell_file = working_inode
                        .open(DEFAULT_SHELL, OpenFlags::O_RDONLY, false)
                        .unwrap();
                    argv_vec.insert(0, DEFAULT_SHELL.to_string());
                    shell_file
                }
                _ => return ENOEXEC,
            };

            let buffer =
                unsafe { core::slice::from_raw_parts_mut(MMAP_BASE as *mut u8, elf.get_size()) };
            let caches = elf.get_all_caches().unwrap();
            let frames = caches
                .iter()
                .map(|cache| {
                    let lock = cache.try_lock();
                    assert!(lock.is_some());
                    Some(lock.unwrap().get_tracker())
                })
                .collect();

            crate::mm::KERNEL_SPACE
                .lock()
                .insert_program_area(
                    MMAP_BASE.into(),
                    crate::mm::MapPermission::R | crate::mm::MapPermission::W,
                    frames,
                )
                .unwrap();

            let task = current_task().unwrap();
            show_frame_consumption! {
                "load_elf";
                if let Err(errno) = task.load_elf(buffer, &argv_vec, &envp_vec) {
                    return errno;
                };
            }
            // remove elf area
            crate::mm::KERNEL_SPACE
                .lock()
                .remove_area_with_start_vpn(VirtAddr::from(MMAP_BASE).floor())
                .unwrap();
            // should return 0 in success
            SUCCESS
        }
        Err(errno) => errno,
    }
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
    // info!("[sys_waitpid] pid: {}, option: {:?}", pid, option);
    let task = current_task().unwrap();
    let token = task.get_user_token();
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
                *translated_refmut(token, status) = exit_code;
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
        let token = task.get_user_token();
        let resource = Resource::from_primitive(resource);
        info!("[sys_prlimit] pid: {}, resource: {:?}", pid, resource);

        drop(inner);
        if !old_limit.is_null() {
            match resource {
                Resource::STACK => {
                    copy_to_user(
                        token,
                        &(RLimit {
                            rlim_cur: USER_STACK_SIZE,
                            rlim_max: USER_STACK_SIZE,
                        }),
                        old_limit,
                    );
                }
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
                            rlim_cur: task.files.lock().get_limit(),
                            rlim_max: FdTable::SYSTEM_FD_LIMIT,
                        }),
                        old_limit,
                    );
                }
                Resource::ILLEAGAL => return EINVAL,
                _ => todo!(),
            }
        }
        if !new_limit.is_null() {
            let rlimit = &mut RLimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            copy_from_user(token, new_limit, rlimit);
            match resource {
                Resource::NOFILE => {
                    task.files.lock().set_limit(rlimit.rlim_cur);
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
/// set pointer to thread ID
/// This feature is currently NOT supported and is implemented as a stub,
/// since threads are not supported.
pub fn sys_set_tid_address(tidptr: usize) -> isize {
    current_task()
        .unwrap()
        .acquire_inner_lock()
        .address
        .clear_child_tid = tidptr;
    sys_gettid()
}
/// # Description
/// fast user-space locking
/// # Arguments
/// * `uaddr`: `usize`, the address to the futex word;
/// * `futex_op`: `u32`, the operation to perform on the futex;
/// The remaining arguments (val, timeout, uaddr2, and val3) are re‐
/// quired only for certain of the futex  operations  described
/// below.  Where one of these arguments is not required, it is
/// ignored.
/// * `val`: `u32`, the argument to futex_op
/// * `timeout`: `*const TimeSpec`,
/// * `uaddr2`: `usize`,
/// * `val3`: `u32`,
pub fn sys_futex(
    uaddr: usize,
    futex_op: u32,
    val: u32,
    timeout: *const TimeSpec,
    uaddr2: usize,
    val3: u32,
) -> isize {
    if uaddr % 4 != 0 {
        return EINVAL;
    }
    let token = current_user_token();
    let private_futex = (futex_op | FUTEX_PRIVATE) != 0;
    let rt_clk = (futex_op | FUTEX_CLOCK_REALTIME) != 0;
    let real_cmd = futex_op & (!(FUTEX_CLOCK_REALTIME | FUTEX_PRIVATE));
    let futex_word = translated_refmut(token, uaddr as *mut u32);
    let uwd2 = translated_refmut(token, uaddr as *mut u32);
    let timeout = if timeout.is_null() {
        None
    } else {
        Some(get_from_user(token, timeout))
    };
    let cmd =
        <threads::FutexCmd as core::convert::TryFrom<u32>>::try_from(real_cmd as u32).unwrap();

    futex(
        futex_word,
        uwd2,
        val,
        val3,
        cmd,
        private_futex,
        rt_clk,
        timeout,
    )
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
    let mut memory_set = task.vm.lock();
    let prot = MapPermission::from_bits(((prot as u8) << 1) | (1 << 4)).unwrap();
    let flags = MapFlags::from_bits(flags).unwrap();
    info!(
        "[mmap] start:{:X}; len:{:X}; prot:{:?}; flags:{:?}; fd:{}; offset:{:X}",
        start, len, prot, flags, fd as isize, offset
    );
    memory_set.mmap(start, len, prot, flags, fd, offset) as isize
}

/// # Versions
/// The membarrier() system call was added in Linux 4.3.
/// Before Linux 5.10, the prototype for membarrier() was:
/// `int membarrier(int cmd, int flags);`
pub fn sys_memorybarrier(cmd: usize, flags: usize, cpu_id: usize) -> isize {
    error!("[sys_memorybarrier]=========PSEUDOIMPLEMENTATION=========");
    error!(
        "This system call is only needed by the multicore environment for faster synchronization."
    );
    error!("In theory, it can be replaced (INefficiently) by fencing.");
    return SUCCESS;
}

pub fn sys_munmap(start: usize, len: usize) -> isize {
    let task = current_task().unwrap();
    let result = task.vm.lock().munmap(start, len);
    match result {
        Ok(_) => SUCCESS,
        Err(errno) => errno,
    }
}

pub fn sys_mprotect(addr: usize, len: usize, prot: usize) -> isize {
    let task = current_task().unwrap();
    let result = task.vm.lock().mprotect(addr, len, prot);
    match result {
        Ok(_) => SUCCESS,
        Err(errno) => errno,
    }
}

pub fn sys_clock_gettime(clk_id: usize, tp: *mut TimeSpec) -> isize {
    if !tp.is_null() {
        let token = current_user_token();
        let timespec = &TimeSpec::now();
        copy_to_user(token, timespec, tp);
        info!(
            "[sys_clock_gettime] clk_id: {}, tp: {:?}",
            clk_id, timespec
        );
    }
    SUCCESS
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

pub fn sys_sigtimedwait(set: usize, info: usize, timeout: usize) -> isize {
    sigtimedwait(
        set as *const Signals,
        info as *mut SigInfo,
        timeout as *const TimeSpec,
    )
}

pub fn sys_sigreturn() -> isize {
    // mark not processing signal handler
    let task = current_task().unwrap();
    info!("[sys_sigreturn] pid: {}", task.pid.0);
    let inner = task.acquire_inner_lock();
    let token = task.get_user_token();
    // restore trap_cx
    let trap_cx = inner.get_trap_cx();
    let sp = trap_cx.x[2];
    copy_from_user(token, sp as *const TrapContext, trap_cx);
    return trap_cx.x[10] as isize; //return a0: not modify any of trap_cx
}

/// Get process times
pub fn sys_times(buf: *mut Times) -> isize {
    let task = current_task().unwrap();
    let inner = task.acquire_inner_lock();
    let token = task.get_user_token();
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
    let token = task.get_user_token();
    copy_to_user(token, &inner.rusage, usage);
    //info!("[sys_getrusage] who: RUSAGE_SELF, usage: {:?}", inner.rusage);
    SUCCESS
}
