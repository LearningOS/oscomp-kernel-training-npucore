const SYSCALL_GETCWD: usize = 17;
const SYSCALL_DUP: usize = 23;
const SYSCALL_DUP3: usize = 24;
const SYSCALL_FCNTL: usize = 25;
const SYSCALL_IOCTL: usize = 29;
const SYSCALL_MKDIRAT: usize = 34;
const SYSCALL_UNLINKAT: usize = 35;
const SYSCALL_LINKAT: usize = 37;
const SYSCALL_UMOUNT2: usize = 39;
const SYSCALL_MOUNT: usize = 40;
const SYSCALL_FACCESSAT: usize = 48;
const SYSCALL_CHDIR: usize = 49;
const SYSCALL_OPENAT: usize = 56;
const SYSCALL_CLOSE: usize = 57;
const SYSCALL_PIPE2: usize = 59;
const SYSCALL_GETDENTS64: usize = 61;
const SYSCALL_LSEEK: usize = 62;
const SYSCALL_READ: usize = 63;
const SYSCALL_WRITE: usize = 64;
const SYSCALL_READV: usize = 65;
const SYSCALL_WRITEV: usize = 66;
const SYSCALL_SENDFILE: usize = 71;
const SYSCALL_PSELECT6: usize = 72;
const SYSCALL_PPOLL: usize = 73;
const SYSCALL_READLINKAT: usize = 78;
const SYSCALL_FSTATAT: usize = 79;
const SYSCALL_FSTAT: usize = 80;
const SYSCALL_FSYNC: usize = 82;
const SYSCALL_UTIMENSAT: usize = 88;
const SYSCALL_EXIT: usize = 93;
const SYSCALL_EXIT_GRUOP: usize = 94;
const SYSCALL_SET_TID_ADDRESS: usize = 96;
const SYSCALL_NANOSLEEP: usize = 101;
const SYSCALL_GETITIMER: usize = 102;
const SYSCALL_SETITIMER: usize = 103;
const SYSCALL_CLOCK_GETTIME: usize = 113;
const SYSCALL_SYSLOG: usize = 116;
const SYSCALL_YIELD: usize = 124;
const SYSCALL_KILL: usize = 129;
const SYSCALL_SIGACTION: usize = 134;
const SYSCALL_SIGPROCMASK: usize = 135;
const SYSCALL_SIGRETURN: usize = 139;
const SYSCALL_TIMES: usize = 153;
const SYSCALL_SETPGID: usize = 154;
const SYSCALL_GETPGID: usize = 155;
const SYSCALL_UNAME: usize = 160;
const SYSCALL_GETRUSAGE: usize = 165;
const SYSCALL_UMASK: usize = 166;
const SYSCALL_GET_TIME_OF_DAY: usize = 169;
const SYSCALL_GETPID: usize = 172;
const SYSCALL_GETPPID: usize = 173;
const SYSCALL_GETUID: usize = 174;
const SYSCALL_GETEUID: usize = 175;
const SYSCALL_GETGID: usize = 176;
const SYSCALL_GETEGID: usize = 177;
const SYSCALL_GETTID: usize = 178;
const SYSCALL_SYSINFO: usize = 179;
const SYSCALL_SBRK: usize = 213;
const SYSCALL_BRK: usize = 214;
const SYSCALL_MUNMAP: usize = 215;
// Warning, we don't implement clone, we implement fork instead.
const SYSCALL_CLONE: usize = 220; // fork is implemented as clone(SIGCHLD, 0) in lib.
const SYSCALL_EXECVE: usize = 221;
const SYSCALL_MMAP: usize = 222;
const SYSCALL_MPROTECT: usize = 226;
const SYSCALL_WAIT4: usize = 260; // wait is implemented as wait4(pid, status, options, 0) in lib.
const SYSCALL_PRLIMIT: usize = 261;
const SYSCALL_RENAMEAT2: usize = 276;
const SYSCALL_FACCESSAT2: usize = 439;

// Not standard POSIX sys_call
const SYSCALL_LS: usize = 500;
const SYSCALL_SHUTDOWN: usize = 501;
const SYSCALL_CLEAR: usize = 502;
const SYSCALL_OPEN: usize = 506; //where?
const SYSCALL_GET_TIME: usize = 1690; //you mean get time of day by 169?

pub mod errno;
pub mod fs;
mod process;

use fs::*;
use log::{debug, error, info, trace, warn};
use process::*;

pub fn syscall_name(id: usize) -> &'static str {
    match id {
        SYSCALL_DUP => "dup",
        SYSCALL_DUP3 => "dup3",
        SYSCALL_OPEN => "open",
        SYSCALL_GET_TIME => "get_time",
        SYSCALL_GETCWD => "getcwd",
        SYSCALL_FCNTL => "fcntl",
        SYSCALL_IOCTL => "ioctl",
        SYSCALL_MKDIRAT => "mkdirat",
        SYSCALL_UNLINKAT => "unlinkat",
        SYSCALL_LINKAT => "linkat",
        SYSCALL_UMOUNT2 => "umount2",
        SYSCALL_MOUNT => "mount",
        SYSCALL_FACCESSAT => "faccessat",
        SYSCALL_CHDIR => "chdir",
        SYSCALL_OPENAT => "openat",
        SYSCALL_CLOSE => "close",
        SYSCALL_PIPE2 => "pipe2",
        SYSCALL_GETDENTS64 => "getdents64",
        SYSCALL_LSEEK => "lseek",
        SYSCALL_READ => "read",
        SYSCALL_WRITE => "write",
        SYSCALL_READV => "readv",
        SYSCALL_WRITEV => "writev",
        SYSCALL_SENDFILE => "sendfile",
        SYSCALL_PSELECT6 => "pselect6",
        SYSCALL_PPOLL => "ppoll",
        SYSCALL_READLINKAT => "readlinkat",
        SYSCALL_FSTATAT => "fstatat",
        SYSCALL_FSTAT => "fstat",
        SYSCALL_FSYNC => "fsync",
        SYSCALL_UTIMENSAT => "utimensat",
        SYSCALL_EXIT => "exit",
        SYSCALL_EXIT_GRUOP => "exit_GRUOP",
        SYSCALL_SET_TID_ADDRESS => "set_tid_address",
        SYSCALL_NANOSLEEP => "nanosleep",
        SYSCALL_GETITIMER => "getitimer",
        SYSCALL_SETITIMER => "setitimer",
        SYSCALL_CLOCK_GETTIME => "clock_gettime",
        SYSCALL_SYSLOG => "syslog",
        SYSCALL_YIELD => "yield",
        SYSCALL_KILL => "kill",
        SYSCALL_SIGACTION => "sigaction",
        SYSCALL_SIGPROCMASK => "sigprocmask",
        SYSCALL_SIGRETURN => "sigreturn",
        SYSCALL_TIMES => "times",
        SYSCALL_SETPGID => "setpgid",
        SYSCALL_GETPGID => "getpgid",
        SYSCALL_UNAME => "uname",
        SYSCALL_GETRUSAGE => "getrusage",
        SYSCALL_UMASK => "umask",
        SYSCALL_GET_TIME_OF_DAY => "get_time_of_day",
        SYSCALL_GETPID => "getpid",
        SYSCALL_GETPPID => "getppid",
        SYSCALL_GETUID => "getuid",
        SYSCALL_GETEUID => "geteuid",
        SYSCALL_GETGID => "getgid",
        SYSCALL_GETEGID => "getegid",
        SYSCALL_GETTID => "gettid",
        SYSCALL_SYSINFO => "sysinfo",
        SYSCALL_SBRK => "sbrk",
        SYSCALL_BRK => "brk",
        SYSCALL_MUNMAP => "munmap",
        SYSCALL_CLONE => "clone",
        SYSCALL_EXECVE => "execve",
        SYSCALL_MMAP => "mmap",
        SYSCALL_MPROTECT => "mprotect",
        SYSCALL_WAIT4 => "wait4",
        SYSCALL_PRLIMIT => "prlimit",
        SYSCALL_RENAMEAT2 => "renameat2",
        SYSCALL_FACCESSAT2 => "faccessat2",
        // non-standard
        SYSCALL_LS => "ls",
        SYSCALL_SHUTDOWN => "shutdown",
        SYSCALL_CLEAR => "clear",
        _ => "unknown",
    }
}
use crate::{
    fs::FdSet,
    task::Rusage,
    timer::{ITimerVal, TimeSpec, Times},
};

pub fn syscall(syscall_id: usize, args: [usize; 6]) -> isize {
    let mut show_info = false;
    if ![
        //black list
        SYSCALL_YIELD,
        // SYSCALL_READ,
        // SYSCALL_WRITE,
        SYSCALL_GETDENTS64,
        // SYSCALL_WRITEV,
        //SYSCALL_PPOLL,
        SYSCALL_GETPPID,
        SYSCALL_CLOCK_GETTIME,
    ]
    .contains(&syscall_id)
    {
        show_info = true;
        info!(
            "[syscall] pid: {}, syscall_id: {} ({}), \nargs: {:?}",
            sys_getpid(),
            syscall_name(syscall_id),
            syscall_id,
            args
        );
    }
    let ret = match syscall_id {
        SYSCALL_GETCWD => sys_getcwd(args[0], args[1]),
        SYSCALL_DUP => sys_dup(args[0]),
        SYSCALL_DUP3 => sys_dup3(args[0], args[1], args[2] as u32),
        SYSCALL_FCNTL => sys_fcntl(args[0], args[1] as u32, args[2]),
        SYSCALL_IOCTL => sys_ioctl(args[0], args[1] as u32, args[2]),
        SYSCALL_MKDIRAT => sys_mkdirat(args[0], args[1] as *const u8, args[2] as u32),
        SYSCALL_UNLINKAT => sys_unlinkat(args[0], args[1] as *const u8, args[2] as u32),
        SYSCALL_UMOUNT2 => sys_umount2(args[0] as *const u8, args[1] as u32),
        SYSCALL_MOUNT => sys_mount(
            args[0] as *const u8,
            args[1] as *const u8,
            args[2] as *const u8,
            args[3],
            args[4] as *const u8,
        ),
        SYSCALL_FACCESSAT => {
            sys_faccessat2(args[0] as u32, args[1] as *const u8, args[2] as u32, 0u32)
        }
        SYSCALL_CHDIR => sys_chdir(args[0] as *const u8),
        SYSCALL_OPEN => sys_openat(AT_FDCWD, args[0] as *const u8, args[1] as u32, 0o777u32),
        SYSCALL_OPENAT => sys_openat(
            args[0],
            args[1] as *const u8,
            args[2] as u32,
            args[3] as u32,
        ),
        SYSCALL_CLOSE => sys_close(args[0]),
        SYSCALL_PIPE2 => sys_pipe2(args[0], args[1] as u32),
        SYSCALL_GETDENTS64 => sys_getdents64(args[0], args[1] as *mut u8, args[2]),
        SYSCALL_READ => sys_read(args[0], args[1], args[2]),
        SYSCALL_READV => sys_readv(args[0], args[1], args[2]),
        SYSCALL_WRITE => sys_write(args[0], args[1], args[2]),
        SYSCALL_WRITEV => sys_writev(args[0], args[1], args[2]),
        SYSCALL_LSEEK => sys_lseek(args[0], args[1], args[2] as u32),
        SYSCALL_SENDFILE => sys_sendfile(args[0], args[1], args[2] as *mut usize, args[3]),
        SYSCALL_READLINKAT => {
            sys_readlinkat(args[0], args[1] as *const u8, args[2] as *mut u8, args[3])
        }
        SYSCALL_FSTATAT => sys_fstatat(
            args[0],
            args[1] as *const u8,
            args[2] as *mut u8,
            args[3] as u32,
        ),
        SYSCALL_FSTAT => sys_fstat(args[0], args[1] as *mut u8),
        SYSCALL_UTIMENSAT => sys_utimensat(
            args[0],
            args[1] as *const u8,
            args[2] as *const [TimeSpec; 2],
            args[3] as u32,
        ),
        SYSCALL_EXIT => sys_exit(args[0] as u32),
        SYSCALL_EXIT_GRUOP => sys_exit(args[0] as u32),
        SYSCALL_CLOCK_GETTIME => sys_clock_get_time(args[0], args[1] as *mut u64),
        SYSCALL_KILL => sys_kill(args[0], args[1]),
        SYSCALL_YIELD => sys_yield(),
        SYSCALL_SIGACTION => sys_sigaction(args[0], args[1], args[2]),
        SYSCALL_SIGPROCMASK => sys_sigprocmask(args[0] as u32, args[1], args[2]),
        SYSCALL_SIGRETURN => sys_sigreturn(),
        SYSCALL_TIMES => sys_times(args[0] as *mut Times),
        SYSCALL_NANOSLEEP => sys_nanosleep(
            args[0] as *const crate::timer::TimeSpec,
            args[1] as *mut crate::timer::TimeSpec,
        ),
        SYSCALL_SETITIMER => sys_setitimer(
            args[0],
            args[1] as *const ITimerVal,
            args[2] as *mut ITimerVal,
        ),
        SYSCALL_GET_TIME => sys_get_time(),
        SYSCALL_GETRUSAGE => sys_getrusage(args[0] as isize, args[1] as *mut Rusage),
        SYSCALL_UMASK => sys_umask(args[0]),
        SYSCALL_GET_TIME_OF_DAY => sys_get_time_of_day(
            args[0] as *mut crate::timer::TimeVal,
            args[1] as *mut crate::timer::TimeZone,
        ),
        SYSCALL_SETPGID => sys_setpgid(args[0], args[1]),
        SYSCALL_GETPGID => sys_getpgid(args[0]),
        SYSCALL_UNAME => sys_uname(args[0] as *mut u8),
        SYSCALL_GETPID => sys_getpid(),
        SYSCALL_GETPPID => sys_getppid(),
        SYSCALL_CLONE => sys_clone(
            args[0] as u32,
            args[1] as *const u8,
            args[2] as *const u32,
            args[3] as *const usize,
            args[4] as *const u32,
        ),
        SYSCALL_EXECVE => sys_execve(
            args[0] as *const u8,
            args[1] as *const *const u8,
            args[2] as *const *const u8,
        ),
        SYSCALL_WAIT4 => sys_wait4(
            args[0] as isize,
            args[1] as *mut u32,
            args[2] as u32,
            args[3] as *mut Rusage,
        ),
        SYSCALL_PRLIMIT => sys_prlimit(
            args[0],
            args[1] as u32,
            args[2] as *const RLimit,
            args[3] as *mut RLimit,
        ),
        SYSCALL_SET_TID_ADDRESS => sys_set_tid_address(args[0]),
        SYSCALL_GETUID => sys_getuid(),
        SYSCALL_GETEUID => sys_geteuid(),
        SYSCALL_GETGID => sys_getgid(),
        SYSCALL_GETEGID => sys_getegid(),
        SYSCALL_GETTID => sys_gettid(),
        SYSCALL_SBRK => sys_sbrk(args[0] as isize),
        SYSCALL_BRK => sys_brk(args[0]),
        SYSCALL_MMAP => sys_mmap(args[0], args[1], args[2], args[3], args[4], args[5]),
        SYSCALL_MUNMAP => sys_munmap(args[0], args[1]),
        SYSCALL_MPROTECT => sys_mprotect(args[0], args[1], args[2]),
        SYSCALL_PSELECT6 => sys_pselect(
            args[0],
            args[1] as *mut FdSet,
            args[2] as *mut FdSet,
            args[3] as *mut FdSet,
            args[4] as *const TimeSpec,
            args[5] as *const crate::task::Signals,
        ),
        SYSCALL_PPOLL => sys_ppoll(args[0], args[1], args[2], args[3]),
        SYSCALL_FACCESSAT2 => sys_faccessat2(
            args[0] as u32,
            args[1] as *const u8,
            args[2] as u32,
            args[3] as u32,
        ),
        _ => {
            error!(
                "Unsupported syscall:{} ({}), calling over arguments:",
                syscall_name(syscall_id),
                syscall_id
            );
            for i in 0..args.len() {
                debug!("args[{}]: {:X}", i, args[i]);
            }
            info!("Exiting.");
            sys_exit(1)
        }
    };

    if show_info {
        info!(
            "[syscall] pid: {}, syscall_id: {} ({}) returned {}",
            sys_getpid(),
            syscall_name(syscall_id),
            syscall_id,
            ret
        );
    }
    ret
}
