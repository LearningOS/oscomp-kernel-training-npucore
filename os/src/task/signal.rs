use alloc::collections::{BTreeMap, BinaryHeap};
use alloc::vec::Vec;
use core::fmt::{self, Debug, Formatter};

pub const SIG_DFL: usize = 0; /* Default action.  */
pub const SIG_IGN: usize = 1; /* Ignore signal.  */

// signal
bitflags! {
    pub struct Signals: usize{
        const	SIGHUP		= 1 << ( 0);
        const	SIGINT		= 1 << ( 1);
        const	SIGQUIT		= 1 << ( 2);
        const	SIGILL		= 1 << ( 3);
        const	SIGTRAP		= 1 << ( 4);
        const	SIGABRT		= 1 << ( 5);
        const	SIGIOT		= 1 << ( 6);
        const	SIGBUS		= 1 << ( 7);
        const	SIGFPE		= 1 << ( 8);
        const	SIGKILL		= 1 << ( 9);
        const	SIGUSR1		= 1 << (10);
        const	SIGSEGV		= 1 << (11);
        const	SIGUSR2		= 1 << (12);
        const	SIGPIPE		= 1 << (13);
        const	SIGALRM		= 1 << (14);
        const	SIGTERM		= 1 << (15);
        const	SIGSTKFLT	= 1 << (16);
        const	SIGCHLD		= 1 << (17);
        const	SIGCONT		= 1 << (18);
        const	SIGSTOP		= 1 << (19);
        const	SIGTSTP		= 1 << (20);
        const	SIGTTIN		= 1 << (21);
        const	SIGTTOU		= 1 << (22);
        const	SIGURG		= 1 << (23);
        const	SIGXCPU		= 1 << (24);
        const	SIGXFSZ		= 1 << (25);
        const	SIGVTALRM	= 1 << (26);
        const	SIGPROF		= 1 << (27);
        const	SIGWINCH	= 1 << (28);
        const	SIGIO		= 1 << (29);
    }
}

bitflags! {
    /* Bits in `sa_flags'.  */
    pub struct SaFlags: usize{
        const SA_NOCLDSTOP = 1		   ;     /* Don't send SIGCHLD when children stop.  */
        const SA_NOCLDWAIT = 2		   ;     /* Don't create zombie on child death.  */
        const SA_SIGINFO   = 4		   ;     /* Invoke signal-catching function with three arguments instead of one.  */
        const SA_ONSTACK   = 0x08000000;    /* Use signal stack by using `sa_restorer'. */
        const SA_RESTART   = 0x10000000;    /* Restart syscall on signal return.  */
        const SA_NODEFER   = 0x40000000;    /* Don't automatically block the signal when its handler is being executed.  */
        const SA_RESETHAND = 0x80000000;    /* Reset to SIG_DFL on entry to handler.  */
        const SA_INTERRUPT = 0x20000000;    /* Historical no-op.  */
    }
}

#[derive(Clone)]
pub struct SigAction {
    pub sa_handler: usize,
    // pub sa_sigaction:usize,
    pub sa_mask: Vec<Signals>,
    pub sa_flags: SaFlags,
}

impl SigAction {
    pub fn new() -> Self {
        Self {
            sa_handler: 0,
            sa_flags: SaFlags::from_bits(0).unwrap(),
            sa_mask: Vec::new(),
        }
    }

    pub fn is_null(&self) -> bool {
        self.sa_handler == 0 && self.sa_flags.is_empty() && self.sa_mask.is_empty()
    }
}
// void     (*sa_handler)(int);//函数指针，保存了内核对信号的处理方式
// void     (*sa_sigaction)(int, siginfo_t *, void *);//
// sigset_t   sa_mask;//保存的是当进程在处理信号的时候，收到的信号
// int        sa_flags;//SA_SIGINFO，OS在处理信号的时候，调用的就是sa_sigaction函数指针当中
// //保存的值0，在处理信号的时候，调用sa_handler保存的函数
// void     (*sa_restorer)(void);
#[derive(Clone)]
pub struct SigInfo {
    pub is_signal_execute: bool, // is process now executing in signal handler
    pub signal_pending: BinaryHeap<Signals>,
    pub signal_handler: BTreeMap<Signals, SigAction>,
}

impl SigInfo {
    pub fn new() -> Self {
        Self {
            is_signal_execute: false,
            signal_pending: BinaryHeap::new(),
            signal_handler: BTreeMap::new(),
        }
    }
}

impl Debug for SigInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "( is_signal_execute:{}, signal_pending:{:?}, signal_handler:{:?})",
            self.is_signal_execute, self.signal_pending, self.signal_handler
        ))
    }
}

impl Debug for SigAction {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "( sa_handler:0x{:X}, sa_mask:{:?}, sa_flags:{:?})",
            self.sa_handler, self.sa_mask, self.sa_flags
        ))
    }
}
