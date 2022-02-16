use alloc::collections::{BTreeMap, BinaryHeap};
use alloc::vec::Vec;
use core::fmt::{self, Binary, Debug, Formatter};
use log::{trace, info, debug, warn, error};
use riscv::register::{
    mtvec::TrapMode,
    scause::{self, Exception, Interrupt, Trap},
    sie, stval, stvec,
};

use crate::config::*;
use crate::mm::{translated_ref, translated_refmut, copy_to_user, copy_from_user};
use crate::task::{current_trap_cx, exit_current_and_run_next};
use crate::trap::{TrapContext};

use super::{current_task, current_user_token};

/// Default action.
pub const SIG_DFL: usize = 0;
/// Ignore signal.  
pub const SIG_IGN: usize = 1;

pub const SIG_BLOCK: usize = 0;
pub const SIG_UNBLOCK: usize = 1;
pub const SIG_SETMASK: usize = 2;

bitflags! {
    /// Signal
    pub struct Signals: usize{
        const	SIGHUP		= 1 << ( 0);
        const	SIGINT		= 1 << ( 1);
        const	SIGQUIT		= 1 << ( 2);
        const	SIGILL		= 1 << ( 3);
        const	SIGTRAP		= 1 << ( 4);
        const	SIGABRT		= 1 << ( 5);
        const	SIGIOT		= 1 << ( 5);
        const	SIGBUS		= 1 << ( 6);
        const	SIGFPE		= 1 << ( 7);
        const	SIGKILL		= 1 << ( 8);
        const	SIGUSR1		= 1 << ( 9);
        const	SIGSEGV		= 1 << (10);
        const	SIGUSR2		= 1 << (11);
        const	SIGPIPE		= 1 << (12);
        const	SIGALRM		= 1 << (13);
        const	SIGTERM		= 1 << (14);
        const	SIGSTKFLT	= 1 << (15);
        const	SIGCHLD		= 1 << (16);
        const	SIGCONT		= 1 << (17);
        const	SIGSTOP		= 1 << (18);
        const	SIGTSTP		= 1 << (19);
        const	SIGTTIN		= 1 << (20);
        const	SIGTTOU		= 1 << (21);
        const	SIGURG		= 1 << (22);
        const	SIGXCPU		= 1 << (23);
        const	SIGXFSZ		= 1 << (24);
        const	SIGVTALRM	= 1 << (25);
        const	SIGPROF		= 1 << (26);
        const	SIGWINCH	= 1 << (27);
        const	SIGIO		= 1 << (28);
        const   SIGPWR      = 1 << (29);
        const   SIGSYS      = 1 << (30);
    }
}

impl Signals {
    pub fn to_signum(&self) -> Option<usize> {
        if self.bits().count_ones() == 1 {
            Some(self.bits().trailing_zeros() as usize + 1)
        }
        else {
            None
        }
    }
    pub fn peek_front(&self) -> Option<Signals> {
        if self.is_empty() {
            None
        }
        else {
            Signals::from_bits(1 << (self.bits().trailing_zeros() as usize))
        }
    }
}

bitflags! {
    /// Bits in `sa_flags' used to denote the default signal action.
    pub struct SaFlags: usize{
    /// Don't send SIGCHLD when children stop.
        const SA_NOCLDSTOP = 1		   ;
    /// Don't create zombie on child death.
        const SA_NOCLDWAIT = 2		   ;
    /// Invoke signal-catching function with three arguments instead of one.
        const SA_SIGINFO   = 4		   ;
    /// Use signal stack by using `sa_restorer'.
        const SA_ONSTACK   = 0x08000000;
    /// Restart syscall on signal return.
        const SA_RESTART   = 0x10000000;
    /// Don't automatically block the signal when its handler is being executed.
        const SA_NODEFER   = 0x40000000;
    /// Reset to SIG_DFL on entry to handler.
        const SA_RESETHAND = 0x80000000;
    /// Historical no-op.
        const SA_INTERRUPT = 0x20000000;
    /// I don't know what it means, but it presents in busybox!
        const SA_RESTORER  = 0x04000000;
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
// sigset_t   sa_mask;//保存的是当进程在处理信号的时候，收到的信号
// int        sa_flags;//SA_SIGINFO，OS在处理信号的时候，调用的就是sa_sigaction函数指针当中
// //保存的值0，在处理信号的时候，调用sa_handler保存的函数

pub struct SigAction {
    /// 有的平台上是个union:
    /// void     (*sa_handler)(int);//函数指针，保存了内核对信号的处理方式
    /// void     (*sa_sigaction)(int, siginfo_t *, void *);//
    pub sa_handler: usize,
    //pub sa_sigaction: SaFlags,
    /// 指定本次信号行为的标识
    pub sa_flags: SaFlags,
    /// 执行的时候需要阻塞的信号,另外除非SA_NODEFER定义,否则也需要阻塞本次触发的信号
    pub sa_mask: Signals,
    // void     (*sa_restorer)(void); NOT USED BY LINUX/POSIX!
}

impl SigAction {
    pub fn new() -> Self {
        Self {
            sa_handler: SIG_DFL,
            sa_flags: SaFlags::empty(),
            sa_mask: Signals::empty(),
        }
    }

    pub fn is_null(&self) -> bool {
        self.sa_handler == 0 && self.sa_flags.is_empty() && self.sa_mask.is_empty()
    }
}
#[derive(Clone)]
pub struct SigInfo {
    pub signal_pending: Signals,
    pub signal_handler: BTreeMap<Signals, SigAction>,
}

impl SigInfo {
    pub fn new() -> Self {
        Self {
            signal_pending: Signals::empty(),
            signal_handler: BTreeMap::new(),
        }
    }
}

impl Debug for SigInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "[ signal_pending: ({:?}), signal_handler: ({:?}) ]",
            self.signal_pending, self.signal_handler
        ))
    }
}

impl Debug for SigAction {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "[ sa_handler: 0x{:X}, sa_mask: ({:?}), sa_flags: ({:?}) ]",
            self.sa_handler, self.sa_mask, self.sa_flags
        ))
    }
}

pub fn sigaction(signum: usize, act: *const SigAction, oldact: *mut SigAction) -> isize {
    let task = current_task();
    let token = current_user_token();
    if let Some(task) = task {
        let mut inner = task.acquire_inner_lock();
        // Copy the old to the oldset.
        let key = Signals::from_bits(1 << (signum - 1));
        trace!("[sigaction] signal: {:?}", key);
        match key {
            Some(Signals::SIGKILL) | Some(Signals::SIGSTOP) | None => -1,
            Some(key) => {
                if oldact as usize != 0 {
                    if let Some(sigact) = inner.siginfo.signal_handler.remove(&key) {
                        copy_to_user(token, &sigact, oldact);
                        trace!("[sigaction] *oldact: {:?}", sigact);
                    }
                    else {
                        copy_to_user(token, &SigAction::new(), oldact);
                        trace!("[sigaction] *oldact: not found");
                    }
                }
                if act as usize != 0 {
                    let sigact = &mut SigAction::new();
                    copy_from_user(token, act, sigact);
                    sigact.sa_mask.remove(Signals::SIGSTOP | Signals::SIGKILL);
                    // push to PCB, ignore mask and flags now
                    if !(sigact.sa_handler == SIG_DFL || sigact.sa_handler == SIG_IGN) {
                        inner.siginfo.signal_handler.insert(key, *sigact);
                    };
                    trace!("[sigaction] *act: {:?}", sigact);
                }
                0
            }
        }
    } else {
        -1
    }
}

pub fn do_signal() {
    let task = current_task().unwrap();
    let mut inner = task.acquire_inner_lock();
    let mut exception_signal: Option<Signals> = None;
    while let Some(signal) = inner.siginfo.signal_pending.difference(inner.sigmask).peek_front() {
        inner.siginfo.signal_pending.remove(signal);
        trace!("[do_signal] signal: {:?}, pending: {:?}, sigmask: {:?}", signal, inner.siginfo.signal_pending, inner.sigmask);
        if let Some(act) = inner.siginfo.signal_handler.get(&signal) {
            {
                let trap_cx = inner.get_trap_cx();
                let sp = unsafe { (trap_cx.x[2] as *mut TrapContext).sub(1) };
                if (sp as usize) < USER_STACK_TOP {
                    trap_cx.sepc = usize::MAX; // we don't have enough space on user stack, return a bad address to kill this program
                } else {
                    copy_to_user(inner.get_user_token(), trap_cx, sp as *mut TrapContext); // restore context on user stack
                    trap_cx.set_sp(sp as usize); // update sp, because we pushed trapcontext into stack
                    trap_cx.x[10] = signal.to_signum().unwrap(); // a0 <= signum, parameter.
                    trap_cx.x[1] = SIGNAL_TRAMPOLINE; // ra <= __call_sigreturn, when handler ret, we will go to __call_sigreturn
                    trap_cx.sepc = act.sa_handler; // recover pc with addr of handler
                }
                trace!(
                    "[do_signal] signal: {:?}, signum: {:?}, handler: 0x{:X} (ra: 0x{:X}, sp: 0x{:X})",
                    signal,
                    signal.to_signum().unwrap(),
                    act.sa_handler,
                    trap_cx.x[1],
                    trap_cx.x[2]
                );
            }
        }
        // action not found
        else {
            if signal == Signals::SIGCHLD
                || signal == Signals::SIGURG
                || signal == Signals::SIGWINCH
            {
                trace!("[do_signal] Ignore {:?}", signal);
                continue;
            }
            if signal == Signals::SIGCONT {
                // If we have time to do this.
                continue;
            }
            exception_signal = Some(signal);
            drop(inner);
            drop(task);
            break;
        }
    }
    if let Some(signal) = exception_signal {
        if signal == Signals::SIGSEGV {
            warn!("[do_signal] Use default handler for SIGSEGV");
            let scause = scause::read();
            let stval = stval::read();
            println!(
                "[kernel] {:?} in application, bad addr = {:#x}, bad instruction = {:#x}, core dumped.",
                scause.cause(),
                stval,
                current_trap_cx().sepc,
            );
            // page fault exit code
            exit_current_and_run_next(-2);
        } else {
            warn!("[do_signal] Use default handler for {:?}", signal);
            exit_current_and_run_next(signal.to_signum().unwrap() as i32);
        }
    }
}

pub fn sigprocmask(how: usize, set: *const Signals, oldset: *mut Signals) -> isize {
    let task = current_task().unwrap();
    let mut inner = task.acquire_inner_lock();
    let token = inner.get_user_token();
    // Copy the old to the oldset.
    if oldset as usize != 0 {
        *translated_refmut(token, oldset) = inner.sigmask;
        trace!("[sigprocmask] *oldset: ({:?})", inner.sigmask);
    }
    // Assign the sigmask.
    if set as usize != 0 {
        let s = *translated_ref(token, set);
        trace!("[sigprocmask] *set: ({:?})", s);
        let ret = match how {
            SIG_BLOCK => {
                inner.sigmask = inner.sigmask.union(s);
                trace!("[sigprocmask] how: SIG_BLOCK");
                0
            } /*add the signals not yet blocked in the given set to the mask.*/
            SIG_UNBLOCK => {
                inner.sigmask = inner.sigmask.difference(s);
                trace!("[sigprocmask] how: SIG_UNBLOCK");
                0
            } /*remove the blocked signals in the set from the sigmask. NOTE: unblocking a signal not blocked is allowed. */
            SIG_SETMASK => {
                inner.sigmask = s;
                trace!("[sigprocmask] how: SIG_SETMASK");
                0
            } /*set the signal mask to what we see.*/
            _ => -1, // "how" variable NOT recognized
        };
        inner.sigmask = inner
            .sigmask
            .difference(Signals::SIGKILL | Signals::SIGSTOP);
        ret
    } else {
        0
    }
}
