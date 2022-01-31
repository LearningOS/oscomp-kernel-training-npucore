use alloc::collections::{BTreeMap, BinaryHeap};
use alloc::vec::Vec;
use log::info;
use riscv::register::{
    mtvec::TrapMode,
    scause::{self, Exception, Interrupt, Trap},
    sie, stval, stvec,
};
use core::fmt::{self, Debug, Formatter};

use crate::mm::translated_refmut;
use crate::task::{current_trap_cx, exit_current_and_run_next};

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

impl Signals{
    pub fn to_signum(&self) -> usize{
        match self {
            SIGHUP      => 1,
            SIGINT		=> 2,
            SIGQUIT	    => 3,
            SIGILL		=> 4,
            SIGTRAP	    => 5,
            SIGABRT	    => 6,
            SIGIOT		=> 6,
            SIGBUS		=> 7,
            SIGFPE		=> 8,
            SIGKILL	    => 9,
            SIGUSR1	    => 10,
            SIGSEGV	    => 11,
            SIGUSR2	    => 12,
            SIGPIPE	    => 13,
            SIGALRM	    => 14,
            SIGTERM	    => 15,
            SIGSTKFL    => 16,
            SIGCHLD	    => 17,
            SIGCONT	    => 18,
            SIGSTOP	    => 19,
            SIGTSTP	    => 20,
            SIGTTIN	    => 21,
            SIGTTOU	    => 22,
            SIGURG      => 23,
            SIGXCPU	    => 24,
            SIGXFSZ	    => 25,
            SIGVTALR    => 26,
            SIGPROF	    => 27,
            SIGWINCH    => 28,
            SIGIO		=> 29,
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
    }
}

#[derive(Clone)]
#[repr(C)]
pub struct SigAction {
    pub sa_handler: usize,
    //pub sa_sigaction: SaFlags,
    pub sa_mask: Signals,
    pub sa_flags: SaFlags,
}

impl SigAction {
    pub fn new() -> Self {
        Self {
            sa_handler: 0,
            sa_flags: SaFlags::from_bits(0).unwrap(),
            sa_mask: Signals::from_bits(0).unwrap(),
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

pub fn sigaction(signum: isize, act: &SigAction, oldact: *mut usize) -> isize {
    let task = current_task();
    let token = current_user_token();
    info!("enter sigaction");
    if let Some(task) = task {
        let mut inner = task.acquire_inner_lock();
        info!("task not null");
        // Copy the old to the oldset.
        let key = Signals::from_bits(1 << (signum-1)).unwrap();
        info!("key: {:?}", key);
        if let Some(act) = inner.siginfo.signal_handler.remove(&key) {
            if oldact as usize != 0 {
                info!("handler found in oldact");
                *translated_refmut(token, oldact) = act.sa_handler;
                *translated_refmut(token, unsafe {oldact.add(1)}) = 0;
                *translated_refmut(token, unsafe {oldact.add(2)}) = 0;
                //log::debug!("{:?}",unsafe {&*(oldact as *mut SigAction)});
            }
        }
        else{
            if oldact as usize != 0{
                info!("handler not found in oldact");
                *translated_refmut(token, oldact) = 0;
                *translated_refmut(token, unsafe {oldact.add(1)}) = 0;
                *translated_refmut(token, unsafe {oldact.add(2)}) = 0;
                //log::debug!("{:?}",unsafe {&*(oldact as *mut SigAction)});
            }
        }
        // Assign the sigmask.
        {
            info!("sys_sigaction(signum: {:?}, act: None, oldact: {:?} ) = {}", signum, oldact, 0);
            let mut sigaction_new = SigAction {
                sa_handler:act.sa_handler,
                sa_mask:act.sa_mask,
                sa_flags:act.sa_flags,
            };
            // push to PCB
            let sigaction_new_copy = sigaction_new.clone();
            if !(act.sa_handler == SIG_DFL || act.sa_handler == SIG_IGN) {
                inner.siginfo.signal_handler.insert(key, sigaction_new);
            };
            log::debug!("{:?}",inner.siginfo);
            0
        }
    } else {
        -1
    }

}

pub fn do_signal_handlers(){
    let task = current_task().unwrap();
    let mut inner = task.acquire_inner_lock();
    let mut exception_signal: Option<Signals> = None;
    if !inner.siginfo.is_signal_execute {
        while let Some(signal) = inner.siginfo.signal_pending.pop() {
            // action found
            inner.siginfo.is_signal_execute = true;
            log::info!("Pop signal {:?} from pending queue", signal);
            if let Some(act) = inner.siginfo.signal_handler.get(&signal) {
                log::info!("{:?} handler found", signal);
                let handler = act.sa_handler;
                {// avoid borrow mut trap_cx, because we need to modify trapcx_backup
                    let trap_cx = inner.get_trap_cx().clone();
                    inner.trapcx_backup = trap_cx;          // backup
                }
                {
                    let trap_cx = inner.get_trap_cx();
                    trap_cx.set_sp(crate::config::USER_SIGNAL_STACK);      // sp-> signal_stack
                    trap_cx.x[10] = signal.to_signum();    // a0=signum
                    trap_cx.x[1] = crate::config::SIGNAL_TRAMPOLINE;       // ra-> signal_trampoline
                    trap_cx.sepc = handler;    // sepc-> sa_handler
                    info!(" --- {:?} (si_signo={:?}, si_code=UNKNOWN, si_addr=0x{:X})", signal, signal, handler);   
                }
                
            }
            // action not found
            else {
                log::warn!("{:?} handler not found", signal);
                if signal == Signals::SIGTERM || signal == Signals::SIGKILL || signal == Signals::SIGSEGV {
                    exception_signal = Some(signal);
                    break;
                }
                else{
                    log::warn!("Ingore signal {:?}", signal);
                }
            }
        }
        if let Some(signal) = exception_signal {
            drop(inner);
            drop(task);
            if signal == Signals::SIGTERM || signal == Signals::SIGKILL {
                log::info!("Use default handler for {:?}", signal);
                exit_current_and_run_next(signal.to_signum() as i32);
            }
            if signal == Signals::SIGSEGV {
                log::info!("Use default handler for SIGSEGV");
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
            }
        }
    }
}

pub fn sigprocmask(how: usize, set: Option<Signals>, old: *mut Signals) -> isize {
    if let Some(task) = current_task() {
        let mut inner = task.acquire_inner_lock();

        // Copy the old to the oldset.
        if old as usize != 0 {
            *translated_refmut(inner.get_user_token(), old) = inner.sigmask; // fix deadlock here
        }

        // Assign the sigmask.
        if let Some(s) = set {
            let i = match how {
                SIG_BLOCK => {
                    inner.sigmask = inner.sigmask.union(s);
                    0
                } /*add the signals not yet blocked in the given set to the mask.*/
                SIG_UNBLOCK => {
                    inner.sigmask = inner.sigmask.difference(s);
                    0
                } /*remove the blocked signals in the set from the sigmask. NOTE: unblocking a signal not blocked is allowed. */
                SIG_SETMASK => {
                    inner.sigmask = s;
                    0
                } /*set the signal mask to what we see.*/
                _ => -1, // "how" variable NOT recognized
            };
            inner.sigmask = inner
                .sigmask
                .difference(Signals::SIGKILL | Signals::SIGSTOP);
            i
        } else {
            0
        }
    } else {
        -1
    }
}
