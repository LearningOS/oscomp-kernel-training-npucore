use alloc::collections::BTreeMap;
use core::fmt::{self, Debug, Error, Formatter};
use log::{debug, error, info, trace, warn};
use num_enum::FromPrimitive;
use riscv::register::{scause, stval};

use crate::config::*;
use crate::mm::{copy_from_user, copy_to_user, translated_ref, translated_refmut};
use crate::syscall::errno::*;
use crate::task::{block_current_and_run_next, exit_current_and_run_next};
use crate::trap::TrapContext;

use super::current_task;

bitflags! {
    /// Signal
    pub struct Signals: usize{
        const	SIGHUP		= 1 << ( 0);
        const	SIGINT		= 1 << ( 1);
        const	SIGQUIT		= 1 << ( 2);
        const	SIGILL		= 1 << ( 3);
        const	SIGTRAP		= 1 << ( 4);
        const	SIGABRT		= 1 << ( 5);
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
    /// if signum > 64 (illeagal), return `Err()`, else return `Ok(Option<Signals>)`
    /// # Attention
    /// Some signals are not present in `struct Signals` (they are leagal though)
    /// In this case, the `Option<Signals>` will be `None`
    pub fn from_signum(signum: usize) -> Result<Option<Signals>, Error> {
        if signum == 0 {
            return Ok(None);
        }
        if signum <= 64 {
            Ok(Signals::from_bits(1 << (signum - 1)))
        } else {
            Err(core::fmt::Error)
        }
    }
    pub fn to_signum(&self) -> Option<usize> {
        if self.bits().count_ones() == 1 {
            Some(self.bits().trailing_zeros() as usize + 1)
        } else {
            None
        }
    }
    pub fn peek_front(&self) -> Option<Signals> {
        if self.is_empty() {
            None
        } else {
            Signals::from_bits(1 << (self.bits().trailing_zeros() as usize))
        }
    }
}

bitflags! {
    /// Bits in `sa_flags' used to denote the default signal action.
    pub struct SigActionFlags: usize{
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
    /// Use signal trampoline provided by C library's wrapper function.
        const SA_RESTORER  = 0x04000000;
    }
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, FromPrimitive)]
#[repr(usize)]
pub enum SigActionHandler {
    /// Default action.
    SIG_DFL = 0,
    /// Ignore signal.  
    SIG_IGN = 1,
    #[num_enum(default)]
    SIG_HANDLER,
}
#[derive(Clone, Copy)]
#[repr(C)]
pub struct SigAction {
    pub handler: SigActionHandler,
    pub flags: SigActionFlags,
    pub restorer: usize,
    pub mask: Signals,
}

impl SigAction {
    pub fn new() -> Self {
        Self {
            handler: SigActionHandler::SIG_DFL,
            flags: SigActionFlags::empty(),
            restorer: 0,
            mask: Signals::empty(),
        }
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
            "[ sa_handler: 0x{:?}, sa_mask: ({:?}), sa_flags: ({:?}) ]",
            self.handler, self.mask, self.flags
        ))
    }
}

/// Change the action taken by a process on receipt of a specific signal.
/// (See signal(7) for  an  overview of signals.)
/// # Fields in Structure of `act` & `oldact`
///
/// # Arguments
/// * `signum`: specifies the signal and can be any valid signal except `SIGKILL` and `SIGSTOP`.
/// * `act`: new action
/// * `oldact`: old action
pub fn sigaction(signum: usize, act: *const SigAction, oldact: *mut SigAction) -> isize {
    let task = current_task().unwrap();
    let mut inner = task.acquire_inner_lock();
    let result = Signals::from_signum(signum);
    match result {
        Err(_) | Ok(Some(Signals::SIGKILL)) | Ok(Some(Signals::SIGSTOP)) | Ok(None) => {
            warn!("[sigaction] bad signum: {}", signum);
            EINVAL
        }
        Ok(Some(signal)) => {
            trace!("[sigaction] signal: {:?}", signal);
            let token = inner.get_user_token();
            if oldact as usize != 0 {
                if let Some(sigact) = inner.siginfo.signal_handler.remove(&signal) {
                    copy_to_user(token, &sigact, oldact);
                    trace!("[sigaction] *oldact: {:?}", sigact);
                } else {
                    copy_to_user(token, &SigAction::new(), oldact);
                    trace!("[sigaction] *oldact: not found");
                }
            }
            if act as usize != 0 {
                let sigact = &mut SigAction::new();
                copy_from_user(token, act, sigact);
                sigact.mask.remove(Signals::SIGILL | Signals::SIGSEGV | Signals::SIGKILL | Signals::SIGSTOP);
                // push to PCB, ignore mask and flags now
                if !(sigact.handler == SigActionHandler::SIG_DFL
                    || sigact.handler == SigActionHandler::SIG_IGN)
                {
                    inner.siginfo.signal_handler.insert(signal, *sigact);
                };
                trace!("[sigaction] *act: {:?}", sigact);
            }
            SUCCESS
        }
    }
}

pub fn do_signal() {
    let task = current_task().unwrap();
    let mut inner = task.acquire_inner_lock();
    while let Some(signal) = inner
        .siginfo
        .signal_pending
        .difference(inner.sigmask)
        .peek_front()
    {
        inner.siginfo.signal_pending.remove(signal);
        trace!(
            "[do_signal] signal: {:?}, pending: {:?}, sigmask: {:?}",
            signal,
            inner.siginfo.signal_pending,
            inner.sigmask
        );
        if let Some(act) = inner.siginfo.signal_handler.get(&signal) {
            {
                let trap_cx = inner.get_trap_cx();
                let sp = unsafe { (trap_cx.x[2] as *mut TrapContext).sub(1) };
                if (sp as usize) < USER_STACK_TOP {
                    trap_cx.sepc = usize::MAX; // we don't have enough space on user stack, return a bad address to kill this program
                } else {
                    copy_to_user(inner.get_user_token(), trap_cx, sp as *mut TrapContext); // restore context on user stack
                    trap_cx.set_sp(sp as usize); // update sp, because we pushed trapcontext into stack
                    trap_cx.x[10] = signal.to_signum().unwrap(); // a0 <- signum, parameter.
                    trap_cx.x[1] = SIGNAL_TRAMPOLINE; // ra <- __call_sigreturn, when handler ret, we will go to __call_sigreturn
                    trap_cx.sepc = act.handler as usize; // recover pc with addr of handler
                }
                trace!(
                    "[do_signal] signal: {:?}, signum: {:?}, handler: 0x{:?} (ra: 0x{:X}, sp: 0x{:X})",
                    signal,
                    signal.to_signum().unwrap(),
                    act.handler,
                    trap_cx.x[1],
                    trap_cx.x[2]
                );
            }
        } else {
            // user program doesn't register a handler for this signal, use our default handler
            match signal {
                // caused by a specific instruction in user program, print log here before exit
                Signals::SIGILL | Signals::SIGSEGV => {
                    let scause = scause::read();
                    let stval = stval::read();
                    warn!("[do_signal] process terminated due to {:?}", signal);
                    println!(
                        "[kernel] {:?} in application, bad addr = {:#x}, bad instruction = {:#x}, core dumped.",
                        scause.cause(),
                        stval,
                        inner.get_trap_cx().sepc,
                    );
                    drop(inner);
                    drop(task);
                    exit_current_and_run_next(signal.to_signum().unwrap() as u32);
                }
                // the current process we are handing is sure to be in RUNNING status, so just ignore SIGCONT
                // where we really wake up this process is where we sent SIGCONT, such as `sys_kill()`
                Signals::SIGCHLD | Signals::SIGCONT | Signals::SIGURG | Signals::SIGWINCH => {
                    trace!("[do_signal] Ignore {:?}", signal);
                    continue;
                }
                // stop (or we should say block) current process
                Signals::SIGTSTP | Signals::SIGTTIN | Signals::SIGTTOU => {
                    drop(inner);
                    block_current_and_run_next();
                    // because this loop require `inner`, and we have `drop(inner)` above, so `break` is compulsory
                    // this would cause some signals won't be handled immediately when this process resumes
                    // but it doesn't matter, maybe
                    break;
                }
                // for all other signals, we should terminate current process
                _ => {
                    warn!("[do_signal] process terminated due to {:?}", signal);
                    drop(inner);
                    drop(task);
                    exit_current_and_run_next(signal.to_signum().unwrap() as u32);
                }
            }
        }
    }
}

bitflags! {
    pub struct SigMaskHow: u32 {
        const SIG_BLOCK     = 0;
        const SIG_UNBLOCK   = 1;
        const SIG_SETMASK   = 2;
    }
}

/// fetch and/or change the signal mask of the calling thread.
/// # Warning
/// In fact, `set` & `oldset` should be 1024 bits `sigset_t`, but we only support 64 signals now.
/// For the sake of performance, we use `Signals` instead.
pub fn sigprocmask(how: u32, set: *const Signals, oldset: *mut Signals) -> isize {
    let task = current_task().unwrap();
    let mut inner = task.acquire_inner_lock();
    let token = inner.get_user_token();
    // If oldset is non-NULL, the previous value of the signal mask is stored in oldset
    if oldset as usize != 0 {
        *translated_refmut(token, oldset) = inner.sigmask;
        trace!("[sigprocmask] *oldset: ({:?})", inner.sigmask);
    }
    // If set is NULL, then the signal mask is unchanged
    if set as usize != 0 {
        let how = SigMaskHow::from_bits(how);
        let signal_set = *translated_ref(token, set);
        trace!("[sigprocmask] how: {:?}, *set: ({:?})", how, signal_set);
        match how {
            // add the signals not yet blocked in the given set to the mask
            Some(SigMaskHow::SIG_BLOCK) => {
                inner.sigmask = inner.sigmask.union(signal_set);
            }
            // remove the blocked signals in the set from the sigmask
            // NOTE: unblocking a signal not blocked is allowed
            Some(SigMaskHow::SIG_UNBLOCK) => {
                inner.sigmask = inner.sigmask.difference(signal_set);
            }
            // set the signal mask to what we see
            Some(SigMaskHow::SIG_SETMASK) => {
                inner.sigmask = signal_set;
            }
            // `how` was invalid
            _ => return EINVAL,
        };
        // unblock SIGILL & SIGSEGV, otherwise infinite loop may occurred
        // unblock SIGKILL & SIGSTOP, they can't be masked according to standard
        inner.sigmask = inner
            .sigmask
            .difference(Signals::SIGILL | Signals::SIGSEGV | Signals::SIGKILL | Signals::SIGSTOP);
    }
    SUCCESS
}
