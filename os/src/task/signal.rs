use core::fmt::{self, Debug, Error, Formatter};
use log::{debug, error, info, trace, warn};
use riscv::register::{scause, stval};

use crate::config::*;
use crate::mm::{copy_from_user, copy_to_user, translated_ref, translated_refmut};
use crate::syscall::errno::*;
use crate::task::{block_current_and_run_next, exit_current_and_run_next, ustack_bottom_from_tid};
use crate::timer::TimeSpec;
use crate::trap::TrapContext;

use super::{current_task, suspend_current_and_run_next};

bitflags! {
    /// Signal
    pub struct Signals: usize{
        /// Hangup.
        const	SIGHUP		= 1 << ( 0);
        /// Interactive attention signal.
        const	SIGINT		= 1 << ( 1);
        /// Quit.
        const	SIGQUIT		= 1 << ( 2);
        /// Illegal instruction.
        const	SIGILL		= 1 << ( 3);
        /// Trace/breakpoint trap.
        const	SIGTRAP		= 1 << ( 4);
        /// IOT instruction, abort() on a PDP-11.
        const	SIGABRT		= 1 << ( 5);
        /// Bus error.
        const	SIGBUS		= 1 << ( 6);
        /// Erroneous arithmetic operation.
        const	SIGFPE		= 1 << ( 7);
        /// Killed.
        const	SIGKILL		= 1 << ( 8);
        /// User-defined signal 1.
        const	SIGUSR1		= 1 << ( 9);
        /// Invalid access to storage.
        const	SIGSEGV		= 1 << (10);
        /// User-defined signal 2.
        const	SIGUSR2		= 1 << (11);
        /// Broken pipe.
        const	SIGPIPE		= 1 << (12);
        /// Alarm clock.
        const	SIGALRM		= 1 << (13);
        /// Termination request.
        const	SIGTERM		= 1 << (14);
        const	SIGSTKFLT	= 1 << (15);
        /// Child terminated or stopped.
        const	SIGCHLD		= 1 << (16);
        /// Continue.
        const	SIGCONT		= 1 << (17);
        /// Stop, unblockable.
        const	SIGSTOP		= 1 << (18);
        /// Keyboard stop.
        const	SIGTSTP		= 1 << (19);
        /// Background read from control terminal.
        const	SIGTTIN		= 1 << (20);
        /// Background write to control terminal.
        const	SIGTTOU		= 1 << (21);
        /// Urgent data is available at a socket.
        const	SIGURG		= 1 << (22);
        /// CPU time limit exceeded.
        const	SIGXCPU		= 1 << (23);
        /// File size limit exceeded.
        const	SIGXFSZ		= 1 << (24);
        /// Virtual timer expired.
        const	SIGVTALRM	= 1 << (25);
        /// Profiling timer expired.
        const	SIGPROF		= 1 << (26);
        /// Window size change (4.3 BSD, Sun).
        const	SIGWINCH	= 1 << (27);
        /// I/O now possible (4.2 BSD).
        const	SIGIO		= 1 << (28);
        const   SIGPWR      = 1 << (29);
        /// Bad system call.
        const   SIGSYS      = 1 << (30);
        /// RT signal for pthread
        const   SIGTIMER    = 1 << (31);
        /// RT signal for pthread
        const   SIGCANCEL   = 1 << (32);
        /// RT signal for pthread
        const   SIGSYNCCALL = 1 << (33);
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

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SigHandler(usize);

impl SigHandler {
    /// Default action.
    const SIG_DFL: Self = Self(0);
    /// Ignore signal.
    const SIG_IGN: Self = Self(1);
    fn addr(&self) -> Option<usize> {
        match *self {
            Self::SIG_DFL | Self::SIG_IGN => None,
            sig_handler => Some(sig_handler.0),
        }
    }
}

impl Debug for SigHandler {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            SigHandler::SIG_DFL => f.write_fmt(format_args!("SIG_DFL")),
            SigHandler::SIG_IGN => f.write_fmt(format_args!("SIG_IGN")),
            sig_handler => f.write_fmt(format_args!("0x{:X}", sig_handler.0)),
        }
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct SigAction {
    pub handler: SigHandler,
    pub flags: SigActionFlags,
    pub restorer: usize,
    pub mask: Signals,
}

impl SigAction {
    pub fn new() -> Self {
        Self {
            handler: SigHandler::SIG_DFL,
            flags: SigActionFlags::empty(),
            restorer: 0,
            mask: Signals::empty(),
        }
    }
}
// #[derive(Clone)]
// pub struct SigStatus {
//     pub signal_pending: Signals,
//     pub signal_handler: BTreeMap<Signals, SigAction>,
// }

// impl SigStatus {
//     pub fn new() -> Self {
//         Self {
//             signal_pending: Signals::empty(),
//             signal_handler: BTreeMap::new(),
//         }
//     }
// }

// impl Debug for SigStatus {
//     fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
//         f.write_fmt(format_args!(
//             "[ signal_pending: ({:?}), signal_handler: ({:?}) ]",
//             self.signal_pending, self.signal_handler
//         ))
//     }
// }

impl Debug for SigAction {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "[ sa_handler: {:?}, sa_mask: ({:?}), sa_flags: ({:?}) ]",
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
    let result = Signals::from_signum(signum);
    match result {
        Err(_) | Ok(Some(Signals::SIGKILL)) | Ok(Some(Signals::SIGSTOP)) | Ok(None) => {
            warn!("[sigaction] bad signum: {}", signum);
            EINVAL
        }
        Ok(Some(signal)) => {
            trace!("[sigaction] signal: {:?}", signal);
            let token = task.get_user_token();
            if oldact as usize != 0 {
                if let Some(sigact) = task.sighand.lock().remove(&signal) {
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
                sigact.mask.remove(
                    Signals::SIGILL | Signals::SIGSEGV | Signals::SIGKILL | Signals::SIGSTOP,
                );
                // push to PCB, ignore mask and flags now
                if !(sigact.handler == SigHandler::SIG_DFL || sigact.handler == SigHandler::SIG_IGN)
                {
                    task.sighand.lock().insert(signal, *sigact);
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
    while let Some(signal) = inner.sigpending.difference(inner.sigmask).peek_front() {
        inner.sigpending.remove(signal);
        trace!(
            "[do_signal] signal: {:?}, pending: {:?}, sigmask: {:?}",
            signal,
            inner.sigpending,
            inner.sigmask
        );
        let sighand = task.sighand.lock();
        if let Some(act) = sighand.get(&signal) {
            {
                let trap_cx = inner.get_trap_cx();
                let sp = unsafe { (trap_cx.x[2] as *mut TrapContext).sub(1) };
                if (sp as usize) < task.ustack_bottom_va() - USER_STACK_SIZE {
                    error!("[do_signal] User stack will overflow after push trap context! Send SIGSEGV.");
                    drop(inner);
                    drop(sighand);
                    drop(task);
                    exit_current_and_run_next(Signals::SIGSEGV.to_signum().unwrap() as u32);
                } else {
                    copy_to_user(task.get_user_token(), trap_cx, sp as *mut TrapContext); // push trap context into user stack
                    trap_cx.set_sp(sp as usize); // update sp, because we've pushed something into stack
                    trap_cx.x[10] = signal.to_signum().unwrap(); // a0 <- signum, parameter.
                    trap_cx.x[1] = SIGNAL_TRAMPOLINE; // ra <- __call_sigreturn, when handler ret, we will go to __call_sigreturn
                    trap_cx.sepc = act.handler.addr().unwrap(); // restore pc with addr of handler
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
                    drop(sighand);
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
                    drop(sighand);
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
                    drop(sighand);
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
    let token = task.get_user_token();
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

#[allow(unused)]
#[derive(Clone, Copy)]
pub struct SigInfo {
    si_signo: u32,
    si_errno: u32,
    si_code: u32,
}

#[allow(unused)]
impl SigInfo {
    const SI_ASYNCNL: u32 = 60u32.wrapping_neg();
    const SI_TKILL: u32 = 6u32.wrapping_neg();
    const SI_SIGIO: u32 = 5u32.wrapping_neg();
    const SI_ASYNCIO: u32 = 4u32.wrapping_neg();
    const SI_MESGQ: u32 = 3u32.wrapping_neg();
    const SI_TIMER: u32 = 2u32.wrapping_neg();
    const SI_QUEUE: u32 = 1u32.wrapping_neg();
    const SI_USER: u32 = 0;
    const SI_KERNEL: u32 = 128;
    const FPE_INTDIV: u32 = 1;
    const FPE_INTOVF: u32 = 2;
    const FPE_FLTDIV: u32 = 3;
    const FPE_FLTOVF: u32 = 4;
    const FPE_FLTUND: u32 = 5;
    const FPE_FLTRES: u32 = 6;
    const FPE_FLTINV: u32 = 7;
    const FPE_FLTSUB: u32 = 8;
    const ILL_ILLOPC: u32 = 1;
    const ILL_ILLOPN: u32 = 2;
    const ILL_ILLADR: u32 = 3;
    const ILL_ILLTRP: u32 = 4;
    const ILL_PRVOPC: u32 = 5;
    const ILL_PRVREG: u32 = 6;
    const ILL_COPROC: u32 = 7;
    const ILL_BADSTK: u32 = 8;
    const SEGV_MAPERR: u32 = 1;
    const SEGV_ACCERR: u32 = 2;
    const SEGV_BNDERR: u32 = 3;
    const SEGV_PKUERR: u32 = 4;
    const BUS_ADRALN: u32 = 1;
    const BUS_ADRERR: u32 = 2;
    const BUS_OBJERR: u32 = 3;
    const BUS_MCEERR_AR: u32 = 4;
    const BUS_MCEERR_AO: u32 = 5;
    const CLD_EXITED: u32 = 1;
    const CLD_KILLED: u32 = 2;
    const CLD_DUMPED: u32 = 3;
    const CLD_TRAPPED: u32 = 4;
    const CLD_STOPPED: u32 = 5;
    const CLD_CONTINUED: u32 = 6;
}

pub fn sigtimedwait(set: *const Signals, info: *mut SigInfo, timeout: *const TimeSpec) -> isize {
    let task = current_task().unwrap();
    let token = task.get_user_token();
    let set = *translated_ref(token, set);
    let mut timeout_ = TimeSpec::new();
    copy_from_user(token, timeout, &mut timeout_);
    debug!("[sigtimedwait] set: {:?}, timeout: {:?}", set, timeout_);

    let start = TimeSpec::now();
    loop {
        let inner = task.acquire_inner_lock();
        if inner.sigpending.contains(set) {
            let sig = (inner.sigpending & set).peek_front().unwrap();
            let signum = sig.to_signum().unwrap();
            if !info.is_null() {
                copy_to_user(
                    token,
                    &SigInfo {
                        si_signo: signum as u32,
                        si_errno: 0,
                        si_code: 0,
                    },
                    info,
                );
            }
            return signum as isize;
        } else {
            let remain = timeout_ - (TimeSpec::now() - start);
            if remain.is_zero() {
                return EAGAIN;
            } else {
                drop(inner);
                suspend_current_and_run_next();
            }
        }
    }
}
