use crate::{
    syscall::{errno::*, FutexOption},
    task::{block_current_and_run_next, current_task, suspend_current_and_run_next},
    timer::{get_time, get_time_ns, TimeRange, TimeSpec},
};
use alloc::collections::BTreeMap;
use lazy_static::lazy_static;
use log::*;
use num_enum::FromPrimitive;
use spin::Mutex;

#[allow(unused)]
#[derive(Debug, Eq, PartialEq, FromPrimitive)]
#[repr(u32)]
pub enum FutexCmd {
    /// This  operation  tests  that  the value at the futex
    /// word pointed to by the address uaddr still  contains
    /// the expected value val, and if so, then sleeps wait‐
    /// ing for a FUTEX_WAKE operation on  the  futex  word.
    /// The load of the value of the futex word is an atomic
    /// memory access (i.e., using atomic  machine  instruc‐
    /// tions  of  the respective architecture).  This load,
    /// the comparison with the expected value, and starting
    /// to  sleep  are  performed atomically and totally or‐
    /// dered with respect to other futex operations on  the
    /// same  futex word.  If the thread starts to sleep, it
    /// is considered a waiter on this futex word.   If  the
    /// futex  value does not match val, then the call fails
    /// immediately with the error EAGAIN.
    Wait = 0,
    /// This operation wakes at most val of the waiters that
    /// are waiting (e.g., inside FUTEX_WAIT) on  the  futex
    /// word  at  the  address uaddr.  Most commonly, val is
    /// specified as either 1 (wake up a single  waiter)  or
    /// INT_MAX (wake up all waiters).  No guarantee is pro‐
    /// vided about which waiters are awoken (e.g., a waiter
    /// with  a higher scheduling priority is not guaranteed
    /// to be awoken in preference to a waiter with a  lower
    /// priority).
    Wake = 1,
    Fd = 2,
    Requeue = 3,
    CmpRequeue = 4,
    WakeOp = 5,
    LockPi = 6,
    UnlockPi = 7,
    TrylockPi = 8,
    WaitBitset = 9,
    #[num_enum(default)]
    Invalid,
}

lazy_static! {
    pub static ref FUTEX_WAIT_NO: Mutex<BTreeMap<usize, u32>> = Mutex::new(BTreeMap::new());
}

/// Currently the `rt_clk` is ignored.
pub fn futex(
    futex_word: &mut u32,
    val: u32,
    cmd: FutexCmd,
    option: FutexOption,
    timeout: Option<TimeSpec>,
) -> isize {
    let timeout = timeout.map(|t| t + TimeSpec::now());
    let futex_word_addr = futex_word as *const u32 as usize;
    match cmd {
        // Returns  0  if the caller was woken up.
        FutexCmd::Wait => {
            if *futex_word != val {
                trace!(
                    "[futex] --wait-- **not match** futex: {:X}, val: {:X}",
                    *futex_word,
                    val
                );
                return EAGAIN;
            } else {
                loop {
                    let task = current_task().unwrap();
                    let inner = task.acquire_inner_lock();
                    if !inner.sigpending.is_empty() {
                        return EINTR;
                    }
                    drop(inner);
                    drop(task);
                    let mut lock = FUTEX_WAIT_NO.lock();
                    let ticket = lock.remove(&futex_word_addr);
                    if let Some(remain) = ticket {
                        trace!(
                            "[futex] --wait-- found existing ticket, remain times: {}",
                            remain
                        );
                        if remain - 1 > 0 {
                            lock.insert(futex_word_addr, remain - 1);
                        }
                        trace!("[futex] --wait-- update remain times: {}", remain - 1);
                        return SUCCESS;
                    }
                    drop(lock);
                    if let Some(t) = timeout {
                        if t <= TimeSpec::now() {
                            trace!("[futex] --wait-- time out");
                            return SUCCESS;
                        }
                    }
                    suspend_current_and_run_next();
                }
            }
        }
        // Returns the number of waiters that were woken up.
        FutexCmd::Wake => {
            loop {
                let mut lock = FUTEX_WAIT_NO.lock();
                let ticket = lock.remove(&futex_word_addr);
                let before = if let Some(remain) = ticket {
                    trace!(
                        "[futex] --wake-- found existing ticket, remain times: {}",
                        remain
                    );
                    lock.insert(futex_word_addr, remain + val);
                    trace!("[futex] --wake-- update remain times: {}", remain + val);
                    remain + val
                } else {
                    trace!(
                        "[futex] --wake-- insert a ticket with remain times: {}",
                        val
                    );
                    lock.insert(futex_word_addr, val);
                    val
                };
                drop(lock);
                suspend_current_and_run_next();
                // We use RR schedule, so all threads should have tried to consume...
                let lock = FUTEX_WAIT_NO.lock();
                let after = if let Some(&remain) = lock.get(&futex_word_addr) {
                    remain
                } else {
                    0
                };
                drop(lock);
                info!("[futex] --wake-- woke {} proc(s)", val.min(after - before));
                return val.min(after - before) as isize;
            }
        }
        FutexCmd::Invalid => EINVAL,
        _ => ENOSYS,
    }
}
