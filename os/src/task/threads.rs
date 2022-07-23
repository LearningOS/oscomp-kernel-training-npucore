use crate::{
    syscall::errno::*,
    task::{current_task, suspend_current_and_run_next},
    timer::TimeSpec,
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
    pub static ref FUTEX_WAIT_NO: Mutex<BTreeMap<usize, Ticket>> = Mutex::new(BTreeMap::new());
}

#[derive(Debug, Clone, Copy)]
pub enum Ticket {
    Valid(u32),
    Move((usize, u32)),
}

/// Currently the `rt_clk` is ignored.
pub fn do_futex_wait(futex_word: &mut u32, val: u32, timeout: Option<TimeSpec>) -> isize {
    let timeout = timeout.map(|t| t + TimeSpec::now());
    let mut futex_word_addr = futex_word as *const u32 as usize;
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
            let result = lock.remove(&futex_word_addr);
            if let Some(ticket) = result {
                match ticket {
                    Ticket::Valid(remain) => {
                        trace!(
                            "[futex] --wait-- found existing ticket, remain times: {}",
                            remain
                        );
                        if remain - 1 > 0 {
                            lock.insert(futex_word_addr, Ticket::Valid(remain - 1));
                        }
                        trace!("[futex] --wait-- update remain times: {}", remain - 1);
                        return SUCCESS;
                    }
                    Ticket::Move((addr, remain)) => {
                        trace!(
                            "[futex] --wait-- found existing requeue broadcast, addr: {:X}, remain times: {}",
                            addr, remain
                        );
                        if remain - 1 > 0 {
                            lock.insert(futex_word_addr, Ticket::Move((addr, remain - 1)));
                        }
                        futex_word_addr = addr;
                    }
                }
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

pub fn do_futex_wake_without_check(futex_word_addr: usize, val: u32) -> u32 {
    let mut lock = FUTEX_WAIT_NO.lock();
    let result = lock.remove(&futex_word_addr);
    let before = if let Some(ticket) = result {
        match ticket {
            Ticket::Valid(remain) => {
                trace!(
                    "[futex] --wake-- found existing ticket, remain times: {}",
                    remain
                );
                lock.insert(futex_word_addr, Ticket::Valid(remain + val));
                trace!("[futex] --wake-- update remain times: {}", remain + val);
                remain + val
            }
            Ticket::Move(_) => {
                trace!("[futex] --wake-- found existing `Move` broadcast, do nothing.");
                0
            }
        }
    } else {
        trace!(
            "[futex] --wake-- insert a ticket with remain times: {}",
            val
        );
        lock.insert(futex_word_addr, Ticket::Valid(val));
        val
    };
    before
}
pub fn do_futex_wake(futex_word_addr: usize, val: u32) -> isize {
    let before = do_futex_wake_without_check(futex_word_addr, val);
    suspend_current_and_run_next();
    // We use RR schedule, so all threads should have tried to consume...
    let mut lock = FUTEX_WAIT_NO.lock();
    let after = if let Some(result) = lock.remove(&futex_word_addr) {
        match result {
            Ticket::Valid(remain) => remain,
            // emmm, somebody broadcast `Move`, after we insert tickets...
            // pretend that all tickets were used and insert back
            Ticket::Move(_) => {
                lock.insert(futex_word_addr, result);
                0
            },
        }
    } else {
        0
    };
    drop(lock);
    info!("[futex] --wake-- woke {} proc(s)", val.min(after - before));
    return val.min(after - before) as isize;
}

pub fn broadcast_move(futex_word_addr: usize, addr: usize, val2: u32) -> isize {
    let mut lock = FUTEX_WAIT_NO.lock();
    let something = lock.insert(futex_word_addr, Ticket::Move((addr, val2)));
    trace!("[futex] --requeue-- broadcast, futex_addr: {:X} move to addr: {:X}, remain: {}", futex_word_addr, addr, val2);
    if let Some(ticket) = something {
        warn!("[futex] --requeue-- a ticket was covered: {:?}", ticket);
    }
    drop(lock);
    suspend_current_and_run_next();
    // We use RR schedule, so all threads should have received the broadcast, try to take it back.
    let mut lock = FUTEX_WAIT_NO.lock();
    let after = if let Some(result) = lock.remove(&futex_word_addr) {
        match result {
            // emmm, somebody try `futex_wake`, after we broadcast...
            // pretend that all ticket were used and insert back
            Ticket::Valid(_) => {
                lock.insert(futex_word_addr, result);
                0
            },
            Ticket::Move((_, remain)) => remain,
        }
    } else {
        0
    };
    (val2 - after) as isize
}

pub fn do_futex_requeue(futex_word: &u32, futex_word_2: &u32, val: u32, val2: u32) -> isize {
    let futex_word_addr = futex_word as *const u32 as usize;
    let futex_word_2_addr = futex_word_2 as *const u32 as usize;
    let woke = if val != 0 {
        do_futex_wake(futex_word_addr, val)
    } else {
        0
    };
    let requeued = broadcast_move(futex_word_addr, futex_word_2_addr, val2);
    info!("[futex] --requeue-- requeued {} proc(s)", requeued);
    woke + requeued
}
