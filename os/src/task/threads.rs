use crate::{
    syscall::errno::SUCCESS,
    task::{block_current_and_run_next, current_task, suspend_current_and_run_next},
    timer::{get_time, get_time_ns, TimeRange, TimeSpec},
};
use alloc::collections::BTreeMap;
use core::convert::TryFrom;
use lazy_static::lazy_static;
use log::*;
use num_enum::TryFromPrimitive;
use spin::Mutex;
#[derive(Debug, Eq, PartialEq, TryFromPrimitive)]
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
    FUTEX_WAIT = 0,
    /// This operation wakes at most val of the waiters that
    /// are waiting (e.g., inside FUTEX_WAIT) on  the  futex
    /// word  at  the  address uaddr.  Most commonly, val is
    /// specified as either 1 (wake up a single  waiter)  or
    /// INT_MAX (wake up all waiters).  No guarantee is pro‐
    /// vided about which waiters are awoken (e.g., a waiter
    /// with  a higher scheduling priority is not guaranteed
    /// to be awoken in preference to a waiter with a  lower
    /// priority).
    FUTEX_WAKE = 1,
    FUTEX_FD = 2,
    FUTEX_REQUEUE = 3,
    FUTEX_CMP_REQUEUE = 4,
    FUTEX_WAKE_OP = 5,
    FUTEX_LOCK_PI = 6,
    FUTEX_UNLOCK_PI = 7,
    FUTEX_TRYLOCK_PI = 8,
    FUTEX_WAIT_BITSET = 9,
}

pub const FUTEX_PRIVATE: u32 = 128;
pub const FUTEX_CLOCK_REALTIME: u32 = 256;
lazy_static! {
    static ref FUTEX_WAIT_NO: Mutex<BTreeMap<usize, u32>> = Mutex::new(BTreeMap::new());
}

/// Currently the `rt_clk` is ignored.
pub fn futex(
    futex_word: &mut u32,
    uwd2: &mut u32,
    val: u32,
    val3: u32,
    cmd: FutexCmd,
    private_futex: bool,
    rt_clk: bool,
    timeout: Option<TimeSpec>,
) -> isize {
    let timeout = timeout.map(|t| t + TimeSpec::now());
    let futex_word_addr = futex_word as *const u32 as usize;
    match cmd {
        // Returns  0  if the caller was woken up.
        FutexCmd::FUTEX_WAIT => {
            // old rev.
            loop {
                if *futex_word != val {
                    info!("[FUTEX_WAIT] quit for value change.");
                    return SUCCESS;
                } else {
                    let mut lock = FUTEX_WAIT_NO.lock();
                    if let Some(i) = lock.get(&futex_word_addr) {
                        info!("[FUTEX_WAIT] released for a new ticket.");
                        let num = *i;
                        lock.insert(futex_word_addr, num - 1);
                        drop(lock);
                        return SUCCESS;
                    }
                    drop(lock);
                    if let Some(t) = timeout {
                        info!("[FUTEX_WAIT] released timed out.");
                        if t <= TimeSpec::now() {
                            return SUCCESS;
                        }
                    }
                    suspend_current_and_run_next();
                }
            }
        }
        // Returns the number of waiters that were woken up.
        // 我这算法挺智障的...我还是找机会换WaitQueue吧
        FutexCmd::FUTEX_WAKE => {
            let result = 0;
            loop {
                let mut lock = FUTEX_WAIT_NO.lock();
                if let Some(_) = lock.get(&futex_word_addr) {
                    drop(lock);
                    suspend_current_and_run_next();
                } else {
                    info!("[FUTEX_WAKE] no tickets");
                    lock.insert(futex_word_addr, val);
                    drop(lock);
                    suspend_current_and_run_next();
                    let mut lock = FUTEX_WAIT_NO.lock();
                    let diff = *lock.get(&futex_word_addr).unwrap();
                    if diff == 0 {
                        lock.remove(&futex_word_addr);
                    }
                    drop(lock);
                    info!("[FUTEX_WAKE] woke {} proc(s)", (val - diff));
                    return (val - diff) as isize;
                }
            }
        }
        FutexCmd::FUTEX_FD => todo!(),
        FutexCmd::FUTEX_REQUEUE => todo!(),
        FutexCmd::FUTEX_CMP_REQUEUE => todo!(),
        FutexCmd::FUTEX_WAKE_OP => todo!(),
        FutexCmd::FUTEX_LOCK_PI => todo!(),
        FutexCmd::FUTEX_UNLOCK_PI => todo!(),
        FutexCmd::FUTEX_TRYLOCK_PI => todo!(),
        FutexCmd::FUTEX_WAIT_BITSET => todo!(),
    }
}
