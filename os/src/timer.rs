use core::ops::{Sub, Add};

use crate::config::CLOCK_FREQ;
use crate::sbi::set_timer;
use riscv::register::time;

const TICKS_PER_SEC: usize = 100;
const MSEC_PER_SEC: usize = 1000;
const USEC_PER_SEC: usize = 1000_000;
const NSEC_PER_SEC: usize = 1000__000_000;
const USEC_PER_MSEC: usize = 1000;

/// Return current time measured by ticks, which is NOT divided by frequency.
pub fn get_time() -> usize {
    time::read()
}
/// Return current time measured by seconds.
pub fn get_time_sec() -> usize {
    let i = time::read() / (CLOCK_FREQ);
    //log::info!("[timer.rs] time::read(): {},sec: {}", time::read(), i);
    i
}
/// Return current time measured by ms.
pub fn get_time_ms() -> usize {
    let i = time::read() / (CLOCK_FREQ / MSEC_PER_SEC);
    //log::info!("[timer.rs] time::read(): {},ms: {}", time::read(), i);
    i
}
/// Return current time measured by us.
pub fn get_time_us() -> usize {
    let i = time::read() / (CLOCK_FREQ / USEC_PER_SEC);
    //log::info!("[timer.rs] time::read(): {},us: {}", time::read(), i);
    i
}
/// Return current time measured by nano seconds.
pub fn get_time_ns() -> usize {
    let i = time::read() * NSEC_PER_SEC / (CLOCK_FREQ);
    //log::info!("[timer.rs] time::read(): {},ns: {}", time::read(), i);
    i
}

/// Set next trigger.
pub fn set_next_trigger() {
    set_timer(get_time() + CLOCK_FREQ / TICKS_PER_SEC);
}

#[derive(Clone, Copy)]
pub struct TimeSpec {
    pub tv_sec: i32,
    pub tv_nsec: i32,
}

#[derive(Clone, Copy, Debug)]
pub struct TimeVal {
    /// seconds
    pub tv_sec: u32,
    /// microseconds
    pub tv_usec: u32,
}
impl TimeVal {
    pub fn new() -> Self {
        Self {
            tv_sec: 0,
            tv_usec: 0,
        }
    }
    pub fn from_tick(tick: usize) -> Self {
        Self {
            tv_sec: (tick / CLOCK_FREQ) as u32,
            tv_usec: ((tick % CLOCK_FREQ) / (CLOCK_FREQ / USEC_PER_SEC)) as u32,
        }
    }
    pub fn from_s(s: usize) -> Self {
        Self {
            tv_sec: s as u32,
            tv_usec: 0,
        }
    }
    pub fn from_ms(ms: usize) -> Self {
        Self {
            tv_sec: (ms / MSEC_PER_SEC) as u32,
            tv_usec: ((ms % MSEC_PER_SEC) * USEC_PER_MSEC) as u32,
        }
    }
    pub fn from_us(us: usize) -> Self {
        Self {
            tv_sec: (us / USEC_PER_SEC) as u32,
            tv_usec: (us % USEC_PER_SEC) as u32,
        }
    }
    pub fn to_us(&self) -> usize {
        self.tv_sec as usize * USEC_PER_SEC + self.tv_usec as usize
    }
    pub fn is_zero(&self) -> bool {
        self.tv_sec == 0 && self.tv_usec == 0
    }
    pub fn now() -> Self {
        TimeVal::from_tick(get_time())
    }
}

impl Add for TimeVal {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let mut sec = self.tv_sec + other.tv_sec;
        let mut usec = self.tv_usec + other.tv_usec;
        sec += usec / USEC_PER_SEC as u32;
        usec %= USEC_PER_SEC as u32;
        Self {
            tv_sec: sec,
            tv_usec: usec,
        }
    }
}

impl Sub for TimeVal {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        let self_us = self.to_us();
        let other_us = other.to_us();
        if self_us <= other_us {
            TimeVal::new()
        }
        else {
            TimeVal::from_us(self_us - other_us)
        }
    }
}

#[derive(Clone)]
pub struct TimeZone {
    pub tz_minute_west: u32,
    pub tz_dst_time: u32,
}
