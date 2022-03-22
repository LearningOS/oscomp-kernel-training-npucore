#![allow(unused)]
use core::ops::{Add, Sub};

use crate::config::CLOCK_FREQ;
use crate::sbi::set_timer;
use riscv::register::time;

pub const TICKS_PER_SEC: usize = 100;
pub const MSEC_PER_SEC: usize = 1000;
pub const USEC_PER_SEC: usize = 1_000_000;
pub const NSEC_PER_SEC: usize = 1_000_000_000;
pub const NSEC_PER_MSEC: usize = 1_000_000;
pub const USEC_PER_MSEC: usize = 1_000;

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

#[derive(Clone, Copy, Debug)]
pub struct TimeSpec {
    pub tv_sec: u32,
    pub tv_nsec: u32,
}

impl Add for TimeSpec {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let mut sec = self.tv_sec + other.tv_sec;
        let mut nsec = self.tv_nsec + other.tv_nsec;
        sec += nsec / NSEC_PER_SEC as u32;
        nsec %= NSEC_PER_SEC as u32;
        Self {
            tv_sec: sec,
            tv_nsec: nsec,
        }
    }
}

impl Sub for TimeSpec {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        let self_ns = self.to_ns();
        let other_ns = other.to_ns();
        if self_ns <= other_ns {
            TimeSpec::new()
        } else {
            TimeSpec::from_ns(self_ns - other_ns)
        }
    }
}

impl TimeSpec {
    pub fn new() -> Self {
        Self {
            tv_sec: 0,
            tv_nsec: 0,
        }
    }
    pub fn from_tick(tick: usize) -> Self {
        Self {
            tv_sec: (tick / CLOCK_FREQ) as u32,
            tv_nsec: ((tick % CLOCK_FREQ) * NSEC_PER_SEC / CLOCK_FREQ) as u32,
        }
    }
    pub fn from_s(s: usize) -> Self {
        Self {
            tv_sec: s as u32,
            tv_nsec: 0,
        }
    }
    pub fn from_ms(ms: usize) -> Self {
        Self {
            tv_sec: (ms / MSEC_PER_SEC) as u32,
            tv_nsec: ((ms % MSEC_PER_SEC) * NSEC_PER_MSEC) as u32,
        }
    }
    pub fn from_us(ns: usize) -> Self {
        Self {
            tv_sec: (ns / USEC_PER_SEC) as u32,
            tv_nsec: ((ns % USEC_PER_SEC) * (NSEC_PER_SEC / USEC_PER_SEC)) as u32,
        }
    }
    pub fn from_ns(ns: usize) -> Self {
        Self {
            tv_sec: (ns / NSEC_PER_SEC) as u32,
            tv_nsec: (ns % NSEC_PER_SEC) as u32,
        }
    }
    pub fn to_ns(&self) -> usize {
        self.tv_sec as usize * NSEC_PER_SEC + self.tv_nsec as usize
    }
    pub fn is_zero(&self) -> bool {
        self.tv_sec == 0 && self.tv_nsec == 0
    }
    pub fn now() -> Self {
        TimeSpec::from_tick(get_time())
    }
}

/// *CAUTION* tv_sec & tv_usec should be usize.
#[derive(Clone, Copy, Debug)]
pub struct TimeVal {
    /// seconds
    pub tv_sec: usize,
    /// microseconds
    pub tv_usec: usize,
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
            tv_sec: tick / CLOCK_FREQ,
            tv_usec: (tick % CLOCK_FREQ) * USEC_PER_SEC / CLOCK_FREQ,
        }
    }
    pub fn from_s(s: usize) -> Self {
        Self {
            tv_sec: s,
            tv_usec: 0,
        }
    }
    pub fn from_ms(ms: usize) -> Self {
        Self {
            tv_sec: ms / MSEC_PER_SEC,
            tv_usec: (ms % MSEC_PER_SEC) * USEC_PER_MSEC,
        }
    }
    pub fn from_us(us: usize) -> Self {
        Self {
            tv_sec: us / USEC_PER_SEC,
            tv_usec: us % USEC_PER_SEC,
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
        sec += usec / USEC_PER_SEC;
        usec %= USEC_PER_SEC;
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
        } else {
            TimeVal::from_us(self_us - other_us)
        }
    }
}

#[derive(Clone)]
pub struct TimeZone {
    pub tz_minute_west: u32,
    pub tz_dst_time: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct ITimerVal {
    pub it_interval: TimeVal,
    pub it_value: TimeVal,
}
impl ITimerVal {
    pub fn new() -> Self {
        Self {
            it_interval: TimeVal::new(),
            it_value: TimeVal:: new(),
        }
    }
}