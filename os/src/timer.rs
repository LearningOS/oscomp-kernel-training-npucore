use crate::config::CLOCK_FREQ;
use crate::sbi::set_timer;
use riscv::register::time;

const TICKS_PER_SEC: usize = 100;
const MSEC_PER_SEC: usize = 1000;
const USEC_PER_SEC: usize = 1000_000;
const NSEC_PER_SEC: usize = 1000000000;

/// Return current time measured by ticks, which is NOT divided by frequency.
pub fn get_time() -> usize {
    time::read()
}

/// Return current time measured by us.
pub fn get_time_us() -> usize {
    let i = time::read() / (CLOCK_FREQ / USEC_PER_SEC);
    log::info!("[timer.rs] time::read(): {},us: {}", time::read(), i);
    i
}
/// Return current time measured by ms.
pub fn get_time_ms() -> usize {
    let i = time::read() / (CLOCK_FREQ / MSEC_PER_SEC);
    log::info!("[timer.rs] time::read(): {},ms: {}", time::read(), i);
    i
}
/// Return current time measured by nano seconds.
pub fn get_time_ns() -> usize {
    let i = time::read() * NSEC_PER_SEC / (CLOCK_FREQ);
    log::info!("[timer.rs] time::read(): {},ns: {}", time::read(), i);
    i
}

/// Return current time measured by seconds.
pub fn get_time_sec() -> usize {
    let i = time::read() / (CLOCK_FREQ);
    log::info!("[timer.rs] time::read(): {},sec: {}", time::read(), i);
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

#[derive(Clone, Copy)]
pub struct TimeVal {
    /// seconds
    pub tv_sec: u32,
    /// microseconds
    pub tv_usec: u32,
}
impl TimeVal {
    pub fn now() -> Self {
        let mut i = Self {
            tv_usec: get_time_us() as u32,
            tv_sec: 0,
        };
        i.tv_sec = i.tv_usec / 1000000;
        i
    }
    pub fn from_sec(tv_sec: usize) -> Self {
        Self {
            tv_sec: tv_sec as u32,
            tv_usec: (tv_sec as u32) * 1000_000,
        }
    }
    pub fn from_ms(ms: usize) -> Self {
        Self {
            tv_sec: (ms as u32) / 1000,
            tv_usec: (ms as u32) * 1000,
        }
    }
}

#[derive(Clone)]
pub struct TimeZone {
    pub tz_minute_west: u32,
    pub tz_dst_time: u32,
}
