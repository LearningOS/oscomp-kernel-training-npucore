use crate::clock::Clocks;
use embedded_hal::blocking::delay::{DelayMs, DelayUs};
use riscv::register::mcycle;

/// Machine mode cycle counter (`mcycle`) as a delay provider
#[derive(Copy, Clone)]
pub struct McycleDelay {
    core_frequency: u32,
}

impl McycleDelay {
    /// Constructs the delay provider
    pub fn new(clocks: &Clocks) -> Self {
        Self {
            core_frequency: clocks.coreclk().0,
        }
    }
}

impl DelayUs<u64> for McycleDelay {
    fn delay_us(&mut self, us: u64) {
        let t0 = mcycle::read64();
        let clocks = (us * (self.core_frequency as u64)) / 1_000_000;
        while mcycle::read64().wrapping_sub(t0) <= clocks {}
    }
}

impl DelayUs<u32> for McycleDelay {
    #[inline(always)]
    fn delay_us(&mut self, us: u32) {
        self.delay_us(us as u64)
    }
}

// Implemented for constructions like `delay.delay_us(50_000);`
impl DelayUs<i32> for McycleDelay {
    #[inline(always)]
    fn delay_us(&mut self, us: i32) {
        assert!(us >= 0);
        self.delay_us(us as u32);
    }
}

impl DelayUs<u16> for McycleDelay {
    #[inline(always)]
    fn delay_us(&mut self, us: u16) {
        self.delay_us(us as u32)
    }
}

impl DelayUs<u8> for McycleDelay {
    #[inline(always)]
    fn delay_us(&mut self, us: u8) {
        self.delay_us(us as u32)
    }
}

impl DelayMs<u32> for McycleDelay {
    fn delay_ms(&mut self, ms: u32) {
        self.delay_us((ms as u64) * 1000)
    }
}

// Implemented for constructions like `delay.delay_ms(50_000);`
impl DelayMs<i32> for McycleDelay {
    #[inline(always)]
    fn delay_ms(&mut self, ms: i32) {
        assert!(ms >= 0);
        self.delay_ms(ms as u32);
    }
}

impl DelayMs<u16> for McycleDelay {
    #[inline(always)]
    fn delay_ms(&mut self, ms: u16) {
        self.delay_ms(ms as u32)
    }
}

impl DelayMs<u8> for McycleDelay {
    #[inline(always)]
    fn delay_ms(&mut self, ms: u8) {
        self.delay_ms(ms as u32)
    }
}
