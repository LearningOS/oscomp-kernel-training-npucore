#![allow(unused)]

pub const USER_STACK_BOTTOM: usize = SIGNAL_TRAMPOLINE;
pub const USER_STACK_TOP: usize = USER_STACK_BOTTOM - USER_STACK_SIZE;
pub const USER_STACK_SIZE: usize = PAGE_SIZE * 10;
pub const KERNEL_STACK_SIZE: usize = PAGE_SIZE * 2;
pub const USER_HEAP_SIZE: usize = PAGE_SIZE * 20;
pub const KERNEL_HEAP_SIZE: usize = PAGE_SIZE * 0x200;
// pub const USER_SIGNAL_STACK_BOTTOM: usize = USER_STACK_TOP - PAGE_SIZE;
// pub const USER_SIGNAL_STACK_TOP: usize =  USER_SIGNAL_STACK_BOTTOM - USER_SIGNAL_STACK_SIZE;
// pub const USER_SIGNAL_STACK_SIZE: usize = PAGE_SIZE;
pub const MMAP_BASE: usize = 0x6000_0000;
pub const MMAP_SIZE: usize = PAGE_SIZE * 512;
// manually make usable memory space equal
#[cfg(not(any(feature = "board_k210")))]
pub const MEMORY_END: usize = 0x809e0000;
#[cfg(feature = "board_k210")]
pub const MEMORY_END: usize = 0x80800000;
pub const PAGE_SIZE: usize = 0x1000;
pub const PAGE_SIZE_BITS: usize = 0xc;

pub const TRAMPOLINE: usize = usize::MAX - PAGE_SIZE + 1;
pub const TRAP_CONTEXT: usize = TRAMPOLINE - PAGE_SIZE;
pub const SIGNAL_TRAMPOLINE: usize = TRAP_CONTEXT - PAGE_SIZE;

pub use crate::board::{CLOCK_FREQ, MMIO};
