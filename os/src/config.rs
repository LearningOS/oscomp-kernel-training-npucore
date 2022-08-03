#![allow(unused)]

pub const TASK_SIZE: usize = 0xc000_0000;
pub const ELF_DYN_BASE: usize = TASK_SIZE / 3 * 2;
pub const USER_STACK_BASE: usize = TASK_SIZE - PAGE_SIZE;
pub const USER_STACK_SIZE: usize = PAGE_SIZE * 40;
pub const USER_HEAP_SIZE: usize = PAGE_SIZE * 20;

pub const KERNEL_STACK_SIZE: usize = PAGE_SIZE * 2;
pub const KERNEL_HEAP_SIZE: usize = PAGE_SIZE * 0x200;
pub const MMAP_BASE: usize = 0x6000_0000;
pub const MMAP_END: usize = 0x8000_0000;

// manually make usable memory space equal
pub const MEMORY_START: usize = 0x8000_0000;
#[cfg(not(any(feature = "board_k210")))]
pub const MEMORY_END: usize = 0x809e_0000;
#[cfg(feature = "board_k210")]
pub const MEMORY_END: usize = 0x8080_0000;
pub const PAGE_SIZE: usize = 0x1000;
pub const PAGE_SIZE_BITS: usize = 0xc;

pub const TRAMPOLINE: usize = usize::MAX - PAGE_SIZE + 1;
pub const SIGNAL_TRAMPOLINE: usize = TRAMPOLINE - PAGE_SIZE;
pub const TRAP_CONTEXT_BASE: usize = SIGNAL_TRAMPOLINE - PAGE_SIZE;

pub use crate::board::{CLOCK_FREQ, MMIO};
