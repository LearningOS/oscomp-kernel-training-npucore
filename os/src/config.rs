#[allow(unused)]

pub const USER_STACK_BOTTOM: usize = TRAP_CONTEXT - PAGE_SIZE;
pub const USER_STACK_TOP: usize = USER_STACK_BOTTOM - USER_STACK_SIZE;
pub const USER_STACK_SIZE: usize = PAGE_SIZE * 20;
pub const KERNEL_STACK_SIZE: usize = PAGE_SIZE * 2;
pub const USER_HEAP_SIZE: usize = PAGE_SIZE * 20;
pub const KERNEL_HEAP_SIZE: usize = PAGE_SIZE * 0x200; //was 0x30_0000 by THU
// pub const USER_SIGNAL_STACK_BOTTOM: usize = USER_STACK_TOP - PAGE_SIZE;
// pub const USER_SIGNAL_STACK_TOP: usize =  USER_SIGNAL_STACK_BOTTOM - USER_SIGNAL_STACK_SIZE;
// pub const USER_SIGNAL_STACK_SIZE: usize = PAGE_SIZE;
pub const MMAP_BASE: usize = 0x6000_0000;
pub const MMAP_SIZE: usize = PAGE_SIZE * 512;
pub const MEMORY_END: usize = 0x80800000;
pub const PAGE_SIZE: usize = 0x1000;
pub const PAGE_SIZE_BITS: usize = 0xc;

pub const TRAMPOLINE: usize = usize::MAX - PAGE_SIZE + 1;
pub const TRAP_CONTEXT: usize = TRAMPOLINE - PAGE_SIZE;
pub const SIGNAL_TRAMPOLINE: usize = USER_STACK_TOP - 2*PAGE_SIZE;

// Execution of programs
pub const AT_NULL: usize = 0; /* end of vector */
pub const AT_IGNORE: usize = 1; /* entry should be ignored */
pub const AT_EXECFD: usize = 2; /* file descriptor of program */
pub const AT_PHDR: usize = 3; /* program headers for program */
pub const AT_PHENT: usize = 4; /* size of program header entry */
pub const AT_PHNUM: usize = 5; /* number of program headers */
pub const AT_PAGESZ: usize = 6; /* system page size */
pub const AT_BASE: usize = 7; /* base address of interpreter */
pub const AT_FLAGS: usize = 8; /* flags */
pub const AT_ENTRY: usize = 9; /* entry point of program */
pub const AT_NOTELF: usize = 10; /* program is not ELF */
pub const AT_UID: usize = 11; /* real uid */
pub const AT_EUID: usize = 12; /* effective uid */
pub const AT_GID: usize = 13; /* real gid */
pub const AT_EGID: usize = 14; /* effective gid */
pub const AT_PLATFORM: usize = 15; /* string identifying CPU for optimizations */
pub const AT_HWCAP: usize = 16; /* arch dependent hints at CPU capabilities */
pub const AT_CLKTCK: usize = 17; /* frequency at which times() increments */
/* AT_* values 18 through 22 are reserved */
pub const AT_SECURE: usize = 23; /* secure mode boolean */
pub const AT_BASE_PLATFORM: usize = 24; /* string identifying real platform, may
                                         * differ from AT_PLATFORM. */
pub const AT_RANDOM: usize = 25; /* address of 16 random bytes */
pub const AT_HWCAP2: usize = 26; /* extension of AT_HWCAP */

pub const AT_EXECFN: usize = 31; /* filename of program */
/* Pointer to the global system page used for system calls and other
nice things.  */
pub const AT_SYSINFO: usize = 32;
pub const AT_SYSINFO_EHDR: usize = 33;

pub use crate::board::{CLOCK_FREQ, MMIO};
