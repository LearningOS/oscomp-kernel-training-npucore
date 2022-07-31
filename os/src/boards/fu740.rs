use crate::config::DISK_IMAGE_BASE;

pub const CLOCK_FREQ: usize = 1_200_000;

pub const MMIO: &[(usize, usize)] = &[
    (DISK_IMAGE_BASE, 0x800_0000), // disk image
];

pub type BlockDeviceImpl = crate::drivers::block::MemBlockWrapper;
