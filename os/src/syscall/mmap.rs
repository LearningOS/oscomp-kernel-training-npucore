use crate::task::mmap;
use crate::task::munmap;
pub fn sys_mmap(
    start: usize,
    len: usize,
    prot: usize,
    flags: usize,
    fd: usize,
    offset: usize,
) -> isize {
    mmap(start, len, prot, flags, fd, offset) as isize
}
pub fn sys_munmap(start: usize, len: usize) -> isize {
    munmap(start, len) as isize
}
