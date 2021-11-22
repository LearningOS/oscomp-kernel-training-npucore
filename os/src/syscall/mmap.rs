use crate::task::mmap;
use crate::task::munmap;
pub fn sys_mmap(start: usize, len: usize, prot: usize) -> isize {
    mmap(start, len, prot) as isize
}
pub fn sys_munmap(start: usize, len: usize) -> isize {
    munmap(start, len) as isize
}
