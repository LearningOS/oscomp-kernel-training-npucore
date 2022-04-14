use crate::fs::File;
use crate::mm::UserBuffer;

pub struct Zero;
pub struct Null;

impl File for Zero {
    fn readable(&self) -> bool {
        true
    }
    fn writable(&self) -> bool {
        true
    }
    fn read(&self, mut buf: UserBuffer) -> usize {
        buf.clear();
        return buf.len();
    }
    fn write(&self, buf: UserBuffer) -> usize {
        return buf.len();
    }
}

impl File for Null {
    fn readable(&self) -> bool {
        true
    }
    fn writable(&self) -> bool {
        true
    }
    fn read(&self, _buf: UserBuffer) -> usize {
        return 0;
    }
    fn write(&self, buf: UserBuffer) -> usize {
        return buf.len();
    }
}

