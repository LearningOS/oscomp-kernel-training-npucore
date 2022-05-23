use crate::fs::File;
use crate::mm::UserBuffer;

/// Data Sink
/// Data written to the `/dev/zero` special files is discarded.
/// Reads from `/dev/zero` always return  bytes  containing  zero (`'\0'` characters).
pub struct Zero;

/// Data Sink
/// Data written to the `/dev/null` special files is discarded.
/// Reads  from `/dev/null` always return end of file (i.e., read(2) returns 0)
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
    /// Always return zero.
    fn read(&self, _buf: UserBuffer) -> usize {
        return 0;
    }
    fn write(&self, buf: UserBuffer) -> usize {
        return buf.len();
    }
}
