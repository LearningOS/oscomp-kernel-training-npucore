///  A scheduling  scheme  whereby  the  local  process  periodically  checks  until  the  pre-specified events (for example, read, write) have occurred.
use super::{FileDescripter, OSInode};

/// The PollFd struct in 32-bit style.
/// Members:
///   [fd](PollFd.fd): u32 file descriptor
///   [events](PollFd.events): u16 requested events
///   [revents](PollFd.revents) :u16 returned events
#[repr(C)]
pub struct PollFd {
    fd: u32,
    events: u16,
    revents: u16,
}

impl PollFd {
    /* fn get_fdes(&self) -> FileDescripter {}
     * fn get_inode(&self) -> OSInode {} */
}
pub fn poll() {}
pub fn ppoll() {}
