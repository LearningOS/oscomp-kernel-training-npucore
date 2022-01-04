use lazy_static::__Deref;

use crate::{
    mm::{copy_from_user, translated_byte_buffer},
    task::{current_task, suspend_current_and_run_next},
};

///  A scheduling  scheme  whereby  the  local  process  periodically  checks  until  the  pre-specified events (for example, read, write) have occurred.
use super::{FileDescripter, OSInode};

/* Event types that can be polled for.  These bits may be set in `events'
to indicate the interesting event types; they will appear in `revents'
to indicate the status of the file descriptor.  */
/// There is data to read.
const POLLIN: usize = 0x001;

/// There is urgent data to read.
const POLLPRI: usize = 0x002;

/// Writing now will not block.  
const POLLOUT: usize = 0x004;

/* Event types always implicitly polled for.  These bits need not be set in
`events', but they will appear in `revents' to indicate the status of
the file descriptor.  */
/// Error condition.
const POLLERR: usize = 0x008;

/// Hung up.
const POLLHUP: usize = 0x010;

/// Invalid polling request.
const POLLNVAL: usize = 0x020;

/// The PollFd struct in 32-bit style.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PollFd {
    /// File descriptor
    fd: u32,
    /// Requested events
    events: u16,
    /// Returned events
    revents: u16,
}

impl PollFd {
    /* fn get_inode(&self) -> OSInode {} */
}
pub fn poll(poll_fd: usize, nfds: usize, time_spec: usize) -> isize {
    ppoll(poll_fd, nfds, time_spec, 0)
}
pub fn ppoll(poll_fd_p: usize, nfds: usize, time_spec: usize, sigmask: usize) -> isize {
    /*the sigmask is so far ignored */
    /*support only POLLIN for currently*/
    let mut done: isize = 0;
    let mut no_abs: bool = true;
    let mut poll_fd: alloc::vec::Vec<PollFd> = alloc::vec::Vec::with_capacity(nfds);
    poll_fd.resize(
        nfds,
        PollFd {
            fd: 0,
            events: 0,
            revents: 0,
        },
    );
    //    println!("poll_fd:{:?}, Hi!", poll_fd);
    copy_from_user(&mut poll_fd[0], poll_fd_p, nfds * 8);
    //return 1;
    //poll_fd.len()
    let task = current_task().unwrap();
    let mut inner = task.acquire_inner_lock();
    if poll_fd.len() != 0 {
        loop {
            let mut i = 0;
            //
            while i != poll_fd.len() {
                let j = {
                    if poll_fd[i].fd as usize >= inner.fd_table.len()
                        || inner.fd_table[poll_fd[i].fd as usize].is_none()
                    {
                        None
                    } else {
                        /*should be "poll_fd[i].fd as usize"*/
                        Some(
                            inner.fd_table[poll_fd[i].fd as usize]
                                .as_ref()
                                .unwrap()
                                .clone(),
                        )
                    }
                };
                match j.unwrap().fclass {
                    super::FileClass::Abstr(file) => {
                        no_abs = false;
                        if (poll_fd[i].events as usize & POLLIN) != 0 && file.r_ready() {
                            poll_fd[i].revents = POLLIN as u16;
                            done = 1 + i as isize;
                            break;
                        }
                    }
                    super::FileClass::File(file) => {}
                };
                i += 1;
            }
            if no_abs || done != 0 {
                break done;
            }
        }
    } else {
        0
    }
}
