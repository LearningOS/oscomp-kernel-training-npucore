use crate::{fs::File, task::signal::Signals, timer::TimeSpec};
use alloc::vec::Vec;
use core::{
    cmp::max,
    ptr::{null, null_mut},
};
use k210_hal::cache::Uncache;
use lazy_static::__Deref;

use crate::{
    mm::{copy_from_user, translated_byte_buffer, translated_ref, translated_refmut},
    task::{current_task, sigprocmask, suspend_current_and_run_next, SIG_SETMASK},
    timer::TimeVal,
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
    ppoll(poll_fd, nfds, time_spec, None)
}
///
pub fn ppoll(poll_fd_p: usize, nfds: usize, time_spec: usize, sigmask: Option<Signals>) -> isize {
    /*the sigmask is so far ignored */
    /*support only POLLIN for currently*/
    let mut oldsig = Signals::empty();
    let mut has_mask = false;
    match sigmask {
        Some(_) => {
            has_mask = true;
            sigprocmask(SIG_SETMASK, sigmask, &mut oldsig as *mut Signals);
        }
        None => {}
    }
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
                if has_mask {
                    sigprocmask(SIG_SETMASK, Some(oldsig), null_mut::<Signals>());
                }
                break done;
            }
        }
    } else {
        0
    }
}
// This may be unsafe since the size of bits is undefined.
#[derive(Debug)]
#[repr(C)]
pub struct FdSet {
    bits: [u64; 16],
}
use crate::lang_items::Bytes;
impl FdSet {
    pub fn empty() -> Self {
        Self { bits: [0; 16] }
    }
    fn fd_elt(d: usize) -> usize {
        d >> 6
    }
    fn fd_mask(d: usize) -> u64 {
        1 << (d & 0x3F)
    }
    pub fn clr_all(&mut self) {
        for i in 0..16 {
            self.bits[i] = 0;
        }
    }
    pub fn get_fd_vec(&self) -> Vec<usize> {
        let mut v = Vec::new();
        for i in 0..1024 {
            if self.is_set(i) {
                v.push(i);
            }
        }
        v
    }
    pub fn set_num(&self) -> u32 {
        let mut sum: u32 = 0;
        for i in self.bits.iter() {
            sum += i.count_ones();
        }
        sum
    }
    pub fn set(&mut self, d: usize) {
        self.bits[Self::fd_elt(d)] |= Self::fd_mask(d);
    }
    pub fn clr(&mut self, d: usize) {
        self.bits[Self::fd_elt(d)] &= !Self::fd_mask(d);
    }
    pub fn is_set(&self, d: usize) -> bool {
        (Self::fd_mask(d) & self.bits[Self::fd_elt(d)]) != 0
    }
}
impl Bytes<FdSet> for FdSet {
    fn as_bytes(&self) -> &[u8] {
        let size = core::mem::size_of::<FdSet>();
        unsafe {
            core::slice::from_raw_parts(
                self as *const _ as *const FdSet as usize as *const u8,
                size,
            )
        }
    }

    fn as_bytes_mut(&mut self) -> &mut [u8] {
        let size = core::mem::size_of::<FdSet>();
        unsafe {
            core::slice::from_raw_parts_mut(self as *mut _ as *mut FdSet as usize as *mut u8, size)
        }
    }
}
/// Poll each of the file discriptors until certain events
///
/// # Arguments
///
/// * `nfds`: the highest-numbered file descriptor in any of the three sets
///
/// * `read_fds`: files to be watched to see if characters become available for reading
///
/// * `write_fds`: files to be watched to see if characters become available for writing
///
/// * `except_fds`: exceptional conditions
///
/// (For examples of some exceptional conditions, see the discussion of POLLPRI in [poll(2)].)
/// * `timeout`: argument specifies the interval that pselect() should block waiting for a file descriptor to become ready
///
/// * `sigmask`: the sigmask used by the process during the poll, as in ppoll  
///
/// # Return Value
///
/// * On success, select() and pselect() return the number of file descriptors  contained in the three returned descriptor sets (that is, the total number of bits that are set in  readfds, writefds,  exceptfds)  which  may be zero if the timeout expires before anything interesting happens.  
///
/// * On error, -1  is returned,  the file descriptor sets are unmodified, and  timeout  becomes  undefined.
pub fn pselect(
    nfds: usize,
    read_fds: Option<&mut FdSet>,
    write_fds: Option<&mut FdSet>,
    exception_fds: Option<&mut FdSet>,
    /*
    If both fields of the timeval structure are zero,
    then select() returns immediately.
    (This is useful for  polling.)
    If timeout is NULL (no timeout), select() can block indefinitely.
     */
    timeout: Option<&TimeSpec>,
    sigmask: Option<&Signals>,
) -> isize {
    /*
        // this piece of code should be in sys_pselect instead of being here.
        if max(exception_fds.len(), max(read_fds.len(), write_fds.len())) != nfds || nfds < 0 {
            return -1;
    }
     */
    let mut trg = crate::timer::TimeSpec::now();
    if let Some(_) = timeout {
        trg = *timeout.unwrap() + trg;
        log::warn!("[pselect] timeout {:?}", timeout.unwrap());
    }
    let mut done = false;
    let start = crate::timer::get_time_sec();
    let mut oldsig = Signals::empty();
    let mut has_mask = false;
    match sigmask {
        Some(_) => {
            has_mask = true;
            sigprocmask(
                SIG_SETMASK,
                Some(sigmask.unwrap().clone()),
                &mut oldsig as *mut Signals,
            );
        }
        None => {}
    }
    let mut ret = 0;
    let mut r_type = 0;
    loop {
        let task = current_task().unwrap();
        let inner = task.acquire_inner_lock();
        let fd_table = &inner.fd_table;
        for i in 0..nfds {
            macro_rules! do_chk {
                ($f:ident,$func:ident,$r:literal) => {
                    if $f.$func() {
                        done = true;
                        ret = i;
                        r_type = $r;
                        break;
                    }
                };
            }
            macro_rules! chk_fds {
                ($fds:ident,$func:ident,$r:literal) => {
                    if let Some(ref j) = $fds {
                        if j.is_set(i) {
                            if let Some(k) = fd_table[i].as_ref() {
                                match &k.fclass {
                                    super::FileClass::Abstr(file) => {
                                        do_chk!(file, $func, $r);
                                    }
                                    super::FileClass::File(file) => {
                                        do_chk!(file, $func, $r);
                                    }
                                }
                            } else {
                                return -1;
                            }
                        }
                    }
                };
            }
            chk_fds!(read_fds, r_ready, 1);
            chk_fds!(write_fds, w_ready, 2);
        }
        if done {
            log::warn!("fd {} is now ready.", ret);
            if let Some(i) = read_fds {
                *i = FdSet::empty();
                if r_type == 1 {
                    i.set(ret);
                }
            }
            if let Some(i) = write_fds {
                *i = FdSet::empty();
                if r_type == 2 {
                    i.set(ret);
                }
            }
            ret = 1;
            break;
        }
        ret = 0;
        match &timeout {
            None => {}
            Some(_) => {
                log::info!("{:?} to {:?}", trg, TimeSpec::now());
                if (trg - TimeSpec::now()).to_ns() == 0 {
                    break;
                }
            }
        }
        drop(inner);
        suspend_current_and_run_next();
    }

    if has_mask {
        sigprocmask(SIG_SETMASK, Some(oldsig), null_mut::<Signals>());
    }
    log::info!("[pselect] quiting pselect.");
    // look up according to TimeVal
    ret as isize
}

/*
[DEBUG] args[0]: 6 nfds
[DEBUG] args[1]: FFFFFFFFFFFFC948 read_fds
[DEBUG] args[2]: 0 write_fds
[DEBUG] args[3]: 0 except_fds
[DEBUG] args[4]: FFFFFFFFFFFFC8F8 timeout
[DEBUG] args[5]: 0 sigmask
*/

/*
The final argument of the pselect6() system call  is  not  a
sigset_t * pointer, but is instead a structure of the form:

struct {
    const kernel_sigset_t *ss;   /* Pointer to signal set */
    size_t ss_len;               /* Size (in bytes) of object pointed to by 'ss' */
           };

*/
