use crate::{
    fs::File,
    task::{current_user_token, signal::Signals},
    timer::TimeSpec,
};
use alloc::vec::Vec;
use core::ptr::{null, null_mut};

use crate::{
    mm::{copy_from_user_array, copy_to_user_array},
    task::{current_task, sigprocmask, suspend_current_and_run_next, SigMaskHow},
};

///  A scheduling  scheme  whereby  the  local  process  periodically  checks  until  the  pre-specified events (for example, read, write) have occurred.
/// The PollFd struct in 32-bit style.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PollFd {
    /// File descriptor
    fd: u32,
    /// Requested events
    events: PollEvent,
    /// Returned events
    revents: PollEvent,
}

bitflags! {
    struct PollEvent:u16 {
    /* Event types that can be polled for.  These bits may be set in `events'
    to indicate the interesting event types; they will appear in `revents'
    to indicate the status of the file descriptor.  */
    /// There is data to read.
    const POLLIN = 0x001;
    /// There is urgent data to read.
    const POLLPRI = 0x002;
    /// Writing now will not block.
    const POLLOUT = 0x004;

    // These values are defined in XPG4.2.
    /// Normal data may be read.
    const POLLRDNORM = 0x040;
    /// Priority data may be read.
    const POLLRDBAND = 0x080;
    /// Writing now will not block.
    const POLLWRNORM = 0x100;
    /// Priority data may be written.
    const POLLWRBAND = 0x200;


    /// Linux Extension.
    const POLLMSG = 0x400;
    /// Linux Extension.
    const POLLREMOVE = 0x1000;
    /// Linux Extension.
    const POLLRDHUP = 0x2000;

    /* Event types always implicitly polled for.
    These bits need not be set in `events',
    but they will appear in `revents' to indicate the status of the file descriptor.*/

    /// Implicitly polled for only.
    /// Error condition.
    const POLLERR = 0x008;
    /// Implicitly polled for only.
    /// Hung up.
    const POLLHUP = 0x010;
    /// Implicitly polled for only.
    /// Invalid polling request.
    const POLLNVAL = 0x020;
    }
}

impl PollFd {
    /* fn get_inode(&self) -> OSInode {} */
}
pub fn poll(poll_fd: usize, nfds: usize, time_spec: usize) -> isize {
    ppoll(poll_fd, nfds, time_spec, null::<Signals>())
}
///
pub fn ppoll(poll_fd_p: usize, nfds: usize, time_spec: usize, sigmask: *const Signals) -> isize {
    /*support only POLLIN for currently*/
    let oldsig = &mut Signals::empty();
    let mut has_mask = false;
    if sigmask as usize != 0 {
        has_mask = true;
        sigprocmask(SigMaskHow::SIG_SETMASK.bits(), sigmask, oldsig);
    }
    let mut done: isize = 0;
    let mut no_abs: bool = true;
    let mut poll_fd: alloc::vec::Vec<PollFd> = alloc::vec::Vec::with_capacity(nfds);
    poll_fd.resize(
        nfds,
        PollFd {
            fd: 0,
            events: PollEvent::empty(),
            revents: PollEvent::empty(),
        },
    );
    let token = current_user_token();
    //    println!("poll_fd:{:?}, Hi!", poll_fd);
    copy_from_user_array(
        token,
        poll_fd_p as *const PollFd,
        poll_fd.as_mut_ptr(),
        nfds,
    );
    //return 1;
    //poll_fd.len()
    log::info!("[ppoll] polling files:");
    for i in poll_fd.iter_mut() {
        i.revents = PollEvent::empty();
        log::info!("[ppoll] {:?}", i);
    }

    if poll_fd.len() != 0 {
        loop {
            let mut i = 0;
            let task = current_task().unwrap();
            let inner = task.acquire_inner_lock();
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
                match j.unwrap().file {
                    super::FileLike::Abstract(file) => {
                        no_abs = false;
                        if file.hang_up() {
                            poll_fd[i].revents |= PollEvent::POLLHUP;
                            done += 1 as isize;
                            break;
                        }
                        if (poll_fd[i].events.contains(PollEvent::POLLIN)) && file.r_ready() {
                            poll_fd[i].revents |= PollEvent::POLLIN;
                            //poll_fd[i].revents |= PollEvent::POLLHUP;
                            done += 1 as isize;
                            break;
                        }
                    }
                    super::FileLike::Regular(file) => {}
                };
                i += 1;
            }
            if no_abs || done != 0 {
                if has_mask {
                    sigprocmask(
                        SigMaskHow::SIG_SETMASK.bits(),
                        oldsig,
                        null_mut::<Signals>(),
                    );
                }
                break done;
            } else {
                copy_to_user_array(token, &poll_fd[0], poll_fd_p as *mut PollFd, nfds);
                drop(inner);
                drop(task);
                suspend_current_and_run_next();
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
    sigmask: *const Signals,
) -> isize {
    /*
        // this piece of code should be in sys_pselect instead of being here.
        if max(exception_fds.len(), max(read_fds.len(), write_fds.len())) != nfds || nfds < 0 {
            return -1;
    }
     */
    let mut trg = crate::timer::TimeSpec::now();
    log::warn!("[pselect] Hi!");
    if let Some(_) = timeout {
        trg = *timeout.unwrap() + trg;
        log::warn!("[pselect] timeout {:?}", timeout.unwrap());
    }
    let mut done = false;
    let start = crate::timer::get_time_sec();
    let oldsig = &mut Signals::empty();
    let mut has_mask = false;
    if sigmask as usize != 0 {
        has_mask = true;
        sigprocmask(SigMaskHow::SIG_SETMASK.bits(), sigmask, oldsig);
    }
    let mut ret = 2048;
    loop {
        let task = current_task().unwrap();
        let inner = task.acquire_inner_lock();
        let fd_table = &inner.fd_table;
        ret = 2048;
        macro_rules! do_chk {
            ($f:ident,$func:ident,$fds:ident,$i:ident) => {
                if !$f.$func() {
                    ret = 0;
                    break;
                }
            };
        }
        macro_rules! chk_fds {
            ($fds:ident,$func:ident,$chk_func:ident,$($ref_info:ident)?) => {
                if let Some($($ref_info)? j) = $fds {
                    for i in 0..nfds {
                        if j.is_set(i) {
                            //log::warn!("[myselect] i:{}", i);
                            if let Some(k) = fd_table[i].as_ref() {
                                match &k.file {
                                    super::FileLike::Abstract(file) => {
                                        $chk_func!(file, $func,j,i);
                                    }
                                    super::FileLike::Regular(file) => {
                                        $chk_func!(file, $func,j,i);
                                    }
                                }
                            } else {
                                log::error!("[myselect] quiting with -1!");
                                return -1;
                            }
                        }
                    }
                }
            };
        }
        chk_fds!(read_fds, r_ready, do_chk, ref);
        chk_fds!(write_fds, w_ready, do_chk, ref);
        if ret == 2048 {
            //The SUPPORTED fds are all ready since the ret was NOT assigned.
            ret = 0;
            log::warn!("fds are all ready now.");
            ret += if let Some(ref i) = read_fds {
                i.set_num()
            } else {
                0
            };
            ret += if let Some(ref i) = write_fds {
                i.set_num()
            } else {
                0
            };
            // 我们曾把exception赋值放在这里,但当时
            // 似乎有个race:要么
            // 另外,这里if let 不加ref会导致move, 不知道有没有更好的办法不ref也不move却能
            break;
        }
        ret = 0;
        match &timeout {
            None => {}
            Some(_) => {
                //log::trace!("{:?} to {:?}", trg, TimeSpec::now());
                if (trg - TimeSpec::now()).to_ns() == 0 {
                    ret = 0;
                    macro_rules! do_chk_end {
                        ($f:ident,$func:ident,$fds:ident,$i:ident) => {
                            if !$f.$func() {
                                $fds.clr($i);
                            }
                        };
                    }
                    chk_fds!(read_fds, r_ready, do_chk_end,);
                    chk_fds!(write_fds, w_ready, do_chk_end,);
                    break;
                }
            }
        }
        // There SHOULD be ORDER REQ. for dropping?!
        drop(fd_table);
        drop(inner);
        drop(task);
        suspend_current_and_run_next();
    }
    // 这个问题: 由于exception_fds检查未支持,必须在最后
    if exception_fds.is_some() {
        match &timeout {
            Some(_) => {
                if let Some(i) = exception_fds {
                    *i = FdSet::empty();
                }
                loop {
                    if (trg - TimeSpec::now()).to_ns() == 0 {
                        break;
                    } else {
                        suspend_current_and_run_next();
                    }
                }
            }
            None => loop {},
        }
    }
    if has_mask {
        sigprocmask(
            SigMaskHow::SIG_SETMASK.bits(),
            oldsig,
            null_mut::<Signals>(),
        );
    }
    log::warn!("[pselect] quiting pselect. {}", ret);
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
 */
