use core::borrow::Borrow;
use core::borrow::BorrowMut;
use core::fmt::{self, Debug, Formatter};
use core::mem::ManuallyDrop;
use core::str::FromStr;

use super::signal::*;
use super::TaskContext;
use super::{pid_alloc, KernelStack, PidHandle};
use crate::config::*;
use crate::errno_exit;
use crate::fs::{FileDescriptor, FileLike, Stdin, Stdout};
use crate::mm::VirtPageNum;
use crate::mm::{translated_refmut, MapPermission, MemorySet, PhysPageNum, VirtAddr, KERNEL_SPACE};
use crate::task::current_task;
use crate::timer::{ITimerVal, TimeVal};
use crate::trap::{trap_handler, TrapContext};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use lazy_static::__Deref;
use log::{debug, error, info, trace, warn};
use riscv::register::scause::{self, Exception, Interrupt, Trap};
use spin::{Mutex, MutexGuard};

pub struct TaskControlBlock {
    // immutable
    pub pid: PidHandle,
    pub kernel_stack: KernelStack,
    // mutable
    inner: Mutex<TaskControlBlockInner>,
}

pub type FdTable = Vec<Option<FileDescriptor>>;
pub struct TaskControlBlockInner {
    pub sigmask: Signals,
    pub trap_cx_ppn: PhysPageNum,
    pub base_size: usize,
    pub task_cx_ptr: usize,
    pub task_status: TaskStatus,
    pub memory_set: MemorySet,
    pub parent: Option<Weak<TaskControlBlock>>,
    pub children: Vec<Arc<TaskControlBlock>>,
    pub exit_code: i32,
    pub fd_table: FdTable,
    pub address: ProcAddress,
    pub heap_bottom: usize,
    pub heap_pt: usize,
    pub current_path: String,
    pub siginfo: SigInfo,
    pub pgid: usize,
    pub rusage: Rusage,
    pub clock: ProcClock,
    pub timer: [ITimerVal; 3],
}

pub struct ProcClock {
    last_enter_u_mode: TimeVal,
    last_enter_s_mode: TimeVal,
}

impl ProcClock {
    pub fn new() -> Self {
        let now = TimeVal::now();
        Self {
            last_enter_u_mode: now,
            last_enter_s_mode: now,
        }
    }
}

#[derive(Clone, Copy)]
pub struct Rusage {
    ru_utime: TimeVal,  /* user CPU time used */
    ru_stime: TimeVal,  /* system CPU time used */
    ru_maxrss: isize,   // NOT IMPLEMENTED /* maximum resident set size */
    ru_ixrss: isize,    // NOT IMPLEMENTED /* integral shared memory size */
    ru_idrss: isize,    // NOT IMPLEMENTED /* integral unshared data size */
    ru_isrss: isize,    // NOT IMPLEMENTED /* integral unshared stack size */
    ru_minflt: isize,   // NOT IMPLEMENTED /* page reclaims (soft page faults) */
    ru_majflt: isize,   // NOT IMPLEMENTED /* page faults (hard page faults) */
    ru_nswap: isize,    // NOT IMPLEMENTED /* swaps */
    ru_inblock: isize,  // NOT IMPLEMENTED /* block input operations */
    ru_oublock: isize,  // NOT IMPLEMENTED /* block output operations */
    ru_msgsnd: isize,   // NOT IMPLEMENTED /* IPC messages sent */
    ru_msgrcv: isize,   // NOT IMPLEMENTED /* IPC messages received */
    ru_nsignals: isize, // NOT IMPLEMENTED /* signals received */
    ru_nvcsw: isize,    // NOT IMPLEMENTED /* voluntary context switches */
    ru_nivcsw: isize,   // NOT IMPLEMENTED /* involuntary context switches */
}

impl Rusage {
    pub fn new() -> Self {
        Self {
            ru_utime: TimeVal::new(),
            ru_stime: TimeVal::new(),
            ru_maxrss: 0,
            ru_ixrss: 0,
            ru_idrss: 0,
            ru_isrss: 0,
            ru_minflt: 0,
            ru_majflt: 0,
            ru_nswap: 0,
            ru_inblock: 0,
            ru_oublock: 0,
            ru_msgsnd: 0,
            ru_msgrcv: 0,
            ru_nsignals: 0,
            ru_nvcsw: 0,
            ru_nivcsw: 0,
        }
    }
}

impl Debug for Rusage {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "(ru_utime:{:?}, ru_stime:{:?})",
            self.ru_utime, self.ru_stime
        ))
    }
}

impl TaskControlBlockInner {
    pub fn get_task_cx_ptr2(&self) -> *const usize {
        &self.task_cx_ptr as *const usize
    }
    pub fn get_trap_cx(&self) -> &'static mut TrapContext {
        self.trap_cx_ppn.get_mut()
    }
    pub fn get_user_token(&self) -> usize {
        self.memory_set.token()
    }
    fn get_status(&self) -> TaskStatus {
        self.task_status
    }
    pub fn is_zombie(&self) -> bool {
        self.get_status() == TaskStatus::Zombie
    }
    pub fn alloc_fd(&mut self) -> usize {
        if let Some(fd) = (0..self.fd_table.len()).find(|fd| self.fd_table[*fd].is_none()) {
            fd
        } else {
            self.fd_table.push(None);
            self.fd_table.len() - 1
        }
    }
    pub fn get_work_path(&self) -> String {
        self.current_path.clone()
    }
    pub fn add_signal(&mut self, signal: Signals) {
        self.siginfo.signal_pending.insert(signal);
    }
    pub fn update_process_times_enter_trap(&mut self) {
        let now = TimeVal::now();
        self.clock.last_enter_s_mode = now;
        let diff = now - self.clock.last_enter_u_mode;
        self.rusage.ru_utime = self.rusage.ru_utime + diff;
        self.update_itimer_virtual_if_exists(diff);
        self.update_itimer_prof_if_exists(diff);
    }
    pub fn update_process_times_leave_trap(&mut self, scause: Trap) {
        let now = TimeVal::now();
        self.update_itimer_real_if_exists(now - self.clock.last_enter_u_mode);
        if scause != Trap::Interrupt(Interrupt::SupervisorTimer) {
            let diff = now - self.clock.last_enter_s_mode;
            self.rusage.ru_stime = self.rusage.ru_stime + diff;
            self.update_itimer_prof_if_exists(diff);
        }
        self.clock.last_enter_u_mode = now;
    }
    pub fn update_itimer_real_if_exists(&mut self, diff: TimeVal) {
        if !self.timer[0].it_value.is_zero() {
            self.timer[0].it_value = self.timer[0].it_value - diff;
            if self.timer[0].it_value.is_zero() {
                self.add_signal(Signals::SIGALRM);
                self.timer[0].it_value = self.timer[0].it_interval;
            }
        }
    }
    pub fn update_itimer_virtual_if_exists(&mut self, diff: TimeVal) {
        if !self.timer[1].it_value.is_zero() {
            self.timer[1].it_value = self.timer[1].it_value - diff;
            if self.timer[1].it_value.is_zero() {
                self.add_signal(Signals::SIGVTALRM);
                self.timer[1].it_value = self.timer[1].it_interval;
            }
        }
    }
    pub fn update_itimer_prof_if_exists(&mut self, diff: TimeVal) {
        if !self.timer[2].it_value.is_zero() {
            self.timer[2].it_value = self.timer[2].it_value - diff;
            if self.timer[2].it_value.is_zero() {
                self.add_signal(Signals::SIGPROF);
                self.timer[2].it_value = self.timer[2].it_interval;
            }
        }
    }
}

impl TaskControlBlock {
    pub(in crate::task) fn find_child_process_by_pgid(
        &self,
        pgid: usize,
    ) -> Vec<Arc<TaskControlBlock>> {
        let mut v = Vec::new();
        let mut inc: Vec<Arc<TaskControlBlock>>;
        let task = self.acquire_inner_lock();
        for i in &task.children {
            if i.getpgid() == pgid {
                v.push(i.clone());
            } else {
                inc = i.find_child_process_by_pgid(pgid);
                v.append(&mut inc);
            }
        }
        v
    }
    pub(in crate::task) fn find_child_process_by_pid(
        &self,
        pid: usize,
    ) -> Option<Arc<TaskControlBlock>> {
        let mut ret = None;
        let task = self.acquire_inner_lock();
        for i in &task.children {
            if i.getpid() == pid {
                return Some(i.clone());
            } else {
                ret = i.find_child_process_by_pid(pid);
                match ret {
                    None => {}
                    _ => {
                        return ret;
                    }
                }
            }
        }
        ret
    }
    pub fn acquire_inner_lock(&self) -> MutexGuard<TaskControlBlockInner> {
        self.inner.lock()
    }
    pub fn new(elf_data: &[u8]) -> Self {
        // memory_set with elf program headers/trampoline/trap context/user stack
        let (memory_set, user_sp, user_heap, entry_point, auxv) = MemorySet::from_elf(elf_data);

        crate::mm::KERNEL_SPACE
            .lock()
            .remove_area_with_start_vpn(VirtAddr::from(elf_data.as_ptr() as usize).floor());
        let trap_cx_ppn = memory_set
            .translate(VirtAddr::from(TRAP_CONTEXT).into())
            .unwrap()
            .ppn();
        // alloc a pid and a kernel stack in kernel space
        let pid_handle = pid_alloc();
        let pgid = pid_handle.0;
        let kernel_stack = KernelStack::new(&pid_handle);
        let kernel_stack_top = kernel_stack.get_top();
        // push a task context which goes to trap_return to the top of kernel stack
        let task_cx_ptr = kernel_stack.push_on_top(TaskContext::goto_trap_return());
        let task_control_block = Self {
            pid: pid_handle,
            kernel_stack,
            inner: Mutex::new(TaskControlBlockInner {
                trap_cx_ppn,
                pgid,
                sigmask: Signals::empty(),
                base_size: user_sp,
                task_cx_ptr: task_cx_ptr as usize,
                task_status: TaskStatus::Ready,
                memory_set,
                parent: None,
                children: Vec::new(),
                exit_code: 0,
                fd_table: vec![
                    // 0 -> stdin
                    Some(FileDescriptor::new(
                        false,
                        FileLike::Abstract(Arc::new(Stdin)),
                    )),
                    // 1 -> stdout
                    Some(FileDescriptor::new(
                        false,
                        FileLike::Abstract(Arc::new(Stdout)),
                    )),
                    // 2 -> stderr
                    Some(FileDescriptor::new(
                        false,
                        FileLike::Abstract(Arc::new(Stdout)),
                    )),
                ],
                address: ProcAddress::new(),
                heap_bottom: user_heap,
                heap_pt: user_heap,
                current_path: String::from("/"),
                siginfo: SigInfo::new(),
                rusage: Rusage::new(),
                clock: ProcClock::new(),
                timer: [ITimerVal::new(); 3],
            }),
        };
        // prepare TrapContext in user space
        let trap_cx = task_control_block.acquire_inner_lock().get_trap_cx();
        *trap_cx = TrapContext::app_init_context(
            entry_point,
            user_sp,
            KERNEL_SPACE.lock().token(),
            kernel_stack_top,
            trap_handler as usize,
        );
        task_control_block
    }
    pub fn exec(&self, elf_data: &[u8], args: Vec<String>) {
        // memory_set with elf program headers/trampoline/trap context/user stack
        debug!("args.len():{}", args.len());
        let (memory_set, mut user_sp, user_heap, entry_point, mut auxv) =
            MemorySet::from_elf(elf_data);
        info!(
            "[exec] elf_data LOADED. user_sp:{:X}; user_heap:{:X}; entry_point:{:X}",
            user_sp, user_heap, entry_point
        );
        crate::mm::KERNEL_SPACE
            .lock()
            .remove_area_with_start_vpn(VirtAddr::from(elf_data.as_ptr() as usize).floor());
        let trap_cx_ppn = memory_set
            .translate(VirtAddr::from(TRAP_CONTEXT).into())
            .unwrap()
            .ppn();

        ////////////// envp[] ///////////////////
        let mut env: Vec<String> = Vec::new();
        env.push(String::from("SHELL=/user_shell"));
        env.push(String::from("PWD=/"));
        env.push(String::from("USER=root"));
        env.push(String::from("MOTD_SHOWN=pam"));
        env.push(String::from("LANG=C.UTF-8"));
        env.push(String::from(
            "INVOCATION_ID=e9500a871cf044d9886a157f53826684",
        ));
        env.push(String::from("TERM=vt220"));
        env.push(String::from("SHLVL=2"));
        env.push(String::from("JOURNAL_STREAM=8:9265"));
        env.push(String::from("OLDPWD=/root"));
        env.push(String::from("_=busybox"));
        env.push(String::from("LOGNAME=root"));
        env.push(String::from("HOME=/"));
        env.push(String::from("PATH=/"));
        let mut envp: Vec<usize> = (0..=env.len()).collect();
        envp[env.len()] = 0;
        for i in 0..env.len() {
            user_sp -= env[i].len() + 1;
            envp[i] = user_sp;
            let mut p = user_sp;
            // write chars to [user_sp, user_sp + len]
            for c in env[i].as_bytes() {
                *translated_refmut(memory_set.token(), p as *mut u8) = *c;
                p += 1;
            }
            *translated_refmut(memory_set.token(), p as *mut u8) = 0;
        }
        // make the user_sp aligned to 8B for k210 platform
        user_sp -= user_sp % core::mem::size_of::<usize>();

        // push arguments on user stack
        let mut argv: Vec<_> = (0..=args.len()).collect();
        argv[args.len()] = 0;
        for i in 0..args.len() {
            user_sp -= args[i].len() + 1;
            argv[i] = user_sp;
            let mut p = user_sp;
            for c in args[i].as_bytes() {
                *translated_refmut(memory_set.token(), p as *mut u8) = *c;
                p += 1;
            }
            *translated_refmut(memory_set.token(), p as *mut u8) = 0;
        }
        // make the user_sp aligned to 8B for k210 platform
        user_sp -= user_sp % core::mem::size_of::<usize>();

        ////////////// platform String ///////////////////
        let platform = "RISC-V64";
        user_sp -= platform.len() + 1;
        user_sp -= user_sp % core::mem::size_of::<usize>();
        let mut p = user_sp;
        for c in platform.as_bytes() {
            *translated_refmut(memory_set.token(), p as *mut u8) = *c;
            p += 1;
        }
        *translated_refmut(memory_set.token(), p as *mut u8) = 0;

        ////////////// rand bytes ///////////////////
        user_sp -= 16;
        p = user_sp;
        auxv.push(AuxHeader {
            aux_type: AT_RANDOM,
            value: user_sp,
        });
        for i in 0..0xf {
            *translated_refmut(memory_set.token(), p as *mut u8) = i as u8;
            p += 1;
        }

        ////////////// padding //////////////////////
        user_sp -= user_sp % 16;

        ////////////// auxv[] //////////////////////
        auxv.push(AuxHeader {
            aux_type: AT_EXECFN,
            value: argv[0],
        }); // file name
        auxv.push(AuxHeader {
            aux_type: AT_NULL,
            value: 0,
        }); // end
        user_sp -= auxv.len() * core::mem::size_of::<AuxHeader>();
        let auxv_base = user_sp;
        // println!("[auxv]: base 0x{:X}", auxv_base);
        for i in 0..auxv.len() {
            // println!("[auxv]: {:?}", auxv[i]);
            let addr = user_sp + core::mem::size_of::<AuxHeader>() * i;
            *translated_refmut(memory_set.token(), addr as *mut usize) = auxv[i].aux_type;
            *translated_refmut(
                memory_set.token(),
                (addr + core::mem::size_of::<usize>()) as *mut usize,
            ) = auxv[i].value;
        }

        ////////////// *envp [] //////////////////////
        user_sp -= (env.len() + 1) * core::mem::size_of::<usize>();
        let envp_base = user_sp;
        *translated_refmut(
            memory_set.token(),
            (user_sp + core::mem::size_of::<usize>() * (env.len())) as *mut usize,
        ) = 0;
        for i in 0..env.len() {
            *translated_refmut(
                memory_set.token(),
                (user_sp + core::mem::size_of::<usize>() * i) as *mut usize,
            ) = envp[i];
        }

        ////////////// *argv [] //////////////////////
        user_sp -= (args.len() + 1) * core::mem::size_of::<usize>();
        let argv_base = user_sp;
        *translated_refmut(
            memory_set.token(),
            (user_sp + core::mem::size_of::<usize>() * (args.len())) as *mut usize,
        ) = 0;
        for i in 0..args.len() {
            *translated_refmut(
                memory_set.token(),
                (user_sp + core::mem::size_of::<usize>() * i) as *mut usize,
            ) = argv[i];
        }

        ////////////// argc //////////////////////
        user_sp -= core::mem::size_of::<usize>();
        *translated_refmut(memory_set.token(), user_sp as *mut usize) = args.len();

        // **** hold current PCB lock
        let mut inner = self.acquire_inner_lock();
        // substitute memory_set
        inner.memory_set = memory_set;
        inner.heap_bottom = user_heap;
        inner.heap_pt = user_heap;
        // flush signal handler
        inner.siginfo.signal_handler = BTreeMap::new();
        // update trap_cx ppn
        inner.trap_cx_ppn = trap_cx_ppn;
        // initialize trap_cx
        let mut trap_cx = TrapContext::app_init_context(
            entry_point,
            user_sp,
            KERNEL_SPACE.lock().token(),
            self.kernel_stack.get_top(),
            trap_handler as usize,
        );
        trap_cx.x[10] = args.len();
        trap_cx.x[11] = argv_base;
        trap_cx.x[12] = envp_base;
        trap_cx.x[13] = auxv_base;
        *inner.get_trap_cx() = trap_cx;
        // **** release current PCB lock
    }
    pub fn fork(self: &Arc<TaskControlBlock>) -> Arc<TaskControlBlock> {
        // ---- hold parent PCB lock
        let mut parent_inner = self.acquire_inner_lock();
        // copy user space(include trap context)
        let memory_set = MemorySet::from_existed_user(&mut parent_inner.memory_set);
        let trap_cx_ppn = memory_set
            .translate(VirtAddr::from(TRAP_CONTEXT).into())
            .unwrap()
            .ppn();
        // alloc a pid and a kernel stack in kernel space
        let pid_handle = pid_alloc();
        let kernel_stack = KernelStack::new(&pid_handle);
        let kernel_stack_top = kernel_stack.get_top();
        // push a goto_trap_return task_cx on the top of kernel stack
        let task_cx_ptr = kernel_stack.push_on_top(TaskContext::goto_trap_return());
        // copy fd table
        let mut new_fd_table: FdTable = Vec::new();
        for fd in parent_inner.fd_table.iter() {
            if let Some(file) = fd {
                new_fd_table.push(Some(file.clone()));
            } else {
                new_fd_table.push(None);
            }
        }
        let task_control_block = Arc::new(TaskControlBlock {
            pid: pid_handle,
            kernel_stack,
            inner: Mutex::new(TaskControlBlockInner {
                trap_cx_ppn,
                pgid: parent_inner.pgid,
                base_size: parent_inner.base_size,
                task_cx_ptr: task_cx_ptr as usize,
                task_status: TaskStatus::Ready,
                memory_set,
                parent: Some(Arc::downgrade(self)),
                children: Vec::new(),
                exit_code: 0,
                fd_table: new_fd_table,
                address: ProcAddress::new(),
                heap_bottom: parent_inner.heap_bottom,
                heap_pt: parent_inner.heap_pt,
                current_path: parent_inner.current_path.clone(),
                sigmask: Signals::empty(),
                siginfo: parent_inner.siginfo.clone(),
                rusage: Rusage::new(),
                clock: ProcClock::new(),
                timer: [ITimerVal::new(); 3],
            }),
        });
        // add child
        parent_inner.children.push(task_control_block.clone());
        // modify kernel_sp in trap_cx
        // **** acquire child PCB lock
        let trap_cx = task_control_block.acquire_inner_lock().get_trap_cx();
        // **** release child PCB lock
        trap_cx.kernel_sp = kernel_stack_top;
        // return
        task_control_block
        // ---- release parent PCB lock
    }
    pub fn getpid(&self) -> usize {
        self.pid.0
    }
    pub fn setpgid(&self, pgid: usize) -> isize {
        if pgid < 0 {
            return -1;
        }
        let mut inner = self.acquire_inner_lock();
        inner.pgid = pgid;
        0
        //Temporarily suspend. Because the type of 'self' is 'Arc', which can't be borrow as mutable.
    }
    pub fn getpgid(&self) -> usize {
        let inner = self.acquire_inner_lock();
        inner.pgid
    }
}

pub fn exec(path: String, mut args_vec: Vec<String>) -> isize {
    let task = super::current_task().unwrap();
    let mut inner = task.acquire_inner_lock();
    if let Some(app_inode) = crate::fs::open(
        inner.get_work_path().as_str(),
        path.as_str(),
        crate::fs::OpenFlags::RDONLY,
        crate::fs::DiskInodeType::File,
    ) {
        drop(inner);
        let len = app_inode.get_size();
        debug!("[exec] File size: {} bytes", len);
        let start: usize = MMAP_BASE;
        let before_read = crate::mm::unallocated_frames();
        crate::mm::KERNEL_SPACE.lock().insert_framed_area(
            start.into(),
            (start + len).into(),
            MapPermission::R | MapPermission::W,
        );
        unsafe {
            app_inode.read_into(&mut core::slice::from_raw_parts_mut(start as *mut u8, len));
        }
        let after_read = crate::mm::unallocated_frames();

        // return argc because cx.x[10] will be covered with it later
        debug!(
            "[exec] read_all() DONE. consumed frames:{}, last frames:{}",
            before_read - after_read,
            after_read
        );
        let task = current_task().unwrap();
        let argc = args_vec.len();
        info!("[exec] argc = {}", argc);
        let before_exec = crate::mm::unallocated_frames();
        unsafe {
            let buffer = core::slice::from_raw_parts(start as *const u8, len);
            if buffer[0..4] == [0x7f, 0x45, 0x4c, 0x46] {
                task.exec(buffer, args_vec);
            } else {
                macro_rules! unmap_exec_buf {
                    () => {
                        crate::mm::KERNEL_SPACE.lock().remove_area_with_start_vpn(
                            crate::mm::VirtAddr::from(buffer.as_ptr() as usize).floor(),
                        );
                    };
                }
                //Problem 0: Zero Init. Exec Attempt: Use `busybox sh` as `default` while achieving the following purposes.
                //Problem 1: Recursion Redirection Problem: what if the #! gives an X that is NOT a binary.
                //problem 2: Invalid Redirection Problem: what if the #! gives an invalid binary? If you redirect it to `busybox sh` directly, will it be an infinitive recursion?
                let is_script: bool = buffer[0..2] == ['#' as u8, '!' as u8] || true;
                if is_script {
                    let last = buffer[0..1024.min(buffer.len())]
                        .iter()
                        .position(|&r| ['\n' as u8, '\0' as u8, 0].contains(&(r)));
                    /* let path_bin: if let Ok(v) str::from_utf8(buffer[0..last]){
                     *
                     * }else{
                     * 	errno_exit!(ENOEXEC);
                     * }; */
                    let mut path_bin = String::from("/bin/sh");
                    if path_bin == ("/bin/sh") {
                        path_bin = String::from("busybox");
                        args_vec.insert(0, String::from("sh"));
                        args_vec.insert(0, path);
                    }
                    unmap_exec_buf!();
                    return exec(path_bin, args_vec);
                } else {
                    unmap_exec_buf!();
                    -1;
                }
                //return crate::syscall::errno::ENOEXEC;
            }
            //}
        }
        let after_exec = crate::mm::unallocated_frames();
        debug!(
            "[exec] exec() DONE. consumed frames:{}, last frames:{}",
            (before_exec - after_exec) as isize,
            after_exec
        );
        // on success, we should not return.
        let ret = super::current_trap_cx().x[10];
        ret as isize
    } else {
        -1
    }
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum TaskStatus {
    Ready,
    Running,
    Zombie,
    Sleep,
    Stop,
}

pub struct ProcAddress {
    pub set_child_tid: usize,
    pub clear_child_tid: usize,
}

impl ProcAddress {
    pub fn new() -> Self {
        Self {
            set_child_tid: 0,
            clear_child_tid: 0,
        }
    }
}

pub struct AuxHeader {
    pub aux_type: usize,
    pub value: usize,
}
