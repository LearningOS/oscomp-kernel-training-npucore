use super::signal::*;
use super::AuxvEntry;
use super::AuxvType;
use super::TaskContext;
use super::{pid_alloc, KernelStack, PidHandle};
use crate::fs::FileDescriptor;
use crate::fs::OpenFlags;
use crate::fs::ROOT_FD;
use crate::mm::PageTable;
use crate::mm::{MemorySet, PhysPageNum, VirtAddr, KERNEL_SPACE};
use crate::syscall::errno::*;
use crate::syscall::CloneFlags;
use crate::task::current_task;
use crate::timer::TICKS_PER_SEC;
use crate::timer::{ITimerVal, TimeVal};
use crate::trap::{trap_handler, TrapContext};
use crate::{config::*, show_frame_consumption};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::{self, Debug, Formatter};
use log::{debug, error, info, trace, warn};
use riscv::register::scause::{Interrupt, Trap};
use spin::{Mutex, MutexGuard};

#[derive(Clone)]
pub struct FsStatus {
    pub working_inode: Arc<FileDescriptor>,
}

pub struct TaskControlBlock {
    // immutable
    pub pid: PidHandle,
    pub kernel_stack: KernelStack,
    // mutable
    inner: Mutex<TaskControlBlockInner>,
    // shareable and mutable
    pub files: Arc<Mutex<FdTable>>,
    pub fs: Arc<Mutex<FsStatus>>,
    pub vm: Arc<Mutex<MemorySet>>,
    pub sighand: Arc<Mutex<BTreeMap<Signals, SigAction>>>,
}

pub type FdTable = Vec<Option<FileDescriptor>>;
pub struct TaskControlBlockInner {
    pub sigmask: Signals,
    pub sigpending: Signals,
    pub trap_cx_ppn: PhysPageNum,
    pub base_size: usize,
    pub task_cx_ptr: usize,
    pub task_status: TaskStatus,
    pub parent: Option<Weak<TaskControlBlock>>,
    pub children: Vec<Arc<TaskControlBlock>>,
    pub exit_code: u32,
    pub address: ProcAddress,
    pub heap_bottom: usize,
    pub heap_pt: usize,
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

#[allow(unused)]
#[derive(Clone, Copy)]
pub struct Rusage {
    pub ru_utime: TimeVal, /* user CPU time used */
    pub ru_stime: TimeVal, /* system CPU time used */
    ru_maxrss: isize,      // NOT IMPLEMENTED /* maximum resident set size */
    ru_ixrss: isize,       // NOT IMPLEMENTED /* integral shared memory size */
    ru_idrss: isize,       // NOT IMPLEMENTED /* integral unshared data size */
    ru_isrss: isize,       // NOT IMPLEMENTED /* integral unshared stack size */
    ru_minflt: isize,      // NOT IMPLEMENTED /* page reclaims (soft page faults) */
    ru_majflt: isize,      // NOT IMPLEMENTED /* page faults (hard page faults) */
    ru_nswap: isize,       // NOT IMPLEMENTED /* swaps */
    ru_inblock: isize,     // NOT IMPLEMENTED /* block input operations */
    ru_oublock: isize,     // NOT IMPLEMENTED /* block output operations */
    ru_msgsnd: isize,      // NOT IMPLEMENTED /* IPC messages sent */
    ru_msgrcv: isize,      // NOT IMPLEMENTED /* IPC messages received */
    ru_nsignals: isize,    // NOT IMPLEMENTED /* signals received */
    ru_nvcsw: isize,       // NOT IMPLEMENTED /* voluntary context switches */
    ru_nivcsw: isize,      // NOT IMPLEMENTED /* involuntary context switches */
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
    fn get_status(&self) -> TaskStatus {
        self.task_status
    }
    pub fn is_zombie(&self) -> bool {
        self.get_status() == TaskStatus::Zombie
    }
    pub fn add_signal(&mut self, signal: Signals) {
        self.sigpending.insert(signal);
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
    pub fn acquire_inner_lock(&self) -> MutexGuard<TaskControlBlockInner> {
        self.inner.lock()
    }
    /// !!!!!!!!!!!!!!!!WARNING!!!!!!!!!!!!!!!!!!!!!
    /// Currently used for initproc loading only. bin_path must be used changed if used elsewhere.
    pub fn new(elf_data: &[u8]) -> Self {
        // memory_set with elf program headers/trampoline/trap context/user stack
        let (memory_set, user_sp, user_heap, elf_info) = MemorySet::from_elf(elf_data).unwrap();

        crate::mm::KERNEL_SPACE
            .lock()
            .remove_area_with_start_vpn(VirtAddr::from(elf_data.as_ptr() as usize).floor())
            .unwrap();
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
            files: Arc::new(Mutex::new(vec![
                // 0 -> stdin
                Some(ROOT_FD.open("/dev/tty", OpenFlags::O_RDWR, false).unwrap()),
                // 1 -> stdout
                Some(ROOT_FD.open("/dev/tty", OpenFlags::O_RDWR, false).unwrap()),
                // 2 -> stderr
                Some(ROOT_FD.open("/dev/tty", OpenFlags::O_RDWR, false).unwrap()),
            ])),
            fs: Arc::new(Mutex::new(FsStatus {
                working_inode: Arc::new(ROOT_FD.open(".", OpenFlags::O_RDONLY | OpenFlags::O_DIRECTORY, true).unwrap()),
            })),
            vm: Arc::new(Mutex::new(memory_set)),
            sighand: Arc::new(Mutex::new(BTreeMap::new())),
            inner: Mutex::new(TaskControlBlockInner {
                trap_cx_ppn,
                pgid,
                sigmask: Signals::empty(),
                sigpending: Signals::empty(),
                base_size: user_sp,
                task_cx_ptr: task_cx_ptr as usize,
                task_status: TaskStatus::Ready,
                parent: None,
                children: Vec::new(),
                exit_code: 0,
                address: ProcAddress::new(),
                heap_bottom: user_heap,
                heap_pt: user_heap,
                rusage: Rusage::new(),
                clock: ProcClock::new(),
                timer: [ITimerVal::new(); 3],
            }),
        };
        // prepare TrapContext in user space
        let trap_cx = task_control_block.acquire_inner_lock().get_trap_cx();
        *trap_cx = TrapContext::app_init_context(
            elf_info.entry,
            user_sp,
            KERNEL_SPACE.lock().token(),
            kernel_stack_top,
            trap_handler as usize,
        );
        task_control_block
    }

    pub fn load_elf(
        &self,
        elf_data: &[u8],
        argv_vec: &Vec<String>,
        envp_vec: &Vec<String>,
    ) -> Result<(), isize> {
        // memory_set with elf program headers/trampoline/trap context/user stack
        let (memory_set, mut user_sp, program_break, elf_info) = MemorySet::from_elf(elf_data)?;
        let token = (&memory_set).token();

        // go down to the stack page (important!) and align
        user_sp -= 2 * core::mem::size_of::<usize>();

        // because size of parameters is almost never more than PAGE_SIZE,
        // so I decide to use physical address directly for better performance
        let mut phys_user_sp = PageTable::from_token(token)
            .translate_va(VirtAddr::from(user_sp))
            .unwrap()
            .0;
        // we can add this to a phys addr to get corresponding virt addr
        let virt_phys_offset = user_sp - phys_user_sp;
        let phys_start = phys_user_sp;

        // unsafe code is efficient code! here we go!
        fn copy_to_user_string_unchecked(src: &str, dst: *mut u8) {
            let size = src.len();
            unsafe {
                core::slice::from_raw_parts_mut(dst, size)
                    .copy_from_slice(core::slice::from_raw_parts(src.as_ptr(), size));
                // adapt to C-style string
                *dst.add(size) = b'\0';
            }
        }

        // we don't care about the order of env...
        let mut envp_user = Vec::<*const u8>::new();
        for env in envp_vec.iter() {
            phys_user_sp -= env.len() + 1;
            envp_user.push((phys_user_sp + virt_phys_offset) as *const u8);
            copy_to_user_string_unchecked(env, phys_user_sp as *mut u8);
        }
        envp_user.push(core::ptr::null());

        // we don't care about the order of arg, too...
        let mut argv_user = Vec::<*const u8>::new();
        for arg in argv_vec.iter() {
            phys_user_sp -= arg.len() + 1;
            argv_user.push((phys_user_sp + virt_phys_offset) as *const u8);
            copy_to_user_string_unchecked(arg, phys_user_sp as *mut u8);
        }
        argv_user.push(core::ptr::null());

        // align downward to usize (64bit)
        phys_user_sp &= !0x7;

        // 16 random bytes
        phys_user_sp -= 2 * core::mem::size_of::<usize>();
        // should be virt addr!
        let random_bits_ptr = phys_user_sp + virt_phys_offset;
        unsafe {
            *(phys_user_sp as *mut usize) = 0xdeadbeefcafebabe;
            *(phys_user_sp as *mut usize).add(1) = 0xdeadbeefcafebabe;
        }

        // padding
        phys_user_sp -= core::mem::size_of::<usize>();
        unsafe {
            *(phys_user_sp as *mut usize) = 0x0000000000000000;
        }

        let auxv = [
            // AuxvEntry::new(AuxvType::SYSINFO_EHDR, vDSO_mapping);
            // AuxvEntry::new(AuxvType::L1I_CACHESIZE, 0);
            // AuxvEntry::new(AuxvType::L1I_CACHEGEOMETRY, 0);
            // AuxvEntry::new(AuxvType::L1D_CACHESIZE, 0);
            // AuxvEntry::new(AuxvType::L1D_CACHEGEOMETRY, 0);
            // AuxvEntry::new(AuxvType::L2_CACHESIZE, 0);
            // AuxvEntry::new(AuxvType::L2_CACHEGEOMETRY, 0);
            // `0x112d` means IMADZifenciC, aka gc
            AuxvEntry::new(AuxvType::HWCAP, 0x112d),
            AuxvEntry::new(AuxvType::PAGESZ, PAGE_SIZE),
            AuxvEntry::new(AuxvType::CLKTCK, TICKS_PER_SEC),
            AuxvEntry::new(AuxvType::PHDR, elf_info.phdr),
            AuxvEntry::new(AuxvType::PHENT, elf_info.phent),
            AuxvEntry::new(AuxvType::PHNUM, elf_info.phnum),
            AuxvEntry::new(AuxvType::BASE, elf_info.base),
            AuxvEntry::new(AuxvType::FLAGS, 0),
            AuxvEntry::new(AuxvType::ENTRY, elf_info.entry),
            AuxvEntry::new(AuxvType::UID, 0),
            AuxvEntry::new(AuxvType::EUID, 0),
            AuxvEntry::new(AuxvType::GID, 0),
            AuxvEntry::new(AuxvType::EGID, 0),
            AuxvEntry::new(AuxvType::SECURE, 0),
            AuxvEntry::new(AuxvType::RANDOM, random_bits_ptr as usize),
            AuxvEntry::new(
                AuxvType::EXECFN,
                argv_user.first().copied().unwrap() as usize,
            ),
            AuxvEntry::new(AuxvType::NULL, 0),
        ];
        phys_user_sp -= auxv.len() * core::mem::size_of::<AuxvEntry>();
        unsafe {
            core::slice::from_raw_parts_mut(phys_user_sp as *mut AuxvEntry, auxv.len())
                .copy_from_slice(auxv.as_slice());
        }

        phys_user_sp -= envp_user.len() * core::mem::size_of::<usize>();
        unsafe {
            core::slice::from_raw_parts_mut(phys_user_sp as *mut *const u8, envp_user.len())
                .copy_from_slice(envp_user.as_slice());
        }

        phys_user_sp -= argv_user.len() * core::mem::size_of::<usize>();
        unsafe {
            core::slice::from_raw_parts_mut(phys_user_sp as *mut *const u8, argv_user.len())
                .copy_from_slice(argv_user.as_slice());
        }

        phys_user_sp -= core::mem::size_of::<usize>();
        unsafe {
            *(phys_user_sp as *mut usize) = argv_vec.len();
        }

        user_sp = phys_user_sp + virt_phys_offset;

        // unlikely, if `start` and `end` are in different pages, we should panic
        assert_eq!(phys_start & !0xfff, phys_user_sp & !0xfff);

        // print user stack
        let mut phys_addr = phys_user_sp & !0xf;
        while phys_start >= phys_addr {
            info!(
                "0x{:0>16X}:    {:0>16X}  {:0>16X}",
                phys_addr + virt_phys_offset,
                unsafe { *(phys_addr as *mut usize) },
                unsafe { *((phys_addr + core::mem::size_of::<usize>()) as *mut usize) }
            );
            phys_addr += 2 * core::mem::size_of::<usize>();
        }

        // initialize trap_cx
        let trap_cx = TrapContext::app_init_context(
            if let Some(interp_entry) = elf_info.interp_entry {
                interp_entry
            } else {
                elf_info.entry
            },
            user_sp,
            KERNEL_SPACE.lock().token(),
            self.kernel_stack.get_top(),
            trap_handler as usize,
        );
        // trap_cx.x[10] = args_vec.len();
        // trap_cx.x[11] = argv_base;
        // trap_cx.x[12] = envp_base;
        // trap_cx.x[13] = auxv_base;
        // **** hold current PCB lock
        let mut inner = self.acquire_inner_lock();
        // update trap_cx ppn
        inner.trap_cx_ppn = (&memory_set)
            .translate(VirtAddr::from(TRAP_CONTEXT).into())
            .unwrap()
            .ppn();
        *inner.get_trap_cx() = trap_cx;
        // substitute memory_set
        *self.vm.lock() = memory_set;
        inner.heap_bottom = program_break;
        inner.heap_pt = program_break;
        // flush signal handler
        *self.sighand.lock() = BTreeMap::new();
        // flush cloexec fd
        self.files.lock().iter_mut().for_each(|fd| match fd {
            Some(file) => {
                if file.get_cloexec() {
                    *fd = None;
                }
            }
            None => (),
        });
        Ok(())
        // **** release current PCB lock
    }
    pub fn sys_clone(self: &Arc<TaskControlBlock>, flags: CloneFlags) -> Arc<TaskControlBlock> {
        // ---- hold parent PCB lock
        let mut parent_inner = self.acquire_inner_lock();
        // copy user space(include trap context)
        let memory_set = if flags.contains(CloneFlags::CLONE_VM) {
            self.vm.clone()
        } else {
            Arc::new(Mutex::new(MemorySet::from_existing_user(
                &mut self.vm.lock(),
            )))
        };
        let trap_cx_ppn = memory_set
            .lock()
            .translate(VirtAddr::from(TRAP_CONTEXT).into())
            .unwrap()
            .ppn();
        // alloc a pid and a kernel stack in kernel space
        let pid_handle = pid_alloc();
        let kernel_stack = KernelStack::new(&pid_handle);
        let kernel_stack_top = kernel_stack.get_top();
        // push a goto_trap_return task_cx on the top of kernel stack
        let task_cx_ptr = kernel_stack.push_on_top(TaskContext::goto_trap_return());
        let task_control_block = Arc::new(TaskControlBlock {
            pid: pid_handle,
            kernel_stack,
            files: if flags.contains(CloneFlags::CLONE_FILES) {
                self.files.clone()
            } else {
                Arc::new(Mutex::new(self.files.lock().clone()))
            },
            fs: if flags.contains(CloneFlags::CLONE_FS) {
                self.fs.clone()
            } else {
                Arc::new(Mutex::new(self.fs.lock().clone()))
            },
            vm: memory_set,
            sighand: if flags.contains(CloneFlags::CLONE_SIGHAND) {
                self.sighand.clone()
            } else {
                Arc::new(Mutex::new(self.sighand.lock().clone()))
            },
            inner: Mutex::new(TaskControlBlockInner {
                //inherited
                pgid: parent_inner.pgid,
                base_size: parent_inner.base_size,
                heap_bottom: parent_inner.heap_bottom,
                heap_pt: parent_inner.heap_pt,
                //clone
                sigpending: parent_inner.sigpending.clone(),
                //new/empty
                parent: Some(Arc::downgrade(self)),
                children: Vec::new(),
                rusage: Rusage::new(),
                clock: ProcClock::new(),
                address: ProcAddress::new(),
                timer: [ITimerVal::new(); 3],
                sigmask: Signals::empty(),
                //computed
                task_cx_ptr: task_cx_ptr as usize,
                task_status: TaskStatus::Ready,
                trap_cx_ppn,
                //constants
                exit_code: 0,
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
        if (pgid as isize) < 0 {
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
    /// Try to alloc the lowest valid fd in `fd_table`
    pub fn alloc_fd(&self, fd_table: &mut MutexGuard<Vec<Option<FileDescriptor>>>) -> Option<usize> {
        self.alloc_fd_at(0, fd_table)
    }
    /// Try to alloc fd at `hint`, if `hint` is allocated, will alloc lowest valid fd above.
    pub fn alloc_fd_at(&self, hint: usize, fd_table: &mut MutexGuard<Vec<Option<FileDescriptor>>>) -> Option<usize> {
        // [Warning] temporarily use hardcoded implementation, should adapt to `prlimit()` in future
        const FD_LIMIT: usize = 128;
        if hint < fd_table.len() {
            if let Some(fd) = (hint..fd_table.len()).find(|fd| fd_table[*fd].is_none()) {
                Some(fd)
            } else {
                if fd_table.len() < FD_LIMIT {
                    fd_table.push(None);
                    Some(fd_table.len() - 1)
                } else {
                    None
                }
            }
        } else {
            if hint < FD_LIMIT {
                fd_table.resize(hint + 1, None);
                Some(hint)
            } else {
                None
            }
        }
    }
    pub fn get_user_token(&self) -> usize {
        self.vm.lock().token()
    }
}

pub fn load_elf_interp(path: &str) -> Result<&'static [u8], isize> {
    match ROOT_FD.open(path, OpenFlags::O_RDONLY, false) {
        Ok(file) => {
            if file.get_size() < 4 {
                return Err(ELIBBAD);
            }
            let mut magic_number = Box::<[u8; 4]>::new([0; 4]);
            // this operation may be expensive... I'm not sure
            file.read(Some(&mut 0usize), magic_number.as_mut_slice());
            match magic_number.as_slice() {
                b"\x7fELF" => {
                    let buffer_addr = KERNEL_SPACE.lock().last_mmap_area_end();
                    let buffer = unsafe {
                        core::slice::from_raw_parts_mut(buffer_addr.0 as *mut u8, file.get_size())
                    };
                    let caches = file.get_all_caches().unwrap();
                    let frames = 
                        caches
                        .iter()
                        .map(|cache|{
                            let lock = cache.try_lock();
                            assert!(lock.is_some());
                            Some(lock.unwrap().get_tracker())
                        })
                        .collect();

                    crate::mm::KERNEL_SPACE
                        .lock()
                        .insert_program_area(
                            buffer_addr.into(),
                            crate::mm::MapPermission::R | crate::mm::MapPermission::W,
                            frames,
                        )
                        .unwrap();

                    return Ok(buffer);
                }
                _ => Err(ELIBBAD),
            }
        }
        Err(errno) => Err(errno),
    }
}

fn elf_exec(file: &FileDescriptor, argv_vec: &Vec<String>, envp_vec: &Vec<String>) -> isize {
    let buffer = unsafe { core::slice::from_raw_parts_mut(MMAP_BASE as *mut u8, file.get_size()) };
    let caches = file.get_all_caches().unwrap();
    let frames = 
        caches
        .iter()
        .map(|cache|{
            let lock = cache.try_lock();
            assert!(lock.is_some());
            Some(lock.unwrap().get_tracker())
        })
        .collect();

    crate::mm::KERNEL_SPACE
        .lock()
        .insert_program_area(
            MMAP_BASE.into(),
            crate::mm::MapPermission::R | crate::mm::MapPermission::W,
            frames,
        )
        .unwrap();

    let task = current_task().unwrap();
    show_frame_consumption! {
        "task_exec";
        if let Err(errno) = task.load_elf(buffer, argv_vec, envp_vec) {
            return errno;
        };
    }
    // remove elf area
    crate::mm::KERNEL_SPACE
        .lock()
        .remove_area_with_start_vpn(VirtAddr::from(MMAP_BASE).floor())
        .unwrap();
    // should return 0 in success
    SUCCESS
}

// should return 0 in success
pub fn execve(path: String, mut argv_vec: Vec<String>, envp_vec: Vec<String>) -> isize {
    const DEFAULT_SHELL: &str = "/bin/bash";
    debug!(
        "[exec] argv: {:?} /* {} vars */, envp: {:?} /* {} vars */",
        argv_vec,
        argv_vec.len(),
        envp_vec,
        envp_vec.len()
    );
    let task = current_task().unwrap();
    let working_inode = &task.fs.lock().working_inode;

    match working_inode.open(&path, OpenFlags::O_RDONLY, false) {
        Ok(file) => {
            if file.get_size() < 4 {
                return ENOEXEC;
            }
            let mut magic_number = Box::<[u8; 4]>::new([0; 4]);
            // this operation may be expensive... I'm not sure
            file.read(Some(&mut 0usize), magic_number.as_mut_slice());
            match magic_number.as_slice() {
                b"\x7fELF" => elf_exec(&file, &argv_vec, &envp_vec),
                b"#!" => {
                    let shell_file = working_inode.open(
                        DEFAULT_SHELL,
                        OpenFlags::O_RDONLY,
                        false,
                    )
                    .unwrap();
                    argv_vec.insert(0, DEFAULT_SHELL.to_string());
                    elf_exec(&shell_file, &argv_vec, &envp_vec)
                }
                _ => ENOEXEC,
            }
        }
        Err(errno) => errno,
    }
}
// I think it's a little expensive, so I temporarily move it here
// test sh
// if buffer[0..4] != [0x7f, 0x45, 0x4c, 0x46]

// Problem 0: Zero Init. Exec Attempt: Use `busybox sh` as `default` while achieving the following purposes.
// Problem 1: Recursion Redirection Problem: what if the #! gives an X that is NOT a binary.
// problem 2: Invalid Redirection Problem: what if the #! gives an invalid binary? If you redirect it to `busybox sh` directly, will it be an infinitive recursion?

// let path_bin: String;
// let shell: bool = buffer[0..2.min(buffer.len())] == [b'#', b'!']; // see if it tells us the path using #!
// info!("bin_given:{}", shell);
// if shell {
//     let last = buffer[0..85.min(buffer.len())]
//         .iter()
//         .position(|&r| ['\n' as u8, '\0' as u8, 0].contains(&(r)));
//     //assign_to_bin. not done.
//     path_bin = String::from_utf8_lossy(
//         &buffer[2..if last.is_some() { last.unwrap() } else { 2 }], //what if it is #!
//     )
//     .to_string();
//     if path_bin.is_empty() {
//         unmap_exec_buf!(buffer);
//         // #! must be followed by a path or at least a name
//         return ENOEXEC;
//     }
//     info!("path_bin:{}", path_bin);
//     //end of assign_to_bin
//     if ["/bin/sh", "/bin/bash"].contains(&&(path_bin[..])) {
//         info!("[exec]path_bin==/bin/sh");
//         *path = String::from("/bash");
//         args_vec.insert(0, path.to_string());
//     } else {
//         info!("[exec]path_bin!=/bin/sh");
//         let cmd = path_bin.split(' ').collect::<Vec<_>>();
//         //args_vec[0] = path.clone();
//         *path = cmd[0].to_string();
//         let bin_name = path[..]
//             .split('/')
//             .collect::<Vec<_>>()
//             .last()
//             .unwrap()
//             .to_string();
//         if cmd.len() > 1 {
//             for j in (1..cmd.len()).rev() {
//                 args_vec.insert(0, cmd[j].to_string());
//             }
//         }
//         args_vec.insert(0, bin_name);
//         info!("[exec] args_vec{:?}", args_vec);
//     }
//  } else {
// completely no info, fall back to busybox.
// args_vec.insert(0, String::from("busybox"));
// }

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum TaskStatus {
    Ready,
    Running,
    Zombie,
    Interruptible,
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
