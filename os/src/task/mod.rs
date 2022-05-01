mod context;
mod manager;
mod pid;
mod processor;
pub mod signal;
mod switch;
mod task;

use crate::fs::{open, DiskInodeType, File, OpenFlags};
use alloc::sync::Arc;
pub use context::TaskContext;
use lazy_static::*;
use manager::fetch_task;
pub use signal::*;
use switch::__switch;
pub use task::{execve, FdTable, Rusage, TaskControlBlock, TaskStatus};

pub use manager::{add_task, find_task_by_pid, sleep_interruptible, wake_interruptible};
pub use pid::{pid_alloc, KernelStack, PidHandle};
pub use processor::{
    current_task, current_trap_cx, current_user_token, run_tasks, schedule, take_current_task,
};

pub fn suspend_current_and_run_next() {
    // There must be an application running.
    let task = take_current_task().unwrap();

    // ---- hold current PCB lock
    let mut task_inner = task.acquire_inner_lock();
    let task_cx_ptr2 = task_inner.get_task_cx_ptr2();
    // Change status to Ready
    task_inner.task_status = TaskStatus::Ready;
    drop(task_inner);
    // ---- release current PCB lock

    // push back to ready queue.
    add_task(task);
    // jump to scheduling cycle
    schedule(task_cx_ptr2);
}

pub fn block_current_and_run_next() {
    // There must be an application running.
    let task = take_current_task().unwrap();

    // ---- hold current PCB lock
    let mut task_inner = task.acquire_inner_lock();
    let task_cx_ptr2 = task_inner.get_task_cx_ptr2();
    // Change status to Interruptible
    task_inner.task_status = TaskStatus::Interruptible;
    drop(task_inner);
    // ---- release current PCB lock

    // push to interruptible queue of scheduler, so that it won't be scheduled.
    sleep_interruptible(task);
    // jump to scheduling cycle
    schedule(task_cx_ptr2);
}

pub fn exit_current_and_run_next(exit_code: u32) -> ! {
    // take from Processor
    let task = take_current_task().unwrap();
    // **** hold current PCB lock
    let mut inner = task.acquire_inner_lock();
    {
        let parent_task = inner.parent.as_ref().unwrap().upgrade().unwrap(); // this will acquire inner of current task
        let mut parent_inner = parent_task.acquire_inner_lock();
        parent_inner.add_signal(Signals::SIGCHLD);

        if parent_inner.task_status == TaskStatus::Interruptible {
            // wake up parent if parent is waiting.
            parent_inner.task_status = TaskStatus::Ready;
            // push back to ready queue.
            wake_interruptible(parent_task.clone());
        }
    }
    log::info!(
        "[sys_exit] Trying to exit pid {} with {}",
        task.pid.0,
        exit_code
    );
    // Change status to Zombie
    inner.task_status = TaskStatus::Zombie;
    // Record exit code
    inner.exit_code = exit_code;
    // do not move to its parent but under initproc

    // ++++++ hold initproc PCB lock here
    {
        let mut initproc_inner = INITPROC.acquire_inner_lock();
        for child in inner.children.iter() {
            child.acquire_inner_lock().parent = Some(Arc::downgrade(&INITPROC));
            initproc_inner.children.push(child.clone());
        }
    }
    // ++++++ release parent PCB lock here

    inner.children.clear();
    // deallocate user space
    inner.memory_set.recycle_data_pages();
    drop(inner);
    // **** release current PCB lock
    // drop task manually to maintain rc correctly
    log::info!("[sys_exit] Pid {} exited with {}", task.pid.0, exit_code);
    drop(task);
    // we do not have to save task context
    let _unused: usize = 0;
    schedule(&_unused as *const _);
    panic!("Unreachable");
}

lazy_static! {
    pub static ref INITPROC: Arc<TaskControlBlock> = Arc::new({
        let inode = open("/", "initproc", OpenFlags::O_RDONLY, DiskInodeType::File).unwrap();
        let start: usize = crate::config::MMAP_BASE;
        let len = inode.size();
        crate::mm::KERNEL_SPACE.lock().insert_framed_area(
            start.into(),
            (start + len).into(),
            crate::mm::MapPermission::R | crate::mm::MapPermission::W,
        );
        unsafe {
            let buffer = core::slice::from_raw_parts_mut(start as *mut u8, len);
            inode.kread(None, buffer);
            TaskControlBlock::new(buffer)
        }
    });
}

pub fn add_initproc() {
    add_task(INITPROC.clone());
}

#[derive(Clone, Copy)]
#[allow(non_camel_case_types, unused)]
#[repr(usize)]
pub enum AuxvType {
    NULL = 0,
    IGNORE = 1,
    EXECFD = 2,
    PHDR = 3,
    PHENT = 4,
    PHNUM = 5,
    PAGESZ = 6,
    BASE = 7,
    FLAGS = 8,
    ENTRY = 9,
    NOTELF = 10,
    UID = 11,
    EUID = 12,
    GID = 13,
    EGID = 14,
    PLATFORM = 15,
    HWCAP = 16,
    CLKTCK = 17,
    FPUCW = 18,
    DCACHEBSIZE = 19,
    ICACHEBSIZE = 20,
    UCACHEBSIZE = 21,
    IGNOREPPC = 22,
    SECURE = 23,
    BASE_PLATFORM = 24,
    RANDOM = 25,
    HWCAP2 = 26,
    EXECFN = 31,
    SYSINFO = 32,
    SYSINFO_EHDR = 33,
    L1I_CACHESHAPE = 34,
    L1D_CACHESHAPE = 35,
    L2_CACHESHAPE = 36,
    L3_CACHESHAPE = 37,
    L1I_CACHESIZE = 40,
    L1I_CACHEGEOMETRY = 41,
    L1D_CACHESIZE = 42,
    L1D_CACHEGEOMETRY = 43,
    L2_CACHESIZE = 44,
    L2_CACHEGEOMETRY = 45,
    L3_CACHESIZE = 46,
    L3_CACHEGEOMETRY = 47,
    MINSIGSTKSZ = 51,
}

#[derive(Clone, Copy)]
#[allow(unused)]
pub struct AuxvEntry {
    auxv_type: AuxvType,
    auxv_val: usize,
}

impl AuxvEntry {
    fn new(auxv_type: AuxvType, auxv_val: usize) -> Self {
        Self {
            auxv_type,
            auxv_val,
        }
    }
}

pub struct ELFInfo {
    pub entry: usize,
    pub phnum: usize,
    pub phent: usize,
    pub phdr: usize,
}
