mod context;
mod manager;
mod pid;
mod processor;
pub mod signal;
mod switch;
mod task;

use crate::fs::{open, DiskInodeType, OpenFlags};
use alloc::sync::Arc;
pub use context::TaskContext;
use lazy_static::*;
use manager::fetch_task;
pub use signal::*;
use switch::__switch;
pub use task::{AuxHeader, FdTable};
use task::{TaskControlBlock, TaskStatus};

pub use manager::add_task;
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

pub fn exit_current_and_run_next(exit_code: i32) {
    // take from Processor
    let task = take_current_task().unwrap();
    // **** hold current PCB lock
    let mut inner = task.acquire_inner_lock();
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
    drop(task);
    // we do not have to save task context
    let _unused: usize = 0;
    schedule(&_unused as *const _);
}

lazy_static! {
    pub static ref INITPROC: Arc<TaskControlBlock> = Arc::new({
        let inode = open("/", "initproc", OpenFlags::RDONLY, DiskInodeType::File).unwrap();
        let len = inode.get_size();
        let j: usize = len % crate::config::PAGE_SIZE;
        let lrnd = if j == 0 {
            len
        } else {
            len - j + crate::config::PAGE_SIZE
        };
        let start: usize = crate::config::MEMORY_END * 4;
        crate::mm::KERNEL_SPACE.lock().alloc(
            start,
            lrnd,
            (crate::mm::MapPermission::R | crate::mm::MapPermission::W).bits() as usize,
        );
        unsafe {
            let mut buf = core::slice::from_raw_parts_mut(start as *mut u8, lrnd);
            let v = inode.read_into(&mut buf);
            TaskControlBlock::new(buf)
        }
    });
}

/// Literal definition.
/// Note: The process lookup is done over tree enumeration, at a high cost.
pub fn find_process_by_pid(pid: usize) -> Option<Arc<TaskControlBlock>> {
    if pid == INITPROC.getpid() {
        Some(INITPROC.clone())
    } else {
        INITPROC.find_child_process_by_pid(pid)
    }
}

pub fn find_process_by_pgid(pgid: usize) -> alloc::vec::Vec<Arc<TaskControlBlock>> {
    let mut v = alloc::vec::Vec::new();
    if pgid == INITPROC.getpgid() {
        v.push(INITPROC.clone());
    }
    v.append(&mut INITPROC.find_child_process_by_pgid(pgid));
    v
}

pub fn add_initproc() {
    add_task(INITPROC.clone());
}
