mod context;
mod elf;
mod manager;
mod pid;
mod processor;
pub mod signal;
mod switch;
mod task;
pub mod threads;

use crate::fs::{OpenFlags, ROOT_FD};
use alloc::sync::Arc;
pub use context::TaskContext;
pub use elf::{load_elf_interp, AuxvEntry, AuxvType, ELFInfo};
use lazy_static::*;
use manager::fetch_task;
pub use manager::{
    add_task, find_task_by_pid, find_task_by_tgid, procs_count, sleep_interruptible, timeout_wake,
    wake_interruptible,
};
pub use pid::{pid_alloc, trap_cx_bottom_from_tid, ustack_bottom_from_tid, KernelStack, PidHandle};
pub use processor::{
    current_task, current_trap_cx, current_user_token, run_tasks, schedule, take_current_task,
};
pub use signal::*;
use switch::__switch;
pub use task::{Rusage, TaskControlBlock, TaskStatus};

pub fn suspend_current_and_run_next() {
    // There must be an application running.
    let task = take_current_task().unwrap();

    // ---- hold current PCB lock
    let mut task_inner = task.acquire_inner_lock();
    let task_cx_ptr = &mut task_inner.task_cx as *mut TaskContext;
    // Change status to Ready
    task_inner.task_status = TaskStatus::Ready;
    //    log::info!("suspended pid:{}", task.pid.0);
    drop(task_inner);
    // ---- release current PCB lock

    // push back to ready queue.
    add_task(task);
    // jump to scheduling cycle
    schedule(task_cx_ptr);
}

pub fn block_current_and_run_next() {
    // There must be an application running.
    let task = take_current_task().unwrap();

    // ---- hold current PCB lock
    let mut task_inner = task.acquire_inner_lock();
    let task_cx_ptr = &mut task_inner.task_cx as *mut TaskContext;
    // Change status to Interruptible
    task_inner.task_status = TaskStatus::Interruptible;
    drop(task_inner);
    // ---- release current PCB lock

    // push to interruptible queue of scheduler, so that it won't be scheduled.
    sleep_interruptible(task);
    // jump to scheduling cycle
    schedule(task_cx_ptr);
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
    // deallocate user resource (trap context and user stack)
    task.vm.lock().dealloc_user_res(task.tid);
    // deallocate whole user space in advance, or if its parent do not call wait,
    // this resource may not be recycled in a long period of time.
    if Arc::strong_count(&task.vm) == 1 {
        task.vm.lock().recycle_data_pages();
    } 
    drop(inner);
    // **** release current PCB lock
    // drop task manually to maintain rc correctly
    log::info!("[sys_exit] Pid {} exited with {}", task.pid.0, exit_code);
    drop(task);
    // we do not have to save task context
    let mut _unused = TaskContext::zero_init();
    schedule(&mut _unused as *mut _);
    panic!("Unreachable");
}

lazy_static! {
    pub static ref INITPROC: Arc<TaskControlBlock> = Arc::new({
        let inode = ROOT_FD.open("initproc", OpenFlags::O_RDONLY, true).unwrap();
        let start: usize = crate::config::MMAP_BASE;
        let len = inode.get_size();
        crate::mm::KERNEL_SPACE.lock().insert_framed_area(
            start.into(),
            (start + len).into(),
            crate::mm::MapPermission::R | crate::mm::MapPermission::W,
        );
        unsafe {
            let buffer = core::slice::from_raw_parts_mut(start as *mut u8, len);
            inode.read(None, buffer);
            TaskControlBlock::new(buffer)
        }
    });
}

pub fn add_initproc() {
    add_task(INITPROC.clone());
}
