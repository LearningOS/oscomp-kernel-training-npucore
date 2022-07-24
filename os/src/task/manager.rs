use super::{current_task, TaskControlBlock};
use alloc::collections::{VecDeque};
use alloc::sync::{Arc, Weak};
use lazy_static::*;
use spin::Mutex;

pub struct TaskManager {
    pub ready_queue: VecDeque<Arc<TaskControlBlock>>,
    pub interruptible_queue: VecDeque<Arc<TaskControlBlock>>,
}

/// A simple FIFO scheduler.
impl TaskManager {
    pub fn new() -> Self {
        Self {
            ready_queue: VecDeque::new(),
            interruptible_queue: VecDeque::new(),
        }
    }
    pub fn add(&mut self, task: Arc<TaskControlBlock>) {
        self.ready_queue.push_back(task);
    }
    pub fn fetch(&mut self) -> Option<Arc<TaskControlBlock>> {
        self.ready_queue.pop_front()
    }
    pub fn add_interruptible(&mut self, task: Arc<TaskControlBlock>) {
        self.interruptible_queue.push_back(task);
    }
    pub fn drop_interruptible(&mut self, task: &Arc<TaskControlBlock>) {
        self.interruptible_queue
            .retain(|task_in_queue| Arc::as_ptr(task_in_queue) != Arc::as_ptr(task));
    }
    pub fn find_by_pid(&self, pid: usize) -> Option<Arc<TaskControlBlock>> {
        self.ready_queue
            .iter()
            .chain(self.interruptible_queue.iter())
            .find(|task| task.pid.0 == pid)
            .cloned()
    }
    pub fn find_by_tgid(&self, tgid: usize) -> Option<Arc<TaskControlBlock>> {
        self.ready_queue
            .iter()
            .chain(self.interruptible_queue.iter())
            .find(|task| task.tgid == tgid)
            .cloned()
    }
    pub fn ready_count(&self) -> u16 {
        self.ready_queue.len() as u16
    }
    pub fn interruptible_count(&self) -> u16 {
        self.interruptible_queue.len() as u16
    }
    pub fn show_ready(&self) {
        self.ready_queue.iter().for_each(|task| {
            log::error!("[show_ready] pid: {}", task.pid.0);
        })
    }
    pub fn show_interruptible(&self) {
        self.interruptible_queue.iter().for_each(|task| {
            log::error!("[show_interruptible] pid: {}", task.pid.0);
        })
    }
}

lazy_static! {
    pub static ref TASK_MANAGER: Mutex<TaskManager> = Mutex::new(TaskManager::new());
}

pub fn add_task(task: Arc<TaskControlBlock>) {
    TASK_MANAGER.lock().add(task);
}

pub fn fetch_task() -> Option<Arc<TaskControlBlock>> {
    TASK_MANAGER.lock().fetch()
}

/// This function add a task to interruptible_queue,
/// but won't take it out from ready_queue.
/// So you should make sure that the task won't be presented in ready_queue.
/// In common cases, a task will be drop from ready_queue when it is scheduled,
/// and you can use take `take_current_task()` to acquire the ownership of current TCB.
/// # Attention
/// You should find a place to save `Arc<TaskControlBlock>` of the task, or you would
/// be unable to use `wake_interruptible()` to wake it up in the future.
/// This function **won't change task_status**, you should change it manully to insure consistency.
pub fn sleep_interruptible(task: Arc<TaskControlBlock>) {
    TASK_MANAGER.lock().add_interruptible(task);
}

/// This function will drop task from interruptible_queue and push it into ready_queue.
/// The task will be scheduled if everything goes well.
/// # Attention
/// This function **won't change task_status**, you should change it manully to insure consistency.
pub fn wake_interruptible(task: Arc<TaskControlBlock>) {
    let mut manager = TASK_MANAGER.lock();
    manager.drop_interruptible(&task);
    if manager.find_by_pid(task.pid.0).is_none() {
        manager.add(task);
    }
}

/// # Warning
/// `pid` here is unique, user will regard it as `tid`
pub fn find_task_by_pid(pid: usize) -> Option<Arc<TaskControlBlock>> {
    let task = current_task().unwrap();
    if task.pid.0 == pid {
        Some(task)
    } else {
        TASK_MANAGER.lock().find_by_pid(pid)
    }
}

/// Return arbitrary task with `tgid`.
pub fn find_task_by_tgid(tgid: usize) -> Option<Arc<TaskControlBlock>> {
    let task = current_task().unwrap();
    if task.tgid == tgid {
        Some(task)
    } else {
        TASK_MANAGER.lock().find_by_tgid(tgid)
    }
}

pub fn procs_count() -> u16 {
    let manager = TASK_MANAGER.lock();
    manager.ready_count() + manager.interruptible_count()
}

pub struct WaitQueue {
    inner: Mutex<VecDeque<Weak<TaskControlBlock>>>,
}

#[allow(unused)]
impl WaitQueue {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(VecDeque::new()),
        }
    }
    /// This function add a task to WaitQueue but **won't block it**,
    /// if you want to block a task, use `block_current_and_run_next()`.
    pub fn add_task(&mut self, task: Weak<TaskControlBlock>) {
        self.inner.lock().push_back(task);
    }
    /// This function will try to pop a task from WaitQueue but **won't wake it up**
    pub fn pop_task(&mut self) -> Option<Weak<TaskControlBlock>> {
        self.inner.lock().pop_front()
    }
    /// Returns `true` if the `WaitQueue` contains an element equal to the given `task`
    pub fn contains(&self, task: &Weak<TaskControlBlock>) -> bool {
        self.inner.lock().iter().any(|task_in_queue| {
            Weak::as_ptr(task_in_queue) == Weak::as_ptr(task)
        })
    }
    /// Returns `true` if the `WaitQueue` is empty
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }
    /// This funtion will wake up all tasks in inner Vec and change their `task_status`
    /// to `Ready`, so it will try to acquire inner lock and **dead lock could happen**.
    /// These tasks will be scheduled if everything goes well.
    pub fn wake_all(&mut self) -> usize {
        self.wake_at_most(usize::MAX)
    }
    /// Wake no more than `limit` processes in this queue.
    /// # DEADLOCK
    /// This funtion will wake up all tasks in inner Vec and change their `task_status`
    /// to `Ready`, so it will try to acquire inner lock and **deadlocks could happen**.
    pub fn wake_at_most(&mut self, limit: usize) -> usize {
        if limit == 0 {
            return 0;
        }
        let mut vec = self.inner.lock();
        let mut cnt = 0;
        while let Some(task) = vec.pop_front() {
            match task.upgrade() {
                Some(task) => {
                    task.acquire_inner_lock().task_status = super::task::TaskStatus::Ready;
                    wake_interruptible(task);
                    cnt += 1;
                    if cnt == limit {
                        break;
                    }
                },
                // task is dead, just ignore
                None => continue,
            }
        }
        cnt
    }
}

// pub struct TimeOut {
//     time: TimeRange,
//     task: Arc<TaskControlBlock>,
// }
// impl TimeOut {
//     pub fn from_cur_task_rel_time(mut time: TimeRange) -> Self {
//         time = match time {
//             TimeRange::TimeSpec(t) => TimeRange::TimeSpec(t + TimeSpec::now()),
//             TimeRange::TimeVal(t) => TimeRange::TimeVal(t + TimeVal::now()),
//         };
//         Self {
//             task: current_task().unwrap(),
//             time,
//         }
//     }
//     pub fn from_cur_task_abs_time(time: TimeRange) -> Self {
//         Self {
//             time,
//             task: current_task().unwrap(),
//         }
//     }
//     pub fn is_wake_time(&self) -> bool {
//         match self.time {
//             TimeRange::TimeSpec(t) => {
//                 if TimeSpec::now() <= t {
//                     true
//                 } else {
//                     false
//                 }
//             }
//             TimeRange::TimeVal(t) => {
//                 if TimeVal::now() <= t {
//                     true
//                 } else {
//                     false
//                 }
//             }
//         }
//     }
// }
// impl Drop for TimeOut {
//     fn drop(&mut self) {
//         assert!(self.is_wake_time());
//         wake_interruptible(self.task.clone());
//         log::info!("[TimeOut::drop] Woke due to timeout.");
//         self.task.acquire_inner_lock().task_status = super::task::TaskStatus::Ready;
//     }
// }
