use super::TaskControlBlock;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use lazy_static::*;
use spin::Mutex;

pub struct TaskManager {
    ready_queue: VecDeque<Arc<TaskControlBlock>>,
    interruptible_queue: VecDeque<Arc<TaskControlBlock>>,
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
    pub fn drop_interruptible(&mut self, task: Arc<TaskControlBlock>) {
        self.interruptible_queue.retain(|task_in_queue| {
            task_in_queue.as_ref() as *const TaskControlBlock
                != task.as_ref() as *const TaskControlBlock
        });
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
pub fn sleep_interruptible(task: Arc<TaskControlBlock>) {
    TASK_MANAGER.lock().add_interruptible(task);
}

/// This function will drop task from interruptible_queue and push it into ready_queue.
/// The task will be scheduled if everything goes well.
pub fn wake_interruptible(task: Arc<TaskControlBlock>) {
    let mut manager = TASK_MANAGER.lock();
    manager.drop_interruptible(task.clone());
    manager.add(task.clone());
}
