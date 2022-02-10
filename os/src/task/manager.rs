use super::TaskControlBlock;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use lazy_static::*;
use spin::Mutex;

pub struct TaskManager {
    ready_queue: VecDeque<Arc<TaskControlBlock>>,
    wait_queue: VecDeque<Arc<TaskControlBlock>>,
}

/// A simple FIFO scheduler.
impl TaskManager {
    pub fn new() -> Self {
        Self {
            ready_queue: VecDeque::new(),
            wait_queue: VecDeque::new(),
        }
    }
    pub fn add(&mut self, task: Arc<TaskControlBlock>) {
        self.ready_queue.push_back(task);
    }
    pub fn fetch(&mut self) -> Option<Arc<TaskControlBlock>> {
        self.ready_queue.pop_front()
    }
    pub fn sleep(&mut self, task: Arc<TaskControlBlock>) {
        self.wait_queue.push_back(task);
    }
    pub fn wake(&mut self, task: Arc<TaskControlBlock>) {
        let pid = task.getpid();
        let pair = self
            .wait_queue
            .iter()
            .enumerate()
            .find(|(_, task)| task.getpid() == pid);
        if let Some((idx, _)) = pair {
            let task = self.wait_queue.remove(idx).unwrap();
            self.ready_queue.push_back(task);
        }
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

pub fn sleep_task(task: Arc<TaskControlBlock>) {
    TASK_MANAGER.lock().sleep(task);
}

pub fn wake_task(task: Arc<TaskControlBlock>) {
    TASK_MANAGER.lock().wake(task);
}
