use super::super::fs;
use super::{PhysAddr, PhysPageNum};
use crate::config::{MEMORY_END, PAGE_SIZE};
use crate::task::current_task;
// KISS
use alloc::{sync::Arc, vec::Vec};
use core::fmt::{self, Debug, Formatter};
use lazy_static::*;
use spin::RwLock;

pub struct FrameTracker {
    pub ppn: PhysPageNum,
}
/// RAII phantom for physical pages
impl FrameTracker {
    pub fn new(ppn: PhysPageNum) -> Self {
        // page cleaning
        let dwords_array = ppn.get_dwords_array();
        for i in dwords_array {
            *i = 0;
        }
        Self { ppn }
    }
    pub fn new_initialized(ppn: PhysPageNum, f: impl FnOnce(&'static mut [u64])) -> Self {
        let dwords_array = ppn.get_dwords_array();
        f(dwords_array);
        Self { ppn }
    }
}

impl Debug for FrameTracker {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("FrameTracker:PPN={:#x}", self.ppn.0))
    }
}
impl Drop for FrameTracker {
    /// Automatically recycle the physical frame when
    fn drop(&mut self) {
        // println!("do drop at {}", self.ppn.0);
        frame_dealloc(self.ppn);
    }
}

trait FrameAllocator {
    fn new() -> Self;
    fn alloc(&mut self) -> Option<PhysPageNum>;
    fn dealloc(&mut self, ppn: PhysPageNum);
}

pub struct StackFrameAllocator {
    current: usize,
    end: usize,
    recycled: Vec<usize>,
}

impl StackFrameAllocator {
    pub fn init(&mut self, l: PhysPageNum, r: PhysPageNum) {
        self.current = l.0;
        self.end = r.0;
        println!("last {} Physical Frames.", self.end - self.current);
    }
    pub fn unallocated_frames(&self) -> usize {
        self.recycled.len() + self.end - self.current
    }
    pub fn free_space_size(&self) -> usize {
        self.unallocated_frames() * PAGE_SIZE
    }
}
impl FrameAllocator for StackFrameAllocator {
    fn new() -> Self {
        Self {
            current: 0,
            end: 0,
            recycled: Vec::new(),
        }
    }
    fn alloc(&mut self) -> Option<PhysPageNum> {
        if let Some(ppn) = self.recycled.pop() {
            let __ppn: PhysPageNum = ppn.into();
            log::trace!("[frame_alloc] {:?}", __ppn);
            Some(ppn.into())
        } else if self.current == self.end {
            None
        } else {
            self.current += 1;
            let __ppn: PhysPageNum = (self.current - 1).into();
            log::trace!("[frame_alloc] {:?}", __ppn);
            Some((self.current - 1).into())
        }
    }
    /// Deallocate a physical page
    fn dealloc(&mut self, ppn: PhysPageNum) {
        log::trace!("[frame_dealloc] {:?}", ppn);
        let ppn = ppn.0;
        // validity check, note that this should be unnecessary for RELEASE build and it may significantly draw the speed of recycle.
        if option_env!("MODE") == Some("debug") && ppn >= self.current
            || self.recycled.iter().find(|&v| *v == ppn).is_some()
        {
            panic!("Frame ppn={:#x} has not been allocated!", ppn);
        }
        // recycle
        self.recycled.push(ppn);
    }
}

type FrameAllocatorImpl = StackFrameAllocator;

lazy_static! {
    pub static ref FRAME_ALLOCATOR: RwLock<FrameAllocatorImpl> =
        RwLock::new(FrameAllocatorImpl::new());
}
pub fn init_frame_allocator() {
    extern "C" {
        fn ekernel();
    }
    FRAME_ALLOCATOR.write().init(
        PhysAddr::from(ekernel as usize).ceil(),
        PhysAddr::from(MEMORY_END).floor(),
    );
}

/// Try to release `req` pages through all possible methods,
/// on success returns `Ok(())` else return `Err(())`.
pub fn oom_handler(req: usize) -> Result<(), ()> {
    // step 1: clean fs
    let mut released = 0;
    released += fs::directory_tree::oom();
    if released >= req {
        return Ok(());
    }
    // step 2: clean current task's memory space
    let task = current_task().unwrap();
    if let Some(mut memory_set) = task.vm.try_lock() {
        released += memory_set.do_shallow_clean();
        log::warn!("[oom_handler] current task released: {}", released);
    } else {
        log::warn!("[oom_handler] try lock current task vm failed!");
    }
    if released >= req {
        return Ok(());
    }
    // step 3: clean all tasks' memory space
    log::warn!("[oom_handler] notify all tasks!");
    crate::task::do_oom(req - released)
}

pub fn frame_reserve(num: usize) {
    let remain = FRAME_ALLOCATOR.read().unallocated_frames();
    if remain < num {
        oom_handler(num - remain).unwrap()
    }
}

pub fn frame_alloc() -> Option<Arc<FrameTracker>> {
    let ret = FRAME_ALLOCATOR
        .write()
        .alloc()
        .map(|ppn| Arc::new(FrameTracker::new(ppn)));
    if ret.is_some() {
        ret
    } else {
        crate::show_frame_consumption! {
            "GC";
            oom_handler(1).unwrap();
        };
        FRAME_ALLOCATOR
            .write()
            .alloc()
            .map(|ppn| Arc::new(FrameTracker::new(ppn)))
    }
}

pub fn frame_dealloc(ppn: PhysPageNum) {
    FRAME_ALLOCATOR.write().dealloc(ppn);
}

pub fn unallocated_frames() -> usize {
    FRAME_ALLOCATOR.write().unallocated_frames()
}

#[allow(unused)]
pub fn frame_allocator_test() {
    let mut v: Vec<Arc<FrameTracker>> = Vec::new();
    for i in 0..5 {
        let frame = frame_alloc().unwrap();
        println!("{:?}", frame);
        v.push(frame);
    }
    v.clear();
    for i in 0..5 {
        let frame = frame_alloc().unwrap();
        println!("{:?}", frame);
        v.push(frame);
    }
    drop(v);
    println!("frame_allocator_test passed!");
}

pub fn free_space_size_rdlock() -> usize {
    FRAME_ALLOCATOR.read().free_space_size()
}

#[macro_export]
/// # Usage Example
///
/// `show_frame_consumption!{$place, $before}` Format:
///
/// ````
/// show_frame_consumption!("push_elf_area", previous_use)
/// ````
///
/// `show_frame_consumption!{$place, $statement}` Format:
///
/// ````
/// show_frame_consumption! {
///        "push_elf_area";
///        if crate::mm::push_elf_area(file.clone()).is_err() {
///            file.kread(None, buffer);
///        } else {
///            info!("[elf_exec] Hit ELF cache, no alloc");
///        };
///    }
/// ````
///
/// # Arguments
/// * `$place`: the name tag for the promotion.
/// * `statement`: the enclosed
/// * `before`:
macro_rules! show_frame_consumption {
    ($place:literal; $($statement:stmt); *;) => {
        let __frame_consumption_before = crate::mm::unallocated_frames();
        $($statement)*
        let __frame_consumption_after = crate::mm::unallocated_frames();
        log::debug!("[{}] consumed frames: {}, last frames: {}", $place, (__frame_consumption_before - __frame_consumption_after) as isize, __frame_consumption_after)
    };
    ($place:literal, $before:ident) => {
        log::debug!(
            "[{}] consumed frames:{}, last frames:{}",
            $place,
            ($before - crate::mm::unallocated_frames()) as isize,
            crate::mm::unallocated_frames()
        );
    };
}
