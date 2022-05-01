use super::{elf_cache::try_remove_elf, PhysAddr, PhysPageNum};
use crate::{
    config::{MEMORY_END, PAGE_SIZE},

};
// KISS
use alloc::{sync::Arc, vec::Vec};
use core::fmt::{self, Debug, Formatter};
use lazy_static::*;
use spin::RwLock;

pub struct FrameTracker {
    pub ppn: PhysPageNum,
}

impl FrameTracker {
    pub fn new(ppn: PhysPageNum) -> Self {
        // page cleaning
        let bytes_array = ppn.get_bytes_array();
        for i in bytes_array {
            *i = 0;
        }
        Self { ppn }
    }
}

impl Debug for FrameTracker {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("FrameTracker:PPN={:#x}", self.ppn.0))
    }
}

impl Drop for FrameTracker {
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
    fn dealloc(&mut self, ppn: PhysPageNum) {
        let ppn = ppn.0;
        // validity check
        if option_env!("MODE") == Some("debug") && ppn >= self.current || self.recycled.iter().find(|&v| *v == ppn).is_some() {
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

pub fn frame_alloc() -> Option<Arc<FrameTracker>> {
    let ret = FRAME_ALLOCATOR
        .write()
        .alloc()
        .map(|ppn| Arc::new(FrameTracker::new(ppn)));
    if ret.is_some() {
        ret
    } else {
        log::info!("Hit GC");
        try_remove_elf(super::elf_cache::ELF_CACHE.read(), None);
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
macro_rules! show_frame_consumption {
    ($place:literal; $($statement:stmt); *;) => {
        let __frame_consumption_before = crate::mm::unallocated_frames();
        $($statement)*
        let __frame_consumption_after = crate::mm::unallocated_frames();
        debug!("[{}] consumed frames: {}, last frames: {}", $place, (__frame_consumption_before - __frame_consumption_after) as isize, __frame_consumption_after)
    };
    ($place:literal, $before:ident) => {
        debug!(
            "[{}] consumed frames:{}, last frames:{}",
            $place,
            ($before - crate::mm::unallocated_frames()) as isize,
            crate::mm::unallocated_frames()
        );
    };
}
