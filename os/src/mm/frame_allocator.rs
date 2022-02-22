use super::{memory_set::MapArea, PhysAddr, PhysPageNum};
use crate::config::MEMORY_END;
use alloc::{string::String, sync::Arc, vec::Vec};
use core::fmt::{self, Debug, Error, Formatter, Result};
use k210_hal::cache::Uncache;
use lazy_static::*;
use spin::Mutex;

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
    elfs: Vec<Arc<ElfAreas>>,
}

impl StackFrameAllocator {
    pub fn init(&mut self, l: PhysPageNum, r: PhysPageNum) {
        self.current = l.0;
        self.end = r.0;
        println!("last {} Physical Frames.", self.end - self.current);
    }
    pub fn unallocated_frames(&mut self) -> usize {
        self.recycled.len() + self.end - self.current
    }
}
impl FrameAllocator for StackFrameAllocator {
    fn new() -> Self {
        Self {
            current: 0,
            end: 0,
            recycled: Vec::new(),
            elfs: Vec::new(),
        }
    }
    fn alloc(&mut self) -> Option<PhysPageNum> {
        if let Some(ppn) = self.recycled.pop() {
            Some(ppn.into())
        } else {
            if self.current == self.end {
                //attempt to recycle the cached elfs
                for i in 0..self.elfs.len() {
                    if Arc::strong_count(&self.elfs[i]) == 1 {
                        self.elfs.remove(i);
                    }
                }
                //try poping recycled again
                self.recycled.pop().map(|x| x.into())
            } else {
                self.current += 1;
                Some((self.current - 1).into())
            }
        }
    }
    fn dealloc(&mut self, ppn: PhysPageNum) {
        let ppn = ppn.0;
        // validity check
        if ppn >= self.current || self.recycled.iter().find(|&v| *v == ppn).is_some() {
            panic!("Frame ppn={:#x} has not been allocated!", ppn);
        }
        // recycle
        self.recycled.push(ppn);
    }
}

type FrameAllocatorImpl = StackFrameAllocator;

lazy_static! {
    pub static ref FRAME_ALLOCATOR: Mutex<FrameAllocatorImpl> =
        Mutex::new(FrameAllocatorImpl::new());
}
pub fn push_elf_area(path: String, len: usize) -> Result {
    //    FRAME_ALLOCATOR.lock().push_elf_area(path, len)
    let lock = FRAME_ALLOCATOR.lock();
    let v = lock.elfs.iter().find(|now| now.path == path);
    if v.is_none() {
        drop(lock);
        let area = ElfAreas {
            areas: crate::mm::KERNEL_SPACE
                .lock()
                .insert_program_area(
                    crate::config::MMAP_BASE.into(),
                    (crate::config::MMAP_BASE + len).into(),
                    crate::mm::MapPermission::R | crate::mm::MapPermission::W,
                )
                .unwrap(),
            path,
        };
        FRAME_ALLOCATOR.lock().elfs.push(Arc::new(area));
        Err(core::fmt::Error)
    } else {
        crate::mm::KERNEL_SPACE
            .lock()
            .push_no_alloc(v.unwrap().clone())
    }
}
pub fn init_frame_allocator() {
    extern "C" {
        fn ekernel();
    }
    FRAME_ALLOCATOR.lock().init(
        PhysAddr::from(ekernel as usize).ceil(),
        PhysAddr::from(MEMORY_END).floor(),
    );
}

pub fn frame_alloc() -> Option<Arc<FrameTracker>> {
    FRAME_ALLOCATOR
        .lock()
        .alloc()
        .map(|ppn| Arc::new(FrameTracker::new(ppn)))
}

pub fn frame_dealloc(ppn: PhysPageNum) {
    FRAME_ALLOCATOR.lock().dealloc(ppn);
}

pub fn unallocated_frames() -> usize {
    FRAME_ALLOCATOR.lock().unallocated_frames()
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
#[derive(Clone)]
pub struct ElfAreas {
    pub areas: MapArea,
    path: String,
}
