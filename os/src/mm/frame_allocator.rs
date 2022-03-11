use super::{memory_set::MapArea, PhysAddr, PhysPageNum};
use crate::{
    config::{MEMORY_END, PAGE_SIZE},
    fs::FileLike,
};
// KISS
use alloc::{string::String, sync::Arc, vec::Vec};
use core::fmt::{self, Debug, Error, Formatter, Result};
use k210_hal::cache::Uncache;
use lazy_static::*;
use log::info;
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
    pub elfs: Vec<MapArea>,
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
                    if self.elfs[i].file_ref().unwrap() == 1 {
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
    pub static ref FRAME_ALLOCATOR: RwLock<FrameAllocatorImpl> =
        RwLock::new(FrameAllocatorImpl::new());
}
pub fn push_elf_area(file: Arc<crate::fs::OSInode>, len: usize) -> Result {
    //    FRAME_ALLOCATOR.lock().push_elf_area(path, len)
    let rd = FRAME_ALLOCATOR.read();
    if len > rd.free_space_size() {
        log::info!("[push_elf_area] No more space. Trying to replace the saved elfs");
        let mut v = Vec::new();
        for i in rd.elfs.iter().enumerate() {
            if i.1.file_ref().unwrap() == 1 {
                info!("{}", i.1.file_ref().unwrap());
                v.push(i.0);
            }
        }
        drop(rd);
        for i in v {
            FRAME_ALLOCATOR.write().elfs.remove(i);
        }
        if len > FRAME_ALLOCATOR.read().free_space_size() {
            panic!("[push_elf_area] No space left.")
        }
    } else {
        drop(rd);
    }
    let lock = FRAME_ALLOCATOR.read();
    let v = lock.elfs.iter().find(|now| {
        if let FileLike::Regular(ref i) = now.map_file.as_ref().unwrap() {
            i.get_ino() == file.get_ino()
        } else {
            false
        }
    });
    if v.is_none() {
        drop(lock);
        let mut i = crate::mm::KERNEL_SPACE
            .lock()
            .insert_program_area(
                crate::config::MMAP_BASE.into(),
                (crate::config::MMAP_BASE + len).into(),
                crate::mm::MapPermission::R | crate::mm::MapPermission::W,
            )
            .unwrap();
        i.map_file = Some(FileLike::Regular(file));
        // Note: i must be assigned before being pushed into the frame allocator.
        FRAME_ALLOCATOR.write().elfs.push(i);
        Err(core::fmt::Error)
    } else {
        crate::mm::KERNEL_SPACE.lock().push_no_alloc(v.unwrap())
    }
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
    FRAME_ALLOCATOR
        .write()
        .alloc()
        .map(|ppn| Arc::new(FrameTracker::new(ppn)))
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
