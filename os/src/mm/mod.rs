mod address;
mod frame_allocator;
mod heap_allocator;
mod memory_set;
mod page_table;

use address::VPNRange;
pub use address::{PhysAddr, PhysPageNum, StepByOne, VirtAddr, VirtPageNum};
pub use frame_allocator::{
    frame_alloc, frame_dealloc, push_elf_area, unallocated_frames, FrameTracker,
};
pub use memory_set::remap_test;
pub use memory_set::{
    kernel_token, mmap, munmap, sbrk, MapFlags, MapPermission, MemorySet, KERNEL_SPACE,
};
use page_table::PTEFlags;
pub use page_table::{
    copy_from_user, copy_to_user, translated_array_copy, translated_byte_buffer, translated_ref,
    translated_refmut, translated_str, PageTable, PageTableEntry, UserBuffer, UserBufferIterator,
};

pub fn init() {
    heap_allocator::init_heap();
    frame_allocator::init_frame_allocator();
    KERNEL_SPACE.lock().activate();
}

#[macro_export]
/// Convert user pointer trg to `Some(*trg)` or `None` if null.
macro_rules! move_ptr_to_opt {
    ($trg:ident) => {
        if $trg != null() {
            let t = *translated_ref(current_user_token(), $trg);
            Some(t)
        } else {
            None
        }
    };
    ($token:ident,$trg:ident) => {
        if $trg != null() {
            let t = *translated_ref($token, $trg);
            Some(t)
        } else {
            None
        }
    };
}

#[macro_export]
/// Convert user pointer `trg:*const T` to `Some(trg as & T)` or `None` if null.
macro_rules! ptr_to_opt_ref {
    ($trg:ident) => {
        if $trg != null() {
            Some(translated_ref(current_user_token(), $trg))
        } else {
            None
        }
    };
    ($token:ident,$trg:ident) => {
        if $trg != null() {
            Some(translated_ref($token, $trg))
        } else {
            None
        }
    };
}

#[macro_export]
/// Convert user pointer `trg:*mut T` to `Some(trg as &mut T)` or `None` if null.
macro_rules! ptr_to_opt_ref_mut {
    ($trg:ident) => {
        if $trg != null_mut() {
            Some(translated_refmut(current_user_token(), $trg))
        } else {
            None
        }
    };
    ($token:ident,$trg:ident) => {
        if $trg != null_mut() {
            Some(translated_refmut($token, $trg))
        } else {
            None
        }
    };
}
