use super::{frame_allocator::free_space_size_rdlock, memory_set::MapArea};
use crate::fs::FileLike;
// KISS
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Result;
use lazy_static::*;
use log::info;
use spin::{RwLock, RwLockReadGuard};

lazy_static! {
    /// The static global struct to store the ELF MapAreas.
    pub static ref ELF_CACHE: RwLock<Vec<MapArea>> = RwLock::new(Vec::new());
}
/// Push the elf area if found, or try to allocate space for reading in.
/// If no space is left, a GC through `try_remove()` will be triggered.
pub fn push_elf_area(file: Arc<crate::fs::OSInode>) -> Result {
    let len: usize = file.size();
    let rd = ELF_CACHE.read();
    let elf_file = rd.iter().find(|now| {
        if let FileLike::Regular(ref i) = now.map_file.as_ref().unwrap() {
            i.get_ino() == file.get_ino()
        } else {
            false
        }
    });
    if elf_file.is_some() {
        return crate::mm::KERNEL_SPACE
            .lock()
            .push_no_alloc(elf_file.unwrap());
    }
    //else: elf_file.is_none():
    if len > free_space_size_rdlock() {
        log::info!("[push_elf_area] No more space. Trying to replace the saved elfs");
        try_remove_elf(rd, Some(len));
        if len > free_space_size_rdlock() {
            panic!("[push_elf_area] No space left.")
        }
    } else {
        drop(rd);
    }
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
    ELF_CACHE.write().push(i);
    Err(core::fmt::Error)
}
/// The ELF vec garbage collector that consumes a `ELF_CACHE.read()` guard.
/// # Note
/// The `len_exp` is not yet in use.
pub fn try_remove_elf(rd: RwLockReadGuard<Vec<MapArea>>, len_exp: Option<usize>) {
    info!("[elf_cache] Trying to remove a cached file.");
    let mut v = Vec::new();
    let acc_size = 0;
    for i in (0..rd.len()).rev() {
        if rd[i].file_ref().unwrap() == 1 {
            info!(
                "[push_elf_area] file {} has file_ref {}",
                i,
                rd[i].file_ref().unwrap()
            );
            v.push(i);
            /* if len_exp.is_some() {
             *     acc_size += if let FileLike::Regular(f) = rd[i].map_file.unwrap() {
             *         f.get_size()
             *     } else {
             *         0
             *     };
             *     if acc_size >= len_exp.unwrap() {
             *         break;
             *     }
             * }
             */
        }
    }
    drop(rd);
    for i in v {
        ELF_CACHE.write().remove(i);
    }
}
