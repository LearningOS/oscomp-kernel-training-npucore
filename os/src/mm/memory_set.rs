use super::{frame_alloc, FrameTracker};
use super::{translated_byte_buffer, UserBuffer};
use super::{PTEFlags, PageTable, PageTableEntry};
use super::{PhysAddr, PhysPageNum, VirtAddr, VirtPageNum};
use super::{StepByOne, VPNRange};
use crate::config::*;
use crate::fs::{File, FileDescriptor, FileLike};
use crate::task::{current_task, AuxHeader, FdTable};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::borrow::BorrowMut;
//use proc_macro::Spacing;
use core::fmt::{Error, Result};
use core::iter::Map;
use core::panic;
use lazy_static::*;
use log::{debug, error, info, trace, warn};
use riscv::register::satp;
use spin::Mutex;
use core::arch::asm;

extern "C" {
    fn stext();
    fn etext();
    fn srodata();
    fn erodata();
    fn sdata();
    fn edata();
    fn sbss_with_stack();
    fn ebss();
    fn ekernel();
    fn strampoline();
    fn ssignaltrampoline();
}

lazy_static! {
    pub static ref KERNEL_SPACE: Arc<Mutex<MemorySet>> =
        Arc::new(Mutex::new(MemorySet::new_kernel()));
}

pub fn kernel_token() -> usize {
    KERNEL_SPACE.lock().token()
}
/// The memory "space" as in user space or kernel space
pub struct MemorySet {
    page_table: PageTable,
    /// The mapped area.
    /// Segments are implemented using this mechanism. In other words, they may be considered a subset of MapArea.
    /// Yet, other purposes may exist in this struct, such as file mapping.
    areas: Vec<MapArea>,
    /// The pointer to store the heap area in order to ease the heap lookup and allocation/CoW.
    heap_area_idx: Option<usize>,
}

impl MemorySet {
    // pub fn munmap(&mut self, start: usize, len: usize) -> i32 {
    //     info!("[munmap] Trying to unmap start area beg. with {}.", start);
    //     if len == 0 {
    //         return 0;
    //     }
    //     if let Some((i, m)) = self
    //         .areas
    //         .iter_mut()
    //         .enumerate()
    //         .find(|(_, area)| area.vpn_range.get_start() == VirtAddr::from(start).floor())
    //     {
    //         for vpn in m.vpn_range {
    //             match m.map_type {
    //                 MapType::Framed => {
    //                     debug!(
    //                         "[munmap] Removing {}",
    //                         (m.data_frames.get(&vpn).unwrap()).ppn.0
    //                     );
    //                     m.data_frames.remove(&vpn);
    //                 }
    //                 _ => {}
    //             }
    //             if !self.page_table.is_mapped(vpn) {
    //                 unsafe {
    //                     llvm_asm!("sfence.vma" :::: "volatile");
    //                 }
    //                 return -1;
    //             }
    //             self.page_table.unmap(vpn);
    //         }
    //         self.areas.remove(i);
    //     } else {
    //         panic!("Wrong munmap");
    //         //return -1;
    //     }

    //     unsafe {
    //         llvm_asm!("sfence.vma" :::: "volatile");
    //     }
    //     return len as i32;
    // }
    // pub fn alloc(
    //     &mut self,
    //     start: usize,
    //     len: usize,
    //     prot: MapPermission,
    // ) -> Result {
    //     info!("[alloc] start: {}, len: {}, prot: {:?}", start, len, prot);
    //     if len == 0 || len > 0x1_000_000_000 {
    //         return Err(core::fmt::Error);
    //     }
    //     let area = MapArea::new(
    //         start.into(),
    //         (start + len).into(),
    //         MapType::Framed,
    //         prot,
    //         None,
    //     );
    //     self.push(area, None)
    //     if let Ok(_) = self.push(m, None) {
    //         return ((((start + len) - 1 + PAGE_SIZE) / PAGE_SIZE - start / PAGE_SIZE)
    //             * PAGE_SIZE) as i32;
    //     //this was the size
    //     } else {
    //         return -1;
    //     }
    // }
    /// 建立从文件到内存的映射
    // pub fn mmap(
    //     &mut self,
    //     mut start: usize, // 开始地址
    //     len: usize,       // 内存映射长度
    //     prot: usize,      // 保护位标志
    //     flags: usize,     // 映射方式
    //     fd: usize,        // 被映射文件
    //     offset: usize,    // 文件位移
    // ) -> i32 {
    //     let m: MapArea;
    //     //内存分配模块
    //     match flags {
    //         _ => {
    //             return -1;
    //         }
    //         MAP_PRIVATE => {
    //             if len == 0 {
    //                 return 0;
    //             }
    //             if (prot & 0x7 == 0) || (prot & !0x7 != 0) || len > 0x1_000_000_000 {
    //                 return -1;
    //             }
    //             let mut chk = MapPermission::R | MapPermission::W | MapPermission::X;
    //             let mut per: u8 = prot as u8;
    //             per = chk.bits() & per;
    //             chk = !chk;
    //             if (prot & (chk.bits() as usize)) != 0 {
    //                 return -1;
    //             }
    //             if let Some(i) = MapPermission::from_bits(per) {
    //                 m = MapArea::new(start.into(), (len + start).into(), MapType::Framed, i, None);
    //                 if let Ok(_) = self.push(m, None) {
    //                     unsafe {
    //                         llvm_asm!("sfence.vma" :::: "volatile");
    //                     }
    //                 /*                        return ((((start + len) - 1 + PAGE_SIZE) / PAGE_SIZE - start / PAGE_SIZE)
    //                  * PAGE_SIZE) as i32;*/
    //                 //this was the size
    //                 } else {
    //                     return -1;
    //                 }
    //             } else {
    //                 return -1;
    //             }
    //         }
    //     }
    //     unsafe { crate::syscall::fs::sys_read(fd, start as *const u8, len) as i32 }
    // }
    /// Create a new struct with no information at all.
    pub fn new_bare() -> Self {
        Self {
            page_table: PageTable::new(),
            areas: Vec::new(),
            heap_area_idx: None,
        }
    }
    /// Getter to the token of current memory space, or "this" page table.
    pub fn token(&self) -> usize {
        self.page_table.token()
    }
    /// Insert an anonymous segment containing the space between `start_va.floor()` to `end_va.ceil()`
    /// The space is allocated and added to the current MemorySet.
    /// # Prerequisite
    /// Assuming no conflicts. In other words, the space is NOT checked for space validity or overlap.
    /// It is merely mapped, pushed into the current memory set.
    /// Since CoW is implemented, the space is NOT allocated until a page fault is triggered.
    pub fn insert_framed_area(
        &mut self,
        start_va: VirtAddr,
        end_va: VirtAddr,
        permission: MapPermission,
    ) {
        self.push(
            MapArea::new(start_va, end_va, MapType::Framed, permission, None),
            None,
        );
    }
    /// Insert an anonymous segment containing the space between `start_va.floor()` to `end_va.ceil()`
    /// The space is allocated and added to the current MemorySet.
    /// # Prerequisite
    /// Assuming no conflicts. In other words, the space is NOT checked for space validity or overlap.
    /// It is merely mapped, pushed into the current memory set.
    /// Since CoW is implemented, the space is NOT allocated until a page fault is triggered.
    pub fn insert_program_area(
        &mut self,
        start_va: VirtAddr,
        end_va: VirtAddr,
        permission: MapPermission,
    ) -> Option<MapArea> {
        let mut map_area = MapArea::new(start_va, end_va, MapType::Framed, permission, None);
        if let Err(_) = map_area.map(&mut self.page_table) {
            return None;
        }
        self.areas.push(map_area.clone());
        Some(map_area)
    }
    pub fn remove_area_with_start_vpn(&mut self, start_vpn: VirtPageNum) {
        if let Some((idx, area)) = self
            .areas
            .iter_mut()
            .enumerate()
            .find(|(_, area)| area.vpn_range.get_start() == start_vpn)
        {
            area.unmap(&mut self.page_table);
            self.areas.remove(idx);
        }
    }
    /// Push a not-yet-mapped map_area into current MemorySet and copy the data into it if any, allocating the needed memory for the map.
    fn push(&mut self, mut map_area: MapArea, data: Option<&[u8]>) -> Result {
        if let Err(_) = map_area.map(&mut self.page_table) {
            return Err(core::fmt::Error);
        }
        if let Some(data) = data {
            map_area.copy_data(&mut self.page_table, data, 0);
        }
        self.areas.push(map_area);
        Ok(())
    }
    fn push_with_offset(&mut self, mut map_area: MapArea, offset: usize, data: Option<&[u8]>) {
        map_area.map(&mut self.page_table);
        if let Some(data) = data {
            map_area.copy_data(&mut self.page_table, data, offset);
        }
        self.areas.push(map_area);
    }
    /// Push the map area into the memory set without copying or allocation.
    pub fn push_no_alloc(&mut self, map_area: &MapArea) -> Result {
        for (vpn, frame) in &map_area.data_frames {
            if !self.page_table.is_mapped(*vpn) {
                //if not mapped
                let pte_flags = PTEFlags::from_bits(map_area.map_perm.bits).unwrap();
                self.page_table.map(*vpn, frame.ppn.clone(), pte_flags);
            } else {
                return Err(Error);
            }
        }
        self.areas.push(map_area.clone());
        Ok(())
    }
    pub fn find_mmap_area_end(&self) -> VirtAddr {
        let idx = self.areas.len() - 3;
        let map_end = self.areas[idx].vpn_range.get_end().into();
        debug!("[find_mmap_area_end] map_end: {:?}", map_end);
        if map_end > MMAP_BASE.into() {
            map_end
        } else {
            MMAP_BASE.into()
        }
    }
    // pub fn get_map_perm(&self, addr: VirtAddr) -> MapPermission {
    //     let vpn = addr.floor();
    //     for area in self.areas.iter() {
    //         if area.vpn_range.get_start() <= vpn && vpn < area.vpn_range.get_end() {
    //             return area.map_perm;
    //         }
    //     }
    //     MapPermission::empty()
    // }
    // fn find_area(&self, addr: VirtAddr, perm: MapPermission) -> Option<&mut MapArea> {
    //     let vpn = addr.floor();
    //     for area in self.areas.iter_mut().find(|area| {
    //         area.map_perm.contains(perm) && area.vpn_range.get_start() <= vpn && vpn < area.vpn_range.get_end()
    //     }) {
    //         if area.vpn_range.get_start() <= vpn && vpn < area.vpn_range.get_end() {
    //             return Some(area);
    //         }
    //     }
    //     None
    // }
    /// The REAL handler to page fault.
    /// Handles all types of page fault:(In regex:) "(Store|Load|Instruction)(Page)?Fault"
    /// Checks the permission to decide whether to copy.
    pub fn do_page_fault(&mut self, addr: VirtAddr) -> Result {
        let vpn = addr.floor();
        if let Some(area) = self.areas.iter_mut().find(|area| {
            area.map_perm.contains(MapPermission::R | MapPermission::U)// If there is such a page in user space
                && area.vpn_range.get_start() <= vpn// ...and the addr is in the vpn range
                && vpn < area.vpn_range.get_end()
        }) {
            let result = area.map_one(&mut self.page_table, vpn); // attempt to map
            if result.is_ok() {
                // if mapped successfully,
                // in other words, not previously mapped before last statement(let result = ...)
                info!("[do_page_fault] addr: {:?}, solution: lazy alloc", addr);
                Ok(())
            } else {
                //mapped before the assignment
                if area.map_perm.contains(MapPermission::W) {
                    info!("[do_page_fault] addr: {:?}, solution: copy on write", addr);
                    // Whoever triggers this fault shall cause the area to be copied into a new area.
                    area.copy_on_write(&mut self.page_table, vpn)
                } else {
                    // Is it a memory exhaustion?
                    Err(core::fmt::Error)
                }
            }
        } else {
            // In all segments, nothing matches the requirements. Throws.
            error!("[do_page_fault] addr: {:?}, result: bad addr", addr);
            Err(core::fmt::Error)
        }
    }
    pub fn expend_area_to(&mut self, idx: usize, new_end: VirtAddr) -> Result {
        if idx >= self.areas.len() {
            return Err(core::fmt::Error);
        }
        let area = &mut self.areas[idx];
        let end_vpn: VirtPageNum = new_end.ceil();
        for vpn in VPNRange::new(area.vpn_range.get_end(), end_vpn) {
            if let Err(_) = area.map_one(&mut self.page_table, vpn) {
                return Err(core::fmt::Error);
            }
        }
        area.vpn_range = VPNRange::new(area.vpn_range.get_start(), end_vpn);
        Ok(())
    }
    pub fn shrink_area_to(&mut self, idx: usize, new_end: VirtAddr) -> Result {
        if idx >= self.areas.len() {
            return Err(core::fmt::Error);
        }
        let area = &mut self.areas[idx];
        let end_vpn: VirtPageNum = new_end.ceil();
        for vpn in VPNRange::new(end_vpn, area.vpn_range.get_end()) {
            if let Err(_) = area.unmap_one(&mut self.page_table, vpn) {
                return Err(core::fmt::Error);
            }
        }
        area.vpn_range = VPNRange::new(area.vpn_range.get_start(), end_vpn);
        Ok(())
    }
    /// Mention that trampoline is not collected by areas.
    fn map_trampoline(&mut self) {
        self.page_table.map(
            VirtAddr::from(TRAMPOLINE).into(),
            PhysAddr::from(strampoline as usize).into(),
            PTEFlags::R | PTEFlags::X,
        );
    }
    /// Can be accessed in user mode.
    fn map_signaltrampoline(&mut self) {
        self.page_table.map(
            VirtAddr::from(SIGNAL_TRAMPOLINE).into(),
            PhysAddr::from(ssignaltrampoline as usize).into(),
            PTEFlags::R | PTEFlags::X | PTEFlags::U,
        );
    }
    /// Create an empty kernel space.
    /// Without kernel stacks. (Is it done with .bss?)
    pub fn new_kernel() -> Self {
        let mut memory_set = Self::new_bare();
        // map trampoline
        memory_set.map_trampoline();
        // map kernel sections
        println!(".text [{:#x}, {:#x})", stext as usize, etext as usize);
        println!(".rodata [{:#x}, {:#x})", srodata as usize, erodata as usize);
        println!(".data [{:#x}, {:#x})", sdata as usize, edata as usize);
        println!(
            ".bss [{:#x}, {:#x})",
            sbss_with_stack as usize, ebss as usize
        );
        macro_rules! anon_ident_map {
            ($beg:expr,$end:expr,$extra_per:ident) => {
                memory_set.push(
                    MapArea::new(
                        ($beg as usize).into(),
                        ($end as usize).into(),
                        MapType::Identical,
                        MapPermission::R | MapPermission::$extra_per,
                        None,
                    ),
                    None,
                );
            };
            ($name:literal,$beg:expr,$end:expr,$extra_per:ident) => {
                println!("mapping {}", $name);
                anon_ident_map!($beg, $end, $extra_per);
            };
        }
        anon_ident_map!(".text section", stext, etext, X);
        anon_ident_map!(".rodata section", srodata, erodata, R); // read only section
        anon_ident_map!(".data section", sdata, edata, W);
        anon_ident_map!(".bss section", sbss_with_stack, ebss, W);
        anon_ident_map!("physical memory", ekernel, MEMORY_END, W);

        println!("mapping memory-mapped registers");
        for pair in MMIO {
            anon_ident_map!((*pair).0, ((*pair).0 + (*pair).1), W);
        }
        memory_set
    }
    /// Include sections in elf and trampoline and TrapContext and user stack,
    /// also returns user_sp and entry point.
    pub fn from_elf(elf_data: &[u8]) -> (Self, usize, usize, usize, Vec<AuxHeader>) {
        let mut memory_set = Self::new_bare();
        // map trampoline
        memory_set.map_trampoline();
        // map signaltrampoline
        memory_set.map_signaltrampoline();
        // map program headers of elf, with U flag
        let elf = xmas_elf::ElfFile::new(elf_data).unwrap();
        let elf_header = elf.header;
        assert_eq!(
            // assert magic number is equal to ELF.
            // to verify the elf file format.
            elf_header.pt1.magic,
            [0x7f, 0x45, 0x4c, 0x46],
            "invalid elf!"
        );
        let ph_count = elf_header.pt2.ph_count();
        let mut max_end_vpn = VirtPageNum(0);
        let mut head_va = 0; // top va of ELF which points to ELF header

        let mut auxv: Vec<AuxHeader> = [
            // push ELF related auxillary vectors to auxv: Vec<AuxHeader>
            //(aux_type,value)
            (AT_PHENT, elf.header.pt2.ph_entry_size() as usize as usize),
            (AT_PHNUM, ph_count as usize),
            (AT_PAGESZ, PAGE_SIZE as usize),
            (AT_BASE, 0 as usize),
            (AT_FLAGS, 0 as usize),
            (AT_ENTRY, elf.header.pt2.entry_point() as usize),
            (AT_UID, 0 as usize),
            (AT_EUID, 0 as usize),
            (AT_GID, 0 as usize),
            (AT_EGID, 0 as usize),
            (AT_PLATFORM, 0 as usize),
            (AT_HWCAP, 0 as usize),
            (AT_CLKTCK, 100 as usize),
            (AT_SECURE, 0 as usize),
            (AT_NOTELF, 0x112d as usize),
        ]
        .iter()
        .map(|cur| -> AuxHeader {
            AuxHeader {
                aux_type: cur.0,
                value: cur.1,
            }
        })
        .collect::<Vec<AuxHeader>>();

        let mut count = 0;
        for ph in elf.program_iter() {
            // Map only when the sections that is to be loaded.
            if ph.get_type().unwrap() == xmas_elf::program::Type::Load {
                let start_va: VirtAddr = (ph.virtual_addr() as usize).into();
                let end_va: VirtAddr = ((ph.virtual_addr() + ph.mem_size()) as usize).into();
                let offset = start_va.0 - start_va.floor().0 * PAGE_SIZE;

                let mut map_perm = MapPermission::U;
                let ph_flags = ph.flags();
                if ph_flags.is_read() {
                    map_perm |= MapPermission::R;
                }
                if ph_flags.is_write() {
                    map_perm |= MapPermission::W;
                }
                if ph_flags.is_execute() {
                    map_perm |= MapPermission::X;
                }
                let mut map_area = MapArea::new(start_va, end_va, MapType::Framed, map_perm, None);
                max_end_vpn = map_area.vpn_range.get_end();
                if offset == 0 && ph.file_size() != 0 && !map_perm.contains(MapPermission::W) {
                    assert_eq!(ph.offset() % 0x1000, 0);
                    assert_eq!(
                        VirtAddr::from(ph.file_size() as usize).ceil().0,
                        map_area.vpn_range.get_end().0 - map_area.vpn_range.get_start().0
                    );

                    head_va = start_va.into();
                    let kernel_start_vpn =
                        (VirtAddr::from(MMAP_BASE + (ph.offset() as usize))).floor();
                    map_area.map_kernel_shared(&mut memory_set.page_table, kernel_start_vpn);
                    memory_set.areas.push(map_area);
                    // memory_set.push(
                    //     map_area,
                    //     Some(&elf.input
                    //         [ph.offset() as usize..(ph.offset() + ph.file_size()) as usize]),
                    // );
                } else {
                    if map_perm.contains(MapPermission::W) {
                        warn!("[memory_set.from_elf] W! memory size:{}", ph.mem_size());
                    }
                    memory_set.push_with_offset(
                        map_area,
                        offset,
                        Some(
                            &elf.input
                                [ph.offset() as usize..(ph.offset() + ph.file_size()) as usize],
                        ),
                    );
                }
                count = count + 1;
                trace!("[elf] LOAD SEGMENT PUSHED. start_va = 0x{:X}; end_va = 0x{:X}, offset = 0x{:X}", start_va.0, end_va.0, offset);
            }
        }

        // Get ph_head addr for auxv
        let ph_head_addr = head_va + elf.header.pt2.ph_offset() as usize;
        auxv.push(AuxHeader {
            aux_type: AT_PHDR,
            value: ph_head_addr as usize,
        });

        let max_end_va: VirtAddr = max_end_vpn.into();
        let mut user_heap_bottom: usize = max_end_va.into();
        // guard page
        user_heap_bottom += PAGE_SIZE;
        memory_set.heap_area_idx = Some(count);

        // Map USER_STACK
        memory_set.push(
            MapArea::new(
                USER_STACK_TOP.into(),
                USER_STACK_BOTTOM.into(),
                MapType::Framed,
                MapPermission::R | MapPermission::W | MapPermission::U,
                None,
            ),
            None,
        );
        trace!(
            "[elf] USER STACK PUSHED. user_stack_top:{:X}; user_stack_bottom:{:X}",
            USER_STACK_TOP,
            USER_STACK_BOTTOM
        );
        // memory_set.push(MapArea::new(
        //     user_signal_stack_bottom.into(),
        //     user_signal_stack_top.into(),
        //     MapType::Framed,
        //     MapPermission::R | MapPermission::W | MapPermission::U,
        // ), None);
        // trace!(
        //     "[elf] USER SIGNAL STACK PUSHED. user_signal_stack_top:{:X}; user_signal_stack_bottom:{:X}",
        //     user_signal_stack_top,
        //     user_signal_stack_bottom
        // );

        // Map TrapContext
        memory_set.push(
            MapArea::new(
                TRAP_CONTEXT.into(),
                TRAMPOLINE.into(),
                MapType::Framed,
                MapPermission::R | MapPermission::W,
                None,
            ),
            None,
        );
        trace!(
            "[elf] TRAP CONTEXT PUSHED. start_va:{:X}; end_va:{:X}",
            TRAP_CONTEXT,
            TRAMPOLINE
        );

        //return
        (
            memory_set,
            USER_STACK_BOTTOM,
            user_heap_bottom,
            elf.header.pt2.entry_point() as usize,
            auxv,
        )
    }
    pub fn from_existed_user(user_space: &mut MemorySet) -> MemorySet {
        let mut memory_set = Self::new_bare();
        // map trampoline
        memory_set.map_trampoline();
        // map signaltrampoline
        memory_set.map_signaltrampoline();
        // map data sections/user heap/mmap area/user stack
        for i in 0..user_space.areas.len() - 1 {
            let mut new_area = user_space.areas[i].clone();
            new_area.map_shared(&mut memory_set.page_table, &mut user_space.page_table);
            memory_set.areas.push(new_area);
            debug!(
                "[fork] map shared area: {:?}",
                user_space.areas[i].vpn_range
            );
        }
        // copy trap context area
        let trap_cx_area = user_space.areas.last().unwrap();
        let area = MapArea::from_another(trap_cx_area);
        memory_set.push(area, None);
        for vpn in trap_cx_area.vpn_range {
            let src_ppn = user_space.translate(vpn).unwrap().ppn();
            let dst_ppn = memory_set.translate(vpn).unwrap().ppn();
            dst_ppn
                .get_bytes_array()
                .copy_from_slice(src_ppn.get_bytes_array());
        }
        debug!("[fork] copy trap_cx area: {:?}", trap_cx_area.vpn_range);

        memory_set
    }
    pub fn activate(&self) {
        let satp = self.page_table.token();
        unsafe {
            satp::write(satp);
            asm!("sfence.vma");
        }
    }
    /// Translate the `vpn` into its corresponding `Some(PageTableEntry)` in the current memory set if exists
    /// `None` is returned if nothing is found.
    pub fn translate(&self, vpn: VirtPageNum) -> Option<PageTableEntry> {
        self.page_table.translate(vpn)
    }
    pub fn set_pte_flags(&mut self, vpn: VirtPageNum, flags: MapPermission) -> Result {
        self.page_table.set_pte_flags(vpn, flags)
    }
    pub fn recycle_data_pages(&mut self) {
        //*self = Self::new_bare();
        self.areas.clear();
    }
}

#[derive(Clone)]
/// Map area for different segments or a chunk of memory for memory mapped file access.
pub struct MapArea {
    /// Range of the mapped virtual page numbers.
    /// Page aligned.
    vpn_range: VPNRange,
    /// Map physical page frame tracker to virtual pages for RAII & lookup.
    data_frames: BTreeMap<VirtPageNum, Arc<FrameTracker>>,
    /// Direct or framed(virtual) mapping?
    map_type: MapType,
    /// Permissions which are the or of RWXU, where U stands for user.
    map_perm: MapPermission,
    pub map_file: Option<FileLike>,
}

impl MapArea {
    /// Construct a new segment without without allocating memory
    pub fn new(
        start_va: VirtAddr,
        end_va: VirtAddr,
        map_type: MapType,
        map_perm: MapPermission,
        map_file: Option<FileLike>,
    ) -> Self {
        let start_vpn: VirtPageNum = start_va.floor();
        let end_vpn: VirtPageNum = end_va.ceil();
        trace!(
            "[MapArea new] start_vpn:{:X}; end_vpn:{:X}; map_perm:{:?}",
            start_vpn.0,
            end_vpn.0,
            map_perm
        );
        Self {
            vpn_range: VPNRange::new(start_vpn, end_vpn),
            data_frames: BTreeMap::new(),
            map_type,
            map_perm,
            map_file,
        }
    }
    /// Return the reference count to the currently using file if exists.
    pub fn file_ref(&self) -> Option<usize> {
        let ret = self.map_file.as_ref().map(|x| match &x {
            &FileLike::Regular(ref i) => Arc::strong_count(i),
            &FileLike::Abstract(ref i) => Arc::strong_count(i),
        });
        info!("[file_ref] {}", ret.unwrap());
        ret
    }
    /// Copier, but the physical pages are not allocated,
    /// thus leaving `data_frames` empty.
    pub fn from_another(another: &MapArea) -> Self {
        Self {
            vpn_range: VPNRange::new(another.vpn_range.get_start(), another.vpn_range.get_end()),
            data_frames: BTreeMap::new(),
            map_type: another.map_type,
            map_perm: another.map_perm,
            map_file: another.map_file.clone(),
        }
    }
    /// Map an included page in current area.
    /// If the `map_type` is `Framed`, then physical pages shall be allocated by this function.
    /// Otherwise, where `map_type` is `Identical`,
    /// the virtual page will be mapped directly to the physical page with an identical address to the page.
    /// # Note
    /// Vpn should be in this map area, but the check is not enforced in this function!
    pub fn map_one(&mut self, page_table: &mut PageTable, vpn: VirtPageNum) -> Result {
        if !page_table.is_mapped(vpn) {
            //if not mapped
            let ppn: PhysPageNum;
            match self.map_type {
                MapType::Identical => {
                    ppn = PhysPageNum(vpn.0);
                }
                MapType::Framed => {
                    let frame = frame_alloc().unwrap();
                    ppn = frame.ppn;
                    self.data_frames.insert(vpn, frame);
                }
            }
            let pte_flags = PTEFlags::from_bits(self.map_perm.bits).unwrap();
            page_table.map(vpn, ppn, pte_flags);
            Ok(())
        } else {
            //mapped
            Err(core::fmt::Error)
        }
    }
    /// Unmap a page in current area.
    /// If it is framed, then the physical pages will be removed from the `data_frames` Btree.
    /// This is unnecessary if the area is directly mapped.
    /// # Note
    /// Vpn should be in this map area, but the check is not enforced in this function!
    pub fn unmap_one(&mut self, page_table: &mut PageTable, vpn: VirtPageNum) -> Result {
        if !page_table.is_mapped(vpn) {
            return Err(core::fmt::Error);
        }
        match self.map_type {
            MapType::Framed => {
                self.data_frames.remove(&vpn);
            }
            _ => {}
        }
        page_table.unmap(vpn);
        Ok(())
    }
    /// Map & allocate all virtual pages in current area to physical pages in the page table.
    pub fn map(&mut self, page_table: &mut PageTable) -> Result {
        for vpn in self.vpn_range {
            if let Err(_) = self.map_one(page_table, vpn) {
                return Err(core::fmt::Error);
            }
        }
        Ok(())
    }
    /// Map the same area in `self` from `dst_ptab` to `src_ptab`, sharing the same physical address.
    /// Convert map areas to physical pages.
    /// # Of Course...
    /// Since the area is shared, the pages have been allocated.
    /// # Argument
    /// `dst_ptab`: The destination to be mapped into.
    /// `src_ptab`: The source to be mapped from. This is also the page table where `self` should be included.
    pub fn map_shared(&mut self, dst_ptab: &mut PageTable, src_ptab: &mut PageTable) -> Result {
        let map_perm = self.map_perm.difference(MapPermission::W);
        let pte_flags = PTEFlags::from_bits(map_perm.bits).unwrap();
        for vpn in self.vpn_range {
            if let Some(pte) = src_ptab.translate_refmut(vpn) {
                let ppn = pte.ppn();
                if !dst_ptab.is_mapped(vpn) {
                    dst_ptab.map(vpn, ppn, pte_flags);
                    pte.set_permission(map_perm);
                } else {
                    return Err(core::fmt::Error);
                }
            }
        }
        Ok(())
    }
    /// Is it that this function is needed for the reason that kernel space may be directly mapped sometimes?
    pub fn map_kernel_shared(
        &mut self,
        page_table: &mut PageTable,
        kernel_start_vpn: VirtPageNum,
    ) -> Result {
        let kernel_space = KERNEL_SPACE.lock();
        let kernel_page_table = &kernel_space.page_table;
        let kernel_area = kernel_space.areas.last().unwrap();
        let pte_flags = PTEFlags::from_bits(self.map_perm.bits).unwrap();
        let mut src_vpn = kernel_start_vpn;
        for vpn in self.vpn_range {
            if let Some(pte) = kernel_page_table.translate(src_vpn) {
                let ppn = pte.ppn();
                if !page_table.is_mapped(vpn) {
                    let frame = kernel_area.data_frames.get(&src_vpn).unwrap();
                    self.data_frames.insert(vpn, frame.clone());
                    assert_eq!(ppn, frame.ppn);
                    page_table.map(vpn, ppn, pte_flags);
                } else {
                    error!("[map_kernel_shared] user vpn already mapped!");
                    return Err(core::fmt::Error);
                }
            } else {
                error!("[map_kernel_shared] kernel vpn invalid!");
                return Err(core::fmt::Error);
            }
            src_vpn = (src_vpn.0 + 1).into();
        }
        Ok(())
    }
    /// Unmap all pages in `self` from `page_table` using unmap_one()
    pub fn unmap(&mut self, page_table: &mut PageTable) -> Result {
        for vpn in self.vpn_range {
            if let Err(_) = self.unmap_one(page_table, vpn) {
                return Err(core::fmt::Error);
            }
        }
        Ok(())
    }
    /// data: start-aligned but maybe with shorter length
    /// assume that all frames were cleared before
    pub fn copy_data(&mut self, page_table: &mut PageTable, data: &[u8], offset: usize) {
        assert_eq!(self.map_type, MapType::Framed);
        let mut start: usize = 0;
        let mut page_offset: usize = offset;
        let mut current_vpn = self.vpn_range.get_start();
        let len = data.len();
        loop {
            let src = &data[start..len.min(start + PAGE_SIZE - page_offset)];
            let dst = &mut page_table
                .translate(current_vpn)
                .unwrap()
                .ppn()
                .get_bytes_array()[page_offset..(page_offset + src.len())];
            dst.copy_from_slice(src);

            start += PAGE_SIZE - page_offset;

            page_offset = 0;
            if start >= len {
                break;
            }
            current_vpn.step();
        }
    }
    pub fn copy_on_write(&mut self, page_table: &mut PageTable, vpn: VirtPageNum) -> Result {
        let old_frame = self.data_frames.remove(&vpn).unwrap();
        if Arc::strong_count(&old_frame) == 1 {
            // don't need to copy
            // push back old frame and set pte flags to allow write
            self.data_frames.insert(vpn, old_frame);
            page_table.set_pte_flags(vpn, self.map_perm);
            // Starting from this, the write (page) fault will not be triggered in this space,
            // for the pte permission now contains Write.
            trace!("[copy_on_write] no copy occurred");
        } else {
            // do copy in this case
            let old_ppn = old_frame.ppn;
            page_table.unmap(vpn);
            // alloc new frame
            let new_frame = frame_alloc().unwrap();
            let new_ppn = new_frame.ppn;
            self.data_frames.insert(vpn, new_frame);
            let pte_flags = PTEFlags::from_bits(self.map_perm.bits).unwrap();
            page_table.map(vpn, new_ppn, pte_flags);
            // copy data
            new_ppn
                .get_bytes_array()
                .copy_from_slice(old_ppn.get_bytes_array());
            trace!("[copy_on_write] copy occurred");
        }
        Ok(())
    }

    // pub fn map_file(
    //     &mut self,
    //     start_va: VirtAddr,
    //     len: usize,
    //     offset: usize,
    //     fd_table: FdTable,
    //     token: usize,
    // ) -> isize {
    //     let flags = MapFlags::from_bits(flags).unwrap();

    //     if let Some(file) = &fd_table[self.fd as usize] {
    //         match &file.file {
    //             FileLike::Regular(f) => {
    //                 f.set_offset(offset);
    //                 if !f.readable() {
    //                     return -1;
    //                 }
    //                 debug! {"[map file] The start_va is 0x{:X}, offset of file is {}", start_va.0, offset};
    //                 let read_len = f.read(UserBuffer::new(translated_byte_buffer(
    //                     token,
    //                     start_va.0 as *const u8,
    //                     len,
    //                 )));
    //                 trace! {"[map file] read {} bytes", read_len};
    //             }
    //             _ => {
    //                 return -1;
    //             }
    //         };
    //     } else {
    //         return -1;
    //     };
    //     return 1;
    // }
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum MapType {
    Identical,
    Framed,
}

bitflags! {
    pub struct MapPermission: u8 {
        const R = 1 << 1;
        const W = 1 << 2;
        const X = 1 << 3;
        const U = 1 << 4;
    }
}

bitflags! {
    pub struct MapFlags: usize {
        const MAP_SHARED            =   0x01;
        const MAP_PRIVATE           =   0x02;
        const MAP_SHARED_VALIDATE   =   0x03;
        const MAP_TYPE              =   0x0f;
        const MAP_FIXED             =   0x10;
        const MAP_ANONYMOUS         =   0x20;
        const MAP_NORESERVE         =   0x4000;
        const MAP_GROWSDOWN         =   0x0100;
        const MAP_DENYWRITE         =   0x0800;
        const MAP_EXECUTABLE        =   0x1000;
        const MAP_LOCKED            =   0x2000;
        const MAP_POPULATE          =   0x8000;
        const MAP_NONBLOCK          =   0x10000;
        const MAP_STACK             =   0x20000;
        const MAP_HUGETLB           =   0x40000;
        const MAP_SYNC              =   0x80000;
        const MAP_FIXED_NOREPLACE   =   0x100000;
        const MAP_FILE              =   0;
    }
}

pub fn mmap(
    start: usize,
    len: usize,
    prot: MapPermission,
    flags: MapFlags,
    fd: usize,
    offset: usize,
) -> usize {
    if start % PAGE_SIZE != 0 {
        panic!("[mmap] start not aligned.");
    }
    let len = if len == 0 { PAGE_SIZE } else { len };
    let task = current_task().unwrap();
    let mut inner = task.acquire_inner_lock();
    if start != 0 {
        // should change the map_perm of MapArea here
        // and maybe we should spilt a MapArea

        // "Start" va Already mapped
        // let mut startvpn = start / PAGE_SIZE;
        // while startvpn < (start + len) / PAGE_SIZE {
        //     if inner
        //         .memory_set
        //         .set_pte_flags(startvpn.into(), prot)
        //         == -1
        //     {
        //         panic!("mmap: start_va not mmaped");
        //     }
        //     startvpn += 1;
        // }
        start
    } else {
        // "Start" va not mapped
        let start_va = inner.memory_set.find_mmap_area_end();
        let mut new_area = MapArea::new(
            start_va,
            VirtAddr::from(start_va.0 + len),
            MapType::Framed,
            prot,
            None,
        );

        if !flags.contains(MapFlags::MAP_ANONYMOUS) {
            warn!("[mmap] Non-Anony call haven't been support yet!");
            if fd >= inner.fd_table.len() {
                return usize::MAX;
            }
            if let Some(fd) = &inner.fd_table[fd] {
                match &fd.file {
                    FileLike::Regular(inode) => {
                        if !inode.readable() {
                            return usize::MAX;
                        }
                        inode.set_offset(offset)
                    }
                    _ => {
                        return usize::MAX;
                    }
                }
                new_area.map_file = Some(fd.file.clone());
            } else {
                return usize::MAX;
            }
        }
        let idx = inner.memory_set.areas.len() - 2;
        inner.memory_set.areas.insert(idx, new_area);
        start_va.0
    }
}
pub fn munmap(start: usize, len: usize) -> isize {
    let task = current_task().unwrap();
    let mut inner = task.acquire_inner_lock();
    inner
        .memory_set
        .remove_area_with_start_vpn(VirtAddr::from(start).into());
    0
}

pub fn sbrk(increment: isize) -> usize {
    let task = current_task().unwrap();
    let inner = &mut task.acquire_inner_lock();
    let old_pt: usize = inner.heap_pt;
    let new_pt: usize = old_pt + increment as usize;
    if increment > 0 {
        let limit = inner.heap_bottom + USER_HEAP_SIZE;
        if new_pt > limit {
            warn!(
                "[sbrk] over the upperbond! upperbond: {:X}, old_pt: {:X}, new_pt: {:X}",
                limit, old_pt, new_pt
            );
            return old_pt;
        } else {
            let idx = inner.memory_set.heap_area_idx.unwrap();
            if old_pt == inner.heap_bottom {
                let area = MapArea::new(
                    old_pt.into(),
                    new_pt.into(),
                    MapType::Framed,
                    MapPermission::R | MapPermission::W | MapPermission::U,
                    None,
                );
                inner.memory_set.areas.insert(idx, area);
                debug!("[sbrk] heap area allocated");
            } else {
                inner.memory_set.expend_area_to(idx, VirtAddr::from(new_pt));
                trace!("[sbrk] heap area expended to {:X}", new_pt);
            }
            inner.heap_pt = new_pt;
        }
    } else if increment < 0 {
        if new_pt < inner.heap_bottom {
            warn!(
                "[sbrk] over the lowerbond! lowerbond: {:X}, old_pt: {:X}, new_pt: {:X}",
                inner.heap_bottom, old_pt, new_pt
            );
            return old_pt;
        } else if let Some(idx) = inner.memory_set.heap_area_idx {
            inner.memory_set.shrink_area_to(idx, VirtAddr::from(new_pt));
            trace!("[sbrk] heap area shrinked to {:X}", new_pt);
        }
        inner.heap_pt = new_pt;
    }
    new_pt
}

#[allow(unused)]
pub fn remap_test() {
    let mut kernel_space = KERNEL_SPACE.lock();
    let mid_text: VirtAddr = ((stext as usize + etext as usize) / 2).into();
    let mid_rodata: VirtAddr = ((srodata as usize + erodata as usize) / 2).into();
    let mid_data: VirtAddr = ((sdata as usize + edata as usize) / 2).into();
    assert_eq!(
        kernel_space
            .page_table
            .translate(mid_text.floor())
            .unwrap()
            .writable(),
        false
    );
    assert_eq!(
        kernel_space
            .page_table
            .translate(mid_rodata.floor())
            .unwrap()
            .writable(),
        false,
    );
    assert_eq!(
        kernel_space
            .page_table
            .translate(mid_data.floor())
            .unwrap()
            .executable(),
        false,
    );
    info!("remap_test passed!");
}
