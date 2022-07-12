use super::{frame_alloc, FrameTracker};
use super::{translated_byte_buffer, UserBuffer};
use super::{PTEFlags, PageTable, PageTableEntry};
use super::{PhysAddr, PhysPageNum, VirtAddr, VirtPageNum};
use super::{StepByOne, VPNRange};
use crate::config::*;
use crate::fs::file_trait::File;
use crate::syscall::errno::*;
use crate::syscall::fs::SeekWhence;
use crate::task::{current_task, ELFInfo};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::arch::asm;
use lazy_static::*;
use log::{debug, error, info, trace, warn};
use riscv::register::satp;
use spin::Mutex;

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
        )
        .unwrap();
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
        permission: MapPermission,
        frames: Vec<Option<Arc<FrameTracker>>>,
    ) -> Result<(), ()> {
        let map_area = MapArea::from_existing_frame(start_va, MapType::Framed, permission, frames);
        self.push_no_alloc(map_area)?;
        Ok(())
    }
    /// # Warning
    /// if the start_vpn does not match any area's start_vpn, then nothing is done and return `Ok(())`
    pub fn remove_area_with_start_vpn(&mut self, start_vpn: VirtPageNum) -> Result<(), ()> {
        if let Some((idx, area)) = self
            .areas
            .iter_mut()
            .enumerate()
            .find(|(_, area)| area.data_frames.vpn_range.get_start() == start_vpn)
        {
            if let Err(_) = area.unmap(&mut self.page_table) {
                warn!("[remove_area_with_start_vpn] Some pages are already unmapped in target area, is it caused by lazy alloc?");
            }
            self.areas.remove(idx);
        } else {
            warn!(
                "[remove_area_with_start_vpn] Target area not found! Request vpn: {:?}",
                start_vpn
            );
        }
        Ok(())
    }
    /// Push a not-yet-mapped map_area into current MemorySet and copy the data into it if any, allocating the needed memory for the map.
    fn push(&mut self, mut map_area: MapArea, data: Option<&[u8]>) -> Result<(), ()> {
        if let Err(_) = map_area.map(&mut self.page_table) {
            return Err(());
        }
        if let Some(data) = data {
            map_area.copy_data(&mut self.page_table, data, 0);
        }
        self.areas.push(map_area);
        Ok(())
    }
    fn push_with_offset(
        &mut self,
        mut map_area: MapArea,
        offset: usize,
        data: Option<&[u8]>,
    ) -> Result<(), ()> {
        if let Err(_) = map_area.map(&mut self.page_table) {
            return Err(());
        }
        if let Some(data) = data {
            map_area.copy_data(&mut self.page_table, data, offset);
        }
        self.areas.push(map_area);
        Ok(())
    }
    /// Push the map area into the memory set without copying or allocation.
    pub fn push_no_alloc(&mut self, map_area: MapArea) -> Result<(), ()> {
        for vpn in map_area.data_frames.vpn_range {
            let frame = map_area.data_frames.get(&vpn).unwrap();
            if !self.page_table.is_mapped(vpn) {
                //if not mapped
                let pte_flags = PTEFlags::from_bits(map_area.map_perm.bits).unwrap();
                self.page_table.map(vpn, frame.ppn.clone(), pte_flags);
            } else {
                return Err(());
            }
        }
        self.areas.push(map_area);
        Ok(())
    }
    pub fn last_mmap_area_idx(&self) -> Option<usize> {
        // Kernel space
        let idx = if self.heap_area_idx.is_none() {
            self.areas.len() - 1
        } else {
            self.areas.len() - 3
        };
        let map_start = self.areas[idx].data_frames.vpn_range.get_start();
        if VirtAddr::from(map_start).0 >= MMAP_BASE {
            Some(idx)
        } else {
            None
        }
    }
    pub fn last_mmap_area(&self) -> Option<&MapArea> {
        match self.last_mmap_area_idx() {
            Some(idx) => Some(&self.areas[idx]),
            None => None,
        }
    }
    pub fn last_mmap_area_end(&self) -> VirtAddr {
        match self.last_mmap_area() {
            Some(area) => {
                let end_va: VirtAddr = area.data_frames.vpn_range.get_end().into();
                debug!("[last_mmap_area_end] end_va: {:?}", end_va);
                end_va
            }
            None => MMAP_BASE.into(),
        }
    }
    pub fn contains_valid_buffer(&self, buf: usize, size: usize, perm: MapPermission) -> bool {
        let start_vpn = VirtAddr::from(buf).floor();
        let end_vpn = VirtAddr::from(buf + size).ceil();
        self.areas
            .iter()
            .find(|area| {
                // If there is such a page in user space, and the addr is in the vpn range
                area.map_perm.contains(perm | MapPermission::U)
                    && area.data_frames.vpn_range.get_start() <= start_vpn
                    && end_vpn <= area.data_frames.vpn_range.get_end()
            })
            .is_some()
    }
    /// The REAL handler to page fault.
    /// Handles all types of page fault:(In regex:) "(Store|Load|Instruction)(Page)?Fault"
    /// Checks the permission to decide whether to copy.
    pub fn do_page_fault(&mut self, addr: VirtAddr) -> Result<(), ()> {
        let vpn = addr.floor();
        if let Some(area) = self.areas.iter_mut().find(|area| {
            area.map_perm.contains(MapPermission::R | MapPermission::U)// If there is such a page in user space
                && area.data_frames.vpn_range.get_start() <= vpn// ...and the addr is in the vpn range
                && vpn < area.data_frames.vpn_range.get_end()
        }) {
            let result = area.map_one(&mut self.page_table, vpn); // attempt to map
            if result.is_ok() {
                if let Some(file) = &area.map_file {
                    // read to the virtual page which we just mapped
                    // can be improved by mapping to fs cache
                    let target = VirtAddr::from(vpn).0;
                    let page = UserBuffer::new(translated_byte_buffer(
                        self.page_table.token(),
                        target as *const u8,
                        PAGE_SIZE,
                    ));
                    let old_offset = file.get_offset();
                    file.lseek((target - VirtAddr::from(area.data_frames.vpn_range.get_start()).0) as isize, SeekWhence::SEEK_CUR);
                    file.read_user(page);
                    file.lseek(old_offset as isize, SeekWhence::SEEK_SET);
                }
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
                    Err(())
                }
            }
        } else {
            // In all segments, nothing matches the requirements. Throws.
            error!("[do_page_fault] addr: {:?}, result: bad addr", addr);
            Err(())
        }
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
        macro_rules! anonymous_identical_map {
            ($begin:expr,$end:expr,$permission:expr) => {
                memory_set
                    .push(
                        MapArea::new(
                            ($begin as usize).into(),
                            ($end as usize).into(),
                            MapType::Identical,
                            $permission,
                            None,
                        ),
                        None,
                    )
                    .unwrap();
            };
            ($name:literal,$begin:expr,$end:expr,$permission:expr) => {
                println!("mapping {}", $name);
                anonymous_identical_map!($begin, $end, $permission);
            };
        }
        anonymous_identical_map!(
            ".text section",
            stext,
            etext,
            MapPermission::R | MapPermission::X
        );
        anonymous_identical_map!(".rodata section", srodata, erodata, MapPermission::R); // read only section
        anonymous_identical_map!(
            ".data section",
            sdata,
            edata,
            MapPermission::R | MapPermission::W
        );
        anonymous_identical_map!(
            ".bss section",
            sbss_with_stack,
            ebss,
            MapPermission::R | MapPermission::W
        );
        anonymous_identical_map!(
            "physical memory",
            ekernel,
            MEMORY_END,
            MapPermission::R | MapPermission::W
        );

        println!("mapping memory-mapped registers");
        for pair in MMIO {
            anonymous_identical_map!(
                (*pair).0,
                ((*pair).0 + (*pair).1),
                MapPermission::R | MapPermission::W
            );
        }
        memory_set
    }
    pub fn map_elf(&mut self, elf: &xmas_elf::ElfFile) -> Result<(usize, ELFInfo), isize> {
        let bias = match elf.header.pt2.type_().as_type() {
            // static
            xmas_elf::header::Type::Executable => 0,
            xmas_elf::header::Type::SharedObject => {
                match elf
                    .program_iter()
                    .filter(|ph| ph.get_type().unwrap() == xmas_elf::program::Type::Interp)
                    .count()
                {
                    // It's a loader!
                    0 => ELF_DYN_BASE,
                    // It's a dynamically linked ELF.
                    1 => 0,
                    // Emmm, It has multiple interpreters.
                    _ => return Err(EINVAL),
                }
            }
            _ => return Err(ENOEXEC),
        };

        let mut load_segment_count: usize = 0;
        let mut program_break: Option<usize> = None;
        let mut interp_entry: Option<usize> = None;
        let mut interp_base: Option<usize> = None;
        let mut load_addr: Option<usize> = None; // top va of ELF which points to ELF header

        for ph in elf.program_iter() {
            // Map only when the sections that is to be loaded.
            match ph.get_type().unwrap() {
                xmas_elf::program::Type::Load => {
                    let start_va: VirtAddr = (ph.virtual_addr() as usize + bias).into();
                    let end_va: VirtAddr =
                        ((ph.virtual_addr() + ph.mem_size()) as usize + bias).into();
                    let start_va_page_offset = start_va.page_offset();

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
                    if load_addr.is_none() {
                        load_addr = Some(start_va.into());
                    }
                    let mut map_area =
                        MapArea::new(start_va, end_va, MapType::Framed, map_perm, None);
                    // Virtual addr is 4K-aligned
                    if (start_va_page_offset & (PAGE_SIZE - 1)) == 0
                    // Physical addr is 4K-aligned
                        && (ph.offset() as usize & (PAGE_SIZE - 1)) == 0
                        && ph.file_size() != 0
                        && !map_perm.contains(MapPermission::W)
                    {
                        // Size in virtual addr is equal to size in physical addr
                        assert_eq!(
                            VirtAddr::from(ph.file_size() as usize).ceil().0,
                            map_area.data_frames.vpn_range.get_end().0
                                - map_area.data_frames.vpn_range.get_start().0
                        );

                        let kernel_start_vpn =
                            (VirtAddr::from(elf.input.as_ptr() as usize + (ph.offset() as usize)))
                                .floor();
                        map_area
                            .map_from_kernel_elf_area(&mut self.page_table, kernel_start_vpn)
                            .unwrap();
                        self.areas.push(map_area);
                    } else {
                        if let Err(_) = self.push_with_offset(
                            map_area,
                            start_va_page_offset,
                            Some(
                                &elf.input
                                    [ph.offset() as usize..(ph.offset() + ph.file_size()) as usize],
                            ),
                        ) {
                            panic!("[map_elf] Target addr already mapped.")
                        };
                    }
                    program_break = Some(VirtAddr::from(end_va.ceil()).0);
                    load_segment_count += 1;
                    trace!(
                        "[map_elf] start_va = 0x{:X}; end_va = 0x{:X}, offset = 0x{:X}",
                        start_va.0,
                        end_va.0,
                        start_va_page_offset
                    );
                }
                xmas_elf::program::Type::Interp => {
                    assert!(elf.input[(ph.offset() + ph.file_size()) as usize] == b'\0');
                    let path = String::from_utf8_lossy(
                        &elf.input
                            [ph.offset() as usize..(ph.offset() + ph.file_size() - 1) as usize],
                    );
                    debug!("[map_elf] Found interpreter path: {}", path);
                    let interp_data = crate::task::load_elf_interp(&path)?;
                    let interp = xmas_elf::ElfFile::new(interp_data).unwrap();
                    let (_, interp_info) = self.map_elf(&interp)?;
                    interp_entry = Some(interp_info.entry);
                    interp_base = Some(interp_info.base);
                    KERNEL_SPACE
                        .lock()
                        .remove_area_with_start_vpn(
                            VirtAddr::from(interp_data.as_ptr() as usize).ceil(),
                        )
                        .unwrap();
                }
                _ => {}
            }
        }
        self.heap_area_idx = Some(load_segment_count + self.heap_area_idx.unwrap_or_default());
        match (program_break, load_addr) {
            (Some(program_break), Some(load_addr)) => Ok((
                program_break,
                ELFInfo {
                    entry: elf.header.pt2.entry_point() as usize + bias,
                    interp_entry,
                    base: if let Some(interp_base) = interp_base {
                        interp_base
                    } else {
                        bias
                    },
                    phnum: elf.header.pt2.ph_count() as usize,
                    phent: elf.header.pt2.ph_entry_size() as usize,
                    phdr: load_addr + elf.header.pt2.ph_offset() as usize,
                },
            )),
            _ => Err(ENOEXEC),
        }
    }
    /// Include sections in elf and trampoline and TrapContext and user stack,
    /// also returns user_sp and entry point.
    pub fn from_elf(elf_data: &[u8]) -> Result<(Self, usize, usize, ELFInfo), isize> {
        let mut memory_set = Self::new_bare();
        // map trampoline
        memory_set.map_trampoline();
        // map signaltrampoline
        memory_set.map_signaltrampoline();

        let elf = xmas_elf::ElfFile::new(elf_data).unwrap();
        let (program_break, elf_info) = memory_set.map_elf(&elf)?;

        // Map USER_STACK
        memory_set.insert_framed_area(
            USER_STACK_TOP.into(),
            USER_STACK_BOTTOM.into(),
            MapPermission::R | MapPermission::W | MapPermission::U,
        );
        trace!(
            "[elf] USER STACK PUSHED. user_stack_top:{:X}; user_stack_bottom:{:X}",
            USER_STACK_TOP,
            USER_STACK_BOTTOM
        );

        // Map TrapContext
        memory_set.insert_framed_area(
            TRAP_CONTEXT.into(),
            TRAMPOLINE.into(),
            MapPermission::R | MapPermission::W,
        );
        trace!(
            "[elf] TRAP CONTEXT PUSHED. start_va:{:X}; end_va:{:X}",
            TRAP_CONTEXT,
            TRAMPOLINE
        );

        Ok((memory_set, USER_STACK_BOTTOM, program_break, elf_info))
    }
    pub fn from_existing_user(user_space: &mut MemorySet) -> MemorySet {
        let mut memory_set = Self::new_bare();
        // map trampoline
        memory_set.map_trampoline();
        // map signaltrampoline
        memory_set.map_signaltrampoline();
        // map data sections/user heap/mmap area/user stack
        for i in 0..user_space.areas.len() - 1 {
            let mut new_area = user_space.areas[i].clone();
            new_area
                .map_from_existing_page_table(
                    &mut memory_set.page_table,
                    &mut user_space.page_table,
                )
                .unwrap();
            memory_set.areas.push(new_area);
            debug!(
                "[fork] map shared area: {:?}",
                user_space.areas[i].data_frames.vpn_range
            );
        }
        // copy trap context area
        let trap_cx_area = user_space.areas.last().unwrap();
        let area = MapArea::from_another(trap_cx_area);
        memory_set.push(area, None).unwrap();
        for vpn in trap_cx_area.data_frames.vpn_range {
            let src_ppn = user_space.translate(vpn).unwrap().ppn();
            let dst_ppn = memory_set.translate(vpn).unwrap().ppn();
            dst_ppn
                .get_bytes_array()
                .copy_from_slice(src_ppn.get_bytes_array());
        }
        debug!(
            "[fork] copy trap_cx area: {:?}",
            trap_cx_area.data_frames.vpn_range
        );
        memory_set.heap_area_idx = user_space.heap_area_idx;
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
    pub fn set_pte_flags(&mut self, vpn: VirtPageNum, flags: MapPermission) -> Result<(), ()> {
        self.page_table.set_pte_flags(vpn, flags)
    }
    pub fn recycle_data_pages(&mut self) {
        //*self = Self::new_bare();
        self.areas.clear();
    }
    pub fn show_areas(&self) {
        self.areas.iter().for_each(|area| {
            let start_vpn = area.data_frames.vpn_range.get_start();
            let end_vpn = area.data_frames.vpn_range.get_end();
            error!(
                "[show_areas] start_vpn: {:?}, end_vpn: {:?}, map_perm: {:?}",
                start_vpn, end_vpn, area.map_perm
            );
        })
    }
    pub fn sbrk(&mut self, heap_pt: usize, heap_bottom: usize, increment: isize) -> usize {
        let old_pt: usize = heap_pt;
        let new_pt: usize = old_pt + increment as usize;
        if increment > 0 {
            let limit = heap_bottom + USER_HEAP_SIZE;
            if new_pt > limit {
                warn!(
                    "[sbrk] out of the upperbound! upperbound: {:X}, old_pt: {:X}, new_pt: {:X}",
                    limit, old_pt, new_pt
                );
                return old_pt;
            } else {
                let idx = self.heap_area_idx.unwrap();
                // first time to expand heap area, insert heap area
                if old_pt == heap_bottom {
                    let area = MapArea::new(
                        old_pt.into(),
                        new_pt.into(),
                        MapType::Framed,
                        MapPermission::R | MapPermission::W | MapPermission::U,
                        None,
                    );
                    self.areas.insert(idx, area);
                    debug!("[sbrk] heap area allocated");
                // the process already have a heap area, adjust it
                } else {
                    self.areas[idx]
                        .expand_to(&mut self.page_table, VirtAddr::from(new_pt))
                        .unwrap();
                    trace!("[sbrk] heap area expanded to {:X}", new_pt);
                }
            }
        } else if increment < 0 {
            // shrink to `heap_bottom` would cause duplicated insertion of heap area in future
            // so we simply reject it here
            if new_pt <= heap_bottom {
                warn!(
                    "[sbrk] out of the lowerbound! lowerbound: {:X}, old_pt: {:X}, new_pt: {:X}",
                    heap_bottom, old_pt, new_pt
                );
                return old_pt;
            // attention that if the process never call sbrk before, it would have no heap area
            // we only do shrinking when it does have a heap area
            } else {
                if let Some(idx) = self.heap_area_idx {
                    self.areas[idx]
                        .shrink_to(&mut self.page_table, VirtAddr::from(new_pt))
                        .unwrap();
                    trace!("[sbrk] heap area shrinked to {:X}", new_pt);
                }
            }
            // we need to adjust `heap_pt` if it's not out of bound
            // in spite of whether the process has a heap area
        }
        new_pt
    }
    pub fn mmap(
        &mut self,
        start: usize,
        len: usize,
        prot: MapPermission,
        flags: MapFlags,
        fd: usize,
        offset: usize,
    ) -> usize {
        // not aligned on a page boundary
        if start % PAGE_SIZE != 0 {
            return EINVAL as usize;
        }
        let len = if len == 0 { PAGE_SIZE } else { len };
        let task = current_task().unwrap();
        let idx = self.last_mmap_area_idx();
        let page_table = &mut self.page_table;
        let start_va: VirtAddr = if flags.contains(MapFlags::MAP_FIXED) {
            self.munmap(start, len).unwrap();
            start.into()
        } else {
            if let Some(idx) = idx {
                let area = &mut self.areas[idx];
                if flags.contains(MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS)
                    && prot == area.map_perm
                {
                    debug!("[mmap] merge with previous area, call expand_to");
                    let end_va: VirtAddr = area.data_frames.vpn_range.get_end().into();
                    area.expand_to(page_table, VirtAddr::from(end_va.0 + len))
                        .unwrap();
                    return end_va.0;
                }
                area.data_frames.vpn_range.get_end().into()
            } else {
                MMAP_BASE.into()
            }
        };
        let mut new_area = MapArea::new(
            start_va,
            VirtAddr::from(start_va.0 + len),
            MapType::Framed,
            prot,
            None,
        );
        if !flags.contains(MapFlags::MAP_ANONYMOUS) {
            warn!("[mmap] file-backed map!");
            let fd_table = task.files.lock();
            if fd >= fd_table.len() {
                // fd is not a valid file descriptor (and MAP_ANONYMOUS was not set)
                return EBADF as usize;
            }
            if let Some(fd) = &fd_table[fd] {
                let file = fd.file.deep_clone();
                if !file.readable() {
                    return EACCES as usize;
                }
                file.lseek(offset as isize, SeekWhence::SEEK_SET);
                new_area.map_file = Some(file);
            } else {
                // fd is not a valid file descriptor (and MAP_ANONYMOUS was not set)
                return EBADF as usize;
            }
        }
        // the last one is trap context, we inserst mmap area to the slot right before trap context (len - 2)
        let idx = if start_va.0 < MMAP_BASE {
            self.heap_area_idx.unwrap() + 1
        } else {
            self.areas.len() - 2
        };
        self.areas.insert(idx, new_area);
        start_va.0
    }
    pub fn munmap(&mut self, start: usize, len: usize) -> Result<(), isize> {
        let start_va = VirtAddr::from(start);
        let end_va = VirtAddr::from(start + len);
        if !start_va.aligned() {
            warn!("[munmap] Not aligned");
            return Err(EINVAL);
        }
        let start_vpn = start_va.floor();
        let end_vpn = end_va.ceil();
        let page_table = &mut self.page_table;
        let mut found_area = false;
        let mut delete: Vec<usize> = Vec::new();
        let mut break_apart_idx: Option<usize> = None;
        self.areas.iter_mut().enumerate().for_each(|(idx, area)| {
            if let Some((overlap_start, overlap_end)) = area.check_overlapping(start_vpn, end_vpn) {
                found_area = true;
                let area_start_vpn = area.data_frames.vpn_range.get_start();
                let area_end_vpn = area.data_frames.vpn_range.get_end();
                if overlap_start == area_start_vpn && overlap_end == area_end_vpn {
                    trace!("[munmap] unmap whole area, idx: {}", idx);
                    if let Err(_) = area.unmap(page_table) {
                        warn!(
                            "[munmap] Some pages are already unmapped, is it caused by lazy alloc?"
                        );
                    }
                    delete.push(idx);
                } else if overlap_start == area_start_vpn {
                    trace!("[munmap] unmap lower part, call rshrink_to");
                    if let Err(_) = area.rshrink_to(page_table, VirtAddr::from(overlap_end)) {
                        warn!(
                            "[munmap] Some pages are already unmapped, is it caused by lazy alloc?"
                        );
                    }
                } else if overlap_end == area_end_vpn {
                    trace!("[munmap] unmap higher part, call shrink_to");
                    if let Err(_) = area.shrink_to(page_table, VirtAddr::from(overlap_start)) {
                        warn!(
                            "[munmap] Some pages are already unmapped, is it caused by lazy alloc?"
                        );
                    }
                } else {
                    trace!("[munmap] unmap internal part, call into_three");
                    break_apart_idx = Some(idx);
                }
            }
        });
        for idx in delete {
            self.areas.remove(idx);
        }
        if let Some(idx) = break_apart_idx {
            let (first, mut second, third) = self
                .areas
                .remove(idx)
                .into_three(start_vpn, end_vpn)
                .unwrap();
            if let Err(_) = second.unmap(page_table) {
                warn!("[munmap] Some pages are already unmapped, is it caused by lazy alloc?");
            }
            self.areas.insert(idx, first);
            self.areas.insert(idx + 1, third);
            if idx <= self.heap_area_idx.unwrap() {
                self.heap_area_idx = Some(self.heap_area_idx.unwrap() + 1);
            }
        }
        if found_area {
            Ok(())
        } else {
            Err(EINVAL)
        }
    }
    pub fn mprotect(&mut self, addr: usize, len: usize, prot: usize) -> Result<(), isize> {
        let start_va = VirtAddr::from(addr);
        let end_va = VirtAddr::from(addr + len);
        // addr is not a multiple of the system page size.
        if !start_va.aligned() {
            warn!("[mprotect] Not aligned");
            return Err(EINVAL);
        }
        // here (prot << 1) is identical to BitFlags of X/W/R in pte flags
        let prot = MapPermission::from_bits(((prot as u8) << 1) | (1 << 4)).unwrap();
        warn!(
            "[mprotect] addr: {:X}, len: {:X}, prot: {:?}",
            addr, len, prot
        );
        let start_vpn = start_va.floor();
        let end_vpn = end_va.ceil();
        let result = self.areas.iter().enumerate().find(|(_, area)| {
            area.data_frames.vpn_range.get_start() <= start_vpn
                && start_vpn < area.data_frames.vpn_range.get_end()
        });
        match result {
            Some((idx, _)) => {
                let area_start_vpn = self.areas[idx].data_frames.vpn_range.get_start();
                let area_end_vpn = self.areas[idx].data_frames.vpn_range.get_end();
                // Addresses in the range [addr, addr+len-1] are invalid for the address space of the process,
                // or specify one or more pages that are not mapped.
                if end_vpn > area_end_vpn {
                    warn!("[mprotect] addr: {:X} is not in any MapArea", addr);
                    return Err(ENOMEM);
                }
                let mut area = if start_vpn == area_start_vpn && end_vpn == area_end_vpn {
                    trace!("[mprotect] change prot of whole area, idx: {}", idx);
                    self.areas.remove(idx)
                } else if start_vpn == area_start_vpn {
                    trace!("[mprotect] change prot of lower part");
                    let (first, second) = self.areas.remove(idx).into_two(end_vpn).unwrap();
                    self.areas.insert(idx, second);
                    if idx <= self.heap_area_idx.unwrap() {
                        self.heap_area_idx = Some(self.heap_area_idx.unwrap() + 1);
                    }
                    first
                } else if end_vpn == area_end_vpn {
                    trace!("[mprotect] change prot of higher part");
                    let (first, second) = self.areas.remove(idx).into_two(start_vpn).unwrap();
                    self.areas.insert(idx, first);
                    if idx <= self.heap_area_idx.unwrap() {
                        self.heap_area_idx = Some(self.heap_area_idx.unwrap() + 1);
                    }
                    second
                } else {
                    trace!("[mprotect] change prot of internal part, call into_three");
                    let (first, second, third) = self
                        .areas
                        .remove(idx)
                        .into_three(start_vpn, end_vpn)
                        .unwrap();
                    self.areas.insert(idx, first);
                    self.areas.insert(idx + 1, third);
                    if idx <= self.heap_area_idx.unwrap() {
                        self.heap_area_idx = Some(self.heap_area_idx.unwrap() + 2);
                    }
                    second
                };
                let page_table = &mut self.page_table;
                let mut has_unmapped_page = false;
                for vpn in area.data_frames.vpn_range {
                    // Clear W prot, or CoW pages may be written unexpectedly.
                    // And those pages will gain W prot by CoW.
                    if let Err(_) = page_table.set_pte_flags(vpn, prot - MapPermission::W) {
                        has_unmapped_page = true;
                    }
                }
                if has_unmapped_page {
                    warn!("[mprotect] Some pages are not mapped, is it caused by lazy alloc?");
                }
                // If `prot` contains W, store page fault & CoW will occur.
                area.map_perm = prot;
                self.areas.insert(idx + 1, area);
            }
            None => {
                warn!("[mprotect] addr is not a valid pointer");
                return Err(EINVAL);
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct MapRangeDict {
    vpn_range: VPNRange,
    data_frames: Vec<Option<Arc<FrameTracker>>>,
}

impl MapRangeDict {
    pub fn new(vpn_range: VPNRange) -> Self {
        let len = vpn_range.get_end().0 - vpn_range.get_start().0;
        let mut new_dict = Self {
            vpn_range,
            data_frames: Vec::with_capacity(len),
        };
        new_dict.data_frames.resize(len, None);
        new_dict
    }
    /// # Warning
    /// a key which exceeds the end of `vpn_range` would cause panic
    pub fn get(&self, key: &VirtPageNum) -> Option<&Arc<FrameTracker>> {
        self.data_frames[key.0 - self.vpn_range.get_start().0].as_ref()
    }
    /// # Warning
    /// a key which exceeds the end of `vpn_range` would cause panic
    pub fn insert(
        &mut self,
        key: VirtPageNum,
        value: Arc<FrameTracker>,
    ) -> Option<Arc<FrameTracker>> {
        self.data_frames[key.0 - self.vpn_range.get_start().0].replace(value)
    }
    /// # Warning
    /// a key which exceeds the end of `vpn_range` would cause panic
    pub fn remove(&mut self, key: &VirtPageNum) -> Option<Arc<FrameTracker>> {
        self.data_frames[key.0 - self.vpn_range.get_start().0].take()
    }
    pub fn set_start(&mut self, new_vpn_start: VirtPageNum) -> Result<(), ()> {
        let vpn_start = self.vpn_range.get_start();
        let vpn_end = self.vpn_range.get_end();
        if new_vpn_start > vpn_end {
            return Err(());
        }
        self.vpn_range = VPNRange::new(new_vpn_start, vpn_end);
        if new_vpn_start < vpn_start {
            self.data_frames.rotate_left(vpn_start.0 - new_vpn_start.0);
        } else {
            self.data_frames.rotate_left(new_vpn_start.0 - vpn_start.0);
        }
        self.data_frames.resize(vpn_end.0 - new_vpn_start.0, None);
        Ok(())
    }
    pub fn set_end(&mut self, new_vpn_end: VirtPageNum) -> Result<(), ()> {
        let vpn_start = self.vpn_range.get_start();
        self.vpn_range = VPNRange::new(vpn_start, new_vpn_end);
        if vpn_start > new_vpn_end {
            return Err(());
        }
        self.data_frames.resize(new_vpn_end.0 - vpn_start.0, None);
        Ok(())
    }
    pub fn into_two(self, cut: VirtPageNum) -> Result<(Self, Self), ()> {
        let vpn_start = self.vpn_range.get_start();
        let vpn_end = self.vpn_range.get_end();
        if cut <= vpn_start || cut >= vpn_end {
            return Err(());
        }
        let first = MapRangeDict {
            vpn_range: VPNRange::new(vpn_start, cut),
            data_frames: self.data_frames[0..cut.0 - vpn_start.0].to_vec(),
        };
        let second = MapRangeDict {
            vpn_range: VPNRange::new(cut, vpn_end),
            data_frames: self.data_frames[cut.0 - vpn_start.0..vpn_end.0 - vpn_start.0].to_vec(),
        };
        Ok((first, second))
    }
    pub fn into_three(
        self,
        first_cut: VirtPageNum,
        second_cut: VirtPageNum,
    ) -> Result<(Self, Self, Self), ()> {
        let vpn_start = self.vpn_range.get_start();
        let vpn_end = self.vpn_range.get_end();
        if first_cut <= vpn_start || second_cut >= vpn_end || first_cut > second_cut {
            return Err(());
        }
        let first = MapRangeDict {
            vpn_range: VPNRange::new(vpn_start, first_cut),
            data_frames: self.data_frames[0..first_cut.0 - vpn_start.0].to_vec(),
        };
        let second = MapRangeDict {
            vpn_range: VPNRange::new(first_cut, second_cut),
            data_frames: self.data_frames[first_cut.0 - vpn_start.0..second_cut.0 - vpn_start.0]
                .to_vec(),
        };
        let third = MapRangeDict {
            vpn_range: VPNRange::new(second_cut, vpn_end),
            data_frames: self.data_frames[second_cut.0 - vpn_start.0..vpn_end.0 - vpn_start.0]
                .to_vec(),
        };
        Ok((first, second, third))
    }
}

#[derive(Clone)]
/// Map area for different segments or a chunk of memory for memory mapped file access.
pub struct MapArea {
    /// Range of the mapped virtual page numbers.
    /// Page aligned.
    // vpn_range: VPNRange,
    // /// Map physical page frame tracker to virtual pages for RAII & lookup.
    // data_frames: BTreeMap<VirtPageNum, Arc<FrameTracker>>,
    data_frames: MapRangeDict,
    /// Direct or framed(virtual) mapping?
    map_type: MapType,
    /// Permissions which are the or of RWXU, where U stands for user.
    map_perm: MapPermission,
    pub map_file: Option<Arc<dyn File>>,
}

impl MapArea {
    /// Construct a new segment without without allocating memory
    pub fn new(
        start_va: VirtAddr,
        end_va: VirtAddr,
        map_type: MapType,
        map_perm: MapPermission,
        map_file: Option<Arc<dyn File>>,
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
            data_frames: MapRangeDict::new(VPNRange::new(start_vpn, end_vpn)),
            map_type,
            map_perm,
            map_file,
        }
    }
    /// Return the reference count to the currently using file if exists.
    pub fn file_ref(&self) -> Option<usize> {
        let ret = self.map_file.as_ref().map(|x| Arc::strong_count(x));
        info!("[file_ref] {}", ret.unwrap());
        ret
    }
    /// Copier, but the physical pages are not allocated,
    /// thus leaving `data_frames` empty.
    pub fn from_another(another: &MapArea) -> Self {
        Self {
            data_frames: MapRangeDict::new(VPNRange::new(
                another.data_frames.vpn_range.get_start(),
                another.data_frames.vpn_range.get_end(),
            )),
            map_type: another.map_type,
            map_perm: another.map_perm,
            map_file: another.map_file.clone(),
        }
    }
    /// Create `MapArea` from `Vec<Arc<FrameTracker>>` \
    /// # NOTE
    /// `start_vpn` will be set to `start_va.floor()`,
    /// `end_vpn` will be set to `start_vpn + frames.len()`,
    /// `map_file` will be set to `None`.
    pub fn from_existing_frame(
        start_va: VirtAddr,
        map_type: MapType,
        map_perm: MapPermission,
        frames: Vec<Option<Arc<FrameTracker>>>,
    ) -> Self {
        let start_vpn = start_va.floor();
        let end_vpn = VirtPageNum::from(start_vpn.0 + frames.len());
        Self {
            data_frames: MapRangeDict {
                vpn_range: VPNRange::new(start_vpn, end_vpn),
                data_frames: frames,
            },
            map_type,
            map_perm,
            map_file: None,
        }
    }
    /// Map an included page in current area.
    /// If the `map_type` is `Framed`, then physical pages shall be allocated by this function.
    /// Otherwise, where `map_type` is `Identical`,
    /// the virtual page will be mapped directly to the physical page with an identical address to the page.
    /// # Note
    /// Vpn should be in this map area, but the check is not enforced in this function!
    pub fn map_one(&mut self, page_table: &mut PageTable, vpn: VirtPageNum) -> Result<(), ()> {
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
            Err(())
        }
    }
    /// Unmap a page in current area.
    /// If it is framed, then the physical pages will be removed from the `data_frames` Btree.
    /// This is unnecessary if the area is directly mapped.
    /// # Note
    /// Vpn should be in this map area, but the check is not enforced in this function!
    pub fn unmap_one(&mut self, page_table: &mut PageTable, vpn: VirtPageNum) -> Result<(), ()> {
        if !page_table.is_mapped(vpn) {
            return Err(());
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
    pub fn map(&mut self, page_table: &mut PageTable) -> Result<(), ()> {
        for vpn in self.data_frames.vpn_range {
            if let Err(_) = self.map_one(page_table, vpn) {
                return Err(());
            }
        }
        Ok(())
    }
    /// Map the same area in `self` from `dst_page_table` to `src_page_table`, sharing the same physical address.
    /// Convert map areas to physical pages.
    /// # Of Course...
    /// Since the area is shared, the pages have been allocated.
    /// # Argument
    /// `dst_page_table`: The destination to be mapped into.
    /// `src_page_table`: The source to be mapped from. This is also the page table where `self` should be included.
    pub fn map_from_existing_page_table(
        &mut self,
        dst_page_table: &mut PageTable,
        src_page_table: &mut PageTable,
    ) -> Result<(), ()> {
        let map_perm = self.map_perm.difference(MapPermission::W);
        let pte_flags = PTEFlags::from_bits(map_perm.bits).unwrap();
        for vpn in self.data_frames.vpn_range {
            if let Some(pte) = src_page_table.translate_refmut(vpn) {
                let ppn = pte.ppn();
                if !dst_page_table.is_mapped(vpn) {
                    dst_page_table.map(vpn, ppn, pte_flags);
                    pte.set_permission(map_perm);
                } else {
                    return Err(());
                }
            }
        }
        Ok(())
    }

    /// Map vpns in `self` to the same ppns in `kernel_elf_area` from `start_vpn_in_kernel_elf_area`,
    /// range is depend on `self.vpn_range`.
    /// # ATTENTION
    /// Suppose that the kernel_space.areas.last() is elf_area.
    /// `page_table` and `self` should belong to the same memory_set.
    /// vpn_range in `kernel_elf_area` should be broader than (or at least equal to) `self`.
    /// # WARNING
    /// Author did not consider to reuse this function at the time he wrote it.
    /// So be careful to use it in some other places besides `from_elf`.
    pub fn map_from_kernel_elf_area(
        &mut self,
        page_table: &mut PageTable,
        start_vpn_in_kernel_elf_area: VirtPageNum,
    ) -> Result<(), ()> {
        let kernel_space = KERNEL_SPACE.lock();
        let kernel_elf_area = kernel_space
            .areas
            .iter()
            .rev()
            .find(|area| {
                area.data_frames.vpn_range.get_start() <= start_vpn_in_kernel_elf_area
                    && start_vpn_in_kernel_elf_area < area.data_frames.vpn_range.get_end()
            })
            .unwrap();
        let pte_flags = PTEFlags::from_bits(self.map_perm.bits).unwrap();
        let mut src_vpn = start_vpn_in_kernel_elf_area;
        for vpn in self.data_frames.vpn_range {
            if let Some(frame) = kernel_elf_area.data_frames.get(&src_vpn) {
                let ppn = frame.ppn;
                if !page_table.is_mapped(vpn) {
                    self.data_frames.insert(vpn, frame.clone());
                    page_table.map(vpn, ppn, pte_flags);
                } else {
                    error!("[map_from_kernel_elf_area] user vpn already mapped!");
                    return Err(());
                }
            } else {
                error!("[map_from_kernel_elf_area] kernel vpn invalid!");
                return Err(());
            }
            src_vpn = (src_vpn.0 + 1).into();
        }
        Ok(())
    }
    /// Unmap all pages in `self` from `page_table` using unmap_one()
    pub fn unmap(&mut self, page_table: &mut PageTable) -> Result<(), ()> {
        let mut has_unmapped_page = false;
        for vpn in self.data_frames.vpn_range {
            // it's normal to get an `Error` because we are using lazy alloc strategy
            // we still need to unmap remaining pages of `self`, just throw this `Error` to caller
            if let Err(_) = self.unmap_one(page_table, vpn) {
                has_unmapped_page = true;
            }
        }
        if has_unmapped_page {
            Err(())
        } else {
            Ok(())
        }
    }
    /// data: start-aligned but maybe with shorter length
    /// assume that all frames were cleared before
    pub fn copy_data(&mut self, page_table: &mut PageTable, data: &[u8], offset: usize) {
        assert_eq!(self.map_type, MapType::Framed);
        let mut start: usize = 0;
        let mut page_offset: usize = offset;
        let mut current_vpn = self.data_frames.vpn_range.get_start();
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
    pub fn copy_on_write(
        &mut self,
        page_table: &mut PageTable,
        vpn: VirtPageNum,
    ) -> Result<(), ()> {
        let old_frame = self.data_frames.remove(&vpn).unwrap();
        if Arc::strong_count(&old_frame) == 1 {
            // don't need to copy
            // push back old frame and set pte flags to allow write
            self.data_frames.insert(vpn, old_frame);
            page_table.set_pte_flags(vpn, self.map_perm).unwrap();
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
    /// If `new_end` is equal to the current end of area, do nothing and return `Ok(())`.
    pub fn expand_to(&mut self, page_table: &mut PageTable, new_end: VirtAddr) -> Result<(), ()> {
        let new_end_vpn: VirtPageNum = new_end.ceil();
        let old_end_vpn = self.data_frames.vpn_range.get_end();
        if new_end_vpn < old_end_vpn {
            warn!(
                "[expand_to] new_end_vpn: {:?} is lower than old_end_vpn: {:?}",
                new_end_vpn, old_end_vpn
            );
            return Err(());
        }
        // `set_end` must be done before calling `map_one`
        // because `map_one` will insert frames into `data_frames`
        // if we don't `set_end` in advance, this insertion is out of bound
        self.data_frames.set_end(new_end_vpn)?;
        for vpn in VPNRange::new(old_end_vpn, new_end_vpn) {
            if let Err(_) = self.map_one(page_table, vpn) {
                return Err(());
            }
        }
        Ok(())
    }
    /// If `new_end` is equal to the current end of area, do nothing and return `Ok(())`.
    pub fn shrink_to(&mut self, page_table: &mut PageTable, new_end: VirtAddr) -> Result<(), ()> {
        let new_end_vpn: VirtPageNum = new_end.ceil();
        let old_end_vpn = self.data_frames.vpn_range.get_end();
        if new_end_vpn > old_end_vpn {
            warn!(
                "[expand_to] new_end_vpn: {:?} is higher than old_end_vpn: {:?}",
                new_end_vpn, old_end_vpn
            );
            return Err(());
        }
        let mut has_unmapped_page = false;
        for vpn in VPNRange::new(new_end_vpn, old_end_vpn) {
            if let Err(_) = self.unmap_one(page_table, vpn) {
                has_unmapped_page = true;
            }
        }
        // `set_end` must be done after calling `map_one`
        // for the similar reason with `expand_to`
        self.data_frames.set_end(new_end_vpn)?;
        if has_unmapped_page {
            warn!("[shrink_to] Some pages are already unmapped, is it caused by lazy alloc?");
            Err(())
        } else {
            Ok(())
        }
    }
    /// If `new_start` is equal to the current start of area, do nothing and return `Ok(())`.
    pub fn rshrink_to(
        &mut self,
        page_table: &mut PageTable,
        new_start: VirtAddr,
    ) -> Result<(), ()> {
        let new_start_vpn: VirtPageNum = new_start.floor();
        let old_start_vpn = self.data_frames.vpn_range.get_start();
        if new_start_vpn < old_start_vpn {
            warn!(
                "[rshrink_to] new_start_vpn: {:?} is lower than old_start_vpn: {:?}",
                new_start_vpn, old_start_vpn
            );
            return Err(());
        }
        let mut has_unmapped_page = false;
        for vpn in VPNRange::new(old_start_vpn, new_start_vpn) {
            if let Err(_) = self.unmap_one(page_table, vpn) {
                has_unmapped_page = true;
            }
        }
        // `set_start` must be done after calling `map_one`
        // for the similar reason with `expand_to`
        self.data_frames.set_start(new_start_vpn)?;
        if has_unmapped_page {
            warn!("[rshrink_to] Some pages are already unmapped, is it caused by lazy alloc?");
            Err(())
        } else {
            Ok(())
        }
    }
    pub fn check_overlapping(
        &self,
        start_vpn: VirtPageNum,
        end_vpn: VirtPageNum,
    ) -> Option<(VirtPageNum, VirtPageNum)> {
        let area_start_vpn = self.data_frames.vpn_range.get_start();
        let area_end_vpn = self.data_frames.vpn_range.get_end();
        if end_vpn < area_start_vpn || start_vpn >= area_end_vpn {
            return None;
        } else {
            let start = if start_vpn > area_start_vpn {
                start_vpn
            } else {
                area_start_vpn
            };
            let end = if end_vpn < area_end_vpn {
                end_vpn
            } else {
                area_end_vpn
            };
            return Some((start, end));
        }
    }
    pub fn into_two(self, cut: VirtPageNum) -> Result<(Self, Self), ()> {
        let second_file = if let Some(file) = &self.map_file {
            let new_file = file.deep_clone();
            new_file.lseek(
                (file.get_offset() + VirtAddr::from(cut).0
                    - VirtAddr::from(self.data_frames.vpn_range.get_start()).0) as isize,
                SeekWhence::SEEK_SET
            );
            Some(new_file)
        } else {
            None
        };
        let (first_frames, second_frames) = self.data_frames.into_two(cut)?;
        Ok((
            MapArea {
                data_frames: first_frames,
                map_type: self.map_type,
                map_perm: self.map_perm,
                map_file: self.map_file,
            },
            MapArea {
                data_frames: second_frames,
                map_type: self.map_type,
                map_perm: self.map_perm,
                map_file: second_file,
            },
        ))
    }
    pub fn into_three(
        self,
        first_cut: VirtPageNum,
        second_cut: VirtPageNum,
    ) -> Result<(Self, Self, Self), ()> {
        if self.map_file.is_some() {
            warn!("[into_three] break apart file-back MapArea!");
            return Err(());
        }
        let (first_frames, second_frames, third_frames) =
            self.data_frames.into_three(first_cut, second_cut)?;
        Ok((
            MapArea {
                data_frames: first_frames,
                map_type: self.map_type,
                map_perm: self.map_perm,
                map_file: None,
            },
            MapArea {
                data_frames: second_frames,
                map_type: self.map_type,
                map_perm: self.map_perm,
                map_file: None,
            },
            MapArea {
                data_frames: third_frames,
                map_type: self.map_type,
                map_perm: self.map_perm,
                map_file: None,
            },
        ))
    }
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
