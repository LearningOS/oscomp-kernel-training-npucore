use super::{frame_alloc, FrameTracker};
use super::{translated_byte_buffer, UserBuffer};
use super::{PTEFlags, PageTable, PageTableEntry};
use super::{PhysAddr, PhysPageNum, VirtAddr, VirtPageNum};
use super::{StepByOne, VPNRange};
use crate::config::*;
use crate::fs::{File, FileLike};
use crate::syscall::errno::*;
use crate::task::{current_task, ELFInfo};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::arch::asm;
use core::fmt::{Error, Result};
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
    /// # Warning
    /// if the start_vpn does not match any area's start_vpn, then nothing is done and return `Ok(())`
    pub fn remove_area_with_start_vpn(&mut self, start_vpn: VirtPageNum) -> Result {
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
            warn!("[remove_area_with_start_vpn] Target area not found!")
        }
        Ok(())
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
    fn push_with_offset(
        &mut self,
        mut map_area: MapArea,
        offset: usize,
        data: Option<&[u8]>,
    ) -> Result {
        if let Err(_) = map_area.map(&mut self.page_table) {
            return Err(core::fmt::Error);
        }
        if let Some(data) = data {
            map_area.copy_data(&mut self.page_table, data, offset);
        }
        self.areas.push(map_area);
        Ok(())
    }
    /// Push the map area into the memory set without copying or allocation.
    pub fn push_no_alloc(&mut self, map_area: &MapArea) -> Result {
        for vpn in map_area.data_frames.vpn_range {
            let frame = map_area.data_frames.get(&vpn).unwrap();
            if !self.page_table.is_mapped(vpn) {
                //if not mapped
                let pte_flags = PTEFlags::from_bits(map_area.map_perm.bits).unwrap();
                self.page_table.map(vpn, frame.ppn.clone(), pte_flags);
            } else {
                return Err(Error);
            }
        }
        self.areas.push(map_area.clone());
        Ok(())
    }
    pub fn find_mmap_area_end(&self) -> VirtAddr {
        let idx = self.areas.len() - 3;
        let map_end = self.areas[idx].data_frames.vpn_range.get_end().into();
        debug!("[find_mmap_area_end] map_end: {:?}", map_end);
        if map_end > MMAP_BASE.into() {
            map_end
        } else {
            MMAP_BASE.into()
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
    pub fn do_page_fault(&mut self, addr: VirtAddr) -> Result {
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
                    let page = UserBuffer::new(translated_byte_buffer(
                        self.page_table.token(),
                        VirtAddr::from(vpn).0 as *const u8,
                        4096,
                    ));
                    match file {
                        FileLike::Regular(file) => {
                            file.read(page);
                        }
                        // map a non-regular file will cause EACCES, so it's impossible here
                        _ => unreachable!(),
                    }
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
                    Err(core::fmt::Error)
                }
            }
        } else {
            // In all segments, nothing matches the requirements. Throws.
            error!("[do_page_fault] addr: {:?}, result: bad addr", addr);
            Err(core::fmt::Error)
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
    /// Include sections in elf and trampoline and TrapContext and user stack,
    /// also returns user_sp and entry point.
    pub fn from_elf(elf_data: &[u8]) -> (Self, usize, usize, ELFInfo) {
        let mut memory_set = Self::new_bare();
        // map trampoline
        memory_set.map_trampoline();
        // map signaltrampoline
        memory_set.map_signaltrampoline();

        let elf = xmas_elf::ElfFile::new(elf_data).unwrap();
        let mut program_break = 0;
        let mut load_addr: Option<usize> = None; // top va of ELF which points to ELF header
        let mut load_segment_count = 0;
        for ph in elf.program_iter() {
            // Map only when the sections that is to be loaded.
            if ph.get_type().unwrap() == xmas_elf::program::Type::Load {
                let start_va: VirtAddr = (ph.virtual_addr() as usize).into();
                let end_va: VirtAddr = ((ph.virtual_addr() + ph.mem_size()) as usize).into();
                let page_offset = start_va.page_offset();

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
                let mut map_area = MapArea::new(start_va, end_va, MapType::Framed, map_perm, None);
                if page_offset == 0 && ph.file_size() != 0 && !map_perm.contains(MapPermission::W) {
                    assert_eq!(ph.offset() % 0x1000, 0);
                    assert_eq!(
                        VirtAddr::from(ph.file_size() as usize).ceil().0,
                        map_area.data_frames.vpn_range.get_end().0 - map_area.data_frames.vpn_range.get_start().0
                    );

                    let kernel_start_vpn =
                        (VirtAddr::from(MMAP_BASE + (ph.offset() as usize))).floor();
                    map_area
                        .map_from_kernel_elf_area(&mut memory_set.page_table, kernel_start_vpn)
                        .unwrap();
                    memory_set.areas.push(map_area);
                    // memory_set.push(
                    //     map_area,
                    //     Some(&elf.input
                    //         [ph.offset() as usize..(ph.offset() + ph.file_size()) as usize]),
                    // );
                } else {
                    memory_set
                        .push_with_offset(
                            map_area,
                            page_offset,
                            Some(
                                &elf.input
                                    [ph.offset() as usize..(ph.offset() + ph.file_size()) as usize],
                            ),
                        )
                        .unwrap();
                }
                program_break = end_va.ceil().0;
                load_segment_count = load_segment_count + 1;
                trace!("[elf] LOAD SEGMENT PUSHED. start_va = 0x{:X}; end_va = 0x{:X}, offset = 0x{:X}", start_va.0, end_va.0, page_offset);
            }
        }

        memory_set.heap_area_idx = Some(load_segment_count);

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

        (
            memory_set,
            USER_STACK_BOTTOM,
            program_break,
            ELFInfo {
                entry: elf.header.pt2.entry_point() as usize,
                phnum: elf.header.pt2.ph_count() as usize,
                phent: elf.header.pt2.ph_entry_size() as usize,
                phdr: load_addr.unwrap() + elf.header.pt2.ph_offset() as usize,
            },
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
            new_area
                .map_from_existed_page_table(&mut memory_set.page_table, &mut user_space.page_table)
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
        debug!("[fork] copy trap_cx area: {:?}", trap_cx_area.data_frames.vpn_range);
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
    pub fn set_pte_flags(&mut self, vpn: VirtPageNum, flags: MapPermission) -> Result {
        self.page_table.set_pte_flags(vpn, flags)
    }
    pub fn recycle_data_pages(&mut self) {
        //*self = Self::new_bare();
        self.areas.clear();
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
    pub fn get(&self, key: &VirtPageNum) -> Option<&Arc<FrameTracker>>{
        self.data_frames[key.0 - self.vpn_range.get_start().0].as_ref()
    }
    /// # Warning
    /// a key which exceeds the end of `vpn_range` would cause panic
    pub fn insert(&mut self, key: VirtPageNum, value: Arc<FrameTracker>) -> Option<Arc<FrameTracker>> {
        self.data_frames[key.0 - self.vpn_range.get_start().0].replace(value)
    }
    /// # Warning
    /// a key which exceeds the end of `vpn_range` would cause panic
    pub fn remove(&mut self, key: &VirtPageNum) -> Option<Arc<FrameTracker>> {
        self.data_frames[key.0 - self.vpn_range.get_start().0].take()
    }
    /// unchecked, caller should ensure `new_vpn_end` is valid
    pub unsafe fn set_end(&mut self, new_vpn_end: VirtPageNum) {
        let vpn_start = self.vpn_range.get_start();
        self.vpn_range = VPNRange::new(vpn_start, new_vpn_end);
        self.data_frames.resize(new_vpn_end.0 - vpn_start.0, None);
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
            data_frames: MapRangeDict::new(VPNRange::new(start_vpn, end_vpn)),
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
            data_frames: MapRangeDict::new(VPNRange::new(another.data_frames.vpn_range.get_start(), another.data_frames.vpn_range.get_end())),
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
        for vpn in self.data_frames.vpn_range {
            if let Err(_) = self.map_one(page_table, vpn) {
                return Err(core::fmt::Error);
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
    pub fn map_from_existed_page_table(
        &mut self,
        dst_page_table: &mut PageTable,
        src_page_table: &mut PageTable,
    ) -> Result {
        let map_perm = self.map_perm.difference(MapPermission::W);
        let pte_flags = PTEFlags::from_bits(map_perm.bits).unwrap();
        for vpn in self.data_frames.vpn_range {
            if let Some(pte) = src_page_table.translate_refmut(vpn) {
                let ppn = pte.ppn();
                if !dst_page_table.is_mapped(vpn) {
                    dst_page_table.map(vpn, ppn, pte_flags);
                    pte.set_permission(map_perm);
                } else {
                    return Err(core::fmt::Error);
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
    ) -> Result {
        let kernel_space = KERNEL_SPACE.lock();
        let kernel_elf_area = kernel_space.areas.last().unwrap();
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
                    return Err(core::fmt::Error);
                }
            } else {
                error!("[map_from_kernel_elf_area] kernel vpn invalid!");
                return Err(core::fmt::Error);
            }
            src_vpn = (src_vpn.0 + 1).into();
        }
        Ok(())
    }
    /// Unmap all pages in `self` from `page_table` using unmap_one()
    pub fn unmap(&mut self, page_table: &mut PageTable) -> Result {
        let mut has_unmapped_page = false;
        for vpn in self.data_frames.vpn_range {
            // it's normal to get an `Error` because we are using lazy alloc strategy
            // we still need to unmap remaining pages of `self`, just throw this `Error` to caller
            if let Err(_) = self.unmap_one(page_table, vpn) {
                has_unmapped_page = true;
            }
        }
        if has_unmapped_page {
            Err(core::fmt::Error)
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
    pub fn copy_on_write(&mut self, page_table: &mut PageTable, vpn: VirtPageNum) -> Result {
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
    /// If `new_end` is lower than the current end of heap area, do nothing and return `Ok(())`.
    pub fn expand_to(&mut self, page_table: &mut PageTable, new_end: VirtAddr) -> Result {
        let new_end_vpn: VirtPageNum = new_end.ceil();
        let old_end_vpn = self.data_frames.vpn_range.get_end();
        // `set_end` must be done before calling `map_one`
        // because `map_one` will insert frames into `data_frames`
        // if we don't `set_end` in advance, this insertion is out of bound
        unsafe { self.data_frames.set_end(new_end_vpn) };
        for vpn in VPNRange::new(old_end_vpn, new_end_vpn) {
            if let Err(_) = self.map_one(page_table, vpn) {
                return Err(core::fmt::Error);
            }
        }
        Ok(())
    }
    /// If `new_end` is higher than the current end of heap area, do nothing and return `Ok(())`.
    pub fn shrink_to(&mut self, page_table: &mut PageTable, new_end: VirtAddr) -> Result {
        let end_vpn: VirtPageNum = new_end.ceil();
        for vpn in VPNRange::new(end_vpn, self.data_frames.vpn_range.get_end()) {
            if let Err(_) = self.unmap_one(page_table, vpn) {
                return Err(core::fmt::Error);
            }
        }
        // `set_end` must be done after calling `map_one`
        // for the similar reason with `expand_to`
        unsafe { self.data_frames.set_end(end_vpn) };
        Ok(())
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

pub fn mmap(
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
            warn!("[mmap] file-backed map!");
            if fd >= inner.fd_table.len() {
                // fd is not a valid file descriptor (and MAP_ANONYMOUS was not set)
                return EBADF as usize;
            }
            if let Some(fd) = &inner.fd_table[fd] {
                match &fd.file {
                    FileLike::Regular(inode) => {
                        // A file mapping was requested, but fd is not open for reading
                        if !inode.readable() {
                            return EACCES as usize;
                        }
                        inode.lseek(offset as isize, crate::syscall::fs::SeekWhence::SEEK_SET);
                    }
                    // A file descriptor refers to a non-regular file
                    _ => {
                        return EACCES as usize;
                    }
                }
                new_area.map_file = Some(fd.file.clone());
            } else {
                // fd is not a valid file descriptor (and MAP_ANONYMOUS was not set)
                return EBADF as usize;
            }
        }
        // the last one is trap context, we insert mmap area to the slot right before trap context (len - 2)
        let idx = inner.memory_set.areas.len() - 2;
        inner.memory_set.areas.insert(idx, new_area);
        start_va.0
    }
}

/// Still have so much to do with this function.
pub fn munmap(start: usize, len: usize) -> isize {
    let task = current_task().unwrap();
    let mut inner = task.acquire_inner_lock();
    inner
        .memory_set
        .remove_area_with_start_vpn(VirtAddr::from(start).into())
        .unwrap();
    SUCCESS
}

pub fn sbrk(increment: isize) -> usize {
    let task = current_task().unwrap();
    let mut inner = task.acquire_inner_lock();
    let old_pt: usize = inner.heap_pt;
    let new_pt: usize = old_pt + increment as usize;
    if increment > 0 {
        let limit = inner.heap_bottom + USER_HEAP_SIZE;
        if new_pt > limit {
            warn!(
                "[sbrk] out of the upperbound! upperbound: {:X}, old_pt: {:X}, new_pt: {:X}",
                limit, old_pt, new_pt
            );
            return old_pt;
        } else {
            let idx = inner.memory_set.heap_area_idx.unwrap();
            // first time to expand heap area, insert heap area
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
            // the process already have a heap area, adjust it
            } else {
                let memory_set = &mut inner.memory_set;
                let heap_area = &mut memory_set.areas[idx];
                let page_table = &mut memory_set.page_table;
                heap_area
                    .expand_to(page_table, VirtAddr::from(new_pt))
                    .unwrap();
                trace!("[sbrk] heap area expended to {:X}", new_pt);
            }
            inner.heap_pt = new_pt;
        }
    } else if increment < 0 {
        // shrink to `heap_bottom` would cause duplicated insertion of heap area in future
        // so we simply reject it here
        if new_pt <= inner.heap_bottom {
            warn!(
                "[sbrk] out of the lowerbound! lowerbound: {:X}, old_pt: {:X}, new_pt: {:X}",
                inner.heap_bottom, old_pt, new_pt
            );
            return old_pt;
        // attention that if the process never call sbrk before, it would have no heap area
        // we only do shrinking when it does have a heap area
        } else if let Some(idx) = inner.memory_set.heap_area_idx {
            let memory_set = &mut inner.memory_set;
            let heap_area = &mut memory_set.areas[idx];
            let page_table = &mut memory_set.page_table;
            heap_area
                .shrink_to(page_table, VirtAddr::from(new_pt))
                .unwrap();
            trace!("[sbrk] heap area shrinked to {:X}", new_pt);
        }
        // we need to adjust `heap_pt` if it's not out of bound
        // in spite of whether the process has a heap area
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
