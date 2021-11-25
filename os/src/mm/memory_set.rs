use super::{frame_alloc, FrameTracker};
use super::{PTEFlags, PageTable, PageTableEntry};
use super::{PhysAddr, PhysPageNum, VirtAddr, VirtPageNum};
use super::{StepByOne, VPNRange};
use super::{UserBuffer, translated_byte_buffer};
use crate::config::*;
use crate::fs::{File, FileClass, FileDescripter};
use crate::task::{FdTable, AuxHeader};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Result;
use lazy_static::*;
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
}

lazy_static! {
    pub static ref KERNEL_SPACE: Arc<Mutex<MemorySet>> =
        Arc::new(Mutex::new(MemorySet::new_kernel()));
}

pub fn kernel_token() -> usize {
    KERNEL_SPACE.lock().token()
}

pub struct MemorySet {
    page_table: PageTable,
    areas: Vec<MapArea>,
    heap_areas: Vec<MapArea>,
    mmap_areas: Vec<MmapArea>,
}

impl MemorySet {
    pub fn munmap(&mut self, start: usize, len: usize) -> i32 {
        if len == 0 {
            return 0;
        }
        let mut m = MapArea::new(
            start.into(),
            (len + start).into(),
            MapType::Framed,
            MapPermission::X,
        );
        if let Err(_) = m.unmap(&mut self.page_table) {
            unsafe {
                llvm_asm!("sfence.vma" :::: "volatile");
            }
            return -1;
        }
        unsafe {
            llvm_asm!("sfence.vma" :::: "volatile");
        }
        return len as i32;
    }
    pub fn alloc(
        &mut self,
        mut start: usize, // 开始地址
        len: usize,       // 内存映射长度
        prot: usize,      // 保护位标志
    ) -> i32 {
        if len == 0 {
            return 0;
        }
        if (prot & 0x7 == 0) || (prot & !0x7 != 0) || len > 0x1_000_000_000 {
            return -1;
        }
        let mut chk = MapPermission::R | MapPermission::W | MapPermission::X;
        let mut per: u8 = prot as u8;
        per = chk.bits() & per;
        chk = !chk;
        if (prot & (chk.bits() as usize)) != 0 {
            return -1;
        }
        if let Some(i) = MapPermission::from_bits(per) {
            let m: MapArea = MapArea::new(start.into(), (len + start).into(), MapType::Framed, i);
            if let Ok(_) = self.push(m, None) {
                unsafe {
                    llvm_asm!("sfence.vma" :::: "volatile");
                }
                return ((((start + len) - 1 + PAGE_SIZE) / PAGE_SIZE - start / PAGE_SIZE)
                    * PAGE_SIZE) as i32;
            //this was the size
            } else {
                return -1;
            }
        } else {
            return -1;
        }
    }
    /// 建立从文件到内存的映射
    pub fn mmap(
        &mut self,
        mut start: usize, // 开始地址
        len: usize,       // 内存映射长度
        prot: usize,      // 保护位标志
        flags: usize,     // 映射方式
        fd: usize,        // 被映射文件
        offset: usize,    // 文件位移
    ) -> i32 {
        let m: MapArea;
        //内存分配模块
        match flags {
            _ => {
                return -1;
            }
            MAP_PRIVATE => {
                if len == 0 {
                    return 0;
                }
                if (prot & 0x7 == 0) || (prot & !0x7 != 0) || len > 0x1_000_000_000 {
                    return -1;
                }
                let mut chk = MapPermission::R | MapPermission::W | MapPermission::X;
                let mut per: u8 = prot as u8;
                per = chk.bits() & per;
                chk = !chk;
                if (prot & (chk.bits() as usize)) != 0 {
                    return -1;
                }
                if let Some(i) = MapPermission::from_bits(per) {
                    m = MapArea::new(start.into(), (len + start).into(), MapType::Framed, i);
                    if let Ok(_) = self.push(m, None) {
                        unsafe {
                            llvm_asm!("sfence.vma" :::: "volatile");
                        }
                    /*                        return ((((start + len) - 1 + PAGE_SIZE) / PAGE_SIZE - start / PAGE_SIZE)
                     * PAGE_SIZE) as i32;*/
                    //this was the size
                    } else {
                        return -1;
                    }
                } else {
                    return -1;
                }
            }
        }
        unsafe { crate::syscall::fs::sys_read(fd, start as *const u8, len) as i32 }
    }

    pub fn new_bare() -> Self {
        Self {
            page_table: PageTable::new(),
            areas: Vec::new(),
            heap_areas: Vec::new(),
            mmap_areas: Vec::new(),
        }
    }
    pub fn token(&self) -> usize {
        self.page_table.token()
    }
    /// Assume that no conflicts.
    pub fn insert_framed_area(
        &mut self,
        start_va: VirtAddr,
        end_va: VirtAddr,
        permission: MapPermission,
    ) {
        self.push(
            MapArea::new(start_va, end_va, MapType::Framed, permission),
            None,
        );
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
        // println!{"3"}
        map_area.map(&mut self.page_table);
        if let Some(data) = data {
            map_area.copy_data(&mut self.page_table, data, offset);
        }
        self.areas.push(map_area);
    }
    pub fn get_mmap_top(&mut self) -> VirtAddr {
        match self.mmap_areas.last() {
            Some(mmap_area) => mmap_area.area.vpn_range.get_end().into(),
            None => MMAP_BASE.into()
        }
    }
    pub fn insert_mmap_area(
        &mut self,
        start_va: VirtAddr,
        len: usize,
        permission: MapPermission,
        flags: usize,
        fd: isize,
        offset: usize,
        fd_table: FdTable,
        token: usize,
    ) {
        let end_va = (start_va.0 + len).into();
        let mut mmap_area = MmapArea::new(fd, start_va, end_va, permission);
        self.push_mmap_area(
            mmap_area,
            start_va,
            len,
            permission,
            flags,
            fd,
            offset,
            fd_table,
            token
        );
    }
    pub fn remove_mmap_area_with_start_vpn(&mut self, start_vpn: VirtPageNum) {
        if let Some((idx, mmap_area)) = self
            .mmap_areas
            .iter_mut()
            .enumerate()
            .find(|(_, mmap_area)| mmap_area.area.vpn_range.get_start() == start_vpn)
        {
            mmap_area.area.unmap(&mut self.page_table);
            self.mmap_areas.remove(idx);
        }
    }
    pub fn push_mmap_area(
        &mut self,
        mut mmap_area: MmapArea,
        start_va: VirtAddr,
        len: usize,
        permission: MapPermission,
        flags: usize,
        fd: isize,
        offset: usize,
        fd_table: FdTable,
        token: usize,
    ) -> Result {
        if let Err(_) = mmap_area.area.map(&mut self.page_table) {
            return Err(core::fmt::Error);
        }
        mmap_area.map_file(start_va, len, flags, offset, fd_table, token);
        self.mmap_areas.push(mmap_area);
        Ok(())
    }
    pub fn insert_heap_area(
        &mut self,
        start_va: VirtAddr,
        end_va: VirtAddr,
        permission: MapPermission,
    ) {
        self.push_heap_area(
            MapArea::new(start_va, end_va, MapType::Framed, permission),
            None,
        );
    }
    pub fn remove_heap_area_with_start_vpn(&mut self, start_vpn: VirtPageNum) {
        if let Some((idx, heap_area)) = self
            .heap_areas
            .iter_mut()
            .enumerate()
            .find(|(_, heap_area)| heap_area.vpn_range.get_start() == start_vpn)
        {
            heap_area.unmap(&mut self.page_table);
            self.heap_areas.remove(idx);
        }
    }
    pub fn push_heap_area(&mut self, mut heap_area: MapArea, data: Option<&[u8]>) -> Result {
        if let Err(_) = heap_area.map(&mut self.page_table) {
            return Err(core::fmt::Error);
        }
        if let Some(data) = data {
            heap_area.copy_data(&mut self.page_table, data, 0);
        }
        self.heap_areas.push(heap_area);
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
    /// Without kernel stacks.
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
        println!("mapping .text section");
        memory_set.push(
            MapArea::new(
                (stext as usize).into(),
                (etext as usize).into(),
                MapType::Identical,
                MapPermission::R | MapPermission::X,
            ),
            None,
        );
        println!("mapping .rodata section");
        memory_set.push(
            MapArea::new(
                (srodata as usize).into(),
                (erodata as usize).into(),
                MapType::Identical,
                MapPermission::R,
            ),
            None,
        );
        println!("mapping .data section");
        memory_set.push(
            MapArea::new(
                (sdata as usize).into(),
                (edata as usize).into(),
                MapType::Identical,
                MapPermission::R | MapPermission::W,
            ),
            None,
        );
        println!("mapping .bss section");
        memory_set.push(
            MapArea::new(
                (sbss_with_stack as usize).into(),
                (ebss as usize).into(),
                MapType::Identical,
                MapPermission::R | MapPermission::W,
            ),
            None,
        );
        println!("mapping physical memory");
        memory_set.push(
            MapArea::new(
                (ekernel as usize).into(),
                MEMORY_END.into(),
                MapType::Identical,
                MapPermission::R | MapPermission::W,
            ),
            None,
        );
        println!("mapping memory-mapped registers");
        for pair in MMIO {
            memory_set.push(
                MapArea::new(
                    (*pair).0.into(),
                    ((*pair).0 + (*pair).1).into(),
                    MapType::Identical,
                    MapPermission::R | MapPermission::W,
                ),
                None,
            );
        }
        memory_set
    }
    /// Include sections in elf and trampoline and TrapContext and user stack,
    /// also returns user_sp and entry point.
    pub fn from_elf(elf_data: &[u8]) -> (Self, usize, usize, usize, Vec<AuxHeader>) {
        let mut auxv:Vec<AuxHeader> = Vec::new();
        let mut memory_set = Self::new_bare();
        // map trampoline
        memory_set.map_trampoline();
        // map program headers of elf, with U flag
        let elf = xmas_elf::ElfFile::new(elf_data).unwrap();
        let elf_header = elf.header;
        let magic = elf_header.pt1.magic;
        assert_eq!(magic, [0x7f, 0x45, 0x4c, 0x46], "invalid elf!");
        let ph_count = elf_header.pt2.ph_count();
        let mut max_end_vpn = VirtPageNum(0);
        let mut head_va = 0; // top va of ELF which points to ELF header
        // push ELF related auxv
        auxv.push(AuxHeader{aux_type: AT_PHENT, value: elf.header.pt2.ph_entry_size() as usize});// ELF64 header 64bytes
        auxv.push(AuxHeader{aux_type: AT_PHNUM, value: ph_count as usize});
        auxv.push(AuxHeader{aux_type: AT_PAGESZ, value: PAGE_SIZE as usize});
        auxv.push(AuxHeader{aux_type: AT_BASE, value: 0 as usize});
        auxv.push(AuxHeader{aux_type: AT_FLAGS, value: 0 as usize});
        auxv.push(AuxHeader{aux_type: AT_ENTRY, value: elf.header.pt2.entry_point() as usize});
        auxv.push(AuxHeader{aux_type: AT_UID, value: 0 as usize});
        auxv.push(AuxHeader{aux_type: AT_EUID, value: 0 as usize});
        auxv.push(AuxHeader{aux_type: AT_GID, value: 0 as usize});
        auxv.push(AuxHeader{aux_type: AT_EGID, value: 0 as usize});
        auxv.push(AuxHeader{aux_type: AT_PLATFORM, value: 0 as usize});
        auxv.push(AuxHeader{aux_type: AT_HWCAP, value: 0 as usize});
        auxv.push(AuxHeader{aux_type: AT_CLKTCK, value: 100 as usize});
        auxv.push(AuxHeader{aux_type: AT_SECURE, value: 0 as usize});
        auxv.push(AuxHeader{aux_type: AT_NOTELF, value: 0x112d as usize});

        for ph in elf.program_iter(){
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
                let map_area = MapArea::new(start_va, end_va, MapType::Framed, map_perm);
                max_end_vpn = map_area.vpn_range.get_end();
                if offset == 0 {
                    head_va = start_va.into();
                    memory_set.push(
                        map_area,
                        Some(
                            &elf.input
                                [ph.offset() as usize..(ph.offset() + ph.file_size()) as usize],
                        ),
                    );
                } else {
                    memory_set.push_with_offset(
                        map_area,
                        offset,
                        Some(
                            &elf.input
                                [ph.offset() as usize..(ph.offset() + ph.file_size()) as usize],
                        ),
                    );
                }
                println!("[elf] LOAD SEGMENT PUSHED. start_va = 0x{:X}; end_va = 0x{:X}, offset = 0x{:X}", start_va.0, end_va.0, offset);
            }
        }

        // Get ph_head addr for auxv
        let ph_head_addr = head_va + elf.header.pt2.ph_offset() as usize;
        auxv.push(AuxHeader{aux_type: AT_PHDR, value: ph_head_addr as usize});

        let mut user_stack_top: usize = TRAP_CONTEXT;
        user_stack_top -= PAGE_SIZE;
        let user_stack_bottom: usize = user_stack_top - USER_STACK_SIZE;

        let max_end_va: VirtAddr = max_end_vpn.into();
        let mut user_heap_bottom: usize = max_end_va.into();
        // guard page
        user_heap_bottom += PAGE_SIZE;


        memory_set.push(
            MapArea::new(
                user_stack_bottom.into(),
                user_stack_top.into(),
                MapType::Framed,
                MapPermission::R | MapPermission::W | MapPermission::U,
            ),
            None,
        );
        println!(
            "[elf] USER STACK PUSHED. user_stack_top:{:X}; user_stack_bottom:{:X}",
            user_stack_top, user_stack_bottom
        );
        // map TrapContext
        memory_set.push(
            MapArea::new(
                TRAP_CONTEXT.into(),
                TRAMPOLINE.into(),
                MapType::Framed,
                MapPermission::R | MapPermission::W,
            ),
            None,
        );
        println!(
            "[elf] TRAP CONTEXT PUSHED. start_va:{:X}; end_va:{:X}",
            TRAP_CONTEXT, TRAMPOLINE
        );
        (
            memory_set,
            user_stack_top,
            user_heap_bottom,
            elf.header.pt2.entry_point() as usize,
            auxv,
        )
    }
    pub fn from_existed_user(user_space: &MemorySet) -> MemorySet {
        let mut memory_set = Self::new_bare();
        // map trampoline
        memory_set.map_trampoline();
        // copy data sections/trap_context/user_stack
        for area in user_space.areas.iter() {
            let new_area = MapArea::from_another(area);
            memory_set.push(new_area, None);
            // copy data from another space
            for vpn in area.vpn_range {
                let src_ppn = user_space.translate(vpn).unwrap().ppn();
                let dst_ppn = memory_set.translate(vpn).unwrap().ppn();
                dst_ppn
                    .get_bytes_array()
                    .copy_from_slice(src_ppn.get_bytes_array());
            }
        }
        memory_set
    }
    pub fn activate(&self) {
        let satp = self.page_table.token();
        unsafe {
            satp::write(satp);
            llvm_asm!("sfence.vma" :::: "volatile");
        }
    }
    pub fn translate(&self, vpn: VirtPageNum) -> Option<PageTableEntry> {
        self.page_table.translate(vpn)
    }
    pub fn set_pte_flags(&mut self, vpn: VirtPageNum, flags: usize) -> isize{
        self.page_table.set_pte_flags(vpn, flags)
    }
    pub fn recycle_data_pages(&mut self) {
        //*self = Self::new_bare();
        self.areas.clear();
    }
}

pub struct MapArea {
    vpn_range: VPNRange,
    data_frames: BTreeMap<VirtPageNum, FrameTracker>,
    map_type: MapType,
    map_perm: MapPermission,
}

impl MapArea {
    pub fn new(
        start_va: VirtAddr,
        end_va: VirtAddr,
        map_type: MapType,
        map_perm: MapPermission,
    ) -> Self {
        let start_vpn: VirtPageNum = start_va.floor();
        let end_vpn: VirtPageNum = end_va.ceil();
        println!(
            "[MapArea new] start_vpn:{:X}; end_vpn:{:X}; map_perm:{:b}",
            start_vpn.0, end_vpn.0, map_perm.bits()
        );
        Self {
            vpn_range: VPNRange::new(start_vpn, end_vpn),
            data_frames: BTreeMap::new(),
            map_type,
            map_perm,
        }
    }
    pub fn from_another(another: &MapArea) -> Self {
        Self {
            vpn_range: VPNRange::new(another.vpn_range.get_start(), another.vpn_range.get_end()),
            data_frames: BTreeMap::new(),
            map_type: another.map_type,
            map_perm: another.map_perm,
        }
    }
    pub fn map_one(&mut self, page_table: &mut PageTable, vpn: VirtPageNum) -> Result {
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
        if !page_table.is_mapped(vpn) {
            page_table.map(vpn, ppn, pte_flags);
            Ok(())
        } else {
            Err(core::fmt::Error)
        }
    }
    pub fn unmap_one(&mut self, page_table: &mut PageTable, vpn: VirtPageNum) -> Result {
        match self.map_type {
            MapType::Framed => {
                self.data_frames.remove(&vpn);
            }
            _ => {}
        }
        if !page_table.is_mapped(vpn) {
            return Err(core::fmt::Error);
        }
        page_table.unmap(vpn);
        Ok(())
    }
    pub fn map(&mut self, page_table: &mut PageTable) -> Result {
        for vpn in self.vpn_range {
            if let Err(_) = self.map_one(page_table, vpn) {
                return Err(core::fmt::Error);
            }
        }
        Ok(())
    }
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
}

pub struct MmapArea {
    fd: isize,
    area: MapArea,
}

impl MmapArea {
    pub fn new(
        fd: isize,
        start_va: VirtAddr,
        end_va: VirtAddr,
        map_perm: MapPermission,
    ) -> Self {
        println!("[MmapArea new] fd:{:X}; start_va:{:X}; end_va:{:X}", fd, start_va.0, end_va.0);
        Self {
            fd,
            area: MapArea::new(start_va, end_va, MapType::Framed, map_perm),
        }
    }
    pub fn map_file(&mut self, start_va: VirtAddr, len: usize, flags: usize, offset: usize, fd_table: FdTable, token: usize) -> isize {
        let flags = MmapFlags::from_bits(flags).unwrap();
        if flags.contains(MmapFlags::MAP_ANONYMOUS)
            && self.fd == -1 
            && offset == 0 {
            println!("[map file] map anonymous file");
            return 1;
        }

        if self.fd as usize >= fd_table.len() { return -1; }

        if let Some(file) = &fd_table[self.fd as usize] {
            match &file.fclass {
                FileClass::File(f)=>{
                    f.set_offset(offset);
                    if !f.readable() { return -1; }
                    println!{"[map file] The start_va is 0x{:X}, offset of file is {}", start_va.0, offset};
                    let read_len = f.read(UserBuffer::new(translated_byte_buffer(token, start_va.0 as *const u8, len)));
                    println!{"[map file] read {} bytes", read_len};
                },
                _ => { return -1; },
            };
        } else { return -1 };
        return 1;
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
    pub struct MmapFlags: usize {
        const MAP_FILE = 0;
        const MAP_SHARED= 0x01;
        const MAP_PRIVATE = 0x02;
        const MAP_FIXED = 0x10;
        const MAP_ANONYMOUS = 0x20;
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
    println!("remap_test passed!");
}
