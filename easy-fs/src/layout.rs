use super::BLOCK_SZ;
use alloc::string::{String, ToString};
use core::{convert::TryInto, fmt::Debug, iter::empty, mem, ops::Add};

pub const BAD_BLOCK: u32 = 0x0FFF_FFF7;
pub const DIR_ENTRY_UNUSED: u8 = 0xe5;
pub const DIR_ENTRY_LAST_AND_UNUSED: u8 = 0x0;
pub const LAST_LONG_ENTRY: u8 = 0x40u8;
#[derive(Debug, Clone, Copy)]
#[repr(packed)]
/// *On-disk* data structure for partition information.
pub struct BPB {
    /// x86 assembly to jump instruction to boot code.
    pub bs_jmp_boot: [u8; 3],
    /// “MSWIN4.1” There are many misconceptions about this field.
    /// It is only a name string. Unlike some FAT drivers,
    /// Microsoft operating systems don’t pay any attention to this field.
    pub bs_oem_name: [u8; 8],
    /// Bytes per sector, 512 for SD card
    pub byts_per_sec: u16,
    /// sector per cluster, usually 8 for SD card
    pub sec_per_clus: u8,
    /// sector number of the reserved area
    pub rsvd_sec_cnt: u16,
    /// Number of FATs
    pub num_fats: u8,
    /// Have to be ZERO for FAT32.
    /// Positioned at offset
    pub root_ent_cnt: u16,
    /// For FAT32 volumes, this field must be 0.
    pub tot_sec16: u16,
    /// Used to denote the media type. This is a legacy field that is no longer in use.
    /// 0xF8 is the standard value for “fixed” (non-removable) media.
    /// For removable media, 0xF0 is frequently used.
    /// The legal values for this field are:
    /// 0xF0, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, and 0xFF.
    pub media: u8,
    /// On FAT32 volumes this field must be 0, and fat_sz32 contains the FAT size count.
    pub fat_sz16: u16,
    /// Sector per track used by interrupt 0x13, not needed by SD card.
    pub sec_per_trk: u16,
    /// Number of heads for interrupt 0x13.    
    /// This field is relevant as discussed earlier for BPB_SecPerTrk.
    /// This field contains the one based “count of heads”.
    /// For example, on a 1.44 MB 3.5-inch floppy drive this value is 2.
    pub num_heads: u16,
    pub hidd_sec: u32,
    pub tot_sec32: u32,
    pub fat_sz32: u32,
    pub ext_flags: u16,
    pub fs_ver: u16,
    /// This is set to the cluster number of the first cluster of the root directory,
    /// usually 2 but not required to be 2.
    /// Unique to FAT32.
    pub root_clus: u32,
    /// Sector number of FSINFO structure in the reserved area of the
    /// FAT32 volume. Usually 1.   
    /// Unique to FAT32.
    pub fs_info: u16,
    /// If non-zero, indicates the sector number in the reserved area
    /// of the volume of a copy of the boot record.
    /// Usually 6. No value other than 6 is recommended.
    /// Unique to FAT32.
    pub bk_boot_sec: u16,
    pub reserved: [u8; 12],

    pub drv_num: u8,
    pub resvered1: u8,
    pub boot_sig: u8,
    pub vol_id: u32,
    pub vol_lab: [u8; 11],
    pub fil_sys_type: [u8; 8],
}

/*impl Clone for BPB {
    fn clone(&self) -> Self {
        unsafe {
            Self {
                bs_jmp_boot: self.bs_jmp_boot.clone(),
                bs_oem_name: self.bs_oem_name.clone(),
                byts_per_sec: self.byts_per_sec.clone(),
                sec_per_clus: self.sec_per_clus.clone(),
                rsvd_sec_cnt: self.rsvd_sec_cnt.clone(),
                num_fats: self.num_fats.clone(),
                root_ent_cnt: self.root_ent_cnt.clone(),
                tot_sec16: self.tot_sec16.clone(),
                media: self.media.clone(),
                fat_sz16: self.fat_sz16.clone(),
                sec_per_trk: self.sec_per_trk.clone(),
                num_heads: self.num_heads.clone(),
                hidd_sec: self.hidd_sec.clone(),
                tot_sec32: self.tot_sec32.clone(),
                fat_sz32: self.fat_sz32.clone(),
                ext_flags: self.ext_flags.clone(),
                fs_ver: self.fs_ver.clone(),
                root_clus: self.root_clus.clone(),
                fs_info: self.fs_info.clone(),
                bk_boot_sec: self.bk_boot_sec.clone(),
                reserved: self.reserved.clone(),
                drv_num: self.drv_num.clone(),
                resvered1: self.resvered1.clone(),
                boot_sig: self.boot_sig.clone(),
                vol_id: self.vol_id.clone(),
                vol_lab: self.vol_lab.clone(),
                fil_sys_type: self.fil_sys_type.clone(),
            }
        }
    }
}*/

/* impl Debug for BPB {
 *     fn fmt(&self, f: &mut Formatter<'_>) -> Result {
 *         f.debug_struct("BPB")
 *             .field("total_sec32", &self.tot_sec32)
 *             .finish()
 *     }
 * } */
pub enum FatType {
    FAT32,
    FAT16,
    FAT12,
}
impl BPB {
    #[inline(always)]
    pub fn is_valid(&self) -> bool {
        self.root_dir_sec() == 0
            && self.tot_sec16 == 0
            && self.count_of_cluster() >= 66625 /*May not apply to the REAL WORLD/test*/
            && self.fat_sz16 == 0
            && self.root_ent_cnt == 0
    }
    #[inline(always)]
    pub fn data_sector_count(&self) -> u32 {
        self.tot_sec32
            - (self.rsvd_sec_cnt as u32
                + self.num_fats as u32 * self.fat_sz32
                + self.root_dir_sec())
    }
    /// May be WRONG! This function should round DOWN.
    #[inline(always)]
    pub fn count_of_cluster(&self) -> u32 {
        self.data_sector_count() / (self.sec_per_clus as u32)
    }
    #[inline(always)]
    /// The size of cluster counted by the sectors.
    pub fn clus_size(&self) -> u32 {
        (self.byts_per_sec * (self.sec_per_clus as u16)) as u32
    }
    /// Sectors occupied by the root directory
    /// May be WRONG! Should be rounded UP.
    #[inline(always)]
    pub fn root_dir_sec(&self) -> u32 {
        (((self.root_ent_cnt * 32) + (self.byts_per_sec - 1)) / (self.byts_per_sec)) as u32
    }
    #[inline(always)]
    /// The first data sector beyond the root directory
    pub fn data_sector_beg(&self) -> u32 {
        self.first_data_sector()
    }
    #[inline(always)]
    /// The first data sector beyond the root directory
    pub fn first_data_sector(&self) -> u32 {
        let fat_sz: u32;
        if self.fat_sz16 != 0 {
            fat_sz = self.fat_sz16 as u32;
        } else {
            fat_sz = self.fat_sz32 as u32;
        }
        (self.rsvd_sec_cnt as u32) + (self.num_fats as u32) * fat_sz + self.root_dir_sec()
    }
    #[inline(always)]
    pub fn fat_type(&self) -> FatType {
        if self.count_of_cluster() < 4085 {
            FatType::FAT12
        } else if self.count_of_cluster() < 65525 {
            FatType::FAT16
        } else {
            FatType::FAT32
        }
    }
}

#[derive(Debug, Clone)]
#[repr(C)]
/// *On-disk* data structure.
/// The direct creation/storage of this struct should avoided since the size of reserved area is rather big.
pub struct FSInfo {
    /// Value 0x41615252. This lead signature is used to validate that this is in fact an FSInfo sector.
    lead_sig: u32,
    /// The reserved area should be empty.
    reserved1: [u8; 480],
    /// Value 0x61417272. Another signature that is more localized in the sector to the location of the fields that are used.
    struc_sig: u32,
    /// Contains the last known free cluster count on the volume. If the
    /// value is 0xFFFFFFFF, then the free count is unknown and must be
    /// computed. Any other value can be used, but is not necessarily
    /// correct. It should be range checked at least to make sure it is <=
    /// volume cluster count.
    free_count: u32,
    /// This is a hint for the FAT driver. It indicates the cluster number at
    /// which the driver should start looking for free clusters. Because a
    /// FAT32 FAT is large, it can be rather time consuming if there are a
    /// lot of allocated clusters at the start of the FAT and the driver starts
    /// looking for a free cluster starting at cluster 2. Typically this value is
    /// set to the last cluster number that the driver allocated. If the value is
    /// 0xFFFFFFFF, then there is no hint and the driver should start
    /// looking at cluster 2. Any other value can be used, but should be
    /// checked first to make sure it is a valid cluster number for the
    /// volume.
    nxt_free: u32,
    reserved2: [u8; 12],
    /// Value 0xAA550000.
    /// This trail signature is used to validate that this is in fact an FSInfo sector.
    /// Note that the high 2 bytes of this value which go into the bytes at offsets 510 and 511
    /// match the signature bytes used at the same offsets in sector 0.
    trail_sig: u32,
}
impl FSInfo {
    #[allow(unused)]
    /* fn new(block_offset: usize, bpb: &BPB, block_device: Arc<dyn BlockDevice>) -> Self {
     *     let mut ret: Self = unsafe { mem::zeroed() };
     *     get_block_cache(bpb.fs_info.into(), block_device)
     *         .lock()
     *         .read(block_offset, |get: &FSInfo| ret = get.clone());
     *     ret
     * } */
    /// Free a cluster if it is marked used.
    #[allow(unused)]
    fn free_clus(clus_num: usize) {}
}

#[derive(PartialEq)]
pub enum DiskInodeType {
    File,
    Directory,
}

pub type DataBlock = [u8; BLOCK_SZ];

#[derive(PartialEq, Debug, Clone, Copy)]
#[repr(u8)]
pub enum FATDiskInodeType {
    AttrClear = 0,
    AttrReadOnly = 0x01,
    AttrHidden = 0x02,
    AttrSystem = 0x04,

    /// Root Dir
    AttrVolumeID = 0x08,
    AttrDirectory = 0x10,
    AttrArchive = 0x20,
    AttrLongName = 0x0F,
}
pub union FATDirEnt {
    pub short_entry: FATDirShortEnt,
    pub long_entry: FATLongDirEnt,
}

impl Debug for FATDirEnt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if !self.is_long() {
            f.debug_struct("FATDirEnt")
                .field("SHORT", unsafe { &self.short_entry })
                .finish()
        } else {
            f.debug_struct("FATDirEnt")
                .field("LONG", unsafe { &self.long_entry })
                .finish()
        }
    }
}

impl FATDirEnt {
    /// Test whether `self` is a short entry
    /// and whether the short entry name of `self` is the same type of `prefix`.
    pub fn short_ent_name_match(&self, prefix: &String) -> bool {
        let name = self.get_name();
        if self.is_short() && {
            if let Some(i) = name.split_once("~") {
                i.0 == prefix
            } else {
                *prefix == name
            }
        } {
            true
        } else {
            false
        }
    }
    pub fn is_8_3(s: String) -> bool {
        s.is_ascii() && s.to_ascii_uppercase() == s
    }
    /// Embedded spaces within a long name are allowed.
    /// Leading and trailing spaces in a long name are ignored.
    /// Leading and embedded periods are allowed in a name and are stored in the long name.
    /// Trailing periods are ignored.
    /// No '~' or trailing numbers
    pub fn gen_short_name_prefix(s: String) -> String {
        "TESTXT".to_string()
        // let mut m = s;
        // m.to_uppercase().retain(|c| !r#" "#.contains(c));
        // m = m.trim_start_matches(".").to_string();
        // if m.len() <= 8 {
        //     m = m.split_off(8);
        // }
        // todo!();
        // m
    }
    pub fn get_ord(&self) -> usize {
        self.ord()
    }
    pub fn empty() -> Self {
        Self {
            short_entry: FATDirShortEnt::empty(),
        }
    }
    pub fn unused_not_last_entry() -> Self {
        let mut i = Self::empty();
        i.as_bytes_mut()[0] = DIR_ENTRY_UNUSED;
        i
    }
    pub fn unused_and_last_entry() -> Self {
        let mut i = Self::empty();
        i.as_bytes_mut()[0] = DIR_ENTRY_LAST_AND_UNUSED;
        i.as_bytes_mut()[11] = 0u8;
        i
    }
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const _ as usize as *const u8,
                mem::size_of::<Self>(),
            )
        }
    }
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe {
            core::slice::from_raw_parts_mut(
                self as *mut _ as usize as *mut u8,
                mem::size_of::<Self>(),
            )
        }
    }
    pub fn is_last_long_dir_ent(&self) -> bool {
        if let Some(i) = self.get_long_ent() {
            if (i.ord & LAST_LONG_ENTRY) != 0 {
                true
            } else {
                false
            }
        } else {
            false
        }
    }
    pub fn ord(&self) -> usize {
        if let Some(i) = self.get_long_ent() {
            (i.ord & (LAST_LONG_ENTRY - 1)) as usize // 0x40 is used as the "final" mask
        } else {
            0
        }
    }
    pub fn set_size(&mut self, size: u32) {
        {
            self.short_entry.file_size = size
        };
    }
    pub fn set_fst_clus(&mut self, fst_clus: u32) {
        if self.is_short() {
            unsafe {
                self.short_entry.set_fst_clus(fst_clus);
            }
        }
    }
    pub fn is_long(&self) -> bool {
        unsafe { self.short_entry.attr == FATDiskInodeType::AttrLongName }
    }
    #[allow(unused)]
    pub fn is_short(&self) -> bool {
        //unsafe { self.short_entry.attr == FATDiskInodeType::AttrLongName }
        !self.is_long()
    }
    pub fn get_short_ent(&self) -> Option<&FATDirShortEnt> {
        if !self.is_long() {
            unsafe { Some(&(self.short_entry)) }
        } else {
            None
        }
    }
    pub fn get_long_ent(&self) -> Option<&FATLongDirEnt> {
        if self.is_long() {
            unsafe { Some(&(self.long_entry)) }
        } else {
            None
        }
    }
    pub fn get_name(&self) -> String {
        unsafe {
            if self.is_long() {
                self.long_entry.name()
            } else {
                self.short_entry.name().to_string()
            }
        }
    }
    pub fn unused(&self) -> bool {
        self.last_and_unused() || self.unused_not_last()
    }
    pub fn unused_not_last(&self) -> bool {
        unsafe { self.long_entry.ord == DIR_ENTRY_UNUSED }
    }
    pub fn last_and_unused(&self) -> bool {
        unsafe { self.long_entry.ord == DIR_ENTRY_LAST_AND_UNUSED }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(packed)]
/// On-disk & in-file data structure for FAT32 directory.
pub struct FATDirShortEnt {
    /// name, offset
    pub name: [u8; 11],
    pub attr: FATDiskInodeType, //?
    pub nt_res: u8,
    pub crt_time_teenth: u8,
    pub crt_time: u16,
    pub crt_date: u16,
    pub last_acc_date: u16,
    pub fst_clus_hi: u16,
    pub wrt_time: u16,
    pub wrt_date: u16,
    pub fst_clus_lo: u16,
    pub file_size: u32,
}

impl FATDirShortEnt {
    pub fn from_name(name: [u8; 11], fst_clus: u32, file_type: DiskInodeType) -> Self {
        let mut i = Self::empty();
        i.set_fst_clus(fst_clus);
        i.name.copy_from_slice(&name);
        if file_type == DiskInodeType::Directory {
            i.attr = FATDiskInodeType::AttrDirectory;
        } else {
            i.attr = FATDiskInodeType::AttrArchive;
        }
        return i;
    }
    pub fn empty() -> Self {
        Self {
            name: [0; 11],
            attr: FATDiskInodeType::AttrArchive,
            nt_res: 0,
            crt_time_teenth: 0,
            crt_time: 0,
            crt_date: 0,
            last_acc_date: 0,
            fst_clus_hi: 0,
            wrt_time: 0,
            wrt_date: 0,
            fst_clus_lo: 0,
            file_size: 0,
        }
    }
    pub fn set_fst_clus(&mut self, fst_clus: u32) {
        self.fst_clus_hi = (fst_clus >> 16) as u16;
        self.fst_clus_lo = (fst_clus & 0b1111_1111_1111_1111) as u16;
    }
    pub fn get_first_clus(&self) -> u32 {
        (self.fst_clus_lo as u32) | ((self.fst_clus_hi as u32) << 16)
    }
    pub fn is_dir(&self) -> bool {
        self.attr == FATDiskInodeType::AttrDirectory
    }
    #[allow(unused)]
    pub fn is_file(&self) -> bool {
        self.attr == FATDiskInodeType::AttrArchive
            || self.attr == FATDiskInodeType::AttrHidden
            || self.attr == FATDiskInodeType::AttrSystem
            || self.attr == FATDiskInodeType::AttrReadOnly
    }
}
impl FATDirShortEnt {
    pub fn name(&self) -> &str {
        let len = if let Some(i) = (0usize..11).find(|i| self.name[*i] == 32) {
            i
        } else {
            if self.name[0] == 32 {
                0
            } else {
                11
            }
        };
        core::str::from_utf8(&self.name[..len]).unwrap()
    }
}

pub const LONG_DIR_ENT_NAME_CAPACITY: usize = 13;
#[derive(Debug, PartialEq, Clone, Copy)]
#[repr(packed)]
/// *On-disk* data structure for partition information.
pub struct FATLongDirEnt {
    /// The order of this entry in the sequence of long dir entries.
    /// It is associated with the short dir entry at the end of the long dir set,
    /// and masked with 0x40 (`LAST_LONG_ENTRY`),
    /// which indicates that the entry is the last long dir entry in a set of long dir entries.
    /// All valid sets of long dir entries must begin with an entry having this mask.
    ord: u8,
    /// Characters 1-5 of the long-name sub-component in this dir entry.
    name1: [u16; 5],
    /// Attributes - must be ATTR_LONG_NAME
    attr: FATDiskInodeType,
    /// If zero, indicates a directory entry that is a sub-component of a long name.
    /// # NOTE
    /// Other values reserved for future extensions.
    /// Non-zero implies other dirent types.
    ldir_type: u8,
    /// Checksum of name in the short dir entry at the end of the long dir set.
    chk_sum: u8,
    /// Characters 6-11 of the long-name sub-component in this dir entry.
    name2: [u16; 6],
    /// Must be ZERO.
    /// This is an artifact of the FAT "first cluster",
    /// and must be zero for compatibility with existing disk utilities.
    /// It's meaningless in the context of a long dir entry.
    fst_clus_lo: u16,
    /// Characters 12-13 of the long-name sub-component in this dir entry
    name3: [u16; 2],
}

impl FATLongDirEnt {
    pub fn empty() -> Self {
        Self {
            ord: 0u8,
            name1: [0u16; 5],
            attr: FATDiskInodeType::AttrLongName,
            ldir_type: 0u8,
            chk_sum: 0u8,
            name2: [0u16; 6],
            fst_clus_lo: 0u16,
            name3: [0u16; 2],
        }
    }
    pub fn from_name_slice(is_last_ent: bool, order: usize, partial_name: [u16; 13]) -> Self {
        let mut i = Self::empty();

        unsafe {
            core::ptr::addr_of_mut!(i.name1)
                .write_unaligned(partial_name[..5].try_into().expect("Failed to cast!"));
            core::ptr::addr_of_mut!(i.name2)
                .write_unaligned(partial_name[5..11].try_into().expect("Failed to cast!"));
            core::ptr::addr_of_mut!(i.name3)
                .write_unaligned(partial_name[11..].try_into().expect("Failed to cast!"));
        }
        assert!(order < 0x47);
        i.ord = order as u8;
        if is_last_ent {
            i.ord |= LAST_LONG_ENTRY;
        }

        i
    }
    pub fn name(&self) -> String {
        let mut name_all: [u16; LONG_DIR_ENT_NAME_CAPACITY] = [0u16; LONG_DIR_ENT_NAME_CAPACITY];

        name_all[..5].copy_from_slice(unsafe { &core::ptr::addr_of!(self.name1).read_unaligned() });
        name_all[5..11]
            .copy_from_slice(unsafe { &core::ptr::addr_of!(self.name2).read_unaligned() });
        name_all[11..]
            .copy_from_slice(unsafe { &core::ptr::addr_of!(self.name3).read_unaligned() });
        String::from_utf16_lossy(
            &name_all[..if let Some((i, _)) = name_all
                .iter()
                .enumerate()
                .find(|here| -> bool { *here.1 == 0 })
            {
                i
            } else {
                LONG_DIR_ENT_NAME_CAPACITY
            }],
        )
    }
}
