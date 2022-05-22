use crate::layout::{FATDirEnt, FATShortDirEnt};
use crate::vfs::FileContent;
use crate::{CacheManager, Inode};
use alloc::string::{String, ToString};
use spin::MutexGuard;

pub enum DirIterMode {
    LongIter,
    ShortIter,
    UsedIter,
    Unused,
    Enum,
    Dirent,
}

#[allow(unused)]
impl DirIterMode {
    /// Returns `true` if the dir iter mode is [`LongIter`].
    ///
    /// [`LongIter`]: DirIterMode::LongIter
    pub fn is_long_iter(&self) -> bool {
        matches!(self, Self::LongIter)
    }

    /// Returns `true` if the dir iter mode is [`ShortIter`].
    ///
    /// [`ShortIter`]: DirIterMode::ShortIter
    pub fn is_short_iter(&self) -> bool {
        matches!(self, Self::ShortIter)
    }

    /// Returns `true` if the dir iter mode is [`AllIter`].
    ///
    /// [`AllIter`]: DirIterMode::AllIter
    pub fn is_all_iter(&self) -> bool {
        matches!(self, Self::UsedIter)
    }

    /// Returns `true` if the dir iter mode is [`Unused`].
    ///
    /// [`Unused`]: DirIterMode::Unused
    pub fn is_unused(&self) -> bool {
        matches!(self, Self::Unused)
    }
}
pub const FORWARD: bool = true;
pub const BACKWARD: bool = false;
const STEP_SIZE: u32 = core::mem::size_of::<FATDirEnt>() as u32;
pub struct DirIter<'a, T: CacheManager, F: CacheManager> {
    pub lock: MutexGuard<'a, FileContent<T>>,
    pub offset: Option<u32>,
    pub mode: DirIterMode,
    pub forward: bool,
    pub inode: &'a Inode<T, F>,
}

impl<'a, T: CacheManager, F: CacheManager> DirIter<'a, T, F> {
    #[allow(unused)]
    #[inline(always)]
    fn file_size(&self) -> u32 {
        self.lock.size
    }
    #[allow(unused)]
    #[inline(always)]
    pub fn get_offset(&self) -> Option<u32> {
        self.offset
    }
    #[allow(unused)]
    #[inline(always)]
    pub fn set_iter_offset(&mut self, offset: u32) {
        if self.forward {
            if offset == 0 {
                self.offset = None;
            } else {
                self.offset = Some(offset - STEP_SIZE);
            }
        } else {
            self.offset = Some(offset + STEP_SIZE);
        }
    }
    pub fn current_clone(&mut self) -> Option<FATDirEnt> {
        let mut dir_ent = FATDirEnt::empty();
        if self.offset.is_some()
            && self.offset.unwrap() < self.file_size()
            && self.inode.read_at_block_cache(
                &mut self.lock,
                self.offset.unwrap() as usize,
                dir_ent.as_bytes_mut(),
            ) != 0
        {
            Some(dir_ent)
        } else {
            None
        }
    }
    #[allow(unused)]
    #[inline(always)]
    pub fn backward(mut self) -> Self {
        self.forward = false;
        self
    }
    #[allow(unused)]
    #[inline(always)]
    pub fn to_backward(&mut self) {
        self.forward = false;
    }
    #[allow(unused)]
    #[inline(always)]
    pub fn forward(mut self) -> Self {
        self.forward = true;
        self
    }
    #[allow(unused)]
    #[inline(always)]
    pub fn toggle_direction(mut self) -> Self {
        self.forward = !self.forward;
        self
    }
    #[allow(unused)]
    #[inline(always)]
    pub fn short(mut self) -> Self {
        self.mode = DirIterMode::ShortIter;
        self
    }
    #[allow(unused)]
    #[inline(always)]
    pub fn long(mut self) -> Self {
        self.mode = DirIterMode::LongIter;
        self
    }
    #[allow(unused)]
    #[inline(always)]
    pub fn everything(mut self) -> Self {
        self.mode = DirIterMode::Enum;
        self
    }
    #[allow(unused)]
    #[inline(always)]
    pub fn all(mut self) -> Self {
        self.mode = DirIterMode::UsedIter;
        self
    }
    #[allow(unused)]
    #[inline(always)]
    pub fn unused(mut self) -> Self {
        self.mode = DirIterMode::Unused;
        self
    }
    pub fn write_to_current_ent(&mut self, ent: &FATDirEnt) {
        if self.inode.write_at_block_cache(
            &mut self.lock,
            self.offset.unwrap() as usize,
            ent.as_bytes(),
        ) != ent.as_bytes().len()
        {
            panic!("failed!");
        }
        //println!("[write_to_current_ent] offset:{}, content:{:?}", self.offset.unwrap(), ent.as_bytes());
    }
    pub fn step(&mut self) -> Option<FATDirEnt> {
        let mut dir_ent: FATDirEnt = FATDirEnt::empty();
        if self.forward {
            // if offset is None => 0
            // if offset is non-negative => offset + STEP_SIZE
            let offset = self.offset.map(|offset| offset + STEP_SIZE).unwrap_or(0);
            if offset >= self.file_size() {
                return None;
            }
            self.inode
                .read_at_block_cache(&mut self.lock, offset as usize, dir_ent.as_bytes_mut());
            match self.mode {
                DirIterMode::Enum | DirIterMode::Dirent => (),
                _ => {
                    // if directory entry is "last and unused", next is unavailable
                    if dir_ent.last_and_unused() {
                        return None;
                    }
                }
            }
            self.offset = Some(offset);
        } else {
            if self.offset.is_none() {
                return None;
            }
            if self.offset.unwrap() == 0 {
                self.offset = None;
                return None;
            }
            self.offset = self.offset.map(|offset| offset - STEP_SIZE);
            self.inode.read_at_block_cache(
                &mut self.lock,
                self.offset.unwrap() as usize,
                dir_ent.as_bytes_mut(),
            );
        }
        // println!("offset {:?}, unused: {:?}, {:?}", self.offset, dir_ent.unused(), dir_ent);
        Some(dir_ent)
    }
    pub fn walk(self) -> DirWalker<'a, T, F> {
        DirWalker { iter: self }
    }
}
impl<T: CacheManager, F: CacheManager> Iterator for DirIter<'_, T, F> {
    type Item = FATDirEnt;
    fn next(&mut self) -> Option<Self::Item> {
        while let Some(dir_ent) = self.step() {
            fn check_dir_ent_legality(mode: &DirIterMode, dir_ent: &FATDirEnt) -> bool {
                match mode {
                    DirIterMode::Unused => dir_ent.unused_not_last(),
                    DirIterMode::UsedIter => !dir_ent.unused(),
                    DirIterMode::LongIter => !dir_ent.unused() && dir_ent.is_long(),
                    DirIterMode::ShortIter => !dir_ent.unused() && dir_ent.is_short(),
                    DirIterMode::Enum => true,
                    DirIterMode::Dirent => !dir_ent.unused() || dir_ent.last_and_unused(),
                }
            }
            if check_dir_ent_legality(&self.mode, &dir_ent) {
                return Some(dir_ent);
            }
        }
        None
    }
}

pub struct DirWalker<'a, T: CacheManager, F: CacheManager> {
    pub iter: DirIter<'a, T, F>,
}

impl<T: CacheManager, F: CacheManager> Iterator for DirWalker<'_, T, F> {
    type Item = (String, FATShortDirEnt);
    fn next(&mut self) -> Option<Self::Item> {
        let mut name = String::new();
        let mut should_be_ord = usize::MAX;
        while let Some(dir_ent) = self.iter.next() {
            if dir_ent.is_long() {
                if dir_ent.is_last_long_dir_ent() {
                    name = dir_ent.get_name() + &name;
                    should_be_ord = dir_ent.ord() - 1;
                } else if dir_ent.ord() == should_be_ord {
                    name = dir_ent.get_name() + &name;
                    should_be_ord -= 1;
                } else {
                    unreachable!()
                }
            } else if dir_ent.is_short() {
                if name.is_empty() {
                    name = dir_ent.get_name();
                }
                return Some((name, dir_ent.get_short_ent().unwrap().clone()));
            }
        }
        None
    }
}
