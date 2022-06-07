use crate::layout::{FATDirEnt, FATShortDirEnt};
use crate::vfs::FileContent;
use crate::{CacheManager, Inode};
use alloc::string::{String};
use spin::MutexGuard;

pub enum DirIterMode {
    LongIter,
    ShortIter,
    UsedIter,
    Unused,
    Enum,
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
    offset: Option<u32>,
    mode: DirIterMode,
    forward: bool,
    inode: &'a Inode<T, F>,
}

impl<'a, T: CacheManager, F: CacheManager> DirIter<'a, T, F> {
    pub fn new(
        lock: MutexGuard<'a, FileContent<T>>,
        offset: Option<u32>,
        mode: DirIterMode,
        forward: bool,
        inode: &'a Inode<T, F>,
    ) -> Self {
        Self{
            lock,
            offset,
            mode,
            forward,
            inode,
        }
    }

    #[inline(always)]
    /// Get iterator corresponding offset
    pub fn get_offset(&self) -> Option<u32> {
        self.offset
    }

    #[inline(always)]
    /// Sets the offset to make the first iteration of the iterator to the target `offset`
    /// # Arguments
    /// `offset`: The target offset we want after the first iteration
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
        log::debug!("[set_iter_offset] new offset: {:?}", self.offset);
    }
    /// Get iterator corresponding `FATDirEnt`
    pub fn current_clone(&mut self) -> Option<FATDirEnt> {
        let mut dir_ent = FATDirEnt::empty();
        if self.offset.is_some()
            && self.offset.unwrap() < self.lock.size
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
    /// Write `ent` to iterator corresponding directory entry
    /// # Arguments
    /// `ent`: The directory entry we want to write to
    pub fn write_to_current_ent(&mut self, ent: &FATDirEnt) {
        if self.inode.write_at_block_cache(
            &mut self.lock,
            self.offset.unwrap() as usize,
            ent.as_bytes(),
        ) != ent.as_bytes().len()
        {
            panic!("failed!");
        }
        log::debug!("[write_to_current_ent] offset:{}, content:{:?}", self.offset.unwrap(), ent.as_bytes());
    }
    fn step(&mut self) -> Option<FATDirEnt> {
        let mut dir_ent: FATDirEnt = FATDirEnt::empty();
        if self.forward {
            // if offset is None => 0
            // if offset is non-negative => offset + STEP_SIZE
            let offset = self.offset.map(|offset| offset + STEP_SIZE).unwrap_or(0);
            if offset >= self.lock.size {
                return None;
            }
            self.inode
                .read_at_block_cache(&mut self.lock, offset as usize, dir_ent.as_bytes_mut());
            match self.mode {
                DirIterMode::Enum => (),
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
        log::trace!("offset {:?}, unused: {:?}, {:?}", self.offset, dir_ent.unused(), dir_ent);
        Some(dir_ent)
    }
    pub fn walk(self) -> DirWalker<'a, T, F> {
        DirWalker { iter: self }
    }
}

/// Iterator for DirIter
/// `next()` will return the next valid entry and change to the offset corresponding to the target entry
/// `next()` will return None and will not change if the iterator is out of bounds with the next iterator
/// For modes other than `Enum`, their bounds are the `last_and_unused` entry or the start/end of the file
/// For `Enum` mode, its bounds are the start/end of the file(it will not be bound by the `last_and_unused` entry)
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


/// Iterator for DirWalker
/// It is based on `DirIter` and used to iterate over directory entries (combination of long and short entries)
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
