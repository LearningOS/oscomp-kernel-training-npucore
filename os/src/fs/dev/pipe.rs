
use crate::config::PAGE_SIZE;
use crate::fs::directory_tree::DirectoryTreeNode;
use crate::fs::layout::{Stat};
use crate::syscall::fs::Fcntl_Command;
use crate::syscall::errno::*;
use crate::{mm::UserBuffer, fs::file_trait::File};
use crate::task::suspend_current_and_run_next;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use easy_fs::DiskInodeType;
use num_enum::FromPrimitive;
use spin::Mutex;

pub struct Pipe {
    readable: bool,
    writable: bool,
    buffer: Arc<Mutex<PipeRingBuffer>>,
}

impl Pipe {
    pub fn read_end_with_buffer(buffer: Arc<Mutex<PipeRingBuffer>>) -> Self {
        Self {
            readable: true,
            writable: false,
            buffer,
        }
    }
    pub fn write_end_with_buffer(buffer: Arc<Mutex<PipeRingBuffer>>) -> Self {
        Self {
            readable: false,
            writable: true,
            buffer,
        }
    }
}

const RING_DEFAULT_BUFFER_SIZE: usize = 4096;

#[derive(Copy, Clone, PartialEq, Debug)]
enum RingBufferStatus {
    FULL,
    EMPTY,
    NORMAL,
}

pub struct PipeRingBuffer {
    arr: Vec<u8>,
    head: usize,
    tail: usize,
    status: RingBufferStatus,
    write_end: Option<Weak<Pipe>>,
    read_end: Option<Weak<Pipe>>,
}

impl PipeRingBuffer {
    pub fn new() -> Self {
        let mut vec = Vec::<u8>::with_capacity(RING_DEFAULT_BUFFER_SIZE);
        unsafe {
            vec.set_len(RING_DEFAULT_BUFFER_SIZE);
        }
        Self {
            arr: vec,
            head: 0,
            tail: 0,
            status: RingBufferStatus::EMPTY,
            write_end: None,
            read_end: None,
        }
    }
    pub fn get_used_size(&self) -> usize {
        if self.status == RingBufferStatus::FULL {
            self.arr.len()
        } else if self.status == RingBufferStatus::EMPTY {
            0
        } else {
            assert!(self.head != self.tail);
            if self.head < self.tail {
                self.tail - self.head
            } else {
                self.tail + self.arr.len() - self.head
            }
        }
    }
    pub fn set_write_end(&mut self, write_end: &Arc<Pipe>) {
        self.write_end = Some(Arc::downgrade(write_end));
    }
    pub fn set_read_end(&mut self, read_end: &Arc<Pipe>) {
        self.read_end = Some(Arc::downgrade(read_end));
    }
    pub fn all_write_ends_closed(&self) -> bool {
        self.write_end.as_ref().unwrap().upgrade().is_none()
    }
    pub fn all_read_ends_closed(&self) -> bool {
        self.read_end.as_ref().unwrap().upgrade().is_none()
    }
}

/// Return (read_end, write_end)
pub fn make_pipe() -> (Arc<Pipe>, Arc<Pipe>) {
    let buffer = Arc::new(Mutex::new(PipeRingBuffer::new()));
    // buffer仅剩两个强引用，这样读写端关闭后就会被释放
    let read_end = Arc::new(Pipe::read_end_with_buffer(buffer.clone()));
    let write_end = Arc::new(Pipe::write_end_with_buffer(buffer.clone()));
    buffer.lock().set_write_end(&write_end);
    buffer.lock().set_read_end(&read_end);
    (read_end, write_end)
}

#[allow(unused)]
impl File for Pipe {
    fn deep_clone(&self) -> Arc<dyn File> {
        todo!()
    }
    fn readable(&self) -> bool {
        self.readable
    }
    fn writable(&self) -> bool {
        self.writable
    }
    fn read(&self, offset: Option<&mut usize>, buf: &mut [u8]) -> usize {
        unreachable!()
    }
    fn write(&self, offset: Option<&mut usize>, buf: &[u8]) -> usize {
        unreachable!()
    }
    fn r_ready(&self) -> bool {
        let ring_buffer = self.buffer.lock();
        ring_buffer.status != RingBufferStatus::EMPTY
    }

    fn w_ready(&self) -> bool {
        let ring_buffer = self.buffer.lock();
        ring_buffer.status != RingBufferStatus::FULL
    }
    fn read_user(&self, buf: UserBuffer) -> usize {
        assert_eq!(self.readable(), true);
        let mut read_size = 0usize;
        if buf.len() == 0 {
            return read_size;
        }
        loop {
            let mut ring = self.buffer.lock();
            if ring.status == RingBufferStatus::EMPTY {
                if ring.all_write_ends_closed() {
                    return read_size;
                }
                drop(ring);
                suspend_current_and_run_next();
                continue;
            }
            for byte_ref in buf.into_iter() {
                let index = ring.head;
                unsafe {
                    *byte_ref = ring.arr[index];
                }
                ring.head += 1;
                if ring.head == ring.arr.len() {
                    ring.head = 0;
                }
                read_size += 1;
                if ring.head == ring.tail {
                    break;
                }
            }
            // We guarantee that this operation will read at least one byte
            if ring.head == ring.tail {
                ring.status = RingBufferStatus::EMPTY;
            } else {
                ring.status = RingBufferStatus::NORMAL;
            }
            return read_size;
        }
    }
    fn write_user(&self, buf: UserBuffer) -> usize {
        assert_eq!(self.writable(), true);
        let mut write_size = 0usize;
        if buf.len() == 0 {
            return write_size;
        }
        loop {
            let mut ring = self.buffer.lock();
            if ring.status == RingBufferStatus::FULL {
                if ring.all_read_ends_closed() {
                    return write_size;
                }
                drop(ring);
                suspend_current_and_run_next();
                continue;
            }
            for byte_ref in buf.into_iter() {
                let index = ring.tail;
                unsafe {
                    ring.arr[index] = *byte_ref;
                }
                ring.tail += 1;
                if ring.tail == ring.arr.len() {
                    ring.tail = 0;
                }
                write_size += 1;
                if ring.head == ring.tail {
                    break;
                }
            }
            // We guarantee that this operation will write at least one byte
            if ring.head == ring.tail {
                ring.status = RingBufferStatus::FULL;
            } else {
                ring.status = RingBufferStatus::NORMAL;
            }
            return write_size;
        }
    }

    fn get_stat(&self) -> Stat {
        Stat::new(
            5,
            1,
            0o100777,
            1,
            0x0000000400000040,
            0,
            0,
            0,
            0,
        )
    }

    fn get_file_type(&self) -> DiskInodeType {
        DiskInodeType::File
    }

    fn info_dirtree_node(&self, dirnode_ptr: Weak<crate::fs::directory_tree::DirectoryTreeNode>) {
        todo!()
    }

    fn get_dirtree_node(&self) -> Option<Arc<DirectoryTreeNode>> {
        todo!()
    }

    fn open(&self, flags: crate::fs::layout::OpenFlags, special_use: bool) -> Arc<dyn File> {
        todo!()
    }

    fn open_subfile(&self, name: &str) -> Result<Arc<dyn File>, isize> {
        todo!()
    }

    fn create(&self, name: &str, file_type: DiskInodeType) -> Result<Arc<dyn File>, isize> {
        todo!()
    }

    fn link_son(&self, name: &str, son: &Self) -> Result<(), isize> where Self: Sized {
        todo!()
    }

    fn unlink(&self, delete: bool) -> Result<(), isize> {
        todo!()
    }

    fn get_dirent(&self, count: usize) -> alloc::vec::Vec<crate::fs::layout::Dirent> {
        todo!()
    }

    fn lseek(&self, offset: isize, whence: crate::syscall::fs::SeekWhence) -> Result<usize, isize> {
        Err(ESPIPE)
    }

    fn modify_size(&self, diff: isize) -> Result<(), isize> {
        todo!()
    }

    fn truncate_size(&self, new_size: usize) -> Result<(), isize> {
        todo!()
    }

    fn set_timestamp(&self, ctime: Option<usize>, atime: Option<usize>, mtime: Option<usize>) {
        todo!()
    }

    fn get_single_cache(&self, offset: usize) -> Result<Arc<Mutex<crate::fs::fs::cache_mgr::PageCache>>, ()> {
        todo!()
    }

    fn get_all_caches(&self) -> Result<alloc::vec::Vec<Arc<Mutex<crate::fs::fs::cache_mgr::PageCache>>>, ()> {
        todo!()
    }

    fn oom(&self) -> usize {
        0
    }

    fn hang_up(&self) -> bool {
        // The peer has closed its end.
        // Or maybe you should only check whether both ends have been closed by the peer.
        if self.readable {
            self.buffer.lock().all_write_ends_closed()
        } else {
            //writable
            self.buffer.lock().all_read_ends_closed()
        }
    }

    fn fcntl(&self, cmd: u32, arg: u32) -> isize {
        match Fcntl_Command::from_primitive(cmd) {
            Fcntl_Command::GETPIPE_SZ => {
                self.buffer.lock().arr.len() as isize
            },
            Fcntl_Command::SETPIPE_SZ => {
                let new_size = (arg as usize).max(PAGE_SIZE);
                let mut ring = self.buffer.lock();
                let mut old_used_size = ring.get_used_size();
                if new_size < old_used_size {
                    return EBUSY;
                }
                let mut new_buffer = Vec::<u8>::with_capacity(new_size);
                while old_used_size > 0 {
                    let index = ring.head;
                    new_buffer.push(ring.arr[index]);
                    ring.head += 1;
                    if ring.head == ring.arr.len() {
                        ring.head = 0;
                    }
                    old_used_size -= 1;
                }
                ring.head = 0;
                ring.tail = new_buffer.len();
                if ring.tail == 0 {
                    ring.status = RingBufferStatus::EMPTY;
                } else if ring.tail != new_size {
                    ring.status = RingBufferStatus::NORMAL;
                } else {
                    ring.status = RingBufferStatus::FULL;
                }
                unsafe {
                    new_buffer.set_len(new_size);
                }
                ring.arr = new_buffer;
                SUCCESS
            },
            _ => EINVAL,
        }
    }
    
}