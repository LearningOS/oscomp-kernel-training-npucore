
use crate::fs::directory_tree::DirectoryTreeNode;
use crate::fs::layout::{Stat};
use crate::syscall::errno::*;
use crate::{mm::UserBuffer, fs::file_trait::File};
use crate::task::suspend_current_and_run_next;
use alloc::sync::{Arc, Weak};
use easy_fs::DiskInodeType;
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

// const RING_BUFFER_SIZE: usize = 32;
const RING_BUFFER_SIZE: usize = 3010;

#[derive(Copy, Clone, PartialEq)]
enum RingBufferStatus {
    FULL,
    EMPTY,
    NORMAL,
}

pub struct PipeRingBuffer {
    arr: [u8; RING_BUFFER_SIZE],
    head: usize,
    tail: usize,
    status: RingBufferStatus,
    write_end: Option<Weak<Pipe>>,
    read_end: Option<Weak<Pipe>>,
    count: usize,
}

impl PipeRingBuffer {
    pub fn new() -> Self {
        Self {
            arr: [0; RING_BUFFER_SIZE],
            head: 0,
            tail: 0,
            status: RingBufferStatus::EMPTY,
            write_end: None,
            read_end: None,
            count: 0,
        }
    }
    pub fn set_write_end(&mut self, write_end: &Arc<Pipe>) {
        self.write_end = Some(Arc::downgrade(write_end));
    }
    pub fn set_read_end(&mut self, write_end: &Arc<Pipe>) {
        self.read_end = Some(Arc::downgrade(write_end));
    }
    pub fn write_byte(&mut self, byte: u8) {
        self.status = RingBufferStatus::NORMAL;
        self.arr[self.tail] = byte;
        self.tail = (self.tail + 1) % RING_BUFFER_SIZE;
        if self.tail == self.head {
            self.status = RingBufferStatus::FULL;
        }
    }
    pub fn read_byte(&mut self) -> u8 {
        self.status = RingBufferStatus::NORMAL;
        let c = self.arr[self.head];
        self.head = (self.head + 1) % RING_BUFFER_SIZE;
        if self.head == self.tail {
            self.status = RingBufferStatus::EMPTY;
        }
        c
    }
    pub fn available_read(&self) -> usize {
        if self.status == RingBufferStatus::EMPTY {
            0
        } else {
            if self.tail > self.head {
                self.tail - self.head
            } else {
                self.tail + RING_BUFFER_SIZE - self.head
            }
        }
    }
    pub fn available_write(&self) -> usize {
        if self.status == RingBufferStatus::FULL {
            0
        } else {
            RING_BUFFER_SIZE - self.available_read()
        }
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
        let loop_read = ring_buffer.available_read();
        loop_read > 0
    }

    fn w_ready(&self) -> bool {
        let ring_buffer = self.buffer.lock();
        let loop_write = ring_buffer.available_write();
        loop_write > 0
    }
    fn read_user(&self, buf: UserBuffer) -> usize {
        assert_eq!(self.readable(), true);
        let mut buf_iter = buf.into_iter();
        let mut read_size = 0usize;
        let mut try_time = 0;
        loop {
            let mut ring_buffer = self.buffer.lock();
            let loop_read = ring_buffer.available_read();
            if loop_read == 0 {
                if ring_buffer.all_write_ends_closed() {
                    return read_size; //return后就ring_buffer释放了，锁自然释放
                }
                drop(ring_buffer);
                suspend_current_and_run_next();
                continue;
            }
            // read at most loop_read bytes
            for i in 0..loop_read {
                if let Some(byte_ref) = buf_iter.next() {
                    unsafe {
                        *byte_ref = ring_buffer.read_byte();
                    }
                    read_size += 1;
                } else {
                    ring_buffer.count += 1;
                    return read_size;
                }
            }
            return read_size;
        }
    }
    fn write_user(&self, buf: UserBuffer) -> usize {
        assert_eq!(self.writable(), true);
        let mut buf_iter = buf.into_iter();
        let mut write_size = 0usize;
        loop {
            let mut ring_buffer = self.buffer.lock();
            let loop_write = ring_buffer.available_write();
            if loop_write == 0 {
                drop(ring_buffer);
                continue;
            }

            for i in 0..loop_write {
                if let Some(byte_ref) = buf_iter.next() {
                    ring_buffer.write_byte(unsafe { *byte_ref });
                    write_size += 1;
                    ring_buffer.count += 1;
                } else {
                    return write_size;
                }
            }
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
}

impl Pipe {
}
