use crate::config::PAGE_SIZE;
use crate::fs::directory_tree::DirectoryTreeNode;
use crate::fs::layout::Stat;
use crate::fs::DiskInodeType;
use crate::fs::StatMode;
use crate::syscall::errno::*;
use crate::syscall::fs::Fcntl_Command;
use crate::task::{current_task, suspend_current_and_run_next};
use crate::{fs::file_trait::File, mm::UserBuffer};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
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

#[cfg(feature = "board_fu740")]
const RING_DEFAULT_BUFFER_SIZE: usize = 4096 * 16;
#[cfg(not(feature = "board_fu740"))]
const RING_DEFAULT_BUFFER_SIZE: usize = 256;

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
    fn new() -> Self {
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
    fn get_used_size(&self) -> usize {
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
    fn buffer_read(&mut self, buf: &mut [u8]) -> usize {
        // get range
        let begin = self.head;
        let mut end = if self.tail <= self.head {
            self.arr.len()
        } else {
            self.tail
        };
        if end - begin > buf.len() {
            end = begin + buf.len();
        }
        // copy
        let read_bytes = end - begin;
        let src_slice = &self.arr[begin..end];
        let dst_slice = &mut buf[..read_bytes];
        dst_slice.copy_from_slice(src_slice);
        // update head
        self.head = if end == self.arr.len() { 0 } else { end };
        read_bytes
    }
    fn buffer_write(&mut self, buf: &[u8]) -> usize {
        // get range
        let begin = self.tail;
        let mut end = if self.tail < self.head {
            self.head
        } else {
            self.arr.len()
        };
        if end - begin > buf.len() {
            end = begin + buf.len();
        }
        // write
        let write_bytes = end - begin;
        let src_slice = &buf[..write_bytes];
        let dst_slice = &mut self.arr[begin..end];
        dst_slice.copy_from_slice(src_slice);
        // update tail
        self.tail = if end == self.arr.len() { 0 } else { end };
        write_bytes
    }
    fn set_write_end(&mut self, write_end: &Arc<Pipe>) {
        self.write_end = Some(Arc::downgrade(write_end));
    }
    fn set_read_end(&mut self, read_end: &Arc<Pipe>) {
        self.read_end = Some(Arc::downgrade(read_end));
    }
    fn all_write_ends_closed(&self) -> bool {
        self.write_end.as_ref().unwrap().upgrade().is_none()
    }
    fn all_read_ends_closed(&self) -> bool {
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
        if offset.is_some() {
            todo!()
        }
        let mut read_size = 0usize;
        if buf.len() == 0 {
            return read_size;
        }
        loop {
            let task = current_task().unwrap();
            let inner = task.acquire_inner_lock();
            if !inner.sigpending.difference(inner.sigmask).is_empty() {
                return ERESTART as usize;
            }
            drop(inner);
            drop(task);
            let mut ring = self.buffer.lock();
            if ring.status == RingBufferStatus::EMPTY {
                if ring.all_write_ends_closed() {
                    return read_size;
                }
                drop(ring);
                suspend_current_and_run_next();
                continue;
            }
            // We guarantee that this operation will read at least one byte
            // So we modify status first
            ring.status = RingBufferStatus::NORMAL;
            let mut buf_start = 0;
            while buf_start < buf.len() {
                let read_bytes = ring.buffer_read(&mut buf[buf_start..]);
                buf_start += read_bytes;
                read_size += read_bytes;
                if ring.head == ring.tail {
                    ring.status = RingBufferStatus::EMPTY;
                    return read_size;
                }
            }
            return read_size;
        }
    }

    fn write(&self, offset: Option<&mut usize>, buf: &[u8]) -> usize {
        if offset.is_some() {
            todo!()
        }
        let mut write_size = 0usize;
        if buf.len() == 0 {
            return write_size;
        }
        loop {
            let task = current_task().unwrap();
            let inner = task.acquire_inner_lock();
            if !inner.sigpending.difference(inner.sigmask).is_empty() {
                return ERESTART as usize;
            }
            drop(inner);
            drop(task);
            let mut ring = self.buffer.lock();
            if ring.status == RingBufferStatus::FULL {
                if ring.all_read_ends_closed() {
                    return write_size;
                }
                drop(ring);
                suspend_current_and_run_next();
                continue;
            }
            // We guarantee that this operation will write at least one byte
            // So we modify status first
            ring.status = RingBufferStatus::NORMAL;
            let mut buf_start = 0;
            while buf_start < buf.len() {
                let write_bytes = ring.buffer_write(&buf[buf_start..]);
                buf_start += write_bytes;
                write_size += write_bytes;
                if ring.head == ring.tail {
                    ring.status = RingBufferStatus::FULL;
                    return write_size;
                }
            }
            return write_size;
        }
    }

    fn r_ready(&self) -> bool {
        let ring_buffer = self.buffer.lock();
        ring_buffer.status != RingBufferStatus::EMPTY
    }

    fn w_ready(&self) -> bool {
        let ring_buffer = self.buffer.lock();
        ring_buffer.status != RingBufferStatus::FULL
    }

    fn read_user(&self, offset: Option<usize>, buf: UserBuffer) -> usize {
        if offset.is_some() {
            return ESPIPE as usize;
        }
        let mut read_size = 0usize;
        if buf.len() == 0 {
            return read_size;
        }
        loop {
            let task = current_task().unwrap();
            let inner = task.acquire_inner_lock();
            if !inner.sigpending.difference(inner.sigmask).is_empty() {
                return ERESTART as usize;
            }
            drop(inner);
            drop(task);
            let mut ring = self.buffer.lock();
            if ring.status == RingBufferStatus::EMPTY {
                if ring.all_write_ends_closed() {
                    return read_size;
                }
                drop(ring);
                suspend_current_and_run_next();
                continue;
            }
            // We guarantee that this operation will read at least one byte
            // So we modify status first
            ring.status = RingBufferStatus::NORMAL;
            for buf in buf.buffers {
                let mut buf_start = 0;
                while buf_start < buf.len() {
                    let read_bytes = ring.buffer_read(&mut buf[buf_start..]);
                    buf_start += read_bytes;
                    read_size += read_bytes;
                    if ring.head == ring.tail {
                        ring.status = RingBufferStatus::EMPTY;
                        return read_size;
                    }
                }
            }
            return read_size;
        }
    }

    fn write_user(&self, offset: Option<usize>, buf: UserBuffer) -> usize {
        if offset.is_some() {
            return ESPIPE as usize;
        }
        let mut write_size = 0usize;
        if buf.len() == 0 {
            return write_size;
        }
        loop {
            let task = current_task().unwrap();
            let inner = task.acquire_inner_lock();
            if !inner.sigpending.difference(inner.sigmask).is_empty() {
                return ERESTART as usize;
            }
            drop(inner);
            drop(task);
            let mut ring = self.buffer.lock();
            if ring.status == RingBufferStatus::FULL {
                if ring.all_read_ends_closed() {
                    return write_size;
                }
                drop(ring);
                suspend_current_and_run_next();
                continue;
            }
            // We guarantee that this operation will write at least one byte
            // So we modify status first
            ring.status = RingBufferStatus::NORMAL;
            for buf in buf.buffers {
                let mut buf_start = 0;
                while buf_start < buf.len() {
                    let write_bytes = ring.buffer_write(&buf[buf_start..]);
                    buf_start += write_bytes;
                    write_size += write_bytes;
                    if ring.head == ring.tail {
                        ring.status = RingBufferStatus::FULL;
                        return write_size;
                    }
                }
            }
            return write_size;
        }
    }

    fn get_size(&self) -> usize {
        todo!()
    }

    fn get_stat(&self) -> Stat {
        Stat::new(
            crate::makedev!(8, 0),
            1,
            StatMode::S_IFIFO.bits() | 0o666,
            1,
            0,
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

    fn link_child(&self, name: &str, child: &Self) -> Result<(), isize>
    where
        Self: Sized,
    {
        todo!()
    }

    fn unlink(&self, delete: bool) -> Result<(), isize> {
        todo!()
    }

    fn get_dirent(&self, count: usize) -> alloc::vec::Vec<crate::fs::layout::Dirent> {
        todo!()
    }

    fn lseek(&self, offset: isize, whence: crate::fs::SeekWhence) -> Result<usize, isize> {
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

    fn get_single_cache(
        &self,
        offset: usize,
    ) -> Result<Arc<Mutex<crate::fs::PageCache>>, ()> {
        todo!()
    }

    fn get_all_caches(
        &self,
    ) -> Result<alloc::vec::Vec<Arc<Mutex<crate::fs::PageCache>>>, ()> {
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
            Fcntl_Command::GETPIPE_SZ => self.buffer.lock().arr.len() as isize,
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
            }
            _ => EINVAL,
        }
    }
}
