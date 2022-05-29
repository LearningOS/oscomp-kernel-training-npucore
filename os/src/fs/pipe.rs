use super::File;
use crate::mm::UserBuffer;
use crate::task::suspend_current_and_run_next;
use alloc::sync::{Arc, Weak};
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

impl File for Pipe {
    fn readable(&self) -> bool {
        self.readable
    }
    fn writable(&self) -> bool {
        self.writable
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
    fn read(&self, buf: UserBuffer) -> usize {
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
                // gdb_print!(SYSCALL_ENABLE,"[pipe] try read");
                drop(ring_buffer);
                suspend_current_and_run_next();
                continue;
            }
            //gdb_print!(SYSCALL_ENABLE,"[pipe] can read {} bytes\n", loop_read);
            // read at most loop_read bytes
            for i in 0..loop_read {
                if let Some(byte_ref) = buf_iter.next() {
                    unsafe {
                        *byte_ref = ring_buffer.read_byte();
                    }
                    read_size += 1;
                    //panic!("[pipe] read");
                } else {
                    //panic!("[pipe] read");
                    ring_buffer.count += 1;
                    return read_size;
                }
            }
            return read_size;
        }
    }
    fn write(&self, buf: UserBuffer) -> usize {
        //log::info!("[pipe.write] attempt to write...");
        //        log::warn!("[pipe.write] attempted wr");
        assert_eq!(self.writable(), true);
        let mut buf_iter = buf.into_iter();
        let mut write_size = 0usize;
        loop {
            //            log::warn!("[pipe.write]attempted lock");
            let mut ring_buffer = self.buffer.lock();
            //            log::warn!("[pipe.write]attempted lock done.");
            let loop_write = ring_buffer.available_write();
            //            log::warn!("[pipe.write]size avail:{}", loop_write);
            //log::info!("[pipe.write] Lock acquired...");
            if loop_write == 0 {
                drop(ring_buffer);
                // gdb_print!(SYSCALL_ENABLE,"[pipe] try write");

                // if suspend_current_and_run_next() < 0{
                //     return write_size;
                // }
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

    fn r_ready(&self) -> bool {
        let ring_buffer = self.buffer.lock();
        let loop_read = ring_buffer.available_read();
        /* log::warn!(
         *     "r_ready: h{},t{},lhd{}",
         *     ring_buffer.head,
         *     ring_buffer.tail,
         *     loop_read
         * ); */
        loop_read > 0
    }

    fn w_ready(&self) -> bool {
        let ring_buffer = self.buffer.lock();
        let loop_write = ring_buffer.available_write();
        /* log::warn!(
         *     "w_ready: h{},t{},lhd{}",
         *     ring_buffer.head,
         *     ring_buffer.tail,
         *     loop_write
         * ); */
        loop_write > 0
    }
}
