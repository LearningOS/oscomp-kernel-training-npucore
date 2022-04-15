use crate::fs::File;
use crate::mm::{copy_from_user, copy_to_user};
use crate::mm::{translated_ref, translated_refmut, UserBuffer};
use crate::sbi::console_getchar;
use crate::syscall::errno::*;
use crate::task::suspend_current_and_run_next;
use alloc::sync::Arc;
use lazy_static::lazy_static;
use log::{info, warn};
use num_enum::FromPrimitive;
use spin::Mutex;

lazy_static! {
    pub static ref TTY: Arc<Teletype> = Arc::new(Teletype::default());
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WinSize {
    ws_row: u16,
    ws_col: u16,
    xpixel: u16,
    ypixel: u16,
}

impl Default for WinSize {
    fn default() -> Self {
        Self {
            ws_row: 24,
            ws_col: 80,
            xpixel: 0,
            ypixel: 0,
        }
    }
}

#[derive(Default)]
pub struct Teletype {
    inner: Mutex<TeletypeInner>,
}

pub struct TeletypeInner {
    last_char: u8,
    foreground_pgid: u32,
    winsize: WinSize,
    termios: Termios,
}

impl Default for TeletypeInner {
    fn default() -> Self {
        Self {
            last_char: 255,
            foreground_pgid: Default::default(),
            winsize: WinSize::default(),
            termios: Termios::default(),
        }
    }
}

// TODO: independ of rust sbi
impl File for Teletype {
    fn readable(&self) -> bool {
        true
    }

    fn writable(&self) -> bool {
        true
    }

    #[cfg(feature = "board_k210")]
    fn r_ready(&self) -> bool {
        let mut inner = self.inner.lock();
        // in this case, user program call pselect() before, should return true
        if inner.last_char == 0 {
            true
        // in this case, user program call read() before, should return false
        } else {
            inner.last_char = 0;
            false
        }
    }
    
    #[cfg(not(any(feature = "board_k210")))]
    fn r_ready(&self) -> bool {
        let mut inner = self.inner.lock();
        // buffer has valid data
        if inner.last_char != 255 {
            true
        // peek next char
        } else {
            inner.last_char = console_getchar() as u8;
            inner.last_char != 255
        }
    }

    fn w_ready(&self) -> bool {
        true
    }

    #[cfg(feature = "board_k210")]
    fn read(&self, mut buf: UserBuffer) -> usize {
        let mut inner = self.inner.lock();
        // block read here, infallible
        unsafe {
            buf.buffers[0].as_mut_ptr().write_volatile(console_getchar() as u8);
        }
        // fake failed reading to make pseudo non-block reading,
        // in order to return properly in r_ready(),
        // so that we could let bash echo what we input on k210.
        inner.last_char = 255;
        1
    }

    #[cfg(not(any(feature = "board_k210")))]
    fn read(&self, buf: UserBuffer) -> usize {
        let mut inner = self.inner.lock();
        // todo: check foreground pgid
        let mut count = 0;
        for ptr in buf {
            loop {
                //we have read a legal char
                if inner.last_char != 255 {
                    break;
                }
                //if we have read some chars, we can return
                if count > 0 {
                    return count;
                }
                //we read no char, suspend the procedure
                suspend_current_and_run_next();
                inner.last_char = console_getchar() as u8;
            }
            //we can guarantee last_char isn't a illegal char
            unsafe {
                ptr.write_volatile(inner.last_char);
            }
            inner.last_char = console_getchar() as u8;
            count += 1;
        }
        count
    }

    fn write(&self, user_buffer: UserBuffer) -> usize {
        let _inner = self.inner.lock();
        for buffer in user_buffer.buffers.iter() {
            match core::str::from_utf8(*buffer) {
                Ok(content) => print!("{}", content),
                Err(_) => warn!("[tty_write] Non-UTF8 charaters: {:?}", *buffer),
            }
        }
        user_buffer.len()
    }
    
    fn kwrite(&self, offset: Option<&mut usize>, buffer: &[u8]) -> usize {
        let _inner = self.inner.lock();
        match offset {
            Some(_) => {
                ESPIPE as usize
            }
            None => {
                match core::str::from_utf8(buffer) {
                    Ok(content) => print!("{}", content),
                    Err(_) => warn!("[tty_kwrite] Non-UTF8 charaters: {:?}", buffer),
                }
                buffer.len()
            }
        }
    }

    fn ioctl(&self, cmd: u32, argp: usize) -> isize {
        info!("[tty_ioctl] cmd: {:?}, arg: {:X}", TeletypeCommand::from_primitive(cmd), argp);
        let mut inner = self.inner.lock();
        let token = crate::task::current_user_token();
        match TeletypeCommand::from_primitive(cmd) {
            TeletypeCommand::TCGETS | TeletypeCommand::TCGETA => {
                copy_to_user(token, &inner.termios, argp as *mut Termios);
                SUCCESS
            }
            TeletypeCommand::TCSETS | TeletypeCommand::TCSETSW | TeletypeCommand::TCSETSF => {
                copy_from_user(token, argp as *const Termios, &mut inner.termios);
                SUCCESS
            }
            TeletypeCommand::TIOCGPGRP => {
                *translated_refmut(token, argp as *mut u32) = inner.foreground_pgid;
                SUCCESS
            }
            TeletypeCommand::TIOCSPGRP => {
                inner.foreground_pgid = *translated_ref(token, argp as *const u32);
                SUCCESS
            }
            TeletypeCommand::TIOCGWINSZ => {
                copy_to_user(token, &inner.winsize, argp as *mut WinSize);
                SUCCESS
            }
            TeletypeCommand::TIOCSWINSZ => {
                copy_from_user(token, argp as *mut WinSize, &mut inner.winsize);
                SUCCESS
            }
            _ => todo!(),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Eq, PartialEq, FromPrimitive)]
#[repr(u32)]
pub enum TeletypeCommand {
    // For struct termios
    // Gets the current serial port settings.
    TCGETS = 0x5401,
    // Sets the serial port settings immediately.
    TCSETS = 0x5402,
    // Sets the serial port settings after allowing the input and output buffers to drain/empty.
    TCSETSW = 0x5403,
    // Sets the serial port settings after flushing the input and output buffers.
    TCSETSF = 0x5404,

    // For struct termio
    // Gets the current serial port settings.
    TCGETA = 0x5405,
    // Sets the serial port settings immediately.
    TCSETA = 0x5406,
    // Sets the serial port settings after allowing the input and output buffers to drain/empty.
    TCSETAW = 0x5407,
    // Sets the serial port settings after flushing the input and output buffers.
    TCSETAF = 0x5408,

    // Get the process group ID of the foreground process group on this terminal.
    TIOCGPGRP = 0x540F,
    // Set the foreground process group ID of this terminal.
    TIOCSPGRP = 0x5410,

    // Get window size.
    TIOCGWINSZ = 0x5413,
    // Set window size.
    TIOCSWINSZ = 0x5414,

    // Non-cloexec
    FIONCLEX = 0x5450,
    // Cloexec
    FIOCLEX = 0x5451,

    // rustc using pipe and ioctl pipe file with this request id
    // for non-blocking/blocking IO control setting
    FIONBIO = 0x5421,

    // Read time
    RTC_RD_TIME = 0x80247009,

    #[num_enum(default)]
    ILLEAGAL,
}

/*  The termios functions describe a general terminal interface that
    is provided to control asynchronous communications ports.
*/
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Termios {
    pub iflag: u32, // input modes
    pub oflag: u32, // ouput modes
    pub cflag: u32, // control modes
    pub lflag: u32, // local modes
    pub line: u8,
    pub cc: [u8; 32], // terminal special characters.
    pub ispeed: u32,
    pub ospeed: u32,
}

impl Default for Termios {
    fn default() -> Self {
        Termios {
            // IMAXBEL | IUTF8 | IXON | IXANY | ICRNL | BRKINT
            iflag: 0o66402,
            // OPOST | ONLCR
            oflag: 0o5,
            // HUPCL | CREAD | CSIZE | EXTB
            cflag: 0o2277,
            // IEXTEN | ECHOTCL | ECHOKE ECHO | ECHOE | ECHOK | ISIG | ICANON
            lflag: 0o105073,
            line: 0,
            cc: [
                3,   // VINTR Ctrl-C
                28,  // VQUIT
                127, // VERASE
                21,  // VKILL
                4,   // VEOF Ctrl-D
                0,   // VTIME
                1,   // VMIN
                0,   // VSWTC
                17,  // VSTART
                19,  // VSTOP
                26,  // VSUSP Ctrl-Z
                255, // VEOL
                18,  // VREPAINT
                15,  // VDISCARD
                23,  // VWERASE
                22,  // VLNEXT
                255, // VEOL2
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            ispeed: 0,
            ospeed: 0,
        }
    }
}

bitflags! {
    pub struct LocalModes : u32 {
        const ISIG = 0o000001;
        const ICANON = 0o000002;
        const ECHO = 0o000010;
        const ECHOE = 0o000020;
        const ECHOK = 0o000040;
        const ECHONL = 0o000100;
        const NOFLSH = 0o000200;
        const TOSTOP = 0o000400;
        const IEXTEN = 0o100000;
        const XCASE = 0o000004;
        const ECHOCTL = 0o001000;
        const ECHOPRT = 0o002000;
        const ECHOKE = 0o004000;
        const FLUSHO = 0o010000;
        const PENDIN = 0o040000;
        const EXTPROC = 0o200000;
    }
}
