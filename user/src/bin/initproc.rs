#![no_std]
#![no_main]
use user_lib::{__start_backup, exec, fork, wait, yield_};

#[no_mangle]
#[link_section = ".text.entry"]
pub extern "C" fn _start(argc: usize, argv: usize) -> ! {
    __start_backup(argc, argv)
}

#[no_mangle]
fn main() -> i32 {
    if fork() == 0 {
        exec("user_shell\0", &[0 as *const u8]);
    } else {
        loop {
            let mut exit_code: i32 = 0;
            let pid = wait(&mut exit_code);
            if pid == -1 {
                yield_();
                continue;
            }
            user_lib::println!(
                "[initproc] Released a zombie process, pid={}, exit_code={}",
                pid,
                exit_code,
            );
        }
    }
    0
}
