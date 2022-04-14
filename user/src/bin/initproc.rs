#![no_std]
#![no_main]
use user_lib::{exit, exec, fork, wait, yield_};

#[no_mangle]
#[link_section = ".text.entry"]
pub extern "C" fn _start() -> ! {
    exit(main());
}

#[no_mangle]
fn main() -> i32 {
    let path = "/bin/bash\0";
    if fork() == 0 {
        exec(path, &[path.as_ptr() as *const u8]);
    } else {
        loop {
            let mut exit_code: i32 = 0;
            let pid = wait(&mut exit_code);
            // ECHLD is -10
            if pid == -10 {
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
