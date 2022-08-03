#![no_std]
#![no_main]
use user_lib::{exec, exit, fork, wait, waitpid, yield_};

#[no_mangle]
#[link_section = ".text.entry"]
pub extern "C" fn _start() -> ! {
    exit(main());
}

#[no_mangle]
fn main() -> i32 {
    let bash_path = "/bin/bash\0";
    let environ = [
        "SHELL=/bash\0".as_ptr(),
        "PWD=/\0".as_ptr(),
        "LOGNAME=root\0".as_ptr(),
        "MOTD_SHOWN=pam\0".as_ptr(),
        "HOME=/root\0".as_ptr(),
        "LANG=C.UTF-8\0".as_ptr(),
        "TERM=vt220\0".as_ptr(),
        "USER=root\0".as_ptr(),
        "SHLVL=0\0".as_ptr(),
        "OLDPWD=/root\0".as_ptr(),
        "_=/bin/bash\0".as_ptr(),
        "PATH=/:/bin\0".as_ptr(),
        "LD_LIBRARY_PATH=/\0".as_ptr(),
        core::ptr::null(),
    ];
    let schedule = [
        [
            bash_path.as_ptr(),
            "run-all.sh\0".as_ptr(),
            core::ptr::null(),
            core::ptr::null(),
        ],
        [
            bash_path.as_ptr(),
            "-c\0".as_ptr(),
            "echo aaa > lat_sig\0".as_ptr(),
            core::ptr::null(),
        ],
        [
            bash_path.as_ptr(),
            "-c\0".as_ptr(),
            "touch hello\0".as_ptr(),
            core::ptr::null(),
        ],
        [
            bash_path.as_ptr(),
            "busybox_testcode.sh\0".as_ptr(),
            core::ptr::null(),
            core::ptr::null(),
        ],
        [
            bash_path.as_ptr(),
            "lua_testcode.sh\0".as_ptr(),
            core::ptr::null(),
            core::ptr::null(),
        ],
        [
            bash_path.as_ptr(),
            "lmbench_testcode.sh\0".as_ptr(),
            core::ptr::null(),
            core::ptr::null(),
        ],
    ];
    let mut exit_code: i32 = 0;
    for argv in schedule {
        let pid = fork();
        if pid == 0 {
            exec(bash_path, &argv, &environ);
        } else {
            waitpid(pid as usize, &mut exit_code);
        }
    }
    loop {
        wait(&mut exit_code);
    }
    0
}
