mod context;

use core::arch::{asm, global_asm};

use crate::config::{TRAMPOLINE, TRAP_CONTEXT};
use crate::mm::{MapPermission, PhysPageNum, VirtAddr, VirtPageNum};
use crate::syscall::syscall;
use crate::task::{
    current_task, current_trap_cx, current_user_token, do_signal, exit_current_and_run_next,
    suspend_current_and_run_next, Signals,
};
use crate::timer::set_next_trigger;
use riscv::register::{
    mtvec::TrapMode,
    scause::{self, Exception, Interrupt, Trap},
    sie, stval, stvec,
};

global_asm!(include_str!("trap.S"));

extern "C" {
    pub fn __alltraps();
    pub fn __restore();
    pub fn __call_sigreturn();
}

pub fn init() {
    set_kernel_trap_entry();
}

fn set_kernel_trap_entry() {
    unsafe {
        stvec::write(trap_from_kernel as usize, TrapMode::Direct);
    }
}

fn set_user_trap_entry() {
    unsafe {
        stvec::write(TRAMPOLINE as usize, TrapMode::Direct);
    }
}

pub fn enable_timer_interrupt() {
    unsafe {
        sie::set_stimer();
    }
}

#[no_mangle]
pub fn trap_handler() -> ! {
    set_kernel_trap_entry();
    {
        let task = current_task().unwrap();
        let mut inner = task.acquire_inner_lock();
        inner.update_process_times_enter_trap();
    }
    let scause = scause::read();
    let stval = stval::read();
    match scause.cause() {
        Trap::Exception(Exception::UserEnvCall) => {
            // jump to next instruction anyway
            let mut cx = current_trap_cx();
            cx.sepc += 4;
            // get system call return value
            let result = syscall(
                cx.x[17],
                [cx.x[10], cx.x[11], cx.x[12], cx.x[13], cx.x[14], cx.x[15]],
            );
            // cx is changed during sys_exec, so we have to call it again
            cx = current_trap_cx();
            cx.x[10] = result as usize;
        }
        Trap::Exception(Exception::StoreFault)
        | Trap::Exception(Exception::StorePageFault)
        | Trap::Exception(Exception::InstructionFault)
        | Trap::Exception(Exception::InstructionPageFault)
        | Trap::Exception(Exception::LoadFault)
        | Trap::Exception(Exception::LoadPageFault) => {
            let task = current_task().unwrap();
            let mut inner = task.acquire_inner_lock();
            let addr = VirtAddr::from(stval);
            log::debug!(
                "[page_fault] pid: {}, type: {:?}",
                task.pid.0,
                scause.cause()
            );
            // This is where we handle the page fault.
            if inner.memory_set.do_page_fault(addr).is_err() {
                inner.add_signal(Signals::SIGSEGV);
                log::debug!("{:?}", inner.siginfo);
            }
        }
        Trap::Exception(Exception::IllegalInstruction) => {
            let task = current_task().unwrap();
            let mut inner = task.acquire_inner_lock();
            inner.add_signal(Signals::SIGILL);
        }
        Trap::Interrupt(Interrupt::SupervisorTimer) => {
            set_next_trigger();
            suspend_current_and_run_next();
        }
        _ => {
            panic!(
                "Unsupported trap {:?}, stval = {:#x}!",
                scause.cause(),
                stval
            );
        }
    }
    {
        let task = current_task().unwrap();
        let mut inner = task.acquire_inner_lock();
        inner.update_process_times_leave_trap(scause.cause());
    }
    trap_return();
}

#[no_mangle]
pub fn trap_return() -> ! {
    do_signal();
    set_user_trap_entry();
    let trap_cx_ptr = TRAP_CONTEXT;
    let user_satp = current_user_token();
    let restore_va = __restore as usize - __alltraps as usize + TRAMPOLINE;
    unsafe {
        asm!(
            "fence.i",
            "jr {restore_va}",
            restore_va = in(reg) restore_va,
            in("a0") trap_cx_ptr,
            in("a1") user_satp,
            options(noreturn)
        );
    }
}

#[no_mangle]
pub fn trap_from_kernel() -> ! {
    println!("I will protect {:X}!", __call_sigreturn as usize);
    // It seems like rust has not keyword like "volatile" to protect some variables from being optimized out.
    // So I have to put it here. Hope someone can find a better way to solve it!
    panic!(
        "a trap {:?} from kernel! bad addr = {:#x}, bad instruction = {:#x}",
        scause::read().cause(),
        stval::read(),
        current_trap_cx().sepc
    );
}

pub use context::TrapContext;
