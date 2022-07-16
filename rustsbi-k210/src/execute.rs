use core::{
    arch::asm,
    ops::{Generator, GeneratorState, Not},
    panic,
    pin::Pin,
};
use riscv::register::scause::{Exception, Trap};

use crate::feature;
use crate::runtime::{MachineTrap, Runtime, SupervisorContext};

pub fn execute_supervisor(supervisor_mepc: usize, a0: usize, a1: usize) -> ! {
    let mut rt = Runtime::new_sbi_supervisor(supervisor_mepc, a0, a1);
    loop {
        match Pin::new(&mut rt).resume(()) {
            GeneratorState::Yielded(MachineTrap::SbiCall()) => {
                let ctx = rt.context_mut();
                if emulate_sbi_call(ctx) {
                    continue;
                }
                feature::preprocess_supervisor_external(ctx); // specific for 1.9.1; see document for details
                let param = [ctx.a0, ctx.a1, ctx.a2, ctx.a3, ctx.a4, ctx.a5];
                let ans = rustsbi::ecall(ctx.a7, ctx.a6, param);
                ctx.a0 = ans.error;
                ctx.a1 = ans.value;
                ctx.mepc = ctx.mepc.wrapping_add(4);
            }
            GeneratorState::Yielded(MachineTrap::IllegalInstruction()) => {
                let ctx = rt.context_mut();
                // FIXME: get_vaddr_u32这个过程可能出错。
                let ins = unsafe { get_vaddr_u32(ctx.mepc) } as usize;
                if !emulate_illegal_instruction(ctx, ins) {
                    unsafe {
                        if feature::should_transfer_trap(ctx) {
                            feature::do_transfer_trap(
                                ctx,
                                Trap::Exception(Exception::IllegalInstruction),
                            )
                        } else {
                            fail_illegal_instruction(ctx, ins)
                        }
                    }
                }
            }
            GeneratorState::Yielded(MachineTrap::ExternalInterrupt()) => unsafe {
                //rustsbi::println!("[rustsbi] MachineTrap::ExternalInterrupt");
                let ctx = rt.context_mut();
                feature::call_supervisor_interrupt(ctx)
            },
            GeneratorState::Yielded(MachineTrap::MachineTimer()) => {
                //rustsbi::println!("[rustsbi] MachineTrap::MachineTimer");
                feature::forward_supervisor_timer()
            }
            GeneratorState::Yielded(MachineTrap::MachineSoft()) => {
                //rustsbi::println!("[rustsbi] MachineTrap::MachineSoft");
                feature::forward_supervisor_soft()
            }
            // todo：编写样例，验证store page fault和instruction page fault
            GeneratorState::Yielded(MachineTrap::InstructionFault(addr)) => {
                let ctx = rt.context_mut();
                if feature::is_page_fault(addr) {
                    unsafe {
                        feature::do_transfer_trap(
                            ctx,
                            Trap::Exception(Exception::InstructionPageFault),
                        )
                    }
                } else {
                    unsafe {
                        feature::do_transfer_trap(ctx, Trap::Exception(Exception::InstructionFault))
                    }
                }
            }
            GeneratorState::Yielded(MachineTrap::LoadMisaligned(addr)) => {
                todo!();
            }
            /* K210 implements only priv. 1.9.1 which doesn't contain a real `mtval` register,
             * but only a `mbadaddr` register.
             * However, it seems that the abi is actually the same for the access of the two.
             */
            GeneratorState::Yielded(MachineTrap::StoreMisaligned(addr)) => {
                let ctx = rt.context_mut();
                let ins = unsafe { get_vaddr_u32(ctx.mepc) };
                let mut store_val = match get_rs2(ins) {
                    0 => 0,
                    1 => rt.context_mut().ra,
                    2 => rt.context_mut().sp,
                    3 => rt.context_mut().gp,
                    4 => rt.context_mut().tp,

                    5 => rt.context_mut().t0,
                    6 => rt.context_mut().t1,
                    7 => rt.context_mut().t2,

                    8 => rt.context_mut().s0,
                    9 => rt.context_mut().s1,

                    10 => rt.context_mut().a0,
                    11 => rt.context_mut().a1,
                    12 => rt.context_mut().a2,
                    13 => rt.context_mut().a3,
                    14 => rt.context_mut().a4,
                    15 => rt.context_mut().a5,
                    16 => rt.context_mut().a6,
                    17 => rt.context_mut().a7,

                    18 => rt.context_mut().s2,
                    19 => rt.context_mut().s3,
                    20 => rt.context_mut().s4,
                    21 => rt.context_mut().s5,
                    22 => rt.context_mut().s6,
                    23 => rt.context_mut().s7,
                    24 => rt.context_mut().s8,
                    25 => rt.context_mut().s9,
                    26 => rt.context_mut().s10,
                    27 => rt.context_mut().s11,

                    28 => rt.context_mut().t3,
                    29 => rt.context_mut().t4,
                    30 => rt.context_mut().t5,
                    31 => rt.context_mut().t6,
                    _ => panic!(),
                };

                match get_funct(ins) {
                    0b000 => {
                        //sb
                        store_val = store_val as u8 as usize;
                        let l_addr = addr & (!3);
                        let shn = addr & 3;
                        unsafe {
                            s_lv_translation_mode_on();
                            asm!("
                               sll {0}, {0}, {2}
                               lw {3}, 0({1})
                               and {0}, {3}, {0}
                               sw {0}, 0({1})
                               ", in(reg) store_val, in(reg) l_addr, in(reg) shn, out(reg) _);
                            s_lv_translation_mode_off();
                        }
                    }
                    0b001 => {
                        //sh
                        let l_addr = addr & (!3);
                        let shn = addr & 3;
                        if shn != 3 {
                            store_val = (store_val as u16) as usize;
                            unsafe {
                                s_lv_translation_mode_on();
                                asm!("
                               sll {0}, {0}, {2}
                               lw {3}, 0({1})
                               and {0}, {3}, {0}
                               sw {0}, 0({1})
                               ", in(reg) store_val, in(reg) l_addr, in(reg) shn, out(reg) _);
                                s_lv_translation_mode_off();
                            }
                        } else {
                            store_val = (store_val as u16) as usize;
                            let high = store_val >> 8;
                            store_val = (store_val as u8) as usize;
                            unsafe {
                                s_lv_translation_mode_on();
                                asm!("
                               slli {0}, {0}, 3
                               lw {2}, 0({1})
                               and {0}, {2}, {0}
                               sw {0}, 0({1})
                               lw {0}, 4({1})
                               and {2}, {2}, {3}
                               sw {0}, 4({1})
                               ", in(reg) store_val, in(reg) l_addr,
                                     out(reg) _, in(reg) high);
                                s_lv_translation_mode_off();
                            }
                        }
                    }
                    0b010 => {
                        //sw
                        let l_addr = addr & (!3);
                        let shn = addr & 3;
                        let shift_bits = (4 - shn) << 3;
                        store_val = store_val as u32 as usize; //
                        let high = store_val >> shift_bits; //
                        store_val = store_val & ((1 << shift_bits) - 1); // store_val & ((8^shn)-1)
                        unsafe {
                            s_lv_translation_mode_on();
                            asm!("
                               lw {2}, 0({1})
                               and {0}, {2}, {0}
                               sw {0}, 0({1})
                               lw {0}, 4({1})
                               and {2}, {2}, {3}
                               sw {0}, 4({1})
                               ", in(reg) store_val, in(reg) l_addr,
                                  out(reg) _, in(reg) high);
                            s_lv_translation_mode_off();
                        }
                    }
                    0b011 => {
                        //sd
                        let l_addr = addr & (!7);
                        let shn = addr & 7;
                        let shift_bits = (8 - shn) << 4;
                        store_val = store_val as u32 as usize; //
                        let high = store_val >> shift_bits; //
                        store_val = store_val & ((1 << shift_bits) - 1); // store_val & ((8^shn)-1)
                        unsafe {
                            s_lv_translation_mode_on();
                            asm!("
                               ld {2}, 0({1})
                               and {0}, {2}, {0}
                               sd {0}, 0({1})
                               ld {0}, 4({1})
                               and {2}, {2}, {3}
                               sd {0}, 4({1})
                               ", in(reg) store_val, in(reg) l_addr,
                                  out(reg) _, in(reg) high);
                            s_lv_translation_mode_off();
                        }
                    }
                    _ => {
                        panic!(
                            "Unknown funct code for store type. Failed to store misaligned data."
                        );
                    }
                }
            }
            GeneratorState::Yielded(MachineTrap::LoadFault(addr)) => {
                let ctx = rt.context_mut();
                if feature::is_page_fault(addr) {
                    unsafe {
                        feature::do_transfer_trap(ctx, Trap::Exception(Exception::LoadPageFault))
                    }
                } else {
                    unsafe { feature::do_transfer_trap(ctx, Trap::Exception(Exception::LoadFault)) }
                }
            }
            GeneratorState::Yielded(MachineTrap::StoreFault(addr)) => {
                let ctx = rt.context_mut();
                if feature::is_page_fault(addr) {
                    unsafe {
                        feature::do_transfer_trap(ctx, Trap::Exception(Exception::StorePageFault))
                    }
                } else {
                    unsafe {
                        feature::do_transfer_trap(ctx, Trap::Exception(Exception::StoreFault))
                    }
                }
            }
            GeneratorState::Complete(()) => unreachable!(),
        }
    }
}

#[inline(always)]
fn get_rs1(ins: u32) -> u32 {
    get_ins_seg_aligned(ins, 15, 19)
}
fn get_funct(ins: u32) -> u32 {
    get_ins_seg_aligned(ins, 12, 14)
}
#[inline(always)]
fn get_rs2(ins: u32) -> u32 {
    get_ins_seg_aligned(ins, 20, 24)
}
#[inline(always)]
fn get_ins_seg_aligned(ins: u32, beg: u32, last: u32) -> u32 {
    (ins >> beg) & ((1 << (last - beg + 1)) - 1)
}
#[inline]
unsafe fn s_lv_translation_mode_on() {
    asm!("
li {0}, (1<<17)
csrrs {0}, mstatus, {0}
", out(reg) _);
}

#[inline]
unsafe fn s_lv_translation_mode_off() {
    asm!("
li {0}, (1<<17)
csrw mstatus, {0}", out(reg) _)
}

#[inline]
unsafe fn store_half(store_val: usize, addr: usize) {
    asm!("
    sb     {0}, 0({1})
    srli   {0}, (8)
    sb     {0}, 1({1})
    ", in(reg) store_val, in(reg) addr);
}
#[inline]
unsafe fn store_word(store_val: usize, addr: usize) {
    asm!("
      sb     {0}, 0({1})
      srli   {0}, (8)
      sb     {0}, 1({1})
      srli   {0}, (8)
      sb     {0}, 2({1})
      srli   {0}, (8)
      sb     {0}, 3({1})
    ", in(reg) store_val, in(reg) addr);
}
#[inline]
unsafe fn store_double_word(store_val: usize, addr: usize) {
    asm!("
      sb     {0}, 0({1})
      srli   {0}, (8)
      sb     {0}, 1({1})
      srli   {0}, (8)
      sb     {0}, 2({1})
      srli   {0}, (8)
      sb     {0}, 3({1})
      srli   {0}, (8)
      sb     {0}, 4({1})
      srli   {0}, (8)
      sb     {0}, 5({1})
      srli   {0}, (8)
      sb     {0}, 6({1})
      srli   {0}, (8)
      sb     {0}, 7({1})
    ", in(reg) store_val, in(reg) addr);
}

#[inline]
/// We don't know what kind of load it is really doing,
/// but we are pretty sure that k210 we use is a rv64 machine.
unsafe fn get_vaddr_u64(vaddr: usize) -> u64 {
    let mut ans: u64;
    asm!("
        li      {2}, (1 << 17)
        csrrs   {2}, mstatus, {2}
        ld     {0}, 0({1})
        csrw    mstatus, {2}
    ", out(reg) ans, in(reg) vaddr, out(reg) _);
    ans
}

// Was it done in u16 fashion for compatibility reasons?
#[inline]
unsafe fn get_vaddr_u32(vaddr: usize) -> u32 {
    get_vaddr_u16(vaddr) as u32 | ((get_vaddr_u16(vaddr.wrapping_add(2)) as u32) << 16)
}

#[inline]
unsafe fn get_vaddr_u16(vaddr: usize) -> u16 {
    let mut ans: u16;
    asm!("
        li      {2}, (1 << 17)
        csrrs   {2}, mstatus, {2}
        lhu     {0}, 0({1})
        csrw    mstatus, {2}
    ", out(reg) ans, in(reg) vaddr, out(reg) _);
    ans
}

fn emulate_sbi_call(ctx: &mut SupervisorContext) -> bool {
    if feature::emulate_sbi_rustsbi_k210_sext(ctx) {
        return true;
    }
    false
}

fn emulate_illegal_instruction(ctx: &mut SupervisorContext, ins: usize) -> bool {
    if feature::emulate_rdtime(ctx, ins) {
        //rustsbi::println!("[rustsbi] emulate rdtime");
        return true;
    }
    if feature::emulate_sfence_vma(ctx, ins) {
        //rustsbi::println!("[rustsbi] emulate sfence.vma");
        return true;
    }
    false
}

// 真·非法指令异常，是M层出现的
fn fail_illegal_instruction(ctx: &mut SupervisorContext, ins: usize) -> ! {
    panic!("invalid instruction from machine level, mepc: {:016x?}, instruction: {:016x?}, context: {:016x?}", ctx.mepc, ins, ctx);
}
