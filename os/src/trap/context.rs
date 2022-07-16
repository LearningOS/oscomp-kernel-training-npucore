use riscv::register::sstatus::{self, set_spp, Sstatus, SPP};

use crate::task::{Signals, SignalStack};

#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct GpState {
    pub x: [usize; 32]
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct FpState {
    pub f: [usize; 32],
    pub fcsr: u32,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct MachineContext {
    gp: GpState,
    fp: FpState,
}

impl From<TrapContext> for MachineContext {
    fn from(trap_cx: TrapContext) -> Self {
        Self {
            gp: trap_cx.gp,
            fp: trap_cx.fp,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UserContext
{
	pub flags: usize,
	pub link: usize,
	pub stack: SignalStack,
	pub sigmask: Signals,
    pub mcontext: TrapContext,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
/// The trap cotext containing the user context and the supervisor level
pub struct TrapContext {
    /// The registers to be preserved.
    pub gp: GpState,
    pub fp: FpState,
    /// A copy of register a0, useful when we need to restart syscall
    pub origin_a0: usize,
    /// Privilege level of the trap context
    pub sstatus: Sstatus,
    /// Supervisor exception program counter.
    pub sepc: usize,
    /// Supervisor Address Translation and Protection
    pub kernel_satp: usize,
    /// The pointer to trap_handler
    pub trap_handler: usize,
    /// The current sp to be recovered on next entry into kernel space.
    pub kernel_sp: usize,
}

impl TrapContext {
    pub fn set_sp(&mut self, sp: usize) {
        self.gp.x[2] = sp;
    }
    pub fn app_init_context(
        entry: usize,
        sp: usize,
        kernel_satp: usize,
        kernel_sp: usize,
        trap_handler: usize,
    ) -> Self {
        let mut sstatus = sstatus::read();
        // set CPU privilege to User after trapping back
        unsafe {
            set_spp(SPP::User);
        }
        let mut cx = Self {
            gp: GpState::default(),
            fp: FpState::default(),
            origin_a0: 0,
            sstatus,
            sepc: entry,
            kernel_satp,
            trap_handler,
            kernel_sp,
        };
        cx.set_sp(sp);
        cx
    }
}
