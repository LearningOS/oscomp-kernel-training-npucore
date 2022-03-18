use riscv::register::sstatus::{self, Sstatus, SPP, set_spp};

#[repr(C)]
#[derive(Debug, Clone, Copy)]
/// The trap cotext containing the user context and the supervisor level
pub struct TrapContext {
    /// The registers to be preserved.
    pub x: [usize; 32],
    /// Privilege level of the trap context
    pub sstatus: Sstatus,
    /// Supervisor exception program counter.
    pub sepc: usize,
    /// Supervisor Address Translation and Protection
    pub kernel_satp: usize,
    /// The current sp to be recovered on next entry into kernel space.
    pub kernel_sp: usize,
    /// The pointer to trap_handler
    pub trap_handler: usize,
}

impl TrapContext {
    pub fn set_sp(&mut self, sp: usize) {
        self.x[2] = sp;
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
        unsafe { set_spp(SPP::User); }
        let mut cx = Self {
            x: [0; 32],
            sstatus,
            sepc: entry,
            kernel_satp,
            kernel_sp,
            trap_handler,
        };
        cx.set_sp(sp);
        cx
    }
}
