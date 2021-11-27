use core::borrow::BorrowMut;
use core::mem::ManuallyDrop;

use super::signal::*;
use super::TaskContext;
use super::{pid_alloc, KernelStack, PidHandle};
use crate::config::*;
use crate::fs::{FileClass, FileDescripter, Stdin, Stdout};
use crate::mm::VirtPageNum;
use crate::mm::{
    translated_refmut, MapPermission, MemorySet, MmapArea, PhysPageNum, VirtAddr, KERNEL_SPACE,
};
use crate::task::current_user_token;
use crate::trap::{trap_handler, TrapContext};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use spin::{Mutex, MutexGuard};

pub struct TaskControlBlock {
    // immutable
    pub pid: PidHandle,
    pub pgid: usize,
    pub kernel_stack: KernelStack,
    // mutable
    inner: Mutex<TaskControlBlockInner>,
}

pub type FdTable = Vec<Option<FileDescripter>>;
pub struct TaskControlBlockInner {
    pub trap_cx_ppn: PhysPageNum,
    pub base_size: usize,
    pub task_cx_ptr: usize,
    pub task_status: TaskStatus,
    pub memory_set: MemorySet,
    pub parent: Option<Weak<TaskControlBlock>>,
    pub children: Vec<Arc<TaskControlBlock>>,
    pub exit_code: i32,
    pub fd_table: FdTable,
    pub address: ProcAddress,
    pub heap_bottom: usize,
    pub heap_pt: usize,
    pub current_path: String,
    pub siginfo: SigInfo,
}

impl TaskControlBlockInner {
    pub fn get_task_cx_ptr2(&self) -> *const usize {
        &self.task_cx_ptr as *const usize
    }
    pub fn get_trap_cx(&self) -> &'static mut TrapContext {
        self.trap_cx_ppn.get_mut()
    }
    pub fn get_user_token(&self) -> usize {
        self.memory_set.token()
    }
    fn get_status(&self) -> TaskStatus {
        self.task_status
    }
    pub fn is_zombie(&self) -> bool {
        self.get_status() == TaskStatus::Zombie
    }
    pub fn alloc_fd(&mut self) -> usize {
        if let Some(fd) = (0..self.fd_table.len()).find(|fd| self.fd_table[*fd].is_none()) {
            fd
        } else {
            self.fd_table.push(None);
            self.fd_table.len() - 1
        }
    }
    pub fn get_work_path(&self) -> String {
        self.current_path.clone()
    }
    pub fn add_signal(&mut self, signal: Signals) {
        self.siginfo.signal_pending.push(signal);
    }
}

impl TaskControlBlock {
    pub fn acquire_inner_lock(&self) -> MutexGuard<TaskControlBlockInner> {
        self.inner.lock()
    }
    pub fn new(elf_data: &[u8]) -> Self {
        // memory_set with elf program headers/trampoline/trap context/user stack
        let (memory_set, user_sp, user_heap, entry_point, auxv) = MemorySet::from_elf(elf_data);

        crate::mm::KERNEL_SPACE
            .lock()
            .remove_area_with_start_vpn(VirtAddr::from(elf_data.as_ptr() as usize).floor());

        let trap_cx_ppn = memory_set
            .translate(VirtAddr::from(TRAP_CONTEXT).into())
            .unwrap()
            .ppn();
        // alloc a pid and a kernel stack in kernel space
        let pid_handle = pid_alloc();
        let pgid = pid_handle.0;
        let kernel_stack = KernelStack::new(&pid_handle);
        let kernel_stack_top = kernel_stack.get_top();
        // push a task context which goes to trap_return to the top of kernel stack
        let task_cx_ptr = kernel_stack.push_on_top(TaskContext::goto_trap_return());
        let task_control_block = Self {
            pid: pid_handle,
            pgid: pgid,
            kernel_stack,
            inner: Mutex::new(TaskControlBlockInner {
                trap_cx_ppn,
                base_size: user_sp,
                task_cx_ptr: task_cx_ptr as usize,
                task_status: TaskStatus::Ready,
                memory_set,
                parent: None,
                children: Vec::new(),
                exit_code: 0,
                fd_table: vec![
                    // 0 -> stdin
                    Some(FileDescripter::new(
                        false,
                        FileClass::Abstr(Arc::new(Stdin)),
                    )),
                    // 1 -> stdout
                    Some(FileDescripter::new(
                        false,
                        FileClass::Abstr(Arc::new(Stdout)),
                    )),
                    // 2 -> stderr
                    Some(FileDescripter::new(
                        false,
                        FileClass::Abstr(Arc::new(Stdout)),
                    )),
                ],
                address: ProcAddress::new(),
                heap_bottom: user_heap,
                heap_pt: user_heap,
                current_path: String::from("/"),
                siginfo: SigInfo::new(),
            }),
        };
        // prepare TrapContext in user space
        let trap_cx = task_control_block.acquire_inner_lock().get_trap_cx();
        *trap_cx = TrapContext::app_init_context(
            entry_point,
            user_sp,
            KERNEL_SPACE.lock().token(),
            kernel_stack_top,
            trap_handler as usize,
        );
        task_control_block
    }
    pub fn exec(&self, elf_data: &[u8], args: Vec<String>) {
        // memory_set with elf program headers/trampoline/trap context/user stack
        let (memory_set, mut user_sp, user_heap, entry_point, mut auxv) =
            MemorySet::from_elf(elf_data);
        println!(
            "[exec] load DONE. user_sp:{:X}; user_heap:{:X}; entry_point:{:X}",
            user_sp, user_heap, entry_point
        );
        crate::mm::KERNEL_SPACE
            .lock()
            .remove_area_with_start_vpn(VirtAddr::from(elf_data.as_ptr() as usize).floor());

        let trap_cx_ppn = memory_set
            .translate(VirtAddr::from(TRAP_CONTEXT).into())
            .unwrap()
            .ppn();

        ////////////// envp[] ///////////////////
        let mut env: Vec<String> = Vec::new();
        env.push(String::from("SHELL=/user_shell"));
        env.push(String::from("PWD=/"));
        env.push(String::from("USER=root"));
        env.push(String::from("MOTD_SHOWN=pam"));
        env.push(String::from("LANG=C.UTF-8"));
        env.push(String::from(
            "INVOCATION_ID=e9500a871cf044d9886a157f53826684",
        ));
        env.push(String::from("TERM=vt220"));
        env.push(String::from("SHLVL=2"));
        env.push(String::from("JOURNAL_STREAM=8:9265"));
        env.push(String::from("OLDPWD=/root"));
        env.push(String::from("_=busybox"));
        env.push(String::from("LOGNAME=root"));
        env.push(String::from("HOME=/"));
        env.push(String::from("PATH=/"));
        let mut envp: Vec<usize> = (0..=env.len()).collect();
        envp[env.len()] = 0;
        for i in 0..env.len() {
            user_sp -= env[i].len() + 1;
            envp[i] = user_sp;
            let mut p = user_sp;
            // write chars to [user_sp, user_sp + len]
            for c in env[i].as_bytes() {
                *translated_refmut(memory_set.token(), p as *mut u8) = *c;
                p += 1;
            }
            *translated_refmut(memory_set.token(), p as *mut u8) = 0;
        }
        // make the user_sp aligned to 8B for k210 platform
        user_sp -= user_sp % core::mem::size_of::<usize>();

        // push arguments on user stack
        let mut argv: Vec<_> = (0..=args.len()).collect();
        argv[args.len()] = 0;
        for i in 0..args.len() {
            user_sp -= args[i].len() + 1;
            argv[i] = user_sp;
            let mut p = user_sp;
            for c in args[i].as_bytes() {
                *translated_refmut(memory_set.token(), p as *mut u8) = *c;
                p += 1;
            }
            *translated_refmut(memory_set.token(), p as *mut u8) = 0;
        }
        // make the user_sp aligned to 8B for k210 platform
        user_sp -= user_sp % core::mem::size_of::<usize>();

        ////////////// platform String ///////////////////
        let platform = "RISC-V64";
        user_sp -= platform.len() + 1;
        user_sp -= user_sp % core::mem::size_of::<usize>();
        let mut p = user_sp;
        for c in platform.as_bytes() {
            *translated_refmut(memory_set.token(), p as *mut u8) = *c;
            p += 1;
        }
        *translated_refmut(memory_set.token(), p as *mut u8) = 0;

        ////////////// rand bytes ///////////////////
        user_sp -= 16;
        p = user_sp;
        auxv.push(AuxHeader {
            aux_type: AT_RANDOM,
            value: user_sp,
        });
        for i in 0..0xf {
            *translated_refmut(memory_set.token(), p as *mut u8) = i as u8;
            p += 1;
        }

        ////////////// padding //////////////////////
        user_sp -= user_sp % 16;

        ////////////// auxv[] //////////////////////
        auxv.push(AuxHeader {
            aux_type: AT_EXECFN,
            value: argv[0],
        }); // file name
        auxv.push(AuxHeader {
            aux_type: AT_NULL,
            value: 0,
        }); // end
        user_sp -= auxv.len() * core::mem::size_of::<AuxHeader>();
        let auxv_base = user_sp;
        // println!("[auxv]: base 0x{:X}", auxv_base);
        for i in 0..auxv.len() {
            // println!("[auxv]: {:?}", auxv[i]);
            let addr = user_sp + core::mem::size_of::<AuxHeader>() * i;
            *translated_refmut(memory_set.token(), addr as *mut usize) = auxv[i].aux_type;
            *translated_refmut(
                memory_set.token(),
                (addr + core::mem::size_of::<usize>()) as *mut usize,
            ) = auxv[i].value;
        }

        ////////////// *envp [] //////////////////////
        user_sp -= (env.len() + 1) * core::mem::size_of::<usize>();
        let envp_base = user_sp;
        *translated_refmut(
            memory_set.token(),
            (user_sp + core::mem::size_of::<usize>() * (env.len())) as *mut usize,
        ) = 0;
        for i in 0..env.len() {
            *translated_refmut(
                memory_set.token(),
                (user_sp + core::mem::size_of::<usize>() * i) as *mut usize,
            ) = envp[i];
        }

        ////////////// *argv [] //////////////////////
        user_sp -= (args.len() + 1) * core::mem::size_of::<usize>();
        let argv_base = user_sp;
        *translated_refmut(
            memory_set.token(),
            (user_sp + core::mem::size_of::<usize>() * (args.len())) as *mut usize,
        ) = 0;
        for i in 0..args.len() {
            *translated_refmut(
                memory_set.token(),
                (user_sp + core::mem::size_of::<usize>() * i) as *mut usize,
            ) = argv[i];
        }

        ////////////// argc //////////////////////
        user_sp -= core::mem::size_of::<usize>();
        *translated_refmut(memory_set.token(), user_sp as *mut usize) = args.len();

        // **** hold current PCB lock
        let mut inner = self.acquire_inner_lock();
        // substitute memory_set
        inner.memory_set = memory_set;
        inner.heap_bottom = user_heap;
        inner.heap_pt = user_heap;
        // update trap_cx ppn
        inner.trap_cx_ppn = trap_cx_ppn;
        // initialize trap_cx
        let mut trap_cx = TrapContext::app_init_context(
            entry_point,
            user_sp,
            KERNEL_SPACE.lock().token(),
            self.kernel_stack.get_top(),
            trap_handler as usize,
        );
        trap_cx.x[10] = args.len();
        trap_cx.x[11] = argv_base;
        trap_cx.x[12] = envp_base;
        trap_cx.x[13] = auxv_base;
        *inner.get_trap_cx() = trap_cx;
        // **** release current PCB lock
    }
    pub fn fork(self: &Arc<TaskControlBlock>) -> Arc<TaskControlBlock> {
        // ---- hold parent PCB lock
        let mut parent_inner = self.acquire_inner_lock();
        // copy user space(include trap context)
        let memory_set = MemorySet::from_existed_user(&parent_inner.memory_set);
        let trap_cx_ppn = memory_set
            .translate(VirtAddr::from(TRAP_CONTEXT).into())
            .unwrap()
            .ppn();
        // alloc a pid and a kernel stack in kernel space
        let pid_handle = pid_alloc();
        let kernel_stack = KernelStack::new(&pid_handle);
        let kernel_stack_top = kernel_stack.get_top();
        // push a goto_trap_return task_cx on the top of kernel stack
        let task_cx_ptr = kernel_stack.push_on_top(TaskContext::goto_trap_return());
        // copy fd table
        let mut new_fd_table: FdTable = Vec::new();
        for fd in parent_inner.fd_table.iter() {
            if let Some(file) = fd {
                new_fd_table.push(Some(file.clone()));
            } else {
                new_fd_table.push(None);
            }
        }
        let task_control_block = Arc::new(TaskControlBlock {
            pid: pid_handle,
            pgid: self.pgid,
            kernel_stack,
            inner: Mutex::new(TaskControlBlockInner {
                trap_cx_ppn,
                base_size: parent_inner.base_size,
                task_cx_ptr: task_cx_ptr as usize,
                task_status: TaskStatus::Ready,
                memory_set,
                parent: Some(Arc::downgrade(self)),
                children: Vec::new(),
                exit_code: 0,
                fd_table: new_fd_table,
                address: ProcAddress::new(),
                heap_bottom: parent_inner.heap_bottom,
                heap_pt: parent_inner.heap_pt,
                current_path: parent_inner.current_path.clone(),
                siginfo: parent_inner.siginfo.clone(),
            }),
        });
        // add child
        parent_inner.children.push(task_control_block.clone());
        // modify kernel_sp in trap_cx
        // **** acquire child PCB lock
        let trap_cx = task_control_block.acquire_inner_lock().get_trap_cx();
        // **** release child PCB lock
        trap_cx.kernel_sp = kernel_stack_top;
        // return
        task_control_block
        // ---- release parent PCB lock
    }
    pub fn getpid(&self) -> usize {
        self.pid.0
    }
    pub fn setpgid(&self, pgid: usize) -> usize {
        //self.pgid = pgid;
        //Temporarily suspend. Because the type of 'self' is 'Arc', which can't be borrow as mutable.
        0
    }
    pub fn getpgid(&self) -> usize {
        self.pgid
    }
    pub fn sbrk(&self, increment: isize) -> usize {
        let mut inner = self.acquire_inner_lock();
        let old_pt: usize = inner.heap_pt;
        let new_pt: usize = old_pt + increment as usize;
        if increment > 0 {
            let limit = inner.heap_bottom + USER_HEAP_SIZE;
            if new_pt > limit {
                println!(
                    "[sbrk] over the upperbond! {} {} {} {}",
                    limit, inner.heap_pt, new_pt, self.pid.0
                );
                return old_pt;
            }
            inner.memory_set.insert_heap_area(
                old_pt.into(),
                new_pt.into(),
                MapPermission::R | MapPermission::W | MapPermission::U,
            );
            inner.heap_pt = new_pt;
        } else {
            if new_pt < inner.heap_bottom {
                println!("[sbrk] shrinked to the lowest boundary!");
                return old_pt;
            }
            inner.heap_pt = new_pt;
        }
        new_pt
    }

    /// 建立从文件到内存的映射
    pub fn mmap(
        &self,
        start: usize,  // 开始地址
        len: usize,    // 内存映射长度
        prot: usize,   // 保护位标志
        flags: usize,  // 映射方式
        fd: usize,     // 被映射文件
        offset: usize, // 文件位移
    ) -> usize {
        println!(
            "[mmap] start:{:X}; len:{:X}; prot:{:X}; flags:{:X}; fd:{:X}; offset:{:X}",
            start, len, prot, flags, fd, offset
        );
        if start % PAGE_SIZE != 0 {
            panic!("[mmap] start not aligned.");
        }
        if (prot & !0x7 != 0) || len > 0x1_000_000_000 {
            return -1isize as usize;
        }
        let len = if len == 0 { PAGE_SIZE } else { len };
        let mut inner = self.acquire_inner_lock();
        if start != 0 {
            // "Start" va Already mapped
            let mut startvpn = start / PAGE_SIZE;
            while startvpn < (start + len) / PAGE_SIZE {
                if inner
                    .memory_set
                    .set_pte_flags(startvpn.into(), ((prot << 1) | (1 << 4)) as usize)
                    == -1
                {
                    panic!("mmap: start_va not mmaped");
                }
                startvpn += 1;
            }
            start
        } else {
            // "Start" va not mapped
            let start_va = inner.memory_set.get_mmap_top();
            let permission = MapPermission::from_bits(((prot << 1) | (1 << 4)) as u8).unwrap();
            let fd_table = inner.fd_table.clone();
            let token = inner.get_user_token();
            inner.memory_set.insert_mmap_area(
                start_va,
                len,
                permission,
                flags,
                fd as isize,
                offset,
                fd_table,
                token,
            );
            start_va.0
        }
    }
    pub fn munmap(&self, start: usize, len: usize) -> isize {
        let mut inner = self.acquire_inner_lock();
        inner
            .memory_set
            .remove_mmap_area_with_start_vpn(VirtAddr::from(start).into());
        0
    }
}

#[derive(Copy, Clone, PartialEq)]
pub enum TaskStatus {
    Ready,
    Running,
    Zombie,
}

pub struct ProcAddress {
    pub set_child_tid: usize,
    pub clear_child_tid: usize,
}

impl ProcAddress {
    pub fn new() -> Self {
        Self {
            set_child_tid: 0,
            clear_child_tid: 0,
        }
    }
}

pub struct AuxHeader {
    pub aux_type: usize,
    pub value: usize,
}
