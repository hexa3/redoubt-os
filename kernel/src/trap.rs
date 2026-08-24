use core::arch::global_asm;

/// Full register state captured on every ring3->ring0 trap.
///
/// Layout contract with `trap_stub` below (ascending addresses):
/// GP registers pushed by software, then the five CPU-pushed values.
/// User-origin traps always have this complete layout. The idle loop also
/// permits timer interrupts at ring 0; that path only inspects the common
/// register/RIP/CS/RFLAGS prefix and returns through the native three-word
/// interrupt frame (see the assembly stub below).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TrapFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

impl TrapFrame {
    /// Fabricate an initial user-mode frame for a freshly spawned task.
    pub fn new_user(entry: u64, user_stack_top: u64, cs: u64, ss: u64) -> Self {
        TrapFrame {
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            r11: 0,
            r10: 0,
            r9: 0,
            r8: 0,
            rdi: 0,
            rsi: 0,
            rbp: 0,
            rbx: 0,
            rdx: 0,
            rcx: 0,
            rax: 0,
            rip: entry,
            cs,
            // bit 1 is reserved-and-must-be-1; IF set so timers tick in userland
            rflags: 0x202,
            rsp: user_stack_top,
            ss,
        }
    }
}

pub const VECTOR_TIMER: u64 = 32;
pub const VECTOR_SYSCALL: u64 = 0x80;

global_asm!(
    "
.macro PUSHALL
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
.endm

.macro POPALL
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
.endm

// rdi = frame ptr (set here), rsi = vector number, call into rust,
// rust returns the frame pointer to resume in rax (may belong to a
// different task: scheduler swapped stacks underneath us).
//
// Traps can arrive from ring 3 or ring 0 (the idle context runs with
// interrupts enabled). Ring-3 traps supply all five CPU words and can be
// context-switched. Ring-0 timer traps supply only rip/cs/rflags; they are
// handled in place and must return through exactly those three words.
// Do not synthesize rsp/ss here: iretq does not consume them when returning
// to the same privilege level, which would grow the idle stack by 16 bytes
// per tick.
.macro TRAP_STUB name:req, vector:req
.globl \\name
\\name:
    PUSHALL
    mov rdi, rsp
    movabs rsi, \\vector
    call handle_trap
    mov rsp, rax
    POPALL
    iretq
.endm

TRAP_STUB trap_stub_timer, {VECTOR_TIMER}
TRAP_STUB trap_stub_syscall, {VECTOR_SYSCALL}

// Recoverable CPU exceptions use a sibling path. Error-code exceptions have
// one extra word above the CPU frame; discard it before constructing the
// common TrapFrame. A user fault is never resumed: handle_user_fault exits
// that task and returns another task's frame. A kernel fault halts there.
.macro FAULT_STUB name:req, vector:req, has_error:req
.globl \\name
\\name:
.if \\has_error
    add rsp, 8
.endif
    PUSHALL
    mov rdi, rsp
    movabs rsi, \\vector
    call handle_user_fault
    mov rsp, rax
    POPALL
    iretq
.endm

FAULT_STUB fault_stub_de, 0, 0
FAULT_STUB fault_stub_bp, 3, 0
FAULT_STUB fault_stub_of, 4, 0
FAULT_STUB fault_stub_br, 5, 0
FAULT_STUB fault_stub_ud, 6, 0
FAULT_STUB fault_stub_nm, 7, 0
FAULT_STUB fault_stub_ts, 10, 1
FAULT_STUB fault_stub_np, 11, 1
FAULT_STUB fault_stub_ss, 12, 1
FAULT_STUB fault_stub_gp, 13, 1
FAULT_STUB fault_stub_pf, 14, 1
FAULT_STUB fault_stub_mf, 16, 0
FAULT_STUB fault_stub_ac, 17, 1
FAULT_STUB fault_stub_xm, 19, 0
FAULT_STUB fault_stub_cp, 21, 1
",
    VECTOR_TIMER = const VECTOR_TIMER,
    VECTOR_SYSCALL = const VECTOR_SYSCALL,
);

extern "sysv64" {
    // Referenced from the global_asm stubs above; invisible to rustc's
    // reachability analysis, hence the allow.
    #[allow(dead_code)]
    fn handle_trap(frame: *mut TrapFrame, vector: u64) -> *mut TrapFrame;
    #[allow(dead_code)]
    fn trap_stub_timer();
    #[allow(dead_code)]
    fn trap_stub_syscall();
    #[allow(dead_code)]
    fn fault_stub_de();
    #[allow(dead_code)]
    fn fault_stub_bp();
    #[allow(dead_code)]
    fn fault_stub_of();
    #[allow(dead_code)]
    fn fault_stub_br();
    #[allow(dead_code)]
    fn fault_stub_ud();
    #[allow(dead_code)]
    fn fault_stub_nm();
    #[allow(dead_code)]
    fn fault_stub_ts();
    #[allow(dead_code)]
    fn fault_stub_np();
    #[allow(dead_code)]
    fn fault_stub_ss();
    #[allow(dead_code)]
    fn fault_stub_gp();
    #[allow(dead_code)]
    fn fault_stub_pf();
    #[allow(dead_code)]
    fn fault_stub_mf();
    #[allow(dead_code)]
    fn fault_stub_ac();
    #[allow(dead_code)]
    fn fault_stub_xm();
    #[allow(dead_code)]
    fn fault_stub_cp();
}

/// Address of the asm stubs, for IDT wiring via set_handler_addr.
/// (Called only from Rust; the stubs themselves are entered by the CPU.)
pub fn stub_addr_timer() -> u64 {
    trap_stub_timer as *const () as usize as u64
}

pub fn stub_addr_syscall() -> u64 {
    trap_stub_syscall as *const () as usize as u64
}

/// Address of a recoverable CPU-exception stub.
pub fn fault_stub_addr(vector: u8) -> u64 {
    let f: unsafe extern "sysv64" fn() = match vector {
        0 => fault_stub_de,
        3 => fault_stub_bp,
        4 => fault_stub_of,
        5 => fault_stub_br,
        6 => fault_stub_ud,
        7 => fault_stub_nm,
        10 => fault_stub_ts,
        11 => fault_stub_np,
        12 => fault_stub_ss,
        13 => fault_stub_gp,
        14 => fault_stub_pf,
        16 => fault_stub_mf,
        17 => fault_stub_ac,
        19 => fault_stub_xm,
        21 => fault_stub_cp,
        _ => panic!("no fault stub for vector {vector}"),
    };
    f as *const () as usize as u64
}
