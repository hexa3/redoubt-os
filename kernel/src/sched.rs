//! Cooperative round-robin scheduler with timer preemption at return-to-user.
//!
//! The kernel runs with interrupts disabled; scheduling decisions happen
//! exclusively in trap context (syscall entry, timer tick while a user task
//! was running). Every not-running task keeps its full TrapFrame at the top
//! of its kernel stack; switching = swap CR3 + TSS.RSP0 + RSP.

use alloc::collections::VecDeque;
use core::arch::asm;
use core::sync::atomic::{AtomicBool, Ordering};

use x86_64::VirtAddr;

use crate::gdt;
use crate::interrupts::{self, PICS};
use crate::kprintln;
use crate::syscall;
use crate::task::{self, TaskState};
use crate::trap;
use crate::trap::TrapFrame;

static CURRENT: spin::Mutex<Option<usize>> = spin::Mutex::new(None);
static READY: spin::Mutex<VecDeque<usize>> = spin::Mutex::new(VecDeque::new());
/// Emit the idle task table once at boot. Repeating it for every interactive
/// key would pollute both the framebuffer and serial shell transcript.
static IDLE_REPORTED: AtomicBool = AtomicBool::new(false);

const QUANTUM_TICKS: u64 = 20; // 200ms at 100Hz

pub fn current() -> Option<usize> {
    *CURRENT.lock()
}

pub fn set_current(id: Option<usize>) {
    *CURRENT.lock() = id;
}

pub fn make_ready(tid: usize, front: bool) {
    let mut q = READY.lock();
    if front {
        q.push_front(tid);
    } else {
        q.push_back(tid);
    }
}

/// Pick the next Ready task (round-robin). Does not change CPU state.
pub fn pick_next(exclude: Option<usize>) -> Option<usize> {
    let mut q = READY.lock();
    // skip zombies / blocked entries that ended up here defensively
    let mut skipped: VecDeque<usize> = VecDeque::new();
    while let Some(tid) = q.pop_front() {
        let ok = task::with_tasks(|ts| {
            ts.iter()
                .any(|t| t.id == tid && t.state == TaskState::Ready)
        });
        if Some(tid) != exclude && ok {
            for s in skipped.drain(..) {
                q.push_back(s);
            }
            return Some(tid);
        }
        skipped.push_back(tid);
    }
    None
}

fn load_cr3(cr3: x86_64::PhysAddr) {
    unsafe { asm!("mov cr3, {}", in(reg) cr3.as_u64(), options(nostack)) };
}

pub fn set_tss_rsp0(top: VirtAddr) {
    let addr = gdt::tss_addr();
    assert!(addr != 0, "TSS missing");
    unsafe {
        let tss = &mut *(addr as *mut x86_64::structures::tss::TaskStateSegment);
        tss.privilege_stack_table[0] = top;
    }
}

/// Make `tid` runnable on this CPU: address space, TSS.RSP0, saved frame.
/// Returns the kernel RSP to resume from.
pub unsafe fn resume(tid: usize) -> u64 {
    let (cr3, rsp, ktop) = task::with_tasks(|ts| {
        let t = ts
            .iter_mut()
            .find(|t| t.id == tid)
            .expect("resumed task vanished");
        t.state = TaskState::Running;
        (t.cr3, t.saved_rsp, t.kstack_top.as_u64())
    });
    set_current(Some(tid));
    load_cr3(cr3);
    set_tss_rsp0(VirtAddr::new(ktop));
    rsp
}

/// Called from trap asm. Returns pointer of the TrapFrame to iretq through
/// (may belong to a different task than the one that trapped).
#[no_mangle]
pub unsafe extern "sysv64" fn handle_trap(
    frame_ptr: *mut TrapFrame,
    vector: u64,
) -> *mut TrapFrame {
    do_handle_trap(frame_ptr, vector)
}

unsafe fn do_handle_trap(frame_ptr: *mut TrapFrame, vector: u64) -> *mut TrapFrame {
    // Reap queued corpses first: we are executing on a live task's kernel
    // stack, so teardown of dead tasks' stacks is safe here and only here.
    task::drain_reaper();
    match vector {
        trap::VECTOR_TIMER => {
            // we only ever take the timer in user mode; eoi + preempt
            unsafe { PICS.lock().notify_end_of_interrupt(interrupts::TIMER_IRQ) };
            interrupts::bump_tick();
            wake_expired();
            maybe_preempt(frame_ptr)
        }
        trap::VECTOR_SYSCALL => syscall::dispatch(frame_ptr),
        other => {
            kprintln!("[redoubt] unexpected vector {other}");
            frame_ptr
        }
    }
}

/// Wake every bounded wait whose deadline has passed (recv deadlines,
/// sleeps). Runs at each timer boundary, which is the only place scheduler
/// decisions happen in this kernel. Woken callers see E_TIMEDOUT in rax.
fn wake_expired() {
    let now = interrupts::ticks();
    let mut woke: alloc::vec::Vec<usize> = alloc::vec::Vec::new();
    task::with_tasks(|ts| {
        for t in ts.iter_mut() {
            let expired = match t.state {
                TaskState::BlockedRecv { deadline, .. } => deadline != 0 && now >= deadline,
                TaskState::BlockedSleep { until } => now >= until,
                _ => false,
            };
            if expired {
                if matches!(t.state, TaskState::BlockedRecv { .. }) {
                    unsafe { (*(t.saved_rsp as *mut TrapFrame)).rax = syscall::E_TIMEDOUT };
                } else {
                    unsafe { (*(t.saved_rsp as *mut TrapFrame)).rax = syscall::E_OK };
                }
                t.state = TaskState::Ready;
                woke.push(t.id);
            }
        }
    });
    for tid in woke {
        make_ready(tid, true);
    }
}

fn maybe_preempt(frame_ptr: *mut TrapFrame) -> *mut TrapFrame {
    static SINCE_SWITCH: spin::Mutex<u64> = spin::Mutex::new(0);
    let mut since = SINCE_SWITCH.lock();
    *since += 1;
    if *since < QUANTUM_TICKS {
        return frame_ptr;
    }
    *since = 0;
    drop(since);

    let cur = current();
    let next = pick_next(cur);
    match (cur, next) {
        // An IRQ (for example keyboard input) may wake a task while the
        // CPU is parked in the idle loop. The next timer tick is our safe
        // trap boundary to leave the ring-0 idle frame and resume that task.
        (None, Some(next_id)) => unsafe { resume(next_id) as *mut TrapFrame },
        (None, None) => frame_ptr,
        (Some(_), None) => frame_ptr,
        (Some(cur), Some(next_id)) => {
            task::with_tasks(|ts| {
                let t = ts
                    .iter_mut()
                    .find(|t| t.id == cur)
                    .expect("current vanished");
                debug_assert!(t.state == TaskState::Running);
                t.saved_rsp = frame_ptr as u64;
                t.state = TaskState::Ready;
            });
            make_ready(cur, false);
            unsafe { resume(next_id) as *mut TrapFrame }
        }
    }
}

/// Park the current task permanently (blocking path found no runnable peer).
/// Keeps interrupts alive so the PIT still ticks and any future wakeup
/// path can observe time. Dumps the task table once for diagnostics.
pub fn park_idle() -> ! {
    if !IDLE_REPORTED.swap(true, Ordering::Relaxed) {
        let ticks = interrupts::ticks();
        kprintln!("[redoubt] no runnable tasks; idle (uptime {ticks} ticks). task table:");
        task::with_tasks(|ts| {
            for t in ts.iter() {
                kprintln!("[redoubt]   tid {:>2}  {:<8}  {:?}", t.id, t.name, t.state);
            }
        });
        let (used, total) = crate::frame::stats();
        kprintln!("[redoubt] frames held {used}/{total}");
    }
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    // Leave the dying task's address space AND its kernel stack before
    // anything reclaims them: the caller may be a just-exited task whose
    // stack the reaper frees at the very next trap. Switch CR3 to the
    // kernel space, move RSP onto the dedicated idle stack, point RSP0
    // there too (for any future ring-3 transition), then enable interrupts
    // and sleep. park_idle never returns, so abandoning the old stack is
    // safe.
    crate::paging::activate_kernel_space();
    set_tss_rsp0(task::idle_stack_top());
    let top = task::idle_stack_top().as_u64();
    unsafe {
        asm!(
            "mov rsp, {top}",
            "xor ebp, ebp",
            "sti",
            "2: hlt",
            "jmp 2b",
            top = in(reg) top,
            options(noreturn)
        );
    }
}

/// Initial entry from kernel_main: never returns.
pub fn kickoff() -> ! {
    match pick_next(None) {
        Some(tid) => {
            kprintln!("[redoubt] scheduler kickoff -> tid {tid}");
            unsafe {
                let rsp = resume(tid);
                asm!(
                    "mov rsp, {rsp}",
                    "pop r15", "pop r14", "pop r13", "pop r12",
                    "pop r11", "pop r10", "pop r9", "pop r8",
                    "pop rdi", "pop rsi", "pop rbp", "pop rbx",
                    "pop rdx", "pop rcx", "pop rax",
                    "iretq",
                    rsp = in(reg) rsp,
                    options(noreturn)
                );
            }
        }
        None => park_idle(),
    }
}
