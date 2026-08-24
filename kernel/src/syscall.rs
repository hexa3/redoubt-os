//! System call dispatch. Every capability check happens here, in the kernel.
//!
//! Contract with trap.rs: dispatch receives the trapped task's full
//! TrapFrame and returns the TrapFrame that should be resumed by iretq —
//! usually the same one, sometimes another task's after a context switch,
//! and blocking calls simply never return for the invoking invocation.

use alloc::collections::VecDeque;

use crate::caps::{self, Cap};
use crate::kprintln;
use crate::paging;
use crate::sched;
use crate::task::{self, TaskState};
use crate::trap::TrapFrame;

pub mod num {
    pub const YIELD: u64 = 1;
    pub const EXIT: u64 = 2;
    pub const DEBUG_WRITE: u64 = 3;
    pub const IPC_CALL: u64 = 4;
    pub const IPC_RECV: u64 = 5;
    pub const IPC_REPLY: u64 = 6;
    pub const CAP_DERIVE: u64 = 7;
    pub const TASK_SPAWN: u64 = 8;
    pub const WAIT: u64 = 9;
    pub const INPUT_READ: u64 = 10;
    pub const TICKS: u64 = 11;
    pub const SET_NAME: u64 = 12;
    pub const STATS: u64 = 13;
    pub const REBOOT: u64 = 14;
    pub const SLEEP: u64 = 15;
    pub const KILL: u64 = 16;
    pub const BLOCK_READ: u64 = 17;
    pub const BLOCK_WRITE: u64 = 18;
}

/// SYS_WAIT flags.
pub const WAIT_NOHANG: u64 = 1;

pub const E_OK: u64 = 0;
pub const E_CAP_MISSING: u64 = 1;
pub const E_CAP_DENIED: u64 = 2;
pub const E_NO_REPLY_WAITING: u64 = 4;
pub const E_BAD_ARG: u64 = 5;
pub const E_NO_CHILDREN: u64 = 6;
/// The receiver handling an IPC call exited before it could reply.
pub const E_PEER_DIED: u64 = 7;
/// The endpoint already has a receiver responsible for an earlier call.
pub const E_ENDPOINT_BUSY: u64 = 8;
/// Nonblocking operation found nothing to do (WAIT_NOHANG).
pub const E_WOULD_BLOCK: u64 = 9;
/// A bounded wait (recv deadline / sleep) elapsed.
pub const E_TIMEDOUT: u64 = 10;

const MAX_SPAWN_ELF: usize = 2 * 1024 * 1024;
/// Largest single block transfer a syscall may carry (4 KiB).
const MAX_BLOCK_SECTORS: u16 = 8;

/// One IPC endpoint: synchronous rendezvous with an explicit reply slot.
pub struct Endpoint {
    /// Callers blocked waiting for a receiver, FIFO.
    pub pending_callers: VecDeque<(usize, [u64; 6])>,
    /// The call this server is allowed to answer next.
    pub active_caller: Option<usize>,
    /// Receiver currently responsible for `active_caller`. Tracking this
    /// lets task exit turn a permanently blocked call into a defined error.
    pub active_server: Option<usize>,
}

pub static ENDPOINTS: spin::Mutex<alloc::vec::Vec<Endpoint>> =
    spin::Mutex::new(alloc::vec::Vec::new());

pub fn create_endpoint(name: &'static str) -> u64 {
    let mut eps = ENDPOINTS.lock();
    eps.push(Endpoint {
        pending_callers: VecDeque::new(),
        active_caller: None,
        active_server: None,
    });
    let id = (eps.len() - 1) as u64;
    kprintln!("[redoubt] endpoint '{name}' = #{id}");
    id
}

/// Syscall ABI (int 0x80): number in rax, args in rdi,rsi,rdx,r10,r8,r9,
/// result in rax.
struct Args([u64; 6]);

fn args_of(f: &TrapFrame) -> Args {
    Args([f.rdi, f.rsi, f.rdx, f.r10, f.r8, f.r9])
}

pub fn dispatch(frame_ptr: *mut TrapFrame) -> *mut TrapFrame {
    let frame = unsafe { &mut *frame_ptr };
    let tid = match sched::current() {
        Some(t) => t,
        None => {
            kprintln!("[redoubt] BUG: syscall with no current task");
            return frame_ptr;
        }
    };
    let num = frame.rax;
    let Args(a) = args_of(frame);

    match num {
        num::YIELD => yield_task(tid, frame_ptr),
        num::EXIT => exit_task(tid, a[0]),
        num::DEBUG_WRITE => {
            sys_debug_write(frame, tid, a[0], a[1], a[2]);
            frame_ptr
        }
        num::IPC_CALL => ipc_call(tid, frame_ptr, a),
        num::IPC_RECV => ipc_recv(tid, frame_ptr, a[0], a[1]),
        num::IPC_REPLY => ipc_reply(tid, frame_ptr, a),
        num::CAP_DERIVE => {
            sys_cap_derive(frame, tid, a);
            frame_ptr
        }
        num::TASK_SPAWN => {
            sys_task_spawn(frame, tid, a);
            frame_ptr
        }
        num::WAIT => sys_wait(tid, frame_ptr, a[0]),
        num::INPUT_READ => sys_input_read(tid, frame_ptr, a),
        num::TICKS => {
            frame.rax = crate::interrupts::ticks();
            frame_ptr
        }
        num::SET_NAME => {
            sys_set_name(frame, tid, a[0], a[1] as usize);
            frame_ptr
        }
        num::STATS => {
            sys_stats(frame, tid, a[0], a[1] as usize);
            frame_ptr
        }
        num::REBOOT => {
            kprintln!("[redoubt] tid {tid} requested reboot");
            crate::ata::machine_reboot()
        }
        num::SLEEP => sys_sleep(tid, frame_ptr, a[0]),
        num::KILL => sys_kill(frame_ptr, tid, a[0]),
        num::BLOCK_READ => block_io(frame_ptr, tid, a, false),
        num::BLOCK_WRITE => block_io(frame_ptr, tid, a, true),
        other => {
            kprintln!("[redoubt] tid {tid}: unknown syscall {other:#x}");
            frame.rax = u64::MAX;
            frame_ptr
        }
    }
}

/// Entry point for CPU exceptions taken from ring 3. The trap stub supplies
/// a normal TrapFrame (discarding a hardware error word when present), so we
/// can use the same lifecycle path as SYS_EXIT. A kernel-origin fault is not
/// recoverable: continuing risks corrupting every service, so report it and
/// halt instead.
#[no_mangle]
pub unsafe extern "sysv64" fn handle_user_fault(
    frame_ptr: *mut TrapFrame,
    vector: u64,
) -> *mut TrapFrame {
    let frame = &*frame_ptr;
    if frame.cs & 3 != 3 {
        kprintln!(
            "[redoubt] FATAL kernel exception #{vector} at {:#x}",
            frame.rip
        );
        loop {
            x86_64::instructions::hlt();
        }
    }

    let Some(tid) = sched::current() else {
        kprintln!("[redoubt] FATAL user exception #{vector} without current task");
        loop {
            x86_64::instructions::hlt();
        }
    };
    kprintln!(
        "[redoubt] tid {tid} faulted: exception #{vector} at {:#x}; terminating",
        frame.rip
    );
    // Keep fault exits distinct from ordinary application status codes.
    exit_task(tid, 0x100 + vector)
}

// ------------------------------------------------------------------ helpers

fn current_cr3() -> x86_64::PhysAddr {
    x86_64::registers::control::Cr3::read().0.start_address()
}

fn kprint_raw(s: &str) {
    crate::console::write_str(s);
}

/// Read user memory through the trapping task's own page tables.
fn copy_from_user(cr3: x86_64::PhysAddr, src: u64, len: usize) -> Option<alloc::vec::Vec<u8>> {
    // The shared kernel mappings are reachable through `translate`; reject
    // them before walking page tables so a forged pointer cannot turn a
    // syscall such as debug_write or task_spawn into a kernel-memory read.
    if !task::user_range_valid(src, len) {
        return None;
    }
    let mut out = alloc::vec::Vec::with_capacity(len);
    for i in 0..len {
        let va = x86_64::VirtAddr::new(src + i as u64);
        let pa = paging::translate(cr3, va)?;
        let p = paging::phys_to_virt(pa).as_u64() as *const u8;
        out.push(unsafe { p.read() });
    }
    Some(out)
}

/// Write kernel bytes into user memory with the same fence as
/// `copy_from_user`: the complete destination range must lie in user space
/// AND be mapped before anything is written.
fn copy_to_user(cr3: x86_64::PhysAddr, dst: u64, src: &[u8]) -> bool {
    if !task::user_range_valid(dst, src.len()) {
        return false;
    }
    for (i, b) in src.iter().enumerate() {
        let va = x86_64::VirtAddr::new(dst + i as u64);
        let Some(pa) = paging::translate(cr3, va) else {
            return false;
        };
        unsafe { (paging::phys_to_virt(pa).as_u64() as *mut u8).write(*b) };
    }
    true
}

/// SYS_DEBUG_WRITE(buf, len, raw): print bytes to the kernel console.
/// Default output is attributed ("[tid N] " prefix); raw=1 suppresses the
/// prefix for interactive clients (the console server speaking for a
/// human's session).
fn sys_debug_write(frame: &mut TrapFrame, tid: usize, buf: u64, len: u64, raw: u64) {
    let len = (len as usize).min(512);
    match copy_from_user(current_cr3(), buf, len) {
        Some(bytes) => {
            if raw == 0 {
                kprint_raw("[tid ");
                kprint_raw(&itoa_small(tid));
                kprint_raw("] ");
            }
            let text = core::str::from_utf8(&bytes).unwrap_or("<binary>\n");
            kprint_raw(text);
            if !text.ends_with('\n') && raw == 0 {
                kprint_raw("\n");
            }
            frame.rax = E_OK;
        }
        None => {
            frame.rax = E_CAP_MISSING;
        }
    }
}

fn itoa_small(mut v: usize) -> alloc::string::String {
    if v == 0 {
        return "0".into();
    }
    let mut digits = alloc::vec::Vec::new();
    while v > 0 {
        digits.push(b'0' + (v % 10) as u8);
        v /= 10;
    }
    digits.reverse();
    alloc::string::String::from_utf8(digits).unwrap()
}

// ------------------------------------------------------- yield / exit

fn yield_task(tid: usize, frame_ptr: *mut TrapFrame) -> *mut TrapFrame {
    // Only queue ourselves if someone else can run; otherwise stay Running
    // without touching the ready queue (pushing anyway would grow a
    // duplicate entry on every yield).
    let next = sched::pick_next(Some(tid));
    let next = match next {
        Some(n) => n,
        None => return frame_ptr, // sole runnable task: keep the CPU
    };
    task::with_tasks(|ts| {
        let t = ts
            .iter_mut()
            .find(|t| t.id == tid)
            .expect("current vanished");
        debug_assert!(t.state == TaskState::Running);
        t.saved_rsp = frame_ptr as u64;
        t.state = TaskState::Ready;
    });
    sched::make_ready(tid, false);
    unsafe { sched::resume(next) as *mut TrapFrame }
}

/// The full task-termination lifecycle minus the CPU handoff: zombie
/// marking, orphaning, exit-code delivery, IPC unwinding. Safe for any
/// NON-RUNNING task: it touches only the victim's saved state, never the
/// CPU. Self-exit adds the handoff via `exit_task` below.
fn terminate_lifecycle(tid: usize, code: u64) {
    // 1. become zombie; find our parent and any children.
    enum Fate {
        /// Parent alive and waiting: deliver code, then reap ourselves.
        Deliver(usize),
        /// Parent alive, not waiting yet: stay a readable zombie.
        Linger,
        /// No living parent (or kernel-spawned): nobody can wait on us.
        Orphan,
    }
    // `schedule_reap` also takes the task-table lock, so collect orphaned
    // zombie children while holding it and enqueue their teardown only
    // after releasing it. Reaping inside this closure would deadlock
    // whenever a parent exited after one of its children.
    let (fate, orphaned_zombies) = task::with_tasks(|ts| {
        let me = match ts.iter_mut().find(|t| t.id == tid) {
            Some(t) => t,
            None => return (Fate::Orphan, alloc::vec::Vec::new()),
        };
        me.state = TaskState::Zombie { code };
        let parent = me.parent;
        // orphan the children first: a dead parent means no one can ever
        // wait on them, so already-dead ones are reaped straight away and
        // live ones will self-orphan at their own exit.
        let kids: alloc::vec::Vec<usize> = ts
            .iter()
            .filter(|t| t.parent == Some(tid))
            .map(|t| t.id)
            .collect();
        let mut orphaned_zombies = alloc::vec::Vec::new();
        for kid in kids {
            if let Some(k) = ts.iter_mut().find(|t| t.id == kid) {
                k.parent = None;
                if matches!(k.state, TaskState::Zombie { .. }) {
                    orphaned_zombies.push(kid);
                }
            }
        }
        let fate = match parent {
            Some(pid) => match ts.iter().find(|t| t.id == pid) {
                Some(p) => match p.state {
                    TaskState::BlockedWait => Fate::Deliver(pid),
                    _ => Fate::Linger,
                },
                None => Fate::Orphan,
            },
            None => Fate::Orphan,
        };
        (fate, orphaned_zombies)
    });

    for zombie in orphaned_zombies {
        task::schedule_reap(zombie);
    }

    // A service may fault or exit after accepting an IPC request. Do this
    // before selecting another task so no caller remains parked forever on
    // a reply that can no longer arrive.
    abort_ipc_for_exiting_task(tid);

    match fate {
        Fate::Deliver(pid) => {
            // hand the exit code to the blocked parent before anything else
            task::with_tasks(|ts| {
                let p = ts
                    .iter_mut()
                    .find(|t| t.id == pid)
                    .expect("parent vanished");
                let pf = p.saved_rsp as *mut TrapFrame;
                unsafe {
                    (*pf).rax = E_OK;
                    (*pf).rdi = tid as u64;
                    (*pf).rsi = code;
                }
                p.state = TaskState::Ready;
            });
            sched::make_ready(pid, true);
            task::schedule_reap(tid);
            kprintln!("[redoubt] tid {tid} exited (code={code:#x}) -> delivered to tid {pid}");
        }
        Fate::Linger => {
            kprintln!("[redoubt] tid {tid} exited (code={code:#x}), awaiting wait()");
        }
        Fate::Orphan => {
            task::schedule_reap(tid);
            kprintln!("[redoubt] tid {tid} exited (code={code:#x}), reaped");
        }
    }
}

/// Exit path for the CURRENT task: run the lifecycle, then hand the CPU
/// to whoever is next. The corpse stays queued until its stack can be
/// torn down safely (next trap boundary). Never returns normally: the
/// returned "frame pointer" is the next task's kernel RSP, per the trap
/// stub contract.
fn exit_task(tid: usize, code: u64) -> *mut TrapFrame {
    terminate_lifecycle(tid, code);
    sched::set_current(None);
    match sched::pick_next(None) {
        Some(next) => unsafe { sched::resume(next) as *mut TrapFrame },
        None => sched::park_idle(),
    }
}

/// Remove an exiting task from all IPC bookkeeping. Calls assigned to a
/// dying receiver are failed explicitly; calls made by a dying task are
/// discarded so a later reply cannot dereference a reclaimed TrapFrame.
fn abort_ipc_for_exiting_task(tid: usize) {
    let mut stranded = alloc::vec::Vec::new();
    {
        let mut endpoints = ENDPOINTS.lock();
        for endpoint in endpoints.iter_mut() {
            endpoint
                .pending_callers
                .retain(|(caller, _)| *caller != tid);
            if endpoint.active_caller == Some(tid) {
                endpoint.active_caller = None;
                endpoint.active_server = None;
            }
            if endpoint.active_server == Some(tid) {
                if let Some(caller) = endpoint.active_caller.take() {
                    stranded.push(caller);
                }
                endpoint.active_server = None;
            }
        }
    }

    for caller in stranded {
        let woke = task::with_tasks(|tasks| {
            let Some(task) = tasks.iter_mut().find(|task| task.id == caller) else {
                return false;
            };
            if !matches!(task.state, TaskState::BlockedCall { .. }) {
                return false;
            }
            unsafe { (*(task.saved_rsp as *mut TrapFrame)).rax = E_PEER_DIED };
            task.state = TaskState::Ready;
            true
        });
        if woke {
            sched::make_ready(caller, true);
            kprintln!("[redoubt] tid {caller}: IPC peer {tid} exited before reply");
        }
    }
}

/// sys_input_read(buf, len): consume decoded keyboard bytes.
///   data available -> rax=count, bytes written into the caller's buffer
///   queue empty    -> caller parks; interrupt context fills its frame
///                     (rax=count) and marks it Ready when a key arrives
///                    (unless flags bit0 = NOHANG: rax=E_WOULD_BLOCK)
///   bad args       -> rax=E_BAD_ARG
pub const INPUT_NOHANG: u64 = 1;

fn sys_input_read(tid: usize, frame_ptr: *mut TrapFrame, a: [u64; 6]) -> *mut TrapFrame {
    const MAX_READ: usize = 512;
    let buf = a[0];
    let len = (a[1] as usize).min(MAX_READ);
    let flags = a[2];
    let cr3 = task::with_tasks(|ts| ts.iter().find(|t| t.id == tid).map(|t| t.cr3));
    let Some(cr3) = cr3 else {
        let f = unsafe { &mut *frame_ptr };
        f.rax = E_BAD_ARG;
        return frame_ptr;
    };

    // Park if the queue is empty: request_read registers us as a waiter
    // and returns Parked without copying anything.
    if flags & INPUT_NOHANG != 0 {
        match crate::input::try_read(cr3, buf, len) {
            Some(n) => {
                let f = unsafe { &mut *frame_ptr };
                f.rax = n as u64;
            }
            None => {
                let f = unsafe { &mut *frame_ptr };
                f.rax = E_WOULD_BLOCK;
            }
        }
        return frame_ptr;
    }
    match crate::input::request_read(tid, cr3, buf, len) {
        crate::input::ReadOutcome::Served(n) => {
            let f = unsafe { &mut *frame_ptr };
            f.rax = n as u64;
            frame_ptr
        }
        crate::input::ReadOutcome::Parked => {
            task::with_tasks(|ts| {
                let t = ts.iter_mut().find(|t| t.id == tid).unwrap();
                t.saved_rsp = frame_ptr as u64;
                t.state = TaskState::BlockedInput;
            });
            sched::set_current(None);
            match sched::pick_next(None) {
                Some(next) => unsafe { sched::resume(next) as *mut TrapFrame },
                None => sched::park_idle(),
            }
        }
        crate::input::ReadOutcome::BadArgs => {
            let f = unsafe { &mut *frame_ptr };
            f.rax = E_BAD_ARG;
            frame_ptr
        }
    }
}

/// sys_wait(flags): block until a child exits; returns (child_tid, code).
///   flags & WAIT_NOHANG -> return E_WOULD_BLOCK instead of parking
///   success             -> rax=E_OK, rdi=tid, rsi=code
///   no children at all  -> rax=E_NO_CHILDREN
fn sys_wait(tid: usize, frame_ptr: *mut TrapFrame, flags: u64) -> *mut TrapFrame {
    // already-exited child? reap it inline right now.
    let zombie = task::with_tasks(|ts| {
        ts.iter()
            .filter(|t| t.parent == Some(tid))
            .find(|t| matches!(t.state, TaskState::Zombie { .. }))
            .map(|t| t.id)
    });
    if let Some(zid) = zombie {
        let code = task::reap_zombie(zid).unwrap_or(0);
        let f = unsafe { &mut *frame_ptr };
        f.rax = E_OK;
        f.rdi = zid as u64;
        f.rsi = code;
        return frame_ptr;
    }

    // living children? block until one exits.
    let has_living = task::with_tasks(|ts| {
        ts.iter()
            .any(|t| t.parent == Some(tid) && !matches!(t.state, TaskState::Zombie { .. }))
    });
    if !has_living {
        let f = unsafe { &mut *frame_ptr };
        f.rax = E_NO_CHILDREN;
        return frame_ptr;
    }
    if flags & WAIT_NOHANG != 0 {
        let f = unsafe { &mut *frame_ptr };
        f.rax = E_WOULD_BLOCK;
        return frame_ptr;
    }

    task::with_tasks(|ts| {
        let t = ts.iter_mut().find(|t| t.id == tid).unwrap();
        t.saved_rsp = frame_ptr as u64;
        t.state = TaskState::BlockedWait;
    });
    sched::set_current(None);
    match sched::pick_next(None) {
        Some(next) => unsafe { sched::resume(next) as *mut TrapFrame },
        None => sched::park_idle(),
    }
}

// ------------------------------------------------------------------- IPC

/// Validate that `slot` holds an Endpoint cap carrying `need` rights.
fn get_endpoint_cap(tid: usize, slot: u64, need: u64) -> Result<u64, u64> {
    let ep = task::with_tasks(|ts| {
        let t = ts.iter_mut().find(|t| t.id == tid)?;
        match t.caps.get(slot as usize) {
            Some(Some(Cap::Endpoint { endpoint, rights })) if rights & need == need => {
                Some(*endpoint)
            }
            Some(Some(Cap::Endpoint { .. })) => None, // wrong rights, distinguish below
            Some(None) | None => None,
            _ => None,
        }
    });
    // second pass distinguishes missing vs denied
    let state = task::with_tasks(|ts| {
        let t = ts.iter_mut().find(|t| t.id == tid)?;
        match t.caps.get(slot as usize) {
            None | Some(None) => Some(E_CAP_MISSING),
            Some(Some(Cap::Endpoint { rights, .. })) if rights & need != need => Some(E_CAP_DENIED),
            _ => None,
        }
    });
    match (state, ep) {
        (Some(err), _) => Err(err),
        (None, Some(ep)) => Ok(ep),
        (None, None) => Err(E_CAP_DENIED),
    }
}

fn ipc_call(tid: usize, frame_ptr: *mut TrapFrame, a: [u64; 6]) -> *mut TrapFrame {
    let ep_slot = a[0];
    let msg = [a[1], a[2], a[3], a[4], a[5], 0];
    let ep_idx = match get_endpoint_cap(tid, ep_slot, caps::R_WRITE) {
        Ok(e) => e as usize,
        Err(e) => {
            let f = unsafe { &mut *frame_ptr };
            f.rax = e;
            return frame_ptr;
        }
    };

    // stash frame before possibly switching away
    task::with_tasks(|ts| {
        let t = ts.iter_mut().find(|t| t.id == tid).unwrap();
        t.saved_rsp = frame_ptr as u64;
    });

    let receiver_tid = {
        let mut eps = ENDPOINTS.lock();
        let ep = &mut eps[ep_idx];
        let mut receiver_tid = None;
        // find a receiver blocked on this endpoint
        task::with_tasks(|ts| {
            if let Some(w) = ts
                .iter_mut()
                .find(|t| matches!(t.state, TaskState::BlockedRecv { endpoint, .. } if endpoint == ep_idx as u64))
            {
                let wid = w.id;
                let wframe = w.saved_rsp as *mut TrapFrame;
                unsafe {
                    (*wframe).rax = E_OK;
                    (*wframe).rdi = tid as u64;
                    (*wframe).rsi = msg[0];
                    (*wframe).rdx = msg[1];
                    (*wframe).r10 = msg[2];
                    (*wframe).r8 = msg[3];
                    (*wframe).r9 = msg[4];
                }
                w.state = TaskState::Ready;
                sched::make_ready(wid, true);
                receiver_tid = Some(wid);
            }
        });
        if let Some(receiver) = receiver_tid {
            ep.active_caller = Some(tid);
            ep.active_server = Some(receiver);
        } else {
            ep.pending_callers.push_back((tid, msg));
        }
        receiver_tid
    };

    task::with_tasks(|ts| {
        let t = ts.iter_mut().find(|t| t.id == tid).unwrap();
        t.state = if receiver_tid.is_some() {
            TaskState::BlockedCall {
                endpoint: ep_idx as u64,
            } // awaiting reply
        } else {
            TaskState::BlockedSend {
                endpoint: ep_idx as u64,
            }
        };
    });
    sched::set_current(None);

    match sched::pick_next(None) {
        Some(next) => unsafe { sched::resume(next) as *mut TrapFrame },
        None => sched::park_idle(),
    }
}

fn ipc_recv(tid: usize, frame_ptr: *mut TrapFrame, ep_slot: u64, deadline: u64) -> *mut TrapFrame {
    let ep_idx = match get_endpoint_cap(tid, ep_slot, caps::R_READ) {
        Ok(e) => e as usize,
        Err(e) => {
            let f = unsafe { &mut *frame_ptr };
            f.rax = e;
            return frame_ptr;
        }
    };

    let delivered = {
        let mut eps = ENDPOINTS.lock();
        // This endpoint intentionally has one reply slot. Letting a receiver
        // call recv again before replying would overwrite active_caller and
        // strand the first caller forever; reject the protocol violation.
        if eps[ep_idx].active_caller.is_some() {
            let frame = unsafe { &mut *frame_ptr };
            frame.rax = E_ENDPOINT_BUSY;
            return frame_ptr;
        }
        match eps[ep_idx].pending_callers.pop_front() {
            Some((caller_tid, msg)) => {
                eps[ep_idx].active_caller = Some(caller_tid);
                eps[ep_idx].active_server = Some(tid);
                // The caller was parked before a receiver existed.  It is
                // now waiting only for this receiver's explicit reply.
                task::with_tasks(|ts| {
                    if let Some(caller) = ts.iter_mut().find(|t| t.id == caller_tid) {
                        caller.state = TaskState::BlockedCall {
                            endpoint: ep_idx as u64,
                        };
                    }
                });
                let f = unsafe { &mut *frame_ptr };
                f.rax = E_OK;
                f.rdi = caller_tid as u64;
                f.rsi = msg[0];
                f.rdx = msg[1];
                f.r10 = msg[2];
                f.r8 = msg[3];
                f.r9 = msg[4];
                true
            }
            None => false,
        }
    };
    if delivered {
        return frame_ptr;
    }

    // A caller using a deadline at or before the current tick is polling:
    // do not park it until the next timer interrupt just to discover that no
    // message is available. This preserves deadline semantics while making
    // multiplexed servers able to service high-throughput streams fairly.
    if deadline != 0 && deadline <= crate::interrupts::ticks() {
        let frame = unsafe { &mut *frame_ptr };
        frame.rax = E_TIMEDOUT;
        return frame_ptr;
    }

    // block until someone calls (or the optional deadline elapses)
    task::with_tasks(|ts| {
        let t = ts.iter_mut().find(|t| t.id == tid).unwrap();
        t.saved_rsp = frame_ptr as u64;
        t.state = TaskState::BlockedRecv {
            endpoint: ep_idx as u64,
            deadline,
        };
    });
    sched::set_current(None);
    match sched::pick_next(None) {
        Some(next) => unsafe { sched::resume(next) as *mut TrapFrame },
        None => sched::park_idle(),
    }
}

fn ipc_reply(tid: usize, frame_ptr: *mut TrapFrame, a: [u64; 6]) -> *mut TrapFrame {
    let ep_slot = a[0];
    let reply = [a[1], a[2], a[3], a[4], a[5]];
    let ep_idx = match get_endpoint_cap(tid, ep_slot, caps::R_WRITE) {
        Ok(e) => e as usize,
        Err(e) => {
            let f = unsafe { &mut *frame_ptr };
            f.rax = e;
            return frame_ptr;
        }
    };

    let caller = {
        let mut endpoints = ENDPOINTS.lock();
        let endpoint = &mut endpoints[ep_idx];
        if endpoint.active_server != Some(tid) {
            None
        } else {
            endpoint.active_server = None;
            endpoint.active_caller.take()
        }
    };
    match caller {
        Some(cid) => {
            task::with_tasks(|ts| {
                let ct = ts
                    .iter_mut()
                    .find(|t| t.id == cid)
                    .expect("caller vanished");
                let cf = ct.saved_rsp as *mut TrapFrame;
                unsafe {
                    (*cf).rax = E_OK;
                    (*cf).rdi = reply[0];
                    (*cf).rsi = reply[1];
                    (*cf).rdx = reply[2];
                    (*cf).r10 = reply[3];
                    (*cf).r8 = reply[4];
                }
                ct.state = TaskState::Ready;
            });
            sched::make_ready(cid, true);
            let f = unsafe { &mut *frame_ptr };
            f.rax = E_OK;
            frame_ptr
        }
        None => {
            let f = unsafe { &mut *frame_ptr };
            f.rax = E_NO_REPLY_WAITING;
            frame_ptr
        }
    }
}

// ---------------------------------------------------------- capabilities

/// Derive a cap for a CHILD's table from the caller's `src_slot`.
/// Spawn-time transfer keeps the same kernel object (for Block caps, the
/// same LBA range) and intersects only the rights mask — narrowing ranges
/// requires an explicit CAP_DERIVE in the parent's own table first.
/// Same attenuation rules as sys_cap_derive, but returns the object
/// instead of installing it.
fn derive_for_child(tid: usize, src_slot: u64, mask: u64) -> Result<Cap, u64> {
    task::with_tasks(|ts| {
        let t = ts.iter_mut().find(|t| t.id == tid).ok_or(E_CAP_MISSING)?;
        let src = match t.caps.get(src_slot as usize) {
            None | Some(None) => return Err(E_CAP_MISSING),
            Some(Some(c)) => *c,
        };
        if src.rights() & caps::R_GRANT == 0 {
            return Err(E_CAP_DENIED);
        }
        let new_rights = src.rights() & mask;
        if new_rights == 0 {
            return Err(E_CAP_DENIED);
        }
        Ok(match src {
            Cap::Endpoint { endpoint, .. } => Cap::Endpoint {
                endpoint,
                rights: new_rights,
            },
            Cap::Memory {
                base_paddr, pages, ..
            } => Cap::Memory {
                base_paddr,
                pages,
                rights: new_rights,
            },
            Cap::Block {
                disk,
                lba_start,
                lbas,
                ..
            } => Cap::Block {
                disk,
                lba_start,
                lbas,
                rights: new_rights,
            },
        })
    })
}

/// sys_task_spawn(elf_ptr, elf_len, spec_ptr, spec_words):
///
/// Creates a new user task from an ELF image located in the CALLER's
/// address space. `spec` is an array of (src_slot, rights_mask) pairs
/// copied from the caller; each pair must pass grant validation and
/// becomes the child's capability at the same index. This is the only
/// route to process creation — and therefore to privilege transfer —
/// that userspace has.
///
/// success -> rax=E_OK, rdi=child tid; failure -> rax=errno.
fn sys_task_spawn(frame: &mut TrapFrame, tid: usize, a: [u64; 6]) {
    let elf_ptr = a[0];
    let elf_len = a[1] as usize;
    let spec_ptr = a[2];
    let spec_words = a[3] as usize;

    if elf_len == 0 || elf_len > MAX_SPAWN_ELF || spec_words % 2 != 0 {
        frame.rax = E_BAD_ARG;
        return;
    }
    if spec_words / 2 > crate::caps::CAP_TABLE_SIZE {
        frame.rax = E_BAD_ARG;
        return;
    }

    let Some(elf) = copy_from_user(current_cr3(), elf_ptr, elf_len) else {
        frame.rax = E_BAD_ARG;
        return;
    };

    // Empty spec = spawn with zero privileges.
    let mut child_caps: alloc::vec::Vec<Cap> = alloc::vec::Vec::new();
    if spec_words > 0 {
        let Some(spec) = copy_from_user(current_cr3(), spec_ptr, spec_words * 8) else {
            frame.rax = E_BAD_ARG;
            return;
        };
        for pair in spec.chunks_exact(16) {
            let src_slot = u64::from_le_bytes(pair[0..8].try_into().unwrap());
            let mask = u64::from_le_bytes(pair[8..16].try_into().unwrap());
            match derive_for_child(tid, src_slot, mask) {
                Ok(c) => child_caps.push(c),
                Err(e) => {
                    frame.rax = e;
                    return;
                }
            }
        }
    }

    match task::spawn_user(&elf, "user", &child_caps, Some(tid)) {
        Ok(child_tid) => {
            frame.rax = E_OK;
            frame.rdi = child_tid as u64;
        }
        Err(()) => frame.rax = E_BAD_ARG,
    }
}

/// sys_cap_derive(src_slot, mask, [r_lo, r_len]):
///   success -> rax=E_OK, rdi=new slot index
///   failure -> rax=errno
///
/// Status and payload live in different registers so an errno can never be
/// mistaken for a slot index (both are small integers).
///
/// Block caps narrow structurally: the requested `[r_lo, r_lo+r_len)` must
/// intersect the held range; the derived cap covers exactly the
/// intersection. Endpoint/Memory caps ignore the range arguments.
fn sys_cap_derive(frame: &mut TrapFrame, tid: usize, a: [u64; 6]) {
    let src_slot = a[0];
    let mask = a[1];
    let res = task::with_tasks(|ts| {
        let t = match ts.iter_mut().find(|t| t.id == tid) {
            Some(t) => t,
            None => return Err(E_CAP_MISSING),
        };
        let src = match t.caps.get(src_slot as usize) {
            None | Some(None) => return Err(E_CAP_MISSING),
            Some(Some(c)) => *c,
        };
        if src.rights() & caps::R_GRANT == 0 {
            return Err(E_CAP_DENIED);
        }
        let new_rights = src.rights() & mask;
        if new_rights == 0 {
            return Err(E_CAP_DENIED);
        }
        // Range arguments are only meaningful for Block capabilities;
        // rejecting nonzero ranges there keeps kind-probing honest.
        if !matches!(src, Cap::Block { .. }) && (a[2] != 0 || a[3] != 0) {
            return Err(E_BAD_ARG);
        }
        let derived = match src {
            Cap::Endpoint { endpoint, .. } => Cap::Endpoint {
                endpoint,
                rights: new_rights,
            },
            Cap::Memory {
                base_paddr, pages, ..
            } => Cap::Memory {
                base_paddr,
                pages,
                rights: new_rights,
            },
            Cap::Block {
                disk,
                lba_start,
                lbas,
                ..
            } => {
                // requested range intersected with held range
                let req_lo = a[2];
                let req_hi = match req_lo.checked_add(a[3]) {
                    Some(h) => h,
                    None => return Err(E_BAD_ARG),
                };
                let hold_hi = lba_start.saturating_add(lbas);
                let lo = req_lo.max(lba_start);
                let hi = req_hi.min(hold_hi);
                if hi <= lo {
                    // requested range misses the held range entirely
                    return Err(E_CAP_DENIED);
                }
                Cap::Block {
                    disk,
                    lba_start: lo,
                    lbas: hi - lo,
                    rights: new_rights,
                }
            }
        };
        match t.free_cap_slot() {
            Some(slot) => {
                t.caps[slot] = Some(derived);
                Ok(slot as u64)
            }
            None => Err(E_CAP_MISSING),
        }
    });
    match res {
        Ok(slot) => {
            frame.rax = E_OK;
            frame.rdi = slot;
        }
        Err(e) => {
            frame.rax = e;
            frame.rdi = 0;
        }
    }
}

// ------------------------------------------------- observability & control

/// SYS_SET_NAME(buf, len): label this task (bounded, sanitized) so fault
/// reports, task dumps, and supervisor status stay attributable.
fn sys_set_name(frame: &mut TrapFrame, tid: usize, buf: u64, len: usize) {
    const MAX_NAME: usize = 16;
    let len = len.min(MAX_NAME);
    let Some(bytes) = copy_from_user(current_cr3(), buf, len) else {
        frame.rax = E_BAD_ARG;
        return;
    };
    let name = core::str::from_utf8(&bytes).unwrap_or("");
    task::with_tasks(|ts| {
        if let Some(t) = ts.iter_mut().find(|t| t.id == tid) {
            t.set_name(name);
        }
    });
    frame.rax = E_OK;
}

/// SYS_STATS(buf): write a fixed-layout observability record.
#[repr(C)]
struct SysStats {
    magic: u32,
    tick_hz: u32,
    ticks: u64,
    frames_used: u64,
    frames_total: u64,
    my_pages: u64,
    ntasks: u32,
}

fn sys_stats(frame: &mut TrapFrame, tid: usize, buf: u64, len: usize) {
    let need = core::mem::size_of::<SysStats>();
    if len < need {
        frame.rax = E_BAD_ARG;
        return;
    }
    let my_pages = task::with_tasks(|ts| {
        ts.iter()
            .find(|t| t.id == tid)
            .map(|t| t.pages)
            .unwrap_or(0)
    });
    let stats = SysStats {
        magic: 0x4145_4753, // "AEGS"
        tick_hz: 100,
        ticks: crate::interrupts::ticks(),
        frames_used: crate::frame::stats().0,
        frames_total: crate::frame::stats().1,
        my_pages,
        ntasks: task::with_tasks(|ts| ts.len() as u32),
    };
    // serialize through a byte buffer; no unaligned user writes
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&stats as *const SysStats) as *const u8,
            core::mem::size_of::<SysStats>(),
        )
    };
    if copy_to_user(current_cr3(), buf, bytes) {
        frame.rax = E_OK;
    } else {
        frame.rax = E_BAD_ARG;
    }
}

/// SYS_SLEEP(ticks): park until the PIT advances `ticks` times (min 1).
fn sys_sleep(tid: usize, frame_ptr: *mut TrapFrame, delta: u64) -> *mut TrapFrame {
    if delta == 0 || delta > u32::MAX as u64 {
        let f = unsafe { &mut *frame_ptr };
        f.rax = E_BAD_ARG;
        return frame_ptr;
    }
    let until = crate::interrupts::ticks().saturating_add(delta);
    task::with_tasks(|ts| {
        let t = ts.iter_mut().find(|t| t.id == tid).unwrap();
        t.saved_rsp = frame_ptr as u64;
        t.state = TaskState::BlockedSleep { until };
    });
    sched::set_current(None);
    match sched::pick_next(None) {
        Some(next) => unsafe { sched::resume(next) as *mut TrapFrame },
        None => sched::park_idle(),
    }
}

/// SYS_KILL(tid): terminate a child. Enforcement is structural: only the
/// spawner may kill, so no process can signal outside its own subtree.
/// The victim goes through the ordinary exit path (zombie -> wait/reap),
/// including IPC unwinding.
fn sys_kill(frame_ptr: *mut TrapFrame, tid: usize, victim: u64) -> *mut TrapFrame {
    let victim = victim as usize;
    if victim == tid {
        let f = unsafe { &mut *frame_ptr };
        f.rax = E_BAD_ARG;
        return frame_ptr;
    }
    let is_child =
        task::with_tasks(|ts| ts.iter().any(|t| t.id == victim && t.parent == Some(tid)));
    if !is_child {
        let f = unsafe { &mut *frame_ptr };
        f.rax = E_CAP_DENIED;
        return frame_ptr;
    }
    // 0x200 marks a supervisor-initiated stop, distinct from app codes and
    // from fault exits (0x100 + vector). Runs the victim's lifecycle right
    // here on the KILLER's stack: the victim is not executing, so its
    // saved state is ours to mutate. Teardown of the corpse's stack is
    // deferred to the next trap boundary as usual.
    terminate_lifecycle(victim, 0x200);
    let f = unsafe { &mut *frame_ptr };
    f.rax = E_OK;
    frame_ptr
}

// ------------------------------------------------------------ block I/O

/// Validate that `slot` holds a Cap::Block whose range covers
/// `[lba, lba+count)` INTERPRETED RELATIVE to the capability's own base,
/// mirroring how memory capabilities address their granted window. A
/// holder cannot observe or select outside its granted range because all
/// arithmetic happens on kernel-private bounds.
fn check_block_cap(
    tid: usize,
    slot: u64,
    disk: u64,
    lba: u64,
    count: u64,
    need: u64,
) -> Result<(), u64> {
    let state = task::with_tasks(|ts| {
        let Some(t) = ts.iter_mut().find(|t| t.id == tid) else {
            return E_CAP_MISSING;
        };
        match t.caps.get(slot as usize) {
            None | Some(None) => E_CAP_MISSING,
            Some(Some(crate::caps::Cap::Block { .. })) => match t.caps[slot as usize] {
                Some(crate::caps::Cap::Block {
                    disk: d,
                    lba_start: _,
                    lbas,
                    rights,
                }) => {
                    let end = match lba.checked_add(count) {
                        Some(e) => e,
                        None => return E_BAD_ARG,
                    };
                    let covers = d == disk && end <= lbas;
                    if !covers {
                        E_CAP_DENIED
                    } else if rights & need != need {
                        E_CAP_DENIED
                    } else {
                        E_OK
                    }
                }
                _ => unreachable!(),
            },
            _ => E_CAP_DENIED,
        }
    });
    Ok(state).and_then(|s| if s == E_OK { Ok(()) } else { Err(s) })
}

/// SYS_BLOCK_READ/WRITE(cap_slot, rel_lba, count, buf).
fn block_io(frame_ptr: *mut TrapFrame, tid: usize, a: [u64; 6], write: bool) -> *mut TrapFrame {
    let slot = a[0];
    let rel_lba = a[1];
    let count = a[2] as u16;
    let buf = a[3];

    if count == 0 || count > MAX_BLOCK_SECTORS {
        let f = unsafe { &mut *frame_ptr };
        f.rax = E_BAD_ARG;
        return frame_ptr;
    }
    let bytes = count as usize * 512;

    // Which disk does the caller intend? The cap names it; take the disk
    // from the cap itself so a caller cannot probe disks it holds no cap
    // for by varying arguments.
    let cap_located: Option<(u64, u64)> = task::with_tasks(|ts| {
        ts.iter()
            .find(|t| t.id == tid)
            .and_then(|t| match t.caps.get(slot as usize) {
                Some(Some(crate::caps::Cap::Block {
                    disk, lba_start, ..
                })) => Some((*disk, *lba_start)),
                _ => None,
            })
    });
    let Some((disk, cap_base)) = cap_located else {
        let f = unsafe { &mut *frame_ptr };
        f.rax = if task::with_tasks(|ts| {
            matches!(
                ts.iter()
                    .find(|t| t.id == tid)
                    .map(|t| t.caps.get(slot as usize)),
                Some(None) | None
            )
        }) {
            E_CAP_MISSING
        } else {
            E_CAP_DENIED
        };
        return frame_ptr;
    };

    let need = if write { caps::R_WRITE } else { caps::R_READ };
    if let Err(e) = check_block_cap(tid, slot, disk, rel_lba, count as u64, need) {
        let f = unsafe { &mut *frame_ptr };
        f.rax = e;
        return frame_ptr;
    }

    // translate the relative offset to an absolute LBA inside the window
    let lba = match cap_base.checked_add(rel_lba) {
        Some(l) => l,
        None => {
            let f = unsafe { &mut *frame_ptr };
            f.rax = E_BAD_ARG;
            return frame_ptr;
        }
    };

    let cr3 = current_cr3();
    let mut sector_buf = [0u8; MAX_BLOCK_SECTORS as usize * 512];
    if write {
        if !task::user_range_valid(buf, bytes) {
            let f = unsafe { &mut *frame_ptr };
            f.rax = E_BAD_ARG;
            return frame_ptr;
        }
        let Some(data) = copy_from_user(cr3, buf, bytes) else {
            let f = unsafe { &mut *frame_ptr };
            f.rax = E_BAD_ARG;
            return frame_ptr;
        };
        sector_buf[..bytes].copy_from_slice(&data);
        match crate::ata::write_sectors(disk, lba, count, &sector_buf[..bytes]) {
            Ok(()) => {
                let f = unsafe { &mut *frame_ptr };
                f.rax = E_OK;
            }
            Err(_) => {
                let f = unsafe { &mut *frame_ptr };
                f.rax = E_BAD_ARG;
            }
        }
    } else {
        match crate::ata::read_sectors(disk, lba, count, &mut sector_buf[..bytes]) {
            Ok(()) => {
                if copy_to_user(cr3, buf, &sector_buf[..bytes]) {
                    let f = unsafe { &mut *frame_ptr };
                    f.rax = E_OK;
                } else {
                    let f = unsafe { &mut *frame_ptr };
                    f.rax = E_BAD_ARG;
                }
            }
            Err(_) => {
                let f = unsafe { &mut *frame_ptr };
                f.rax = E_BAD_ARG;
            }
        }
    }
    frame_ptr
}
