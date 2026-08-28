//! PS/2 keyboard input path.
//!
//! IRQ1 (interrupts.rs) hands us raw scancodes; this module decodes them
//! into bytes and either satisfies pending readers immediately or queues
//! them for the next SYS_INPUT_READ. Decoding is deliberately minimal:
//! scancode set 1, US layout, shift support, extended (E0-prefixed) keys
//! ignored. Enough to type commands; not a HID stack.

use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicBool, Ordering};

const QUEUE_CAP: usize = 256;

static QUEUE: spin::Mutex<VecDeque<u8>> = spin::Mutex::new(VecDeque::new());
static SHIFT: AtomicBool = AtomicBool::new(false);
static CTRL: AtomicBool = AtomicBool::new(false);
static EXTENDED: AtomicBool = AtomicBool::new(false);

// Private decoded key values. They are control bytes outside the printable
// terminal range and are consumed by the console editor before shell input.
const KEY_UP: u8 = 0x80;
const KEY_DOWN: u8 = 0x81;

/// A task parked in SYS_INPUT_READ with its destination buffer.
struct Waiter {
    tid: usize,
    /// User-space destination VA.
    buf: u64,
    /// Capacity of the destination.
    len: usize,
    /// Reader's address space (for physmap translation).
    cr3: x86_64::PhysAddr,
}

static WAITERS: spin::Mutex<VecDeque<Waiter>> = spin::Mutex::new(VecDeque::new());

/// Map a scancode-set-1 MAKE code to an ASCII byte under current shift.
/// Returns None for modifiers and everything we do not model.
fn decode(sc: u8) -> Option<u8> {
    let sh = SHIFT.load(Ordering::Relaxed);
    let c = match sc {
        // number row
        0x02 => b'1',
        0x03 => b'2',
        0x04 => b'3',
        0x05 => b'4',
        0x06 => b'5',
        0x07 => b'6',
        0x08 => b'7',
        0x09 => b'8',
        0x0a => b'9',
        0x0b => b'0',
        0x0c => b'-',
        0x0d => b'=',
        0x0e => 0x08, // backspace
        0x0f => b'\t',
        // top letter row
        0x10 => b'q',
        0x11 => b'w',
        0x12 => b'e',
        0x13 => b'r',
        0x14 => b't',
        0x15 => b'y',
        0x16 => b'u',
        0x17 => b'i',
        0x18 => b'o',
        0x19 => b'p',
        0x1a => b'[',
        0x1b => b']',
        0x1c => b'\n', // enter
        // home row
        0x1e => b'a',
        0x1f => b's',
        0x20 => b'd',
        0x21 => b'f',
        0x22 => b'g',
        0x23 => b'h',
        0x24 => b'j',
        0x25 => b'k',
        0x26 => b'l',
        0x27 => b';',
        0x28 => b'\'',
        0x29 => b'`',
        0x2b => b'\\',
        // bottom letter row
        0x2c => b'z',
        0x2d => b'x',
        0x2e => b'c',
        0x2f => b'v',
        0x30 => b'b',
        0x31 => b'n',
        0x32 => b'm',
        0x33 => b',',
        0x34 => b'.',
        0x35 => b'/',
        0x39 => b' ',
        _ => return None,
    };
    if CTRL.load(Ordering::Relaxed) && c.is_ascii_alphabetic() {
        return Some(c & 0x1f); // ASCII C0 controls: Ctrl-C, Ctrl-U, …
    }
    Some(if sh { unshift(c) } else { c })
}

fn unshift(c: u8) -> u8 {
    match c {
        b'1' => b'!',
        b'2' => b'@',
        b'3' => b'#',
        b'4' => b'$',
        b'5' => b'%',
        b'6' => b'^',
        b'7' => b'&',
        b'8' => b'*',
        b'9' => b'(',
        b'0' => b')',
        b'-' => b'_',
        b'=' => b'+',
        b'[' => b'{',
        b']' => b'}',
        b';' => b':',
        b'\'' => b'"',
        b'`' => b'~',
        b'\\' => b'|',
        b',' => b'<',
        b'.' => b'>',
        b'/' => b'?',
        c if c.is_ascii_lowercase() => c - b'a' + b'A',
        other => other,
    }
}

/// Entry point from the IRQ1 handler with one raw scancode byte.
pub fn on_scancode(sc: u8) {
    // Extended set-1 keys carry an E0 prefix. Preserve the two editor keys
    // people expect from a shell instead of dropping all extended input.
    if sc == 0xe0 {
        EXTENDED.store(true, Ordering::Relaxed);
        return;
    }
    if EXTENDED.swap(false, Ordering::Relaxed) {
        if sc & 0x80 == 0 {
            match sc {
                0x48 => enqueue(KEY_UP),
                0x50 => enqueue(KEY_DOWN),
                _ => {}
            }
        }
        return;
    }

    if sc == 0x2a || sc == 0x36 {
        SHIFT.store(true, Ordering::Relaxed);
        return;
    }
    if sc == 0xaa || sc == 0xb6 {
        SHIFT.store(false, Ordering::Relaxed);
        return;
    }
    if sc == 0x1d {
        CTRL.store(true, Ordering::Relaxed);
        return;
    }
    if sc == 0x9d {
        CTRL.store(false, Ordering::Relaxed);
        return;
    }

    let is_break = sc & 0x80 != 0;
    if is_break {
        return; // key releases carry no data for us
    }
    let Some(byte) = decode(sc) else { return };

    enqueue(byte);
}

fn enqueue(byte: u8) {
    {
        let mut q = QUEUE.lock();
        if q.len() >= QUEUE_CAP {
            q.pop_front(); // drop oldest rather than growing without bound
        }
        q.push_back(byte);
    }
    // deliver straight to a parked reader if there is one
    let waiter = WAITERS.lock().pop_front();
    if let Some(w) = waiter {
        deliver_to(w);
    }
}

/// Hand queued bytes directly to a registered reader and mark it Ready.
/// Runs in interrupt context: must stay allocation-free where possible and
/// never touch the waiter's stack (only its saved TrapFrame registers).
fn deliver_to(w: Waiter) {
    let mut written = 0usize;
    let mut q = QUEUE.lock();
    while written < w.len {
        let Some(b) = q.front().copied() else { break };
        // one byte at a time through the reader's page tables
        let Some(pa) =
            crate::paging::translate(w.cr3, x86_64::VirtAddr::new(w.buf + written as u64))
        else {
            break; // buffer left memory mid-sleep: give what we have
        };
        unsafe { (crate::paging::phys_to_virt(pa).as_u64() as *mut u8).write(b) };
        q.pop_front();
        written += 1;
    }
    drop(q);

    crate::task::with_tasks(|ts| {
        if let Some(t) = ts.iter_mut().find(|t| t.id == w.tid) {
            if matches!(t.state, crate::task::TaskState::BlockedInput) {
                let f = t.saved_rsp as *mut crate::trap::TrapFrame;
                unsafe {
                    // SYS_INPUT_READ returns its byte count directly in
                    // rax, just like the immediate (queue-nonempty) path.
                    // Returning E_OK here made a parked reader observe a
                    // spurious zero-length read and discard the key.
                    (*f).rax = written as u64;
                }
                t.state = crate::task::TaskState::Ready;
            }
        }
    });
    crate::sched::make_ready(w.tid, true);
}

/// Outcome of a SYS_INPUT_READ attempt.
pub enum ReadOutcome {
    /// Bytes copied into the reader's buffer.
    Served(usize),
    /// Queue empty: reader registered as waiter, will be woken on keypress.
    Parked,
    /// Unusable arguments (zero length / unmapped buffer).
    BadArgs,
}

/// SYS_INPUT_READ implementation.
pub fn request_read(tid: usize, cr3: x86_64::PhysAddr, buf: u64, len: usize) -> ReadOutcome {
    if len == 0 || !crate::task::user_range_valid(buf, len) {
        return ReadOutcome::BadArgs;
    }
    // sanity: destination must be mapped before we ever park on it
    if crate::paging::translate(cr3, x86_64::VirtAddr::new(buf)).is_none() {
        return ReadOutcome::BadArgs;
    }

    let mut q = QUEUE.lock();
    if q.is_empty() {
        drop(q);
        WAITERS.lock().push_back(Waiter { tid, buf, len, cr3 });
        return ReadOutcome::Parked;
    }
    let mut written = 0usize;
    while written < len {
        let Some(b) = q.front().copied() else { break };
        let Some(pa) = crate::paging::translate(cr3, x86_64::VirtAddr::new(buf + written as u64))
        else {
            break;
        };
        unsafe { (crate::paging::phys_to_virt(pa).as_u64() as *mut u8).write(b) };
        q.pop_front();
        written += 1;
    }
    ReadOutcome::Served(written)
}

/// Non-blocking read for multiplexing servers: copies whatever is queued
/// (possibly nothing) without ever parking the caller.
pub fn try_read(cr3: x86_64::PhysAddr, buf: u64, len: usize) -> Option<usize> {
    if len == 0 || !crate::task::user_range_valid(buf, len) {
        return Some(0);
    }
    let mut q = QUEUE.lock();
    let mut written = 0usize;
    while written < len {
        let Some(b) = q.front().copied() else { break };
        let Some(pa) = crate::paging::translate(cr3, x86_64::VirtAddr::new(buf + written as u64))
        else {
            break;
        };
        unsafe { (crate::paging::phys_to_virt(pa).as_u64() as *mut u8).write(b) };
        q.pop_front();
        written += 1;
    }
    Some(written)
}

/// Bytes waiting (diagnostics).
#[allow(dead_code)]
pub fn pending() -> usize {
    QUEUE.lock().len()
}
