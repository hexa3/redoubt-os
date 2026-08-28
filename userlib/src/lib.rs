//! Minimal runtime for redoubt user-space programs.
//!
//! Provides `_start` (the kernel's fabricated trap frame lands here),
//! syscall wrappers (int 0x80), a bump global allocator, IPC payload
//! helpers, and a panic handler.

#![no_std]

extern crate alloc;

pub mod sys {
    pub const SYS_YIELD: u64 = 1;
    pub const SYS_EXIT: u64 = 2;
    pub const SYS_DEBUG_WRITE: u64 = 3;
    pub const SYS_IPC_CALL: u64 = 4;
    pub const SYS_IPC_RECV: u64 = 5;
    pub const SYS_IPC_REPLY: u64 = 6;
    pub const SYS_CAP_DERIVE: u64 = 7;
    pub const SYS_TASK_SPAWN: u64 = 8;
    pub const SYS_WAIT: u64 = 9;
    pub const SYS_INPUT_READ: u64 = 10;
    pub const SYS_TICKS: u64 = 11;
    pub const SYS_SET_NAME: u64 = 12;
    pub const SYS_STATS: u64 = 13;
    pub const SYS_REBOOT: u64 = 14;
    pub const SYS_SLEEP: u64 = 15;
    pub const SYS_KILL: u64 = 16;
    pub const SYS_BLOCK_READ: u64 = 17;
    pub const SYS_BLOCK_WRITE: u64 = 18;

    /// Full register result of a syscall (blocking calls are woken with
    /// reply data planted in the argument registers).
    #[derive(Debug, Clone, Copy)]
    pub struct Ret {
        pub rax: u64,
        pub a0: u64,
        pub a1: u64,
        pub a2: u64,
        pub a3: u64,
        pub a4: u64,
        pub a5: u64,
    }

    /// Number in rax; args in rdi,rsi,rdx,r10,r8,r9 (all six).
    ///
    /// # Safety
    ///
    /// This issues an unrestricted kernel syscall. Callers must satisfy the
    /// selected syscall's pointer, capability, and lifetime contract; use
    /// the typed wrappers in this module whenever one exists.
    #[inline]
    pub unsafe fn raw_full(n: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> Ret {
        use core::arch::asm;
        let mut rax_out: u64;
        let mut rdi_out: u64;
        let mut rsi_out: u64;
        let mut rdx_out: u64;
        let mut r10_out: u64;
        let mut r8_out: u64;
        let mut r9_out: u64;
        unsafe {
            asm!(
                "int 0x80",
                inlateout("rax") n => rax_out,
                inlateout("rdi") a0 => rdi_out,
                inlateout("rsi") a1 => rsi_out,
                inlateout("rdx") a2 => rdx_out,
                inlateout("r10") a3 => r10_out,
                inlateout("r8") a4 => r8_out,
                inlateout("r9") a5 => r9_out,
                options(nostack)
            );
        }
        Ret {
            rax: rax_out,
            a0: rdi_out,
            a1: rsi_out,
            a2: rdx_out,
            a3: r10_out,
            a4: r8_out,
            a5: r9_out,
        }
    }

    pub fn debug_write(b: &[u8]) -> u64 {
        unsafe {
            raw_full(
                SYS_DEBUG_WRITE,
                b.as_ptr() as u64,
                b.len() as u64,
                0,
                0,
                0,
                0,
            )
            .rax
        }
    }

    /// Verbatim console output: no [tid] prefix, no newline fixups.
    pub fn debug_write_raw(b: &[u8]) -> u64 {
        unsafe {
            raw_full(
                SYS_DEBUG_WRITE,
                b.as_ptr() as u64,
                b.len() as u64,
                1,
                0,
                0,
                0,
            )
            .rax
        }
    }

    pub fn yield_now() {
        unsafe { raw_full(SYS_YIELD, 0, 0, 0, 0, 0, 0) };
    }

    pub fn exit(code: u64) -> ! {
        unsafe { raw_full(SYS_EXIT, code, 0, 0, 0, 0, 0) };
        loop {
            core::hint::spin_loop();
        }
    }
}

/// A capability slot index in this process's table.
#[derive(Debug, Clone, Copy)]
pub struct CapSlot(pub u64);

/// Rights bits — must mirror kernel/src/caps.rs.
pub const R_READ: u64 = 1 << 0;
pub const R_WRITE: u64 = 1 << 1;
pub const R_GRANT: u64 = 1 << 2;

/// IPC payload codec: 5 message words carry up to 40 bytes little-endian,
/// NUL-padded. Both sides of every protocol share this layout.
pub mod msg {
    pub fn pack(bytes: &[u8]) -> [u64; 5] {
        let mut out = [0u64; 5];
        for (i, chunk) in bytes.chunks(8).take(5).enumerate() {
            let mut w = [0u8; 8];
            w[..chunk.len()].copy_from_slice(chunk);
            out[i] = u64::from_le_bytes(w);
        }
        out
    }

    /// Unpack into a byte slice trimmed at the first NUL.
    pub fn unpack(words: &[u64; 5]) -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec::Vec::with_capacity(40);
        for &w in words {
            let b = w.to_le_bytes();
            let end = b.iter().position(|&c| c == 0).unwrap_or(8);
            out.extend_from_slice(&b[..end]);
            if end < 8 {
                break;
            }
        }
        out
    }
}

/// Print arbitrary-length text through a console endpoint.
///
/// The IPC payload budget is 40 packed bytes per message and
/// [`msg::pack`] silently truncates longer payloads, so anything longer
/// must be sent as sequential verbatim fragments. Every fragment after
/// the first carries its own SOH marker; the console concatenates them
/// naturally because it prints each verbatim message as-is.
pub fn print_split(ep: CapSlot, data: &[u8]) -> bool {
    const SOH: u8 = 0x01;
    for chunk in data.chunks(37) {
        let mut m = alloc::vec![SOH];
        m.extend_from_slice(chunk);
        if ep.call(msg::pack(&m)).is_err() {
            return false;
        }
    }
    true
}

/// Binary-safe codec for protocols that must carry arbitrary bytes
/// (program images contain NULs, which [`msg::unpack`] would trim).
/// Exactly `bytes.len()` (<= 40, zero-padded) maps to five words.
pub mod raw {
    /// Pack bytes into five words, zero-padding the tail.
    pub fn pack(bytes: &[u8]) -> [u64; 5] {
        let mut out = [0u64; 5];
        let mut tmp = [0u8; 40];
        let n = bytes.len().min(40);
        tmp[..n].copy_from_slice(&bytes[..n]);
        for (i, w) in out.iter_mut().enumerate() {
            *w = u64::from_le_bytes(tmp[i * 8..i * 8 + 8].try_into().unwrap());
        }
        out
    }

    /// Unpack all 40 bytes behind five words (no NUL trimming).
    pub fn unpack_all(words: &[u64; 5], out: &mut [u8]) {
        let n = out.len().min(40);
        for i in 0..n / 8 {
            out[i * 8..i * 8 + 8].copy_from_slice(&words[i].to_le_bytes());
        }
        let rem = n % 8;
        if rem > 0 {
            let b = words[n / 8].to_le_bytes();
            out[(n / 8) * 8..n].copy_from_slice(&b[..rem]);
        }
    }
}

impl CapSlot {
    /// Synchronous call: block until server replies.
    /// Returns reply words or errno.
    pub fn call(self, w: [u64; 5]) -> Result<[u64; 5], u64> {
        // slot + 5 message words fill the six argument registers exactly.
        let r = unsafe { sys::raw_full(sys::SYS_IPC_CALL, self.0, w[0], w[1], w[2], w[3], w[4]) };
        if r.rax == 0 {
            Ok([r.a0, r.a1, r.a2, r.a3, r.a4])
        } else {
            Err(r.rax)
        }
    }

    /// Block until a caller arrives on this endpoint.
    /// Returns (caller_tid, message words), or errno if the cap check failed.
    pub fn recv(self) -> Result<(u64, [u64; 5]), u64> {
        self.recv_until(0)
    }

    /// Like `recv`, but wakes with E_TIMEDOUT at absolute tick `deadline`
    /// (0 = wait forever). Lets single-threaded servers poll children.
    pub fn recv_until(self, deadline: u64) -> Result<(u64, [u64; 5]), u64> {
        let r = unsafe { sys::raw_full(sys::SYS_IPC_RECV, self.0, deadline, 0, 0, 0, 0) };
        if r.rax == 0 {
            Ok((r.a0, [r.a1, r.a2, r.a3, r.a4, r.a5]))
        } else {
            Err(r.rax)
        }
    }

    /// Reply to the current caller (non-blocking).
    pub fn reply(self, w: [u64; 5]) -> u64 {
        unsafe { sys::raw_full(sys::SYS_IPC_REPLY, self.0, w[0], w[1], w[2], w[3], w[4]).rax }
    }

    /// Derive an attenuated copy into a fresh local slot.
    /// ABI: rax=status, rdi=new slot (so errno and slot can't collide).
    pub fn derive(self, rights_mask: u64) -> Result<CapSlot, u64> {
        let r = unsafe { sys::raw_full(sys::SYS_CAP_DERIVE, self.0, rights_mask, 0, 0, 0, 0) };
        if r.rax == 0 {
            Ok(CapSlot(r.a0))
        } else {
            Err(r.rax)
        }
    }

    /// Derive a block cap narrowed to `[lba, lba+lbas)` AND the requested
    /// rights. Only valid on Block capabilities.
    pub fn derive_block(self, rights_mask: u64, lba: u64, lbas: u64) -> Result<CapSlot, u64> {
        let r = unsafe { sys::raw_full(sys::SYS_CAP_DERIVE, self.0, rights_mask, lba, lbas, 0, 0) };
        if r.rax == 0 {
            Ok(CapSlot(r.a0))
        } else {
            Err(r.rax)
        }
    }
}

/// Spawn a new task from `elf` (bytes in this process's memory).
///
/// `grants` transfers capabilities to the child: element i becomes the
/// child's slot i. Every source slot must carry R_GRANT; the child receives
/// the intersection of the mask with the held rights — attenuation only.
/// Returns the child's task id.
pub fn spawn(elf: &[u8], grants: &[(CapSlot, u64)]) -> Result<u64, u64> {
    // spec layout: (src_slot, rights_mask) pairs of little-endian u64s
    let mut spec = alloc::vec::Vec::with_capacity(grants.len() * 16);
    for (slot, mask) in grants {
        spec.extend_from_slice(&slot.0.to_le_bytes());
        spec.extend_from_slice(&mask.to_le_bytes());
    }
    let r = unsafe {
        sys::raw_full(
            sys::SYS_TASK_SPAWN,
            elf.as_ptr() as u64,
            elf.len() as u64,
            spec.as_ptr() as u64,
            (spec.len() / 8) as u64,
            0,
            0,
        )
    };
    if r.rax == 0 {
        Ok(r.a0)
    } else {
        Err(r.rax)
    }
}

/// Block until any child task exits; reaps it.
/// Returns (child_tid, exit_code) or errno (6 = no children).
pub fn wait() -> Result<(u64, u64), u64> {
    let r = unsafe { sys::raw_full(sys::SYS_WAIT, 0, 0, 0, 0, 0, 0) };
    if r.rax == 0 {
        Ok((r.a0, r.a1))
    } else {
        Err(r.rax)
    }
}

/// Block until this exact direct child exits, then reap it.
///
/// This keeps a transient command from consuming a long-lived sibling's
/// exit notification when its parent owns several children.
pub fn wait_for(tid: u64) -> Result<(u64, u64), u64> {
    if tid == 0 {
        return Err(5); // E_BAD_ARG: task id zero is reserved for wait-any.
    }
    let r = unsafe { sys::raw_full(sys::SYS_WAIT, 0, tid, 0, 0, 0, 0) };
    if r.rax == 0 {
        Ok((r.a0, r.a1))
    } else {
        Err(r.rax)
    }
}

/// Block until at least one keyboard byte is available; fills `buf` with
/// up to buf.len() decoded bytes. Returns the byte count actually written.
pub fn input_read(buf: &mut [u8]) -> Result<usize, u64> {
    let r = unsafe {
        sys::raw_full(
            sys::SYS_INPUT_READ,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
            0,
            0,
            0,
            0,
        )
    };
    if r.rax <= buf.len() as u64 {
        Ok(r.rax as usize)
    } else {
        Err(r.rax)
    }
}

// ------------------------------------------------- new lifecycle wrappers

/// Non-blocking input poll for multiplexing servers. Ok(n) with n >= 0
/// bytes copied; Err(E_WOULD_BLOCK) means the queue was empty.
pub fn input_try_read(buf: &mut [u8]) -> Result<usize, u64> {
    let r = unsafe {
        sys::raw_full(
            sys::SYS_INPUT_READ,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
            1, // NOHANG
            0,
            0,
            0,
        )
    };
    if r.rax != u64::MAX && r.rax <= buf.len() as u64 && r.rax != 9 {
        Ok(r.rax as usize)
    } else {
        Err(r.rax)
    }
}

/// Monotonic system tick (100 Hz).
pub fn ticks() -> u64 {
    unsafe { sys::raw_full(sys::SYS_TICKS, 0, 0, 0, 0, 0, 0).rax }
}

/// Label this task (bounded to 16 printable chars kernel-side).
pub fn set_name(name: &str) -> bool {
    let b = name.as_bytes();
    let r = unsafe {
        sys::raw_full(
            sys::SYS_SET_NAME,
            b.as_ptr() as u64,
            b.len() as u64,
            0,
            0,
            0,
            0,
        )
    };
    r.rax == 0
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SysStats {
    pub magic: u32,
    pub tick_hz: u32,
    pub ticks: u64,
    pub frames_used: u64,
    pub frames_total: u64,
    pub my_pages: u64,
    pub ntasks: u32,
}

pub const SYS_STATS_MAGIC: u32 = 0x4145_4753;

/// Snapshot system + self resource accounting.
pub fn stats() -> Result<SysStats, u64> {
    let mut st = SysStats {
        magic: 0,
        tick_hz: 0,
        ticks: 0,
        frames_used: 0,
        frames_total: 0,
        my_pages: 0,
        ntasks: 0,
    };
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(
            (&mut st as *mut SysStats) as *mut u8,
            core::mem::size_of::<SysStats>(),
        )
    };
    let r = unsafe {
        sys::raw_full(
            sys::SYS_STATS,
            bytes.as_ptr() as u64,
            bytes.len() as u64,
            0,
            0,
            0,
            0,
        )
    };
    if r.rax == 0 && st.magic == SYS_STATS_MAGIC {
        Ok(st)
    } else if r.rax == 0 {
        // kernel wrote something else; refuse to interpret
        Err(u64::MAX)
    } else {
        Err(r.rax)
    }
}

/// Reboot the machine (appliance update flow ends here).
pub fn reboot() -> ! {
    loop {
        unsafe { sys::raw_full(sys::SYS_REBOOT, 0, 0, 0, 0, 0, 0) };
    }
}

/// Park for at least `ticks` timer periods. Wakes with E_OK.
pub fn sleep(ticks: u64) -> Result<(), u64> {
    let r = unsafe { sys::raw_full(sys::SYS_SLEEP, ticks, 0, 0, 0, 0, 0) };
    if r.rax == 0 {
        Ok(())
    } else {
        Err(r.rax)
    }
}

/// Terminate a child process (supervisor use only).
pub fn kill(tid: u64) -> Result<(), u64> {
    let r = unsafe { sys::raw_full(sys::SYS_KILL, tid, 0, 0, 0, 0, 0) };
    if r.rax == 0 {
        Ok(())
    } else {
        Err(r.rax)
    }
}

/// wait() that returns immediately when nothing has exited.
/// E_WOULD_BLOCK means children exist but none has exited yet.
pub fn try_wait() -> Result<Option<(u64, u64)>, u64> {
    const WAIT_NOHANG: u64 = 1;
    let r = unsafe { sys::raw_full(sys::SYS_WAIT, WAIT_NOHANG, 0, 0, 0, 0, 0) };
    match r.rax {
        0 => Ok(Some((r.a0, r.a1))),
        9 => Ok(None), // E_WOULD_BLOCK
        e => Err(e),
    }
}

/// Read disk sectors through a block capability. Max 8 sectors per call.
pub fn block_read(cap: CapSlot, lba: u64, count: u16, buf: &mut [u8]) -> Result<(), u64> {
    if buf.len() < count as usize * 512 || count > 8 || count == 0 {
        return Err(5); // E_BAD_ARG
    }
    let r = unsafe {
        sys::raw_full(
            sys::SYS_BLOCK_READ,
            cap.0,
            lba,
            count as u64,
            buf.as_ptr() as u64,
            0,
            0,
        )
    };
    if r.rax == 0 {
        Ok(())
    } else {
        Err(r.rax)
    }
}

/// Write disk sectors through a block capability. Max 8 sectors per call.
pub fn block_write(cap: CapSlot, lba: u64, count: u16, buf: &[u8]) -> Result<(), u64> {
    if buf.len() < count as usize * 512 || count > 8 || count == 0 {
        return Err(5);
    }
    let r = unsafe {
        sys::raw_full(
            sys::SYS_BLOCK_WRITE,
            cap.0,
            lba,
            count as u64,
            buf.as_ptr() as u64,
            0,
            0,
        )
    };
    if r.rax == 0 {
        Ok(())
    } else {
        Err(r.rax)
    }
}

// Host-side unit tests link `std`, which already supplies `panic_impl`.
// Freestanding user images retain the runtime panic handler.
#[cfg(not(test))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // Best-effort: report then die. No unwinding in a no_std world.
    sys::debug_write(b"userspace panic: ");
    let _ = info;
    sys::exit(101)
}

extern "Rust" {
    fn main() -> !;
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    unsafe { main() }
}

// ------------------------------------------------------------- allocator

/// Fixed 1 MiB bump arena per process. Lives in .bss (MaybeUninit keeps it
/// out of the file image); the kernel zero-fills every page it maps.
const HEAP_SIZE: usize = 1024 * 1024;
struct BumpAlloc {
    head: core::sync::atomic::AtomicUsize,
}

unsafe impl core::alloc::GlobalAlloc for BumpAlloc {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let base = core::ptr::addr_of!(HEAP) as *const u8 as usize;
        let mut head = self.head.load(core::sync::atomic::Ordering::Relaxed);
        loop {
            // A request with a giant alignment or size must fail cleanly,
            // never wrap into a small in-bounds-looking offset and hand out
            // overlapping memory from the fixed arena.
            let Some(start) = base.checked_add(head) else {
                return core::ptr::null_mut();
            };
            let align_mask = layout.align() - 1;
            let Some(padded) = start.checked_add(align_mask) else {
                return core::ptr::null_mut();
            };
            let aligned = padded & !align_mask;
            let Some(end) = aligned.checked_add(layout.size()) else {
                return core::ptr::null_mut();
            };
            let Some(next) = end.checked_sub(base) else {
                return core::ptr::null_mut();
            };
            if next > HEAP_SIZE {
                return core::ptr::null_mut();
            }
            match self.head.compare_exchange_weak(
                head,
                next,
                core::sync::atomic::Ordering::Relaxed,
                core::sync::atomic::Ordering::Relaxed,
            ) {
                Ok(_) => return aligned as *mut u8,
                Err(h) => head = h,
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {
        // bump: never reclaimed; fine for bounded demo workloads
    }
}

static mut HEAP: core::mem::MaybeUninit<[u8; HEAP_SIZE]> = core::mem::MaybeUninit::uninit();

#[global_allocator]
static ALLOC: BumpAlloc = BumpAlloc {
    head: core::sync::atomic::AtomicUsize::new(0),
};
