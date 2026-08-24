use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use x86_64::structures::paging::PageTableFlags;
use x86_64::{PhysAddr, VirtAddr};

use crate::frame;
use crate::gdt;
use crate::kprintln;
use crate::paging;
use crate::trap::TrapFrame;

pub const KSTACK_PAGES: u64 = 8; // 32 KiB kernel stack per task
const KSTACK_GUARD_PAGES: u64 = 1;

/// User virtual layout.
pub const USER_STACK_TOP: u64 = 0x0000_7f00_0000;
pub const USER_STACK_BYTES: u64 = 64 * 1024;
/// Kernel stacks share one higher-half region so a trap can always run on
/// the owning task's stack regardless of which address space is active.
const KSTACK_REGION_BASE: u64 = 0xFFFF_C000_0000_0000;
const KSTACK_SLOT_BYTES: u64 = (KSTACK_PAGES + KSTACK_GUARD_PAGES) * 4096;

static NEXT_KSTACK_SLOT: AtomicUsize = AtomicUsize::new(1);
static NEXT_TID: AtomicUsize = AtomicUsize::new(1);

/// Whether `[start, start + len)` lies wholly in the user portion of an
/// address space. Kernel mappings are shared into every task's page table,
/// so page-table translation alone is never sufficient authorization for a
/// kernel copy operation.
pub fn user_range_valid(start: u64, len: usize) -> bool {
    let Some(end) = start.checked_add(len as u64) else {
        return false;
    };
    start < USER_STACK_TOP && end <= USER_STACK_TOP
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Ready,
    Running,
    /// Blocked in sys_ipc_call waiting for a receiver (message queued).
    BlockedSend {
        endpoint: u64,
    },
    /// Call delivered; blocked waiting for the server's reply.
    BlockedCall {
        endpoint: u64,
    },
    /// Blocked in sys_ipc_recv waiting for a message. `deadline` is an
    /// absolute tick count after which the caller wakes with E_TIMEDOUT;
    /// 0 means wait forever.
    BlockedRecv {
        endpoint: u64,
        deadline: u64,
    },
    /// Blocked in sys_wait waiting for a child to exit.
    BlockedWait,
    /// Blocked in sys_input_read waiting for keyboard bytes.
    BlockedInput,
    /// Blocked in sys_sleep until the absolute tick deadline.
    BlockedSleep {
        until: u64,
    },
    /// Exited; resources still held until reaped (exit code readable).
    Zombie {
        code: u64,
    },
}

pub struct Task {
    pub id: usize,
    pub name: String,
    pub state: TaskState,
    pub cr3: PhysAddr,
    pub kstack_top: VirtAddr,
    /// Saved kernel RSP while not running; points at the TrapFrame.
    pub saved_rsp: u64,
    pub caps: Vec<Option<crate::caps::Cap>>,
    /// Parent task, if spawned by another task (None = kernel-spawned).
    pub parent: Option<usize>,
    /// Kernel-stack mapping bookkeeping: VA of first mapped page and the
    /// physical frame range behind it.
    pub kstack_base_va: VirtAddr,
    pub kstack_frames_base: PhysAddr,
    /// User leaf pages charged to this task (ELF segments + user stack).
    /// Observability only: the reaper frees frames via the address-space
    /// walk, not from this counter.
    pub pages: u64,
}

impl Task {
    pub fn free_cap_slot(&self) -> Option<usize> {
        self.caps.iter().position(|c| c.is_none())
    }

    /// Replace the task's display name (SYS_SET_NAME). Bounded so a
    /// malicious name cannot grow the table.
    pub fn set_name(&mut self, name: &str) {
        self.name.clear();
        for b in name.bytes().take(16) {
            if b.is_ascii_graphic() || b == b' ' {
                self.name.push(b as char);
            }
        }
        if self.name.is_empty() {
            self.name.push('?');
        }
    }
}

static TASKS: spin::Mutex<Vec<Task>> = spin::Mutex::new(Vec::new());

pub fn with_tasks<R>(f: impl FnOnce(&mut Vec<Task>) -> R) -> R {
    let mut t = TASKS.lock();
    f(&mut t)
}

fn alloc_kstack() -> Option<(VirtAddr, PhysAddr)> {
    let slot = NEXT_KSTACK_SLOT.fetch_add(1, Ordering::Relaxed);
    if slot >= 4096 {
        return None;
    }
    kstack_slot(slot)
}

/// Kernel-stack slot 0 is reserved for the idle context: the stack the CPU
/// falls back to whenever TSS.RSP0 must not point into a task's stack
/// (see sched::park_idle). Mapped everywhere like any other kstack; never
/// freed.
pub fn idle_stack_top() -> VirtAddr {
    static IDLE: spin::Once<VirtAddr> = spin::Once::new();
    *IDLE.call_once(|| {
        let (top, _) = kstack_slot(0).expect("out of frames for idle kernel stack");
        top
    })
}

fn kstack_slot(slot: usize) -> Option<(VirtAddr, PhysAddr)> {
    if slot >= 4096 {
        return None;
    }
    let base = KSTACK_REGION_BASE + slot as u64 * KSTACK_SLOT_BYTES;
    let stack_base = base + KSTACK_GUARD_PAGES * 4096;
    let frames = frame::alloc_frames(KSTACK_PAGES)?;
    // Guard page stays unmapped; the stack itself goes into every live
    // address space (the kernel keeps executing on the outgoing task's
    // stack across a CR3 switch) and is recorded for future spaces.
    if paging::register_kstack(VirtAddr::new(stack_base), frames, KSTACK_PAGES).is_err() {
        frame::free_frames(frames, KSTACK_PAGES);
        return None;
    }
    Some((VirtAddr::new(stack_base + KSTACK_PAGES * 4096), frames))
}

/// Load an ELF image into a fresh address space and create a Ready task.
///
/// `caps` are installed into the child's table in order, starting at
/// slot 0 — this is how privileges are transferred across spawn.
/// `parent` records the spawner for exit/reap bookkeeping (None = kernel).
/// Returns Err on malformed ELF or resource exhaustion; a hostile ELF
/// must never panic the kernel.
pub fn spawn_user(
    elf: &[u8],
    name: &str,
    caps: &[crate::caps::Cap],
    parent: Option<usize>,
) -> Result<usize, ()> {
    let cr3 = paging::new_address_space().ok_or(())?;
    let (entry, elf_pages) = match load_elf(cr3, elf) {
        Ok(res) => res,
        Err(()) => {
            // `load_elf` may already have mapped frames before finding a
            // malformed later segment. Destroying the private subtree frees
            // both those leaves and its page tables.
            paging::destroy_address_space(cr3);
            return Err(());
        }
    };

    let stack_frames = match frame::alloc_frames(USER_STACK_BYTES / 4096) {
        Some(frames) => frames,
        None => {
            paging::destroy_address_space(cr3);
            return Err(());
        }
    };
    // A freed stack can be handed to a different task by the frame
    // allocator. Clear it before mapping so neither previous user data nor
    // boot-time contents become visible in the new process.
    unsafe {
        core::ptr::write_bytes(
            paging::phys_to_virt(stack_frames).as_mut_ptr::<u8>(),
            0,
            USER_STACK_BYTES as usize,
        )
    };
    let stack_base = USER_STACK_TOP - USER_STACK_BYTES;
    let flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::NO_EXECUTE
        | PageTableFlags::USER_ACCESSIBLE;
    let stack_pages = USER_STACK_BYTES / 4096;
    for i in 0..stack_pages {
        if paging::map_page_in(
            cr3,
            VirtAddr::new(stack_base + i * 4096),
            PhysAddr::new(stack_frames.as_u64() + i * 4096),
            flags,
        )
        .is_err()
        {
            // Mappings earlier in this loop own the same contiguous frame
            // range. Remove those leaves before returning the full range,
            // otherwise address-space destruction would free them twice.
            for mapped in 0..i {
                paging::unmap_page_in(cr3, VirtAddr::new(stack_base + mapped * 4096));
            }
            frame::free_frames(stack_frames, stack_pages);
            paging::destroy_address_space(cr3);
            return Err(());
        }
    }

    let Some((kstack_top, kstack_frames_base)) = alloc_kstack() else {
        paging::destroy_address_space(cr3);
        return Err(());
    };

    let sel = gdt::selectors();
    let user_cs = (sel.user_code.0 | 3) as u64;
    let user_ss = (sel.user_data.0 | 3) as u64;
    let frame = TrapFrame::new_user(entry, USER_STACK_TOP, user_cs, user_ss);

    let frame_addr = kstack_top.as_u64() - core::mem::size_of::<TrapFrame>() as u64;
    unsafe { (frame_addr as *mut TrapFrame).write(frame) };

    let id = NEXT_TID.fetch_add(1, Ordering::Relaxed);
    with_tasks(|tasks| {
        tasks.push(Task {
            id,
            name: String::from(name),
            state: TaskState::Ready,
            cr3,
            kstack_top,
            saved_rsp: frame_addr,
            caps: {
                let mut v: Vec<Option<crate::caps::Cap>> =
                    alloc::vec![None; crate::caps::CAP_TABLE_SIZE];
                for (i, c) in caps.iter().enumerate().take(crate::caps::CAP_TABLE_SIZE) {
                    v[i] = Some(*c);
                }
                v
            },
            parent,
            kstack_base_va: VirtAddr::new(kstack_top.as_u64() - KSTACK_PAGES * 4096),
            kstack_frames_base,
            pages: elf_pages + stack_pages,
        });
    });
    kprintln!(
        "[redoubt] spawned '{}' tid={} entry={entry:#x} cr3={:#x} caps={}",
        name,
        id,
        cr3.as_u64(),
        caps.len()
    );
    crate::sched::make_ready(id, false);
    Ok(id)
}

/// Parse a statically linked little-endian x86-64 ELF and copy its PT_LOAD
/// segments into `cr3`. Deliberately small but paranoid: every field that
/// could make us write outside our own mappings is validated first.
/// Returns the entry point and the number of leaf pages mapped.
fn load_elf(cr3: PhysAddr, elf: &[u8]) -> Result<(u64, u64), ()> {
    if elf.len() < 0x40 {
        return Err(());
    }
    if &elf[0..4] != b"\x7fELF" || elf[4] != 2 || elf[5] != 1 || elf[6] != 1 {
        return Err(()); // magic / class / endianness / version
    }
    if rd16(elf, 0x12) != 0x3e {
        return Err(()); // not x86-64
    }
    if rd16(elf, 0x10) != 2 {
        return Err(()); // must be ET_EXEC: we apply no relocations
    }

    let entry = rd(elf, 0x18);
    let phoff = rd(elf, 0x20) as usize;
    let phentsize = rd16(elf, 0x36) as usize;
    let phnum = rd16(elf, 0x38) as usize;

    if phnum > 32 || phentsize < 56 {
        return Err(());
    }
    let phend = phoff
        .checked_add(phnum.checked_mul(phentsize).ok_or(())?)
        .ok_or(())?;
    if phend > elf.len() {
        return Err(());
    }

    const PT_LOAD: u32 = 1;
    const PAGE_SIZE: u64 = 4096;
    const USER_LOAD_LIMIT: u64 = USER_STACK_TOP - USER_STACK_BYTES;
    let mut entry_is_executable = false;
    struct LoadSegment {
        flags: u32,
        offset: usize,
        vaddr: u64,
        filesz: usize,
        page_start: u64,
        page_end: u64,
    }
    let mut segments = Vec::new();

    // Validate the complete load plan before allocating or mapping anything.
    // In particular, page-overlapping PT_LOADs would make a later segment
    // replace a leaf installed for an earlier one and leak its frame.
    for i in 0..phnum {
        let ph = phoff + i * phentsize;
        if rd32(elf, ph) != PT_LOAD {
            continue;
        }
        let p_flags = rd32(elf, ph + 4);
        let p_offset = usize::try_from(rd(elf, ph + 8)).map_err(|_| ())?;
        let p_vaddr = rd(elf, ph + 16);
        let p_filesz = usize::try_from(rd(elf, ph + 32)).map_err(|_| ())?;
        let p_memsz = usize::try_from(rd(elf, ph + 40)).map_err(|_| ())?;
        let p_align = rd(elf, ph + 48);

        if p_memsz == 0 {
            continue;
        }
        if p_offset.checked_add(p_filesz).ok_or(())? > elf.len() {
            return Err(());
        }
        if p_filesz > p_memsz {
            return Err(());
        }
        if p_align > 1
            && (!p_align.is_power_of_two() || p_vaddr % p_align != (p_offset as u64) % p_align)
        {
            return Err(());
        }
        let segment_end = p_vaddr.checked_add(p_memsz as u64).ok_or(())?;
        let page_start = p_vaddr & !(PAGE_SIZE - 1);
        let page_end = segment_end.checked_add(PAGE_SIZE - 1).ok_or(())? & !(PAGE_SIZE - 1);
        if page_start < PAGE_SIZE || page_end > USER_LOAD_LIMIT {
            return Err(()); // segments stay out of the stack region
        }
        // Never create a writable executable user page. The binary format
        // does not need it, and allowing it turns a memory bug into code
        // injection inside an otherwise isolated service.
        if p_flags & 0b11 == 0b11 {
            return Err(());
        }
        if p_flags & 1 != 0 && entry >= p_vaddr && entry < segment_end {
            entry_is_executable = true;
        }

        if segments
            .iter()
            .any(|other: &LoadSegment| page_start < other.page_end && other.page_start < page_end)
        {
            return Err(());
        }
        segments.push(LoadSegment {
            flags: p_flags,
            offset: p_offset,
            vaddr: p_vaddr,
            filesz: p_filesz,
            page_start,
            page_end,
        });
    }

    let mut elf_pages: u64 = 0;
    for segment in segments {
        let rw = PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::NO_EXECUTE
            | PageTableFlags::USER_ACCESSIBLE;
        for page in (segment.page_start..segment.page_end).step_by(PAGE_SIZE as usize) {
            let fr = frame::alloc_frames(1).ok_or(())?;
            unsafe { core::ptr::write_bytes(paging::phys_to_virt(fr).as_mut_ptr::<u8>(), 0, 4096) };
            if paging::map_page_in(cr3, VirtAddr::new(page), fr, rw).is_err() {
                frame::free_frames(fr, 1);
                return Err(());
            }
            elf_pages += 1;
        }

        unsafe {
            for (i, byte) in elf[segment.offset..segment.offset + segment.filesz]
                .iter()
                .enumerate()
            {
                let va = VirtAddr::new(segment.vaddr + i as u64);
                let pa = paging::translate(cr3, va).ok_or(())?;
                (paging::phys_to_virt(pa).as_u64() as *mut u8).write(*byte);
            }
        }

        let mut final_flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
        if segment.flags & 2 != 0 {
            final_flags |= PageTableFlags::WRITABLE;
        }
        if segment.flags & 1 == 0 {
            final_flags |= PageTableFlags::NO_EXECUTE;
        }
        for page in (segment.page_start..segment.page_end).step_by(PAGE_SIZE as usize) {
            let pa = paging::translate(cr3, VirtAddr::new(page)).ok_or(())?;
            paging::map_page_in(cr3, VirtAddr::new(page), pa, final_flags)?;
        }
    }
    if !entry_is_executable {
        return Err(()); // entry must land in an executable loaded segment
    }
    Ok((entry, elf_pages))
}

fn rd(elf: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&elf[off..off + 8]);
    u64::from_le_bytes(b)
}

fn rd16(elf: &[u8], off: usize) -> u16 {
    let mut b = [0u8; 2];
    b.copy_from_slice(&elf[off..off + 2]);
    u16::from_le_bytes(b)
}

fn rd32(elf: &[u8], off: usize) -> u32 {
    let mut b = [0u8; 4];
    b.copy_from_slice(&elf[off..off + 4]);
    u32::from_le_bytes(b)
}

// ------------------------------------------------------------------- reaper
//
// Exit releases nothing by itself: the dying task is still executing on its
// own kernel stack when it runs the exit syscall, and its TrapFrame sits at
// the top of that very stack. Instead the task becomes Zombie{code} and its
// resources are torn down either
//   * inline by a LIVE sibling context (sys_wait reaping a zombie child), or
//   * deferred to the next trap boundary (handle_trap -> drain_reaper),
//     which is always executing on some *other* live task's stack.
//
// The dedicated idle stack guarantees the second rule has no exception even
// when the last runnable task exits: park_idle repoints TSS.RSP0 away from
// the dying stack before enabling interrupts.

struct PendingReap {
    cr3: PhysAddr,
    kstack_base_va: VirtAddr,
    kstack_frames_base: PhysAddr,
}

static REAP_QUEUE: spin::Mutex<alloc::vec::Vec<PendingReap>> =
    spin::Mutex::new(alloc::vec::Vec::new());

/// Reclaim everything a task owns. Must run in a context whose kernel stack
/// is NOT the doomed one.
fn reclaim(p: PendingReap) {
    // The private PML4 subtree owns every user leaf, including the user
    // stack. `destroy_address_space` frees those frames as it walks leaves;
    // freeing `user_stack_base` again here would corrupt the free list.
    paging::destroy_address_space(p.cr3);
    paging::unregister_kstack(p.kstack_base_va, KSTACK_PAGES);
    frame::free_frames(p.kstack_frames_base, KSTACK_PAGES);
}

/// Snapshot a zombie's resources, remove it from the task table, and defer
/// its teardown to the next trap boundary.
///
/// The caller must have already extracted any information anyone needs
/// (exit code delivery happens before this point).
pub fn schedule_reap(tid: usize) {
    let snap = with_tasks(|ts| {
        let pos = ts.iter().position(|t| t.id == tid)?;
        debug_assert!(matches!(ts[pos].state, TaskState::Zombie { .. }));
        let t = &ts[pos];
        Some(PendingReap {
            cr3: t.cr3,
            kstack_base_va: t.kstack_base_va,
            kstack_frames_base: t.kstack_frames_base,
        })
    });
    let Some(snap) = snap else { return };
    with_tasks(|ts| ts.retain(|t| t.id != tid));
    REAP_QUEUE.lock().push(snap);
}

/// Tear down every queued corpse. Called at trap entry, where the CPU is
/// provably on a live task's kernel stack.
pub fn drain_reaper() {
    let mut q = REAP_QUEUE.lock();
    if q.is_empty() {
        return;
    }
    let drained: alloc::vec::Vec<PendingReap> = q.drain(..).collect();
    drop(q);
    for p in drained {
        reclaim(p);
    }
}

/// Reap a zombie child right now (sys_wait path): returns its exit code.
/// Caller context runs on the PARENT's stack, so inline teardown is safe.
pub fn reap_zombie(tid: usize) -> Option<u64> {
    let snap = with_tasks(|ts| {
        let pos = ts.iter().position(|t| t.id == tid)?;
        let code = match ts[pos].state {
            TaskState::Zombie { code } => code,
            _ => return None,
        };
        let t = &ts[pos];
        let p = PendingReap {
            cr3: t.cr3,
            kstack_base_va: t.kstack_base_va,
            kstack_frames_base: t.kstack_frames_base,
        };
        ts.remove(pos);
        Some((code, p))
    })?;
    let (code, p) = snap;
    reclaim(p);
    Some(code)
}
