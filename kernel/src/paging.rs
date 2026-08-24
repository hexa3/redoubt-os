use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use x86_64::instructions::tlb;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::page_table::PageTableEntry;
use x86_64::structures::paging::{PageTable, PageTableFlags, PhysFrame, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

use crate::frame;

pub static PHYS_OFFSET: AtomicU64 = AtomicU64::new(0);

pub fn set_phys_offset(off: u64) {
    PHYS_OFFSET.store(off, Ordering::Relaxed);
}

pub fn phys_to_virt(p: PhysAddr) -> VirtAddr {
    VirtAddr::new(p.as_u64() + PHYS_OFFSET.load(Ordering::Relaxed))
}

/// Physical page table of the currently active address space.
pub fn current_pml4() -> &'static mut PageTable {
    let (frame, _) = Cr3::read();
    unsafe { &mut *(phys_to_virt(frame.start_address()).as_mut_ptr::<PageTable>()) }
}

fn table_of(entry: &PageTableEntry) -> &'static mut PageTable {
    let addr = phys_to_virt(entry.addr());
    unsafe { &mut *(addr.as_mut_ptr::<PageTable>()) }
}

fn next_table_mut(entry: &mut PageTableEntry) -> Option<&'static mut PageTable> {
    if entry.is_unused() {
        let frame = frame::alloc_frames(1)?;
        let vaddr = phys_to_virt(frame).as_mut_ptr::<u8>();
        unsafe { core::ptr::write_bytes(vaddr, 0, 4096) };
        // NOTE 1: no NO_EXECUTE — NX on intermediate levels propagates down
        // and would silently make whole regions non-executable.
        // NOTE 2: USER_ACCESSIBLE here — U/S is ANDed across levels, so
        // intermediates must permit user access or ring 3 can't touch any
        // leaf beneath them, whatever the leaf itself says.
        entry.set_addr(
            frame,
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE,
        );
        tlb::flush_all();
    }
    Some(table_of(entry))
}

/// Map `virt` -> physical page containing `phys` in the address space rooted
/// at `pml4_phys`. Higher half must alias the kernel mappings (see
/// `new_address_space`).
pub fn map_page_in(
    pml4_phys: PhysAddr,
    virt: VirtAddr,
    phys: PhysAddr,
    flags: PageTableFlags,
) -> Result<(), ()> {
    let frame = PhysFrame::<Size4KiB>::containing_address(phys);
    let l4 = unsafe { &mut *(phys_to_virt(pml4_phys).as_mut_ptr::<PageTable>()) };
    let l3 = next_table_mut(&mut l4[virt.p4_index()]).ok_or(())?;
    let l2 = next_table_mut(&mut l3[virt.p3_index()]).ok_or(())?;
    let l1 = next_table_mut(&mut l2[virt.p2_index()]).ok_or(())?;
    l1[virt.p1_index()].set_frame(frame, flags);
    tlb::flush_all();
    Ok(())
}

pub fn map_page(virt: VirtAddr, phys: PhysAddr, flags: PageTableFlags) {
    let pml4 = Cr3::read().0.start_address();
    map_page_in(pml4, virt, phys, flags).expect("out of frames while mapping kernel page");
}

/// Clear the leaf mapping for `virt` in the space rooted at `pml4_phys`.
/// Never frees page-table pages: intermediate tables in the cloned region
/// may be shared by reference between address spaces, so only leaf entries
/// may be touched here. Table reclamation is destroy_address_space's job,
/// and only for the private user subtree (PML4 slot 0).
pub fn unmap_page_in(pml4_phys: PhysAddr, virt: VirtAddr) {
    let l4 = unsafe { &mut *(phys_to_virt(pml4_phys).as_mut_ptr::<PageTable>()) };
    let e4 = &mut l4[virt.p4_index()];
    if e4.is_unused() {
        return;
    }
    let l3 = table_of(e4);
    let e3 = &mut l3[virt.p3_index()];
    if e3.is_unused() {
        return;
    }
    let l2 = table_of(e3);
    let e2 = &mut l2[virt.p2_index()];
    if e2.is_unused() {
        return;
    }
    let l1 = table_of(e2);
    l1[virt.p1_index()].set_unused();
    tlb::flush_all();
}

pub fn translate(pml4_phys: PhysAddr, virt: VirtAddr) -> Option<PhysAddr> {
    let l4 = unsafe { &*(phys_to_virt(pml4_phys).as_ptr::<PageTable>()) };
    let e4 = &l4[virt.p4_index()];
    if e4.is_unused() {
        return None;
    }
    let l3 = table_of(e4);
    let e3 = &l3[virt.p3_index()];
    if e3.is_unused() {
        return None;
    }
    let l2 = table_of(e3);
    let e2 = &l2[virt.p2_index()];
    if e2.is_unused() {
        return None;
    }
    let l1 = table_of(e2);
    let e1 = &l1[virt.p1_index()];
    if e1.is_unused() {
        return None;
    }
    Some(e1.addr() + virt.page_offset().into())
}

/// Every live address space (PML4 physical addresses), including the
/// kernel's own. Kernel stacks must be reachable from all of them because
/// the kernel briefly keeps executing on the outgoing task's stack after a
/// CR3 switch; a stack mapped only in its owner's space faults right there.
static ADDRESS_SPACES: spin::Mutex<Vec<PhysAddr>> = spin::Mutex::new(Vec::new());

/// Kernel-stack allocations: (stack base VA, frames base PA, page count).
/// Replayed into every address space, existing and future.
static KSTACKS: spin::Mutex<Vec<(u64, PhysAddr, u64)>> = spin::Mutex::new(Vec::new());

pub fn register_address_space(pml4: PhysAddr) {
    let mut spaces = ADDRESS_SPACES.lock();
    if !spaces.contains(&pml4) {
        spaces.push(pml4);
    }
}

/// Switch back to the kernel's own address space (registered first at boot).
/// park_idle uses this so the idle context never executes on an address
/// space that the reaper may have just torn down.
pub fn activate_kernel_space() {
    let spaces = ADDRESS_SPACES.lock();
    let Some(kernel) = spaces.first().copied() else {
        return;
    };
    drop(spaces);
    unsafe { core::arch::asm!("mov cr3, {}", in(reg) kernel.as_u64(), options(nostack)) };
}

/// Map a freshly allocated kernel stack into every registered address space
/// and remember it so future address spaces pick it up too.
pub fn register_kstack(stack_base: VirtAddr, frames_base: PhysAddr, pages: u64) -> Result<(), ()> {
    let spaces = ADDRESS_SPACES.lock();
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
    for i in 0..pages {
        let va = VirtAddr::new(stack_base.as_u64() + i * 4096);
        let pa = PhysAddr::new(frames_base.as_u64() + i * 4096);
        for &pml4 in spaces.iter() {
            if map_page_in(pml4, va, pa, flags).is_err() {
                // No task owns this stack until registration completes. Undo
                // leaves we may have installed, then let the caller return
                // the backing frames instead of converting pressure into a
                // kernel panic.
                for j in 0..=i {
                    let undo_va = VirtAddr::new(stack_base.as_u64() + j * 4096);
                    for &undo_pml4 in spaces.iter() {
                        unmap_page_in(undo_pml4, undo_va);
                    }
                }
                return Err(());
            }
        }
    }
    drop(spaces);
    KSTACKS
        .lock()
        .push((stack_base.as_u64(), frames_base, pages));
    Ok(())
}

/// Remove a kernel stack's mappings from every address space and forget it,
/// so future address spaces no longer replay it. Call only once the owning
/// task can no longer run on the stack (see reaper deferral rules).
pub fn unregister_kstack(stack_base: VirtAddr, pages: u64) {
    let base = stack_base.as_u64();
    {
        let spaces = ADDRESS_SPACES.lock();
        for i in 0..pages {
            let va = VirtAddr::new(base + i * 4096);
            for &pml4 in spaces.iter() {
                unmap_page_in(pml4, va);
            }
        }
    }
    KSTACKS.lock().retain(|&(b, _, _)| b != base);
}

/// Free every page under PML4 slot 0 (the private user subtree): leaf
/// frames, all intermediate table pages, and the PML4 frame itself.
/// Shared higher-half subtrees (slots 1..511) are left untouched.
///
/// Must not be the currently active address space unless only accessed via
/// the physmap (which is how we always touch it).
fn free_user_subtree(pml4: PhysAddr) {
    /// Recurse over a private subtree. `level` counts table levels below the
    /// PML4 (3 = PDPT … 1 = PT); leaf entries are reached at level 1.
    fn walk(table_phys: PhysAddr, level: u32, guard: u32) {
        if guard == 0 {
            return; // cycle paranoia; cannot happen with our builder
        }
        let table = unsafe { &mut *(phys_to_virt(table_phys).as_mut_ptr::<PageTable>()) };
        for entry in table.iter_mut() {
            if entry.is_unused() {
                continue;
            }
            let flags = entry.flags();
            if !flags.contains(PageTableFlags::HUGE_PAGE) && level > 1 {
                let child = entry.addr();
                walk(child, level - 1, guard - 1);
            }
            // every frame below us is ours: leaves are user pages, this
            // level's tables were allocated by next_table_mut
            frame::free_frames(entry.addr(), 1);
            entry.set_unused();
        }
    }
    // slot 0 only: levels pml4->pdpt->pd->pt = level 4..1; recurse from level 4
    fn walk_root(pml4: PhysAddr) {
        let table = unsafe { &mut *(phys_to_virt(pml4).as_mut_ptr::<PageTable>()) };
        let e = &mut table[0];
        if !e.is_unused() {
            walk(e.addr(), 3, 8);
            frame::free_frames(e.addr(), 1); // pdpt
            e.set_unused();
        }
        frame::free_frames(pml4, 1); // the pml4 itself
    }
    walk_root(pml4);
}

/// Tear down a dead task's address space: reclaim its user frames and
/// tables, deregister it so kstack mapping fan-out skips it from now on.
pub fn destroy_address_space(pml4: PhysAddr) {
    free_user_subtree(pml4);
    ADDRESS_SPACES.lock().retain(|&p| p != pml4);
}

/// Replay every registered kernel stack into the fresh address space.
/// Call before registering the new space itself.
fn replay_kstacks(pml4: PhysAddr) -> Result<(), ()> {
    let kstacks = KSTACKS.lock();
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
    for &(base, frames_base, pages) in kstacks.iter() {
        for i in 0..pages {
            map_page_in(
                pml4,
                VirtAddr::new(base + i * 4096),
                PhysAddr::new(frames_base.as_u64() + i * 4096),
                flags,
            )?;
        }
    }
    Ok(())
}

/// Create a fresh address space: user range (PML4 slot 0, VAs < 512 GiB)
/// empty; every other slot copied from the kernel's table so kernel text,
/// physmap, and kernel stacks stay visible after CR3 switches.
/// NOTE: the bootloader maps our kernel at phys+2^40 => PML4 index 2,
/// which is NOT in the canonical higher half; hence copy from slot 1 up.
pub fn new_address_space() -> Option<PhysAddr> {
    let new_frame = frame::alloc_frames(1)?;
    unsafe { core::ptr::write_bytes(phys_to_virt(new_frame).as_mut_ptr::<u8>(), 0, 4096) };
    let new_l4 = unsafe { &mut *(phys_to_virt(new_frame).as_mut_ptr::<PageTable>()) };
    let cur = current_pml4();
    for i in 1..512 {
        new_l4[i] = cur[i].clone();
    }
    // Kernel stacks are per-task and allocated AFTER their owner's space
    // exists, but other tasks' stacks must still be reachable here (the
    // kernel hops between them across CR3 switches). Replay them explicitly;
    // cloned PML4 slots only cover what existed in the parent.
    if replay_kstacks(new_frame).is_err() {
        free_user_subtree(new_frame);
        return None;
    }
    register_address_space(new_frame);
    Some(new_frame)
}
