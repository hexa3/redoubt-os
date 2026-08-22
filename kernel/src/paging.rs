use core::sync::atomic::{AtomicU64, Ordering};

use x86_64::structures::paging::page_table::PageTableEntry;
use x86_64::structures::paging::{PageTable, PageTableFlags, PhysFrame, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};
use x86_64::instructions::tlb;
use x86_64::registers::control::Cr3;

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

fn next_table_mut(entry: &mut PageTableEntry) -> &'static mut PageTable {
    if entry.is_unused() {
        let frame = frame::alloc_frames(1)
            .unwrap_or_else(|| panic!("out of frames while building page tables"));
        let vaddr = phys_to_virt(frame).as_mut_ptr::<u8>();
        unsafe { core::ptr::write_bytes(vaddr, 0, 4096) };
        entry.set_addr(
            frame,
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE,
        );
        tlb::flush_all();
    }
    table_of(entry)
}

/// Map `virt` -> physical page containing `phys` in the address space rooted
/// at `pml4_phys`. Higher half must alias the kernel mappings (see
/// `new_address_space`).
pub fn map_page_in(pml4_phys: PhysAddr, virt: VirtAddr, phys: PhysAddr, flags: PageTableFlags) {
    let frame = PhysFrame::<Size4KiB>::containing_address(phys);
    let l4 = unsafe { &mut *(phys_to_virt(pml4_phys).as_mut_ptr::<PageTable>()) };
    let l3 = next_table_mut(&mut l4[virt.p4_index()]);
    let l2 = next_table_mut(&mut l3[virt.p3_index()]);
    let l1 = next_table_mut(&mut l2[virt.p2_index()]);
    l1[virt.p1_index()].set_frame(frame, flags);
    tlb::flush_all();
}

pub fn map_page(virt: VirtAddr, phys: PhysAddr, flags: PageTableFlags) {
    let pml4 = Cr3::read().0.start_address();
    map_page_in(pml4, virt, phys, flags);
}

pub fn unmap_page(virt: VirtAddr) {
    let mut table: &mut PageTable = current_pml4();
    for idx in [
        virt.p4_index(),
        virt.p3_index(),
        virt.p2_index(),
        virt.p1_index(),
    ] {
        if table[idx].is_unused() {
            return;
        }
        if idx == virt.p1_index() {
            table[idx].set_unused();
            break;
        }
        table = table_of(&table[idx]);
    }
    tlb::flush_all();
}

pub fn translate(pml4_phys: PhysAddr, virt: VirtAddr) -> Option<PhysAddr> {
    let l4 = unsafe { &*(phys_to_virt(pml4_phys).as_ptr::<PageTable>()) };
    let e4 = &l4[virt.p4_index()];
    if e4.is_unused() { return None; }
    let l3 = table_of(e4);
    let e3 = &l3[virt.p3_index()];
    if e3.is_unused() { return None; }
    let l2 = table_of(e3);
    let e2 = &l2[virt.p2_index()];
    if e2.is_unused() { return None; }
    let l1 = table_of(e2);
    let e1 = &l1[virt.p1_index()];
    if e1.is_unused() { return None; }
    Some(e1.addr() + virt.page_offset().into())
}

/// Create a fresh address space whose lower half is empty and whose upper
/// half copies the kernel's PML4 entries (shared kernel mappings).
pub fn new_address_space() -> PhysAddr {
    let new_frame = frame::alloc_frames(1).expect("out of frames for address space");
    unsafe { core::ptr::write_bytes(phys_to_virt(new_frame).as_mut_ptr::<u8>(), 0, 4096) };
    let new_l4 = unsafe { &mut *(phys_to_virt(new_frame).as_mut_ptr::<PageTable>()) };
    let cur = current_pml4();
    for i in 256..512 {
        new_l4[i] = cur[i].clone();
    }
    new_frame
}
