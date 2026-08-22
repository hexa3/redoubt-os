use x86_64::VirtAddr;
use x86_64::structures::paging::PageTableFlags;

use linked_list_allocator::LockedHeap;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

pub const HEAP_BASE: u64 = 0x0000_7000_0000_0000;
const HEAP_BYTES: u64 = 8 * 1024 * 1024;

pub fn init() {
    let pages = HEAP_BYTES / 4096;
    let frames = crate::frame::alloc_frames(pages).expect("out of frames for kernel heap");
    let flags =
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
    for i in 0..pages {
        let va = VirtAddr::new(HEAP_BASE + i * 4096);
        let pa = x86_64::PhysAddr::new(frames.as_u64() + i * 4096);
        crate::paging::map_page(va, pa, flags);
    }
    unsafe { ALLOCATOR.lock().init(HEAP_BASE as *mut u8, HEAP_BYTES as usize) };
}
