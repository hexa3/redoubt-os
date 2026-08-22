use core::sync::atomic::{AtomicU64, Ordering};

use x86_64::PhysAddr;

use bootloader_api::info::MemoryRegionKind;

/// Bump allocator over the bootloader-reported usable regions.
/// Frames are handed out physically contiguously on request and never
/// returned; sufficient for a prototype whose allocations are bounded by
/// the demo workload.
pub struct FrameAllocator {
    regions: [(u64, u64); MAX_REGIONS],
    n_regions: usize,
    cur: AtomicUsize,
    next_free: AtomicU64,
    allocated_frames: AtomicU64,
}

use core::sync::atomic::AtomicUsize;

const MAX_REGIONS: usize = 32;
const PAGE_SIZE: u64 = 4096;
const MIN_ADDR: u64 = 0x100_000; // stay above BIOS/EBDA territory

static ALLOCATOR: spin::Once<spin::Mutex<FrameAllocator>> = spin::Once::new();

pub fn init(regions: &bootloader_api::info::MemoryRegions) {
    let mut regions_arr = [(0u64, 0u64); MAX_REGIONS];
    let mut n = 0usize;
    for r in regions.iter() {
        if r.kind != MemoryRegionKind::Usable || n >= MAX_REGIONS {
            continue;
        }
        let start = (r.start.max(MIN_ADDR) + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let end = r.end & !(PAGE_SIZE - 1);
        if start < end {
            regions_arr[n] = (start, end);
            n += 1;
        }
    }
    let first_free = regions_arr.first().map(|(s, _)| *s).unwrap_or(0);
    ALLOCATOR.call_once(|| {
        spin::Mutex::new(FrameAllocator {
            regions: regions_arr,
            n_regions: n,
            cur: AtomicUsize::new(0),
            next_free: AtomicU64::new(first_free),
            allocated_frames: AtomicU64::new(0),
        })
    });
}

/// Allocate `count` physically contiguous frames. Returns base physical address.
pub fn alloc_frames(count: u64) -> Option<PhysAddr> {
    let mutex = ALLOCATOR.get()?;
    let count = count.max(1);
    let mut fa = mutex.lock();
    while fa.cur.load(Ordering::Relaxed) < fa.n_regions {
        let cur = fa.cur.load(Ordering::Relaxed);
        let (start, end) = fa.regions[cur];
        let aligned = (fa.next_free.load(Ordering::Relaxed) + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        if aligned + count * PAGE_SIZE <= end {
            fa.next_free.store(aligned + count * PAGE_SIZE, Ordering::Relaxed);
            fa.allocated_frames.fetch_add(count, Ordering::Relaxed);
            return Some(PhysAddr::new(aligned));
        }
        fa.cur.store(cur + 1, Ordering::Relaxed);
        if cur + 1 < fa.n_regions {
            fa.next_free.store(fa.regions[cur + 1].0, Ordering::Relaxed);
        }
    }
    None
}

pub fn stats() -> (u64, u64) {
    match ALLOCATOR.get() {
        Some(m) => {
            let fa = m.lock();
            (
                fa.allocated_frames.load(Ordering::Relaxed),
                fa.regions[..fa.n_regions]
                    .iter()
                    .map(|(s, e)| (e - s) / PAGE_SIZE)
                    .sum(),
            )
        }
        None => (0, 0),
    }
}
