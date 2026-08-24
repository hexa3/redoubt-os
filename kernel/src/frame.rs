use core::sync::atomic::{AtomicU64, Ordering};

use alloc::vec::Vec;
use x86_64::PhysAddr;

use bootloader_api::info::MemoryRegionKind;

/// Region allocator over the bootloader-reported usable memory.
///
/// Allocation strategy, in order:
///   1. first-fit scan of the free list (ranges returned by `free_frames`),
///   2. bump allocation from the remaining virgin regions.
///
/// Freed ranges are kept sorted by base address and coalesced with their
/// neighbours, so repeated spawn/exit cycles reach a fixed point instead of
/// exhausting memory the way a pure bump allocator would.
pub struct FrameAllocator {
    regions: [(u64, u64); MAX_REGIONS],
    n_regions: usize,
    cur: AtomicUsize,
    next_free: AtomicU64,
    /// Free ranges (base, end), sorted by base, pairwise non-adjacent.
    free: Vec<(u64, u64)>,
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
            free: Vec::new(),
            allocated_frames: AtomicU64::new(0),
        })
    });
}

/// Allocate `count` physically contiguous frames. Returns base physical address.
pub fn alloc_frames(count: u64) -> Option<PhysAddr> {
    let mutex = ALLOCATOR.get()?;
    let count = count.max(1);
    let bytes = count * PAGE_SIZE;
    let mut fa = mutex.lock();

    // 1: serve from the free list (first fit; ranges are sorted).
    for i in 0..fa.free.len() {
        let (base, end) = fa.free[i];
        if end - base >= bytes {
            let ret = base;
            if end - base == bytes {
                fa.free.remove(i);
            } else {
                fa.free[i] = (base + bytes, end);
            }
            fa.allocated_frames.fetch_add(count, Ordering::Relaxed);
            return Some(PhysAddr::new(ret));
        }
    }

    // 2: bump out of virgin regions.
    while fa.cur.load(Ordering::Relaxed) < fa.n_regions {
        let cur = fa.cur.load(Ordering::Relaxed);
        let (_, end) = fa.regions[cur];
        let aligned = (fa.next_free.load(Ordering::Relaxed) + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        if aligned + count * PAGE_SIZE <= end {
            fa.next_free
                .store(aligned + count * PAGE_SIZE, Ordering::Relaxed);
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

/// Return a contiguous range of frames to the allocator. Adjacent ranges
/// are merged so fragmentation stays bounded for our spawn/exit pattern.
///
/// Caller contract: frames being freed are owned exclusively by the caller
/// (no aliases in other address spaces); violating this is a kernel bug.
pub fn free_frames(base: PhysAddr, count: u64) {
    let Some(mutex) = ALLOCATOR.get() else { return };
    if count == 0 {
        return;
    }
    let start = base.as_u64();
    assert_eq!(start % PAGE_SIZE, 0, "free_frames: unaligned base");
    let bytes = count
        .checked_mul(PAGE_SIZE)
        .expect("free_frames: size overflow");
    let end = start
        .checked_add(bytes)
        .expect("free_frames: range overflow");
    let mut fa = mutex.lock();
    assert!(
        fa.regions[..fa.n_regions]
            .iter()
            .any(|&(region_start, region_end)| start >= region_start && end <= region_end),
        "free_frames: range outside usable memory"
    );
    assert!(
        fa.allocated_frames.load(Ordering::Relaxed) >= count,
        "free_frames: allocation accounting underflow"
    );
    fa.allocated_frames.fetch_sub(count, Ordering::Relaxed);

    // insert sorted; merge with predecessor/successor when touching
    let mut at = fa.free.len();
    for (i, &(b, _e)) in fa.free.iter().enumerate() {
        if b > start {
            at = i;
            break;
        }
    }
    // The free list is the allocator's ownership ledger. A duplicate or
    // overlapping free is always a kernel bug; fail closed here instead of
    // inserting a corrupt range that can later hand one frame to two tasks.
    if at > 0 {
        assert!(
            fa.free[at - 1].1 <= start,
            "free_frames: overlaps preceding free range"
        );
    }
    if at < fa.free.len() {
        assert!(
            end <= fa.free[at].0,
            "free_frames: overlaps following free range"
        );
    }
    // merge left
    if at > 0 && fa.free[at - 1].1 == start {
        fa.free[at - 1].1 = end;
        // merge right too
        if at < fa.free.len() && fa.free[at].0 == end {
            let e = fa.free.remove(at).1;
            fa.free[at - 1].1 = e;
        }
        return;
    }
    // merge right
    if at < fa.free.len() && fa.free[at].0 == end {
        fa.free[at].0 = start;
        return;
    }
    fa.free.insert(at, (start, end));
}

/// (currently held, total) frame counts, for boot diagnostics.
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
