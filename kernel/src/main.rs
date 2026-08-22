#![feature(abi_x86_interrupt)]
#![no_std]
#![no_main]

extern crate alloc;

mod frame;
mod gdt;
mod heap;
mod interrupts;
mod paging;
mod serial;

use core::arch::asm;
use core::panic::PanicInfo;

use bootloader_api::config::{BootloaderConfig, Mapping};
use bootloader_api::{entry_point, BootInfo};
use x86_64::structures::paging::PageTableFlags;
use x86_64::VirtAddr;

pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.kernel_stack_size = 256 * 1024;
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

static INITFS_ELF: &[u8] = include_bytes!(env!("AEGIS_INITFS_PATH"));
static CONSOLE_ELF: &[u8] = include_bytes!(env!("AEGIS_CONSOLE_PATH"));

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    serial::init();
    kprintln!("[aegis] kernel v0.1 booting");

    // stash physical memory offset before anything touches memory
    let phys_off = boot_info
        .physical_memory_offset
        .into_option()
        .expect("bootloader did not map physical memory");
    paging::set_phys_offset(phys_off);

    frame::init(&boot_info.memory_regions);
    let (alloc, total) = frame::stats();
    kprintln!("[aegis] frame allocator ready ({alloc}/{total} frames used)");

    kprintln!("[aegis] init: gdt");
    gdt::init();
    kprintln!("[aegis] init: idt+pit");
    interrupts::init();

    kprintln!("[aegis] init: cr0/efer");
    enable_write_protect_and_nxe();

    kprintln!("[aegis] init: heap");
    heap::init();
    kprintln!("[aegis] kernel heap up (8 MiB @ {:#x})", crate::heap::HEAP_BASE);

    // smoke tests
    let mut v = alloc::vec::Vec::new();
    for i in 0..1000u32 {
        v.push(i);
    }
    let sum: u32 = v.iter().sum();
    assert_eq!(sum, 499500);
    kprintln!("[aegis] heap smoke test ok (sum of 0..1000 = {sum})");

    x86_64::instructions::interrupts::enable();
    let t0 = interrupts::ticks();
    while interrupts::ticks() < t0 + 50 {
        unsafe { asm!("hlt") };
    }
    let dt = interrupts::ticks() - t0;
    kprintln!("[aegis] timer alive: +{dt} ticks (~{:.1}s at 100Hz)", dt as f64 / 100.0);

    x86_64::instructions::interrupts::int3();

    kprintln!(
        "[aegis] initfs elf {} bytes, console elf {} bytes",
        INITFS_ELF.len(),
        CONSOLE_ELF.len()
    );
    kprintln!("[aegis] foundation ready; scheduler comes next");

    loop {
        unsafe { asm!("hlt") }
    }
}

fn enable_write_protect_and_nxe() {
    use x86_64::registers::control::{Cr0, Cr0Flags};
    unsafe {
        Cr0::update(|f| f.insert(Cr0Flags::WRITE_PROTECT));
    }
    // EFER.NXE so NO_EXECUTE page flags are honored; also SCE for later syscall support
    const IA32_EFER: u32 = 0xC000_0080;
    const NXE: u64 = 1 << 11;
    const SCE: u64 = 1 << 0;
    let cur = unsafe { rdmsr(IA32_EFER) };
    unsafe { wrmsr(IA32_EFER, cur | NXE | SCE) };
}

#[inline]
unsafe fn rdmsr(msr: u32) -> u64 {
    let (hi, lo): (u32, u32);
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nostack)
        );
    }
    ((hi as u64) << 32) | lo as u64
}

#[inline]
unsafe fn wrmsr(msr: u32, val: u64) {
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") (val & 0xffff_ffff) as u32,
            in("edx") ((val >> 32) & 0xffff_ffff) as u32,
            options(nostack)
        );
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    kprint!("[aegis][PANIC] {info}\n");
    loop {
        unsafe { asm!("hlt") }
    }
}
