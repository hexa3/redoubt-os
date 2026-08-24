#![feature(abi_x86_interrupt)]
#![no_std]
#![no_main]

extern crate alloc;

mod ata;
mod caps;
mod console;
mod fbcon;
mod font;
mod frame;
mod gdt;
mod heap;
mod input;
mod interrupts;
mod paging;
mod sched;
mod serial;
mod syscall;
mod task;
mod trap;

use core::panic::PanicInfo;

use bootloader_api::config::{BootloaderConfig, Mapping};
use bootloader_api::{entry_point, BootInfo};

pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.kernel_stack_size = 256 * 1024;
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config.mappings.framebuffer = Mapping::Dynamic;
    config
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

static INITFS_ELF: &[u8] = include_bytes!(env!("REDOUBT_INITFS_PATH"));
static CONSOLE_ELF: &[u8] = include_bytes!(env!("REDOUBT_CONSOLE_PATH"));

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    serial::init();
    kprintln!("[redoubt] kernel v0.1 booting");

    // stash physical memory offset before anything touches memory
    let phys_off = boot_info
        .physical_memory_offset
        .into_option()
        .expect("bootloader did not map physical memory");
    paging::set_phys_offset(phys_off);

    // framebuffer text console — everything from here on hits screen + serial
    let fb = core::mem::replace(
        &mut boot_info.framebuffer,
        bootloader_api::info::Optional::None,
    )
    .into_option();
    if let Some(fb) = fb {
        fbcon::init(fb);
        kprintln!("[redoubt] framebuffer console up");
    } else {
        // serial-only boot (headless); console macros degrade gracefully
        serial_write_line("[redoubt] no framebuffer; serial only");
    }

    frame::init(&boot_info.memory_regions);
    let (alloc, total) = frame::stats();
    kprintln!("[redoubt] frame allocator ready ({alloc}/{total} frames used)");

    kprintln!("[redoubt] init: gdt");
    gdt::init();
    kprintln!("[redoubt] init: idt+pit");
    interrupts::init();
    kprintln!("[redoubt] init: ata");
    let disks = ata::init();
    kprintln!("[redoubt] ata: {disks} disk(s) present");

    kprintln!("[redoubt] init: cr0/efer");
    enable_write_protect_and_nxe();

    kprintln!("[redoubt] init: heap");
    heap::init();
    kprintln!(
        "[redoubt] kernel heap up (8 MiB @ {:#x})",
        crate::heap::HEAP_BASE
    );

    // smoke tests
    let mut v = alloc::vec::Vec::new();
    for i in 0..1000u32 {
        v.push(i);
    }
    let sum: u32 = v.iter().sum();
    assert_eq!(sum, 499500);
    kprintln!("[redoubt] heap smoke test ok (sum of 0..1000 = {sum})");

    // ---- userspace bring-up ------------------------------------------------
    // Register the kernel's own address space first: every task's kernel
    // stack gets mapped into it, and every child clones its higher half.
    paging::register_address_space(x86_64::registers::control::Cr3::read().0.start_address());
    // Reserve the idle context stack (slot 0) before any task exists.
    let _ = task::idle_stack_top();

    use caps::{Cap, R_GRANT, R_READ, R_WRITE};
    let console_ep = syscall::create_endpoint("console");
    let fs_ep = syscall::create_endpoint("initfs");
    let cfg_ep = syscall::create_endpoint("cfg");
    let sup_ep = syscall::create_endpoint("sup");
    let info_ep = syscall::create_endpoint("info");
    let stdin_ep = syscall::create_endpoint("stdin");

    // Privileges are transferred exclusively through spawn-time cap lists:
    // console owns its endpoint outright; initfs gets a write-only console
    // handle plus stewardship of its own filesystem endpoint. When a
    // persistent volume exists, initfs also receives the whole-disk block
    // capability (r|w|g) and attenuates it downward to the storage service.
    // Delegation matrix: initfs is the boot initializer and holds
    // delegable handles to every boot endpoint plus the whole-disk block
    // capability. Children receive strictly attenuated intersections.
    let mut initfs_caps: alloc::vec::Vec<Cap> = alloc::vec![
        Cap::Endpoint {
            endpoint: console_ep,
            rights: R_WRITE | R_GRANT
        },
        Cap::Endpoint {
            endpoint: fs_ep,
            rights: R_READ | R_WRITE | R_GRANT
        },
        Cap::Endpoint {
            endpoint: cfg_ep,
            rights: R_READ | R_WRITE | R_GRANT
        },
        Cap::Endpoint {
            endpoint: sup_ep,
            rights: R_READ | R_WRITE | R_GRANT
        },
        Cap::Endpoint {
            endpoint: info_ep,
            rights: R_READ | R_WRITE | R_GRANT
        },
        // initfs delegates this write-only client handle to the shell.
        // The console server alone retains read/serve authority.
        Cap::Endpoint {
            endpoint: stdin_ep,
            rights: R_WRITE | R_GRANT
        },
    ];
    if ata::drive_present(1) {
        initfs_caps.push(Cap::Block {
            disk: 1,
            lba_start: 0,
            lbas: ata::drive_sectors(1),
            rights: R_READ | R_WRITE | R_GRANT,
        });
        kprintln!(
            "[redoubt] initfs holds block cap for disk 1 ({} sectors)",
            ata::drive_sectors(1)
        );
    }

    let _t_console = task::spawn_user(
        CONSOLE_ELF,
        "console",
        &[
            // output side: everyone prints through this
            Cap::Endpoint {
                endpoint: console_ep,
                rights: R_READ | R_WRITE | R_GRANT,
            },
            // input side: console serves interactive line reads here so a
            // half-typed line can never stall system output behind it
            Cap::Endpoint {
                endpoint: stdin_ep,
                rights: R_READ | R_WRITE | R_GRANT,
            },
        ],
        None,
    )
    .expect("embedded console ELF is invalid");

    let _t_initfs = task::spawn_user(INITFS_ELF, "initfs", &initfs_caps, None)
        .expect("embedded initfs ELF is invalid");
    let _ = (cfg_ep, sup_ep, info_ep, stdin_ep);

    kprintln!("[redoubt] entering scheduler");
    sched::kickoff()
}

fn enable_write_protect_and_nxe() {
    use x86_64::registers::control::{Cr0, Cr0Flags};
    unsafe {
        Cr0::update(|f| f.insert(Cr0Flags::WRITE_PROTECT));
    }
    // EFER.NXE so NO_EXECUTE page flags are honored; SCE enables syscall/sysret
    const IA32_EFER: u32 = 0xC000_0080;
    const NXE: u64 = 1 << 11;
    const SCE: u64 = 1 << 0;
    let cur = unsafe { rdmsr(IA32_EFER) };
    unsafe { wrmsr(IA32_EFER, cur | NXE | SCE) };
}

#[inline]
unsafe fn rdmsr(msr: u32) -> u64 {
    use core::arch::asm;
    let hi: u32;
    let lo: u32;
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
    use core::arch::asm;
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

fn serial_write_line(s: &str) {
    use core::fmt::Write;
    let _ = write!(crate::serial::SERIAL.lock(), "{s}\n");
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    kprint!("[redoubt][PANIC] {info}\n");
    loop {
        unsafe { core::arch::asm!("hlt") }
    }
}
