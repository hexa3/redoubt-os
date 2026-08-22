#![no_std]
#![no_main]

use core::arch::asm;

use bootloader_api::{entry_point, BootInfo};

const COM1: u16 = 0x3f8;

fn port_out(port: u16, val: u8) {
    unsafe { asm!("out dx, al", in("dx") port, in("al") val) }
}

fn port_in(port: u16) -> u8 {
    let v: u8;
    unsafe { asm!("in al, dx", out("al") v, in("dx") port) };
    v
}

fn serial_init() {
    port_out(COM1 + 1, 0x00);
    port_out(COM1 + 3, 0x80);
    port_out(COM1, 0x03);
    port_out(COM1 + 1, 0x00);
    port_out(COM1 + 3, 0x03);
    port_out(COM1 + 2, 0xc7);
    port_out(COM1 + 4, 0x0b);
}

fn serial_putc(b: u8) {
    while (port_in(COM1 + 5) & 0x20) == 0 {}
    port_out(COM1, b);
}

fn serial_write(s: &[u8]) {
    for &b in s {
        if b == b'\n' {
            serial_putc(b'\r');
        }
        serial_putc(b);
    }
}

fn hlt_forever() -> ! {
    loop {
        unsafe { asm!("hlt") }
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    serial_write(b"AEGIS PANIC: ");
    if let Some(loc) = info.location() {
        // best-effort decimal printing without fmt machinery
        serial_write(loc.file().as_bytes());
        serial_write(b":");
        print_dec(loc.line() as u64);
    } else {
        serial_write(b"unknown location");
    }
    serial_write(b"\n");
    hlt_forever()
}

fn print_dec(mut v: u64) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    serial_write(&buf[i..]);
}

entry_point!(kernel_main);

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    serial_init();
    serial_write(b"[aegis] kernel booted\n");

    let regions = boot_info.memory_regions.len();
    serial_write(b"[aegis] memory regions: ");
    print_dec(regions as u64);
    serial_write(b"\n");

    for r in boot_info.memory_regions.iter() {
        serial_write(b"  region kind=");
        match r.kind {
            bootloader_api::info::MemoryRegionKind::Usable => serial_write(b"usable"),
            bootloader_api::info::MemoryRegionKind::Bootloader => serial_write(b"bootloader"),
            bootloader_api::info::MemoryRegionKind::UnknownBios(t) => {
                serial_write(b"bios:");
                print_dec(t as u64);
            }
            other => serial_write(b"other"),
        }
        serial_write(b" start=0x");
        print_hex(r.start);
        serial_write(b" end=0x");
        print_hex(r.end);
        serial_write(b"\n");
    }

    serial_write(b"[aegis] initfs elf bytes: ");
    print_dec(INITFS_ELF.len() as u64);
    serial_write(b"\n");
    serial_write(b"[aegis] console elf bytes: ");
    print_dec(CONSOLE_ELF.len() as u64);
    serial_write(b"\n");

    serial_write(b"[aegis] hello from the kernel\n");
    hlt_forever()
}

static INITFS_ELF: &[u8] = include_bytes!(env!("AEGIS_INITFS_PATH"));
static CONSOLE_ELF: &[u8] = include_bytes!(env!("AEGIS_CONSOLE_PATH"));

fn print_hex(v: u64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 16];
    for (i, slot) in buf.iter_mut().enumerate() {
        *slot = HEX[((v >> (60 - 4 * i)) & 0xf) as usize];
    }
    serial_write(&buf);
}
