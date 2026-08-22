use core::arch::asm;
use core::fmt::{self, Write};

use spin::Mutex;

const COM1: u16 = 0x3f8;

pub fn port_out(port: u16, val: u8) {
    unsafe { asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack)) }
}

pub fn port_in(port: u16) -> u8 {
    let v: u8;
    unsafe { asm!("in al, dx", out("al") v, in("dx") port, options(nomem, nostack)) };
    v
}

fn serial_putc(b: u8) {
    while (port_in(COM1 + 5) & 0x20) == 0 {}
    port_out(COM1, b);
}

pub struct Serial;

impl Write for Serial {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            if b == b'\n' {
                serial_putc(b'\r');
            }
            serial_putc(b);
        }
        Ok(())
    }
}

pub static SERIAL: Mutex<Serial> = Mutex::new(Serial);

pub fn init() {
    port_out(COM1 + 1, 0x00); // disable UART interrupts
    port_out(COM1 + 3, 0x80); // DLAB on
    port_out(COM1, 0x01); // divisor = 1 -> 115200 baud
    port_out(COM1 + 1, 0x00);
    port_out(COM1 + 3, 0x03); // 8N1
    port_out(COM1 + 2, 0xc7); // FIFO on, clear
    port_out(COM1 + 4, 0x0b); // RTS/DSR
}

#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = write!($crate::serial::SERIAL.lock(), $($arg)*);
    }};
}

#[macro_export]
macro_rules! kprintln {
    ($($arg:tt)*) => {{ $crate::kprint!("{}\n", format_args!($($arg)*)); }};
}
