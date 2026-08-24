//! Output facade: every kernel line goes to serial AND the framebuffer.
//!
//! Formats twice (once per sink) instead of allocating a buffer, so it is
//! safe to call before the kernel heap exists.

use core::fmt;

use crate::{fbcon, serial};

/// Format once through each sink. No allocation; safe pre-heap.
pub fn write_args(args: fmt::Arguments) {
    use fmt::Write;
    let _ = write!(serial::SERIAL.lock(), "{}", args);
    if let Some(mut fb) = fbcon::writer() {
        let _ = write!(fb, "{}", args);
    }
}

/// Raw string path used by syscall handlers.
pub fn write_str(s: &str) {
    write_args(format_args!("{s}"));
}

#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => {{
        $crate::console::write_args(format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! kprintln {
    ($($arg:tt)*) => {{ $crate::kprint!("{}\n", format_args!($($arg)*)); }};
}
