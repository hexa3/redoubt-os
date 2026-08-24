//! Text console on the bootloader-provided linear framebuffer.
//!
//! 8x8 glyphs (kernel/src/font.rs), one text cell per 8x8 pixel block.
//! The framebuffer is mapped by the bootloader in the kernel's higher
//! half, so it is reachable from every address space via the cloned PML4
//! slots — no per-task mapping work needed.

use core::fmt;

use bootloader_api::info::{FrameBufferInfo, PixelFormat};

use crate::{font::FONT8X8, kprintln};

struct Screen {
    buf: &'static mut [u8],
    info: FrameBufferInfo,
    cols: usize,
    rows: usize,
}

impl Screen {
    fn put_pixel(&mut self, x: usize, y: usize, rgb: [u8; 3]) {
        if x >= self.info.width || y >= self.info.height {
            return;
        }
        let idx = y * self.info.stride + x * self.info.bytes_per_pixel;
        if idx + self.info.bytes_per_pixel > self.buf.len() {
            return;
        }
        match self.info.pixel_format {
            PixelFormat::Rgb => {
                self.buf[idx] = rgb[0];
                if self.info.bytes_per_pixel > 1 {
                    self.buf[idx + 1] = rgb[1];
                }
                if self.info.bytes_per_pixel > 2 {
                    self.buf[idx + 2] = rgb[2];
                }
            }
            _ => {
                // BGR and unknown layouts
                self.buf[idx] = rgb[2];
                if self.info.bytes_per_pixel > 1 {
                    self.buf[idx + 1] = rgb[1];
                }
                if self.info.bytes_per_pixel > 2 {
                    self.buf[idx + 2] = rgb[0];
                }
            }
        }
    }

    fn draw_char(&mut self, row: usize, col: usize, ch: u8) {
        let g = (ch as usize) & 0x7f;
        for gy in 0..8 {
            let bits = FONT8X8[g * 8 + gy];
            for gx in 0..8 {
                let on = bits & (0x80 >> gx) != 0;
                self.put_pixel(col * 8 + gx, row * 8 + gy, if on { FG } else { BG });
            }
        }
    }

    fn scroll(&mut self) {
        let line_bytes = self.info.stride * 8;
        if self.buf.len() > line_bytes {
            self.buf.copy_within(line_bytes.., 0);
        }
        for y in (self.rows - 1) * 8..self.rows * 8 {
            for x in 0..self.info.width {
                self.put_pixel(x, y, BG);
            }
        }
    }

    fn newline(&mut self, cur: &mut (usize, usize)) {
        cur.0 = 0;
        cur.1 += 1;
        if cur.1 >= self.rows {
            self.scroll();
            cur.1 = self.rows - 1;
        }
    }
}

const FG: [u8; 3] = [0xC8, 0xC8, 0xC8];
const BG: [u8; 3] = [0x10, 0x12, 0x18];

static SCREEN: spin::Once<spin::Mutex<Screen>> = spin::Once::new();
static CURSOR: spin::Mutex<(usize, usize)> = spin::Mutex::new((0, 0));

pub fn init(fb: bootloader_api::info::FrameBuffer) {
    let info = fb.info();
    let cols = info.width / 8;
    let rows = info.height / 8;
    // 'static via into_buffer; the bootloader mapping lives forever.
    let buf: &'static mut [u8] = fb.into_buffer();
    kprintln!(
        "[redoubt] fb: buf={:#x} len={:#x} {}x{} bpp={} stride={} fmt={:?}",
        buf.as_ptr() as usize,
        buf.len(),
        info.width,
        info.height,
        info.bytes_per_pixel,
        info.stride,
        info.pixel_format
    );
    SCREEN.call_once(|| {
        spin::Mutex::new(Screen {
            buf,
            info,
            cols,
            rows,
        })
    });
    // clear to background now that we hold the screen
    let mut s = SCREEN.get().unwrap().lock();
    for y in 0..s.info.height {
        for x in 0..s.info.width {
            s.put_pixel(x, y, BG);
        }
    }
}

/// Raw byte writer.
pub fn write_bytes(bytes: &[u8]) {
    let Some(screen_cell) = SCREEN.get() else {
        return;
    };
    let mut s = screen_cell.lock();
    let mut cur = CURSOR.lock();
    for &b in bytes {
        match b {
            b'\n' => s.newline(&mut cur),
            b'\r' => cur.0 = 0,
            0x08 => {
                if cur.0 > 0 {
                    cur.0 -= 1;
                    s.draw_char(cur.1, cur.0, b' ');
                } else if cur.1 > 0 {
                    cur.1 -= 1;
                    cur.0 = s.cols - 1;
                    s.draw_char(cur.1, cur.0, b' ');
                }
            }
            _ => {
                s.draw_char(cur.1, cur.0, b);
                cur.0 += 1;
                if cur.0 >= s.cols {
                    s.newline(&mut cur);
                }
            }
        }
    }
}

/// fmt::Write adapter so kprint! can format straight into pixels.
pub struct FbWriter;

impl fmt::Write for FbWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        write_bytes(s.as_bytes());
        Ok(())
    }
}

pub fn writer() -> Option<FbWriter> {
    if SCREEN.get().is_some() {
        Some(FbWriter)
    } else {
        None
    }
}
