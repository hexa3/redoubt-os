#![no_std]
#![no_main]

extern crate alloc;

use core::mem;
use redoubt_userlib::msg;
use redoubt_userlib::{sys, CapSlot};

// redoubt-console: the system's interactive console server.
//
// Two endpoints, one direction each - the split is load-bearing:
//   slot 0 "console" (output): SOH-prefixed text prints verbatim; other
//          payloads print with a [tid N] prefix and are ack'd. Calls here
//          complete immediately, ALWAYS, so no service's output can ever
//          queue behind an unfinished line read.
//   slot 1 "stdin" (input): "read" returns one full input LINE. While a
//          line is open this endpoint's active-call slot stays occupied
//          (kernel rule), but that only affects stdin - output flows.
//
// The main loop never parks exclusively anywhere: bounded recv slices on
// both endpoints, NOHANG keyboard polls between them, echo at keypress
// time regardless of who is reading.

const SOH: u8 = 0x01;
/// Longest line the editor will accept before silently refusing more.
const LINE_MAX: usize = 72;
const HISTORY_MAX: usize = 16;
const KEY_UP: u8 = 0x80;
const KEY_DOWN: u8 = 0x81;

#[derive(Default)]
struct Editor {
    line: alloc::vec::Vec<u8>,
    /// Complete lines typed ahead of any reader.
    ready: alloc::vec::Vec<alloc::vec::Vec<u8>>,
    history: alloc::vec::Vec<alloc::vec::Vec<u8>>,
    /// Selected history item, if the operator is browsing one.
    history_pos: Option<usize>,
}

impl Editor {
    fn replace_line(&mut self, next: &[u8]) {
        for _ in 0..self.line.len() {
            sys::debug_write_raw(b"\x08 \x08");
        }
        self.line.clear();
        self.line.extend_from_slice(next);
        sys::debug_write_raw(next);
    }

    fn history_up(&mut self) {
        let Some(last) = self.history.len().checked_sub(1) else {
            return;
        };
        let pos = self.history_pos.map_or(last, |p| p.saturating_sub(1));
        self.history_pos = Some(pos);
        let line = self.history[pos].clone();
        self.replace_line(&line);
    }

    fn history_down(&mut self) {
        let Some(pos) = self.history_pos else {
            return;
        };
        if pos + 1 < self.history.len() {
            let next = pos + 1;
            self.history_pos = Some(next);
            let line = self.history[next].clone();
            self.replace_line(&line);
        } else {
            self.history_pos = None;
            self.replace_line(b"");
        }
    }

    fn remember(&mut self, line: &[u8]) {
        self.history_pos = None;
        if line.is_empty() || self.history.last().is_some_and(|last| last == line) {
            return;
        }
        if self.history.len() == HISTORY_MAX {
            self.history.remove(0);
        }
        self.history.push(line.to_vec());
    }

    /// Feed one decoded byte; echoes as it goes. Returns Some(line) when
    /// this byte terminated a line.
    fn feed(&mut self, b: u8) -> Option<alloc::vec::Vec<u8>> {
        match b {
            0x08 | 0x7f => {
                self.history_pos = None;
                if self.line.pop().is_some() {
                    sys::debug_write_raw(b"\x08 \x08");
                }
                None
            }
            0x15 => {
                // Ctrl-U: erase the whole editable line.
                self.history_pos = None;
                self.replace_line(b"");
                None
            }
            0x03 => {
                // Ctrl-C: visibly cancel and return an empty line so the
                // waiting shell immediately redraws its prompt.
                self.history_pos = None;
                self.line.clear();
                sys::debug_write_raw(b"^C\n");
                Some(alloc::vec::Vec::new())
            }
            b'\n' | b'\r' => {
                sys::debug_write_raw(b"\n");
                let done = mem::replace(&mut self.line, alloc::vec::Vec::new());
                self.history_pos = None;
                if done.is_empty() {
                    None // stray enter; nothing to deliver
                } else {
                    Some(done)
                }
            }
            0x20..=0x7e => {
                self.history_pos = None;
                if self.line.len() < LINE_MAX {
                    self.line.push(b);
                    sys::debug_write_raw(&[b]);
                }
                None
            }
            _ => None, // other control bytes are not data
        }
    }
}

#[no_mangle]
fn main() -> ! {
    sys::debug_write(b"console: server up\n");
    let out = CapSlot(0);
    let stdin = CapSlot(1);
    let mut ed = Editor::default();
    let mut kbuf = [0u8; 16];
    // A "read" accepted on stdin holds that endpoint's single active-call
    // slot until its line completes. Output keeps flowing throughout.
    let mut read_open = false;

    loop {
        // ---- input side: accept a reader or complete one ----
        if !read_open {
            match stdin.recv_until(redoubt_userlib::ticks() + 20) {
                Ok((_tid, words)) => {
                    let text = msg::unpack(&words);
                    if text.as_slice() == b"read" {
                        read_open = true;
                        if let Some(line) = pop_ready(&mut ed.ready) {
                            stdin.reply(msg::pack(&line));
                            read_open = false;
                        }
                    } else {
                        // protocol violation on the input channel
                        stdin.reply(msg::pack(b"err: stdin?"));
                    }
                }
                Err(10) => {} // quiet slice
                Err(e) => sys::exit(e),
            }
        }

        // ---- output side: every message completes right now ----
        match out.recv_until(redoubt_userlib::ticks() + 10) {
            Ok((tid, words)) => {
                let text = msg::unpack(&words);
                let prefixed: alloc::vec::Vec<u8> = match text.first() {
                    Some(&SOH) => text[1..].to_vec(),
                    _ => {
                        let mut line: alloc::vec::Vec<u8> = b"[tid ".to_vec();
                        push_num(&mut line, tid);
                        line.extend_from_slice(b"] ");
                        line.extend_from_slice(&text);
                        line
                    }
                };
                sys::debug_write_raw(&prefixed);
                out.reply([1, 0, 0, 0, 0]);
            }
            Err(10) => {}
            Err(e) => sys::exit(e),
        }

        // ---- drain the keyboard without ever parking ----
        loop {
            match redoubt_userlib::input_try_read(&mut kbuf) {
                Ok(0) => break,
                Ok(n) => {
                    for &b in &kbuf[..n] {
                        match b {
                            KEY_UP => ed.history_up(),
                            KEY_DOWN => ed.history_down(),
                            _ => {}
                        }
                        if b != KEY_UP && b != KEY_DOWN {
                            if let Some(done) = ed.feed(b) {
                                ed.remember(&done);
                                ed.ready.push(done);
                            }
                        }
                    }
                }
                Err(_) => break,
            }
        }

        // ---- hand an open reader the oldest complete line ----
        if read_open {
            if let Some(line) = pop_ready(&mut ed.ready) {
                stdin.reply(msg::pack(&line));
                read_open = false;
            }
        }
    }
}

fn pop_ready(ready: &mut alloc::vec::Vec<alloc::vec::Vec<u8>>) -> Option<alloc::vec::Vec<u8>> {
    if ready.is_empty() {
        None
    } else {
        Some(ready.remove(0))
    }
}

fn push_num(out: &mut alloc::vec::Vec<u8>, mut v: u64) {
    if v == 0 {
        out.push(b'0');
        return;
    }
    let mut digits = [0u8; 20];
    let mut n = 0;
    while v > 0 {
        digits[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    while n > 0 {
        n -= 1;
        out.push(digits[n]);
    }
}
