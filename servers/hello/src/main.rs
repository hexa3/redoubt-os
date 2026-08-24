#![no_std]
#![no_main]

extern crate alloc;

use redoubt_userlib::msg;
use redoubt_userlib::{sys, CapSlot};

// redoubt-hello: the first task spawned BY userspace (initfs launches us
// from its embedded program store, passing a write-only console cap as
// our slot 0). Proves: SYS_TASK_SPAWN, cross-task capability transfer,
// and IPC from a dynamically created process.

#[no_mangle]
fn main() -> ! {
    let console = CapSlot(0);
    for i in 1..=3u64 {
        let mut text = alloc::vec::Vec::new();
        text.extend_from_slice(b"hello from spawned task #");
        push_num(&mut text, i);
        text.push(b'\n');
        if console.call(msg::pack(&text)).is_err() {
            sys::exit(9);
        }
    }
    sys::exit(7);
}

fn push_num(out: &mut alloc::vec::Vec<u8>, mut v: u64) {
    if v == 0 {
        out.push(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut n = 0;
    while v > 0 {
        buf[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    while n > 0 {
        n -= 1;
        out.push(buf[n]);
    }
}
