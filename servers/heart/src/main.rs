#![no_std]
#![no_main]

extern crate alloc;

use redoubt_userlib::msg;
use redoubt_userlib::{sys, CapSlot};

// redoubt-heart: the appliance's first supervised service.
//
// Spawned by supd with slot 0 = console (write-only) and slot 1 = the
// query endpoint (call-only). Prints a periodic heartbeat and answers a
// trivial liveness request, giving the supervisor something real to
// restart: `stop heart` / `start heart` from the shell exercises the full
// supervision path, and killing it via fault-test-style faults proves
// restart-under-backoff.

#[no_mangle]
fn main() -> ! {
    redoubt_userlib::set_name("heart");
    let console = CapSlot(0);
    let query = CapSlot(1);

    // announce ourselves in the audit trail (best-effort)
    let _ = query.call(msg::pack(b"log heart started"));

    let mut beats: u64 = 0;
    loop {
        // liveness query: storaged reports the active slot back to us;
        // failure of the storage service must not kill us.
        let _ = query.call(msg::pack(b"slot"));
        beats += 1;
        let mut line: alloc::vec::Vec<u8> = b"[heart] beat ".to_vec();
        push_num(&mut line, beats);
        line.push(b'\n');
        if !redoubt_userlib::print_split(console, &line) {
            sys::exit(9); // console lost
        }
        if redoubt_userlib::sleep(200).is_err() {
            sys::exit(10);
        }
    }
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
