#![no_std]
#![no_main]

extern crate alloc;

use redoubt_userlib::msg;
use redoubt_userlib::{sys, CapSlot};

// redoubt-shell: the interactive face of redoubt.
//
// Spawned by initfs with slot 0 = console (write-only), slot 1 = initfs
// endpoint (exec), slot 2 = query endpoint (storage reads), slot 3 = sup
// endpoint (supervisor control), and slot 4 = stdin (call-only). Everything
// typed at the keyboard flows:
// IRQ1 -> kernel decode -> console line editor -> this loop. Every command
// exercises the IPC + capability machinery.
//
// Operator surface: help, echo, hello, exec, services, start/stop/restart,
// update, app install/list/run/remove, slot, get, audit, uptime, stats,
// reboot.

const SOH: u8 = 0x01;

struct Console {
    out: CapSlot,
    stdin: CapSlot,
}

impl Console {
    /// Verbatim output (no [tid] prefix), chunked past the IPC budget.
    fn print(&self, s: &[u8]) -> bool {
        redoubt_userlib::print_split(self.out, s)
    }

    /// Line reads ride the dedicated stdin endpoint so a half-typed line
    /// never blocks system output anywhere.
    fn read_line(&self) -> alloc::vec::Vec<u8> {
        match self.stdin.call(msg::pack(b"read")) {
            Ok(words) => msg::unpack(&words),
            Err(e) => {
                let mut m: alloc::vec::Vec<u8> = b"[read-errno ".to_vec();
                push_num(&mut m, e);
                m.push(b']');
                redoubt_userlib::print_split(self.out, &m);
                alloc::vec::Vec::new()
            }
        }
    }
}

#[no_mangle]
fn main() -> ! {
    let console = Console {
        out: CapSlot(0),
        stdin: CapSlot(4),
    };
    let initfs = CapSlot(1);
    let query = CapSlot(2);
    let sup = CapSlot(3);

    // NOTE: IPC payload budget is 40 packed bytes per message; every string
    // sent here must stay under it including its newline.
    console.print(b"redoubt shell ready. type 'help'.\n");
    loop {
        console.print(b"> ");
        let line = console.read_line();
        let text = trim(&line);
        if text.is_empty() {
            continue;
        }
        if !execute(&console, &initfs, &query, &sup, text) {
            sys::exit(8); // console lost
        }
    }
}

/// Returns false only if the console endpoint failed.
fn execute(
    console: &Console,
    initfs: &CapSlot,
    query: &CapSlot,
    sup: &CapSlot,
    line: &[u8],
) -> bool {
    let (cmd, rest) = split_cmd(line);
    match cmd {
        b"help" => help(console),
        b"echo" => {
            let mut out = alloc::vec::Vec::with_capacity(rest.len() + 1);
            out.extend_from_slice(rest);
            out.push(b'\n');
            console.print(&out)
        }
        b"hello" => exec_req(console, initfs, b"hello"),
        b"exec" => exec_req(console, initfs, rest),
        b"services" => services_cmd(console, sup),
        b"start" | b"stop" | b"restart" => svc_action(console, sup, cmd, rest),
        b"update" => call_print(console, sup, b"update"),
        b"apps" => apps_cmd(console, query),
        b"app" => app_cmd(console, initfs, query, sup, rest),
        b"slot" => call_print(console, query, b"slot"),
        b"recovery" => recovery_cmd(console, query, sup, rest),
        b"get" => {
            if rest.is_empty() {
                return console.print(b"usage: get <key>\n");
            }
            let mut req: alloc::vec::Vec<u8> = b"get ".to_vec();
            req.extend_from_slice(rest);
            req.truncate(38);
            call_print(console, query, &req)
        }
        b"audit" => audit_cmd(console, query),
        b"uptime" => {
            let mut out: alloc::vec::Vec<u8> = b"up ".to_vec();
            push_num(&mut out, redoubt_userlib::ticks() / 100);
            out.extend_from_slice(b" s (");
            push_num(&mut out, redoubt_userlib::ticks());
            out.extend_from_slice(b" ticks)\n");
            console.print(&out)
        }
        b"stats" => match redoubt_userlib::stats() {
            Ok(st) => {
                let mut l1: alloc::vec::Vec<u8> = b"frames used/total: ".to_vec();
                push_num(&mut l1, st.frames_used);
                l1.push(b'/');
                push_num(&mut l1, st.frames_total);
                l1.push(b'\n');
                let ok = console.print(&l1);
                let mut l2: alloc::vec::Vec<u8> = b"my pages: ".to_vec();
                push_num(&mut l2, st.my_pages);
                l2.extend_from_slice(b"; tasks: ");
                push_num(&mut l2, st.ntasks as u64);
                l2.push(b'\n');
                console.print(&l2) && ok
            }
            Err(_) => console.print(b"stats unavailable\n"),
        },
        b"reboot" => {
            console.print(b"rebooting now\n");
            redoubt_userlib::reboot()
        }
        _ => {
            let shown = &line[..line.len().min(16)];
            let mut out: alloc::vec::Vec<u8> = b"? unknown '".to_vec();
            out.extend_from_slice(shown);
            out.extend_from_slice(b"' (try help)\n");
            console.print(&out)
        }
    }
}

fn help(console: &Console) -> bool {
    // one message per line: IPC payloads cap at 40 packed bytes
    for chunk in [
        &b"commands:"[..],
        b"  echo <text>      print text",
        b"  exec <name>      run store program",
        b"  services         list supervised services",
        b"  start|stop|restart <name>",
        b"  update           apply staged update",
        b"  apps             list installed apps",
        b"  app install; run|remove <name>",
        b"  slot             active system slot",
        b"  recovery status|select <a|b> confirm",
        b"  get <key>        read configuration",
        b"  audit [count]    recent audit records",
        b"  uptime, stats, reboot",
    ] {
        let mut m = alloc::vec![SOH];
        m.extend_from_slice(chunk);
        m.push(b'\n');
        if console.out.call(msg::pack(&m)).is_err() {
            return false;
        }
    }
    true
}

/// Offline recovery is deliberately narrow: it can inspect both slots and
/// select only a slot that storaged independently verifies. A selection is
/// staged in the authenticated superblock and takes effect after reboot.
fn recovery_cmd(console: &Console, query: &CapSlot, sup: &CapSlot, rest: &[u8]) -> bool {
    match rest {
        b"status" => {
            call_print(console, query, b"slot")
                && call_print(console, query, b"slot-a")
                && call_print(console, query, b"slot-b")
        }
        _ => {
            let (verb, tail) = split_cmd(rest);
            if verb != b"select" {
                return console.print(b"usage: recovery status|select <a|b> confirm\n");
            }
            let (slot, confirmation) = split_cmd(tail);
            if (slot != b"a" && slot != b"b") || confirmation.is_empty() {
                return console.print(b"usage: recovery select <a|b> confirm\n");
            }
            let mut req = b"select-slot ".to_vec();
            req.extend_from_slice(slot);
            req.push(b' ');
            req.extend_from_slice(confirmation);
            call_print(console, sup, &req)
        }
    }
}

fn apps_cmd(console: &Console, query: &CapSlot) -> bool {
    let count = match query.call(msg::pack(b"app-count")) {
        Ok(w) => core::str::from_utf8(&msg::unpack(&w))
            .ok()
            .and_then(|s| s.trim().parse::<usize>().ok())
            .unwrap_or(0),
        Err(e) => return err_print(console, b"apps failed", e),
    };
    if count == 0 {
        return console.print(b"no installed apps\n");
    }
    for i in 0..count {
        let mut req: alloc::vec::Vec<u8> = b"app-list ".to_vec();
        push_num(&mut req, i as u64);
        match query.call(msg::pack(&req)) {
            Ok(w) => {
                let mut out = msg::unpack(&w);
                out.push(b'\n');
                if !console.print(&out) {
                    return false;
                }
            }
            Err(e) => return err_print(console, b"apps failed", e),
        }
    }
    true
}

fn app_cmd(
    console: &Console,
    initfs: &CapSlot,
    query: &CapSlot,
    sup: &CapSlot,
    rest: &[u8],
) -> bool {
    let (verb, name) = split_cmd(rest);
    match verb {
        b"list" => apps_cmd(console, query),
        b"install" if name.is_empty() => call_print(console, sup, b"install-app"),
        b"run" if !name.is_empty() => {
            let mut req: alloc::vec::Vec<u8> = b"app ".to_vec();
            req.extend_from_slice(name);
            call_print(console, initfs, &req)
        }
        b"remove" if !name.is_empty() => {
            let mut req: alloc::vec::Vec<u8> = b"remove-app ".to_vec();
            req.extend_from_slice(name);
            call_print(console, sup, &req)
        }
        _ => console.print(b"usage: app install|list|run|remove <name>\n"),
    }
}

fn call_print(console: &Console, ep: &CapSlot, req: &[u8]) -> bool {
    match ep.call(msg::pack(req)) {
        Ok(reply) => {
            let mut out = msg::unpack(&reply);
            out.push(b'\n');
            console.print(&out)
        }
        Err(e) => err_print(console, b"request failed", e),
    }
}

fn err_print(console: &Console, what: &[u8], e: u64) -> bool {
    let mut out: alloc::vec::Vec<u8> = alloc::vec![SOH as u8];
    out.clear();
    out.extend_from_slice(what);
    out.extend_from_slice(b" (errno ");
    push_num(&mut out, e);
    out.extend_from_slice(b")\n");
    console.print(&out)
}

/// `services`: count then one line per service.
fn services_cmd(console: &Console, sup: &CapSlot) -> bool {
    let count = match sup.call(msg::pack(b"status-count")) {
        Ok(w) => core::str::from_utf8(&msg::unpack(&w))
            .ok()
            .and_then(|s| s.trim().parse::<usize>().ok())
            .unwrap_or(0),
        Err(e) => return err_print(console, b"services failed", e),
    };
    for i in 0..count {
        let mut req: alloc::vec::Vec<u8> = b"status ".to_vec();
        push_num(&mut req, i as u64);
        match sup.call(msg::pack(&req)) {
            Ok(w) => {
                let mut out = msg::unpack(&w);
                out.push(b'\n');
                if !console.print(&out) {
                    return false;
                }
            }
            Err(e) => return err_print(console, b"services failed", e),
        }
    }
    true
}

fn svc_action(console: &Console, sup: &CapSlot, verb: &[u8], name: &[u8]) -> bool {
    if name.is_empty() {
        let mut out: alloc::vec::Vec<u8> = b"usage: ".to_vec();
        out.extend_from_slice(verb);
        out.extend_from_slice(b" <name>\n");
        return console.print(&out);
    }
    let mut req: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(name.len() + 9);
    req.extend_from_slice(verb);
    req.push(b' ');
    req.extend_from_slice(name);
    req.truncate(38);
    match sup.call(msg::pack(&req)) {
        Ok(reply) => {
            let mut out = msg::unpack(&reply);
            out.push(b'\n');
            console.print(&out)
        }
        Err(e) => err_print(console, b"operation failed", e),
    }
}

/// `audit [n]`: newest n (max 8) records, oldest first.
fn audit_cmd(console: &Console, query: &CapSlot) -> bool {
    let total = match query.call(msg::pack(b"auditcount")) {
        Ok(w) => core::str::from_utf8(&msg::unpack(&w))
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0),
        Err(e) => return err_print(console, b"audit failed", e),
    };
    let show = total.min(8);
    for i in (total - show)..total {
        let mut req: alloc::vec::Vec<u8> = b"audit ".to_vec();
        push_num(&mut req, i);
        match query.call(msg::pack(&req)) {
            Ok(w) => {
                let mut out = msg::unpack(&w);
                out.push(b'\n');
                if !console.print(&out) {
                    return false;
                }
            }
            Err(e) => return err_print(console, b"audit failed", e),
        }
    }
    true
}

fn exec_req(console: &Console, initfs: &CapSlot, name: &[u8]) -> bool {
    let mut req = alloc::vec::Vec::with_capacity(name.len() + 5);
    req.extend_from_slice(b"exec ");
    req.extend_from_slice(name);
    match initfs.call(msg::pack(&req)) {
        Ok(reply) => {
            let mut out = msg::unpack(&reply);
            out.push(b'\n');
            console.print(&out)
        }
        Err(e) => err_print(console, b"exec request failed", e),
    }
}

fn split_cmd(line: &[u8]) -> (&[u8], &[u8]) {
    match line.iter().position(|&c| c == b' ') {
        Some(i) => (&line[..i], trim(&line[i..])),
        None => (line, b""),
    }
}

fn trim(mut s: &[u8]) -> &[u8] {
    while let Some(&f) = s.first() {
        if f == b' ' || f == b'\t' {
            s = &s[1..];
        } else {
            break;
        }
    }
    while let Some(&l) = s.last() {
        if l == b' ' || l == b'\t' {
            s = &s[..s.len() - 1];
        } else {
            break;
        }
    }
    s
}

fn push_num(out: &mut alloc::vec::Vec<u8>, v: u64) {
    let mut v = v;
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
