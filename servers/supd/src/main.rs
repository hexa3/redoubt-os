#![no_std]
#![no_main]

extern crate alloc;

use redoubt_userlib::msg;
use redoubt_userlib::{sys, CapSlot};

// redoubt-supd: the application supervisor.
//
// Reads the service roster from the configuration service, spawns every
// autostart service as its own child (fetching program bytes from initfs's
// verified store), and keeps them alive: exits trigger restart with
// exponential backoff, crash-loops are detected, and manual stop/start is
// available to the operator through the shell.
//
// Caps installed by initfs:
//   slot 0 console (w|g)   - transferred (attenuated to w) to services
//   slot 1 initfs  (w)     - fetch protocol for program bytes
//   slot 2 query   (w)     - roster + audit-log writes
//   slot 3 config  (w)     - update initiation
//   slot 4 sup     (r|w)   - served here: status/restart/stop/start/update
//                               plus application install/remove mediation

const MAX_SERVICES: usize = 6;
const BASE_BACKOFF_TICKS: u64 = 20;
const MAX_BACKOFF_TICKS: u64 = 1600;

#[derive(Clone, Copy, PartialEq, Eq)]
enum SvcState {
    Stopped,
    Running(u64), // tid
    Waiting(u64), // resume-at tick
    Failed,
}

struct Service {
    name: alloc::string::String,
    autostart: bool,
    restart: bool,
    state: SvcState,
    failures: u32,
    restarts: u64,
}

#[no_mangle]
fn main() -> ! {
    redoubt_userlib::set_name("supd");
    let console = CapSlot(0);
    let fs = CapSlot(1);
    let query = CapSlot(2);
    let config = CapSlot(3);
    let sup = CapSlot(4);

    say(console, b"[supd] starting\n");

    let mut services: alloc::vec::Vec<Service> = alloc::vec::Vec::new();
    load_roster(query, &mut services);

    for i in 0..services.len() {
        if services[i].autostart {
            spawn_service(i, &mut services, console, fs, query);
        }
    }

    supervise(services, console, fs, query, config, sup)
}

fn say(console: CapSlot, s: &[u8]) {
    let _ = redoubt_userlib::print_split(console, s);
}

fn push_num(out: &mut alloc::vec::Vec<u8>, mut v: u64) {
    if v == 0 {
        out.push(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut n = 0;
    while v > 0 {
        buf[n] = b'0' + (v % 10) as u64 as u8;
        v /= 10;
        n += 1;
    }
    while n > 0 {
        n -= 1;
        out.push(buf[n]);
    }
}

/// Pull the signed roster from storaged. Calls block until storaged
/// listens; ordering guarantees it was spawned before us.
fn load_roster(query: CapSlot, out: &mut alloc::vec::Vec<Service>) {
    let count = match query.call(msg::pack(b"roster-count")) {
        Ok(w) => core::str::from_utf8(&msg::unpack(&w))
            .ok()
            .and_then(|s| s.trim().parse::<usize>().ok())
            .unwrap_or(0),
        Err(_) => 0,
    };
    for i in 0..count.min(MAX_SERVICES) {
        let mut req: alloc::vec::Vec<u8> = b"roster ".to_vec();
        push_num(&mut req, i as u64);
        if let Ok(w) = query.call(msg::pack(&req)) {
            let line = msg::unpack(&w);
            let parts: alloc::vec::Vec<&[u8]> = line
                .split(|&b| b == b' ')
                .filter(|p| !p.is_empty())
                .collect();
            if parts.len() >= 3 {
                out.push(Service {
                    name: alloc::string::String::from(
                        core::str::from_utf8(parts[0]).unwrap_or("?"),
                    ),
                    autostart: parts[1] == b"autostart",
                    restart: parts[2] == b"restart",
                    state: SvcState::Stopped,
                    failures: 0,
                    restarts: 0,
                });
            }
        }
    }
}

/// Fetch program bytes from initfs's verified store. initfs refuses any
/// program absent from its boot-verified manifest, so integrity holds.

fn strip_prefix<'a>(s: &'a [u8], p: &[u8]) -> Option<&'a [u8]> {
    if s.len() >= p.len() && &s[..p.len()] == p {
        Some(&s[p.len()..])
    } else {
        None
    }
}

fn trim(mut s: &[u8]) -> &[u8] {
    while let Some(&f) = s.first() {
        if f == b' ' || f == b'\t' || f == b'\r' {
            s = &s[1..];
        } else {
            break;
        }
    }
    while let Some(&l) = s.last() {
        if l == b' ' || l == b'\t' || l == b'\r' {
            s = &s[..s.len() - 1];
        } else {
            break;
        }
    }
    s
}

fn find_service<'a>(services: &'a mut alloc::vec::Vec<Service>, name: &[u8]) -> Option<usize> {
    services.iter().position(|s| s.name.as_bytes() == name)
}

fn fetch_program(fs: CapSlot, name: &[u8]) -> Result<alloc::vec::Vec<u8>, u64> {
    let mut req: alloc::vec::Vec<u8> = b"fetch ".to_vec();
    req.extend_from_slice(name);
    let reply = fs.call(msg::pack(&req))?;
    let text = msg::unpack(&reply);
    let raw_len: &str = match strip_prefix(&text, b"len ") {
        Some(r) => match core::str::from_utf8(r) {
            Ok(s) => s,
            Err(_) => return Err(17),
        },
        None => return Err(17),
    };
    let len: usize = match raw_len.trim().parse() {
        Ok(v) => v,
        Err(_) => return Err(17),
    };
    if len > 1024 * 1024 {
        return Err(17);
    }

    let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(len);
    while buf.len() < len {
        let mut creq: alloc::vec::Vec<u8> = b"chunk ".to_vec();
        creq.extend_from_slice(name);
        creq.push(b' ');
        push_num(&mut creq, buf.len() as u64);
        let words = fs.call(msg::pack(&creq))?;
        let want = len - buf.len();
        let take = want.min(38);
        let mut tmp = [0u8; 40];
        redoubt_userlib::raw::unpack_all(&words, &mut tmp);
        buf.extend_from_slice(&tmp[..take]);
    }
    Ok(buf)
}

fn spawn_service(
    idx: usize,
    services: &mut alloc::vec::Vec<Service>,
    console: CapSlot,
    fs: CapSlot,
    query: CapSlot,
) -> bool {
    let name = services[idx].name.as_bytes().to_vec();
    let elf = match fetch_program(fs, &name) {
        Ok(e) => e,
        Err(e) => {
            let mut line: alloc::vec::Vec<u8> = b"[supd] fetch '".to_vec();
            line.extend_from_slice(&name);
            line.extend_from_slice(b"' errno ");
            push_num(&mut line, e);
            line.push(b'\n');
            say(console, &line);
            return false;
        }
    };
    // Spawn-time masks attenuate structurally: children receive our
    // console (write-only, no re-delegation) and the query endpoint
    // (call-only). No pre-derivation - a W-only copy would have lost its
    // grant bit and become untransferable.
    match redoubt_userlib::spawn(
        &elf,
        &[
            (CapSlot(0), redoubt_userlib::R_WRITE),
            (CapSlot(2), redoubt_userlib::R_WRITE),
        ],
    ) {
        Ok(tid) => {
            services[idx].state = SvcState::Running(tid);
            services[idx].failures = 0;
            let mut line: alloc::vec::Vec<u8> = b"svc-start ".to_vec();
            line.extend_from_slice(&name);
            audit(query, &line, b"");
            true
        }
        Err(_) => {
            services[idx].state = SvcState::Failed;
            false
        }
    }
}

fn audit(query: CapSlot, head: &[u8], tail: &[u8]) {
    let mut req: alloc::vec::Vec<u8> = b"log ".to_vec();
    req.extend_from_slice(head);
    req.extend_from_slice(tail);
    req.truncate(38); // IPC payload budget
    let _ = query.call(msg::pack(&req));
}

/// The supervision loop: reap exited children with backoff, respawn what
/// is due, and answer operator requests. Single-threaded by design - the
/// kernel's recv deadlines make polling possible without threads.
fn supervise(
    mut services: alloc::vec::Vec<Service>,
    console: CapSlot,
    fs: CapSlot,
    query: CapSlot,
    config: CapSlot,
    sup: CapSlot,
) -> ! {
    loop {
        // ---- reap exited children ----
        while let Ok(Some((tid, code))) = redoubt_userlib::try_wait() {
            let mut line: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
            let mut idx = None;
            for (i, s) in services.iter_mut().enumerate() {
                if let SvcState::Running(rtid) = s.state {
                    if rtid == tid {
                        s.state = SvcState::Stopped;
                        s.failures += 1;
                        idx = Some(i);
                    }
                }
            }
            if let Some(i) = idx {
                let backoff = BASE_BACKOFF_TICKS << (services[i].failures.min(7) as u64);
                let backoff = backoff.min(MAX_BACKOFF_TICKS);
                if services[i].restart && services[i].failures <= 5 {
                    let at = redoubt_userlib::ticks() + backoff;
                    services[i].state = SvcState::Waiting(at);
                } else {
                    services[i].state = SvcState::Failed;
                }
                line.extend_from_slice(b"svc-exit ");
                line.extend_from_slice(services[i].name.as_bytes());
                line.extend_from_slice(b" code ");
                push_num(&mut line, code);
                audit(query, &line, b"");
            } else {
                line.extend_from_slice(b"unknown-child ");
                push_num(&mut line, tid);
                audit(query, &line, b"");
            }
        }

        // ---- respawn due services ----
        let now = redoubt_userlib::ticks();
        let mut next_deadline = u64::MAX;
        for i in 0..services.len() {
            if let SvcState::Waiting(at) = services[i].state {
                if at <= now {
                    spawn_service(i, &mut services, console, fs, query);
                    services[i].restarts += 1;
                } else {
                    next_deadline = next_deadline.min(at);
                }
            }
        }

        // ---- listen for operators until the next restart is due ----
        let deadline = next_deadline.min(now + 200);
        match sup.recv_until(deadline.max(now + 1)) {
            Ok((_, words)) => {
                let req = msg::unpack(&words);
                let reply = handle_op(&mut services, console, fs, query, config, &req);
                sup.reply(msg::pack(&reply));
            }
            Err(e) => {
                if e == 10 {
                    continue; // E_TIMEDOUT: just our poll boundary
                }
                sys::exit(e); // lost our capability
            }
        }
    }
}

fn handle_op(
    services: &mut alloc::vec::Vec<Service>,
    console: CapSlot,
    fs: CapSlot,
    query: CapSlot,
    config: CapSlot,
    req: &[u8],
) -> alloc::vec::Vec<u8> {
    if req == b"status-count" {
        let mut v: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        push_num(&mut v, services.len() as u64);
        return v;
    }
    if let Some(rest) = strip_prefix(req, b"status ") {
        let idx: usize = core::str::from_utf8(trim(rest))
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(usize::MAX);
        if let Some(s) = services.get(idx) {
            let mut v: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
            v.extend_from_slice(s.name.as_bytes());
            v.push(b' ');
            match s.state {
                SvcState::Running(_) => v.extend_from_slice(b"running"),
                SvcState::Stopped => v.extend_from_slice(b"stopped"),
                SvcState::Waiting(_) => v.extend_from_slice(b"backoff"),
                SvcState::Failed => v.extend_from_slice(b"FAILED"),
            }
            v.extend_from_slice(b" r=");
            push_num(&mut v, s.restarts);
            v.extend_from_slice(b" f=");
            push_num(&mut v, s.failures as u64);
            return v;
        }
        return b"err: range".to_vec();
    }
    if let Some(rest) = strip_prefix(req, b"restart ") {
        let name = trim(rest);
        if let Some(idx) = find_service(services, name) {
            if let SvcState::Running(tid) = services[idx].state {
                let _ = redoubt_userlib::kill(tid);
                // exit is reaped on the next loop pass; force immediate path
                services[idx].restart = true;
                services[idx].failures = 0;
                services[idx].state = SvcState::Waiting(redoubt_userlib::ticks() + 1);
                drain_one(services, console, fs, query);
                return b"ok restarting".to_vec();
            }
            services[idx].failures = 0;
            services[idx].restart = true;
            if spawn_service(idx, services, console, fs, query) {
                return b"ok started".to_vec();
            }
            return b"err: spawn failed".to_vec();
        }
        return b"err: unknown".to_vec();
    }
    if let Some(rest) = strip_prefix(req, b"stop ") {
        let name = trim(rest);
        if let Some(idx) = find_service(services, name) {
            match services[idx].state {
                SvcState::Running(tid) => {
                    services[idx].restart = false; // stay down when killed
                    let _ = redoubt_userlib::kill(tid);
                    drain_one(services, console, fs, query);
                    return b"ok stopping".to_vec();
                }
                _ => {
                    services[idx].restart = false;
                    return b"ok already-down".to_vec();
                }
            }
        }
        return b"err: unknown".to_vec();
    }
    if let Some(rest) = strip_prefix(req, b"start ") {
        let name = trim(rest);
        if let Some(idx) = find_service(services, name) {
            services[idx].restart = true;
            services[idx].failures = 0;
            if matches!(services[idx].state, SvcState::Running(_)) {
                return b"ok already-up".to_vec();
            }
            if spawn_service(idx, services, console, fs, query) {
                return b"ok started".to_vec();
            }
            return b"err: spawn failed".to_vec();
        }
        return b"err: unknown".to_vec();
    }
    if req == b"update" {
        match config.call(msg::pack(b"begin-update")) {
            Ok(w) => return msg::unpack(&w),
            Err(e) => {
                let mut v: alloc::vec::Vec<u8> = b"err: storage ".to_vec();
                push_num(&mut v, e);
                return v;
            }
        }
    }
    if req == b"install-app" || req.strip_prefix(b"remove-app ").is_some() {
        match config.call(msg::pack(req)) {
            Ok(w) => return msg::unpack(&w),
            Err(e) => {
                let mut v: alloc::vec::Vec<u8> = b"err: storage ".to_vec();
                push_num(&mut v, e);
                return v;
            }
        }
    }
    b"err: op?".to_vec()
}

/// Reap exactly one exited child (used right after kill so replies reflect
/// the new state). Runs the same accounting as the main loop.
fn drain_one(
    services: &mut alloc::vec::Vec<Service>,
    console: CapSlot,
    fs: CapSlot,
    query: CapSlot,
) {
    let _ = (&console, &fs);
    if let Ok(Some((tid, _code))) = redoubt_userlib::try_wait() {
        for s in services.iter_mut() {
            if let SvcState::Running(rtid) = s.state {
                if rtid == tid {
                    s.state = SvcState::Stopped;
                }
            }
        }
    } else {
        // child may need another scheduling round; yield briefly
        redoubt_userlib::sleep(2).ok();
        if let Ok(Some((tid, _code))) = redoubt_userlib::try_wait() {
            for s in services.iter_mut() {
                if let SvcState::Running(rtid) = s.state {
                    if rtid == tid {
                        s.state = SvcState::Stopped;
                    }
                }
            }
        }
        let _ = query;
    }
}
