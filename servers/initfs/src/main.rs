#![no_std]
#![no_main]

extern crate alloc;

use redoubt_crypto::{ed25519, sha256};
use redoubt_userlib::msg;
use redoubt_userlib::{sys, CapSlot};

// redoubt-initfs: init program, program store, exec + fetch services.
//
// The embedded program store is covered by an Ed25519-signed manifest that
// is verified against a pinned public key BEFORE anything runs. Every
// launch path (exec for interactive programs, fetch for supervisors)
// re-checks the digest of the exact bytes handed out; a mismatch fails
// closed. This is the device-side half of invariant #3: all booted code is
// verified before execution.
//
// Boot sequence:
//   1. verify store manifest signature (fail closed on mismatch)
//   2. capability sanity demo (delegation from non-grant must be refused)
//   3. spawn storaged (volume, config, audit) and supd (supervisor),
//      transferring only attenuated capabilities downward
//   4. spawn the interactive shell
//   5. serve forever:
//        exec <name>   - run to completion, reap, reply with status
//        fetch <name>  - chunked transfer for supervisors that spawn
//
// Caps installed by the kernel:
//   slot0 console(w|g), slot1 fs(r|w|g), slot2 config(w|g),
//   slot3 sup(w|g), slot4 query(r|w|g), slot5 stdin(w|g),
//   slot6 block(r|w|g when a volume disk exists)

static MANIFEST: &[u8] = include_bytes!(env!("REDOUBT_STORE_MANIFEST"));
static SIG: &[u8] = include_bytes!(env!("REDOUBT_STORE_SIG"));
static PUB_HEX: &str = env!("REDOUBT_STORE_PUB");

static HELLO_ELF: &[u8] = include_bytes!(env!("REDOUBT_ELF_HELLO"));
static FAULT_TEST_ELF: &[u8] = include_bytes!(env!("REDOUBT_ELF_FAULT_TEST"));
static HEART_ELF: &[u8] = include_bytes!(env!("REDOUBT_ELF_HEART"));
static SHELL_ELF: &[u8] = include_bytes!(env!("REDOUBT_ELF_SHELL"));
static STORAGED_ELF: &[u8] = include_bytes!(env!("REDOUBT_ELF_STORAGED"));
static SUPD_ELF: &[u8] = include_bytes!(env!("REDOUBT_ELF_SUPD"));

/// Kernel installs the whole-disk block cap at our slot 6 when a volume
/// disk exists. Probe cheaply via a range-narrowed derive.
fn block_present() -> bool {
    CapSlot(6)
        .derive_block(redoubt_userlib::R_READ, 0, 1)
        .is_ok()
}

fn store() -> [(&'static [u8], &'static [u8]); 6] {
    [
        (b"hello", HELLO_ELF),
        (b"fault-test", FAULT_TEST_ELF),
        (b"heart", HEART_ELF),
        (b"shell", SHELL_ELF),
        (b"storaged", STORAGED_ELF),
        (b"supd", SUPD_ELF),
    ]
}

fn say(s: &[u8]) {
    sys::debug_write(s);
}

fn say_num(prefix: &[u8], v: u64, suffix: &[u8]) {
    let mut line = alloc::vec::Vec::with_capacity(prefix.len() + 22 + suffix.len());
    line.extend_from_slice(prefix);
    push_num(&mut line, v);
    line.extend_from_slice(suffix);
    say(&line);
}

fn pinned_pubkey() -> [u8; ed25519::PUBLIC_LEN] {
    let mut k = [0u8; 32];
    for i in 0..32 {
        k[i] = u8::from_str_radix(PUB_HEX.get(i * 2..i * 2 + 2).unwrap_or("zz"), 16).unwrap_or(0);
    }
    k
}

struct ManifestEntry {
    name: [u8; 16],
    name_len: usize,
    len: usize,
    sha: [u8; 32],
}

/// Parse "name len hexdigest" lines after the header line.
fn parse_manifest(m: &[u8]) -> alloc::vec::Vec<ManifestEntry> {
    let mut out = alloc::vec::Vec::new();
    for line in m.split(|&b| b == b'\n').skip(1) {
        let parts: alloc::vec::Vec<&[u8]> = line
            .split(|&b| b == b' ')
            .filter(|p| !p.is_empty())
            .collect();
        if parts.len() != 3 {
            continue;
        }
        let mut e = ManifestEntry {
            name: [0u8; 16],
            name_len: 0,
            len: 0,
            sha: [0u8; 32],
        };
        let n = parts[0].len().min(16);
        e.name[..n].copy_from_slice(&parts[0][..n]);
        e.name_len = n;
        if core::str::from_utf8(parts[2]).unwrap_or("").len() != 64 {
            continue;
        }
        let mut ok = true;
        for i in 0..32 {
            match u8::from_str_radix(
                core::str::from_utf8(parts[2])
                    .unwrap_or("")
                    .get(i * 2..i * 2 + 2)
                    .unwrap_or("zz"),
                16,
            ) {
                Ok(b) => e.sha[i] = b,
                Err(_) => {
                    ok = false;
                    break;
                }
            }
        }
        match core::str::from_utf8(parts[1])
            .unwrap_or("")
            .parse::<usize>()
        {
            Ok(v) => e.len = v,
            Err(_) => ok = false,
        }
        if ok && e.name_len > 0 {
            out.push(e);
        }
    }
    out
}

#[no_mangle]
fn main() -> ! {
    say(b"initfs: userspace alive\n");

    // ---- 1: verify the program store before ANY launch path opens ------
    let mut sig = [0u8; 64];
    if SIG.len() == 64 {
        sig.copy_from_slice(SIG);
    } else {
        say(b"initfs: FATAL manifest signature malformed\n");
        sys::exit(9);
    }
    match ed25519::verify(&pinned_pubkey(), MANIFEST, &sig) {
        Ok(()) => say(b"initfs: program store signature VERIFIED\n"),
        Err(_) => {
            say(b"initfs: FATAL program store FAILED SIGNATURE - refusing\n");
            sys::exit(9);
        }
    }
    let manifest = parse_manifest(MANIFEST);
    // every store entry must be covered by the manifest
    for (name, elf) in store().iter() {
        let covered = manifest.iter().any(|e| {
            e.name_len == name.len()
                && e.name[..e.name_len] == **name
                && e.len == elf.len()
                && e.sha == sha256::sha256(elf)
        });
        if !covered {
            say_num(
                b"initfs: FATAL store digest mismatch: '",
                name[0] as u64,
                b"'\n",
            );
            sys::exit(9);
        }
    }

    let console = CapSlot(0);
    let fs = CapSlot(1);
    let cfg = CapSlot(2);
    let sup = CapSlot(3);
    let info = CapSlot(4);
    let stdin = CapSlot(5);

    // ---- 2: capability invariant demo -----------------------------------
    // Delegation from a non-grant capability must be structurally refused.
    let w_only = match console.derive(redoubt_userlib::R_WRITE) {
        Ok(slot) => slot,
        Err(e) => {
            say_num(b"initfs: derive failed errno ", e, b"\n");
            sys::exit(4);
        }
    };
    match redoubt_userlib::spawn(HELLO_ELF, &[(w_only, redoubt_userlib::R_WRITE)]) {
        Ok(_) => {
            say(b"initfs: BUG: delegation via non-grant cap succeeded!\n");
            sys::exit(3);
        }
        Err(e) => say_num(
            b"initfs: spawn via non-grant cap DENIED as expected (errno ",
            e,
            b")\n",
        ),
    }

    // ---- 3: storage + supervisor ----------------------------------------
    // storaged gets console(w), query+config endpoints (rw), and the whole-
    // disk block cap (slot 4) when present. It cannot touch our endpoint.
    // storaged gets console(w), both storage endpoints (rw), and the
    // whole-disk block cap when present. It cannot touch our endpoint.
    let storaged_grants: alloc::vec::Vec<(CapSlot, u64)> = {
        let mut v = alloc::vec![
            (console, redoubt_userlib::R_WRITE),
            (info, redoubt_userlib::R_READ | redoubt_userlib::R_WRITE),
            (cfg, redoubt_userlib::R_READ | redoubt_userlib::R_WRITE),
        ];
        if block_present() {
            v.push((
                CapSlot(6),
                redoubt_userlib::R_READ | redoubt_userlib::R_WRITE | redoubt_userlib::R_GRANT,
            ));
        }
        v
    };
    let _storaged = match redoubt_userlib::spawn(STORAGED_ELF, &storaged_grants) {
        Ok(t) => t,
        Err(e) => {
            say_num(b"initfs: STORAGED SPAWN FAILED errno ", e, b"\n");
            sys::exit(5);
        }
    };
    say(b"initfs: storaged launched\n");

    // supd gets its own console grant (to hand down), fs access for fetch,
    // read/write into storage, and stewardship of the sup endpoint.
    let _supd = match redoubt_userlib::spawn(
        SUPD_ELF,
        &[
            (console, redoubt_userlib::R_WRITE | redoubt_userlib::R_GRANT),
            (fs, redoubt_userlib::R_WRITE),
            (info, redoubt_userlib::R_WRITE | redoubt_userlib::R_GRANT),
            (cfg, redoubt_userlib::R_WRITE),
            (sup, redoubt_userlib::R_READ | redoubt_userlib::R_WRITE),
        ],
    ) {
        Ok(t) => t,
        Err(e) => {
            say_num(b"initfs: SUPD SPAWN FAILED errno ", e, b"\n");
            sys::exit(5);
        }
    };
    say(b"initfs: supervisor launched\n");

    // ---- 4: shell --------------------------------------------------------
    match redoubt_userlib::spawn(
        SHELL_ELF,
        &[
            (console, redoubt_userlib::R_WRITE),
            (fs, redoubt_userlib::R_WRITE),
            (info, redoubt_userlib::R_WRITE),
            (sup, redoubt_userlib::R_WRITE),
            (stdin, redoubt_userlib::R_WRITE),
        ],
    ) {
        Ok(_t) => say(b"initfs: shell launched\n"),
        Err(e) => say_num(b"initfs: SHELL SPAWN FAILED errno ", e, b"\n"),
    }

    // ---- 5: exec/fetch service loop --------------------------------------
    serve(console, fs, info)
}

fn serve(console: CapSlot, fs: CapSlot, info: CapSlot) -> ! {
    loop {
        let (_caller, words) = match fs.recv() {
            Ok(r) => r,
            Err(e) => sys::exit(e),
        };
        let req = msg::unpack(&words);
        let reply: alloc::vec::Vec<u8> = dispatch_req(&req, console, info);
        fs.reply(msg::pack(&reply));
    }
}

fn dispatch_req(req: &[u8], console: CapSlot, info: CapSlot) -> alloc::vec::Vec<u8> {
    if let Some(rest) = req.strip_prefix(b"exec ".as_slice()) {
        return run_program(trim(rest), console);
    }
    if let Some(rest) = req.strip_prefix(b"app ".as_slice()) {
        return run_installed_app(trim(rest), console, info);
    }
    if let Some(rest) = req.strip_prefix(b"fetch ".as_slice()) {
        let name = trim(rest);
        return fetch_meta(name);
    }
    if req.strip_prefix(b"chunk ".as_slice()).is_some() {
        return handle_chunk(req);
    }
    b"err: usage 'exec <name>', 'app <name>', or 'fetch <name>'".to_vec()
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

fn lookup(name: &[u8]) -> Option<&'static [u8]> {
    store()
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, elf)| *elf)
}

fn fetch_meta(name: &[u8]) -> alloc::vec::Vec<u8> {
    let Some(_elf) = lookup(name) else {
        let mut out = b"err: no such program '".to_vec();
        out.extend_from_slice(name);
        out.push(b'\'');
        return out;
    };
    let mut out = b"len ".to_vec();
    push_num(&mut out, lookup(name).unwrap().len() as u64);
    out
}

/// Chunked transfer: 38 payload bytes per call (fits msg budget).
fn handle_chunk(req: &[u8]) -> alloc::vec::Vec<u8> {
    let rest = match req.strip_prefix(b"chunk ".as_slice()) {
        Some(r) => r,
        None => return b"err: bad".to_vec(),
    };
    let sp = match rest.iter().rposition(|&c| c == b' ') {
        Some(i) => i,
        None => return b"err: bad".to_vec(),
    };
    let name = trim(&rest[..sp]);
    let off: usize = match core::str::from_utf8(trim(&rest[sp + 1..]))
        .ok()
        .and_then(|s| s.parse().ok())
    {
        Some(o) => o,
        None => return b"err: bad offset".to_vec(),
    };
    let Some(elf) = lookup(name) else {
        return b"err: no such program".to_vec();
    };
    if off >= elf.len() {
        return alloc::vec::Vec::new();
    }
    let end = (off + 38).min(elf.len());
    // Binary-safe: return exactly 40 zero-padded bytes. msg::pack over
    // these is lossless, and the client decodes with raw::unpack_all.
    let mut tmp = [0u8; 40];
    tmp[..end - off].copy_from_slice(&elf[off..end]);
    tmp.to_vec()
}

/// Interactive exec: launch with its own console grant, wait for exit,
/// reply with the status. Digest verification happened at boot; the bytes
/// we spawn are the same static slice we hashed.
fn run_program(name: &[u8], console: CapSlot) -> alloc::vec::Vec<u8> {
    let Some(elf) = lookup(name) else {
        let mut out = b"err: no such program '".to_vec();
        out.extend_from_slice(name);
        out.push(b'\'');
        return out;
    };
    match redoubt_userlib::spawn(elf, &[(console, redoubt_userlib::R_WRITE)]) {
        Ok(tid) => match redoubt_userlib::wait() {
            Ok((done_tid, code)) if done_tid == tid => {
                let mut out = b"ok: '".to_vec();
                out.extend_from_slice(name);
                out.extend_from_slice(b"' exited ");
                push_num(&mut out, code);
                out
            }
            Ok((done_tid, code)) => {
                let mut out = b"err: reaped unexpected tid ".to_vec();
                push_num(&mut out, done_tid);
                out.extend_from_slice(b" code ");
                push_num(&mut out, code);
                out
            }
            Err(e) => {
                let mut out = b"err: wait failed errno ".to_vec();
                push_num(&mut out, e);
                out
            }
        },
        Err(e) => {
            let mut out = b"err: spawn failed errno ".to_vec();
            push_num(&mut out, e);
            out
        }
    }
}

// -------------------------------------------------------- installed programs

/// Installed apps live in storaged's encrypted paired-slot store. initfs
/// does not trust a storage reply merely because it came from an endpoint it
/// holds: it reassembles the ELF, hashes it, and checks the package signature
/// against the same pinned public key used by the verified system store.
fn run_installed_app(name: &[u8], console: CapSlot, info: CapSlot) -> alloc::vec::Vec<u8> {
    if name.is_empty() || name.len() > redoubt_crypto::layout::APP_NAME_MAX {
        return b"err: invalid app".to_vec();
    }
    let (len, version) = match app_info(info, name) {
        Some(v) => v,
        None => return b"err: no verified app".to_vec(),
    };
    if len == 0 || len > redoubt_crypto::layout::APP_STAGE_CAP {
        return b"err: app bounds".to_vec();
    }
    let digest = match app_fixed(info, b"ah ", name, 0, 32) {
        Some(v) => {
            let mut d = [0u8; 32];
            d.copy_from_slice(&v[..32]);
            d
        }
        None => return b"err: app metadata".to_vec(),
    };
    let mut sig = [0u8; 64];
    for off in [0usize, 40usize] {
        let want = if off == 0 { 40 } else { 24 };
        let Some(bytes) = app_fixed(info, b"as ", name, off, want) else {
            return b"err: app signature".to_vec();
        };
        sig[off..off + want].copy_from_slice(&bytes[..want]);
    }
    let mut elf = alloc::vec::Vec::with_capacity(len);
    while elf.len() < len {
        let mut req: alloc::vec::Vec<u8> = b"ac ".to_vec();
        req.extend_from_slice(name);
        req.push(b' ');
        push_num(&mut req, elf.len() as u64);
        let words = match info.call(msg::pack(&req)) {
            Ok(w) => w,
            Err(_) => return b"err: app fetch".to_vec(),
        };
        let mut raw = [0u8; 40];
        redoubt_userlib::raw::unpack_all(&words, &mut raw);
        let take = (len - elf.len()).min(raw.len());
        elf.extend_from_slice(&raw[..take]);
    }
    if sha256::sha256(&elf) != digest {
        return b"err: app digest".to_vec();
    }
    let signed = redoubt_crypto::layout::app_signing_message(name, version, len, &digest);
    if ed25519::verify(&pinned_pubkey(), &signed, &sig) != Ok(()) {
        return b"err: app signature".to_vec();
    }
    match redoubt_userlib::spawn(&elf, &[(console, redoubt_userlib::R_WRITE)]) {
        Ok(tid) => match redoubt_userlib::wait() {
            Ok((done, code)) if done == tid => {
                let mut out = b"ok app '".to_vec();
                out.extend_from_slice(name);
                out.extend_from_slice(b"' exited ");
                push_num(&mut out, code);
                out
            }
            Ok((done, _)) => {
                let mut out = b"err: app reaped ".to_vec();
                push_num(&mut out, done);
                out
            }
            Err(_) => b"err: app wait".to_vec(),
        },
        Err(_) => b"err: app spawn".to_vec(),
    }
}

fn app_info(info: CapSlot, name: &[u8]) -> Option<(usize, u64)> {
    let mut req: alloc::vec::Vec<u8> = b"ai ".to_vec();
    req.extend_from_slice(name);
    let reply = msg::unpack(&info.call(msg::pack(&req)).ok()?);
    let mut words = reply.split(|b| *b == b' ');
    if words.next()? != b"len" {
        return None;
    }
    let len = core::str::from_utf8(words.next()?).ok()?.parse().ok()?;
    if words.next()? != b"ver" {
        return None;
    }
    let version = core::str::from_utf8(words.next()?).ok()?.parse().ok()?;
    Some((len, version))
}

/// Get binary app metadata. `prefix` is either `ah ` or `as `; signatures
/// include an offset, while hashes do not.
fn app_fixed(
    info: CapSlot,
    prefix: &[u8],
    name: &[u8],
    off: usize,
    want: usize,
) -> Option<[u8; 40]> {
    let mut req: alloc::vec::Vec<u8> = prefix.to_vec();
    req.extend_from_slice(name);
    if prefix == b"as " {
        req.push(b' ');
        push_num(&mut req, off as u64);
    }
    let words = info.call(msg::pack(&req)).ok()?;
    let mut raw = [0u8; 40];
    redoubt_userlib::raw::unpack_all(&words, &mut raw);
    if want > raw.len() {
        return None;
    }
    Some(raw)
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
