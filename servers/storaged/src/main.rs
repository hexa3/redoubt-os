#![no_std]
#![no_main]

extern crate alloc;

use redoubt_crypto::layout;
use redoubt_crypto::{ed25519, hmac, sha256};
use redoubt_userlib::msg;
use redoubt_userlib::{sys, CapSlot};

// redoubt-storaged: the appliance configuration & persistence service.
//
// Owns the persistent volume behind kernel-enforced Cap::Block authority:
//   * superblock      - active slot, generation counters, dev volume key
//   * slot A / slot B - signed, encrypted system definitions (A/B updates)
//   * runtime config  - MAC'd mutable KV overrides (never signed policy)
//   * audit log       - append-only hash-chained records
//
// Mount policy fails closed: a slot whose header MAC, payload digest, or
// Ed25519 signature does not verify is skipped; if neither slot verifies,
// storaged enters recovery mode with compiled-in factory defaults and
// refuses mutations until a properly signed update installs a real slot.
//
// Caps installed by initfs:
//   slot 0 console (w), slot 1 query endpoint (r|w),
//   slot 2 config endpoint (r|w), slot 3 whole-disk block (r|w|g | absent)

const SLOT_PAYLOAD_SECTORS: u64 = (layout::PAYLOAD_CAP / layout::SECTOR) as u64;

/// Compiled-in factory definition: what recovery mode serves, and exactly
/// what `redoubt-tools mkvol` signs as generation 1.
pub const FACTORY_PAYLOAD: &[u8] =
    b"# redoubt system definition v1\ndevice-id=redoubt-dev-01\nmin-generation=1\nservice heart autostart restart\n";
const FACTORY_CONFIG: &[u8] = b"hostname=redoubt-dev-01\n";

static PUB_KEY_BYTES: &[u8] = include_bytes!(env!("REDOUBT_STORE_PUB_FILE"));
static UPDATED_ELF: &[u8] = include_bytes!(env!("REDOUBT_UPDATED_ELF"));

fn pub_key() -> [u8; ed25519::PUBLIC_LEN] {
    let mut k = [0u8; 32];
    let hex = core::str::from_utf8(PUB_KEY_BYTES).unwrap_or("").trim();
    for i in 0..32 {
        k[i] = u8::from_str_radix(hex.get(i * 2..i * 2 + 2).unwrap_or("zz"), 16).unwrap_or(0);
    }
    k
}

/// Shared 512 KiB workspace for slot payload validation/loading.
///
/// User stacks are 64 KiB, so payloads this large must live in .bss, not
/// on the stack. storaged is a single-threaded server: sequential use of
/// one static buffer is race-free by construction.
static mut WORKSPACE: [u8; layout::PAYLOAD_CAP] = [0u8; layout::PAYLOAD_CAP];

fn workspace() -> &'static mut [u8; layout::PAYLOAD_CAP] {
    unsafe { &mut *core::ptr::addr_of_mut!(WORKSPACE) }
}

struct RosterEntry {
    name: alloc::string::String,
    autostart: bool,
    restart: bool,
}

/// A verified, executable application slot. Entries are populated only after
/// the encrypted bytes, digest, and package signature all validate at mount
/// or after a completed install.
#[derive(Clone, Copy)]
struct AppEntry {
    slot: u8,
    name: [u8; layout::APP_NAME_MAX],
    name_len: usize,
    payload_len: usize,
    version: u64,
    payload_sha: [u8; 32],
    signature: [u8; 64],
}

#[no_mangle]
fn main() -> ! {
    redoubt_userlib::set_name("storaged");
    let console = CapSlot(0);
    let query = CapSlot(1);
    let config = CapSlot(2);
    // slot 3 exists only when the kernel found a volume disk
    let block = probe_block_cap();

    say(console, b"[storaged] starting\n");

    let mut st = State {
        recovery: true,
        block,
        vol_key: [0u8; 32],
        active: None,
        generation: 0,
        payload: FACTORY_PAYLOAD.to_vec(),
        overrides: FACTORY_CONFIG.to_vec(),
        cfg_gen: 0,
        roster: parse_roster(FACTORY_PAYLOAD),
        device_id: find_kv(FACTORY_PAYLOAD, b"device-id")
            .unwrap_or(b"redoubt-device")
            .to_vec(),
        audit_seq: 0,
        audit_prev: [0u8; 32],
        pubkey: pub_key(),
        apps: alloc::vec::Vec::new(),
        cached_app: None,
    };

    match block {
        Some(cap) => mount(&mut st, cap, console),
        None => say(console, b"[storaged] no block capability: RECOVERY mode\n"),
    }

    serve(st, console, query, config, block)
}

struct State {
    recovery: bool,
    block: Option<CapSlot>,
    vol_key: [u8; 32],
    active: Option<layout::SlotId>,
    generation: u64,
    payload: alloc::vec::Vec<u8>,
    overrides: alloc::vec::Vec<u8>,
    cfg_gen: u64,
    roster: alloc::vec::Vec<RosterEntry>,
    device_id: alloc::vec::Vec<u8>,
    audit_seq: u64,
    audit_prev: [u8; 32],
    pubkey: [u8; 32],
    apps: alloc::vec::Vec<AppEntry>,
    /// The most recently verified program, held in `WORKSPACE` for its
    /// chunked transfer to initfs. Any mutation invalidates this cache.
    cached_app: Option<AppEntry>,
}

// ------------------------------------------------------------ utilities

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
        buf[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    while n > 0 {
        n -= 1;
        out.push(buf[n]);
    }
}

/// Slot 3 holds the whole-disk capability when present. Probe cheaply.
fn probe_block_cap() -> Option<CapSlot> {
    // Block derives are range-narrowed: request a real (non-empty) range.
    match CapSlot(3).derive_block(redoubt_userlib::R_READ, 0, 1) {
        Ok(_) => Some(CapSlot(3)),
        Err(_) => None,
    }
}

fn parse_roster(payload: &[u8]) -> alloc::vec::Vec<RosterEntry> {
    let mut out = alloc::vec::Vec::new();
    for line in payload.split(|&b| b == b'\n') {
        let line = trim(line);
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        if let Some(rest) = strip_prefix(line, b"service ") {
            let parts: alloc::vec::Vec<&[u8]> = rest
                .split(|&b| b == b' ')
                .filter(|p| !p.is_empty())
                .collect();
            if parts.len() >= 3 {
                out.push(RosterEntry {
                    name: alloc::string::String::from(
                        core::str::from_utf8(parts[0]).unwrap_or("?"),
                    ),
                    autostart: parts[1] == b"autostart",
                    restart: parts[2] == b"restart",
                });
            }
        }
    }
    out
}

fn find_kv<'a>(payload: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    for line in payload.split(|&b| b == b'\n') {
        let line = trim(line);
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        if let Some(eq) = line.iter().position(|&c| c == b'=') {
            if &line[..eq] == key {
                return Some(trim(&line[eq + 1..]));
            }
        }
    }
    None
}

fn lookup(st: &State, key: &[u8]) -> Option<alloc::vec::Vec<u8>> {
    // runtime overrides win over signed defaults
    for line in st.overrides.split(|&b| b == b'\n') {
        let line = trim(line);
        if let Some(eq) = line.iter().position(|&c| c == b'=') {
            if &line[..eq] == key {
                return Some(trim(&line[eq + 1..]).to_vec());
            }
        }
    }
    find_kv(&st.payload, key).map(|v| v.to_vec())
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

fn strip_prefix<'a>(s: &'a [u8], p: &[u8]) -> Option<&'a [u8]> {
    if s.len() >= p.len() && &s[..p.len()] == p {
        Some(&s[p.len()..])
    } else {
        None
    }
}

// --------------------------------------------------------- block helpers

fn br(cap: CapSlot, lba: u64, sectors: u16, buf: &mut [u8]) -> bool {
    redoubt_userlib::block_read(cap, lba, sectors, buf).is_ok()
}

fn bw(cap: CapSlot, lba: u64, sectors: u16, buf: &[u8]) -> bool {
    redoubt_userlib::block_write(cap, lba, sectors, buf).is_ok()
}

// -------------------------------------------------------------- mounting

fn mount(st: &mut State, cap: CapSlot, console: CapSlot) {
    let mut sec = [0u8; layout::SECTOR];

    if !br(cap, layout::SUPERBLOCK_LBA, 1, &mut sec) {
        say(console, b"[storaged] disk read failed: RECOVERY mode\n");
        return;
    }
    if &sec[0..8] != layout::SB_MAGIC {
        say(
            console,
            b"[storaged] volume unformatted: RECOVERY (stage an update to install)\n",
        );
        return;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&sec[layout::SB_KEY_OFF..layout::SB_KEY_OFF + 32]);
    if !layout::superblock_valid(&key, &sec) {
        say(
            console,
            b"[storaged] SUPERBLOCK INTEGRITY FAILURE: RECOVERY\n",
        );
        return;
    }
    let (active_sb, gen_a, gen_b) = layout::parse_superblock(&sec).unwrap_or((None, 0, 0));
    let mut gens = [gen_a, gen_b];

    // ---- A/B validation with automatic rollback ----
    let mut active = active_sb;
    if !slot_validates(cap, &key, active, &st.pubkey) {
        if let Some(a) = active {
            zero_header(cap, a);
            let mut line: alloc::vec::Vec<u8> = b"rollback slot ".to_vec();
            line.push(if a.num() == 1 { b'A' } else { b'B' });
            scan_audit(st, cap);
            audit_raw(st, &line);
            // Keep the operator-visible recovery event within one IPC
            // payload. Longer lines are chunked by print_split and another
            // service may legitimately print between chunks.
            say(console, b"[store] active invalid; rollback\n");
        }
        let other = match active.map(|s| s.other()) {
            Some(o) => Some(o),
            None => None,
        };
        if let Some(o) = other {
            if slot_validates(cap, &key, Some(o), &st.pubkey) {
                active = Some(o);
            } else {
                active = None;
            }
        }
    }

    let Some(active) = active else {
        say(console, b"[storaged] no verifiable slot: RECOVERY mode\n");
        st.vol_key = key;
        st.active = None;
        scan_audit(st, cap);
        audit_raw(st, b"boot recovery");
        return;
    };

    // ---- load winning payload ----
    let idx = (active.num() - 1) as usize;
    let plain = workspace();
    match validate_and_load(cap, &key, active, &st.pubkey, plain.as_mut()) {
        Some((len, gen)) => {
            st.vol_key = key;
            st.active = Some(active);
            st.generation = gen;
            gens[idx] = gen;
            st.payload.clear();
            st.payload.extend_from_slice(&plain[..len]);
            st.roster = parse_roster(&st.payload);
            st.device_id = find_kv(&st.payload, b"device-id").unwrap_or(b"?").to_vec();
            st.recovery = false;
        }
        None => {
            say(console, b"[storaged] payload verify failed: RECOVERY\n");
            st.vol_key = key;
            scan_audit(st, cap);
            audit_raw(st, b"boot payload-fail");
            return;
        }
    }

    // ---- runtime config overrides ----
    if br(cap, layout::CONFIG_LBA, 1, &mut sec) && &sec[0..8] == layout::CFG_MAGIC {
        let expect_mac = hmac::HmacSha256::oneshot(&st.vol_key, &sec[..448]);
        let mut got = [0u8; 32];
        got.copy_from_slice(&sec[448..480]);
        if layout::constant_time_eq(&expect_mac, &got) {
            if let Some((_mac, gen, text)) = layout::parse_config(&sec) {
                st.overrides.clear();
                st.overrides.extend_from_slice(text);
                st.cfg_gen = gen;
            }
        } else {
            scan_audit(st, cap);
            audit_raw(st, b"cfg tamper ignored");
            say(
                console,
                b"[storaged] config blob corrupt: defaults in effect\n",
            );
        }
    }

    // ---- audit replay + installed applications ----
    scan_audit(st, cap);
    load_apps(st, cap);
    let mut line: alloc::vec::Vec<u8> = b"boot slot".to_vec();
    line.push(if active.num() == 1 { b'A' } else { b'B' });
    line.extend_from_slice(b" gen ");
    push_num(&mut line, gens[idx]);
    audit_raw(st, &line);

    let mut banner: alloc::vec::Vec<u8> = b"[storaged] mounted slot ".to_vec();
    banner.push(if active.num() == 1 { b'A' } else { b'B' });
    banner.extend_from_slice(b" gen ");
    push_num(&mut banner, gens[idx]);
    banner.extend_from_slice(b"; ");
    push_num(&mut banner, st.roster.len() as u64);
    banner.extend_from_slice(b" service(s); audit ");
    push_num(&mut banner, st.audit_seq);
    banner.extend_from_slice(b" records\n");
    say(console, &banner);
}

/// Stream-validate a slot: header parse, state, ciphertext HMAC, decrypt,
/// digest, Ed25519 signature over plaintext. Returns (payload_len, gen).
fn validate_and_load(
    cap: CapSlot,
    key: &[u8; 32],
    slot: layout::SlotId,
    pubkey: &[u8; 32],
    out: &mut [u8],
) -> Option<(usize, u64)> {
    let mut hdr_sec = [0u8; layout::SECTOR];
    if !br(cap, slot.hdr_lba(), 1, &mut hdr_sec) {
        return None;
    }
    let hdr = layout::parse_slot_header(&hdr_sec)?;
    // Note: hdr.slot is informational - sealed images are slot-agnostic
    // (the same package may install into A or B), so we do not require it
    // to equal the installing slot. All security fields (MAC, digest,
    // signature, generation) are slot-independent by construction.
    if hdr.state != layout::SLOT_STATE_VALID {
        return None;
    }
    let len = hdr.payload_len as usize;
    if len == 0 || len > layout::PAYLOAD_CAP || out.len() < len {
        return None;
    }

    // ciphertext integrity: MAC(header prefix || ciphertext)
    let mut h = hmac::HmacSha256::new(key);
    h.update(&hdr_sec[..layout::HDR_MAC_OFF]);

    // decrypt in place while streaming the MAC over the raw ciphertext
    let mut lba = slot.payload_lba();
    let mut done = 0usize;
    let nonce = layout::seal_nonce(hdr.generation);
    while done < len {
        let take = (len - done).min(8 * layout::SECTOR);
        let sectors = ((take + layout::SECTOR - 1) / layout::SECTOR) as u16;
        let buf = &mut out[done..done + sectors as usize * layout::SECTOR];
        if !br(cap, lba, sectors, buf) {
            return None;
        }
        h.update(&buf[..take]);
        // `done` is always a multiple of 512, hence of ChaCha20's 64-byte
        // block size. Continue the keystream instead of restarting at zero
        // for every disk transfer.
        redoubt_crypto::chacha20::xor_stream(key, (done / 64) as u32, &nonce, &mut buf[..take]);
        lba += sectors as u64;
        done += take;
    }
    let expect_mac = h.finalize();
    let got_mac = &hdr_sec[layout::HDR_MAC_OFF..layout::HDR_MAC_OFF + 32];
    if !layout::constant_time_eq(&expect_mac, got_mac) {
        return None;
    }

    let digest = sha256::sha256(&out[..len]);
    if !layout::constant_time_eq(&digest, &hdr.payload_sha) {
        return None;
    }
    if ed25519::verify(pubkey, &out[..len], &hdr.signature) != Ok(()) {
        return None;
    }
    Some((len, hdr.generation))
}

// --------------------------------------------------------- application store

fn app_name_valid(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= layout::APP_NAME_MAX
        && name.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-')
}

fn app_entry_from_header(h: layout::AppHeader) -> AppEntry {
    AppEntry {
        slot: h.slot,
        name: h.name,
        name_len: h.name_len,
        payload_len: h.payload_len,
        version: h.version,
        payload_sha: h.payload_sha,
        signature: h.signature,
    }
}

fn same_app_name(entry: &AppEntry, name: &[u8]) -> bool {
    entry.name_len == name.len() && entry.name[..entry.name_len] == *name
}

fn best_app(st: &State, name: &[u8]) -> Option<AppEntry> {
    st.apps
        .iter()
        .copied()
        .filter(|a| same_app_name(a, name))
        .max_by_key(|a| a.version)
}

/// Read, authenticate, decrypt, digest-check, and signature-check one app.
/// The caller owns the supplied workspace; never use its contents after a
/// failed return.
fn validate_and_load_app(
    cap: CapSlot,
    key: &[u8; 32],
    slot: u8,
    pubkey: &[u8; 32],
    out: &mut [u8],
) -> Option<AppEntry> {
    let lba = layout::app_slot_lba(slot)?;
    let mut hdr_sec = [0u8; layout::SECTOR];
    if !br(cap, lba, 1, &mut hdr_sec) {
        sys::debug_write(b"[storaged] app header read failed\n");
        return None;
    }
    let Some(hdr) = layout::parse_app_header(&hdr_sec) else {
        return None; // an empty application slot is normal
    };
    if hdr.slot != slot || !app_name_valid(&hdr.name[..hdr.name_len]) || out.len() < hdr.payload_len
    {
        sys::debug_write(b"[storaged] app header invalid\n");
        return None;
    }
    let len = hdr.payload_len;
    let mut h = hmac::HmacSha256::new(key);
    h.update(&hdr_sec[..layout::APP_HDR_MAC_OFF]);
    let mut done = 0usize;
    while done < len {
        let take = (len - done).min(8 * layout::SECTOR);
        let sectors = ((take + layout::SECTOR - 1) / layout::SECTOR) as u16;
        let buf = &mut out[done..done + sectors as usize * layout::SECTOR];
        if !br(cap, lba + 1 + (done / layout::SECTOR) as u64, sectors, buf) {
            sys::debug_write(b"[storaged] app payload read failed\n");
            return None;
        }
        h.update(&buf[..take]);
        redoubt_crypto::chacha20::xor_stream(
            key,
            (done / 64) as u32,
            &layout::app_nonce(slot, hdr.version),
            &mut buf[..take],
        );
        done += take;
    }
    if !layout::constant_time_eq(
        &h.finalize(),
        &hdr_sec[layout::APP_HDR_MAC_OFF..layout::APP_HDR_MAC_END],
    ) {
        sys::debug_write(b"[storaged] app MAC invalid\n");
        return None;
    }
    let digest = sha256::sha256(&out[..len]);
    if !layout::constant_time_eq(&digest, &hdr.payload_sha) {
        sys::debug_write(b"[storaged] app digest invalid\n");
        return None;
    }
    let signed = layout::app_signing_message(
        &hdr.name[..hdr.name_len],
        hdr.version,
        len,
        &hdr.payload_sha,
    );
    if ed25519::verify(pubkey, &signed, &hdr.signature) != Ok(()) {
        sys::debug_write(b"[storaged] app signature invalid\n");
        return None;
    }
    Some(app_entry_from_header(hdr))
}

fn load_apps(st: &mut State, cap: CapSlot) {
    st.apps.clear();
    st.cached_app = None;
    for slot in 0..layout::APP_SLOTS as u8 {
        let valid = validate_and_load_app(cap, &st.vol_key, slot, &st.pubkey, workspace());
        if let Some(entry) = valid {
            st.apps.push(entry);
        } else {
            // Invalid/empty candidates are never executable. Do not erase
            // them here: preserving bytes makes power-loss forensics possible.
        }
    }
}

fn app_unique_count(st: &State) -> usize {
    let mut count = 0usize;
    for i in 0..st.apps.len() {
        if !st.apps[..i]
            .iter()
            .any(|old| same_app_name(old, &st.apps[i].name[..st.apps[i].name_len]))
        {
            count += 1;
        }
    }
    count
}

fn app_at_index(st: &State, want: usize) -> Option<AppEntry> {
    let mut seen = 0usize;
    for entry in st.apps.iter().copied() {
        if best_app(st, &entry.name[..entry.name_len]).map(|best| best.slot) != Some(entry.slot) {
            continue;
        }
        if seen == want {
            return Some(entry);
        }
        seen += 1;
    }
    None
}

fn cache_app(st: &mut State, name: &[u8]) -> Option<AppEntry> {
    let entry = best_app(st, name)?;
    if st
        .cached_app
        .map(|cached| cached.slot == entry.slot && cached.version == entry.version)
        != Some(true)
    {
        let cap = st.block?;
        let loaded = validate_and_load_app(cap, &st.vol_key, entry.slot, &st.pubkey, workspace())?;
        if loaded.version != entry.version || loaded.payload_sha != entry.payload_sha {
            return None;
        }
        st.cached_app = Some(loaded);
    }
    st.cached_app
}

fn parse_app_chunk_req(rest: &[u8]) -> Option<(&[u8], usize)> {
    let split = rest.iter().rposition(|b| *b == b' ')?;
    let name = trim(&rest[..split]);
    let off = core::str::from_utf8(trim(&rest[split + 1..]))
        .ok()?
        .parse::<usize>()
        .ok()?;
    Some((name, off))
}

fn app_info(st: &mut State, name: &[u8]) -> alloc::vec::Vec<u8> {
    match cache_app(st, name) {
        Some(entry) => {
            let mut out = b"len ".to_vec();
            push_num(&mut out, entry.payload_len as u64);
            out.extend_from_slice(b" ver ");
            push_num(&mut out, entry.version);
            out
        }
        None => b"err: no app".to_vec(),
    }
}

fn app_hash(st: &State, name: &[u8]) -> alloc::vec::Vec<u8> {
    match best_app(st, name) {
        Some(entry) => entry.payload_sha.to_vec(),
        None => b"err: no app".to_vec(),
    }
}

fn app_sig(st: &State, name: &[u8], off: usize) -> alloc::vec::Vec<u8> {
    let Some(entry) = best_app(st, name) else {
        return b"err: no app".to_vec();
    };
    if off >= entry.signature.len() {
        return alloc::vec::Vec::new();
    }
    let mut out = [0u8; 40];
    let take = (entry.signature.len() - off).min(out.len());
    out[..take].copy_from_slice(&entry.signature[off..off + take]);
    out.to_vec()
}

fn app_chunk(st: &mut State, name: &[u8], off: usize) -> alloc::vec::Vec<u8> {
    let Some(entry) = cache_app(st, name) else {
        return b"err: no app".to_vec();
    };
    if off >= entry.payload_len {
        return alloc::vec::Vec::new();
    }
    let mut out = [0u8; 40];
    let take = (entry.payload_len - off).min(out.len());
    out[..take].copy_from_slice(&workspace()[off..off + take]);
    out.to_vec()
}

fn target_app_slot(st: &State, name: &[u8]) -> Option<u8> {
    if let Some(current) = best_app(st, name) {
        return layout::app_peer_slot(current.slot);
    }
    for first in (0..layout::APP_SLOTS as u8).step_by(2) {
        let second = first + 1;
        if !st.apps.iter().any(|a| a.slot == first || a.slot == second) {
            return Some(first);
        }
    }
    None
}

fn install_app(st: &mut State, console: CapSlot) -> alloc::vec::Vec<u8> {
    let Some(cap) = st.block else {
        return b"err: no volume".to_vec();
    };
    if st.recovery {
        return b"err: recovery mode".to_vec();
    }
    let mut head = [0u8; layout::SECTOR];
    if !br(cap, layout::STAGING_LBA, 1, &mut head) {
        return b"err: staging io".to_vec();
    }
    if &head[0..8] != layout::APP_PKG_MAGIC || head[8] != layout::APP_FORMAT_VERSION {
        return b"err: no app package".to_vec();
    }
    // `pkg_head` only sees the first sector. Parse length from the fixed
    // metadata, then read the whole package into the shared workspace.
    let package_len = u32::from_le_bytes(head[12..16].try_into().unwrap_or([0; 4])) as usize;
    if package_len == 0 || package_len > layout::APP_STAGE_CAP {
        return b"err: malformed app".to_vec();
    }
    let bytes = layout::APP_PKG_HEADER + package_len;
    let sectors = (bytes + layout::SECTOR - 1) / layout::SECTOR;
    let raw = workspace();
    let mut done = 0usize;
    while done < sectors * layout::SECTOR {
        let take = (sectors * layout::SECTOR - done).min(8 * layout::SECTOR);
        let count = (take / layout::SECTOR) as u16;
        if !br(
            cap,
            layout::STAGING_LBA + (done / layout::SECTOR) as u64,
            count,
            &mut raw[done..done + take],
        ) {
            return b"err: staging io".to_vec();
        }
        done += take;
    }
    let Some(pkg) = layout::parse_app_stage_package(&raw[..bytes]) else {
        return b"err: malformed app".to_vec();
    };
    if !app_name_valid(&pkg.name[..pkg.name_len]) || sha256::sha256(pkg.payload) != pkg.payload_sha
    {
        return b"err: BAD PACKAGE".to_vec();
    }
    let signed = layout::app_signing_message(
        &pkg.name[..pkg.name_len],
        pkg.version,
        pkg.payload.len(),
        &pkg.payload_sha,
    );
    if ed25519::verify(&st.pubkey, &signed, &pkg.signature) != Ok(()) {
        return b"err: BAD SIGNATURE".to_vec();
    }
    let name = pkg.name;
    let name_len = pkg.name_len;
    let payload_len = pkg.payload.len();
    let version = pkg.version;
    let payload_sha = pkg.payload_sha;
    let signature = pkg.signature;
    if let Some(old) = best_app(st, &name[..name_len]) {
        if version <= old.version {
            return b"err: stale version".to_vec();
        }
    }
    let Some(slot) = target_app_slot(st, &name[..name_len]) else {
        return b"err: app store full".to_vec();
    };
    let Some(slot_lba) = layout::app_slot_lba(slot) else {
        return b"err: internal".to_vec();
    };

    // Move plaintext down over its package header, zero sector padding, then
    // encrypt only the signed length. Header publication happens last.
    raw.copy_within(layout::APP_PKG_HEADER..bytes, 0);
    let padded = (payload_len + layout::SECTOR - 1) / layout::SECTOR * layout::SECTOR;
    raw[payload_len..padded].fill(0);
    let mut hdr = [0u8; layout::SECTOR];
    if !layout::write_app_header(
        &mut hdr,
        slot,
        &name[..name_len],
        version,
        &raw[..payload_len],
        &signature,
    ) {
        return b"err: malformed app".to_vec();
    }
    redoubt_crypto::chacha20::xor_stream(
        &st.vol_key,
        0,
        &layout::app_nonce(slot, version),
        &mut raw[..payload_len],
    );
    let mac = layout::app_header_mac(&st.vol_key, &hdr, &raw[..payload_len]);
    hdr[layout::APP_HDR_MAC_OFF..layout::APP_HDR_MAC_END].copy_from_slice(&mac);
    let zeros = [0u8; layout::SECTOR];
    if !bw(cap, slot_lba, 1, &zeros) {
        return b"err: app io".to_vec();
    }
    let mut wrote = 0usize;
    while wrote < padded {
        let take = (padded - wrote).min(8 * layout::SECTOR);
        if !bw(
            cap,
            slot_lba + 1 + (wrote / layout::SECTOR) as u64,
            (take / layout::SECTOR) as u16,
            &raw[wrote..wrote + take],
        ) {
            return b"err: app io".to_vec();
        }
        wrote += take;
    }
    if !bw(cap, slot_lba, 1, &hdr) {
        return b"err: app io".to_vec();
    }
    let entry = AppEntry {
        slot,
        name,
        name_len,
        payload_len,
        version,
        payload_sha,
        signature,
    };
    st.apps.retain(|a| a.slot != slot);
    st.apps.push(entry);
    st.cached_app = None;
    let mut audit = b"app-install ".to_vec();
    audit.extend_from_slice(&entry.name[..entry.name_len]);
    audit.truncate(38);
    audit_raw(st, &audit);
    let mut out = b"ok app ".to_vec();
    out.extend_from_slice(&entry.name[..entry.name_len]);
    out.extend_from_slice(b" v");
    push_num(&mut out, entry.version);
    let _ = console;
    out
}

fn remove_app(st: &mut State, name: &[u8]) -> alloc::vec::Vec<u8> {
    if !app_name_valid(name) {
        return b"err: invalid app".to_vec();
    }
    let Some(cap) = st.block else {
        return b"err: no volume".to_vec();
    };
    let mut removed = false;
    let zeros = [0u8; layout::SECTOR];
    for entry in st.apps.iter().copied().filter(|a| same_app_name(a, name)) {
        if let Some(lba) = layout::app_slot_lba(entry.slot) {
            if !bw(cap, lba, 1, &zeros) {
                return b"err: app io".to_vec();
            }
            removed = true;
        }
    }
    if !removed {
        return b"err: no app".to_vec();
    }
    st.apps.retain(|a| !same_app_name(a, name));
    st.cached_app = None;
    let mut audit = b"app-remove ".to_vec();
    audit.extend_from_slice(name);
    audit_raw(st, &audit);
    b"ok removed".to_vec()
}

fn zero_header(cap: CapSlot, slot: layout::SlotId) {
    let zeros = [0u8; layout::SECTOR];
    bw(cap, slot.hdr_lba(), 1, &zeros);
}

fn slot_validates(
    cap: CapSlot,
    key: &[u8; 32],
    slot: Option<layout::SlotId>,
    pubkey: &[u8; 32],
) -> bool {
    let Some(slot) = slot else { return false };
    validate_and_load(cap, key, slot, pubkey, workspace()).is_some()
}

// --------------------------------------------------------------- audit

/// Replay the hash chain from record 0; positions the append cursor after
/// the last intact record. A broken chain is reported, never repaired
/// silently: records after the break become free space for new events.
fn scan_audit(st: &mut State, cap: CapSlot) {
    let mut sec = [0u8; layout::SECTOR];
    let mut prev = [0u8; 32];
    let mut seq = 0u64;
    while (seq as usize) < layout::AUDIT_RECORDS {
        if !br(cap, layout::AUDIT_START_LBA + seq, 1, &mut sec) {
            break;
        }
        match layout::check_audit_record(&sec, seq, &prev) {
            layout::AuditCheck::Valid(_) => {
                prev.copy_from_slice(&sec[layout::AUD_DIGEST_OFF..layout::AUD_DIGEST_OFF + 32]);
                seq += 1;
            }
            _ => break,
        }
    }
    st.audit_seq = seq;
    st.audit_prev = prev;
}

/// Append one event. Best-effort: a disk failure loses the record, never
/// the caller. Records are SHA-256 hash-chained; editing history breaks
/// the chain at the edited record.
fn audit_raw(st: &mut State, text: &[u8]) {
    let Some(cap) = st.block else { return };
    if st.audit_seq as usize >= layout::AUDIT_RECORDS {
        return; // log full: stop appending rather than wrap and overwrite
    }
    let tick = redoubt_userlib::ticks();
    let mut rec = [0u8; layout::SECTOR];
    let digest = layout::write_audit_record(
        &mut rec,
        st.audit_seq,
        tick,
        1, // event class: generic text
        0,
        &text[..text.len().min(layout::AUD_DATA_MAX)],
        &st.audit_prev,
    );
    if bw(cap, layout::AUDIT_START_LBA + st.audit_seq, 1, &rec) {
        st.audit_seq += 1;
        st.audit_prev = digest;
    }
}

// ------------------------------------------------------- config persist

fn persist_overrides(st: &mut State) -> bool {
    let Some(cap) = st.block else { return false };
    st.cfg_gen += 1;
    let mut sec = [0u8; layout::SECTOR];
    layout::write_config(&mut sec, st.cfg_gen, &st.overrides, &st.vol_key);
    bw(cap, layout::CONFIG_LBA, 1, &sec)
}

fn slot_status_text(st: &State) -> alloc::vec::Vec<u8> {
    match (st.recovery, st.active) {
        (true, _) => b"recovery".to_vec(),
        (false, Some(s)) => {
            let mut v = alloc::vec::Vec::new();
            v.push(if s.num() == 1 { b'A' } else { b'B' });
            v.extend_from_slice(b" gen ");
            push_num(&mut v, st.generation);
            v
        }
        _ => b"unknown".to_vec(),
    }
}

/// Independently verify one system slot for the recovery console. This never
/// trusts the generation recorded in the superblock: the authenticated slot
/// header, ciphertext MAC, plaintext digest, and payload signature are all
/// checked again before reporting the slot as bootable.
fn inspect_slot(st: &State, slot: layout::SlotId) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::new();
    out.push(if slot.num() == 1 { b'A' } else { b'B' });
    let Some(block) = st.block else {
        out.extend_from_slice(b" unavailable");
        return out;
    };
    match validate_and_load(block, &st.vol_key, slot, &st.pubkey, workspace()) {
        Some((_len, generation)) => {
            out.extend_from_slice(b" valid gen ");
            push_num(&mut out, generation);
        }
        None => out.extend_from_slice(b" INVALID"),
    }
    out
}

/// Make a *verified* slot the next boot target. This is intentionally
/// separate from update commit: recovery may select an older valid slot, so
/// normal monotonic-generation update rules do not apply. It only changes
/// the authenticated superblock pointer; it never writes code or payload
/// bytes and requires the exact `confirm` token at the API boundary.
fn select_verified_slot(st: &mut State, target: layout::SlotId) -> alloc::vec::Vec<u8> {
    let Some(block) = st.block else {
        return b"err: no volume".to_vec();
    };
    let Some((_len, target_gen)) =
        validate_and_load(block, &st.vol_key, target, &st.pubkey, workspace())
    else {
        return b"err: target INVALID".to_vec();
    };

    // Re-read and authenticate the pointer immediately before replacing it;
    // a damaged superblock must lead to recovery, never a blind overwrite.
    let mut sb = [0u8; layout::SECTOR];
    if !br(block, layout::SUPERBLOCK_LBA, 1, &mut sb)
        || !layout::superblock_valid(&st.vol_key, &sb)
    {
        return b"err: superblock".to_vec();
    }
    let Some((_previous, mut gen_a, mut gen_b)) = layout::parse_superblock(&sb) else {
        return b"err: superblock".to_vec();
    };
    if target == layout::SlotId::A {
        gen_a = target_gen;
    } else {
        gen_b = target_gen;
    }
    layout::write_superblock(&mut sb, Some(target), gen_a, gen_b, &st.vol_key);
    if !bw(block, layout::SUPERBLOCK_LBA, 1, &sb) {
        return b"err: pointer write".to_vec();
    }

    let mut audit = b"recovery select ".to_vec();
    audit.push(if target.num() == 1 { b'A' } else { b'B' });
    audit_raw(st, &audit);
    let mut out = b"ok selected ".to_vec();
    out.push(if target.num() == 1 { b'A' } else { b'B' });
    out.extend_from_slice(b"; reboot");
    out
}

// --------------------------------------------------------- update flow

/// begin-update: verify + apply the staged package into the INACTIVE slot,
/// then commit only after independent re-validation. The update agent is a
/// separate process holding narrowly-derived capabilities:
///   * read  over the staging region only
///   * write over the inactive slot region only
/// It can neither touch the running slot nor the superblock.
fn run_update(st: &mut State, console: CapSlot) -> alloc::vec::Vec<u8> {
    // The update path reuses the shared validation workspace, so no app
    // transfer may keep treating its former bytes as cached afterwards.
    st.cached_app = None;
    let Some(block) = st.block else {
        return b"err: no volume".to_vec();
    };
    let active = st.active;
    let inactive = match active.map(|s| s.other()) {
        Some(o) => o,
        None => layout::SlotId::A, // recovery installs into slot A
    };

    // derive narrow caps for the agent (structural attenuation)
    // Derived caps must keep R_GRANT to be transferable at spawn time;
    // the child's grant mask still attenuates what IT receives.
    let stage_cap = match block.derive_block(
        redoubt_userlib::R_READ | redoubt_userlib::R_GRANT,
        layout::STAGING_LBA,
        layout::STAGING_SECTORS,
    ) {
        Ok(c) => c,
        Err(e) => return fmt_err(b"err: derive stage ", e),
    };
    let slot_lo = inactive.hdr_lba();
    let slot_len = 2 + SLOT_PAYLOAD_SECTORS - (inactive.payload_lba() - inactive.hdr_lba());
    let slot_cap = match block.derive_block(
        redoubt_userlib::R_WRITE | redoubt_userlib::R_GRANT,
        slot_lo,
        slot_len,
    ) {
        Ok(c) => c,
        Err(e) => return fmt_err(b"err: derive slot ", e),
    };

    say(console, b"[storaged] verifying staged update\n");
    let child = match redoubt_userlib::spawn(
        UPDATED_ELF,
        &[
            (stage_cap, redoubt_userlib::R_READ),
            (slot_cap, redoubt_userlib::R_WRITE),
        ],
    ) {
        Ok(t) => t,
        Err(e) => return fmt_err(b"err: spawn updated ", e),
    };

    // wait for the agent with a bounded timeout
    let deadline = redoubt_userlib::ticks() + 1200; // ~12s incl. signature math
    let exit_code = loop {
        match redoubt_userlib::try_wait() {
            Ok(Some((tid, code))) if tid == child => break code,
            Ok(Some((_other, _code))) => continue,
            Ok(None) => {}
            Err(_) => break 0xFFFF,
        }
        if redoubt_userlib::ticks() >= deadline {
            let _ = redoubt_userlib::kill(child);
            break 0xFFFE;
        }
        if redoubt_userlib::sleep(10).is_err() {
            break 0xFFFE;
        }
    };

    let mut line: alloc::vec::Vec<u8> = b"update ".to_vec();
    match exit_code {
        0 => {
            // independent re-validation before commit
            let scratch = workspace();
            match validate_and_load(block, &st.vol_key, inactive, &st.pubkey, scratch.as_mut()) {
                Some((len, gen)) => {
                    if !commit_slot(st, block, inactive, gen) {
                        line.extend_from_slice(b"commit-fail");
                        audit_raw(st, &line);
                        return b"err: commit failed".to_vec();
                    }
                    line.extend_from_slice(b"applied gen ");
                    push_num(&mut line, gen);
                    audit_raw(st, &line);
                    let mut out: alloc::vec::Vec<u8> = b"ok applied ".to_vec();
                    push_num(&mut out, len as u64);
                    out.extend_from_slice(b" bytes; reboot");
                    return out;
                }
                None => {
                    line.extend_from_slice(b"validate-fail");
                    audit_raw(st, &line);
                    return b"err: applied but validation failed".to_vec();
                }
            }
        }
        16 => {
            line.extend_from_slice(b"reject bad-signature");
            audit_raw(st, &line);
            b"err: BAD SIGNATURE".to_vec()
        }
        17 => {
            line.extend_from_slice(b"reject no-package");
            audit_raw(st, &line);
            b"err: no staged package".to_vec()
        }
        18 => {
            line.extend_from_slice(b"io-error");
            audit_raw(st, &line);
            b"err: staging io error".to_vec()
        }
        19 => {
            line.extend_from_slice(b"reject stale-generation");
            audit_raw(st, &line);
            b"err: stale generation".to_vec()
        }
        c => {
            line.extend_from_slice(b"agent-exit ");
            push_num(&mut line, c);
            audit_raw(st, &line);
            b"err: agent failed".to_vec()
        }
    }
}

/// Flip the superblock's active pointer atomically-ish: a torn sector
/// fails the MAC at next mount and falls back to the other valid slot.
fn commit_slot(st: &mut State, cap: CapSlot, new_active: layout::SlotId, gen: u64) -> bool {
    // freshness gate: never let a stale package roll the system back
    if st.active.is_some() && gen <= st.generation {
        return false;
    }
    let mut gens = [0u64; 2];
    gens[(new_active.num() - 1) as usize] = gen;
    // keep the other generation for freshness checks
    if let Some(old) = st.active {
        if old != new_active {
            gens[(old.num() - 1) as usize] = st.generation;
        }
    }
    let mut sb = [0u8; layout::SECTOR];
    layout::write_superblock(&mut sb, Some(new_active), gens[0], gens[1], &st.vol_key);
    if bw(cap, layout::SUPERBLOCK_LBA, 1, &sb) {
        st.active = Some(new_active);
        st.generation = gen;
        true
    } else {
        false
    }
}

fn fmt_err(prefix: &[u8], errno: u64) -> alloc::vec::Vec<u8> {
    let mut v = prefix.to_vec();
    push_num(&mut v, errno);
    v
}

// ------------------------------------------------------------ serve loop

fn serve(
    mut st: State,
    console: CapSlot,
    query: CapSlot,
    config: CapSlot,
    _block_unused: Option<CapSlot>,
) -> ! {
    // Bounded-wait event loop over both endpoints. A plain blocking recv
    // here deadlocks by construction: parking on a quiet endpoint strands
    // callers queued on the other one. Deadlines bound every wait to
    // ~1s so both sides always make progress.
    const SLICE_TICKS: u64 = 100;
    loop {
        // After servicing a query, only give the configuration endpoint one
        // tick before returning to queued queries. This matters for binary
        // transfers: waiting a full second between every 40-byte app chunk
        // turns a small ELF load into minutes of needless latency.
        let mut config_deadline = redoubt_userlib::ticks() + SLICE_TICKS;
        match query.recv_until(redoubt_userlib::ticks() + SLICE_TICKS) {
            Ok((_, words)) => {
                let req = msg::unpack(&words);
                let reply = handle_query(&mut st, console, &req);
                query.reply(msg::pack(&reply));
                config_deadline = redoubt_userlib::ticks();
            }
            Err(10) => {} // E_TIMEDOUT: nothing queued, rotate
            Err(e) => sys::exit(e),
        }
        match config.recv_until(config_deadline) {
            Ok((_, words)) => {
                let req = msg::unpack(&words);
                let reply = handle_config(&mut st, console, &req);
                config.reply(msg::pack(&reply));
            }
            Err(10) => {}
            Err(e) => sys::exit(e),
        }
    }
}

fn handle_query(st: &mut State, console: CapSlot, req: &[u8]) -> alloc::vec::Vec<u8> {
    if let Some(rest) = strip_prefix(req, b"log ") {
        audit_raw(st, trim(rest));
        return b"ok".to_vec();
    }
    if req == b"id" {
        let mut v = b"id=".to_vec();
        v.extend_from_slice(&st.device_id);
        return v;
    }
    if req == b"slot" {
        return slot_status_text(st);
    }
    if req == b"slot-a" {
        return inspect_slot(st, layout::SlotId::A);
    }
    if req == b"slot-b" {
        return inspect_slot(st, layout::SlotId::B);
    }
    if let Some(rest) = strip_prefix(req, b"get ") {
        let key = trim(rest);
        match lookup(st, key) {
            Some(v) => {
                let mut out = key.to_vec();
                out.push(b'=');
                out.extend_from_slice(&v);
                out
            }
            None => b"err: unset".to_vec(),
        }
    } else if req == b"roster-count" {
        let mut v = alloc::vec::Vec::new();
        push_num(&mut v, st.roster.len() as u64);
        v
    } else if let Some(rest) = strip_prefix(req, b"roster ") {
        let idx: usize = core::str::from_utf8(trim(rest))
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(usize::MAX);
        match st.roster.get(idx) {
            Some(r) => {
                let mut v = alloc::vec::Vec::new();
                v.extend_from_slice(r.name.as_bytes());
                v.extend_from_slice(if r.autostart {
                    b" autostart"
                } else {
                    b" manual"
                });
                v.extend_from_slice(if r.restart { b" restart" } else { b" once" });
                v
            }
            None => b"err: range".to_vec(),
        }
    } else if req == b"auditcount" {
        let mut v = alloc::vec::Vec::new();
        push_num(&mut v, st.audit_seq);
        v
    } else if let Some(rest) = strip_prefix(req, b"audit ") {
        let want: u64 = core::str::from_utf8(trim(rest))
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(u64::MAX);
        read_audit_record(st, want)
    } else if req == b"app-count" {
        let mut out = alloc::vec::Vec::new();
        push_num(&mut out, app_unique_count(st) as u64);
        out
    } else if let Some(rest) = strip_prefix(req, b"app-list ") {
        let idx = core::str::from_utf8(trim(rest))
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(usize::MAX);
        match app_at_index(st, idx) {
            Some(app) => {
                let mut out = app.name[..app.name_len].to_vec();
                out.push(b' ');
                push_num(&mut out, app.version);
                out
            }
            None => b"err: range".to_vec(),
        }
    } else if let Some(name) = strip_prefix(req, b"app-info ").or_else(|| strip_prefix(req, b"ai "))
    {
        app_info(st, trim(name))
    } else if let Some(name) = strip_prefix(req, b"app-hash ").or_else(|| strip_prefix(req, b"ah "))
    {
        app_hash(st, trim(name))
    } else if let Some(rest) = strip_prefix(req, b"app-sig ").or_else(|| strip_prefix(req, b"as "))
    {
        match parse_app_chunk_req(rest) {
            Some((name, off)) => app_sig(st, name, off),
            None => b"err: query?".to_vec(),
        }
    } else if let Some(rest) =
        strip_prefix(req, b"app-chunk ").or_else(|| strip_prefix(req, b"ac "))
    {
        match parse_app_chunk_req(rest) {
            Some((name, off)) => app_chunk(st, name, off),
            None => b"err: query?".to_vec(),
        }
    } else {
        let _ = console;
        b"err: query?".to_vec()
    }
}

/// Read one audit record by absolute sequence number.
fn read_audit_record(st: &State, seq: u64) -> alloc::vec::Vec<u8> {
    let Some(cap) = st.block else {
        return b"err: novol".to_vec();
    };
    if seq >= st.audit_seq {
        return b"err: range".to_vec();
    }
    let mut sec = [0u8; layout::SECTOR];
    if !br(cap, layout::AUDIT_START_LBA + seq, 1, &mut sec) {
        return b"err: io".to_vec();
    }
    let rec_seq = u64::from_le_bytes(sec[4..12].try_into().unwrap_or([0; 8]));
    let tick = u64::from_le_bytes(sec[12..20].try_into().unwrap_or([0; 8]));
    let dlen = u16::from_le_bytes(sec[22..24].try_into().unwrap_or([0; 2])) as usize;
    let data = &sec[56..56 + dlen.min(layout::AUD_DATA_MAX)];
    let mut v: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    push_num(&mut v, rec_seq);
    v.push(b' ');
    push_num(&mut v, tick);
    v.push(b' ');
    v.extend_from_slice(data);
    v.truncate(38); // fits the IPC payload budget with room to spare
    v
}

fn handle_config(st: &mut State, console: CapSlot, req: &[u8]) -> alloc::vec::Vec<u8> {
    if st.recovery {
        if let Some(rest) = strip_prefix(req, b"set ") {
            let _ = rest;
            return b"err: recovery mode is read-only".to_vec();
        }
    }
    if let Some(rest) = strip_prefix(req, b"set ") {
        // "set <k> <v>"
        let eq = match rest.iter().position(|&c| c == b' ') {
            Some(i) => i,
            None => return b"err: usage set <k> <v>".to_vec(),
        };
        let key = trim(&rest[..eq]);
        let value = trim(&rest[eq + 1..]);
        if key.is_empty() || key.len() > 24 || value.len() > 24 {
            return b"err: bounds".to_vec();
        }
        // rebuild overrides text without this key, then append it
        let mut text: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        for line in st.overrides.split(|&b| b == b'\n') {
            let l = trim(line);
            if l.is_empty() {
                continue;
            }
            if let Some(eq2) = l.iter().position(|&c| c == b'=') {
                if &l[..eq2] == key {
                    continue;
                }
            }
            text.extend_from_slice(l);
            text.push(b'\n');
        }
        text.extend_from_slice(key);
        text.push(b'=');
        text.extend_from_slice(value);
        text.push(b'\n');
        if text.len() > layout::CFG_TEXT_MAX {
            return b"err: full".to_vec();
        }
        st.overrides = text;
        if persist_overrides(st) {
            let mut line: alloc::vec::Vec<u8> = b"cfg-set ".to_vec();
            line.extend_from_slice(key);
            audit_raw(st, &line);
            b"ok".to_vec()
        } else {
            b"err: io".to_vec()
        }
    } else if req == b"begin-update" {
        run_update(st, console)
    } else if req == b"select-slot a confirm" {
        select_verified_slot(st, layout::SlotId::A)
    } else if req == b"select-slot b confirm" {
        select_verified_slot(st, layout::SlotId::B)
    } else if req == b"select-slot a" || req == b"select-slot b" {
        b"err: confirmation required".to_vec()
    } else if req == b"install-app" {
        install_app(st, console)
    } else if let Some(name) = strip_prefix(req, b"remove-app ") {
        remove_app(st, trim(name))
    } else {
        b"err: config?".to_vec()
    }
}
