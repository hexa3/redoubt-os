//! redoubt persistent-volume layout — single source of truth for the host
//! tools (`redoubt-tools`) and the on-device storage service.
//!
//! Geometry (512-byte sectors, default 16 MiB volume):
//!
//!   LBA 0            superblock (magic, active slot, generations,
//!                    development volume key, HMAC integrity tag)
//!   LBA 1            runtime configuration blob (KV overrides, MAC'd,
//!                    generation-counted; NOT part of the signed image)
//!   LBA 2            slot A header
//!   LBA 4..1027      slot A payload (signed system definition, encrypted)
//!   LBA 1034         slot B header
//!   LBA 1036..2059   slot B payload
//!   LBA 3072..16383  append-only hash-chained audit log
//!   LBA 20480..20735 update-package staging area
//!
//! Security model (dev platform; see DESIGN_DECISIONS.md):
//! - The *system definition* payload (service roster, identity) is signed
//!   with Ed25519; the public key is pinned in the verifying binaries.
//! - Payloads at rest are ChaCha20-encrypted and HMAC-tagged with the
//!   volume key. On the development platform the volume key lives in the
//!   superblock (plaintext-in-header); Release-1 seals it behind a TPM.
//! - The audit log is hash-chained per record; any edit breaks the chain.
//! - Runtime KV overrides are integrity-protected but deliberately unsigned:
//!   they are mutable state, not shipped code or policy.

pub const SECTOR: usize = 512;

pub const SUPERBLOCK_LBA: u64 = 0;
pub const CONFIG_LBA: u64 = 1;
pub const SLOT_A_HDR_LBA: u64 = 2;
pub const SLOT_A_PAYLOAD_LBA: u64 = 4;
pub const SLOT_B_HDR_LBA: u64 = 1034;
pub const SLOT_B_PAYLOAD_LBA: u64 = 1036;
pub const AUDIT_START_LBA: u64 = 3072;
pub const AUDIT_END_LBA: u64 = 16383;
/// Eight 256 KiB application slots. Slots are paired (0/1, 2/3, …) so an
/// application update never overwrites the last verified version.
pub const APP_START_LBA: u64 = 16384;
pub const APP_SLOT_SECTORS: u64 = 512;
pub const APP_SLOTS: usize = 8;
pub const STAGING_LBA: u64 = 20480;
pub const STAGING_SECTORS: u64 = 256;

/// Payload capacity per slot, bytes.
pub const PAYLOAD_CAP: usize = 1000 * SECTOR;
/// One app slot reserves its first sector for authenticated metadata.
pub const APP_PAYLOAD_CAP: usize = (APP_SLOT_SECTORS as usize - 1) * SECTOR;
/// Audit record count.
pub const AUDIT_RECORDS: usize = (AUDIT_END_LBA - AUDIT_START_LBA) as usize;

pub const SB_MAGIC: &[u8; 8] = b"AEGSVOL\x00";
pub const CFG_MAGIC: &[u8; 8] = b"AEGSCFG\x00";
pub const SLOT_MAGIC: &[u8; 8] = b"AEGSLOT\x00";
pub const PKG_MAGIC: &[u8; 7] = b"AEGUPKG";
pub const APP_MAGIC: &[u8; 8] = b"AEGSAPP\x00";
pub const APP_PKG_MAGIC: &[u8; 8] = b"AEGAPKG\x00";

pub const VOL_FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotId {
    A,
    B,
}

impl SlotId {
    pub fn other(self) -> SlotId {
        match self {
            SlotId::A => SlotId::B,
            SlotId::B => SlotId::A,
        }
    }
    /// Numeric encoding in the superblock's active_slot field.
    pub fn num(self) -> u32 {
        match self {
            SlotId::A => 1,
            SlotId::B => 2,
        }
    }
    pub fn from_num(n: u32) -> Option<SlotId> {
        match n {
            1 => Some(SlotId::A),
            2 => Some(SlotId::B),
            _ => None,
        }
    }
    pub fn hdr_lba(self) -> u64 {
        match self {
            SlotId::A => SLOT_A_HDR_LBA,
            SlotId::B => SLOT_B_HDR_LBA,
        }
    }
    pub fn payload_lba(self) -> u64 {
        match self {
            SlotId::A => SLOT_A_PAYLOAD_LBA,
            SlotId::B => SLOT_B_PAYLOAD_LBA,
        }
    }
    /// 12-byte ChaCha20 nonce binding slot payloads to a generation. The
    /// slot byte is deliberately NOT mixed in: update packages carry a
    /// pre-sealed slot image that must decrypt identically whichever slot
    /// installs it.
    pub fn data_nonce(self, purpose: u8, gen: u64) -> [u8; 12] {
        let _ = self;
        let mut n = [0u8; 12];
        n[0] = purpose;
        n[2..10].copy_from_slice(&gen.to_le_bytes());
        n
    }
}

/// Canonical nonce for sealed slot payloads (shared by host provisioning,
/// update packages, and the storage service).
pub fn seal_nonce(gen: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[0] = b'S';
    n[2..10].copy_from_slice(&gen.to_le_bytes());
    n
}

// ------------------------------------------------------------ superblock

pub const SB_KEY_OFF: usize = 0x28;
pub const SB_MAC_OFF: usize = 0x48;
pub const SB_TAG_LEN: usize = 32;

/// Parse the fixed fields of a superblock sector. Returns
/// (active_slot, gen_a, gen_b); integrity must be checked separately with
/// `superblock_mac`.
pub fn parse_superblock(sb: &[u8]) -> Option<(Option<SlotId>, u64, u64)> {
    if sb.len() < SECTOR || &sb[0..8] != SB_MAGIC {
        return None;
    }
    let version = u32::from_le_bytes(sb[8..12].try_into().ok()?);
    if version != VOL_FORMAT_VERSION {
        return None;
    }
    let active = SlotId::from_num(u32::from_le_bytes(sb[16..20].try_into().ok()?));
    let gen_a = u64::from_le_bytes(sb[24..32].try_into().ok()?);
    let gen_b = u64::from_le_bytes(sb[32..40].try_into().ok()?);
    Some((active, gen_a, gen_b))
}

pub fn write_superblock(
    sb: &mut [u8],
    active: Option<SlotId>,
    gen_a: u64,
    gen_b: u64,
    key: &[u8; 32],
) {
    for b in sb.iter_mut() {
        *b = 0;
    }
    sb[0..8].copy_from_slice(SB_MAGIC);
    sb[8..12].copy_from_slice(&VOL_FORMAT_VERSION.to_le_bytes());
    let act = active.map(|s| s.num()).unwrap_or(0);
    sb[16..20].copy_from_slice(&act.to_le_bytes());
    sb[24..32].copy_from_slice(&gen_a.to_le_bytes());
    sb[32..40].copy_from_slice(&gen_b.to_le_bytes());
    sb[SB_KEY_OFF..SB_KEY_OFF + 32].copy_from_slice(key);
    let mac = super::hmac::HmacSha256::oneshot(key, &sb[..SB_MAC_OFF]);
    sb[SB_MAC_OFF..SB_MAC_OFF + 32].copy_from_slice(&mac);
}

/// HMAC over the superblock prefix using the volume key itself.
pub fn superblock_mac(key: &[u8; 32], sb: &[u8]) -> [u8; 32] {
    super::hmac::HmacSha256::oneshot(key, &sb[..SB_MAC_OFF])
}

pub fn superblock_valid(key: &[u8; 32], sb: &[u8]) -> bool {
    let expect = superblock_mac(key, sb);
    let got = &sb[SB_MAC_OFF..SB_MAC_OFF + 32];
    constant_time_eq(&expect, got)
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for i in 0..a.len() {
        acc |= a[i] ^ b[i];
    }
    acc == 0
}

// --------------------------------------------------------- runtime config

pub const CFG_TEXT_MAX: usize = 400;

/// Parse a runtime-config sector into its text (empty when unformatted).
/// Integrity checked by caller via `config_mac`.
pub fn parse_config(sec: &[u8]) -> Option<([u8; 32], u64, &[u8])> {
    if sec.len() < SECTOR || &sec[0..8] != CFG_MAGIC {
        return None;
    }
    let gen = u64::from_le_bytes(sec[8..16].try_into().ok()?);
    let len = u16::from_le_bytes(sec[16..18].try_into().ok()?) as usize;
    if len > CFG_TEXT_MAX {
        return None;
    }
    let mut mac = [0u8; 32];
    mac.copy_from_slice(&sec[448..480]);
    Some((mac, gen, &sec[32..32 + len]))
}

pub fn write_config(sec: &mut [u8], gen: u64, text: &[u8], key: &[u8; 32]) {
    assert!(text.len() <= CFG_TEXT_MAX);
    for b in sec.iter_mut() {
        *b = 0;
    }
    sec[0..8].copy_from_slice(CFG_MAGIC);
    sec[8..16].copy_from_slice(&gen.to_le_bytes());
    sec[16..18].copy_from_slice(&(text.len() as u16).to_le_bytes());
    sec[32..32 + text.len()].copy_from_slice(text);
    let mac = super::hmac::HmacSha256::oneshot(key, &sec[..448]);
    sec[448..480].copy_from_slice(&mac);
}

pub fn config_mac(key: &[u8; 32], sec: &[u8]) -> [u8; 32] {
    super::hmac::HmacSha256::oneshot(key, &sec[..448])
}

// ------------------------------------------------------------------ slots

pub const SLOT_STATE_EMPTY: u8 = 0;
pub const SLOT_STATE_VALID: u8 = 1;
pub const SLOT_STATE_BAD: u8 = 2;

pub const HDR_SIG_OFF: usize = 0x40;
pub const HDR_MAC_OFF: usize = 0x80;
pub const HDR_MAC_END: usize = 0xA0;

/// Parsed slot header fields.
pub struct SlotHeader {
    pub slot: SlotId,
    pub state: u8,
    pub generation: u64,
    pub payload_len: u32,
    pub payload_sha: [u8; 32],
    pub signature: [u8; 64],
}

pub fn parse_slot_header(hdr: &[u8]) -> Option<SlotHeader> {
    if hdr.len() < SECTOR || &hdr[0..8] != SLOT_MAGIC {
        return None;
    }
    let slot = SlotId::from_num(hdr[8] as u32)?;
    let state = hdr[9];
    if state > SLOT_STATE_BAD {
        return None;
    }
    Some(SlotHeader {
        slot,
        state,
        generation: u64::from_le_bytes(hdr[16..24].try_into().ok()?),
        payload_len: u32::from_le_bytes(hdr[24..28].try_into().ok()?),
        payload_sha: hdr[32..64].try_into().ok()?,
        signature: hdr[HDR_SIG_OFF..HDR_SIG_OFF + 64].try_into().ok()?,
    })
}

/// Serialize header fields into `hdr`, leaving the trailing MAC area zeroed
/// (caller computes it over the ciphertext and stores it at HDR_MAC_OFF).
pub fn write_slot_header(
    hdr: &mut [u8],
    slot: SlotId,
    state: u8,
    generation: u64,
    payload: &[u8],
    signature: &[u8; 64],
) {
    assert!(payload.len() <= PAYLOAD_CAP);
    for b in hdr.iter_mut() {
        *b = 0;
    }
    hdr[0..8].copy_from_slice(SLOT_MAGIC);
    hdr[8] = match slot {
        SlotId::A => 1,
        SlotId::B => 2,
    };
    hdr[9] = state;
    hdr[16..24].copy_from_slice(&generation.to_le_bytes());
    hdr[24..28].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    hdr[32..64].copy_from_slice(&super::sha256::sha256(payload));
    hdr[HDR_SIG_OFF..HDR_SIG_OFF + 64].copy_from_slice(signature);
}

/// MAC binding header fields to this slot's ciphertext.
pub fn slot_mac(key: &[u8; 32], hdr: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    let mut h = super::hmac::HmacSha256::new(key);
    h.update(&hdr[..HDR_MAC_OFF]);
    h.update(ciphertext);
    h.finalize()
}

pub fn slot_mac_ok(key: &[u8; 32], hdr: &[u8], ciphertext: &[u8]) -> bool {
    let expect = slot_mac(key, hdr, ciphertext);
    let got = &hdr[HDR_MAC_OFF..HDR_MAC_OFF + 32];
    constant_time_eq(&expect, got)
}

// ------------------------------------------------------- update packages
//
// A staged package is a SEALED SLOT IMAGE: the exact sectors (header, gap,
// payload) that will be written into the inactive slot region, already
// encrypted and MAC'd under the volume key by provisioning. The outer
// staging header carries an Ed25519 signature over that image, so the
// on-device update agent can verify authenticity WITHOUT holding the
// volume key or seeing plaintext: it checks the signature and copies the
// image verbatim into the inactive slot. Decryption + digest + payload
// signature verification happens at mount/commit time in storaged.

pub const PKG_IMAGE_OFF: usize = 0x80;
pub const PKG_LEN_OFF: usize = 0x10;
pub const PKG_SHA_OFF: usize = 0x18;
pub const PKG_SIG_OFF: usize = 0x38; // Ed25519 over the image bytes

/// Total slot-image size in bytes (header + gap sector + payload region).
pub const SLOT_IMAGE_MAX: usize = SECTOR * (2 + (PAYLOAD_CAP / SECTOR));

/// Build a complete sealed slot image: header sector, gap sector, and the
/// encrypted payload region. Returns the image length.
pub fn build_slot_image(
    img: &mut [u8],
    generation: u64,
    payload: &[u8],
    payload_signature: &[u8; 64],
    key: &[u8; 32],
) -> usize {
    assert!(img.len() >= SLOT_IMAGE_MAX);
    for b in img.iter_mut() {
        *b = 0;
    }
    write_slot_header(
        &mut img[..SECTOR],
        SlotId::A, // slot byte is not security-relevant here
        SLOT_STATE_VALID,
        generation,
        payload,
        payload_signature,
    );
    let nonce = seal_nonce(generation);
    let mut ct = Vec::from(payload);
    xor_in_place(key, &nonce, &mut ct);
    let mac = slot_mac(key, &img[..SECTOR], &ct);
    img[SECTOR..] // gap stays zero
        .iter_mut()
        .for_each(|b| *b = 0);
    img[HDR_MAC_OFF..HDR_MAC_OFF + 32].copy_from_slice(&mac);
    let payload_start = 2 * SECTOR;
    img[payload_start..payload_start + ct.len()].copy_from_slice(&ct);
    payload_start + ct.len()
}

use alloc::vec::Vec;
extern crate alloc;

fn xor_in_place(key: &[u8; 32], nonce: &[u8; 12], data: &mut [u8]) {
    super::chacha20::xor_stream(key, 0, nonce, data);
}

/// Serialize a staging package around a slot image. `image_sig` is the
/// Ed25519 signature over `img` bytes, produced by provisioning.
pub fn write_stage_package(out: &mut [u8], img: &[u8], image_sig: &[u8; 64]) -> usize {
    assert!(out.len() >= PKG_IMAGE_OFF + img.len());
    for b in out.iter_mut() {
        *b = 0;
    }
    out[0..7].copy_from_slice(PKG_MAGIC);
    out[7] = 2; // version
    out[PKG_LEN_OFF..PKG_LEN_OFF + 8].copy_from_slice(&(img.len() as u64).to_le_bytes());
    out[PKG_SHA_OFF..PKG_SHA_OFF + 32].copy_from_slice(&super::sha256::sha256(img));
    out[PKG_SIG_OFF..PKG_SIG_OFF + 64].copy_from_slice(image_sig);
    out[PKG_IMAGE_OFF..PKG_IMAGE_OFF + img.len()].copy_from_slice(img);
    PKG_IMAGE_OFF + img.len()
}

/// Parse the staging header without any key material: returns the image
/// byte slice and its signature. Callers must still verify the signature.
pub fn parse_stage_package(buf: &[u8]) -> Option<(&[u8], [u8; 64])> {
    if buf.len() < PKG_IMAGE_OFF || &buf[0..7] != PKG_MAGIC || buf[7] != 2 {
        return None;
    }
    let len = u64::from_le_bytes(buf[PKG_LEN_OFF..PKG_LEN_OFF + 8].try_into().ok()?) as usize;
    if len == 0 || len > SLOT_IMAGE_MAX || buf.len() < PKG_IMAGE_OFF + len {
        return None;
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&buf[PKG_SIG_OFF..PKG_SIG_OFF + 64]);
    Some((&buf[PKG_IMAGE_OFF..PKG_IMAGE_OFF + len], sig))
}

// ------------------------------------------------------- app packages/store
//
// Application packages are deliberately separate from system-update
// packages. A package signs its name, version, length, and payload digest;
// storaged verifies it, encrypts it into an inactive paired app slot, and
// publishes its authenticated header last. The existing version remains
// executable if power fails during installation.

pub const APP_FORMAT_VERSION: u8 = 1;
pub const APP_STATE_EMPTY: u8 = 0;
pub const APP_STATE_VALID: u8 = 1;
pub const APP_NAME_MAX: usize = 24;
pub const APP_HDR_NAME_OFF: usize = 32;
pub const APP_HDR_SHA_OFF: usize = 64;
pub const APP_HDR_SIG_OFF: usize = 96;
pub const APP_HDR_MAC_OFF: usize = 160;
pub const APP_HDR_MAC_END: usize = 192;

/// App package metadata occupies the beginning of the existing staging
/// area. Its payload follows immediately and is limited by that area.
pub const APP_PKG_HEADER: usize = 192;
pub const APP_STAGE_CAP: usize = STAGING_SECTORS as usize * SECTOR - APP_PKG_HEADER;

/// Canonical, fixed-width byte string signed for every application package.
/// The zero-padded name representation makes the encoding unambiguous.
pub const APP_SIGN_BYTES: usize = 80;

#[derive(Clone, Copy)]
pub struct AppHeader {
    pub slot: u8,
    pub name: [u8; APP_NAME_MAX],
    pub name_len: usize,
    pub payload_len: usize,
    pub version: u64,
    pub payload_sha: [u8; 32],
    pub signature: [u8; 64],
}

pub struct AppPackage<'a> {
    pub name: [u8; APP_NAME_MAX],
    pub name_len: usize,
    pub payload: &'a [u8],
    pub version: u64,
    pub payload_sha: [u8; 32],
    pub signature: [u8; 64],
}

pub fn app_slot_lba(slot: u8) -> Option<u64> {
    if (slot as usize) < APP_SLOTS {
        Some(APP_START_LBA + slot as u64 * APP_SLOT_SECTORS)
    } else {
        None
    }
}

/// Pair containing `slot`; each pair holds the current and candidate version
/// of one named application.
pub fn app_peer_slot(slot: u8) -> Option<u8> {
    if (slot as usize) < APP_SLOTS {
        Some(slot ^ 1)
    } else {
        None
    }
}

pub fn app_nonce(slot: u8, version: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[0] = b'A';
    n[1] = slot;
    n[2..10].copy_from_slice(&version.to_le_bytes());
    n
}

pub fn app_signing_message(
    name: &[u8],
    version: u64,
    payload_len: usize,
    payload_sha: &[u8; 32],
) -> [u8; APP_SIGN_BYTES] {
    let mut out = [0u8; APP_SIGN_BYTES];
    out[0..8].copy_from_slice(b"AEGAPPV1");
    let n = name.len().min(APP_NAME_MAX);
    out[8] = n as u8;
    out[9..9 + n].copy_from_slice(&name[..n]);
    out[33..41].copy_from_slice(&version.to_le_bytes());
    out[41..45].copy_from_slice(&(payload_len as u32).to_le_bytes());
    out[45..77].copy_from_slice(payload_sha);
    out
}

pub fn app_header_mac(key: &[u8; 32], hdr: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    let mut h = super::hmac::HmacSha256::new(key);
    h.update(&hdr[..APP_HDR_MAC_OFF]);
    h.update(ciphertext);
    h.finalize()
}

pub fn app_header_mac_ok(key: &[u8; 32], hdr: &[u8], ciphertext: &[u8]) -> bool {
    let expect = app_header_mac(key, hdr, ciphertext);
    constant_time_eq(&expect, &hdr[APP_HDR_MAC_OFF..APP_HDR_MAC_END])
}

pub fn write_app_header(
    hdr: &mut [u8],
    slot: u8,
    name: &[u8],
    version: u64,
    payload: &[u8],
    signature: &[u8; 64],
) -> bool {
    if hdr.len() < SECTOR
        || (slot as usize) >= APP_SLOTS
        || name.is_empty()
        || name.len() > APP_NAME_MAX
        || payload.len() > APP_PAYLOAD_CAP
    {
        return false;
    }
    for b in hdr.iter_mut() {
        *b = 0;
    }
    hdr[0..8].copy_from_slice(APP_MAGIC);
    hdr[8] = APP_FORMAT_VERSION;
    hdr[9] = APP_STATE_VALID;
    hdr[10] = slot;
    hdr[11] = name.len() as u8;
    hdr[12..16].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    hdr[16..24].copy_from_slice(&version.to_le_bytes());
    hdr[APP_HDR_NAME_OFF..APP_HDR_NAME_OFF + name.len()].copy_from_slice(name);
    hdr[APP_HDR_SHA_OFF..APP_HDR_SHA_OFF + 32].copy_from_slice(&super::sha256::sha256(payload));
    hdr[APP_HDR_SIG_OFF..APP_HDR_SIG_OFF + 64].copy_from_slice(signature);
    true
}

pub fn parse_app_header(hdr: &[u8]) -> Option<AppHeader> {
    if hdr.len() < SECTOR || &hdr[0..8] != APP_MAGIC || hdr[8] != APP_FORMAT_VERSION {
        return None;
    }
    if hdr[9] != APP_STATE_VALID || (hdr[10] as usize) >= APP_SLOTS {
        return None;
    }
    let name_len = hdr[11] as usize;
    let payload_len = u32::from_le_bytes(hdr[12..16].try_into().ok()?) as usize;
    if name_len == 0 || name_len > APP_NAME_MAX || payload_len == 0 || payload_len > APP_PAYLOAD_CAP
    {
        return None;
    }
    let mut name = [0u8; APP_NAME_MAX];
    name.copy_from_slice(&hdr[APP_HDR_NAME_OFF..APP_HDR_NAME_OFF + APP_NAME_MAX]);
    let mut payload_sha = [0u8; 32];
    payload_sha.copy_from_slice(&hdr[APP_HDR_SHA_OFF..APP_HDR_SHA_OFF + 32]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&hdr[APP_HDR_SIG_OFF..APP_HDR_SIG_OFF + 64]);
    Some(AppHeader {
        slot: hdr[10],
        name,
        name_len,
        payload_len,
        version: u64::from_le_bytes(hdr[16..24].try_into().ok()?),
        payload_sha,
        signature,
    })
}

pub fn write_app_stage_package(
    out: &mut [u8],
    name: &[u8],
    version: u64,
    payload: &[u8],
    signature: &[u8; 64],
) -> Option<usize> {
    if out.len() < APP_PKG_HEADER + payload.len()
        || name.is_empty()
        || name.len() > APP_NAME_MAX
        || payload.is_empty()
        || payload.len() > APP_STAGE_CAP
    {
        return None;
    }
    for b in out.iter_mut() {
        *b = 0;
    }
    out[0..8].copy_from_slice(APP_PKG_MAGIC);
    out[8] = APP_FORMAT_VERSION;
    out[9] = name.len() as u8;
    out[12..16].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    out[16..24].copy_from_slice(&version.to_le_bytes());
    out[APP_HDR_NAME_OFF..APP_HDR_NAME_OFF + name.len()].copy_from_slice(name);
    out[APP_HDR_SHA_OFF..APP_HDR_SHA_OFF + 32].copy_from_slice(&super::sha256::sha256(payload));
    out[APP_HDR_SIG_OFF..APP_HDR_SIG_OFF + 64].copy_from_slice(signature);
    out[APP_PKG_HEADER..APP_PKG_HEADER + payload.len()].copy_from_slice(payload);
    Some(APP_PKG_HEADER + payload.len())
}

pub fn parse_app_stage_package(buf: &[u8]) -> Option<AppPackage<'_>> {
    if buf.len() < APP_PKG_HEADER || &buf[0..8] != APP_PKG_MAGIC || buf[8] != APP_FORMAT_VERSION {
        return None;
    }
    let name_len = buf[9] as usize;
    let payload_len = u32::from_le_bytes(buf[12..16].try_into().ok()?) as usize;
    if name_len == 0 || name_len > APP_NAME_MAX || payload_len == 0 || payload_len > APP_STAGE_CAP {
        return None;
    }
    let end = APP_PKG_HEADER.checked_add(payload_len)?;
    if end > buf.len() {
        return None;
    }
    let mut name = [0u8; APP_NAME_MAX];
    name.copy_from_slice(&buf[APP_HDR_NAME_OFF..APP_HDR_NAME_OFF + APP_NAME_MAX]);
    let mut payload_sha = [0u8; 32];
    payload_sha.copy_from_slice(&buf[APP_HDR_SHA_OFF..APP_HDR_SHA_OFF + 32]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&buf[APP_HDR_SIG_OFF..APP_HDR_SIG_OFF + 64]);
    Some(AppPackage {
        name,
        name_len,
        payload: &buf[APP_PKG_HEADER..end],
        version: u64::from_le_bytes(buf[16..24].try_into().ok()?),
        payload_sha,
        signature,
    })
}

// ----------------------------------------------------------- audit log

pub const AUD_MAGIC: u32 = 0x31445541; // "AUD1" little-endian
pub const AUD_DATA_MAX: usize = 424;
pub const AUD_DIGEST_OFF: usize = 0x1E0;

/// Serialize one audit record. `prev` is the previous record's digest
/// (zeroes for the first record). Returns the record's own digest.
pub fn write_audit_record(
    rec: &mut [u8],
    seq: u64,
    tick: u64,
    event: u8,
    aux: u8,
    data: &[u8],
    prev: &[u8; 32],
) -> [u8; 32] {
    assert!(data.len() <= AUD_DATA_MAX);
    for b in rec.iter_mut() {
        *b = 0;
    }
    rec[0..4].copy_from_slice(&AUD_MAGIC.to_le_bytes());
    rec[4..12].copy_from_slice(&seq.to_le_bytes());
    rec[12..20].copy_from_slice(&tick.to_le_bytes());
    rec[20] = event;
    rec[21] = aux;
    rec[22..24].copy_from_slice(&(data.len() as u16).to_le_bytes());
    rec[24..56].copy_from_slice(prev);
    rec[56..56 + data.len()].copy_from_slice(data);
    let digest = super::sha256::sha256(&rec[..AUD_DIGEST_OFF]);
    rec[AUD_DIGEST_OFF..AUD_DIGEST_OFF + 32].copy_from_slice(&digest);
    digest
}

/// Outcome of validating a record during log replay.
pub enum AuditCheck {
    Valid(u64),
    /// Empty/unformatted sector: clean end of log.
    End,
    /// Corrupted or tampered record: chain broken at this position.
    Broken,
}

pub fn check_audit_record(rec: &[u8], expected_seq: u64, expected_prev: &[u8; 32]) -> AuditCheck {
    if rec.len() < SECTOR {
        return AuditCheck::Broken;
    }
    if u32::from_le_bytes(rec[0..4].try_into().unwrap()) == 0 {
        return AuditCheck::End;
    }
    if u32::from_le_bytes(rec[0..4].try_into().unwrap()) != AUD_MAGIC {
        return AuditCheck::Broken;
    }
    let seq = u64::from_le_bytes(rec[4..12].try_into().unwrap());
    if seq != expected_seq {
        return AuditCheck::Broken;
    }
    if !constant_time_eq(&rec[24..56], expected_prev) {
        return AuditCheck::Broken;
    }
    let digest = super::sha256::sha256(&rec[..AUD_DIGEST_OFF]);
    if !constant_time_eq(&digest, &rec[AUD_DIGEST_OFF..AUD_DIGEST_OFF + 32]) {
        return AuditCheck::Broken;
    }
    AuditCheck::Valid(seq)
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    #[test]
    fn superblock_roundtrip_and_mac() {
        let mut sb = [0u8; SECTOR];
        let key = [7u8; 32];
        write_superblock(&mut sb, Some(SlotId::B), 11, 9, &key);
        let (active, ga, gb) = parse_superblock(&sb).unwrap();
        assert_eq!(active, Some(SlotId::B));
        assert_eq!((ga, gb), (11, 9));
        assert!(superblock_valid(&key, &sb));
        // flip a payload bit: MAC must fail
        sb[0x10] ^= 1;
        assert!(!superblock_valid(&key, &sb));
        // wrong key must fail
        sb[0x10] ^= 1;
        assert!(!superblock_valid(&[8u8; 32], &sb));
        assert!(superblock_valid(&key, &sb));
    }

    #[test]
    fn config_roundtrip() {
        let mut sec = [0u8; SECTOR];
        let key = [3u8; 32];
        let text = b"hostname=dev-01\nflag=on\n";
        write_config(&mut sec, 42, text, &key);
        let (mac, gen, parsed) = parse_config(&sec).unwrap();
        assert_eq!(gen, 42);
        assert_eq!(parsed, text);
        assert!(constant_time_eq(&mac, &config_mac(&key, &sec)));
        sec[100] ^= 1;
        assert!(!constant_time_eq(&mac, &config_mac(&key, &sec)));
    }

    #[test]
    fn slot_header_roundtrip() {
        let mut hdr = [0u8; SECTOR];
        let payload = b"device-id=x\nservice heart autostart\n";
        let sig = [9u8; 64];
        write_slot_header(&mut hdr, SlotId::A, SLOT_STATE_VALID, 5, payload, &sig);
        let h = parse_slot_header(&hdr).unwrap();
        assert_eq!(h.slot, SlotId::A);
        assert_eq!(h.generation, 5);
        assert_eq!(h.payload_len as usize, payload.len());
        assert_eq!(h.signature, sig);
        assert_eq!(&h.payload_sha[..], &crate::sha256::sha256(payload)[..]);
        // MAC binds header to ciphertext
        let key = [2u8; 32];
        let ct = [1u8; 77];
        let mac = slot_mac(&key, &hdr, &ct);
        hdr[HDR_MAC_OFF..HDR_MAC_OFF + 32].copy_from_slice(&mac);
        assert!(slot_mac_ok(&key, &hdr, &ct));
        let ct2 = [1u8; 76];
        assert!(!slot_mac_ok(&key, &hdr, &ct2));
    }

    #[test]
    fn sealed_image_roundtrip_and_agent_checks() {
        use crate::ed25519;

        let vol_key = [4u8; 32];
        let payload = b"service heart autostart restart\ndevice-id=redoubt-dev-01\n";
        let seed = [7u8; 32];

        // provisioning: sign the payload for the slot header, seal the
        // image, then sign the image for the staging header
        let payload_sig = ed25519::sign(&seed, payload);
        let mut img = std::vec![0u8; SLOT_IMAGE_MAX];
        let img_len = build_slot_image(&mut img, 9, payload, &payload_sig, &vol_key);
        img.truncate(img_len);
        let img_sig = ed25519::sign(&seed, &img);

        let mut pkg = std::vec![0u8; PKG_IMAGE_OFF + img.len()];
        let total = write_stage_package(&mut pkg, &img, &img_sig);
        assert_eq!(total, PKG_IMAGE_OFF + img.len());

        // agent-side: parse + verify WITHOUT the volume key
        let (image, sig) = parse_stage_package(&pkg).unwrap();
        assert_eq!(image.len(), img.len());
        assert!(ed25519::verify(&ed25519::public_from_seed(&seed), image, &sig) == Ok(()));
        // tampered image must fail signature verification
        let mut bad = pkg.clone();
        bad[PKG_IMAGE_OFF + SECTOR + 5] ^= 1;
        let (image2, sig2) = parse_stage_package(&bad).unwrap();
        assert!(ed25519::verify(&ed25519::public_from_seed(&seed), image2, &sig2).is_err());

        // storaged-side: validate_and_load semantics via raw pieces: the
        // installed header decrypts under the volume key and its MAC binds
        let hdr = parse_slot_header(&img[..SECTOR]).unwrap();
        assert_eq!(hdr.generation, 9);
        assert_eq!(hdr.payload_len as usize, payload.len());
        let ct = &img[2 * SECTOR..2 * SECTOR + payload.len()];
        let expect_mac = {
            let mut hh = crate::hmac::HmacSha256::new(&vol_key);
            hh.update(&img[..HDR_MAC_OFF]);
            hh.update(ct);
            hh.finalize()
        };
        assert!(constant_time_eq(
            &expect_mac,
            &img[HDR_MAC_OFF..HDR_MAC_OFF + 32]
        ));

        // decryption restores plaintext with the shared seal nonce
        let mut plain = std::vec![0u8; ct.len()];
        plain.copy_from_slice(ct);
        crate::chacha20::xor_stream(&vol_key, 0, &seal_nonce(9), &mut plain);
        assert_eq!(&plain[..], payload);
    }

    #[test]
    fn app_package_and_authenticated_header_roundtrip() {
        use crate::ed25519;

        let seed = [11u8; 32];
        let key = [12u8; 32];
        let name = b"hello-app";
        let payload = b"\x7fELF pretend application bytes\0";
        let digest = crate::sha256::sha256(payload);
        let signed = app_signing_message(name, 7, payload.len(), &digest);
        let sig = ed25519::sign(&seed, &signed);

        let mut package = std::vec![0u8; APP_PKG_HEADER + payload.len()];
        let total = write_app_stage_package(&mut package, name, 7, payload, &sig).unwrap();
        assert_eq!(total, APP_PKG_HEADER + payload.len());
        let parsed = parse_app_stage_package(&package).unwrap();
        assert_eq!(&parsed.name[..parsed.name_len], name);
        assert_eq!(parsed.payload, payload);
        assert_eq!(parsed.payload_sha, digest);
        assert!(ed25519::verify(
            &ed25519::public_from_seed(&seed),
            &app_signing_message(
                &parsed.name[..parsed.name_len],
                parsed.version,
                parsed.payload.len(),
                &parsed.payload_sha
            ),
            &parsed.signature
        )
        .is_ok());

        let mut hdr = [0u8; SECTOR];
        assert!(write_app_header(&mut hdr, 3, name, 7, payload, &sig));
        let header = parse_app_header(&hdr).unwrap();
        assert_eq!(header.slot, 3);
        assert_eq!(header.version, 7);
        let mut ciphertext = payload.to_vec();
        crate::chacha20::xor_stream(&key, 0, &app_nonce(3, 7), &mut ciphertext);
        let mac = app_header_mac(&key, &hdr, &ciphertext);
        hdr[APP_HDR_MAC_OFF..APP_HDR_MAC_END].copy_from_slice(&mac);
        assert!(app_header_mac_ok(&key, &hdr, &ciphertext));
        ciphertext[0] ^= 1;
        assert!(!app_header_mac_ok(&key, &hdr, &ciphertext));
    }

    #[test]
    fn streamed_chacha_slot_decryption_uses_continuing_counter() {
        let key = [3u8; 32];
        let nonce = seal_nonce(12);
        let mut one_shot = std::vec![0x5au8; 10 * SECTOR + 37];
        let mut streamed = one_shot.clone();
        crate::chacha20::xor_stream(&key, 0, &nonce, &mut one_shot);
        let mut done = 0usize;
        while done < streamed.len() {
            let take = (streamed.len() - done).min(8 * SECTOR);
            crate::chacha20::xor_stream(
                &key,
                (done / 64) as u32,
                &nonce,
                &mut streamed[done..done + take],
            );
            done += take;
        }
        assert_eq!(streamed, one_shot);
    }

    #[test]
    fn audit_chain_detects_edit() {
        let mut rec0 = [0u8; SECTOR];
        let mut rec1 = [0u8; SECTOR];
        let zero = [0u8; 32];
        let d0 = write_audit_record(&mut rec0, 0, 100, 3, 1, b"boot A", &zero);
        let _d1 = write_audit_record(&mut rec1, 1, 105, 4, 2, b"spawn heart", &d0);
        assert!(matches!(
            check_audit_record(&rec0, 0, &zero),
            AuditCheck::Valid(0)
        ));
        assert!(matches!(
            check_audit_record(&rec1, 1, &d0),
            AuditCheck::Valid(1)
        ));
        // editing history breaks the chain at the edited record
        rec0[56] ^= 1;
        assert!(matches!(
            check_audit_record(&rec0, 0, &zero),
            AuditCheck::Broken
        ));
        // all-zero sector is the clean end marker
        let blank = [0u8; SECTOR];
        assert!(matches!(
            check_audit_record(&blank, 2, &[0u8; 32]),
            AuditCheck::End
        ));
    }

    /// Deterministic malformed-input campaign for every disk-facing parser.
    /// It supplements the valid round trips above with adversarial lengths
    /// and contents, catching bounds regressions without relying on a host
    /// fuzzer being installed in a release build environment.
    #[test]
    fn malformed_disk_records_are_total() {
        let mut state = 0x7a11_5eed_c0de_f00du64;
        for _case in 0..4096 {
            let mut sector = [0u8; SECTOR];
            for byte in &mut sector {
                // xorshift64*: cheap, deterministic, and sufficiently
                // varied for parser boundary coverage.
                state ^= state >> 12;
                state ^= state << 25;
                state ^= state >> 27;
                *byte = state.wrapping_mul(0x2545_f491_4f6c_dd1d) as u8;
            }
            let len = (state as usize) % (SECTOR + 1);
            let input = &sector[..len];
            let _ = parse_superblock(input);
            let _ = parse_config(input);
            let _ = parse_slot_header(input);
            let _ = parse_stage_package(input);
            let _ = parse_app_header(input);
            let _ = parse_app_stage_package(input);
            let _ = check_audit_record(input, state, &[0u8; 32]);
        }
    }
}
