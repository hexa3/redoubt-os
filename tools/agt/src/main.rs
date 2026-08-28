//! redoubt-tools: host-side provisioning for the redoubt appliance image.
//!
//! Subcommands:
//!   keygen   — generate an Ed25519 development signing pair
//!   mkvol    — create/format the persistent volume (store.img)
//!   updpack  — build, sign, and stage an update package into a volume
//!   apppack  — sign and stage an installable application package
//!   inspect  — print volume/slot/audit state
//!
//! Signing keys are provisioned from outside the repository for production;
//! the development pair under keys/dev exists only to bootstrap CI and
//! local QEMU runs and MUST NOT be treated as a production root of trust.

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use redoubt_crypto::layout;
use redoubt_crypto::{ed25519, sha256};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let r = match args.get(1).map(|s| s.as_str()) {
        Some("keygen") => cmd_keygen(&args[2..]),
        Some("mkvol") => cmd_mkvol(&args[2..]),
        Some("updpack") => cmd_updpack(&args[2..]),
        Some("apppack") => cmd_apppack(&args[2..]),
        Some("inspect") => cmd_inspect(&args[2..]),
        _ => usage(),
    };
    if let Err(e) = r {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn usage() -> Result<(), String> {
    println!(
        "usage:\n  redoubt-tools keygen --out <prefix>\n  \
         redoubt-tools mkvol --image <img> [--size-mb N] --key <prefix>\n  \
         redoubt-tools updpack --image <img> --payload <file> --gen N --key <prefix> [--corrupt]\n  \
         redoubt-tools apppack --image <img> --elf <file> --name <id> --version N --key <prefix> [--corrupt]\n  \
         redoubt-tools inspect --image <img>"
    );
    Ok(())
}

// ---------------------------------------------------------------- helpers

fn arg_of(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn flag_present(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("bad hex length".into());
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|e| format!("bad hex: {e}")))
        .collect()
}

struct Volume {
    file: std::fs::File,
    sectors: u64,
}

impl Volume {
    fn open(path: &Path) -> Result<Volume, String> {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| format!("open {}: {e}", path.display()))?;
        let len = f.metadata().map_err(|e| e.to_string())?.len();
        if len % layout::SECTOR as u64 != 0 {
            return Err(format!("{}: not sector-aligned", path.display()));
        }
        Ok(Volume {
            file: f,
            sectors: len / layout::SECTOR as u64,
        })
    }

    fn create(path: &Path, sectors: u64) -> Result<Volume, String> {
        if sectors == 0 {
            return Err("volume must contain at least one sector".into());
        }
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create {}: {e}", parent.display()))?;
        }
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| format!("create {}: {e}", path.display()))?;
        // grow to exactly sectors * 512 bytes
        let end = sectors
            .checked_mul(layout::SECTOR as u64)
            .ok_or("volume size overflow")?;
        (&f).seek(SeekFrom::Start(end.saturating_sub(1)))
            .and_then(|_| Write::write_all(&mut &f, &[0]))
            .map_err(|e| format!("size {}: {e}", path.display()))?;
        Ok(Volume { file: f, sectors })
    }

    fn lba_offset(&self, lba: u64, count: u64) -> Result<u64, String> {
        let end = lba
            .checked_add(count)
            .ok_or_else(|| format!("LBA range overflow: {lba}+{count}"))?;
        if end > self.sectors {
            return Err(format!("access past end of volume: lba {lba}"));
        }
        lba.checked_mul(layout::SECTOR as u64)
            .ok_or_else(|| format!("LBA offset overflow: {lba}"))
    }

    fn read_lba(&mut self, lba: u64, count: u64, buf: &mut [u8]) -> Result<(), String> {
        let bytes = usize::try_from(
            count
                .checked_mul(layout::SECTOR as u64)
                .ok_or("read length overflow")?,
        )
        .map_err(|_| "read length does not fit host address space")?;
        if buf.len() != bytes {
            return Err(format!(
                "read buffer is {} bytes; expected {bytes}",
                buf.len()
            ));
        }
        let offset = self.lba_offset(lba, count)?;
        self.file
            .seek(SeekFrom::Start(offset))
            .and_then(|_| self.file.read_exact(buf))
            .map_err(|e| format!("read lba {lba}: {e}"))
    }

    fn write_lba(&mut self, lba: u64, buf: &[u8]) -> Result<(), String> {
        if buf.len() % layout::SECTOR != 0 {
            return Err(format!(
                "write buffer is not {}-byte aligned",
                layout::SECTOR
            ));
        }
        let count = (buf.len() / layout::SECTOR) as u64;
        let offset = self.lba_offset(lba, count)?;
        self.file
            .seek(SeekFrom::Start(offset))
            .and_then(|_| self.file.write_all(buf))
            .map_err(|e| format!("write lba {lba}: {e}"))
    }

    fn flush(&mut self) -> Result<(), String> {
        self.file.flush().map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod volume_tests {
    use super::*;

    fn volume(sectors: u64) -> Volume {
        Volume {
            file: std::fs::File::open("/dev/null").unwrap(),
            sectors,
        }
    }

    #[test]
    fn lba_bounds_reject_out_of_range_and_overflow() {
        let vol = volume(10);
        assert_eq!(vol.lba_offset(9, 1).unwrap(), 9 * layout::SECTOR as u64);
        assert!(vol.lba_offset(10, 1).is_err());
        assert!(vol.lba_offset(u64::MAX, 1).is_err());
        assert!(vol.lba_offset(9, u64::MAX).is_err());
    }

    #[test]
    fn lba_bounds_accept_an_empty_write_at_the_end() {
        let vol = volume(10);
        assert_eq!(vol.lba_offset(10, 0).unwrap(), 10 * layout::SECTOR as u64);
    }
}

/// The factory system definition written into slot A at format time. Must
/// stay in sync with storaged's compiled-in recovery default.
pub const FACTORY_PAYLOAD: &str = "\
# redoubt system definition v1
device-id=redoubt-dev-01
min-generation=1
service heart autostart restart
";

const FACTORY_CONFIG: &str = "hostname=redoubt-dev-01\n";

fn load_key(prefix: &str) -> Result<[u8; 32], String> {
    let seed_path = PathBuf::from(format!("{prefix}.seed"));
    let text = std::fs::read_to_string(&seed_path)
        .map_err(|e| format!("read {}: {e}", seed_path.display()))?;
    let mut seed = [0u8; 32];
    let raw = hex_decode(text.trim())?;
    if raw.len() != seed.len() {
        return Err(format!(
            "{}: expected a 32-byte Ed25519 seed, got {} bytes",
            seed_path.display(),
            raw.len()
        ));
    }
    seed.copy_from_slice(&raw);
    Ok(seed)
}

// ----------------------------------------------------------------- keygen

fn cmd_keygen(args: &[String]) -> Result<(), String> {
    let out = arg_of(args, "--out").ok_or("keygen needs --out <prefix>")?;
    let prefix = PathBuf::from(&out);
    if let Some(parent) = prefix.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let seed_path = PathBuf::from(format!("{out}.seed"));
    let pub_path = PathBuf::from(format!("{out}.pub"));
    if seed_path.exists() || pub_path.exists() {
        return Err(format!(
            "refusing to overwrite existing key material at {}",
            prefix.display()
        ));
    }
    let seed: [u8; 32] = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| {
            let mut b = [0u8; 32];
            f.read_exact(&mut b)?;
            Ok(b)
        })
        .map_err(|e| format!("entropy: {e}"))?;
    let public = ed25519::public_from_seed(&seed);
    let mut seed_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&seed_path)
        .map_err(|e| format!("create {}: {e}", seed_path.display()))?;
    seed_file
        .write_all((hex_encode(&seed) + "\n").as_bytes())
        .map_err(|e| format!("write {}: {e}", seed_path.display()))?;
    let mut pub_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pub_path)
        .map_err(|e| format!("create {}: {e}", pub_path.display()))?;
    pub_file
        .write_all((hex_encode(&public) + "\n").as_bytes())
        .map_err(|e| format!("write {}: {e}", pub_path.display()))?;
    println!(
        "wrote {}.seed (keep private) and {}.pub",
        Path::new(&out).display(),
        Path::new(&out).display()
    );
    Ok(())
}

// ------------------------------------------------------------------ mkvol

fn cmd_mkvol(args: &[String]) -> Result<(), String> {
    let image = arg_of(args, "--image").ok_or("mkvol needs --image")?;
    let key_prefix = arg_of(args, "--key").unwrap_or_else(|| "keys/redoubt-dev".into());
    let size_mb: u64 = match arg_of(args, "--size-mb") {
        Some(s) => s.parse().map_err(|_| "bad --size-mb")?,
        None => 16,
    };
    let sectors = size_mb
        .checked_mul(1024 * 1024)
        .ok_or("--size-mb overflow")?
        / layout::SECTOR as u64;
    // The staging region has the highest allocated LBA, so its end is the
    // minimum geometry required before formatting starts.
    let min_sectors = layout::STAGING_LBA + layout::STAGING_SECTORS;
    if sectors < min_sectors {
        return Err(format!(
            "volume is too small: {sectors} sectors; need at least {min_sectors}"
        ));
    }

    let path = PathBuf::from(&image);
    let mut vol = if path.exists() {
        // refuse to clobber a formatted volume silently
        let mut v = Volume::open(&path)?;
        let mut sb = [0u8; layout::SECTOR];
        v.read_lba(0, 1, &mut sb)?;
        if &sb[0..8] == layout::SB_MAGIC {
            return Err(format!("{image} is already formatted; delete it first"));
        }
        v
    } else {
        Volume::create(&path, sectors)?
    };
    if vol.sectors < min_sectors {
        return Err(format!(
            "{image} is too small: {} sectors; need at least {min_sectors}",
            vol.sectors
        ));
    }

    let seed = load_key(&key_prefix)?;
    let signature_holder = seed; // naming clarity below

    // volume key from host entropy
    let vol_key: [u8; 32] = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| {
            let mut b = [0u8; 32];
            f.read_exact(&mut b)?;
            Ok(b)
        })
        .map_err(|e| format!("entropy: {e}"))?;

    let payload = FACTORY_PAYLOAD.as_bytes();
    let sig = ed25519::sign(&signature_holder, payload);
    let generation: u64 = 1;

    // superblock: slot A active
    let mut sb = [0u8; layout::SECTOR];
    layout::write_superblock(&mut sb, Some(layout::SlotId::A), generation, 0, &vol_key);
    vol.write_lba(layout::SUPERBLOCK_LBA, &sb)?;

    // empty runtime config with hostname default
    let mut cfg = [0u8; layout::SECTOR];
    layout::write_config(&mut cfg, 0, FACTORY_CONFIG.as_bytes(), &vol_key);
    vol.write_lba(layout::CONFIG_LBA, &cfg)?;

    // slot A header + encrypted payload
    write_slot(
        &mut vol,
        layout::SlotId::A,
        generation,
        payload,
        &sig,
        &vol_key,
    )?;
    // slot B left EMPTY (state byte zero via all-zero header)

    // clear staging + audit regions
    let zeros = [0u8; layout::SECTOR];
    for lba in layout::STAGING_LBA..layout::STAGING_LBA + layout::STAGING_SECTORS {
        vol.write_lba(lba, &zeros)?;
    }
    for lba in layout::AUDIT_START_LBA..layout::AUDIT_START_LBA + 8 {
        vol.write_lba(lba, &zeros)?;
    }
    vol.flush()?;
    println!("formatted {image}: {} MiB, gen {generation} active on A", {
        let s = vol.sectors;
        s * layout::SECTOR as u64 / (1024 * 1024)
    });
    Ok(())
}

/// Write one slot: header + ciphertext + MAC.
fn write_slot(
    vol: &mut Volume,
    slot: layout::SlotId,
    generation: u64,
    payload: &[u8],
    sig: &[u8; 64],
    vol_key: &[u8; 32],
) -> Result<(), String> {
    let mut hdr = [0u8; layout::SECTOR];
    layout::write_slot_header(
        &mut hdr,
        slot,
        layout::SLOT_STATE_VALID,
        generation,
        payload,
        sig,
    );
    let nonce = slot.data_nonce(b'S', generation);
    let mut ct = payload.to_vec();
    redoubt_crypto::chacha20::xor_stream(vol_key, 0, &nonce, &mut ct);
    let mac = layout::slot_mac(vol_key, &hdr, &ct);
    hdr[layout::HDR_MAC_OFF..layout::HDR_MAC_OFF + 32].copy_from_slice(&mac);

    // payload region: ciphertext padded with zeros
    let mut region = vec![0u8; layout::PAYLOAD_CAP];
    region[..ct.len()].copy_from_slice(&ct);

    vol.write_lba(slot.hdr_lba(), &hdr)?;
    vol.write_lba(slot.payload_lba(), &region)
}

// ---------------------------------------------------------------- updpack

fn cmd_updpack(args: &[String]) -> Result<(), String> {
    let image = arg_of(args, "--image").ok_or("updpack needs --image")?;
    let payload_path = arg_of(args, "--payload").ok_or("updpack needs --payload <file>")?;
    let gen: u64 = arg_of(args, "--gen")
        .ok_or("updpack needs --gen N")?
        .parse()
        .map_err(|_| "bad --gen")?;
    let key_prefix = arg_of(args, "--key").unwrap_or_else(|| "keys/dev/redoubt".into());
    let corrupt = flag_present(args, "--corrupt");

    let seed = load_key(&key_prefix)?;
    let mut vol = Volume::open(Path::new(&image))?;

    // read volume key from superblock (dev platform: key lives there)
    let mut sb = [0u8; layout::SECTOR];
    vol.read_lba(0, 1, &mut sb)?;
    layout::parse_superblock(&sb).ok_or("not a formatted redoubt volume".to_string())?;
    let mut vol_key = [0u8; 32];
    vol_key.copy_from_slice(&sb[layout::SB_KEY_OFF..layout::SB_KEY_OFF + 32]);
    if !layout::superblock_valid(&vol_key, &sb) {
        return Err("superblock MAC invalid".into());
    }

    let payload = std::fs::read(&payload_path).map_err(|e| format!("{payload_path}: {e}"))?;
    if payload.len() > layout::PAYLOAD_CAP {
        return Err("payload too large for slot capacity".into());
    }
    let payload_sig = ed25519::sign(&seed, &payload);

    // seal the full slot image (header + gap + encrypted payload)
    let mut img = vec![0u8; layout::SLOT_IMAGE_MAX];
    let img_len = layout::build_slot_image(&mut img, gen, &payload, &payload_sig, &vol_key);
    img.truncate(img_len);
    let image_sig = ed25519::sign(&seed, &img);

    let mut pkg = vec![0u8; layout::PKG_IMAGE_OFF + img.len()];
    let total = layout::write_stage_package(&mut pkg, &img, &image_sig);
    if corrupt {
        // Tamper with the SEALED IMAGE after signing: exactly what a
        // malicious delivery channel would produce. The device-side
        // Ed25519 check must reject this.
        pkg[layout::PKG_IMAGE_OFF + 2 * layout::SECTOR] ^= 0x20;
    }
    while pkg.len() % layout::SECTOR != 0 || pkg.len() < total {
        pkg.push(0);
    }
    if total > (layout::STAGING_SECTORS as usize) * layout::SECTOR {
        return Err("package exceeds staging region".into());
    }
    vol.write_lba(layout::STAGING_LBA, &pkg)?;
    vol.flush()?;

    let sha_hex = hex_encode(&sha256::sha256(&payload));
    if corrupt {
        println!("staged CORRUPTED package gen {gen} ({sha_hex}) - device must reject");
    } else {
        println!(
            "staged package gen {gen}, {} bytes, payload sha {sha_hex}",
            payload.len()
        );
    }
    Ok(())
}

// ---------------------------------------------------------------- apppack

/// Build and stage a signed application package. The device verifies the
/// signature before it writes anything to an application slot; the package
/// itself is intentionally plaintext because its staging area is transient.
fn cmd_apppack(args: &[String]) -> Result<(), String> {
    let image = arg_of(args, "--image").ok_or("apppack needs --image")?;
    let elf_path = arg_of(args, "--elf").ok_or("apppack needs --elf <file>")?;
    let name = arg_of(args, "--name").ok_or("apppack needs --name <id>")?;
    let version: u64 = arg_of(args, "--version")
        .ok_or("apppack needs --version N")?
        .parse()
        .map_err(|_| "bad --version")?;
    let key_prefix = arg_of(args, "--key").unwrap_or_else(|| "keys/dev/redoubt".into());
    let corrupt = flag_present(args, "--corrupt");

    if !valid_app_name(name.as_bytes()) {
        return Err("app name must be 1..24 ASCII letters, digits, or hyphens".into());
    }
    let payload = std::fs::read(&elf_path).map_err(|e| format!("{elf_path}: {e}"))?;
    if payload.is_empty() || payload.len() > layout::APP_STAGE_CAP {
        return Err(format!(
            "application is {} bytes; staging capacity is {} bytes",
            payload.len(),
            layout::APP_STAGE_CAP
        ));
    }

    let seed = load_key(&key_prefix)?;
    let digest = sha256::sha256(&payload);
    let signing = layout::app_signing_message(name.as_bytes(), version, payload.len(), &digest);
    let signature = ed25519::sign(&seed, &signing);
    let mut package = vec![0u8; layout::APP_PKG_HEADER + payload.len()];
    let total = layout::write_app_stage_package(
        &mut package,
        name.as_bytes(),
        version,
        &payload,
        &signature,
    )
    .ok_or("could not encode app package")?;
    if corrupt {
        package[layout::APP_PKG_HEADER] ^= 0x20;
    }
    package.resize(
        (total + layout::SECTOR - 1) / layout::SECTOR * layout::SECTOR,
        0,
    );

    let mut vol = Volume::open(Path::new(&image))?;
    let mut sb = [0u8; layout::SECTOR];
    vol.read_lba(layout::SUPERBLOCK_LBA, 1, &mut sb)?;
    if layout::parse_superblock(&sb).is_none() {
        return Err("not a formatted redoubt volume".into());
    }
    vol.write_lba(layout::STAGING_LBA, &package)?;
    vol.flush()?;

    let sha_hex = hex_encode(&digest);
    if corrupt {
        println!("staged CORRUPTED app '{name}' v{version} ({sha_hex}) - device must reject");
    } else {
        println!(
            "staged app '{name}' v{version}, {} bytes, sha {sha_hex}",
            payload.len()
        );
    }
    Ok(())
}

fn valid_app_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= layout::APP_NAME_MAX
        && name.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-')
}

// ---------------------------------------------------------------- inspect

fn cmd_inspect(args: &[String]) -> Result<(), String> {
    let image = arg_of(args, "--image").ok_or("inspect needs --image")?;
    let mut vol = Volume::open(Path::new(&image))?;
    let mut sec = [0u8; layout::SECTOR];
    let mut hdr = [0u8; layout::SECTOR];

    vol.read_lba(0, 1, &mut sec)?;
    if &sec[0..8] != layout::SB_MAGIC {
        println!("unformatted volume");
        return Ok(());
    }
    let (active, ga, gb) = layout::parse_superblock(&sec).ok_or("bad superblock version")?;
    let mut vol_key = [0u8; 32];
    vol_key.copy_from_slice(&sec[layout::SB_KEY_OFF..layout::SB_KEY_OFF + 32]);
    println!("volume: {} sectors", vol.sectors);
    println!(
        "superblock: active={} genA={ga} genB={gb} mac_ok={}",
        active
            .map(|s| match s {
                layout::SlotId::A => "A",
                layout::SlotId::B => "B",
            })
            .unwrap_or("none"),
        layout::superblock_valid(&vol_key, &sec),
    );

    for slot in [layout::SlotId::A, layout::SlotId::B] {
        vol.read_lba(slot.hdr_lba(), 1, &mut hdr)?;
        match layout::parse_slot_header(&hdr) {
            None => println!("slot {}: EMPTY", if slot.num() == 1 { "A" } else { "B" }),
            Some(hd) => {
                println!(
                    "slot {}: state={} gen={} len={} sha={}…",
                    if slot.num() == 1 { "A" } else { "B" },
                    hd.state,
                    hd.generation,
                    hd.payload_len,
                    hex_encode(&hd.payload_sha[..6])
                );
            }
        }
    }

    for app_slot in 0..layout::APP_SLOTS as u8 {
        let Some(lba) = layout::app_slot_lba(app_slot) else {
            continue;
        };
        vol.read_lba(lba, 1, &mut hdr)?;
        let Some(app) = layout::parse_app_header(&hdr) else {
            continue;
        };
        let sectors = (app.payload_len + layout::SECTOR - 1) / layout::SECTOR;
        let mut ciphertext = vec![0u8; sectors * layout::SECTOR];
        vol.read_lba(lba + 1, sectors as u64, &mut ciphertext)?;
        let mac_ok = layout::app_header_mac_ok(&vol_key, &hdr, &ciphertext[..app.payload_len]);
        redoubt_crypto::chacha20::xor_stream(
            &vol_key,
            0,
            &layout::app_nonce(app.slot, app.version),
            &mut ciphertext[..app.payload_len],
        );
        let sha_ok = sha256::sha256(&ciphertext[..app.payload_len]) == app.payload_sha;
        println!(
            "app slot {}: {} v{} len={} mac_ok={} sha_ok={}",
            app.slot,
            String::from_utf8_lossy(&app.name[..app.name_len]),
            app.version,
            app.payload_len,
            mac_ok,
            sha_ok
        );
    }

    // audit tail: walk the hash chain from record 0
    let mut prev = [0u8; 32];
    let mut seq = 0u64;
    loop {
        if seq as usize >= layout::AUDIT_RECORDS {
            break;
        }
        vol.read_lba(layout::AUDIT_START_LBA + seq, 1, &mut sec)?;
        match layout::check_audit_record(&sec, seq, &prev) {
            layout::AuditCheck::Valid(_) => {
                prev.copy_from_slice(&sec[layout::AUD_DIGEST_OFF..layout::AUD_DIGEST_OFF + 32]);
                seq += 1;
            }
            layout::AuditCheck::End => break,
            layout::AuditCheck::Broken => {
                println!("audit: BROKEN CHAIN after record {}", seq.saturating_sub(1));
                break;
            }
        }
    }
    println!("audit: {seq} valid records");
    Ok(())
}
