#![no_std]
#![no_main]

extern crate alloc;

use redoubt_crypto::ed25519;
use redoubt_crypto::layout;
use redoubt_userlib::{sys, CapSlot};

// redoubt-updated: the update agent.
//
// Spawned per-operation by storaged with exactly two capabilities:
//   slot 0: read  over the update-package staging region
//   slot 1: write over the inactive slot region (header + gap + payload)
//
// The staged package is an Ed25519-signed SEALED SLOT IMAGE (see
// crypto::layout). The agent holds no volume key and never sees plaintext:
// it verifies the image signature against the pinned public key and copies
// the verified bytes verbatim into the inactive slot. Decryption, digest,
// and payload-signature verification happen later under storaged's mount /
// commit paths, so a malicious or corrupted package can at worst waste the
// INACTIVE slot - the running system is untouched by construction.
//
// Exit codes:
//   0  applied   16 bad signature   17 malformed/absent package
//   18 staging I/O error            19 target write failed

static PUB_KEY_BYTES: &[u8] = include_bytes!(env!("REDOUBT_STORE_PUB_FILE"));

fn pub_key() -> [u8; ed25519::PUBLIC_LEN] {
    let mut k = [0u8; 32];
    let hex = core::str::from_utf8(PUB_KEY_BYTES).unwrap_or("").trim();
    for i in 0..32 {
        k[i] = u8::from_str_radix(hex.get(i * 2..i * 2 + 2).unwrap_or("zz"), 16).unwrap_or(0);
    }
    k
}

#[no_mangle]
fn main() -> ! {
    // Agents run silent: results travel via exit code + audit trail.
    let stage_cap = CapSlot(0);
    let slot_cap = CapSlot(1);

    // ---- read the staged package ----
    let mut pkg = alloc::vec![0u8; layout::STAGING_SECTORS as usize * layout::SECTOR];
    {
        // Block caps address their granted WINDOW relatively: our stage
        // read cap starts at the physical staging region, so offset 0.
        let mut done = 0usize;
        while done < pkg.len() {
            let take = (pkg.len() - done).min(8 * layout::SECTOR);
            let sectors = ((take + layout::SECTOR - 1) / layout::SECTOR) as u16;
            let rel_lba = (done / layout::SECTOR) as u64;
            if redoubt_userlib::block_read(stage_cap, rel_lba, sectors, &mut pkg[done..done + take])
                .is_err()
            {
                sys::exit(18);
            }
            done += take;
        }
    }

    // ---- structural parse (no keys needed) ----
    let Some((image, sig)) = layout::parse_stage_package(&pkg) else {
        sys::exit(17);
    };

    // ---- authenticity: Ed25519 over the exact bytes we will install ----
    if ed25519::verify(&pub_key(), image, &sig) != Ok(()) {
        sys::exit(16);
    }

    // ---- copy into the inactive slot region ----
    // Our write cap spans [hdr_lba, hdr_lba + 2 + payload_sectors); the
    // image layout mirrors that geometry starting at offset 0.
    {
        let mut lba_off = 0u64;
        let mut done = 0usize;
        while done < image.len() {
            let take = (image.len() - done).min(8 * layout::SECTOR);
            let sectors = ((take + layout::SECTOR - 1) / layout::SECTOR) as u16;
            // the final chunk is zero-padded out to the sector boundary
            let mut padded = [0u8; 8 * layout::SECTOR];
            padded[..take].copy_from_slice(&image[done..done + take]);
            if redoubt_userlib::block_write(slot_cap, lba_off, sectors, &padded).is_err() {
                sys::exit(19);
            }
            lba_off += sectors as u64;
            done += take;
        }
    }

    sys::exit(0)
}
