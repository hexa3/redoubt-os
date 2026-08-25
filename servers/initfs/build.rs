use std::path::PathBuf;

use redoubt_crypto::{ed25519, sha256};

/// Build-time signing for the embedded program store.
///
/// Every program linked into initfs is digested with SHA-256; the manifest
/// listing name/length/digest is signed with the development Ed25519 key.
/// At boot initfs verifies this signature against the pinned public key and
/// refuses to launch anything whose digest does not match — fail closed.
///
/// Production builds provision a different key pair from outside the repo
/// via REDOUBT_SIGNING_PREFIX; the committed keys/dev pair exists only so CI
/// and local QEMU runs exercise real verification deterministically.

fn main() {
    // A production build may use an externally provisioned key. Cargo must
    // not reuse a manifest and pinned key compiled under a different prefix.
    println!("cargo:rerun-if-env-changed=REDOUBT_SIGNING_PREFIX");
    let ld = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("userlib")
        .join("x86_64-user.ld");
    println!("cargo:rustc-link-arg=-T{}", ld.display());
    println!("cargo:rustc-link-arg=-no-pie");
    println!("cargo:rustc-link-arg=-s");
    println!("cargo:rerun-if-changed={}", ld.display());

    // ---- embedded programs -------------------------------------------------
    let mut programs: Vec<(String, PathBuf)> = Vec::new();
    for (name, var) in [
        ("hello", "CARGO_BIN_FILE_REDOUBT_HELLO_redoubt-hello"),
        (
            "fault-test",
            "CARGO_BIN_FILE_REDOUBT_FAULT_TEST_redoubt-fault-test",
        ),
        ("heart", "CARGO_BIN_FILE_REDOUBT_HEART_redoubt-heart"),
        ("shell", "CARGO_BIN_FILE_REDOUBT_SHELL_redoubt-shell"),
        (
            "storaged",
            "CARGO_BIN_FILE_REDOUBT_STORAGED_redoubt-storaged",
        ),
        ("supd", "CARGO_BIN_FILE_REDOUBT_SUPD_redoubt-supd"),
        ("updated", "CARGO_BIN_FILE_REDOUBT_UPDATED_redoubt-updated"),
    ] {
        match std::env::var_os(var) {
            Some(p) => programs.push((name.to_string(), PathBuf::from(p))),
            None => panic!("program-store artifact dependency missing: {var}"),
        }
    }

    // ---- manifest ----------------------------------------------------------
    let mut manifest = String::from("redoubt-manifest v1\n");
    for (name, path) in &programs {
        let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let digest = sha256::sha256(&bytes);
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        manifest.push_str(&format!("{name} {} {hex}\n", bytes.len()));
        println!("cargo:rerun-if-changed={}", path.display());
    }

    // ---- signing key -------------------------------------------------------
    let manifest_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let key_prefix = std::env::var_os("REDOUBT_SIGNING_PREFIX")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            manifest_dir
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("keys")
                .join("dev")
                .join("redoubt")
        });
    println!("cargo:rerun-if-changed={}.seed", key_prefix.display());
    println!("cargo:rerun-if-changed={}.pub", key_prefix.display());

    let seed_text = std::fs::read_to_string(format!("{}.seed", key_prefix.display()))
        .unwrap_or_else(|e| {
            panic!(
                "signing key {}.seed missing ({e}); generate one with \
                 `cargo run -p redoubt-tools -- keygen --out {}`",
                key_prefix.display(),
                key_prefix.display()
            )
        });
    let seed_hex = seed_text.trim();
    let mut seed = [0u8; 32];
    for i in 0..32 {
        seed[i] = u8::from_str_radix(&seed_hex[i * 2..i * 2 + 2], 16)
            .unwrap_or_else(|e| panic!("bad seed hex: {e}"));
    }
    let pub_text = std::fs::read_to_string(format!("{}.pub", key_prefix.display()))
        .unwrap_or_else(|e| panic!("public key {}.pub missing: {e}", key_prefix.display()));

    let signature = ed25519::sign(&seed, manifest.as_bytes());

    // sanity: our own signature must verify against OUR copy of the pubkey;
    // initfs re-verifies against the same pinned bytes at boot.
    let mut pub_arr = [0u8; 32];
    let pub_hex = pub_text.trim();
    for i in 0..32 {
        pub_arr[i] = u8::from_str_radix(&pub_hex[i * 2..i * 2 + 2], 16)
            .unwrap_or_else(|e| panic!("bad pubkey hex: {e}"));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&signature);
    assert_eq!(
        ed25519::verify(&pub_arr, manifest.as_bytes(), &sig_arr),
        Ok(()),
        "manifest self-check failed"
    );

    // ---- outputs for include_bytes! ---------------------------------------
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let manifest_path = out_dir.join("store_manifest.txt");
    let sig_path = out_dir.join("store_manifest.sig");
    std::fs::write(&manifest_path, &manifest).unwrap();
    std::fs::write(&sig_path, &sig_arr).unwrap();
    println!(
        "cargo:rustc-env=REDOUBT_STORE_MANIFEST={}",
        manifest_path.display()
    );
    println!("cargo:rustc-env=REDOUBT_STORE_SIG={}", sig_path.display());
    println!("cargo:rustc-env=REDOUBT_STORE_PUB={}", pub_hex);

    // expose individual program paths for the embedded store
    for (name, path) in &programs {
        let var = format!("REDOUBT_ELF_{}", name.to_uppercase().replace('-', "_"));
        println!("cargo:rustc-env={var}={}", path.display());
    }
}
