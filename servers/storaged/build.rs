use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=REDOUBT_SIGNING_PREFIX");
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
    println!(
        "cargo:rustc-env=REDOUBT_STORE_PUB_FILE={}.pub",
        key_prefix.display()
    );
    println!("cargo:rerun-if-changed={}.pub", key_prefix.display());

    let updated = PathBuf::from(
        std::env::var_os("CARGO_BIN_FILE_REDOUBT_UPDATED_redoubt-updated")
            .expect("updated artifact dependency missing"),
    );
    println!("cargo:rustc-env=REDOUBT_UPDATED_ELF={}", updated.display());
    println!("cargo:rerun-if-changed={}", updated.display());

    let ld = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("userlib")
        .join("x86_64-user.ld");
    println!("cargo:rustc-link-arg=-T{}", ld.display());
    println!("cargo:rustc-link-arg=-no-pie");
    // stripped binaries keep the boot image small; loader ignores debug sections
    // but the spawn-size bound counts the whole file
    println!("cargo:rustc-link-arg=-s");
    println!("cargo:rerun-if-changed={}", ld.display());
}
