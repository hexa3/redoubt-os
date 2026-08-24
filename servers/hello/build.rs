use std::path::PathBuf;

fn main() {
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
