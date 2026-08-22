fn main() {
    let initfs = std::env::var_os("CARGO_BIN_FILE_AEGIS_INITFS_aegis-initfs")
        .expect("initfs artifact missing");
    let console = std::env::var_os("CARGO_BIN_FILE_AEGIS_CONSOLE_aegis-console")
        .expect("console artifact missing");
    println!("cargo:rustc-env=AEGIS_INITFS_PATH={}", initfs.to_string_lossy());
    println!("cargo:rustc-env=AEGIS_CONSOLE_PATH={}", console.to_string_lossy());
}
