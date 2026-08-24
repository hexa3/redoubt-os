fn main() {
    let initfs = std::env::var_os("CARGO_BIN_FILE_REDOUBT_INITFS_redoubt-initfs")
        .expect("initfs artifact missing");
    let console = std::env::var_os("CARGO_BIN_FILE_REDOUBT_CONSOLE_redoubt-console")
        .expect("console artifact missing");
    println!(
        "cargo:rustc-env=REDOUBT_INITFS_PATH={}",
        initfs.to_string_lossy()
    );
    println!(
        "cargo:rustc-env=REDOUBT_CONSOLE_PATH={}",
        console.to_string_lossy()
    );
}
