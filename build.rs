use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let kernel = PathBuf::from(
        std::env::var_os("CARGO_BIN_FILE_REDOUBT_KERNEL_redoubt-kernel")
            .expect("kernel artifact dependency missing"),
    );

    let bios_path = out_dir.join("bios.img");
    bootloader::BiosBoot::new(&kernel)
        .create_disk_image(&bios_path)
        .unwrap();

    println!("cargo:rustc-env=REDOUBT_BIOS_PATH={}", bios_path.display());
}
