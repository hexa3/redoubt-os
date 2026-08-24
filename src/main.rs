fn main() {
    let bios_path = env!("REDOUBT_BIOS_PATH");
    let dest = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("redoubt-bios.img");
    std::fs::copy(bios_path, &dest).unwrap();
    println!("{}", dest.display());
}
