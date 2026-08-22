fn main() {
    let bios_path = env!("AEGIS_BIOS_PATH");
    let dest = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("aegis-bios.img");
    std::fs::copy(bios_path, &dest).unwrap();
    println!("{}", dest.display());
}
