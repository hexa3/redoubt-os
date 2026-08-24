# Redoubt OS development signing keys

`redoubt.seed` + `redoubt.pub` form the **development** Ed25519 root of trust.
They sign the program-store manifest and update packages used by the
development/QEMU image, and the matching public key is pinned inside
initfs/storaged/updated. Both files are generated locally and ignored by git;
the seed must never be committed or published.

These keys exist so CI and local runs get a disposable verified-boot path.
They are NOT a production root of trust: production signing material is
provisioned from outside the repository (see PRODUCT_DIRECTION.md) via the
`--key <prefix>` argument to `redoubt-tools`, never committed here. If you
regenerate the pair (`cargo run -p redoubt-tools -- keygen --out keys/dev/redoubt`)
you must rebuild every verifying binary so their pinned public key matches.
