#!/usr/bin/env bash
# Build redoubt: user servers -> kernel (with embedded servers) -> bootable BIOS image.
# Output: redoubt-bios.img in the repo root.
set -euo pipefail
cd "$(dirname "$0")"

# Generate disposable development signing material on demand. The private
# seed and derived public key are intentionally ignored by git.
if [[ ! -f keys/dev/redoubt.seed || ! -f keys/dev/redoubt.pub ]]; then
    cargo run --release --package redoubt-tools -- keygen --out keys/dev/redoubt
fi

cargo run --release --package redoubt-build

# Provision the development appliance volume on first build so a fresh
# clone boots straight into a verified system. Existing volumes are left
# untouched: updates and audit history must survive rebuilds.
if [[ ! -f store.img ]]; then
    cargo run --release --package redoubt-tools -- mkvol --image store.img --key keys/dev/redoubt
fi
