#!/usr/bin/env bash
# Build redoubt: user servers -> kernel (with embedded servers) -> bootable BIOS image.
# Output: redoubt-bios.img in the repo root.
set -euo pipefail
cd "$(dirname "$0")"

# Generate disposable development signing material on demand. The private
# seed and derived public key are intentionally ignored by git.
SIGNING_PREFIX="${REDOUBT_SIGNING_PREFIX:-keys/dev/redoubt}"
if [[ ! -f "${SIGNING_PREFIX}.seed" || ! -f "${SIGNING_PREFIX}.pub" ]]; then
    if [[ "${SIGNING_PREFIX}" != "keys/dev/redoubt" ]]; then
        echo "error: production signing key ${SIGNING_PREFIX}.{seed,pub} is missing" >&2
        exit 2
    fi
    cargo run --release --package redoubt-tools -- keygen --out "$SIGNING_PREFIX"
fi

cargo run --release --package redoubt-build

# Provision the development appliance volume on first build so a fresh
# clone boots straight into a verified system. Existing volumes are left
# untouched: updates and audit history must survive rebuilds.
if [[ ! -f store.img ]]; then
    cargo run --release --package redoubt-tools -- mkvol --image store.img --key "$SIGNING_PREFIX"
fi
