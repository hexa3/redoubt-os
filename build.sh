#!/usr/bin/env bash
# Build Aegis: user servers -> kernel (with embedded servers) -> bootable BIOS image.
# Output: aegis-bios.img in the repo root.
set -euo pipefail
cd "$(dirname "$0")"

cargo run --release --package aegis-build
