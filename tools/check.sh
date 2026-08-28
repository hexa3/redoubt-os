#!/usr/bin/env bash
# Reproducible host + boot validation for redoubt.
#
# Runs host-safe unit tests, verifies formatting, builds a fresh BIOS image,
# and proves that QEMU reaches the verified interactive shell.  The emulator
# is deliberately terminated after a bounded time because a healthy OS keeps
# running after boot.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo fmt --all -- --check
cargo clippy -p redoubt-crypto --all-targets --locked -- -D warnings
cargo test --workspace --locked
./build.sh

boot_log="$(mktemp -t redoubt-boot.XXXXXX)"
cleanup() { rm -f "$boot_log"; }
trap cleanup EXIT

set +e
timeout "${REDOUBT_BOOT_TIMEOUT:-16s}" ./run-qemu.sh >"$boot_log" 2>&1
status=$?
set -e

# `timeout` is the expected result for a successful non-interactive boot.
if [[ "$status" -ne 124 ]]; then
    cat "$boot_log" >&2
    echo "error: QEMU ended before the smoke-test timeout (status $status)" >&2
    exit 1
fi

for marker in \
    "initfs: program store signature VERIFIED" \
    "initfs: storaged launched" \
    "initfs: supervisor launched" \
    "redoubt shell ready"; do
    if ! rg -Fq "$marker" "$boot_log"; then
        cat "$boot_log" >&2
        echo "error: boot did not reach: $marker" >&2
        exit 1
    fi
done

echo "redoubt check: host tests, image build, and verified-shell boot passed"
