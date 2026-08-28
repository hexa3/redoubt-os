#!/usr/bin/env bash
# Exercise a real shell session without changing the developer's appliance
# volume. This is intentionally separate from check.sh: it needs Docker's
# QEMU monitor and takes longer than the boot smoke test.
set -euo pipefail
cd "$(dirname "$0")/.."

./build.sh >/dev/null

# drive.sh mounts this repository at /work in its QEMU container, so the
# disposable volume must live below the repository rather than /tmp.
scratch_dir="$(mktemp -d .redoubt-interactive.XXXXXX)"
session_log="$scratch_dir/session.log"
cleanup() { rm -rf "$scratch_dir"; }
trap cleanup EXIT

# The session generates audit records, so work against a disposable copy.
cp store.img "$scratch_dir/store.img"
REDOUBT_VOLUME="$scratch_dir/store.img" \
    ./tools/drive.sh "${REDOUBT_DRIVE_WAIT:-7}" hello "exec fault-test" services >"$session_log"

for marker in \
    "ok: 'hello' exited 7" \
    "ok: 'fault-test' exited 262" \
    "heart running r=0 f=0"; do
    if ! rg -Fq "$marker" "$session_log"; then
        cat "$session_log" >&2
        echo "error: interactive check did not reach: $marker" >&2
        exit 1
    fi
done

echo "redoubt interactive check: execution, fault containment, and supervision passed"
