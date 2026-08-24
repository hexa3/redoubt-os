#!/usr/bin/env bash
# Produce a traceable redoubt release candidate without modifying source files.
# Signing is deliberately separate: release automation must receive signing
# material from the deployment environment, never store a private key here.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT_DIR="${1:-dist}"
mkdir -p "$OUT_DIR"

./build.sh

IMAGE="$OUT_DIR/redoubt-bios.img"
cp redoubt-bios.img "$IMAGE"
sha256sum "$IMAGE" >"$OUT_DIR/SHA256SUMS"

REVISION="$(git rev-parse --verify HEAD 2>/dev/null || printf 'unknown')"
# A revision without a dirty marker is misleading: a locally edited kernel
# can still be built at a valid commit. Include untracked files too, because
# generated userland and build scripts are part of the image provenance.
if test -n "$(git status --porcelain 2>/dev/null)"; then
    REVISION="${REVISION}-dirty"
fi

{
    printf 'image=redoubt-bios.img\n'
    printf 'created_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'git_revision=%s\n' "$REVISION"
    printf 'rustc=%s\n' "$(rustc --version)"
} >"$OUT_DIR/BUILD_INFO"

cargo metadata --locked --format-version 1 --no-deps >"$OUT_DIR/cargo-metadata.json"
printf 'release candidate: %s\n' "$OUT_DIR"
