#!/usr/bin/env bash
# Produce a traceable redoubt release candidate without modifying source files.
# Signing is deliberately separate: release automation must receive signing
# material from the deployment environment, never store a private key here.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT_DIR="${1:-dist}"
mkdir -p "$OUT_DIR"

: "${REDOUBT_SIGNING_PREFIX:?set REDOUBT_SIGNING_PREFIX to an externally provisioned signing-key prefix}"
case "$REDOUBT_SIGNING_PREFIX" in
    keys/dev/*|*/keys/dev/*)
        echo "error: refusing to produce a release candidate with a development key" >&2
        exit 2
        ;;
esac
if [[ ! -f "${REDOUBT_SIGNING_PREFIX}.seed" || ! -f "${REDOUBT_SIGNING_PREFIX}.pub" ]]; then
    echo "error: signing material ${REDOUBT_SIGNING_PREFIX}.{seed,pub} is missing" >&2
    exit 2
fi

REDOUBT_SIGNING_PREFIX="$REDOUBT_SIGNING_PREFIX" ./build.sh

IMAGE="$OUT_DIR/redoubt-bios.img"
VOLUME="$OUT_DIR/redoubt-store.img"
cp redoubt-bios.img "$IMAGE"
cp store.img "$VOLUME"
sha256sum "$IMAGE" "$VOLUME" >"$OUT_DIR/SHA256SUMS"
PUBKEY_SHA256="$(sha256sum "${REDOUBT_SIGNING_PREFIX}.pub" | awk '{print $1}')"

REVISION="$(git rev-parse --verify HEAD 2>/dev/null || printf 'unknown')"
# A revision without a dirty marker is misleading: a locally edited kernel
# can still be built at a valid commit. Include untracked files too, because
# generated userland and build scripts are part of the image provenance.
if test -n "$(git status --porcelain 2>/dev/null)"; then
    REVISION="${REVISION}-dirty"
fi

{
    printf 'image=redoubt-bios.img\n'
    printf 'volume=redoubt-store.img\n'
    printf 'created_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'git_revision=%s\n' "$REVISION"
    printf 'rustc=%s\n' "$(rustc --version)"
    printf 'signing_public_key_sha256=%s\n' "$PUBKEY_SHA256"
} >"$OUT_DIR/BUILD_INFO"

cargo metadata --locked --format-version 1 --no-deps >"$OUT_DIR/cargo-metadata.json"
printf 'release candidate: %s\n' "$OUT_DIR"
