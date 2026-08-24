#!/usr/bin/env bash
# Run the redoubt disk image in QEMU.
# Prefers a locally installed qemu-system-x86_64; falls back to Docker.
# Usage: ./run-qemu.sh [path/to/image.img] [extra qemu args...]
set -euo pipefail
cd "$(dirname "$0")"

IMAGE="redoubt-bios.img"
if [[ $# -gt 0 ]]; then
    IMAGE="$1"
    shift
fi

QEMU_ARGS=(-drive "format=raw,file=$IMAGE")
if [[ -f store.img ]]; then
    # persistent appliance volume rides the secondary IDE master; the
    # kernel enumerates it as disk 1 and storaged mounts it via caps
    QEMU_ARGS+=(-drive "format=raw,file=store.img,if=none,id=d1" \
                "-device" "ide-hd,drive=d1,bus=ide.1")
fi
QEMU_ARGS+=(
    -display none
    -serial stdio
    -no-reboot
)

run_qemu_docker() {
    docker image inspect redoubt-qemu >/dev/null 2>&1 || \
        docker build -f docker/Dockerfile.qemu -t redoubt-qemu . >/dev/null

    local kvm_flags=""
    if [[ -e /dev/kvm && -w /dev/kvm ]]; then
        kvm_flags="--device=/dev/kvm"
    fi

    exec docker run --rm --network none $kvm_flags \
        -u "$(id -u):$(id -g)" \
        -e HOME=/tmp \
        -v "$(pwd):/work" -w /work \
        redoubt-qemu qemu-system-x86_64 "${QEMU_ARGS[@]}" "$@"
}

if command -v qemu-system-x86_64 >/dev/null 2>&1; then
    exec qemu-system-x86_64 "${QEMU_ARGS[@]}" "$@"
fi

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    run_qemu_docker "$@"
fi

echo "error: need qemu-system-x86_64 on PATH, or a working Docker install" >&2
exit 1
