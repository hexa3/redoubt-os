#!/usr/bin/env bash
# Run the Aegis disk image in QEMU.
# Prefers a locally installed qemu-system-x86_64; falls back to Docker.
# Usage: ./run-qemu.sh [path/to/image.img] [extra qemu args...]
set -euo pipefail
cd "$(dirname "$0")"

IMAGE="aegis-bios.img"
if [[ $# -gt 0 ]]; then
    IMAGE="$1"
    shift
fi

QEMU_ARGS=(
    -drive "format=raw,file=$IMAGE"
    -display none
    -serial stdio
    -no-reboot
)

run_qemu_docker() {
    docker image inspect aegis-qemu >/dev/null 2>&1 || \
        docker build -f docker/Dockerfile.qemu -t aegis-qemu . >/dev/null

    local kvm_flags=""
    if [[ -e /dev/kvm && -w /dev/kvm ]]; then
        kvm_flags="--device=/dev/kvm"
    fi

    exec docker run --rm --network none $kvm_flags \
        -u "$(id -u):$(id -g)" \
        -e HOME=/tmp \
        -v "$(pwd):/work" -w /work \
        aegis-qemu qemu-system-x86_64 "${QEMU_ARGS[@]}" "$@"
}

if command -v qemu-system-x86_64 >/dev/null 2>&1; then
    exec qemu-system-x86_64 "${QEMU_ARGS[@]}" "$@"
fi

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    run_qemu_docker "$@"
fi

echo "error: need qemu-system-x86_64 on PATH, or a working Docker install" >&2
exit 1
