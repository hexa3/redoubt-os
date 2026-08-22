# Aegis Build Log

Timestamped record of the autonomous build session. Times are local.

## Session start

- 2026-08-22 ~20:50 — Environment audit: Arch Linux, Rust stable 1.97.1 present, no QEMU
  installed, passwordless sudo unavailable (cannot pacman-install), but Docker works and
  network is up. Decision: run QEMU inside a minimal Debian container
  (`docker/Dockerfile.qemu`); `run-qemu.sh` prefers a local qemu if one exists.
- 2026-08-22 ~20:50 — **The referenced `IDEAL_OS_SPEC.md` is not present anywhere on this
  machine** (searched home dir). Reconstructing requirements from the mission directive and
  documenting all spec-level decisions in `DESIGN_DECISIONS.md`. No time will be spent
  waiting on it.
- 2026-08-22 ~20:52 — Toolchain: nightly + `x86_64-unknown-none` target +
  `llvm-tools-preview` + `rust-src` installing in background.
- 2026-08-22 ~20:55 — Architecture choice: x86-64 (host-native, best-documented Rust os-dev
  ecosystem, QEMU trivially available). Kernel language: Rust (`#![no_std]`, freestanding
  target). Boot path: `bootloader` crate v0.11 (BIOS image) to avoid hand-writing boot
  sector/long-mode trampoline; attributed in DESIGN_DECISIONS.md.
