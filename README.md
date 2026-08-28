# redoubt

`redoubt` is a bootable x86_64 microkernel appliance OS. Its small kernel
starts isolated userspace servers for the console, verified program store,
encrypted persistent storage, service supervision, and signed updates.

The resulting BIOS image boots directly in QEMU into an interactive shell.
See [platform support](PLATFORMS.md) before selecting hardware.

## What is implemented

- Ring-3 user programs, separate address spaces, NX/W^X mappings, timer
  scheduling, keyboard input, and framebuffer/serial consoles.
- Capability-limited IPC, task spawn, targeted child waits, task lifecycle
  cleanup, and range-limited block I/O.
- A signed embedded program store; init refuses to launch it if verification
  fails.
- Encrypted, authenticated paired storage slots with audit records and
  recovery selection.
- A supervisor with restart backoff, a shell, and signed update/application
  installation paths.

## Quick start

Install the nightly Rust toolchain components declared in
`rust-toolchain.toml`; QEMU is required to run locally. Docker is an
alternative for QEMU and is required by the scripted interactive driver.

```bash
./build.sh
./run-qemu.sh
```

The first build creates a disposable development signing key under
`keys/dev/` and provisions `store.img`. They are intentionally local-only.
Subsequent builds preserve the volume so audit history and updates survive.

At the shell, use `help`; useful commands include `hello`, `services`,
`stats`, `audit`, `slot`, `update`, and `exec fault-test`.

## Validation

```bash
# formatting, strict crypto linting, unit tests, release image, QEMU boot
./tools/check.sh

# optional Docker-backed keyboard/monitor session; uses a copied volume
./tools/interactive-check.sh
```

`tools/drive.sh` can send custom shell lines and capture serial output plus
a framebuffer screenshot:

```bash
./tools/drive.sh 7 hello services stats
```

## Release

Release signing material is deliberately external to the repository. Set a
non-development `REDOUBT_SIGNING_PREFIX` pointing to `.seed` and `.pub`
files, then run:

```bash
REDOUBT_SIGNING_PREFIX=/secure/path/redoubt ./tools/release.sh dist
```

The release script writes the BIOS image, persistent volume, checksums,
build provenance, and Cargo metadata to the chosen directory.
