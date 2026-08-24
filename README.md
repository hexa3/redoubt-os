# Redoubt OS

Redoubt OS is a small x86-64 Rust microkernel that boots to a capability-safe
interactive appliance system. Ring-3 user servers provide the console,
program store, configuration/persistence, supervision, and updates; the
kernel owns only scheduling, paging, interrupts, capabilities, synchronous
IPC, and a polled ATA driver exposed exclusively through capability-scoped
block I/O.

## Run it

```bash
./build.sh
./run-qemu.sh
```

The build produces `redoubt-bios.img` plus — on first build — `store.img`,
the 16 MiB persistent appliance volume (A/B slots, runtime config, audit
log). `run-qemu.sh` uses a locally installed QEMU when available and
otherwise uses the supplied Docker image; it attaches `store.img` as the
secondary IDE disk when present. Serial carries the boot log.

For a repeatable headless keyboard session plus a framebuffer capture:

```bash
./tools/drive.sh 12 'services' 'get hostname' 'uptime'
```

If another QEMU session has an image open, pass isolated copies with
`REDOUBT_IMAGE=...` / `REDOUBT_VOLUME=...`; `REDOUBT_MON_PORT=...` selects a
non-default monitor port. Reboot scenarios need `REDOUBT_REBOOT_OK=1`
(otherwise `-no-reboot` makes QEMU exit at reset) and benefit from
`REDOUBT_POST_WAIT=14` so the second boot is captured.

## The operator shell

| command | effect |
|---------|--------|
| `help`, `echo <text>` | basics |
| `exec <name>`, `hello` | run a program from the verified store |
| `exec fault-test` | dev diagnostic: `ud2`; must exit 262 with the shell intact |
| `services` | supervised services and their state |
| `start/stop/restart <name>` | drive the supervisor (`heart`) |
| `update` | verify + apply the staged update into the inactive slot |
| `apps`, `app list` | list installed applications and their versions |
| `app install` | verify and install the app package staged by `redoubt-tools apppack` |
| `app run <name>`, `app remove <name>` | execute or revoke an installed app |
| `slot` | active system slot and generation |
| `get <key>` | read configuration (signed defaults, runtime overrides) |
| `audit [n]` | recent records of the append-only audit log |
| `uptime`, `stats` | ticks; frame/page accounting |
| `reboot` | resets the machine (used after `update`) |

## Security model, as implemented here

* **Verified program store.** initfs embeds hello/fault-test/heart/shell/
  storaged/supd/updated together with a SHA-256 manifest signed with
  Ed25519. The signature is checked against a pinned public key before any
  launch path opens; every served program is digest-checked per request.
  Failure is fatal at boot — fail closed.
* **Signed system definitions, A/B slots.** The service roster and device
  identity live in slot A or B of the volume as an Ed25519-signed payload,
  encrypted at rest and bound to its header by HMAC. Updates stage a
  sealed slot image; the on-device agent verifies it WITHOUT holding the
  volume key and copies it into the *inactive* slot only; storaged
  re-validates independently before committing the superblock.
* **Rollback both ways.** A tampered package is rejected by signature and
  leaves the running slot untouched; a corrupted ACTIVE slot fails
  validation at boot and the previous signed slot mounts automatically.
* **Capabilities are the only authority transport.** Endpoints, block
  ranges, everything: kernel objects behind rights-masked slots.
  Attenuation is structural (intersection), spawn-time transfer is the
  only delegation channel, and block caps address their granted window
  relatively so a holder cannot even name LBAs outside it.
* **Fault containment + supervision.** Recoverable ring-3 exceptions kill
  only the faulting task (exit `0x100+vector`); supd restarts its services
  with exponential backoff, crash-loop detection, and audit events.
* **Audit log.** Append-only, SHA-256 hash-chained per record; editing
  history breaks the chain visibly at that record.

The `keys/dev` pair is generated locally for CI and development. Its private
seed and derived public key are ignored by git; production signing material is
always provisioned from outside the repository (see PRODUCT_DIRECTION.md).

## Installing an application (development platform)

Applications are signed ELF packages, not arbitrary disk images. Stage one
on a development volume, then install it through the shell:

```bash
cargo run --release -p redoubt-tools -- apppack \
  --image store.img \
  --elf target/x86_64-unknown-none/release/redoubt-hello \
  --name hello-app --version 1 --key keys/dev/redoubt
```

Then run `app install`, `apps`, and `app run hello-app` in redoubt. The device
checks the package signature and digest, writes the candidate into the
inactive member of a paired encrypted app slot, and publishes its header
only after the payload write succeeds. `initfs` independently re-checks the
digest and Ed25519 signature before it spawns the ELF with only a write-only
console capability. `app remove <name>` revokes both slot headers, so the
bytes cannot be launched after a reboot.

## Architecture

- BIOS/QEMU x86-64 boot, framebuffer text console, PS/2 keyboard input.
- Per-process address spaces, guarded globally-mapped kernel stacks.
- Preemptive round-robin scheduling at 100 Hz, recv/sleep deadlines woken
  from the timer tick, big-kernel-lock execution model.
- Synchronous IPC endpoints with explicit replies; single reply slot per
  endpoint; peer-death and endpoint-busy are explicit errors.
- Kernel-enforced `(object, rights)` capabilities: endpoints, memory
  grants, and LBA-windowed block disks, with range-narrowed derivation.
- ET_EXEC ELF loading from userspace, `wait`/zombie reaping, supervisor
  kill restricted to the spawner's own children.
- Self-contained `redoubt-crypto` crate (SHA-256/HMAC/SHA-512/ChaCha20/
  Ed25519) shared by host tooling and on-device servers, validated against
  RFC test vectors in CI.

See [DESIGN_DECISIONS.md](DESIGN_DECISIONS.md) for rationale,
[BUILD_LOG.md](BUILD_LOG.md) for the implementation record, and
[PRODUCT_DIRECTION.md](PRODUCT_DIRECTION.md) for the production contract
and exactly which gates remain between this development platform and
Release-1 firmware. [ROADMAP.md](ROADMAP.md) defines the separately
deliverable laptop and ESP32 product tracks.

## License

Redoubt OS is available under the [Apache License 2.0](LICENSE).
