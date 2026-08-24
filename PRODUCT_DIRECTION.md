# Redoubt OS Appliance Product Contract

## Product

redoubt will be a secure, single-purpose x86-64 appliance operating system for
an edge controller, kiosk, or hardened terminal. It is not pursuing POSIX or
desktop compatibility: every service runs with only the capabilities it
needs, and the supported hardware profile is intentionally narrow.

## Release-1 target

- x86-64 UEFI hardware with a TPM 2.0, one wired Ethernet controller, one
  NVMe device, framebuffer display, and USB HID keyboard.
- A signed, versioned system image; verified boot; A/B updates with rollback.
- An encrypted persistent configuration volume and an append-only audit log.
- A small set of separately restartable services: console/UI, configuration,
  network management, application supervisor, and update agent.
- Remote administration over mutually authenticated TLS, disabled unless a
  device-owner key is provisioned.

## Security invariants

1. A userspace pointer never authorizes access to a kernel mapping. Every
   copy validates the bounded user address range and each mapping.
2. Capabilities are the only authority transport. Service restarts must not
   manufacture broader privileges.
3. All booted code and updates are verified before execution. Failed updates
   must leave the prior signed slot bootable.
4. A fault in a user service must be contained, reported, and restartable;
   it must not halt the kernel or corrupt another service.
5. The release build is reproducible, continuously built, and exercised in
   QEMU from boot through recovery scenarios.

## Delivery order

1. Kernel isolation, resource accounting, fault containment, and deterministic
   observability.
2. UEFI secure boot, image manifest/signature verification, A/B storage, and
   recovery console.
3. NVMe, USB HID, and Ethernet drivers behind capability-limited services.
4. Encrypted configuration, network control plane, update agent, and service
   supervisor.
5. Hardware-in-the-loop testing, performance budgets, release signing, and
   operations documentation.

The current BIOS/QEMU image remains the development platform while this work
is built. It is not represented as production firmware until Release-1's
hardware, signing, recovery, and test gates are met.

## Status (2026-08-24): development-platform delivery

What the development image now delivers against the contract above:

| Contract item | Dev-platform status |
|---|---|
| Signed, versioned system image | **Mechanism complete.** Program store + slot payloads carry Ed25519 signatures over SHA-256 digests; versions are monotonic generations. CI and local builds generate an ignored `keys/dev` pair; production keys provision externally (`REDOUBT_SIGNING_PREFIX`). |
| Verified boot | **In-system verification complete and fail-closed** at every code entry point (store manifest at initfs boot, per-program digests on launch, slot payloads at mount). Firmware-rooted verification (UEFI secure boot measuring the bootloader) remains a Release-1 hardware gate. |
| A/B updates with rollback | **Complete on the dev volume.** Sealed-image packages, keyless on-device agent writing the inactive slot only, independent re-validation before superblock commit, generation-freshness enforcement, signature rejection proven in CI, boot-time rollback from a corrupted active slot proven in CI. |
| Encrypted persistent configuration | **Complete for the dev volume**: ChaCha20-at-rest payloads, HMAC-bound headers, MAC'd runtime config overrides with signed-defaults fallback. Key sealing behind a TPM is a Release-1 gate; dev-mode stores the volume key in the superblock by explicit decision. |
| Append-only audit log | **Complete for the dev volume**: hash-chained records that survive reboots; chain breaks are reported, never silently repaired. |
| Signed application installation | **Complete for the dev volume.** `redoubt-tools apppack` stages an Ed25519-signed ELF; storaged verifies, encrypts, and publishes it into an inactive paired app slot; initfs re-verifies before spawning it with only a console capability. CI proves install/run/reboot persistence/tamper rejection/removal. |
| Separately restartable services | **Console/UI, configuration, application supervisor, update agent delivered.** supd restarts services under exponential backoff with crash-loop detection; fault containment plus supervision satisfies invariant 4 end to end. |
| Network management service | **Not started** - no NIC driver exists on the dev platform yet. |
| Remote administration over mTLS | **Not started** - depends on the network gate; disabled-by-absence today, which matches "disabled unless provisioned" but not the full requirement. |

Security invariants: 1, 2, and 4 are enforced structurally (user-pointer
fencing, capability-only authority transport with spawn-time transfer,
containment + supervision). Invariant 3 holds for everything after the
bootloader; invariant 5 holds via CI exercising boot -> shell, fault
recovery, supervision cycles, update+reboot, tamper rejection, and
rollback on every push.

Delivery-order position: step 1 complete; step 2 complete at the
in-system layer (UEFI/TPM root of trust outstanding); step 3 one-of-four
(ATA behind caps; NVMe/USB-HID/Ethernet outstanding); steps 4-5 partially
delivered through storaged/supd/updated and QEMU-in-the-loop CI.
