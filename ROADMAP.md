# Redoubt OS Delivery Roadmap

This repository currently delivers an x86-64 BIOS/QEMU development platform.
It is a verified microkernel appliance, not yet installable laptop firmware
and not ESP32 firmware. Those are distinct products sharing protocol, package,
and security ideas—not one image compiled for every machine.

## Target split

| Product | Initial hardware | Execution/isolation model | Installable artifact |
|---|---|---|---|
| redoubt Laptop | x86-64 UEFI QEMU, then one explicitly supported laptop model | Existing Ring-3 capability microkernel | Signed EFI system image + A/B system and application volumes |
| redoubt Edge | ESP32-C6 development board | Single-address-space, capability-disciplined embedded runtime | Signed ESP32 firmware `.bin`, flashed over USB or OTA |

An ordinary ESP32 is not an interchangeable microkernel target: it lacks the
MMU needed for the x86-64 process/address-space isolation implemented here.
The Edge runtime therefore cannot claim the Laptop kernel's Ring-3 isolation.
It may be a secure controller or a managed co-processor, while the Laptop
edition retains the full microkernel security boundary. ESP32-C6 is the
baseline because it is RISC-V and has modern Espressif support; a different
board must be selected deliberately before driver work begins.

## Baseline that is complete now

- x86-64 BIOS/QEMU boot; capability-only IPC, process lifecycle, and
  range-limited ATA block access.
- Ed25519-verified program store, encrypted and authenticated dev volume,
  A/B updates, bad-package rejection, boot-time fallback, audit chain, and
  supervised user services.
- Signed persistent applications: `apppack` stages a signed ELF, storaged
  installs it transactionally into paired encrypted slots, and initfs verifies
  it again before giving it only its approved console capability. Installation,
  reboot persistence, tamper rejection, and removal run in QEMU CI.
- Repeatable QEMU checks for shell input, fault containment, service
  stop/start, update+reboot, package rejection, and rollback.

The development signing key under `keys/dev` is test material only. A
production key is generated and held outside this repository.

## Milestone L1 — installable laptop developer image

**Outcome:** a user can boot redoubt in UEFI QEMU, install a signed image onto a
dedicated test disk, and recover with the previous slot after an interrupted
or invalid update.

1. Replace BIOS-only image production with a UEFI image built and tested in
   OVMF QEMU. Preserve the existing verified initfs and A/B volume semantics.
2. Add a measured-boot policy: Secure Boot verifies the EFI loader; the loader
   verifies the kernel manifest; the kernel/user-space path continues to
   verify applications and configuration.
3. Define disk partitioning: EFI System Partition, read-only boot assets,
   A/B system slots, and a distinct A/B application-store volume.
4. Add a recovery application that can inspect slots, verify signatures, and
   select a prior bootable image without network access.

**Acceptance:** fresh UEFI install, signed update, power-cut simulation at
each write boundary, Secure-Boot rejection of an unsigned loader, and recovery
to the last known-good slot all run in CI.

## Milestone L2 — signed application installation (development-platform complete)

**Outcome:** an operator can install and remove a user application without
rebuilding the OS image or giving the application implicit authority. This is
delivered on the BIOS/QEMU development platform; the UEFI installer in L1
will carry the same app-store format forward.

Package format:

- application ELF(s), immutable manifest, version, issuer key ID, SHA-256
  digests, Ed25519 signature, and requested capability policy;
- package signatures verified by a dedicated `appd` service against an
  owner-controlled trust store;
- installation is transactional into an inactive application-store index;
- execution transfers only capabilities named by an administrator-approved
  policy. Applications never receive the system-volume or update-agent caps.

Commands should be `app install <package>`, `app list`, `app remove <id>`,
`app run <id>`, and `app rollback`. System updates remain separate from
application updates.

**Acceptance:** valid install and run, tampered package rejection, console-only
capability attenuation, uninstall/reboot persistence, and paired-slot update
recovery. The current CI covers install/run/reboot/rejection/removal; explicit
power-cut injection between app payload and header writes remains an L1
firmware-image recovery test.

## Milestone L3 — network and remote management

**Outcome:** a dedicated network service provides a minimal management API;
no other service gets raw NIC authority.

1. Add one virtio-net driver for QEMU before choosing physical NICs.
2. Run an IP stack such as `smoltcp` inside a network service behind a
   capability-limited packet interface.
3. Add a management service with TLS 1.3 mutual authentication, device-owner
   provisioning, certificate rotation, audit records, rate limiting, and a
   default-deny firewall.
4. Fuzz parsers and test client-certificate rejection, expired credentials,
   replay attempts, and management-service restart.

**Acceptance:** the management API is disabled without an owner key; a
provisioned client can inspect/update the device, and no application can send
packets without a delegated network capability.

## Milestone L4 — physical laptop hardware

**Outcome:** supported hardware is explicit, narrow, and testable.

1. PCIe enumeration and one NVMe controller family.
2. USB xHCI plus one HID keyboard/touchscreen path.
3. One Intel or Realtek Ethernet adapter, selected after the QEMU virtio-net
   implementation stabilizes the service boundary.
4. TPM 2.0 measured-boot log and key sealing; recovery rules for TPM reset,
   motherboard replacement, and owner-key rotation.

Do not claim generic-laptop support until each exact hardware profile passes
cold-boot, suspend/resume (if supported), update rollback, and device-removal
tests.

## Milestone E1 — ESP32-C6 Edge runtime

**Outcome:** a flashable secure controller image, not a false claim of MMU
process isolation.

1. Create a separate `redoubt-edge` workspace target using the Espressif Rust
   HAL, linker layout, serial console, watchdog, flash storage, and hardware
   RNG.
2. Reuse only portable crypto, signed-package, configuration, audit, and
   message-format crates after target-specific tests are added.
3. Verify firmware signatures in a boot chain compatible with the board's
   secure-boot and flash-encryption facilities; seal/update keys using the
   board's supported key storage.
4. Offer USB flashing (`esptool`) and signed OTA A/B firmware updates.
5. Connect it to redoubt Laptop through a mutually authenticated management
   protocol, treating the ESP32 as a separate trust domain.

**Acceptance:** reproducible `.bin`, flash/boot/recovery test on the chosen
board, signature rejection, watchdog recovery, interrupted OTA rollback, and
documented physical provisioning.

## Later research tracks

- ARM64 and RISC-V kernel ports begin only after the architecture-dependent
  kernel code is isolated behind a small HAL and the syscall/capability ABI is
  versioned.
- A type-1 hypervisor is a separate security architecture project. It requires
  CPU virtualization, IOMMU, interrupt virtualization, VM lifecycle, and a
  threat model; it must not be slipped into the microkernel incrementally.
- Academic comparisons require preregistered workloads, pinned hardware,
  reproducible scripts, and careful equivalence claims against Linux and
  seL4. They are not a substitute for the engineering release gates above.

## Immediate next implementation decision

Choose one track before adding code: **L1 (UEFI QEMU laptop installer)**,
**L2 (signed application installer on the existing QEMU platform)**, or
**E1 (ESP32-C6 runtime)**. Each has different toolchains, hardware assumptions,
and security boundaries. L2 is the fastest way to make the current appliance
install applications; L1 is the necessary path to a laptop-bootable OS; E1
creates the downloadable ESP32 product.
