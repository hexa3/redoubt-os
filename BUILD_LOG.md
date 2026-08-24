# Redoubt OS Build Log

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

## Checkpoint 1 — boot (achieved ~21:20)

- Fixed: bootloader crate's UEFI build fails on current nightly (`wcslen` link error, known
  upstream incompatibility). Switched to `default-features = false, features = ["bios"]` —
  we only ship BIOS images; QEMU's SeaBIOS is the target firmware.
- Fixed: bindeps env vars use the *bin name verbatim* (`CARGO_BIN_FILE_REDOUBT_INITFS_redoubt-initfs`),
  not the underscored form.
- `./build.sh` now produces a bootable `redoubt-bios.img`; `./run-qemu.sh` boots it headless
  under Docker-hosted qemu-system-x86_64 with serial on stdio.
- Verified by actually running it: kernel prints boot banner, full memory map (10 regions),
  and sizes of the two embedded user-server ELFs.
- Commit: `9b27c45`.

## Checkpoint 2 — kernel foundations (achieved ~22:05)

- Added modules: `serial` (kprint/kprintln macros), `frame` (bump allocator over
  bootloader usable regions), `paging` (physmap-based table walking, map/unmap/translate,
  `new_address_space` sharing the kernel's higher half), `heap` (8 MiB at 0x7000_0000_0000
  via linked_list_allocator), `gdt` (kernel+user segments, TSS, double-fault IST),
  `interrupts` (all 19 exceptions with decode, PIC remap to 32..48, PIT @100Hz).
- Bugs found by booting, not reading:
  1. `ltr` before `lgdt` → triple fault. Reordered: GDTR → selectors → TR.
  2. Zeroed fresh page-table frames through their *physical* address (identity-map
     assumption) → #PF during heap init. Fixed via physmap translation.
  3. Enabled IF before remapping PICs → IRQ0 hit vector 8 (double-fault gate) → chaos.
     PIC initialize() now precedes any interrupt enable.
- Verified: heap smoke test (Vec sum) passes; timer ticks; breakpoint handler works;
  all init lines on serial.
- Design decision recorded: kernel runs with interrupts disabled ("big kernel lock"
  style); preemption happens only at return-to-user and syscall boundaries. Simplifies
  trap frames (uniform: always from ring 3) and removes reentrancy. Documented in
  DESIGN_DECISIONS.md.
- Commit: CP2.

## Checkpoint 3 — userspace bring-up (achieved 2026-08-23 ~12:30)

- New modules: `task` (address spaces, ELF loader, kernel stacks), `trap`
  (uniform ring-3 TrapFrame + asm stubs for timer/int 0x80), `sched`
  (round-robin, quantum 200ms, switch = CR3 + TSS.RSP0 + RSP), `caps`
  (capability tables), `syscall` (int 0x80 dispatch: yield/exit/debug_write/
  ipc call/recv/reply/cap_derive). `userlib` crate: _start, syscall wrappers,
  panic handler.
- Bugs found by booting:
  1. Kernel stack mapped only in its owner's address space -> after
     `mov cr3`, kernel still executes on the OUTGOING task's stack ->
     #PF at CPL=0 mid-switch (#PF -> #PF -> #DF -> triple fault, captured in
     qemu -d int log). Fix: global kstack registry; every kstack mapped into
     every address space (`paging::register_kstack` + replay on spawn).
  2. Double-fault IST entry held a PHYSICAL address as RSP -> every double
     fault immediately triple-faulted. Fixed via physmap alias.
  3. Yield with no peer enqueued the caller anyway -> unbounded duplicate
     ready-queue entries. Now a no-op.
  4. Reply-waiters parked as BlockedRecv could be stolen by a later recv.
     Distinct BlockedCall state introduced.
  5. userlib dropped the 5th IPC message word (r9 unused in the asm
     wrapper).
- Verified by running: two ring-3 tasks; console busy-loops and is timer-
  preempted (>300 context switches over a 75s soak); initfs yields
 voluntarily; zero faults.

## Checkpoint 4 — IPC + capability enforcement (achieved 2026-08-23 ~13:05)

- console became a real server: recv -> print packed-text payload -> reply
  ack. initfs became a client: five synchronous round-trips, verified acks.
- Capability demo on boot: derive(r+w) from a w+g source yields w-only;
  delegation from a non-grant cap is refused (E_CAP_DENIED); fs endpoint
  attenuates to r-only cleanly.
- ABI fix: derive now returns status in rax and the new slot in rdi — an
  errno of 2 had been indistinguishable from slot 2 before.
- Exit path fixed: exit_task resumed the next task but then hit an
  unreachable!() — first exercise was the day initfs exited while console
  still ran. Idle park now enables interrupts, dumps the task table, and
  hlt-loops so a quiet system explains itself.

## Checkpoint 5 — process creation from userspace (achieved 2026-08-23 ~13:40)

- SYS_TASK_SPAWN(8): ELF bytes + capability grant list copied from the
  CALLER's address space; each (slot, mask) pair passes grant validation
  and becomes a child slot. This is the only privilege-transfer channel.
- New `redoubt-hello` server; its ELF is embedded in initfs ("program
  store"). The kernel never loads hello itself — spawn-from-userspace is
  load-bearing, not theatrical. Boot chain: kernel -> initfs+console ->
  initfs spawns hello WITH a transferred console cap -> hello prints via
  IPC -> exits(7) -> initfs exits(0) -> idle task table dump.
- ELF loader hardened from assert()s to Result<>: ET_EXEC only, bounds-
  checked phdrs, no segment/stack overlap, entry must be mapped. A hostile
  ELF can waste frames but cannot panic the kernel.
- Build fixes discovered en route: x86_64-unknown-none defaults to PIE
  (ET_DYN) unless `-no-pie` + linker script are passed — hello needed its
  own build.rs; `[0; N]` heap initializer landed in .data (1 MiB file!)
  until switched to MaybeUninit/.bss; user binaries now stripped (-s).
- Zero compiler warnings across workspace. 90s soak clean.

## Checkpoint 6 — usable interactive system (completed 2026-08-23)

- Added framebuffer text output, a PS/2 IRQ1 input queue, a blocking
  `SYS_INPUT_READ`, line editing in the console server, and a shell launched
  by initfs. The complete path is now keyboard -> IRQ1 -> console -> IPC ->
  shell -> initfs exec service -> spawned program.
- Added `SYS_WAIT` plus zombie reaping. Address spaces, user stacks, and
  globally mapped kernel stacks are returned to the frame allocator only
  after execution has moved to a different stack.
- Fixed two completion-critical scheduler edges found during fresh QEMU
  boots: ring-0 idle timer frames no longer consume 16 bytes per tick, and a
  task woken by an IRQ now resumes from idle on the next timer boundary.
- Verified from a fresh BIOS image: boot, IPC/capability demonstration,
  userspace hello spawn and wait, shell launch, and a stable idle period.

## Production-foundation pass (in progress, 2026-08-23)

- Defined the appliance OS product contract in `PRODUCT_DIRECTION.md`, with
  a narrow Release-1 hardware profile and explicit security/recovery gates.
- Hardened every syscall copy boundary against forged kernel-space pointers;
  zeroed reused user stacks before mapping them into a new task.
- Fixed process-load rollback and a task-reaper double-free of user-stack
  frames. The address-space walker is now the sole owner of user leaves.
- Added GitHub Actions CI: format check, freestanding release build, BIOS
  image generation, and a QEMU smoke boot through the shell prompt.
- Added ring-3 fault containment for recoverable x86 exceptions. A temporary
  `ud2` integration image verified #UD -> child exit `0x106` -> parent wait
  -> continued shell boot; the normal hello image was restored afterward.
- Hardened the ELF load plan before it performs any allocation: PT_LOAD page
  ranges must not overlap, their alignment is checked, and W+X mappings are
  rejected. This prevents a malformed later segment from replacing and
  leaking an earlier frame. Page-table exhaustion during task creation is
  now a failed spawn rather than a kernel `expect` panic.
- Added release-candidate provenance which marks any working-tree build as
  `-dirty`, including untracked inputs, so its image checksum cannot be
  mistaken for a clean source revision.
- Made the physical-frame free list fail closed on range overflow,
  out-of-usable-memory frees, accounting underflow, or overlap with an
  existing free range. Those cases represent kernel ownership corruption and
  must never silently reissue one page to two processes.
- Added a `fault-test` program-store entry to the development image. Its
  `ud2` instruction gives QEMU integration tests a stable fault-containment
  exercise (`exec fault-test` -> exit 262 -> shell remains usable), without
  modifying the normal hello binary. GitHub Actions now drives that exact
  keyboard-to-shell recovery path after its normal boot smoke test.
- Bound every active IPC transaction to the receiver that accepted it. A
  receiver that exits now wakes its stranded caller with `E_PEER_DIED` and
  removes its own queued/active calls from endpoint state, preventing a
  future reply from targeting a reaped task frame.
- Rejected a second `recv` while an endpoint still has an unanswered call;
  this protects the single reply slot from being overwritten and makes the
  service protocol failure explicit (`E_ENDPOINT_BUSY`).

## Checkpoint 7 — verified boot, A/B updates, supervision (2026-08-24)

Goal: close the PRODUCT_DIRECTION gaps that the development platform can
close — signed/verified code and system definitions, A/B updates with
rollback, encrypted persistent config, append-only audit, restartable
services, resource accounting, and storage behind capability-limited
access. Everything below was verified by driving real QEMU sessions.

Delivered:

- `redoubt-crypto`: SHA-256/HMAC-SHA-256/SHA-512/ChaCha20/Ed25519 +
  volume-layout module; 17 RFC-vector unit tests, run by CI.
- `redoubt-tools` (host): keygen / mkvol / updpack / inspect. `build.sh`
  provisions a fresh `store.img` on first build.
- Kernel: polled ATA LBA48 driver (IRQs masked), `Cap::Block` with
  range-narrowed derivation and window-relative addressing, block
  read/write syscalls, ticks/stats/set-name/sleep/kill/reboot,
  WAIT-nohang, recv deadlines woken from the timer tick, per-task page
  accounting.
- initfs: Ed25519-verified program store (fail closed at boot),
  chunked binary-safe fetch protocol for supervisors, corrected
  capability wiring for five boot endpoints + block cap.
- storaged: superblock/slot validation with automatic rollback, sealed
  slot mounting (HMAC → decrypt → digest → signature), runtime config
  overrides, hash-chained audit log with replay, recovery mode from
  compiled-in factory defaults, update orchestration.
- supd + heart: roster-driven service spawn via fetch, exponential-
  backoff restarts, crash-loop marking, operator stop/start/restart,
  status reporting; heart exercises liveness end to end.
- updated: keyless update agent - verifies the staged image signature
  against the pinned key and copies it into the inactive slot only.
- shell: services/start/stop/restart/update/slot/get/audit/uptime/
  stats/reboot.
- CI extended to eight scenarios including update+reboot slot switch,
  tamper rejection, and boot-time rollback.

Verified live in QEMU:

- program store signature VERIFIED at every boot; volume mounts as
  "slot A gen 1" with hostname served from the signed payload;
- valid gen2 package: "ok applied 101 bytes; reboot" -> reboot ->
  "mounted slot B gen 2";
- corrupted package: "err: BAD SIGNATURE", running slot untouched;
- host-side byte flip in the ACTIVE slot payload -> boot prints
  "[store] active invalid; rollback" and mounts the
  previous slot automatically;
- stop/start/restart of heart through the shell, fault-test still
  exits 262 with the shell intact, audit chain accumulates across
  reboots (append-only persistence proof).

Bugs found by booting (each fixed and covered above):

1. Endpoint roster drift between kernel and servers gave storaged its
   own block cap where it expected a mutation endpoint (E_CAP_DENIED
   exit). Rebuilt the delegation matrix explicitly (see
   DESIGN_DECISIONS).
2. Plain blocking recv on two endpoints deadlocks structurally when one
   side goes quiet; replaced with bounded-wait event loops.
3. User stack overflow: 512 KiB payload buffers on 64 KiB user stacks -
   moved to a shared .bss workspace (single-threaded server).
4. ATA drive-select needed the LBA bit (0xE0); IDENTIFY tolerates CHS
   select but LBA48 commands do not.
5. hwcd-3 group-law formulas failed an independent affine check for
   doubling; switched to hwcd-4 before any device-side use.
6. Canonical field encoding required conditional p-subtraction after
   carry folding (-1 encoded as p+1).
7. msg::pack silently truncates at 40 bytes - long console lines were
   chopped mid-word; added print_split chunking and a raw codec for ELF
   transfer (NUL-trimming unpack corrupts binaries mid-stream).
8. Pre-derived W-only caps lose G and become untransferable; both supd
   and storaged hit this. Spawn grants attenuate directly instead.
9. SYS_KILL originally reused the self-exit path, clobbering scheduler
   current-state for a non-running victim; termination lifecycle split
   from CPU handoff.
10. Block syscalls validated absolute LBAs while the agent addresses its
    granted window relatively; windowed semantics adopted kernel-side.

## Checkpoint 8 — signed application installation (2026-08-24)

- Added an encrypted paired-slot application store in the unused persistent
  volume region. Four independently named applications each retain a previous
  verified version while a candidate is installed into its peer slot.
- `redoubt-tools apppack` signs the canonical application name, version, length,
  and SHA-256 digest with Ed25519 before staging the ELF. storaged validates
  package shape, digest, signature, freshness, and app-slot capacity before
  publishing the final authenticated header.
- initfs fetches installed ELF bytes through the storage query capability and
  independently re-checks the full digest and signature before `SYS_TASK_SPAWN`.
  Installed programs receive only a write-only console capability.
- Shell surface: `apps`, `app install`, `app run <name>`, and
  `app remove <name>`. Removal clears both application-slot headers, so a
  removed program remains non-executable after reboot.
- Fixed a latent large-payload ChaCha20 bug: streamed validation had restarted
  the cipher counter at zero for each disk transfer. Slot/app validators now
  advance by `done / 64`, with a regression test comparing chunked and
  one-shot decryption. Added true non-blocking IPC receive deadlines so
  chunked app transfer does not wait on a quiet configuration endpoint.
- QEMU verification: signed hello ELF install/run (exit 7), cold-boot
  persistence, corrupt v2 package rejection with v1 intact, and removal.
