# Redoubt OS Design Decisions

`IDEAL_OS_SPEC.md` was never present on this machine, so requirements were
reconstructed from the mission directive. Every spec-level decision made in
its absence is recorded here with its rationale. This file is the source of
truth for "why is it built this way".

## Scope and shape

- **Target**: x86-64, BIOS boot only (QEMU/SeaBIOS). Rationale: host-native
  architecture, best-documented Rust os-dev ecosystem; UEFI support in the
  `bootloader` crate is currently broken on nightly anyway.
- **Language**: Rust, `#![no_std]`, freestanding `x86_64-unknown-none`.
  Nightly toolchain pinned in `rust-toolchain.toml` (needs
  `abi_x86_interrupt` and bindeps).
- **Boot path**: `bootloader` crate v0.11, BIOS image via bindeps.
  Hand-rolling a boot sector + long-mode trampoline buys nothing
  pedagogically that the rest of the kernel doesn't already teach.
- **Architecture**: capability-based microkernel. Servers are ordinary user
  tasks that hold capabilities to IPC endpoints; the kernel validates every
  syscall against per-task capability tables.

## Kernel architecture

### Execution model: interrupts off in the kernel

The kernel runs with IF=0 while servicing user traps. The idle loop alone
enables interrupts before `hlt`, so keyboard IRQs can wake a parked reader;
the following timer boundary transfers the CPU back to that ready task. This
is the classic "big kernel lock" single-core model:

- No reentrancy: kernel data structures need no interrupt-safety.
- User context switches always use complete ring-3 TrapFrames. Ring-0 idle
  timer frames are handled in place and return through their native
  three-word interrupt frame, so they cannot grow the idle stack.
- Cost: no SMP, and long kernel operations delay the timer. Acceptable at
  this scale; revisit only if SMP arrives.

### Address spaces

- PML4 slot 0 (< 512 GiB) is user space. Everything else is cloned from the
  kernel's table at spawn, sharing page-table subtrees by reference.
- The bootloader maps the kernel at `phys + 2^40` (PML4 index 2), *not* in
  canonical higher half — hence slots 1..511 are copied, not just 256..512.
- Intermediate page-table entries get `USER_ACCESSIBLE` and *no* NX: U/S and
  NX both propagate down through levels, so intermediates must be permissive
  whatever the leaf says.
- Fresh address spaces replay all registered kernel-stack mappings
  explicitly (see next section) before being registered themselves.

### Kernel stacks: global by construction

Each task owns a 32 KiB kernel stack plus one guard page, allocated from a
fixed higher-half region (`0xffff_c000_0000_0000`). The bug this design had
to fix: after `mov cr3, new_task`, the kernel still executes a few
instructions on the *outgoing* task's stack. If those VAs aren't mapped in
the incoming address space, you fault at CPL=0 mid-switch — observed live as
#PF -> nested #PF -> #DF -> triple fault.

Rule adopted: **every task's kernel stack is mapped into every address
space, always.** `paging::register_kstack` maps into all live address spaces
and records the mapping; `new_address_space` replays all recorded stacks.
Guard pages stay unmapped. The double-fault IST stack lives in the physmap
region (shared via clone), and its TSS entry holds the *virtual* address —
an earlier version stored the physical address there, which turned every
double fault into a triple fault.

### Scheduling

Round-robin over a ready queue, quantum = 20 PIT ticks (200 ms @ 100 Hz).
Blocked tasks keep their full TrapFrame at the top of their kernel stack;
switching = swap CR3 + TSS.RSP0 + RSP. A yield with no other runnable task
is a no-op that must NOT enqueue the caller (an earlier version grew a
duplicate ready-queue entry on every such yield).

Idle park enables interrupts and `hlt`s. It reports the task table once at
boot, then the next timer resumes any task made ready by an IRQ.

### IPC: synchronous rendezvous, explicit reply

Endpoint semantics:

| State       | Meaning                                   |
|-------------|-------------------------------------------|
| BlockedSend | call queued, waiting for a receiver       |
| BlockedCall | delivered, waiting for the server's reply |
| BlockedRecv | `recv` waiting for a caller               |

Message payload is five u64 words; reply is five words back. A 40-byte
packed-text codec (`userlib::msg`) rides on top. Servers reply only to
`active_caller` — set when a message is delivered, consumed by reply —
which prevents cross-talk between callers.

Bug fixed here: reply-waiters were originally parked as `BlockedRecv`,
which let a later `recv` scan steal them as message receivers. They now use
a distinct `BlockedCall` state.

### Capabilities

A cap is `(kernel object, rights mask)` stored kernel-side; userspace sees
only slot indices. Rights: R (read/recv), W (write/call/send), G (grant).

- **Derive** requires G on the source; result rights = held AND requested.
  Attenuation is structural — escalation is not detected, it is impossible.
- **Spawn-time transfer** is the only way privileges move between
  processes: the spawner passes (slot, mask) pairs; each becomes a child
  slot after the same grant validation. Derived copies lose G if the
  derivation dropped it, so delegation chains terminate — demonstrated on
  boot.
- ABI rule learned the hard way: status and payload must travel in
  different registers. An earlier derive returned "slot index or errno" in
  rax, and an errno of 2 was indistinguishable from slot 2.

### User-memory boundary

The kernel shares its mappings into each address space so it can continue
executing while switching CR3. That makes raw page-table translation an
unsafe authorization primitive: a malicious userspace pointer could name a
kernel mapping even though ring 3 cannot dereference it directly. Every
syscall copy now first checks that the complete range lies below
`USER_STACK_TOP`, then translates each byte/page. The input path applies the
same fence before storing keyboard data in a parked reader's buffer.

User stacks are explicitly zeroed before mapping. Frames returned by a prior
task (or supplied by firmware) must never disclose their contents to the
next process.

The frame allocator treats its free list as an ownership ledger. A range
outside the bootloader-reported usable memory, an accounting underflow, or an
overlapping free is a fatal kernel invariant violation, rather than a chance
to return one physical page to two mutually isolated tasks.

### Fault containment

Recoverable x86 exceptions taken from ring 3 use dedicated trap stubs. The
stubs normalize error-code and non-error-code frames, then terminate only the
faulting task through the ordinary lifecycle path; a waiting parent receives
an exit status of `0x100 + vector`. A kernel-origin exception reports its
vector and instruction pointer, then halts—resuming a corrupt kernel would
violate isolation. Double faults and machine checks remain fatal by nature.

### ELF loader

Minimal but paranoid: ET_EXEC only (no relocation processing),
magic/class/endianness/machine validated, program headers bounds-checked,
load alignment checked, segments may not overlap either each other or the
user stack region, and writable-executable loads are rejected. The entry
point must land in an executable loaded segment. Every failure returns
`Err`; malformed input and page-table frame exhaustion fail a spawn without
panicking the kernel. User programs link at a fixed 0x400000 via
`userlib/x86_64-user.ld` with `-no-pie`.

Note: `-no-pie` is load-bearing. The `x86_64-unknown-none` target produces
PIE binaries unless told otherwise, and PIE ELFs fail loader validation by
design.

### Userland runtime

`userlib` provides `_start`, int 0x80 wrappers preserving all GP registers,
a bump allocator over 1 MiB of .bss (MaybeUninit keeps it out of the file
image — an explicit `[0; N]` initializer silently put it in .data and blew
every size budget), panic->exit(101), and the msg codec.

### Lifecycle and interactive input

`wait` gives parents a child ID and exit code. A task that exits becomes a
zombie only while its parent can still observe it; otherwise its address
space, user stack, and globally mapped kernel stack are queued for teardown.
Teardown runs only from a different live stack, which prevents freeing the
stack currently executing the exit syscall. Orphaning first detaches all
children and queues already-dead children after releasing the task-table
lock, avoiding recursive-lock deadlock. Address-space teardown owns all
user-mapped leaves (including the user stack); the reaper must not free
those frames a second time.

An in-flight IPC call is owned by the receiver that accepted it. If that
receiver exits before replying, the kernel clears the endpoint transaction
and wakes its caller with `E_PEER_DIED`, rather than leaving a process
blocked indefinitely on a dead service. Calls owned by the exiting task are
also removed from pending/active endpoint state before its TrapFrame can be
reaped. Endpoints intentionally have one reply slot: a second `recv` before
the first `reply` is rejected with `E_ENDPOINT_BUSY` instead of overwriting
the first caller's transaction.

The PS/2 IRQ1 path decodes a compact US scancode-set-1 keyboard layout and
feeds a bounded byte queue. `SYS_INPUT_READ` parks the console server when
empty and writes directly to its user buffer when a key arrives. The console
server supplies echo, backspace editing, and full-line replies; the shell
uses that endpoint for `help`, `echo`, `hello`, and `exec <name>`.

## Build system

- `build.sh` -> `cargo run -p redoubt-build` -> bindeps builds the kernel
  with initfs/console embedded as artifacts; root build.rs makes the BIOS
  image.
- initfs embeds `hello.elf` and `shell.elf` (artifact dependencies) as its
  program store; the kernel never sees either. A booted initfs launches the
  shell with attenuated console and initfs capabilities.
- User binaries are stripped (`-s`) at link: debug sections don't reach the
  disk image, and the spawn size bound counts whole files.
- QEMU runs inside Docker (`docker/Dockerfile.qemu`) when no local install
  exists; `run-qemu.sh` prefers local qemu, falls back to Docker, KVM when
  available.

## Known limitations (accepted)

- No FP/SSE state saving: user tasks must not use floating point
  (`target-feature=-sse` makes violations loud instead of corrupting).
- Endpoints are single-receiver-per-message and FIFO; no async
  notifications yet.
- Single core, no SMP; TSS/GDT structures assume it.

## Production-foundation pass (development platform)

These decisions implement the PRODUCT_DIRECTION contract on the BIOS/QEMU
development image. Each section states what is structurally enforced, not
merely intended.

### Self-contained crypto (`redoubt-crypto`)

SHA-256, HMAC-SHA-256, SHA-512, ChaCha20, and Ed25519 live in one
allocation-free `no_std` crate shared by host tooling and on-device
servers. Decisions:

- **Domain constants are derived at runtime** (d = -121665/121666,
  sqrt(-1) = 2^((p-1)/4), the base point by y=4/5 with even-root
  recovery) rather than transcribed. A transcription typo is invisible in
  review and fatal in deployment; derivation removes the class. The RFC
  8032/8439/4231/FIPS vectors in `cargo test -p redoubt-crypto` remain the
  authority.
- **Group law**: extended twisted-Edwards coordinates with the hwcd-4
  unified formulas (C = 2·T1·T2·d, D = 2·Z1·Z2). The hwcd-3 variant was
  tried first and failed an independent affine cross-check for doubling;
  the reference implementation caught it before QEMU could.
- **Canonical encoding needs more than carry folding**: values in
  [p, 2^255) fit the limbs without overflowing, so `to_bytes` performs a
  fixed-point fold AND one conditional p-subtraction. (Found when
  sqrt(-1)^2 · (-1) encoded as p+1.)
- **Not constant-time**, stated plainly: verification operates on public
  material; development signing happens host-side. Release-1 signing keys
  must not be used with this implementation on hostile-input paths.
- Scalar reduction mod L is binary long division over little-endian
  bytes - slow, trivially auditable.

### Volume layout and trust boundaries

16 MiB default volume; geometry in `crypto/src/layout.rs`, the single
source of truth used by both sides:

```
LBA 0        superblock   active slot, generations, dev volume key, HMAC
LBA 1        runtime cfg  MAC'd mutable KV overrides, generation-counted
LBA 2 / 1034 slot headers state, generation, payload digest+sig, HMAC
LBA 4 / 1036 payloads     sealed system definitions (signed, encrypted)
LBA 3072..   audit log    append-only, per-record SHA-256 hash chain
LBA 20480..  staging      sealed update packages awaiting application
```

Three distinct trust classes, deliberately separated:

1. **Signed system definitions** (slot payloads): service roster +
   identity. Ed25519 signature over plaintext, pinned key; ChaCha20 +
   HMAC at rest. These define WHAT RUNS.
2. **Runtime config overrides** (LBA 1): mutable operator state. HMAC'd
   against tampering but deliberately NOT signed - they are data, not
   policy, and updates never overwrite them.
3. **Audit records**: hash-chained only. Tamper-EVIDENT by design; a
   keyed chain would imply secrecy the log does not need.

The superblock's single-sector commit is atomic-enough because it fails
closed: a torn sector fails its HMAC at mount and the validator falls
back to whichever slot still verifies.

### Verified program store

initfs embeds its programs plus a manifest (`name len sha256`) signed at
BUILD time by the same Ed25519 identity that signs update packages. At
boot initfs verifies the manifest against the pinned key BEFORE any
launch path exists and refuses to start if it fails; exec/fetch re-check
the digest of the exact static bytes served. The kernel never loads user
code, so the verification point sits exactly where distribution ends and
execution begins. `keys/dev` is committed so CI exercises real
verification deterministically; production provisions keys via
`REDOUBT_SIGNING_PREFIX` from outside the repository.

### Update flow: the agent holds no keys

A staged package is a SEALED SLOT IMAGE - the exact header/gap/payload
sectors of a slot, already encrypted and MAC'd under the volume key -
with an Ed25519 signature over those image bytes in the outer staging
header. Consequences:

- The update agent verifies authenticity WITHOUT the volume key and
  without ever seeing plaintext; it copies verified bytes into the
  inactive slot region and exits by code. Its two capabilities are reads
  over staging and writes over the inactive slot window; the running
  slot and superblock are unreachable BY CONSTRUCTION.
- storaged independently re-validates the written slot (HMAC, digest,
  payload signature) before committing, and enforces generation freshness
  so stale packages cannot roll the system back.
- Bad signatures abort before any write; corrupted ACTIVE slots fail at
  boot and roll back to the previous signed slot automatically.

An earlier design encrypted packages to the device key and had the agent
decrypt; that forced either key exposure to the agent or a deadlock
(single-threaded servers cannot serve each other mid-operation). Sealing
full images removed both problems and shrank the TCB.

### Capability wiring matrix

Boot endpoints: console(0), initfs(1), cfg(2), sup(3), info(4). initfs
holds delegable handles to all of them plus the whole-disk block cap.
Grants (mask-intersected at spawn):

| child | caps |
|-------|------|
| storaged | console w; info rw; cfg rw; block rwg |
| supd | console wg; fs w; info wg; cfg w; sup rw |
| shell | console w; fs w; info w; sup w |
| services | console w; info w |

Two rules learned by failure:

- **Clients never hold R on service endpoints.** R authorizes recv(), so
  a "read-only" client cap would let it steal server callers. Clients get
  W-only (call/reply); R is exclusively for the serving side.
- **Never pre-derive before transfer.** Deriving a W-only copy strips G;
  transferring THAT then fails E_CAP_DENIED. Attenuation belongs in the
  spawn grant mask, applied directly against the grantable source. Both
  supd and storaged hit this within an hour of each other.

Block capabilities narrow ranges via CAP_DERIVE's range arguments
(intersection, structural), and block syscalls address LBAs RELATIVE to
the capability's window - a holder cannot name absolute LBAs outside its
grant because translation happens kernel-side from private bounds.

### Server event loops need bounded waits

storaged serves two endpoints alternately. A plain blocking recv deadlocks
structurally: parking on the quiet endpoint strands callers queued on the
busy one (observed live as a supd-storaged hang during roster load).
Rule adopted: every multi-endpoint server uses `recv_until(now + slice)`
with ~1s slices; timeouts rotate instead of erroring. Single-endpoint
servers keep indefinite recvs.

Similarly, supervision requires polling children while listening:
SYS_WAIT gained WNOHANG and SYS_IPC_RECV gained absolute deadlines, both
woken by the timer tick scanning expired waiters. No threads anywhere.

### Console transport discipline

IPC messages carry 40 packed bytes and `msg::pack` truncates silently -
long console lines were being chopped mid-word ("VERIFICAT"). All user
output goes through `userlib::print_split` (37-byte SOH fragments), and
program-image transfer uses the `raw` codec (no NUL trimming) because
ELF content is arbitrary binary. Lesson generalized: any protocol carrying
non-text or >40-byte units needs an explicit codec, not string packing.

### Kernel lifecycle additions

- `terminate_lifecycle(tid)` split out of `exit_task`: zombie marking,
  orphaning, IPC unwinding, exit delivery. Safe for any non-running task;
  SYS_KILL runs it inline on the killer's stack after enforcing that the
  victim is the caller's own child. Calling the old self-exit path for a
  victim corrupted scheduler current-state and hung the system (observed).
- Per-task page accounting (ELF leaves + stack) surfaces in SYS_STATS;
  frames used/total and task count ride along. Observability remains
  deterministic: ticks, monotonic audit sequence numbers.
- ATA: polled PIO LBA48, IRQs masked at the PIC, bounded spins, drives
  enumerated primary-master then secondary-master (disk 0 = boot image,
  disk 1 = volume). Drive-select must set the LBA bit (0xE0), not CHS
  (0xA0) - IDENTIFY tolerates the wrong value and LBA48 commands do not.

### Known limitations (accepted, dev platform)

- Crypto is not constant-time; entropy for on-device volume formatting
  comes from tick/TSC jitter (host `mkvol` provisioning uses OS entropy
  and is the normal path).
- The volume key lives in the superblock header (dev mode). Release-1
  seals it behind a TPM; the crypto and layout do not change.
- storaged is single-threaded; update operations block configuration
  queries for their duration (~seconds under TCG).
- No network stack, USB, NVMe, or UEFI secure boot yet - these are
  Release-1 hardware gates tracked in PRODUCT_DIRECTION.md, not deviated
  from here.
