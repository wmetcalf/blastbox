# Warm snapshots via gVisor (runsc) checkpoint/restore — design

Status: **Draft — Phase-0 Stages 1–3 validated on toolz2 (2026-06-05). The JVM/Tika warm
path works out of the box (2.4× on a corpus). The soffice warm path was BLOCKED, then
root-caused (gVisor's restore-EINTR + `osl_acceptPipe`'s single non-retrying `accept()`) and
**FIXED** with a ~10-line `LD_PRELOAD` accept-retry shim — warm soffice C/R now converts
correctly (docx/xlsx/pptx, restore-many). So **both** the JVM/Tika and the soffice/ClippyShot
warm paths are viable on this tier, on **any cloud VM (no nested virt)** — the portable warm
tier; FC stays the faster ms-class option where nested virt exists.** · extends the warm-snapshot tier
(`2026-06-03-warm-uno-fc-snapshot-design.md`) with a **second backend behind the same
abstraction**. Where the FC tier needs `/dev/kvm` + nested virt, this one needs only
**`runsc`** — so the docker/runsc deployment tier gets a warm path too. The core C/R
unknowns are now proven on real `runsc` (see Phase-0 validation); the remaining gate is
the full `unoserver`→convert→parity proof.

## Goal

Give the **gVisor (runsc) runtime tier** the same warm win the Firecracker snapshot
tier already ships: hide an engine's unavoidable boot/warmup cost by capturing a
**warm, idle engine** in a gVisor checkpoint and **restoring a fresh sandbox per job**.
gVisor's checkpoint/restore is its **own** mechanism — the Sentry (its userspace
kernel) serializes its own state — **not CRIU and not CRaC**. It is the closest
runtime-level analogue to FC's whole-VM snapshot: it captures the *sandbox*, not the
engine, so it is **engine-agnostic** by construction.

**Why a second backend** (the crisp pitch): the FC snapshot tier is the premium,
ms-class warm path but requires nested virt + KVM. Many targets — restricted clouds,
managed k8s, hosts without `/dev/kvm` — can run `runsc` but not Firecracker. This tier
is **warm-UNO (and warm-Tika) without nested virt**. It is the framework's established
pattern: a second implementation behind a proven abstraction (two sandboxes, two
rasterizers, three jobstores → now two warm-snapshot backends).

## Who benefits, and how

The tier snapshots the sandbox, so **both** family engines gain a runsc-tier warm path
from one piece of framework code — the Goal-#1 cross-pollination payoff of the
framework design. The benefit lands differently per engine:

| Engine | Role of gVisor C/R | Notes |
|---|---|---|
| **ClippyShot** (LibreOffice) | **Enabling** — the *only* warm path on a pure-runsc host. | `soffice` has no CRaC equivalent; this is the runsc-tier counterpart to FC-snapshot. **First proof:** the simplest target (an idle `unoserver` listening on one UDS) and the parity bar is already defined (pixel-identical warm==cold across calc/csv + impress/draw). |
| **RedTusk** (Tika/JVM) | **Simplifying + gap-filling.** | RedTusk warms via **CRaC** today, but CRaC is invasive: a CRaC-enabled JDK, app-level `Resource`-API instrumentation around every open file/socket, and **CRIU under the hood** (→ the CPU-feature-mismatch fragility the FC runtime already ships a probe for). A whole-sandbox gVisor C/R snapshot warms a booted, JIT-hot JVM **with no CRaC at all**. It is a potential **CRaC off-ramp** and it fills RedTusk's *runsc-tier warm gap* (today RedTusk only warms on the FC tier). **Second validation:** a warm JVM is a *harder* C/R target (many threads + open FDs; the exec'd-child gotcha is likelier), so it follows ClippyShot, exactly the original adoption order. |

`warmup()` stays **engine-defined** ("bring me to warm-idle — persistent listener +
its child are fine, just no in-flight job"); capture stays **framework-defined**. The
engine seam is unchanged.

## Phase-0 validation (toolz2 — 2026-06-05)

Host: `runsc release-20260511.0`, kernel 6.8, passwordless sudo, **`runsc` driven
directly** (`docker checkpoint` is disabled here — experimental off — which confirms the
direct-`runsc` decision). A staged spike ran; **Stages 1 and 2 PASS**, Stage 3 (real
`unoserver` pixel-parity) is the remaining gate.

- **Stage 1 — bare C/R + swapped mount (PASS).** `runsc run` → `runsc checkpoint`
  (image 580 K / 3 files) → `runsc restore` into a fresh container, all rc=0. An in-memory
  counter resumed **i=15 → 30** while writing into a **different `/state` bind-mount** than
  it had at checkpoint — memory state survives **and** the gofer reassociates a swapped
  bind-mount on restore.
- **Stage 2 — live-child topology + control plane (PASS).** A worker that **spawns a
  long-lived child** (stand-in for `unoserver`'s persistent `soffice`), reaches warm-idle,
  and blocks — was checkpointed with its **4-process tree alive** (`runsc ps`: parent `sh`
  + child `sh` + both their `sleep`s), then restored into a container with **swapped
  `in/`+`ctrl/`+`out/` mounts**. **Restore rc=0 with no #11439 "no host FD available"** —
  the exec'd-child/multi-process case is fixed on this build. The restored worker resumed,
  the **host delivered the job by writing a trigger file** it polls, it converted a **new
  input** from the swapped mount correctly, and the child was still alive.

**Three of the research's top risks are de-risked on real `runsc`:** (1) multi-process
checkpoint with a live child (#11439), (2) swapped input/control/output mounts (gofer
reassociation), (3) the control plane across restore.

**Two decisions the spike changed:**

1. **Control plane → host-written trigger file (not a listening UDS).** The spike used a
   host-written `ctrl/go` file the worker polls over the gofer-backed `ctrl/` bind-mount
   (worker writes `ctrl/done` + status back), because host↔sandbox UDS bridging is a known
   gVisor gotcha (the socket lives in the Sentry; it needs `--host-uds` and punches an
   isolation hole). The file trigger is bulletproof over the gofer and proven. The
   listening-UDS option is deferred as a *possible* future optimization, not the design.
2. **The persistent child is fine — relax the "exec'd-child invariant."** `unoserver`
   supervises a *persistent* `soffice` listener (alive at warm-idle), and Stage 2 proved
   that multi-process topology checkpoints+restores cleanly. So the invariant is "don't
   checkpoint **mid-conversion** (no in-flight `unoconvert`/job)," **not** "no child at
   all." `soffice` is captured warm, not spawned post-restore.

### Stage 3 — warm soffice convert: BLOCKED, then root-caused + FIXED

Getting `soffice` itself to *convert* across gVisor C/R hit a hard wall, and it inverts the
spec's assumption that ClippyShot is the *easy* first target:

- LibreOffice **runs** under `runsc` (cold `soffice --convert-to`: docx→PDF, rc=0, ~4.9 s).
- A raw `python-uno` **pipe** converter works against a **live** soffice (`-network=none`,
  soffice `--accept=pipe`, no loopback needed): docx→42 KB PDF, byte-size-identical to the
  cold path. *(Loopback is unavailable in a bare `runsc` bundle — no CNI configures `lo`,
  and gVisor doesn't implement `SIOCSIFADDR` to create one — so TCP `unoserver` is out; the
  pipe/UDS is the right transport anyway, and needs no network.)*
- **But across checkpoint/restore the warm convert *initially* hung.** Post-restore:
  `checkpoint`/`restore` rc=0, soffice **alive**, the pipe socket **present**, the client's
  `connect()` returns 0 (queues) — yet the conversion timed out (`rc=124`). The *same*
  converter works against a live soffice, so it's purely C/R-caused. Root-caused and **fixed**
  below.

**Root cause — narrowed, and it is soffice-specific (NOT a general gVisor-C/R limit).**
The stack dump during the hang showed soffice's threads asleep — one in
`unix.(*Socket).blockingAccept`, several in `futexWaitAbsolute` — which *first* looked like
"gVisor doesn't re-wake blocked `accept()`/futex." **That generalization is wrong.** Minimal
probes across the *same* C/R cycle prove gVisor restores these primitives correctly:

- single-threaded server blocked in **`accept()`** (main thread) → wakes on a post-restore connection ✓
- server blocked in **`epoll_wait`** → wakes ✓
- multi-threaded **condvar/futex handoff** (acceptor → worker via `cv.wait()`/`cv.notify()`) → ✓
- **secondary (non-main) thread** blocked in `accept()` while main thread sleeps → ✓
- a full **JDK 25 JVM** (all its GC/JIT/VM threads) blocked in `accept()` → ✓
- a listener that **already accepted+closed a connection** (connection history), then blocked in `accept()` → ✓

Every one survives restore and answers the client. A startup strace also confirmed soffice's
listener is a **plain `AF_UNIX`/`SOCK_STREAM` socket with no `setsockopt` options** — i.e. no
socket-level difference from the working probes. So the **generic warm-server patterns —
including a dedicated acceptor thread and a full JVM — are fine under gVisor C/R.**

**Root cause (gdb + LibreOffice source + the gVisor restore mechanism).** Three pieces fit:

1. **gdb** (post-restore, symbols installed via a `gdb` rootfs layer; ptrace works under
   runsc): `PipeIPC` is blocked in `__libc_accept(fd=9)` ← **`osl_acceptPipe()`**; the main
   thread idles in a futex in `soffice_main()`. So it's a plain `accept()` that never returns —
   the client's queued connection is never accepted.
2. **LibreOffice source** (`sal/osl/unx/pipe.cxx`): `osl_acceptPipe` does a **single raw
   `accept(socket, nullptr, nullptr)` with NO EINTR-retry loop** — no `poll`, no self-pipe
   (the connect-to-self wakeup is `#ifdef`'d FreeBSD-only). On Linux it relies entirely on the
   kernel returning a connection from that one `accept()`.
3. **gVisor's restore interrupts blocked syscalls with EINTR** — and native-C probes prove it
   does so **regardless of `SA_RESTART` (set across signals 1–64) and regardless of the signal
   mask (all signals blocked)**. Code that **re-calls** `accept` on EINTR recovers — Python
   (PEP 475), the JVM (interruptible I/O), and every C retry-loop probe. `osl_acceptPipe`,
   which does **not** retry, takes the EINTR and bails; the connection that queued during the
   restore window is lost. **That is the entire difference** — it's why ~15 minimal probes
   (single/secondary-thread `accept`, `epoll`, condvar/futex handoff, a full JDK 25 JVM,
   listener-with-history, tmpfs vs gofer socket, 200-fd/two-listener) all survive, and only
   soffice hangs.

**THE FIX (proven on toolz2, shippable).** A ~10-line `LD_PRELOAD` shim wrapping
`accept`/`accept4` to **retry on EINTR** restores exactly the behavior `osl_acceptPipe` omits:

```c
int accept(int fd, struct sockaddr*a, socklen_t*l){
  for(;;){ int r=real_accept(fd,a,l); if(r<0 && errno==EINTR) continue; return r; }
}
```

With `LD_PRELOAD=<accept-retry>.so` on soffice, warm C/R conversion **works** — restore-many
from one checkpoint converted **docx (42673 b, byte-size = cold), xlsx (206 KB), pptx (44 KB)**
correctly (a legacy `.doc` gave a separate `rc=1` conversion error, not a hang). **No LO
rebuild** — the shim is a tiny build artifact dropped into the warm rootfs and an env var.
(Upstream-proper alternatives exist too: a gVisor fix to re-issue interrupted accepts on
restore, or an LO patch to retry `accept` on EINTR in `osl_acceptPipe` — the shim needs
neither and is the pragmatic blastbox-side fix.)

**Perf (measured, toolz2).** soffice `runsc restore` → live soffice ~**0.30 s** (bare sandbox
boot ~0.21 s) vs ~**4 s** cold soffice-to-ready → **~13× on the acquire**, FC's class, and the
output is byte-size-identical to cold. (A clean warm-vs-cold *convert* number needs a leaner
in-process UNO client than the per-job `python-uno` harness used here, whose interpreter+UNO
startup masks the win; the acquire is the real story and it holds.)

**Implication — the inversion is undone; both engines are served.**
- **JVM/Tika (RedTusk):** works with **no shim** — **2.4× corpus** (warm restore+extract p50
  1.81 s vs cold 4.79 s; restore ~0.24 s). The Modal/GKE-proven case.
- **soffice/ClippyShot:** works **with the accept-retry shim** — ~13× acquire, output
  size-identical to cold.

So the gVisor C/R tier is the **portable warm tier for both engines on any cloud VM** (no
nested virt). FC remains the faster ms-class option where `/dev/kvm` + nested virt are
available; gVisor C/R is the broadly-deployable one.

**Pixel-parity gate — PASSED (toolz2), broadened across families + formats.** Warm-restored
soffice (with the shim) vs cold `soffice --convert-to`, both rasterized at **150 DPI**,
per-page **md5 identical** across all three engine families in OOXML **+ legacy + ODF**:
**writer** (docx 1/1, txt 1/1, odt 1/1), **calc** (xlsx 4/4, xls 3/3, ods 4/4), **impress**
(pptx 1/1, odp 1/1). So warm output is byte-for-byte the cold output. Draw (odg) was not
re-tested here for lack of a clean source, but the FC tier already cleared it and the
restored-soffice render engine is identical. *(Malformed corpus `.doc/.ppt/.rtf/.pps`
samples fail **cold** too — bad inputs, not a tier issue, e.g. the legacy-`.doc` "source
file could not be loaded".)* The shim is productionized (see Components/deploy).

**Deploy artifact — the accept-retry shim (required for the soffice path).** Build the
~10-line `accept`/`accept4` EINTR-retry shim into the soffice **warm rootfs** (`gcc -shared
-fPIC -o /opt/clippyshot/accept-retry.so accept_retry.c -ldl`) and set
`LD_PRELOAD=/opt/clippyshot/accept-retry.so` in the warm-worker env. Inert for any other
runtime (FC/cold/docker don't C/R the listener, so the retry never fires). The JVM/Tika path
needs **no** shim. This belongs in the Components table's deploy row for the gVisor-C/R
soffice tier.

## Decisions (locked during brainstorming)

| # | decision | rationale |
|---|---|---|
| Tier | **One generic `SnapshotManager`** + a **`SnapshotBackend` seam that specific container/sandbox types implement** (FC today, gVisor-runsc next). Selected by `BLASTBOX_POOL_RUNTIME=gvisor` + `BLASTBOX_POOL_WARM_SNAPSHOT=1`. | The manager owns the runtime-agnostic lifecycle (build-once idempotency, safe-`slot_id` guard, restore-per-slot, fail-closed contract); each backend owns its mechanics + an **opaque artifact**. Not a duplicated `GvisorSnapshotManager`, and not gVisor bolted onto FC-specific code — a clean seam both implement. |
| Mechanism | **Native `runsc checkpoint` / `runsc restore`**, driven **directly via the `runsc` binary**. NOT CRIU, NOT CRaC, NOT the runc/`docker checkpoint` path. | gVisor C/R is the clean, Sentry-native analogue to FC's snapshot. The **containerd/CRI checkpoint path is unimplemented upstream** (google/gvisor#11810, containerd#12280) and `docker checkpoint` can't restore-into-a-new-container — but the dispatcher already drives the runtime directly, so direct `runsc` is the natural fit. |
| Warm model | Checkpoint a sandbox running a **warm, idle engine listener** (an `unoserver` UDS for ClippyShot; a booted Tika JVM for RedTusk), then **restore a fresh sandbox per job** with per-job bind mounts, one untrusted doc, destroy. | The whole point: pay boot+warmup once at checkpoint-build; restore per job. Identical isolation invariant to the FC tier. |
| Snapshot timing | **Built first-boot on the target runsc host**, not baked at image-build time. | gVisor restore verifies the host has all CPU features captured at checkpoint, and the checkpoint image format is **not documented as version-portable**. Host-local build sidesteps both — the same lesson as the FC tier (and CRaC). |
| I/O plane | **Bind mounts, not vsock + ext4.** Input = per-slot read-only bind mount; output = per-slot rw bind mount read **directly** host-side; control = host writes a **trigger file** (`ctrl/go` = the input path) the worker polls over the gofer-backed `ctrl/` mount; worker writes `ctrl/done` + status. | A gVisor sandbox is a container — it already shares the host FS via the gofer. This is *less* code than the FC tier (no vsock, no ext4 `rdump`); the trust gate validates output from a regular directory exactly as today. **Phase-0 changed this from a listening UDS to a trigger file** — host↔sandbox UDS bridging is a gVisor gotcha; the file trigger is proven (Stage 2). |
| Checkpoint timing | Checkpoint at **warm-idle — persistent listener + child alive, no in-flight job**; do **not** checkpoint mid-conversion. | Stage 2 proved a live parent+child tree checkpoints+restores cleanly (no #11439), so `unoserver`'s persistent `soffice` is captured *warm*. The thing to avoid is an in-flight `unoconvert`/transient job state at checkpoint, not the persistent child. |

## Architecture

**Everything engine-internal stays in-sandbox; only job I/O crosses the trust boundary
— over bind mounts and one host→guest control UDS.**

```
  ┌─ gVisor sandbox (restored from the warm checkpoint) ─────────────┐
  │  unoserver → soffice --accept  (local UDS, IN-SANDBOX)           │
  │       ▲ unoconvert (warm worker, local UNO client)              │
  │       │                                                         │
  │  warm worker ── polling ctrl/go (idle at checkpoint) ───────────┼──◄ host writes
  │       │           reads doc from the RO input bind mount        │     after restore:
  │       └─ writes PDF/PNG to the RW output bind mount ────────────┼──► ctrl/go = input path
  └─────────────────────────────────────────────────────────────────┘     worker → ctrl/done
        per-slot bind mounts:  in/ (ro)   out/ (rw)   ctrl/ (go + done)
```

- The engine's listener (UNO `--accept` UDS / the JVM) lives **inside the sandbox**,
  captured in the checkpoint's serialized Sentry state. On restore it is instantly
  live — no host-side socket to re-wire.
- The host↔guest channels are a per-slot **read-only input** bind mount, a per-slot
  **read-write output** bind mount (read directly — no extraction step), and a per-slot
  **control** bind mount carrying a **trigger file**: after restore the host writes
  `ctrl/go` (= the in-sandbox input path) which the worker is polling; the worker reads
  it, converts, and writes `ctrl/done` + status. (Phase-0 Stage 2 proved this over the
  gofer; it replaces the earlier "host connects to a listening UDS" idea.)

### Snapshot build (once, on host first-boot)

1. `runsc run` a base sandbox from the engine's worker image, with a placeholder/empty
   input mount and a per-base control dir.
2. The warm worker runs `engine.warmup()` (ClippyShot: start `unoserver` →
   `soffice --accept` on a local UDS; RedTusk: boot the JVM + load Tika, optionally
   JIT-warm with benign inputs in the pristine no-input context).
3. The worker reaches **warm-idle**: it blocks **polling `ctrl/go`** (no trigger yet),
   with the persistent `unoserver`+`soffice` listener alive and **no in-flight job** —
   the checkpoint-safe state (Stage-2-proven topology).
4. Host runs `runsc checkpoint --image-path=<dir>` (with `--compression=none` if using
   `--direct`/`--background`).
5. Host kills the base sandbox. Artifact: a checkpoint image of a warm, idle engine
   with **no in-flight job and no exec'd conversion child**.

### Per job (restore → use → destroy)

1. Warm pool's spawn op = `runsc create <id>` + `runsc restore --image-path=<dir>` into
   a **per-slot working dir** with **fresh per-slot bind mounts** (`in/` ro, `out/` rw,
   `ctrl/`). The gofer reassociates the filesystem to the new mounts (gofer `UniqueID`
   reassociation) — so each restore sees its own per-job document.
2. The engine listener is live immediately; the worker is blocked **polling `ctrl/go`**.
   After a short **settle window** (mirrors the FC tier's post-restore settle), the host
   **writes `ctrl/go`** = the in-sandbox input path; the worker picks it up on its next
   poll.
3. The worker reads the untrusted doc from the RO input mount, runs the engine
   (`unoconvert` / Tika), writes artifacts to the RW output mount, replies DONE.
4. Host reads the output directory **directly** (it's a bind mount), validates through
   the trust gate (unchanged), and **destroys** the sandbox. The next job restores the
   **same clean pre-input checkpoint**.

**Isolation invariant preserved:** every job restores the same clean, pre-input warm
baseline, processes exactly one untrusted document, and is destroyed — "one untrusted
doc per disposable restore, never shared." The checkpoint is built before any untrusted
data exists.

## The snapshot abstraction (one generic manager, pluggable backends)

The existing `SnapshotLauncher` Protocol evolves into a `SnapshotBackend` seam; the
manager talks only to it and never inspects a backend's artifact:

```python
class SnapshotBackend(Protocol):
    def available(self) -> bool: ...                       # prereq probe → fail-closed selection
    def boot_base(self) -> BootHandle: ...                 # BootHandle: .wait_ready(t); .checkpoint(dest) -> Artifact; .kill()
    def restore_in(self, slot_workdir: Path, artifact: Artifact) -> RestoreHandle: ...   # fully restored + resumed
```

`Artifact` is **opaque to the manager**. `SnapshotManager.build()` becomes:
`boot = backend.boot_base(); boot.wait_ready(t); artifact = boot.checkpoint(dest); boot.kill()` —
the manager owns idempotency + dest path + error-wrapping; the backend owns the
mechanics and the artifact shape. `restore(slot_id)` becomes:
`backend.restore_in(slot_workdir, artifact)` — the manager owns the safe-`slot_id` guard,
the per-slot workdir, and leak-cleanup-on-failure; the backend does the full restore.

This relocates every FC-ism out of the manager: the `{snapshot_state, mem_file}` artifact,
the Pause+CreateSnapshot / load+resume API calls, **and the RAM-preload toggle**
(`resolve_mem_dir` / `_mem_dir`, FC-only — gVisor C/R has no separate mem file) all move
into `FcSnapshotBackend`. The manager stops knowing FC exists.

## Relationship to the FC snapshot tier (what's reused vs new)

| Piece | FC tier | gVisor C/R tier |
|---|---|---|
| `SnapshotManager` (build-once idempotency, restore-per-slot, safe-`slot_id` guard, fail-closed contract) | ✅ | **Reused unchanged** — it's now runtime-agnostic (talks only to the `SnapshotBackend` seam; artifact opaque). |
| `SnapshotBackend` seam (`available`, `boot_base`, `restore_in`; `BootHandle.checkpoint`) | **`FcSnapshotBackend`** (extracted from today's `FcSnapshotLauncher` + the FC-specific manager bits: artifact = state+mem, Pause+Create, the RAM-preload toggle) | **New `GvisorSnapshotBackend`**: `boot_base()` = `runsc run` warm container + readiness barrier + `runsc checkpoint`; `restore_in(dir, artifact)` = `runsc create` + `runsc restore` with per-slot bind mounts; artifact = the image-path dir. |
| `SlotRuntime` warm-path seam (`host_warm_control`, `stage_warm_input`, `materialize_warm_output`, `reap`) | `SnapshotSlotRuntime` (vsock control, ext4 output via `rdump`) | **New `GvisorSnapshotSlotRuntime`** sharing the build-once/restore/reap skeleton: `host_warm_control` → a **UDS** control (host connects to the guest's listening `ctrl.sock`) instead of vsock; `materialize_warm_output` → **near-noop** (output already in `slot.output_dir` via the rw bind mount); `stage_warm_input` → place the doc in the per-slot `in/` mount. |
| Pool wiring (`select_snapshot_runtime`, `BLASTBOX_POOL_WARM_SNAPSHOT`, settle window) | ✅ | **Reused**; `select_snapshot_runtime` gains a **backend switch** (`firecracker` \| `gvisor`), fail-closed when the selected backend's prereqs are missing. |
| RAM-preload toggle (`BLASTBOX_SNAPSHOT_MEM_*`) | mem file on tmpfs | **N/A** — gVisor C/R has no separate mem-file artifact to pin; the page cache covers the checkpoint pages. (gVisor's own restore-with-sharing / COW-across-restores is **unverified upstream** — see risks.) |

## Components

| where | change | size |
|---|---|---|
| `blastbox/host/runtime/fc_snapshot.py` | **refactor to the seam:** make `SnapshotManager` generic (opaque artifact; talks only to `SnapshotBackend`) and **extract `FcSnapshotBackend`** carrying the FC-isms relocated out of the manager — the `{snapshot_state, mem_file}` artifact, Pause+CreateSnapshot / load+resume, and the RAM-preload toggle (`resolve_mem_dir`). Behavior-identical for FC; **gated by the FC tier's existing tests staying green**. | medium |
| `blastbox/host/runtime/gvisor_snapshot.py` | **net-new:** `GvisorSnapshotBackend` implementing the seam (`runsc run`/`checkpoint`/`create`/`restore` subprocess driver, per-slot bind-mount wiring, version+platform+CPU-feature pinning, readiness barrier; artifact = the image-path dir), and a handle with `checkpoint()`/`kill()`. | large |
| `blastbox/host/runtime/gvisor_snapshot_runtime.py` | **net-new:** `GvisorSnapshotSlotRuntime` (the SlotRuntime; UDS control seam + direct-read output). May share a small base with `SnapshotSlotRuntime`. | medium |
| `blastbox/worker/warm.py` (+ a file-trigger control transport) | the warm lifecycle already does "boot → warmup → one job → exit"; add a **trigger-file control transport** (poll `ctrl/go` for the input path, convert, write `ctrl/done` + status) as the gVisor-tier counterpart to the vsock control — Stage-2-proven over the gofer. | small |
| `blastbox/host/pool_config.py` / `select_snapshot_runtime` | backend switch (`firecracker` \| `gvisor`); fail-closed selection when `runsc` / checkpoint support / kernel features are absent. | small |
| deploy (runsc worker image) | a `runsc`-enabled host + the engine worker image with the UDS-control warm entrypoint (ClippyShot: reuse the existing image + `unoserver`; pin runsc version, expose a `cpufeatures` annotation). | small |

## Security model

- **Checkpoint is a clean, pre-input baseline** — built before any untrusted document
  exists; restores never carry document state forward.
- **One doc per disposable restore, never shared** — unchanged from every other tier.
- **Engine listener is in-sandbox only** (local UDS / in-process JVM), never exposed to
  the host or network. The only host-reachable channel is the per-slot **control UDS**,
  reachable solely through the per-slot bind mount, carrying GO/DONE — never engine data.
- **Output is re-sealed from disk** by the host trust gate exactly as today; warm output
  is validated identically to cold (and the bind-mount path means *fewer* moving parts
  than the FC ext4/`rdump` path).
- **No new network surface** — `--network=none` is unchanged; the control plane is a
  filesystem UDS, not a routable socket.
- **The restored sandbox is still a gVisor sandbox** — full Sentry syscall interposition,
  cap-drop, no-new-privs, read-only rootfs. C/R does not relax the isolation posture.

## Error handling & fallbacks (fail-closed, mirrors the FC tier)

- **Checkpoint build fails on host startup** → fall back to **cold-boot** runsc for all
  jobs (no warm win, fully functional). Logged + a metric.
- **A per-job restore fails** → reap that slot, cold-boot that job.
- **The engine fails inside a restored sandbox** (`unoconvert` hiccup) → in-sandbox
  fallback to cold `soffice --convert-to` for that document, so a warm hiccup never
  fails the job.
- All fallbacks keep the trust-gate + one-doc-per-slot guarantees. Never raise the job
  on a warm-tier hiccup (the standing warm-path rule).

## Testing & validation

1. **Output parity gate (blocking):** warm (restored) vs cold conversion must be
   **pixel-identical** across calc/csv + impress/draw (pptx/odp/ppt/odg) — the exact bar
   the FC warm-UNO tier already cleared. Run on the LO-25.8 image.
2. **Restore-many independence:** restore N sandboxes from one checkpoint; each gets a
   live engine + its own per-slot bind mounts + control UDS; **no cross-restore state
   bleed**, each converts its own per-job document.
3. **Corpus regression (standing gate):** the 342-doc corpus through the gVisor-C/R warm
   path, output hashes compared to the cold baseline; no regression.
4. **Latency:** confirm the warm acquire beats cold-boot+warmup end-to-end (the boot is
   actually hidden). **Set expectations honestly** (see Performance): a solid multiple on
   the acquire, **not** FC's order-of-magnitude.
5. **Fail-closed paths:** checkpoint-build failure, per-job restore failure, in-sandbox
   engine failure all degrade to cold without failing jobs.

## Performance (expectations, from research — confirm in the spike)

- gVisor C/R restore is **sub-second to ~1 s**, dominated by the app's memory footprint,
  with `--background` paging the rest in on demand (Modal production: `import torch`
  restores ~1 s p50 vs ~5 s cold; ~2.5× faster than cold container start).
- **vs Firecracker:** FC snapshot restore is **~ms** (as low as ~4 ms) — **1–2 orders of
  magnitude faster**, because it resumes a frozen VM rather than re-materializing a
  userspace kernel's serialized state. So this tier is the **portable, no-nested-virt**
  warm path, not a faster one. For ClippyShot the relevant comparison is per-job
  **cold `soffice` boot + LO warmup** (the expensive part this hides) — the warm win
  holds; it is a smaller multiple than FC's measured ~13.5× at p50.

## Non-goals (explicit)

- **runc + CRIU warm path** — rejected. CRIU freezes against the host kernel and is
  brittle exactly where this needs it (a *listening* UDS, open FDs, version/kernel
  coupling). gVisor's Sentry-native C/R is the clean route.
- **Forcing RedTusk off CRaC.** The tier is built engine-agnostic so RedTusk *can* drop
  CRaC for it, validated second — but CRaC stays a supported warmup on the FC tier; this
  doesn't rip it out.
- **CRI/containerd checkpoint integration** — unimplemented upstream; out of scope. Drive
  `runsc` directly.
- **gVisor restore-with-sharing / COW-across-restores as a perf assumption** — not relied
  on (unverified upstream; see risks). The tier is correct without it.

## Open questions / risks to resolve (Phase-0 spike gates the build)

Mirroring the FC tier, **the highest-value first step is a throwaway `runsc`
checkpoint/restore proof, before any tier code.** The spike:

1. `runsc run` a warm sandbox → start `unoserver` (listening UDS, **no conversion
   child**) → `runsc checkpoint`.
2. `runsc restore` into a fresh sandbox with a **per-job read-only doc bind-mount that
   differs from checkpoint time** → convert.
3. **Assert pixel-identical to cold `--convert-to`** across calc/csv + impress/draw.

Top risks the spike must confirm (from the research):

- **Exec'd-child FD case (gVisor #11439). — RESOLVED (Stage 2).** A live parent+child
  process tree (`runsc ps` showed 4 processes) checkpointed and restored rc=0 on
  `release-20260511.0`, with the child alive after restore. So `unoserver`'s persistent
  `soffice` is captured warm; PR #11478's fix is in this build. (Still: re-confirm after
  any runsc upgrade — version-pin.)
- **Fresh per-job input mount swap. — RESOLVED (Stages 1+2).** Restored into a container
  with a *different* `in/` (and `ctrl/`, `out/`) bind-mount source than at checkpoint; the
  gofer reassociated and the worker read the new input correctly.
- **Control plane across restore. — RESOLVED via trigger file (Stage 2).** Host writes
  `ctrl/go`; the polling worker picks it up, converts, writes `ctrl/done`. The
  listening-UDS idea was dropped (host↔sandbox UDS needs `--host-uds`, an isolation hole);
  it remains a *possible* future optimization, not a dependency.
- **Compatibility pinning.** Pin runsc **version**, **platform** (systrap vs KVM), and
  **CPU-feature set** (use the `dev.gvisor.internal.cpufeatures` annotation); rebuild the
  checkpoint on upgrade / host change. Reuse the FC tier's "flush warm pool on image
  change" + CPU-feature-mismatch prior art.
- **No live connection at checkpoint.** Guarantee the checkpoint is taken while the
  control UDS is *listening only* — connected endpoints are the documented rejection.
- **SysV/POSIX shm** in headless LibreOffice — not documented as C/R-safe; unlikely in
  headless mode but verify in the spike. (Lower risk; named for completeness.)

**Maturity note (honest):** gVisor's own docs don't stamp C/R "GA," but it is the basis
of **GKE Pod Snapshots (GA, May 2026)** and Modal's production cold-start path — so it is
production-grade in practice, just not formally version-stamped. The containerd/CRI
checkpoint path being unimplemented is why we drive `runsc` directly.
