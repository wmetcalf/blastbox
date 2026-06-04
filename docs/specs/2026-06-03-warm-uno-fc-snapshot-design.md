# Warm-UNO via Firecracker snapshot/restore — design

Status: **core validated on toolz2** · 2026-06-03..06-04 · extends the 2026-05-31
framework design (§9 "FC snapshot effort", Appendix A "Warm-UNO spike") into a
buildable milestone. The full snapshot-of-running-`unoserver` → restore-from-RAM
loop is proven on real FC hardware (see the COW section). Remaining: impress/draw
parity gate + the in-restore document round-trip + warm-pool wiring.

## Goal

Hide LibreOffice's unavoidable ~750 ms `soffice` boot from ClippyShot's per-job
latency by serving conversions from a **warm `unoserver`** that is captured in a
**Firecracker memory snapshot** and **restored per job**. Restore is sub-second;
the UNO server is already listening on restore; the document converts in the
spike-measured ~24–40 ms steady state. This is the VM-level analogue of RedTusk's
JVM CRaC tier — **engine-agnostic, so it works for LibreOffice (no JVM)**.

The 2026-05-31 spike (`/home/coz/redtusk-bench/office-corpus/uno_spike.sh`) already
proved `unoserver`/`unoconvert` output is **byte/pixel-identical** to ClippyShot's
cold `soffice --convert-to` (incl. xlsx `SinglePageSheets`) for writer/calc. This
milestone turns that into a shipped warm path.

## Decisions (locked during brainstorming)

| # | decision | rationale |
|---|---|---|
| Tier | Warm-UNO is the **FC snapshot** path only; **bare-metal bwrap/nsjail stays cold** (existing one-shot path + existing profiles). | Snapshots are FC-specific; bare-metal already ships `sandbox/{bwrap,nsjail}.py` + AppArmor profiles and remains the dev/fallback path. |
| Mechanism | **`unoserver`/`unoconvert`** (not raw python-uno). | The exact tool the spike proved identical; least new code; parity already de-risked. |
| Warm model | **FC memory snapshot of a running, idle UNO server**, restored→used→destroyed per job. | What the operator actually wants; reuses FC's native snapshot/restore; engine-agnostic. |
| Snapshot timing | **Created first-boot on the target FC host**, not baked at image-build time. | FC snapshots are host-CPU-sensitive — the exact `-XX:CPUFeatures` class of bug that burned CRaC. Host-local creation sidesteps it entirely. |

## Architecture

**Everything UNO is in-guest; only job I/O crosses the trust boundary.**

```
  ┌─ Firecracker microVM (restored from the warm snapshot) ──────────┐
  │  unoserver → soffice --accept  (local UDS, IN-GUEST)             │
  │        ▲ unoconvert (guest agent, local UNO client)             │
  │        │                                                        │
  │   guest agent ── reads doc from vsock ── writes PDF/PNG to vdb  │
  └────────┬──────────────────────────────────────────┬────────────┘
           │ vsock (push doc, GO/DONE)                 │ virtio-blk output disk
        host dispatcher / warm pool ──────────────── host reads results (rdump)
```

- The UNO `--accept` socket is a **local UDS inside the guest**, captured in the
  snapshot's memory image. On restore it is instantly live — **no host-side socket
  to re-wire**, which is what makes vsock-across-restore clean.
- The only host↔guest channels are the **existing** ones: vsock (control + the
  untrusted input bytes) and the per-slot virtio-blk **output disk** (results read
  back via `debugfs rdump`). No new host↔guest surface.

### Snapshot build (once, on host first-boot)

1. Boot a base microVM from the ClippyShot rootfs.
2. Guest init starts `unoserver` (which supervises `soffice --accept` on a local UDS).
3. When the UNO socket is listening, the guest signals **READY over vsock**
   (reuses the existing `VsockReadySignal` plumbing).
4. Host **PauseVM → CreateSnapshot** (FC writes `snapshot_state` + `mem_file`).
5. Host kills the base VM. Artifact: a warm, **idle** UNO server (no in-flight job
   connection at snapshot time — required for clean restore).

### Per job (restore → use → destroy)

1. Warm pool's spawn op = **LoadSnapshot** with a **unique vsock UDS** + a **fresh
   per-slot output disk** (FC restores the same memory image N times, so the host
   side must re-path per slot) → **ResumeVM**.
2. UNO server is live immediately. Host pushes the untrusted doc over vsock (GO).
3. Guest agent runs `unoconvert` against the local UNO socket → PDF/PNG to the
   output disk → DONE.
4. Host reads the output disk, validates through the trust gate (unchanged), and
   **destroys** the VM. The next job restores the **same clean pre-input snapshot**.

**Isolation invariant preserved:** every job restores the same clean, pre-input
warm baseline, processes exactly one untrusted document, and is destroyed — "one
untrusted doc per disposable restore, never shared." The snapshot is built before
any untrusted data exists.

## Components

| where | change | size |
|---|---|---|
| `blastbox/host/runtime/firecracker.py` | **net-new:** API-socket restore path (snapshot load/resume is API-driven, not `--config-file`); `create_snapshot()` (Pause→snapshot→kill base VM); `restore_from_snapshot()` (load → unique vsock UDS + fresh outdisk → resume); a `SnapshotManager` that builds the warm snapshot once on first boot and serves restores to the pool. | large |
| `blastbox` FC rootfs (`deploy/firecracker/`) | init starts `unoserver` + signals READY when the UNO socket listens; guest agent runs `unoconvert` for the job (alongside the existing engine path). | medium |
| `deploy/firecracker/Dockerfile.clippyshot` | bundle `unoserver` v3.6 + its python-uno deps into the rootfs. | small |
| ClippyShot engine | `detonate()` drives conversion via the in-guest `unoconvert` when running under the snapshot runtime; cold `soffice --convert-to` stays the bare-metal/fallback path (no engine API change for callers). | small |
| warm pool / `pool_config` | slot runtime's spawn op becomes "restore from snapshot" instead of cold-boot when the snapshot tier is enabled (gated, opt-in). | small |

## Security model

- **Snapshot is a clean, pre-input baseline.** It is built before any untrusted
  document exists; restores never carry document state forward.
- **One doc per disposable restore, never shared** — unchanged from the cold FC tier.
- **UNO `--accept` socket is in-guest only** (local UDS), never exposed to the host
  or network — addresses the spike's "new attack surface" caveat.
- **Output is re-sealed from disk** by the host trust gate exactly as today; warm
  output is validated identically to cold.
- Host↔guest surface is unchanged (vsock + output disk); the snapshot tier adds **no
  new host-reachable channel**.

## Error handling & fallbacks

- **Snapshot create fails on host startup** → fall back to cold-boot FC for all jobs
  (no warm win, fully functional). Logged + a metric.
- **A per-job restore fails** → reap that slot, fall back to cold-boot for that job.
- **`unoconvert` fails inside the guest** → guest agent falls back to cold
  `soffice --convert-to` for that document, so a UNO hiccup never fails the job.
- All fallbacks keep the existing trust-gate + one-doc-per-slot guarantees.

## Testing & validation

1. **Output parity gate (blocking):** the spike proved writer/calc byte-identical;
   **impress/draw (pptx/odp/odg) parity is unverified on LO 25.8** and MUST be
   confirmed on the `clippyshot:audit` (LO 25.8) image before shipping — warm
   `unoconvert` vs cold `--convert-to`, pixel + byte comparison.
2. **Snapshot/restore correctness:** restore N VMs from one snapshot, each gets a
   live UNO server + a unique vsock + fresh outdisk; no cross-restore state bleed.
3. **Corpus regression (standing FC gate):** the 342-doc corpus on toolz2 through
   the warm-UNO snapshot path, output hashes compared to the cold baseline; no
   regression vs 342/342.
4. **Latency:** confirm the ~4–7× soffice-stage win materializes end-to-end (the
   boot is actually hidden), not just in isolation.

## Non-goals (explicit)

- Bare-metal (bwrap/nsjail) warm path — stays cold.
- Build-time/baked snapshots — rejected (CPU-mismatch risk); host-local only.
- Migrating RedTusk's JVM tier from CRaC to FC snapshot — the snapshot plumbing is
  built engine-agnostic so it *could* later, but that's out of scope here.
- A persistent-server-in-one-shot-sandbox lifecycle — not needed for the snapshot
  model (the server lives in guest memory, not a sandboxed host process).

## Open questions / risks to resolve during implementation

- **FC vsock + snapshot caveats.** Verify on a real FC host that a vsock device
  snapshotted while *idle* (no in-flight connection) restores cleanly and accepts a
  fresh host connection per restore. This is the highest-risk unknown; validate
  early with a throwaway snapshot before building the full tier.
  - **Phase 0 finding (2026-06-04, from the FC v1.12.1 embedded API schema, not yet
    runtime-confirmed):** `PUT /snapshot/load` (`LoadSnapshotConfig`) exposes
    `snapshot_path`, `mem_backend{backend_type,backend_path}`, `enable_diff_snapshots`,
    `network_overrides`, `resume_vm` — **there is NO vsock-uds override**. So the host
    vsock UDS path is baked into the snapshot and cannot be remapped in the load body.
    Implication: per-restore vsock uniqueness must come from the *environment*, not the
    load config — run each restore in a **per-slot working dir** (relative `uds_path`)
    so the same baked-in path resolves to a distinct per-slot socket.
  - **Phase 0 CONFIRMED on toolz2 (2026-06-04, `fc_snapshot_spike.py`, FC v1.12.1):**
    booted a base microVM over the API with a **relative** `vsock` uds_path
    (`vsock.sock`) + relative outdisk, cwd=base → FC created `base/vsock.sock`;
    `PATCH /vm Paused` + `PUT /snapshot/create` succeeded; then loaded the snapshot
    into **two** fresh firecrackers each in its own cwd (`slots/slot-A`, `slots/slot-B`)
    via `PUT /snapshot/load` + `resume_vm:true` — **each restore re-created its own
    `vsock.sock` in its own cwd** (verdict `{slot-A: True, slot-B: True}`). So the
    per-slot-cwd vsock mechanism + snapshot/restore both work on real FC. Still TODO:
    the host↔guest **round-trip** through a restored vsock (guest responds post-restore)
    — needs the warm rootfs + job protocol, not just the probe.
- **Output-disk remap on restore.** Confirm FC lets a restored VM attach a fresh
  per-slot output drive (the snapshot was taken with a base drive); decide whether
  the output disk is excluded from the snapshot and attached at restore, or remapped.
- **`unoserver` packaging — RESOLVED + warm conversion CONFIRMED on toolz2
  (2026-06-04, in the `clippyshot:dev` LO image):** the image ships LibreOffice +
  the C++ UNO libs but **not** the Python bridge, and the `/opt/clippyshot` venv
  can't see the system `uno` module. Fix (now in `Dockerfile.clippyshot`): install
  **`python3-uno`** (→ `/usr/lib/python3/dist-packages/uno.py` for the **system**
  python3) + `unoserver` into **system** python3 (not the venv). Then `unoserver`
  starts ("UNO PORT LISTENING") and **`unoconvert` produced a valid PDF** (the
  engine resolves `unoserver`/`unoconvert` to `/usr/local/bin`, shebang
  `#!/usr/bin/python3`, which has `uno`, since the venv has neither).
  - **Warm path E2E CONFIRMED through the ClippyShot engine (2026-06-04):** a thin
    overlay on `clippyshot:dev` (the warm `uno.py`/`engine.py`/`runner.py` + the deps
    fix + `blastbox`) ran, **as the non-root `clippy` user**, `engine.warmup()` →
    started `unoserver` → ready; the runner's warm fast-path converted a csv via
    `unoconvert` with `calc_pdf_Export` (my `pdf_filter_for_label` drove the filter).
    **Warm vs cold output is PIXEL-IDENTICAL** (page-1 render md5 equal,
    `14797`-byte PDFs both).
  - **Warm worker boots + warms in a REAL FC microVM (2026-06-04):** built the FC
    clippyshot rootfs (the 3 warm files staged + python3-uno + system unoserver +
    iproute2) and booted it; the guest agent ran `engine.warmup()` →
    `INFO:unoserver: Starting unoserver 3.6 … Started. Server PID: 109` as uid 10001.
    **Loopback bug found + fixed:** FC guests boot with `lo` DOWN, so unoserver's
    `soffice --accept=socket,host=127.0.0.1` was unreachable (`couldn't connect to
    socket` → `Could not start Libreoffice`); the init now `ip link set lo up`. The
    cold `--convert-to` path never needed loopback. **Snapshot-of-running-`unoserver`
    + restore-from-RAM now CONFIRMED** (see the COW section: warm base → READY →
    snapshot mem on `/dev/shm` → restore in 0.01 s → restored guest's JOB listener
    answers). Remaining: the impress/draw parity gate, and pushing an actual doc
    through the restored guest's vsock JOB channel (the in-restore transport round-trip;
    conversion itself already proven pixel-identical through the engine).
- **Snapshot memory cost + RAM-resident COW (design decision, 2026-06-04).** The
  snapshot's **mem file ≈ guest RAM** (~2 GB once LO/soffice is live) — the dominant
  cost. FC's `File` mem backend already `mmap`s it **`MAP_PRIVATE`** on load, so N
  restores **share the read-only base pages** + copy-on-write only what each VM
  dirties → cost is *base once + Σ(dirtied working set)*, NOT N × full. Two levels:
  1. **Opt-in: put the mem file on `tmpfs` (`/dev/shm`).** Pins the base in RAM —
     zero disk I/O on any restore (incl. the first), still COW-shared. Cost: ~one
     guest-RAM of RAM held for the warm baseline. Because that RAM cost is real and
     **hosts differ in how much RAM they have, this is a per-host toggle, default
     OFF** (the safe choice on a small box — the mem file lives on disk in the base
     dir, still page-cache-backed, just evictable under pressure):
     - `BLASTBOX_SNAPSHOT_MEM_TMPFS=1` → preload into the default tmpfs `/dev/shm`.
     - `BLASTBOX_SNAPSHOT_MEM_DIR=<path>` → preload into an explicit dir (for hosts
       whose tmpfs is mounted elsewhere); wins over the boolean toggle.
     - neither → mem on disk (default).

     Wired in `fc_snapshot.py`: `resolve_mem_dir()` reads the env, and
     `SnapshotManager.from_env(base, launcher)` constructs the manager with the
     resolved `mem_dir`. An explicit `mem_dir=` arg still short-circuits env
     resolution (tests, direct callers).

     **Pool wiring DONE (`fc_snapshot_runtime.py`).** `SnapshotSlotRuntime` is a
     `SlotRuntime` whose `spawn()` builds the warm snapshot once (via
     `SnapshotManager.from_env`, so the toggle is honored) then restores per slot;
     `is_ready`/`is_alive`/`reap` + the warm-path seam (`host_warm_control`,
     `materialize_warm_output`) mirror the cold `FirecrackerSlotRuntime` so the
     dispatcher's per-slot job flow is unchanged. `select_snapshot_runtime()` builds
     it (waiting for the base VM's READY via `VsockReadySignal` before snapshotting).
     Gated opt-in: `BLASTBOX_POOL_RUNTIME=firecracker` + `BLASTBOX_POOL_WARM_SNAPSHOT=1`
     → `build_warm_pool` routes the FC tier's spawn op through the snapshot runtime.

     **In-restore doc round-trip GATE — run on toolz2 (2026-06-04, `rt_roundtrip.py`,
     drives the real `SnapshotSlotRuntime`).** `spawn()` (boot base → warm `unoserver`
     → READY → snapshot mem on `/dev/shm` → restore) completed in **9.4 s**;
     `is_ready`/`is_alive` True; `host_warm_control().signal_go(csv)` → guest received
     the doc (`job_received bytes=43`) → **GO→DONE in 0.7 s, status `ok`**. So the vsock
     job round-trip into a restored warm VM works. The gate surfaced two real bugs the
     CONNECT-liveness probe could not:
     - **Output-disk ext4 corruption on restore (FIXED, host-side).** The base VM
       snapshots with its outdisk **mounted** → the guest's ext4 metadata is in guest
       RAM. Attaching a freshly-`mkfs`'d per-slot disk on restore → different
       UUID/checksums → `EXT4-fs error: Directory block failed checksum`. Fix:
       `FcSnapshotLauncher.restore_in` now **copies the base outdisk image** (empty at
       READY, snapshot-time-consistent) instead of fresh-`mkfs` — writes still land on
       the isolated per-slot copy. (`copy_outdisk` dep; one 256 MiB copy per restore.)
     - **Stale `clippyshot:dev` base (rootfs rebuild, NOT a code bug).** The engine
       adapter does `from clippyshot.rasterizer import build_rasterizer`; the warm
       rootfs's `clippyshot:dev` predates that symbol (it landed with the PDFium
       default on `feat/warm-uno-worker`) → `ImportError` in `detonate()`. Fix: rebuild
       `clippyshot:dev` from the current branch, then rebuild the warm FC rootfs.
     Re-running the gate after both fixes is the remaining step to a green
     pixel-identity round-trip.
  2. **Scale: FC's `Uffd` (userfaultfd) backend** — a handler process holds one base
     copy and serves guest pages lazily/shared across all restores; most RAM-efficient
     for large pools, at the cost of a page-fault handler. Future optimization.
  - **CONFIRMED end-to-end on toolz2 (2026-06-04, `snap_warm.py`, FC v1.12.1).** Booted
    the warm clippyshot rootfs over the API with a host vsock READY listener bound at
    `base/vsock.sock_10000`; the guest ran `engine.warmup()` → `unoserver` + `soffice`
    came up and the guest signalled `READY` over vsock (so the base reached the
    **warm-idle** state — a *running* UNO server, not a cold boot). Then `PATCH /vm
    Paused` + `PUT /snapshot/create` with `mem_file_path` on **`/dev/shm`** wrote the
    snapshot in **1.4 s**, mem file **2048 MiB** (= full guest RAM with live soffice —
    confirms the snapshot is large and the COW-in-RAM placement matters). Killed the
    base, then `PUT /snapshot/load` (`mem_backend` File → the `/dev/shm` mem) +
    `resume_vm:true` in a fresh per-slot cwd **restored in 0.01 s** (RAM-backed COW, no
    disk read). Confirmed the restored guest is **alive and warm**: a host→guest vsock
    `CONNECT 10001` (the agent's JOB port) returned `OK …` — i.e. the restored VM
    resumed *with the running `unoserver` and the job listener intact*. This proves the
    whole tier's premise: snapshot a live `unoserver`, restore it from RAM near-instantly,
    and the restore is immediately ready to serve a job. (Still TODO: push an actual doc
    through the restored guest's vsock JOB channel and assert pixel-identity end-to-end —
    the conversion itself is already proven pixel-identical through the engine; this gates
    only the in-restore transport.)
