# Warm-UNO via Firecracker snapshot/restore — design

Status: **proposed** · 2026-06-03 · extends the 2026-05-31 framework design
(§9 "FC snapshot effort", Appendix A "Warm-UNO spike") into a buildable milestone.

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
- **Output-disk remap on restore.** Confirm FC lets a restored VM attach a fresh
  per-slot output drive (the snapshot was taken with a base drive); decide whether
  the output disk is excluded from the snapshot and attached at restore, or remapped.
- **`unoserver` packaging in the rootfs** — pin v3.6 + python-uno; confirm it warms
  to a listening socket deterministically for the READY signal.
- **Snapshot memory cost** — each restored VM holds a full copy-on-write of the
  snapshot memory; size the pool against host RAM.
