# CRaC `SnapshotBackend` — Design (Phase 3 groundwork)

**Status:** DESIGN / groundwork. Implementation + real validation is Phase 4 (needs redtusk's CRaC JVM + Tika workload). No production code until the design is reviewed.
**Date:** 2026-06-08

## Goal

Add **CRaC** (Coordinated Restore at Checkpoint — JVM checkpoint/restore) as a third `SnapshotBackend` in `blastbox.host`, alongside the FC mem-snapshot and gVisor C/R warm tiers. This generalizes redtusk's JVM warm tier into the framework so that redtusk — and **any future Java detonation engine** — gets sub-second warm-start from the framework instead of re-implementing it.

## Why it fits the existing seam (no manager changes)

`SnapshotManager` (`host/runtime/fc_snapshot.py`) is backend-agnostic: it drives any `SnapshotBackend` and round-trips an **opaque** checkpoint artifact. The protocol (`host/runtime/snapshot_backend.py`):

```
SnapshotBackend: available() -> bool ; boot_base() -> BootHandle ; restore_in(slot_workdir, artifact) -> RestoreHandle
BootHandle:      wait_ready(timeout_s) ; checkpoint(dest_dir) -> opaque artifact ; kill()
RestoreHandle:   kill()  (+ backend-specific I/O accessors)
```

CRaC maps onto this 1:1, mirroring `FcSnapshotBackend` (a thin adapter delegating spawn/checkpoint/restore to a launcher):

| seam | FC | **CRaC** |
|---|---|---|
| `available()` | FC bin + /dev/kvm present | a **CRaC-capable JVM** (`java -XX:CRaCCheckpointTo` supported) **+ `criu`** present + criu's privileges (`CAP_CHECKPOINT_RESTORE`/`CAP_SYS_ADMIN`) |
| `boot_base()` | boot base microVM | launch base JVM worker with `-XX:CRaCCheckpointTo=<dir>`; run a **warmup detonation** so JIT/class-load/caches are hot; signal READY |
| `BootHandle.checkpoint(dest)` | FC `/snapshot/create` → {snapshot,mem} | `jcmd <pid> JDK.checkpoint` → CRaC image dir (opaque artifact = that dir) |
| `restore_in(slot, artifact)` | spawn FC + `/snapshot/load` + resume | `java -XX:CRaCRestoreFrom=<image>` → restored warm JVM (~10s of ms) |
| `RestoreHandle` | FC vsock I/O | the restored JVM's job I/O channel |

## Components (new, on a `CracSnapshotBackend` branch)

1. **`host/runtime/crac_snapshot_backend.py`** — `CracSnapshotBackend` + `CracBootHandle` + `CracRestoreHandle`, modeled on `fc_snapshot_backend.py`. Thin; delegates to:
2. **`host/runtime/crac_snapshot_launcher.py`** — `CracSnapshotLauncher`: constructs the `java`/`jcmd`/`criu` argv, spawns the base + restored processes (subprocess-injectable for tests, exactly like `FcSnapshotLauncher`).
3. **`host/runtime/crac_snapshot_runtime.py`** — `select_crac_snapshot_runtime()` builds `CracSnapshotBackend.from_env()` + `SnapshotManager` + a `CracSnapshotSlotRuntime` (the per-slot control plane), mirroring `fc_snapshot_runtime.py` / `gvisor_snapshot_runtime.py`.
4. **Pool wiring** — `pool_config.py`: extend the `BLASTBOX_POOL_RUNTIME` switch with `"crac"` (today: `none`/`fc`/`gvisor`).
5. **Java-side warm entrypoint** — the CRaC counterpart of `deploy/gvisor/run_warm.py` / `deploy/firecracker/run_guest.py`: a JVM process that boots → warms → signals READY (checkpoint fires) → **post-restore** enters the job-processing loop (read trigger, run the Java engine's `detonate`, write sealed output). Lives in the engine image (redtusk's), not blastbox core.

## Control plane

The host must signal a restored warm JVM to process one job and read its sealed output. Reuse the **file-trigger** pattern already proven for the gVisor tier (`run_warm.py`: host writes `ctrl/go`, worker polls; output read from a bind mount) rather than vsock — CRaC restore is a plain process, not a microVM, so no vsock is needed. The `CracRestoreHandle` exposes the slot's input/output dirs + the trigger file.

## `available()` / selection (fail-closed)

`available()` returns True only if: a CRaC JVM is on PATH (probe `java -XX:CRaCCheckpointTo=/dev/null -version` or a capability flag), `criu` is present and runnable, and the process has criu's required capability. Anything missing → backend unavailable → the pool falls back (or the operator gets a clear error), never a half-working warm tier.

## Validation plan

- **Phase 3 (this branch):** unit tests with an **injected subprocess runner** (mock `java`/`jcmd`/`criu`), exactly how `test_fc_snapshot*.py` / `test_gvisor_snapshot.py` test the FC/gVisor backends without the real runtime. Covers: `available()` detection, argv construction, the checkpoint→artifact→restore round-trip wiring, fail-closed selection.
- **Phase 4 (with redtusk):** the real gate. A CRaC JVM + redtusk's Tika `detonate` + the 342-corpus on toolz2 — checkpoint a warmed Tika JVM, restore per slot, prove parity + the warm-start speedup, against redtusk's current bespoke CRaC.

## Open questions — must be ground-truthed against redtusk in Phase 4

1. **How redtusk does CRaC today.** Its warm tier is JVM CRaC **baked into `redtusk-worker:crac-vsock` + FC restore-from-rootfs** — i.e. CRaC currently rides *inside* the Firecracker tier, not standalone. Need to read redtusk's actual CRaC wiring (on toolz2) to know whether this backend restores CRaC **standalone** (criu in a runsc/runc container) or whether CRaC-in-FC is the real shape and this backend should compose with the FC one.
2. **criu privileges vs the hardened worker model.** criu needs `CAP_CHECKPOINT_RESTORE` (or `CAP_SYS_ADMIN`); the worker model is `--cap-drop=ALL`. Resolve how the *restore* runs (the base/checkpoint side is operator-side; the restored worker should still be cap-dropped). gVisor restore had an analogous tension (the accept-retry shim) — expect similar.
3. **Where the checkpoint is taken.** Base-JVM warmup must run a representative `detonate` so the snapshot is actually warm (JIT/caches), not a cold boot — define the warmup input.
4. **Artifact size / RAM-preload.** FC's mem file dominates and supports a tmpfs RAM-preload toggle (`BLASTBOX_SNAPSHOT_MEM_TMPFS`). A CRaC image is heap+state; decide whether the same `/dev/shm` preload applies.

## Scope boundary

This doc is the Phase-3 **design**. The implementation lands on `feat/crac-snapshot-backend` as unit-mocked components (reviewable, CI-testable) and is **not wired into any deployed pool** until Phase 4 ground-truths it against redtusk. The honest dependency: CRaC's real correctness can only be proven with a real CRaC JVM workload, which is redtusk.
