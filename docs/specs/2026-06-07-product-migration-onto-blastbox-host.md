# Migrate redtusk + ClippyShot onto blastbox.host — Design

**Status:** DRAFT for owner approval. No code until approved.
**Date:** 2026-06-07

## Goal

Make redtusk and ClippyShot *run on* `blastbox.host` (the reusable orchestrator) instead of each shipping its own bespoke host. Today both import blastbox only for contract types — the duplication map found **~9,100 LOC of host/orchestration reimplemented across the two** (~5,387 redtusk + ~3,713 ClippyShot) that `blastbox.host` already provides in ~7,779 LOC. This collapses three orchestrators (and two Firecracker stacks) into one.

Two framework capabilities must be generalized to make that possible without losing product behavior:
1. an **extensible ingress** so product-specific routes survive, and
2. **CRaC as a first-class `SnapshotBackend`** for redtusk's JVM warm tier (and future Java projects).

## Decisions locked (owner, 2026-06-07)

- **Sequence:** ClippyShot first as a cheap end-to-end proof, then CRaC + redtusk.
- **Ingress:** an extension seam in `host.ingress` (products register their own routers on the shared core) — not a lossy core + side-app.
- **Cut-over:** build the blastbox.host stack *alongside* the existing one, run the 342-corpus through both, retire the bespoke host **only on parity**. The deployed systems keep working until proven.

## What blastbox.host already provides (verified)

- **Engine seam** — `blastbox.worker.engine.Engine` Protocol (`worker/engine.py:52`): `detonate(input, outdir, limits) -> DetonationResult`, `detect(input) -> Detection`, `warmup() -> None`. A product's real IP is the engine body; everything else is the duplicated host.
- **Dispatch** — `host.dispatch.Dispatcher(*, job_store, engines: Mapping[str, EngineSpec], limits, job_root, runtime_selector=select_worker_runtime, pool=None, …)` (`dispatch.py:88`). `EngineSpec(name, image, worker_argv)` is **operator-configured; image never derived from job data** (`dispatch.py:74`).
- **Ingress** — `host.ingress.build_app(*, allowed_engines, …)` (`ingress/app.py:149`). Routes (`/v1/jobs` submit/list/status, `/v1/jobs/{id}/artifacts/{artifact_id}`, metadata/result, health/ready/version/metrics) are defined **inline** — **no extension seam exists yet**.
- **Job store** — `host.jobs.factory.build_job_store_from_env` (memory / redis / sql; all three backends).
- **Runtime** — `host.runtime.docker.select_worker_runtime` + argv builder (runsc/runc cold path); `host.runtime.firecracker.FirecrackerSlotRuntime` + `rdump_ext4` (FC microVM); warm tiers via the snapshot seam.
- **Snapshot seam** — `host.runtime.snapshot_backend`: `SnapshotBackend.available()/boot_base()->BootHandle/restore_in(workdir, artifact)->RestoreHandle`; `BootHandle.wait_ready/checkpoint(dest)->opaque artifact/kill`. Existing backends: FC mem-snapshot, gVisor C/R.
- **CLI** — `blastbox serve` (ingress) + `blastbox dispatch` (loop) (`host/cli.py:141,152`).
- **Trust gate** — `host.trust.validate_worker_output` (O_NOFOLLOW TOCTOU-safe fd reads + `seal_envelope` re-hash). Strictly stronger than either product's hand-rolled check.

## New framework work

### A. Ingress extension seam (`host.ingress`)

`build_app` gains an extension hook so a product mounts its own routes on the shared core without forking the ingress:

```python
# host/ingress/extension.py  (new)
@dataclass(frozen=True)
class IngressExtension:
    """Operator-provided product routes mounted on the shared ingress."""
    routers: list[APIRouter]            # extra FastAPI routers (product routes)
    # optional hooks, added only if a product needs them:
    # on_startup / on_shutdown callables

def build_app(*, allowed_engines, extension: IngressExtension | None = None, …):
    app = FastAPI(...)
    # ... existing shared routes ...
    if extension:
        for r in extension.routers:
            app.include_router(r)
    return app
```

- Shared core (submit/status/artifacts/auth/health/metrics) stays in `build_app`, owned by blastbox.
- Product routes become product-owned `APIRouter`s injected at `serve` wiring time.
- The artifact-serving path-confinement (`resolve()+relative_to`) stays in the core; product routes that serve derived artifacts (PNG variants) reuse the core's confined-read helper (exported for that purpose).
- **Auth/limits/traversal guards are NOT delegated to product routers** — the core applies them; product routers inherit the app's middleware.

**Covers:** ClippyShot's Tika-compat (`/tika`,`/rmeta`) + typed-PNG routes (`/pdf`,`/trimmed`,`/focused`,`/page`); redtusk's infected-zip (`/v1/jobs/{id}/artifacts/zip`, pyzipper AES, pw `infected`).

### B. CRaC `SnapshotBackend` (`host.runtime.crac_snapshot`)

A third backend implementing the existing seam — no manager changes (`SnapshotManager` is backend-agnostic):

```python
class CracSnapshotBackend:                      # SnapshotBackend
    def available(self) -> bool:                # CRaC-capable JVM + criu present
    def boot_base(self) -> BootHandle:          # launch base JVM worker (Java engine), warm it
class CracBootHandle:                           # BootHandle
    def wait_ready(self, timeout_s): ...        # engine signals warm-idle
    def checkpoint(self, dest_dir) -> object:   # jcmd JDK.checkpoint / criu -> opaque artifact (checkpoint dir)
    def kill(self): ...
class CracRestoreHandle:                         # RestoreHandle + I/O accessors
    def kill(self): ...
```

- Models on the existing FC/gVisor backends; the opaque artifact is the CRaC checkpoint dir.
- Selected via the same pool-runtime switch used for FC/gVisor; `available()` fail-closed.
- redtusk's current CRaC lives in the worker *image* (`redtusk-worker:crac-vsock`) + FC restore — this backend lifts the orchestration of it into blastbox so any Java engine reuses it.

### C. No change needed

`EngineSpec`/`Dispatcher`/`serve`/`dispatch`/job-store factory/runtime selection are sufficient as-is. ClippyShot's FC engine adapter already exists (`deploy/firecracker/clippyshot_engine.py`, 362 LOC).

## Migration approach (per product)

**Build-alongside → corpus-compare → cut-over-on-parity:**
1. Stand up the new stack (`blastbox serve` + `blastbox dispatch` with the product `EngineSpec` + extension routers) **next to** the existing one, different port/job-root.
2. Run the **342-doc corpus** through both. Compare success counts AND per-doc outcomes against the bespoke baseline (ClippyShot 277/342 fixed-config; redtusk 342/342 FC, 340/342 gVisor).
3. Only on parity: repoint the deployment, then **delete** the product's bespoke host.
4. Each phase is a branch + PR, gated on the corpus + the existing unit suites staying green.

## Phases (corpus-gated)

| # | Phase | Repo | Gate |
|---|---|---|---|
| 1 | Ingress extension seam (A) | blastbox | unit tests; existing ingress tests stay green |
| 2 | **ClippyShot proof**: worker image (runsc) w/ engine adapter + `EngineSpec` + serve/dispatch wiring + extension routers; build alongside | clippyshot + blastbox | 342-corpus parity vs ClippyShot bespoke (≥277/342, same per-doc); then delete `clippyshot/{dispatcher,worker,jobs,runtime}.py` |
| 3 | CRaC `SnapshotBackend` (B) | blastbox | unit + a real CRaC checkpoint/restore integration test |
| 4 | **redtusk**: engine adapter + worker image (FC + runsc + CRaC) + wiring; build alongside on toolz2; unwind vendored `fc_cpu_features.py` | redtusk + blastbox | 342-corpus parity on toolz2 (FC 342/342, gVisor 340/342); then delete redtusk's bespoke host |

## Per-product delete / add (from the map)

**ClippyShot — delete ~3,713 LOC:** `api.py` (host routes → core + extension router), `dispatcher.py`, `jobs/{base,memory,redis_store,sql_store,retention}.py`, `runtime/docker_runtime.py`, the dispatcher metadata re-check (→ `host.trust`). **Keep:** `engine.py` (ClippyShotEngine) + LO/rasterizer/scanner pipeline + `sandbox/` (worker-side). **Add:** `EngineSpec` + serve/dispatch wiring + a `clippyshot` `APIRouter` for the Tika/PNG routes. Adapter already exists.

**redtusk — delete ~5,387 LOC:** `api.py`, `dispatcher.py`, `jobs/*`, `worker_runtime.py` + `sandbox/vsock_server.py` (FC stack → `host.runtime.firecracker`), `runtime/docker_runtime.py`, `sandbox/container.py`, `pool.py`, `jobs/retention.py`, orchestration half of `limits.py`, **and the vendored `fc_cpu_features.py`**. **Add:** a `RedTuskEngine` adapter (wrap Tika/XLM/CHM detonation), an infected-zip `APIRouter`, and CRaC wiring behind the Phase-3 backend.

## Parity gaps & handling

- **Product routes** (Tika/PNG/infected-zip) → the Phase-1 extension seam. Preserved, not lost.
- **redis**: redtusk lacks it, blastbox.host has it — a *gain*; validate no behavior change for sqlite/postgres paths.
- **Throughput**: unmeasured whether blastbox.host dispatch matches the products' current rates (redtusk FC ~2.5× gVisor, pool=8 optimum). The corpus-compare in each phase measures wall-time too; if blastbox.host regresses throughput materially, that's a blocker to surface, not silently accept.
- **warmup() parity**: ClippyShot's warm-UNO claims pixel/byte-identical; must hold when driven by blastbox's `WarmPool` rather than ClippyShot's single-server `warmup()`. Verified in Phase 2 by hash-comparing warm vs cold output.

## Risks / unknowns

- CRaC under blastbox's pool is **new integration** (third backend); Phase 3 needs a real checkpoint/restore test, not just unit mocks.
- redtusk is **live on toolz2**; the build-alongside discipline (different port/job-root) is what keeps it serving during Phase 4.
- The ingress core may have product-specific assumptions baked in that surface only when a second product mounts routes — Phase 1 adds a test that mounts a dummy router to lock the seam.
- Worker images: ClippyShot's runsc worker image needs blastbox + the adapter (a slimmer `Dockerfile.clippyshot` without the FC bits); redtusk's needs blastbox + a redtusk adapter + the CRaC JVM.

## Out of scope (for now)

- Retiring per-product `limits.py` entirely (keep product env prefixes; only the orchestration tunables move to `Limits.from_env`).
- Any change to engine bodies (LO/Tika conversion logic) — only the host around them moves.
