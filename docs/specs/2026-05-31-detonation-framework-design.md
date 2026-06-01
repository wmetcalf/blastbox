# Detonation Framework — Design Spec

- **Status:** Draft for review
- **Date:** 2026-05-31
- **Working name:** `blastbox` (TBD — see Open Questions)
- **Authors:** Will Metcalf + Claude

## 1. Problem & goals

Two solo-owned services — **RedTusk** (Tika/JVM document *extraction*) and **ClippyShot**
(LibreOffice document→image *rasterization*) — independently process untrusted/malicious
documents in disposable sandboxed workers. They have **diverged from a common substrate**:
~11 near-identical infra modules (`api`, `cli`, `dispatcher`, `errors`, `jobs/*`, `limits`,
`observability/*`, `runtime/docker_runtime`, `sandbox/container`, `types`) maintained as
parallel, drifting copies — and each has grown advances the other lacks:

- RedTusk: warm pool (`pool.py`), Firecracker microVM + vsock (`worker_runtime.py`), schema validation.
- ClippyShot: host-native sandboxing (`sandbox/{bwrap,nsjail,detect}`) + a security-hardening pass (2026-05).

**Goals (all four explicitly in scope):**

1. **Cross-pollinate advances** — ClippyShot inherits warm-pool/Firecracker; RedTusk inherits host-native bwrap/nsjail + the hardening — without hand-porting each twice.
2. **Single audit/security surface** — the untrusted-input handling (dispatch, output-trust, runtime selection, sandbox) is hardened and audited once.
3. **Bootstrap new engines fast** — a 3rd/4th blastbox (PDF renderer, archive exploder, EML blastbox) gets ingress + orchestration + isolation for free.
4. **Cut duplication/maintenance** — one place to fix bugs and bump deps.

**Non-goals:** a standalone detonation *service/daemon* (no operational decoupling required); a
GUI; supporting non-detonation workloads.

**Approach:** greenfield the shared core (design top-down, best-of-both, unconstrained by either
project's accumulated quirks), then adopt it across the family. Greenfield-design is right; the
only failure mode — greenfield-that-never-gets-adopted, i.e. a *third* parallel copy — is
prevented by the single owner committing to adoption (Section 7).

## 2. Architecture

Three layers; the engine plugs into exactly one place. The host layer never imports the engine.

```
blastbox/                    ← shared, audited-once core
├── host/                     LAYER 1 — host orchestrator (engine-agnostic)
│   ├── ingress     FastAPI app + CLI: upload, job lifecycle, artifact serving, /metrics
│   ├── jobs        JobStore protocol + memory/sql/redis backends + retention
│   ├── dispatch    claim → select runtime/pool → launch worker → VALIDATE output → serve
│   ├── runtime     tiered selection: runc / runsc / firecracker (+ snapshot) + warm pool; fail-closed
│   ├── trust       output-trust validator (typed envelope: path-confinement, size caps, hash, input-SHA)
│   └── limits · observability · errors
│
├── worker/                   LAYER 2 — worker SDK (runs INSIDE the disposable worker)
│   ├── sandbox     container / bwrap / nsjail backends + seccomp/apparmor + in-proc hardening checks
│   ├── lifecycle   one-shot ("run argv to completion") AND service ("boot listener → 1 job → teardown")
│   ├── harness     entrypoint: read job → set up sandbox → call engine → write + self-validate metadata
│   └── protocol    warm-pool ready/job handshake (what makes a slot "warm")
│
├── contract/                 the typed data contract (shared by host, worker, and engines)
│   ├── envelope    fixed security-critical schema (artifacts, input, status, warnings)
│   └── nodes       typed node library (Page, EmbeddedResource, ExtractedText, Record, …)
│
└── (each project provides)   LAYER 3 — the Engine
```

Data flow (one job): ingress accepts upload → `jobs` records it → `dispatch` claims it, selects a
runtime+slot, launches a disposable worker → `worker/harness` sets up the sandbox and calls the
engine's `detonate()` → engine writes artifacts + a typed metadata document → harness self-validates
it → worker exits, container/VM destroyed → `dispatch` re-validates the envelope (output-trust) →
artifacts served. The input is deleted from the shared volume immediately after conversion.

## 3. The engine seam

The one thing each project writes:

```python
class Engine(Protocol):
    name: str
    formats: frozenset[str]                                   # for detection/rejection

    def detect(self, input: Path) -> Detection: ...           # optional; type detection/reject
    def warmup(self) -> None: ...                             # optional; bring engine to "ready"
                                                              #   BEFORE any input exists
    def detonate(self, input: Path, outdir: Path,
                 limits: Limits) -> Metadata: ...             # the work: produce artifacts + typed metadata
```

- **`detonate()`** is the work. ClippyShot's engine = LibreOffice → pdftoppm → hash/qr/ocr → page
  metadata. RedTusk's engine = Tika extract (a thin Python shim that execs `java` against the
  contract, or a small worker-SDK port in Java).
- **`warmup()`** (optional) brings the engine to a ready state in a pristine, no-input context, so
  whatever it produces is safe to capture. This is the single hook the warm-pool / FC-snapshot
  machinery uses (Section 5). For ClippyShot, `warmup()` = boot soffice + start the UNO listener
  (validated by the spike, Appendix A). For RedTusk it = load Tika / CRaC-restore.
- **`detect()`** (optional) lets an engine reject inputs it won't render before the sandbox spins up.

**Division of labor (envelope vs payload).** `detonate()` writes artifact files to `outdir` and
returns a `Metadata` carrying (a) the typed payload tree and (b) a *declared* artifact set — each
with a stable `id`, an `outdir`-relative `path`, and a `kind`. The worker SDK then **seals** that
into the Envelope: it stats each declared file (computing `sha256` and `bytes`), confirms existence
and path-confinement, verifies every `ArtifactRef` in the payload resolves to a declared artifact,
and self-validates the whole against the contract before emitting. `host/trust` re-validates the
sealed envelope. So the engine never computes hashes or handles paths defensively — all
file/path/size/hash handling lives in the audited SDK and host, not in engine code.

The host orchestrator depends only on the **contract** (Section 4), never on an engine module.

## 4. The typed data contract

Two tiers: a **fixed security envelope** the framework validates identically for every engine, and a
**typed payload tree** built from a shared node library that ranges from fully-generic to
fully-specific.

### 4.1 Envelope (framework-owned, fixed, security-critical)

```
Envelope = {
  engine: str,
  status: "ok" | "rejected" | "engine_error",
  input:  { sha256, detected: Detection },
  artifacts: [ { id, path, kind, sha256, bytes } ],   # every file the worker wrote
  warnings:  [ Warning ],
  payload:   Node,                                     # typed tree (4.2)
}
```

`host/trust` enforces on the envelope, for every engine: each `artifact.path` confined under the
output dir (no `..`/absolute/symlink), `bytes` ≤ cap, `sha256` well-formed, total artifact
count/size bounded, `input.sha256` matches what was sent (RedTusk's round-trip integrity check),
and `metadata.json` itself is a regular file (reject symlink/FIFO). This is the audit-once surface.

### 4.2 Typed node library (the payload)

The payload is a **typed tree** of nodes from a shared library. Every node carries a `type`
discriminator; the library is a ladder from generic to specific; an engine climbs only as high as it
needs.

```
Leaf types (shared vocabulary, self-validating):
  Hash · Detection · Warning · ArtifactRef · Dimensions · Lang …

Composite types (reusable, recursive):
  ExtractedText    { text, char_count, lang }
  Page             { index, dims, image: ArtifactRef, hashes[], children[] }
  EmbeddedResource { embedded_path, content_type, depth, metadata: Record, children[] }
  Record           { fields: dict[str, Scalar | list | Record] }   # the GENERIC floor

Engine specializations (optional ceiling):
  ClippyShotPage(Page) { qr: list[QRCode], ocr: OcrResult }
```

`children[]` is a **recursive discriminated union** —
`Page | EmbeddedResource | ExtractedText | Record | <registered engine type>` — so one backbone
models ClippyShot's flat pages, Tika's recursive embedded-doc tree, and a future archive-exploder's
nested entries, uniformly.

**The spectrum, three real altitudes:**

- *Specific (ClippyShot):* `ClippyShotPage` — precise, fully-typed qr/ocr.
- *Middle (Tika):* `EmbeddedResource` — typed `content_type`/`depth`/`children`, with Tika's long
  tail of metadata keys in a generic `Record`. Typed where it matters, generic where it's a bag.
- *Generic (anything new):* pure `Record` trees — ship a new engine today with zero new types;
  promote to named types later once patterns emerge.

**Properties this buys:**

1. **Single source of truth for shape.** Validators, size caps, hash regex, and `ArtifactRef`
   path-confinement live *on the types* — audited once; the worker SDK self-validates on emit and
   `host/trust` re-validates.
2. **Cross-engine consumers for free.** Because `Page`/`ExtractedText`/`EmbeddedResource` are
   *shared*, the framework can offer generic walkers ("give me every `ExtractedText`" / "every
   `Page`") that work on any engine's output without knowing the engine. The framework understands
   the *shared vocabulary*; it treats an engine subclass as its base type (or opaque-beyond-base) —
   so `give-me-all-pages` finds a `ClippyShotPage` without knowing what it adds.
3. **Artifact-by-reference.** The payload never inlines file bytes or paths; it references envelope
   artifacts by `id` (`image: ArtifactRef("a5")`). All file/path/size/hash handling stays in the
   framework's audited `host/trust`; the engine payload carries structure and references only.

### 4.3 Across the language seam

The node library (pydantic) is canonical and emits a JSON Schema. ClippyShot's Python engine
constructs the types directly; RedTusk's JVM worker emits conforming JSON (Tika's rmeta →
`EmbeddedResource` trees) which the worker SDK / host validate against the types. "Typed" holds even
when the engine isn't Python. RedTusk's existing `schema.py` generalizes into this library.

## 5. Runtime & pool

### 5.1 Slot abstraction (warm + cold)

A **slot** is the unit the pool manages. Every slot is strictly **one untrusted doc then destroyed**
(warm ≠ reuse). Two populations:

| Population | What it is | Cost paid | When |
|---|---|---|---|
| **Warm pool** | pre-booted slot, engine at "ready" (`warmup()` done), blocked waiting for a job | startup pre-paid in background | steady state — claim is instant |
| **Cold / burst** | slot spawned on demand when warm is exhausted | startup on the job's critical path | load spikes beyond warm capacity |

Knobs (proven in RedTusk): `warm_size`, `concurrent_ceiling`,
`burst_size`/`burst_trigger_s`/`burst_drain_s`, spawn rate-limit + backoff, health-check eviction.
The dispatcher claims a warm slot if IDLE; else spawns cold (counts against the ceiling); burst
lifts the effective warm target under sustained queue depth, then drains. The "cold pool" is the
burst/overflow path — same lifecycle, startup-on-critical-path.

**Why the pool matters (empirical):** RedTusk's data shows a cold per-job model *saturates* under
batch load (gVisor pool_wait p50 = 61 s on a 932-file corpus); a warm pool took it to 291 ms and
wall time ~2.3× lower. The pool is what keeps slots available — the dominant win is throughput/queue
depth, not single-job latency.

### 5.2 Runtime tiers × warmth, and `warmup()` capture

What "warm" *means* is engine-defined (`warmup()`); how warm state is *captured* is framework-defined:

| Runtime | Cold slot | Warm slot | Per-job isolation |
|---|---|---|---|
| **runc** | spawn container | boot container, `warmup()`, block-and-wait | namespaces (weakest) |
| **runsc (gVisor)** | spawn container | boot + `warmup()` + block | syscall interposition |
| **FC cold-boot** | full KVM boot (~1 s) + `warmup()` | boot + `warmup()` + block (RedTusk's current, via CRaC) | fresh VM, hardware |
| **FC snapshot** | — | boot once → `warmup()` → **FC snapshot**; restore per job (~125 ms) | fresh VM per restore, hardware |

**FC snapshotting** is the premium tier and is engine-agnostic: boot a microVM, call `warmup()`
(pristine, no input), snapshot, then restore a fresh copy per job, feed one doc, discard. The
expensive boot + warmup is paid **once at snapshot-build time**; each job restores in ~125 ms. This
is the cleanest way to hide an unavoidable engine-boot cost, and more memory-efficient than holding N
live warm processes resident (one snapshot file + restore-on-demand). It is the primitive RedTusk
left aspirational, and it is **ClippyShot's best warm-start path** because soffice has no CRaC
equivalent (Appendix A).

Isolation invariants for warm tiers: the snapshot/warm state is captured **before any input**, so no
contamination; each job gets a pristine warm slot, runs exactly one doc, is destroyed. Caveats the
framework owns: rebuild the snapshot/flush the warm pool when the engine image changes (RedTusk's
"restart to flush stale warm containers"); reseed guest entropy on restore (FC handles this).

### 5.3 Runtime selection

`runtime` selects the best available tier and **fails closed** when a secure tier is required but
unavailable (ClippyShot's `REQUIRE_SECURE_RUNTIME` posture; RedTusk's `ALLOW_INSECURE_RUNC`
override). Auto-detect prefers stronger isolation (FC > runsc > runc) but a missing stronger tier is
a loud, explicit decision, never a silent downgrade.

## 6. Security model

- **One untrusted doc per disposable slot.** Never reuse a worker/server across docs. Warm pools and
  snapshots are *pre-warming*, not sharing — the warm state is captured before any input exists.
- **Output is untrusted.** `host/trust` validates the envelope (Section 4.1) before persisting:
  path-confinement, size caps, hash well-formedness, input-SHA round-trip, regular-file metadata.
  The worker SDK self-validates against the typed contract before emitting (defense in depth).
- **Sandbox service-lifecycle.** `worker/lifecycle` must support BOTH "run argv to completion" (cold
  engines) AND "boot a service, accept one job, tear down" (warm engines, e.g. soffice UNO listener).
  The warm path adds a local IPC socket (UDS/loopback only — never a routable interface) crossing the
  sandbox boundary; the seccomp/cap/NoNewPrivs posture is otherwise unchanged. This requirement comes
  directly from the warm-UNO spike (Appendix A).
- **Best-of-both isolation.** `worker/sandbox` merges RedTusk's container/FC with ClippyShot's
  bwrap/nsjail/detect + the 2026-05 hardening (bounded extraction, XXE-safe XML, seccomp
  socket/personality/setpgid fixes, scanner-arg validation, Limits bounds, fail-closed runtime).
- **No engine creds in the worker** beyond what the job needs; dispatcher holds the Docker/KVM
  privilege; worker has no DB credentials.

## 7. Adoption plan

ClippyShot is the first consumer (smaller, just hardened, lower blast radius). No big-bang rewrite —
each step is behind the engine seam, and the existing service keeps working until parity is proven.

1. **Build the greenfield core** (`host/` + `worker/` + `contract/`) against a trivial no-op engine
   with tests. Validate the orchestrator + worker SDK + output-trust independently of any real engine.
2. **Wrap ClippyShot as `ClippyShotEngine.detonate()`** — initially the engine just calls the
   existing `Converter.convert()` and emits the typed `Metadata`. Minimal change; proves the seam
   against real complexity without rewriting engine internals.
3. **Run ClippyShot on the framework** — replace its dispatcher/jobstore/runtime/sandbox with the
   framework's. Parity-test against today's ClippyShot (same artifacts, equivalent metadata).
4. **Light up the new tiers** — add `ClippyShotEngine.warmup()` (soffice UNO listener, behind a
   flag) + the warm pool + FC. This is the first concrete cross-pollination payoff.
5. **Port RedTusk second** — Tika engine the same way; RedTusk gains host-native bwrap/nsjail + the
   hardening; the framework's pool/FC/contract are *donated by* RedTusk, so this is largely a
   re-homing.

**Donor mapping:** framework `runtime`/pool ← RedTusk `pool.py`/`worker_runtime.py`; framework
`worker/sandbox` + seccomp/apparmor ← ClippyShot `sandbox/*` + 2026-05 hardening; framework
`host/trust` ← both dispatchers' validators merged; framework `contract` ← RedTusk `schema.py`
generalized into the typed node library.

## 8. Testing

- **Contract:** property tests on the typed nodes (round-trip, validators, ArtifactRef confinement,
  recursive-union (de)serialization); golden envelopes for ClippyShot-simple and Tika-complex.
- **Output-trust:** adversarial worker outputs (traversal, symlink/FIFO metadata, oversized
  artifacts, bad hashes, input-SHA mismatch) must all be rejected.
- **Worker lifecycle:** both one-shot and service modes across all sandbox backends; warm-slot
  handshake; teardown guarantees (no soffice/JVM survives a job).
- **Runtime/pool:** warm/cold claim, burst lift/drain, health-check eviction, fail-closed runtime
  selection, FC snapshot build/restore parity (restored VM produces identical output to cold boot).
- **Engine parity:** ClippyShot-on-framework vs current ClippyShot produces equivalent metadata +
  byte-identical artifacts across the safe-fixture corpus (run in the LO-25.8 image).
- Integration suites run in the engine's Docker image (per existing convention).

## 9. Open questions

- **Name.** `blastbox` is a placeholder. Alternatives welcome.
- **FC snapshot effort.** Snapshot/restore is unimplemented in RedTusk (it cold-boots + CRaC-restores).
  Building the snapshot tier is net-new work; scope it as a distinct milestone after the core lands.
- **Container-init overlap (decides warm-LO value).** The warm-UNO win is ~4–7× *only if* the
  unavoidable ~750 ms soffice boot is hidden behind container/job provisioning. Measure how much of
  current per-container startup already overlaps soffice boot before committing to ClippyShot's warm
  path. (Follow-up task.)
- **Impress/Draw output parity.** The spike validated writer/calc pixel-identical output; pptx/odp/odg
  were untestable on host LO 24.2 (blank render). Confirm on the LO-25.8 `clippyshot:audit` image
  before shipping warm-UNO.
- **`unoserver` vs raw python-uno.** `unoserver` is a viable off-the-shelf warm-LO path
  (`--user-installation`, `--output-filter`, `--filter-option SinglePageSheets=true`,
  `--stop-after 1`); its supervised-subprocess model must coexist with the sandbox backends. Decide
  during ClippyShot warm-path implementation.

## Appendix A — Warm-UNO spike result (2026-05-31)

Empirical backing for the ClippyShot `warmup()` design and the worker service-lifecycle requirement.

- **Output compatibility (the make-or-break question): proven identical.** Warm UNO `storeToURL`
  with the cold path's filters (`writer_pdf_Export`, `calc_pdf_Export` + `FilterData{SinglePageSheets
  =true}`) produces **pixel-perfect and byte-identical** output vs cold `--convert-to`
  (`MSE=0, diff_px=0, phash_dist=0`) across docx/odt/csv/**xlsx**. The spreadsheet — the predicted
  divergence point — did not diverge. PDFs byte-equal except `/CreationDate`+`/ID` (rasterized away).
- **Speed:** soffice boot ~750 ms is **unavoidable** (same for `--convert-to` and `--accept`).
  Steady-state convert is 24–40 ms (~30×) but requires reuse → forbidden by isolation. Realistic win
  in the one-doc-per-slot model: **~4–7× on the soffice stage, only if the ~750 ms boot is hidden**
  (warm pool / FC snapshot). Naive boot-then-convert-then-die ≈ no win.
- **Isolation:** compatible only as pre-warming, never sharing; one server per disposable slot, one
  doc, torn down with the slot. The URP `--accept` socket is new attack surface — bind loopback/UDS
  only.
- **Integration cost:** ~250–450 LOC. Pre-load logic (MHT/altChunk/xlsx-patch/two-pass/sheet-capture)
  ports as-is. New: a UNO client (~150–250 LOC). The wrinkle: ClippyShot's `Sandbox` protocol is
  one-shot; a warm server needs the service lifecycle (Section 6) across all backends — the bulk of
  the work, and now a first-class framework requirement.
- **`unoserver` v3.6** reproduces the cold output identically and ships the needed lifecycle flags.
