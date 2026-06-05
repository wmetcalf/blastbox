# blastbox

**A reusable framework for running untrusted/malicious documents through disposable, hardened
workers** — and turning their output into a typed, host-validated result you can trust.

Extracted from the common substrate of two production services (a LibreOffice document→image
rasterizer and a Tika recursive-extraction service) that had each grown a parallel, drifting copy of
the same machinery. blastbox is the single, audited-once core; each service becomes a thin *engine*.

- **Write one function.** An engine implements `detonate(input, outdir, limits) -> DetonationResult`.
  The framework gives it ingress, a JobStore, a disposable hardened worker per job, output-trust
  validation, artifact serving, optional warm pooling, metrics, and a CLI — for free.
- **Output is never trusted.** A worker processes a malicious document; the host **re-seals its
  output from disk** (recomputing hashes/sizes, confining paths) before believing a byte of it.
- **One untrusted doc per disposable slot** — always. Warm pooling pre-pays startup in the
  background; it never reuses a worker across documents.
- **Typed, engine-shaped output.** A shared node library (`Page`, `EmbeddedResource`, `ExtractedText`,
  a generic `Record` floor, recursive) lets engines be as specific or generic as they need, while the
  framework validates a fixed security envelope identically for everyone.

Proven end-to-end against two real, language-diverse engines: a **Python + LibreOffice** rasterizer
and a **JVM + Tika** recursive extractor.

## Architecture

```
blastbox/
├── contract/   typed node tree + security envelope + seal/validate (registry-aware at any depth)
├── host/       LAYER 1 — host orchestrator (engine-agnostic) — needs blastbox[host]
│   ├── ingress     FastAPI API + CLI: upload, status, artifact serving, /metrics
│   ├── jobs/       JobStore protocol + memory / sql / redis backends + retention
│   ├── dispatch    claim → launch disposable worker → validate output → serve   (+ warm path)
│   ├── runtime/    backend select (fail-closed): hardened `docker run` (runc/runsc)
│   │               OR a Firecracker microVM per slot (AF_VSOCK warm protocol; the
│   │               engine defines warmup — a JVM engine via CRaC, with guest-console
│   │               CPU-feature-mismatch detect + a probe; a non-JVM engine without)
│   ├── pool        warm slot pool (one-doc-per-slot, never-reuse; burst + health loops)
│   ├── trust       output-trust validator — re-seals worker output from disk
│   └── observability
└── worker/     LAYER 2 — worker SDK (runs inside the disposable worker) — lean core
    ├── engine      the seam: detect / warmup / detonate
    ├── harness     read input → detonate → seal → write metadata.json
    ├── sandbox/    auto-selected in-process hardening: nsjail / bwrap / nono / container
    │               (BLASTBOX_SANDBOX override; container inside OCI; nono = Landlock, no userns)
    ├── warm        service lifecycle: boot → warmup → one job → exit
    └── fc_warm / fc_guest   Firecracker guest: AF_VSOCK control plane + warm protocol
```

The host never imports an engine; it depends only on the **contract**. An engine never handles
hashes/paths defensively; the worker SDK and host do that in audited code.

## Writing an engine

```python
from pathlib import Path
from blastbox import Engine, DetonationResult, run_detonation
from blastbox.contract import Page, DeclaredArtifact, Detection, ArtifactRef, Dimensions
from blastbox.limits import Limits

class MyEngine:
    name = "myengine"
    formats = frozenset({"pdf"})

    def detonate(self, input: Path, outdir: Path, limits: Limits) -> DetonationResult:
        # ... render/extract; write artifact files into outdir ...
        (outdir / "page-001.png").write_bytes(png_bytes)
        return DetonationResult(
            payload=Page(index=0, dims=Dimensions(width=210, height=297, unit="mm"),
                         image=ArtifactRef(id="p0")),
            artifacts=[DeclaredArtifact(id="p0", path="page-001.png", kind="image")],
            detected=Detection(label="pdf", mime="application/pdf", confidence=1.0, source="myengine"),
        )

# worker entrypoint:
if __name__ == "__main__":
    import sys
    from blastbox.worker.harness import main
    sys.exit(main(MyEngine()))
```

The harness seals your declared artifacts (recomputing sha256/size from disk, confining paths,
resolving references) and writes `metadata.json`. The host's `validate_worker_output` re-validates it.
Complex engines build recursive `EmbeddedResource` trees (e.g. Tika's recursive metadata); simple
ones use `Page`/`Record`. Engine-specific node subtypes register via `contract.register_node_type`.

## Install

```sh
pip install blastbox           # lean core — everything an ENGINE needs (pydantic only)
pip install blastbox[host]     # + the host orchestrator (FastAPI, jobstores, observability)
```

## Run (host)

```sh
blastbox serve     --host 127.0.0.1 --port 8000     # the ingress API
blastbox dispatch                                    # the worker dispatcher loop
```

`POST /v1/jobs` (multipart `file` + `engine`) enqueues a job; the dispatcher launches a hardened
disposable worker for it; `GET /v1/jobs/{id}/artifacts/{artifact_id}` serves validated output.

## Security model

- Disposable worker per job: `--network=none --cap-drop=ALL --no-new-privileges --read-only`, runsc
  preferred (fail-closed when a secure runtime is required); the input is deleted after conversion.
- The host re-seals worker output from disk — worker-reported hashes/sizes are never trusted; artifact
  paths are confined; the input-SHA round-trip is checked; `metadata.json` must be a regular file.
- Ingress rejects oversized bodies before spooling, sanitizes filenames, serves artifacts by id under
  a confined path, and (optionally) sits behind a bearer token / auth proxy.
- The contract bounds payload size/depth and validates every node; engine subtypes are validated
  against their registered schema.

## Status

Core framework complete and adversarially tested: contract + full host orchestrator + worker SDK
(harness, sandbox self-check, warm protocol) + warm pool (burst + health loops) + warm dispatch.

**Two runtime backends**, selected fail-closed: hardened `docker run` (runc/runsc) and a **Firecracker
microVM per slot** (AF_VSOCK warm protocol — *the engine* defines what "warmup" means, so the tier is
engine-agnostic). **Four in-process sandbox backends**, auto-selected (`nsjail` → `bwrap` → `nono` →
`container`; `container` inside an OCI host) with a `BLASTBOX_SANDBOX` override. `nono` is a **Landlock**
capability sandbox — filesystem + network containment **without user namespaces**, for hosts where
`bwrap`/`nsjail` can't run (restricted-userns / no `CAP_SYS_ADMIN`); it's `secure=False` (no
seccomp/namespaces) and so an explicit opt-in, at ~1–4 % per-job overhead.

Warmup is per-engine: the **JVM/Tika** engine warms via **CRaC** (checkpoint/restore), and for that path
the Firecracker runtime adds guest-console **CPU-feature-mismatch detection** + a one-shot compatibility
**probe**. The **LibreOffice**
engine has **no CRaC** (it isn't a JVM): instead its ~750 ms `soffice` boot is hidden by the **warm-UNO
FC snapshot/restore** tier (below), or it falls back to cold-starting `soffice --convert-to` per job.

Proven end-to-end — live on a Firecracker host — with two real, language-diverse engines, both in the
**FC warm-pool tier**: a **JVM + Tika** recursive extractor (CRaC warm-restore) and a **Python +
LibreOffice** rasterizer (warm-UNO snapshot/restore, or cold-boot; `deploy/firecracker/Dockerfile.clippyshot`).
The LibreOffice engine also runs standalone on the **docker + sandbox** tier (runc/runsc).

**Warm-UNO via FC snapshot/restore — shipped.** A microVM with a running, idle in-guest `unoserver`
(soffice `--accept` on a local UDS) is captured in a Firecracker memory snapshot built *first-boot on the
host*, then restored→converted→destroyed per job — the "FC but not CRaC" warm route that hides the
~750 ms soffice boot. Validated end-to-end on a Firecracker host: snapshot a live `unoserver` → restore
from `/dev/shm` → convert → output is **pixel-identical to cold** `--convert-to` across calc/csv **and
impress/draw** (pptx / odp / ppt / odg). Measured: a warm restore (~0.5 s; the FC `load-snapshot`
primitive itself is ~4 ms) replaces a ~7.8 s cold boot+warmup — **~13.5× to a ready slot** — with the
copy-on-write mem base optionally **pinned in RAM** (`BLASTBOX_SNAPSHOT_MEM_TMPFS`, a per-host toggle).
Everything UNO stays in-guest; only the existing vsock + output-disk channels cross the boundary. Gated
opt-in: `BLASTBOX_POOL_RUNTIME=firecracker` + `BLASTBOX_POOL_WARM_SNAPSHOT=1`; bare-metal
`bwrap`/`nsjail`/`nono` stays cold. Implemented in `host/runtime/fc_snapshot*.py`
(`SnapshotManager` + `SnapshotSlotRuntime`); design:
`docs/specs/2026-06-03-warm-uno-fc-snapshot-design.md`.

**Benchmarking — `blastbox bench`.** A runtime-agnostic perf harness (stats + percentiles + A/B
comparisons) with a scenario registry that skips cleanly when prerequisites are absent, plus a
`perf`-marked CI ratio gate. `blastbox bench --list`; scenarios include `sandbox.overhead` (nono vs
bwrap vs none), `snapshot.restore-latency`, and `convert.latency`. Design:
`docs/specs/2026-06-04-blastbox-bench-design.md`.

## License

MIT.
