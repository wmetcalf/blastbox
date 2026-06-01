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
│   ├── runtime/    runc/runsc selection (fail-closed) + hardened worker `docker run` argv
│   ├── pool        warm slot pool (one-doc-per-slot, never-reuse)
│   ├── trust       output-trust validator — re-seals worker output from disk
│   └── observability
└── worker/     LAYER 2 — worker SDK (runs inside the disposable worker) — lean core
    ├── engine      the seam: detect / warmup / detonate
    ├── harness     read input → detonate → seal → write metadata.json
    ├── sandbox/    in-process hardening self-check + env-stripped subprocess execution
    └── warm        service lifecycle: boot → warmup → one job → exit
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
(harness, container sandbox, warm protocol) + warm pool + warm dispatch. Proven end-to-end on two real
engines.

Roadmap: host-native `bwrap`/`nsjail` sandbox backends; Firecracker microVM + snapshot runtime; the
warm-pool burst/health loops.

## License

MIT.
