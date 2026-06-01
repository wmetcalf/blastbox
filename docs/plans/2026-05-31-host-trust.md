# Host Orchestrator — Output-Trust Slice

**Goal:** `blastbox.host.trust` — the single function the dispatcher calls to turn an untrusted
worker's `metadata.json` + output dir into a host-trusted `Envelope`, or reject it.

**Architecture:** The worker (which processed a malicious document) is untrusted; its output must be
re-derived from disk, never believed. This layer reads the worker's `metadata.json`, parses the typed
structure via `blastbox.contract`, then **re-seals from disk** (so worker-reported hashes/sizes are
discarded and recomputed), enforces the `Limits` caps, and confirms the input-SHA round-trip. One
public function; no I/O beyond reading the bounded metadata + stat/hash of declared artifacts.

**Tech Stack:** Python 3.12+, `blastbox.contract`, `blastbox.limits`, pytest.

## File structure
- `src/blastbox/host/trust.py`
- `tests/host/test_trust.py`

## Public API
```python
class OutputTrustError(BlastboxError): ...   # from blastbox.errors

def validate_worker_output(
    *, output_dir: Path, input_sha256: str, engine: str, limits: Limits,
) -> Envelope:
    """Read + validate a worker's output. Returns a host-trusted Envelope or raises OutputTrustError."""
```

## The flow (each step rejects on violation, raising OutputTrustError)
1. **metadata path safety.** `meta = output_dir / "metadata.json"`. Reject if it does not exist, is
   not a *regular file* (`meta.is_file()` and `not meta.is_symlink()` — a symlink/FIFO is refused so a
   compromised worker can't point it at `/etc/...` or hang the host on a FIFO), or `meta.stat().st_size
   > limits.max_metadata_bytes`.
2. **parse.** `raw = meta.read_bytes()`; `parsed = envelope_from_json(raw, max_bytes=limits.max_metadata_bytes)`
   (the contract validates the typed payload tree + bounds). On `ValueError`/contract errors → reject.
3. **engine match.** `parsed.engine == engine` (the worker must be the engine we dispatched) → else reject.
4. **RE-SEAL from disk (do not trust worker-reported hashes/sizes).** Convert each `parsed.artifacts[i]`
   to a `DeclaredArtifact(id, path, kind)` (taking only id/path/kind — discard the worker's sha256/bytes),
   then call `seal_envelope(engine=engine, outdir=output_dir, input_sha256=input_sha256,
   detected=parsed.detected, declared=[...], warnings=parsed.warnings, payload=parsed.payload,
   status=parsed.status)`. This recomputes sha256/bytes from the real files, re-confines every path
   under `output_dir`, and re-resolves every `ArtifactRef` — all in the audited contract code. On any
   `ValueError` → reject.
5. **input-SHA round-trip.** The host knows the SHA-256 of the bytes it actually sent (`input_sha256`).
   `seal_envelope` already stamps it into the envelope; additionally assert `parsed.input_sha256 ==
   input_sha256` (the worker's *claimed* input hash must match what we sent — defeats a worker that
   processed/returns a different document) → else reject. (Note: the Envelope carries a flat
   `input_sha256` field + a separate `detected: Detection` field — confirm the exact attribute names
   by reading `src/blastbox/contract/envelope.py` before coding.)
6. **caps.** `validate_envelope(sealed, outdir=output_dir, max_artifact_bytes=limits.max_artifact_bytes,
   max_total_bytes=limits.max_total_artifact_bytes, max_artifacts=limits.max_artifacts)` → on ValueError reject.
7. Return the sealed (host-trusted) Envelope.

Wrap every underlying `ValueError`/contract exception in `OutputTrustError` with a concise,
scrubbed message (use `sanitize_public_error`); never leak a raw worker-controlled string unscrubbed.

## Tests (TDD)
Build a helper that writes a valid `output_dir` (real artifact files + a metadata.json whose Envelope
references them). Then:
1. **happy path** — valid output → returns an Envelope; `artifacts[i].sha256` equals the *real* file
   hash (prove re-seal recomputed, not trusted).
2. **tampered bytes/sha** — worker reports a smaller `bytes`/wrong `sha256` in metadata.json than the
   real file → still rejected/recomputed (the returned hash is the true one; a cap set just below the
   real size rejects).
3. **metadata missing** → OutputTrustError.
4. **metadata is a symlink** (point it at a valid json elsewhere) → OutputTrustError (regular-file gate).
5. **metadata over `max_metadata_bytes`** → OutputTrustError.
6. **engine mismatch** (`parsed.engine != engine`) → OutputTrustError.
7. **input_sha mismatch** (metadata's input.sha256 ≠ the `input_sha256` we pass) → OutputTrustError.
8. **artifact path traversal / symlink escape** (declared path `../x`, or a symlink in output_dir to
   outside) → OutputTrustError (re-seal confinement).
9. **unresolved ArtifactRef** in the payload → OutputTrustError.
10. **over caps** — too many artifacts / artifact over `max_artifact_bytes` / total over
    `max_total_artifact_bytes` → OutputTrustError.
11. **malformed json / non-dict / missing payload** → OutputTrustError (not an uncaught crash).

## Finish
`.venv/bin/pytest tests/ -q` all pass (incl. contract + jobs), mypy + ruff clean. Don't push.
