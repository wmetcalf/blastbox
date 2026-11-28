# Pull Worker Agent (Go) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A credential-less, cgo-free Go worker agent that pulls work from a blastbox control plane over outbound HTTPS, runs the engine under seatbelt (macOS) or nsjail (Linux), and hands the output back to a control-plane `node-finalizer` that trust-gates, re-seals and signs it; with liveness alerts and a signed reproducible release.

**Architecture:** Approach B+E1 of the spec. Identity/session/claim routes are reused byte for byte. The ingress gains a narrow node data plane (input stream, result upload, heartbeat, renew, `run` block) and quarantines uploads into a shared spool. A separate `blastbox node-finalizer` process (holds DB, blobs, attest key; never claims) runs the existing cold-path finalisation code on each quarantined upload. Python is the reference for every byte-level contract; committed conformance vectors gate both languages in CI.

**Tech Stack:** Python 3.12 / FastAPI / cryptography (blastbox); Go 1.23 stdlib only (`crypto/ecdsa`, `crypto/x509`, `archive/tar`, `net/http`, `github.com/BurntSushi/toml` is the ONE allowed third-party module, pinned in go.sum); GitHub Actions + cosign keyless; Swift (william-tells).

**Spec:** `docs/superpowers/specs/2026-11-27-pull-worker-agent-go-design.md` (§19 Decisions override everything above it).

## Global Constraints

- blastbox commits are trailer-free conventional commits; one feature branch per PR off fresh `origin/main` (stack only where stated).
- `ruff check src tests scripts`, `mypy src`, `pytest -q` green in `.venv` for every Python task.
- Go: `CGO_ENABLED=0`, `go vet ./...`, `go test ./...`, `gofmt -l` empty; builds with `-trimpath -buildvcs=true`.
- No secrets in argv or environment anywhere (paths to secrets only). Never log key material, tokens, receipts or DSNs.
- No inbound listener on the node; the agent follows no redirects, sets no proxy, talks only to the configured ingress origin; TLS roots = only the configured CA file.
- v1 node grants are `tiers=["none"]`; `run.network != "none"` → release unstarted.
- Certs last 7 days (`--days 7` default). Node key = PKCS#8 P-256 file, mode 0600, owned by the agent user; refuse group/world-readable or symlinked keys.
- Liveness defaults: `node_silent` after 90 s (3 × `heartbeat_s`=30), `engine_orphaned` after 300 s, `cert_expiring` at 48 h. All three configurable by env and reported in the liveness JSON.
- `worker_runtime` values: `"seatbelt"` (macOS) and `"nsjail"` (Linux) only. `worker_tier = "node-agent"`.
- A sample that reached a sandbox is never released (only failed).
- Header names: `x-blastbox-node-session`, `x-blastbox-claim-id`, `x-blastbox-receipt`, `x-blastbox-input-sha256`, `x-blastbox-worker-runtime`.
- `User-Agent: blastbox-agent/<semver> (<goos>/<goarch>)`.

## Review Focus

1. **Upload of a result for a job whose claim was reclaimed mid-upload** — the ingress must refuse (403/409) and never quarantine; the finalizer must re-check `(RUNNING, claim_id)` before every destructive step. Test in Task B3 and B4.
2. **Duplicate/retried result PUT after a lost response** — must return the stored outcome, never extract twice or finalise twice. Test in Task B3/B4.
3. **Agent killed between sandbox start and upload** — on restart the agent must not re-run or release that job; it fails it (`state/jobs/<id>/started` marker) or leaves it for the reclaim sweep. Test in Task D5.
4. **Clock skew between node and control plane (±10 min)** — opaque tokens, server-time-relative renewal, and `finished_at` clamped to `MAX_FUTURE_SKEW_S` must not wedge the agent. Test in Task D5.
5. **A probe that passes because the sandbox silently didn't apply** (e.g. sandbox-exec missing, nsjail not root-capable) — the probe must require the handshake nonce written from inside the sandbox AND the three denials; absence of the handshake fails the probe. Test in Task D3.

---

## PR A — node identity v2, CSR enrolment, online renewal, conformance vectors (blastbox, branch `feat/node-identity-v2` off origin/main)

### Task A1: node-info v2 (WireGuard key optional)

**Files:**
- Modify: `src/blastbox/host/pki.py` (`_node_info_bytes`, `NodeIdentity`, `issue_node`, `node_identity`)
- Modify: `src/blastbox/host/cli.py` (`issue-node` `--wg-pubkey` optional; consumers at the worker-link/attest lookups ~L1578, ~L1922, ~L1972 skip identities with `wg_pubkey is None`)
- Test: `tests/host/test_pki_node_info_v2.py`

**Interfaces:**
- Produces: `NodeIdentity.wg_pubkey: str | None`; `NodeIdentity.info_version: int` (1 or 2); `CertAuthority.issue_node(node_id, *, wg_pubkey: str | None = None, grants=None, days=7)` stamps `v: 2` and omits `"wg"` when None, keeps `v: 1` byte-identical when a key is given.

- [ ] Write failing tests: `test_v2_cert_without_wg_verifies` (identity.wg_pubkey is None, info_version == 2, grants round-trip); `test_v1_cert_still_verifies_and_requires_wg` (v1 with missing/garbled wg → ValueError, unchanged message); `test_v2_with_garbled_wg_rejected`; `test_unknown_version_rejected` (`v: 3` → "unsupported node-info version"); `test_v1_bytes_unchanged` (issue with wg → extension JSON equals the pre-change encoding exactly); `test_worker_link_skips_wg_less_node` (the cli peer-map helper ignores a v2 no-wg identity instead of raising).
- [ ] Run, see them fail. Implement. Run full `pytest -q tests/host -k "pki or node or link"` green.
- [ ] Commit `feat(pki): node-info v2 makes the WireGuard key optional`.

### Task A2: sign a node CSR (`pki sign-node-csr`)

**Files:**
- Modify: `src/blastbox/host/pki.py` (add `CertAuthority.sign_node_csr`)
- Modify: `src/blastbox/host/cli.py` (subcommand `pki sign-node-csr`)
- Test: `tests/host/test_pki_sign_node_csr.py`

**Interfaces:**
- Produces: `CertAuthority.sign_node_csr(csr_pem: bytes, *, node_id: str, grants: NodeGrants, days: int = 7) -> bytes` (cert PEM). Rules: CSR signature valid; key is EC P-256 exactly (refuse RSA, other curves); CSR CN must equal `node_id` (refuse otherwise); every CSR extension/attribute is IGNORED; EKU = critical `OID_NODE_AUTH` only; node-info v2 without `wg`, grants from the arguments. Shares one private `_build_node_cert(node_id, public_key, wg, grants, days)` with `issue_node`.
- CLI: `blastbox pki sign-node-csr --csr PATH --node-id ID [--engine E]... [--tier T]... [--credentials] [--days 7] [--out PATH]`; default out `<pki>/node-<id>.crt`, written atomically (tmp + rename, 0644). Prints the cert path and `not_after`, never key material.

- [ ] Failing tests: `test_csr_grants_come_from_flags_not_csr` (CSR carrying a forged node-info extension and clientAuth EKU → issued cert has flag grants and only node EKU); `test_cn_mismatch_refused`; `test_rsa_and_p384_refused`; `test_bad_signature_refused`; `test_issued_cert_passes_node_identity` (v2, wg None); `test_cli_sign_node_csr_writes_atomically` (out file exists, no `.tmp` left, mode 0644).
- [ ] Implement; tests green; commit `feat(pki): sign node CSRs so the node key never leaves the node`.

### Task A3: online renewal — `POST /v1/nodes/renew`, `GET /v1/nodes/cert`, `pki renew-pending`

**Files:**
- Create: `src/blastbox/host/node_renew.py` (queue + signer logic, no FastAPI)
- Modify: `src/blastbox/host/ingress/node_claim.py` (two routes)
- Modify: `src/blastbox/host/cli.py` (`pki renew-pending`)
- Create: `deploy/systemd/blastbox-pki-renew.service`, `deploy/systemd/blastbox-pki-renew.timer` (OnUnitActiveSec=5min)
- Test: `tests/host/test_node_renew.py`, `tests/host/ingress/test_node_renew_routes.py`

**Interfaces:**
- Produces in `node_renew.py`:
  - `RENEW_DIR = "renew"` (under the PKI dir, mode 0700).
  - `queue_csr(pki_dir: Path, node_id: str, csr_pem: bytes) -> None` — validates (signature, P-256, CN == node_id, ≤ 8 KiB), writes `<pki>/renew/<node_id>.csr` atomically, mode 0600. Raises `RenewRefused(str)`.
  - `current_cert(pki_dir: Path, node_id: str) -> bytes | None` — PEM of the verifying (`node_identity`) cert for that node with the latest `not_after`.
  - `sign_pending(ca: CertAuthority, pki_dir: Path, *, days: int = 7) -> list[tuple[str, str]]` — for each queued CSR: look up `current_cert` (must still verify; an expired/removed node is NOT renewed — that is revocation), re-issue via `sign_node_csr` with **that cert's grants**, atomically replace the file the current cert lives in, delete the CSR. Returns `[(node_id, "renewed"|"refused: <why>")]`.
- Routes (session-authenticated, under the existing `_node_from_token` + `_grants_now(node_id) is not None` gate):
  - `POST /v1/nodes/renew {csr_pem}` → 202 `{"queued": true}`; refusal → 400 with reason; ungranted → 403 `_REFUSED`.
  - `GET /v1/nodes/cert` → 200 `{"cert_pem", "not_after"}` (the current cert for the session's node) or 404.
- CLI: `blastbox pki renew-pending [--days 7]` (requires the CA key; prints one line per node).

- [ ] Failing tests: `test_queue_rejects_cn_not_session_node`, `test_queue_rejects_oversize_and_non_p256`, `test_sign_pending_uses_current_cert_grants` (CSR for node with grants williamtells/none → new cert same grants, new public key), `test_sign_pending_refuses_revoked_node` (cert deleted → CSR deleted, result "refused: no current certificate", nothing issued), `test_sign_pending_replaces_in_place` (one file per node afterwards; `fleet_grants` sees one identity), routes: `test_renew_requires_session` (401), `test_renew_queues_202`, `test_cert_route_returns_latest`.
- [ ] Implement; green; commit `feat(nodes): online cert renewal via a queued CSR and a CA-host timer`.

### Task A4: conformance vectors v1 (Python generator + Python gate)

**Files:**
- Create: `scripts/gen_conformance.py` (deterministic generator; `--check` mode exits 1 on drift)
- Create: `conformance/v1/` — `challenge.json`, `signing_payload.json`, `session_token.json`, `receipt.json`, `canonical_json.json`, `ecdsa_cross.json`, `node_certs/` (fixed test CA + v1/v2 certs + negatives listed in spec §8), `sandbox/seatbelt/*.json`, `sandbox/nsjail/*.json`, `SHA256SUMS`, `README.md` (what each file is, how to regenerate, "bump = new directory v2/")
- Create: `tests/conformance/test_vectors.py`
- Modify: `.github/workflows/ci.yml` (step `python scripts/gen_conformance.py --check` in `test` job)

**Interfaces:**
- Fixed inputs live in the generator: claim secret `bytes.fromhex("00"*32)`… (32 fixed bytes), fixed times, a committed fixed P-256 test CA key and node keys (`conformance/v1/node_certs/*.key`, clearly labelled TEST ONLY). Certs are generated once and committed (they carry random serials); `--check` verifies every committed cert still passes/fails `node_identity` as its vector says rather than regenerating them. Time-dependent verdicts (expired) are evaluated with a frozen `now` field in the vector.
- Vector shapes (Go consumes these; keep keys stable):
  - `challenge.json`: `{"secret_hex", "cases":[{"scope","expiry_repr","challenge","verify_at","verdict":"ok"|"expired"|"wrong_scope"|"malformed"|"foreign"}]}`
  - `signing_payload.json`: `{"cases":[{"challenge","scope","node_id","payload_hex"}]}`
  - `session_token.json`, `receipt.json`: input fields + expected string + negative cases with verdict.
  - `canonical_json.json`: `{"cases":[{"input": <json>, "canonical_hex"} | {"input_repr", "error":"float"}]}`
  - `ecdsa_cross.json`: `{"python_signed":[{"public_key_pem","payload_hex","signature_b64"}], "go_signed":[]}` (Go task D1 appends `go_signed`; Python test verifies every entry of both lists).
  - `sandbox/seatbelt/<case>.json`: `{"request":{"exec_paths","ro_paths","rw_paths","accelerators","scratch","canary"},"profile","params"}` from `seatbelt.build_profile`.
  - `sandbox/nsjail/<case>.json`: `{"request":{...}, "argv":[...]}` from `NsjailSandbox._build_argv` with fixed paths (seccomp policy path fixed).
- [ ] Failing test `test_vectors_match_generator` (runs generator in-memory, compares to committed files), `test_sha256sums_cover_every_file`, `test_ecdsa_cross_both_directions_verify`.
- [ ] Write generator + vectors; green; commit `test(conformance): v1 vectors for the node protocol, generated by the Python reference`.

**PR A done:** marla `--fix` until green; push; PR; bots; merge.

---

## PR B — node data plane + node-finalizer (blastbox, branch `feat/node-data-plane`, stacked on PR A until it merges, then rebased on main)

### Task B1: factor cold-path finalisation into one reusable method

**Files:**
- Modify: `src/blastbox/host/dispatch.py` (extract from the cold path: output size cap → `validate_worker_output` → engine_error gate → network capture seal (optional) → `_write_sealed_metadata` → chmod → `_claim_is_still_ours` → `_seal_receipt` → `_upload_output` (+ retain-for-retry) → CAS DONE → `_index_page_hashes`)
- Test: existing dispatch suites stay green; add `tests/host/test_dispatch_finalise_output.py`

**Interfaces:**
- Produces: `Dispatcher.finalise_output(job: Job, output_dir: Path, observation: RunObservation | None, *, capture_on: bool = False) -> str` returning `"done"`, `"failed: <reason>"`, `"lost"` (claim no longer ours) or `"retained"` (upload failed, retained for retry). Behaviour identical to today's inline code; the cold path calls it.
- [ ] Failing tests: `test_finalise_output_done` (valid tree → DONE, receipt sealed when key present), `test_finalise_output_engine_error_fails`, `test_finalise_output_lost_claim_does_not_upload`, `test_finalise_output_untrusted_tree_fails`.
- [ ] Refactor; whole `pytest -q` green; commit `refactor(dispatch): one finalise_output for every path that seals a tree`.

### Task B2: claim response `run` block; stop handing out `result_dir`

**Files:**
- Modify: `src/blastbox/host/ingress/node_claim.py` (claim route return), `src/blastbox/host/jobs/base.py` (`Job.to_node_dict()`)
- Test: `tests/host/ingress/test_node_claim_run_block.py`

**Interfaces:**
- `Job.to_node_dict() -> dict` = `to_dict()` minus `result_dir`. (`params` stays in `job` for the Python `HttpJobStore`; the agent reads `run.params` only.)
- `run` = `{"deadline_s": int, "limits": {"max_input", "max_metadata", "max_artifact", "max_total_artifacts", "max_artifacts"}, "network": str, "params": {k: v for k, v in job.params if not k.upper().startswith("BLASTBOX_")}, "input": {"sha256", "bytes", "filename"}}`.
  - `deadline_s`: env `BLASTBOX_NODE_RUN_DEADLINE_S_<ENGINE_UPPER>` else `BLASTBOX_NODE_RUN_DEADLINE_S` else 300; clamp to [10, 3600].
  - `limits`: `Limits.from_env()` on the ingress, mapped field for field.
  - `network`: the job's resolved personality tier via `_job_requirements` (tier or `"none"` when unresolved and not strict).
  - `input.bytes`: size of the spooled input or blob (None if unknown; agent then relies on `max_input`).
- [ ] Failing tests: `test_claim_has_run_block`, `test_run_params_strip_blastbox_keys`, `test_claim_job_has_no_result_dir`, `test_http_store_still_parses_claim` (`HttpJobStore` claim against the app still yields a `Job`).
- [ ] Implement; green; commit `feat(nodes): a server-authored run block on the claim; result_dir no longer leaves the host`.

### Task B3: `GET /v1/nodes/jobs/{id}/input` and `PUT /v1/nodes/jobs/{id}/result`

**Files:**
- Create: `src/blastbox/host/node_results.py` (quarantine spool layout + marker/outcome I/O; no FastAPI)
- Modify: `src/blastbox/host/ingress/node_claim.py` (routes; `register_node_claim_routes(..., blob_store=None, job_root=None)`), `src/blastbox/host/ingress/app.py` (pass them)
- Modify: `src/blastbox/host/ingress/middleware.py` if the body-size middleware would reject the result PUT before the route's own cap (raise the per-route ceiling to the computed stream cap for this path only)
- Test: `tests/host/ingress/test_node_data_plane.py`

**Interfaces (node_results.py):**
- `results_root(job_root: Path) -> Path` = env `BLASTBOX_NODE_RESULTS_DIR` else `job_root / ".node-results"` (0700).
- Layout: `<root>/<job_id>/<claim_digest>/` where `claim_digest = sha256(claim_id)[:16]`; inside `out/` (extracted tree), `upload.json` (marker, written LAST, atomically), `outcome.json` (written by the finalizer).
- `UploadMarker` dataclass: `job_id, claim_id, node_id, node_cert_sha256, worker_runtime, received_at, started_at_ms, finished_at_ms`.
- `write_marker(dir, marker)`, `read_marker(dir) -> UploadMarker | None`, `write_outcome(dir, status: str, reason: str | None)`, `read_outcome(dir) -> dict | None`, `pending(root) -> Iterator[Path]` (dirs with marker and no outcome).
- Input route: `_owned_job` + `status == RUNNING` else 403 `_REFUSED`; serve `<job_root>/<id>/input/<filename>` if a regular file, else `blob_store.get_sample(job.input_sha256, tmp)` into a private temp under job_root then stream and delete; headers `Content-Length`, `x-blastbox-input-sha256`; `application/octet-stream`.
- Result route: headers session/claim-id/receipt + optional `x-blastbox-worker-runtime` (must be `seatbelt` or `nsjail`, else 400) + `x-blastbox-started-at-ms`/`x-blastbox-finished-at-ms` (ints, clamped to now+`MAX_FUTURE_SKEW_S`). Order: auth (`_owned_job`, RUNNING) → if a dir for this (job, claim) exists: return its outcome (200 `{status:"done"}` / 422 `{status:"failed", reason}`) or 202 `{status:"accepted"}` if pending — never re-extract → stream body to a temp file with the push-path stream cap (`int(max_artifact_total*1.1) + max_metadata + max_artifacts*1024 + 65536`; 413 past it) → `_safe_extract_tar` into `<dir>.partial/out` with `max_total_bytes`, `max_members = max_artifacts + 64`, `max_metadata_bytes` (422 + no marker on any extraction error) → re-check ownership → rename `.partial` → final, write marker → 202 `{status:"accepted"}`. `node_cert_sha256` = sha256 of the DER of `node_renew.current_cert(pki, node_id)`.
- [ ] Failing tests (authorisation matrix): wrong node's session → 403; stale claim id → 403; revoked cert (file deleted, cache bypassed via mtime signature) → 403; expired session → 401; job QUEUED/DONE → 403; input sha header equals content sha; blob-store fallback path; adversarial tars (`..`, absolute path, symlink, hardlink, device, duplicate member, over member cap, over byte cap) → 422/413 and no marker; `test_result_put_idempotent` (second PUT returns 202 then the stored outcome, extracts once); `test_result_put_after_reclaim_refused`; `test_worker_runtime_header_allowlisted`.
- [ ] Implement; green; commit `feat(nodes): stream the input to a node and quarantine its result tar`.

### Task B4: `blastbox node-finalizer`

**Files:**
- Create: `src/blastbox/host/node_finalizer.py`
- Modify: `src/blastbox/attest.py`? NO — modify `src/blastbox/host/attest.py` (`RunObservation` + `build_receipt` gain optional `node_id`, `node_cert_sha256`; emitted only when not None)
- Modify: `src/blastbox/host/cli.py` (`node-finalizer` subcommand: `--once`, `--interval 1.0`)
- Modify: `DEPLOYMENT.md` (finalizer service, env, the shared results volume, "the ingress never holds the attest key")
- Test: `tests/host/test_node_finalizer.py`

**Interfaces:**
- `class NodeFinalizer: __init__(self, *, job_store, blob_store, limits, job_root, attest_key=FROM_ENV, results_dir=None)`; `run_once() -> int` (count finalised); `run_forever(stop: threading.Event)`.
- Per pending dir: read marker; `job = store.get(job_id)`; if not RUNNING or `claim_id != marker.claim_id` → outcome `failed: claim lost`, no writes to the job; else build `RunObservation(job_id, engine, input_sha256=job.input_sha256, worker_runtime=marker.worker_runtime, worker_tier="node-agent", started_at_ms, finished_at_ms, node_id, node_cert_sha256)` (no net fields) and call `Dispatcher.finalise_output(job, out_dir, observation)` on an internal `Dispatcher(job_store=..., engines={}, limits=..., job_root=..., blob_store=..., attest_key=...)`; write outcome from its return; job failures use `_fail_job` (claim-fenced). Outcome dirs older than 1 h are removed; the extracted `out/` is removed right after finalisation.
- Refuses to start when the attest key is missing unless `--no-receipts` is given (stated loudly). Never claims.
- [ ] Failing tests: `test_finalizer_marks_done_and_signs_receipt_with_node_fields`, `test_finalizer_fails_untrusted_tree`, `test_finalizer_skips_lost_claim`, `test_finalizer_idempotent_rerun` (second `run_once` → 0, job unchanged), `test_receipt_without_node_fields_unchanged` (old receipts byte-identical), `test_end_to_end_claim_input_result_finalise` (TestClient app + finalizer, a trivial tree).
- [ ] Implement; green; commit `feat(nodes): node-finalizer seals node results where the attest key lives`.

### Task B5: conformance vectors for the data plane

**Files:** Modify `scripts/gen_conformance.py`; add `conformance/v1/claim_responses/`, `input_stream/`, `result_tars/`, `envelope_seal/`, `transcripts/`; extend `tests/conformance/test_vectors.py`.

- `claim_responses/*.json`: `{"status", "body", "decision": "run"|"idle"|"rehandshake"|"refused"|"release_unstarted"}` (incl. a run block with `network:"sinkhole"` → `release_unstarted`).
- `input_stream/*.json`: `{"headers", "body_hex", "max_input", "verdict": "accept"|"abort_short"|"abort_long"|"abort_hash"|"abort_redirect"}`.
- `result_tars/`: `<case>.tar` + `<case>.json {"server_verdict": "accepted"|"rejected", "reason"}`; plus `writer/<case>.json {"tree": {...}, "tar_sha256"}` for the Go deterministic writer (USTAR, sorted paths, mode 0644, uid/gid 0, mtime 0, no PAX unless needed).
- `envelope_seal/*.json`: tree → sealed artifact `sha256`/`bytes`.
- `transcripts/*.json`: ordered `[{"req": {"method","path","headers_present":[...]}, "resp": {"status"}}]` for happy, refused, lost-claim 409, session-expiry-mid-upload (401 then re-handshake then 202).
- [ ] Tests: server verdict for every adversarial tar matches its vector by calling the real route; green; commit `test(conformance): data-plane vectors`.

**PR B done:** marla `--fix` until green; push; PR; bots; merge.

---

## PR C — heartbeat, liveness and alerts (blastbox, branch `feat/node-liveness`, off main after PR B merges)

### Task C1: liveness store + heartbeat route + claim recording

**Files:**
- Create: `src/blastbox/host/node_liveness.py`
- Modify: `src/blastbox/host/ingress/node_claim.py` (`POST /v1/nodes/heartbeat`; `/claim` records `last_claim_at` on every authenticated attempt incl. 204)
- Modify: `src/blastbox/host/node_registry.py` banner (now WIRED for liveness; update the banner test accordingly)
- Test: `tests/host/test_node_liveness.py`, `tests/host/ingress/test_node_heartbeat.py`

**Interfaces:**
- `HeartbeatBody` (pydantic, every list bounded ≤ 64, strings ≤ 128): `agent_version, binary_sha256, goos, goarch, started_at, engines[{name, sandbox, floor, slots, busy, selftest_ok, selftest_at}], in_flight[{job_id, claim_id, started_at, deadline_at}], cert_not_after`.
- `class LivenessStore(Protocol)`: `record_heartbeat(node_id, body: dict, at: float)`, `record_claim(node_id, engine: str | None, at: float)`, `snapshot() -> dict[str, NodeLiveness]`. Implementations `SqlLivenessStore` (table `node_liveness(node_id PK, last_heartbeat_at, last_claim_at, body TEXT)`, borrowing the job store's pool like `SqlNodeRegistry`), `RedisLivenessStore`, `InMemoryLivenessStore`; `build_liveness_store(job_store)`.
- Route returns 200 `{"server_time": float, "min_agent_version": env BLASTBOX_NODE_MIN_AGENT_VERSION or "0.0.0", "heartbeat_s": 30}`.
- [ ] Failing tests: heartbeat requires session (401) and grants (403); body over bounds → 422; `record_claim` on 204; SQLite store round-trip; body stored is the claim, never used for authz (grants unchanged by a heartbeat that lists extra engines).
- [ ] Implement; green; commit `feat(nodes): heartbeat and per-node liveness on the control plane`.

### Task C2: alert evaluation, metrics, `/v1/fleet/liveness`

**Files:**
- Modify: `src/blastbox/host/node_liveness.py` (`LivenessConfig`, `evaluate`)
- Modify: `src/blastbox/host/ingress/app.py` (route `GET /v1/fleet/liveness`, API-key protected like other `/v1/` routes; gauges registered with the existing observability registry)
- Test: `tests/host/test_node_alerts.py`

**Interfaces:**
- `LivenessConfig.from_env()`: `silent_after_s` (`BLASTBOX_NODE_SILENT_AFTER_S`, 90), `orphaned_after_s` (`BLASTBOX_ENGINE_ORPHANED_AFTER_S`, 300), `cert_expiring_s` (`BLASTBOX_NODE_CERT_EXPIRING_S`, 172800).
- `evaluate(*, now, enrolled: dict[str, NodeIdentity], live: dict[str, NodeLiveness], oldest_queued: dict[str, float], cfg) -> list[Alert]`; `Alert(kind: "node_silent"|"node_unhealthy"|"engine_orphaned"|"cert_expiring", subject: str, since: float, detail: str)`. Expected set = enrolled (verifying, unexpired) certs. `engine_orphaned`: an engine with QUEUED work older than `orphaned_after_s` and no enrolled node granted it whose heartbeat is fresh and selftest ok.
- `GET /v1/fleet/liveness` → `{"config": {...all three...}, "nodes": [{node_id, last_heartbeat_at, last_claim_at, agent_version, engines, cert_not_after}], "alerts": [...], "generated_at"}`.
- Metrics: `blastbox_node_last_heartbeat_seconds{node}`, `blastbox_node_last_claim_seconds{node}`, `blastbox_node_selftest_ok{node,engine}`, `blastbox_node_cert_expiry_seconds{node}`, `blastbox_engine_oldest_queued_seconds{engine}`, `blastbox_node_alert{kind,subject}` (1 while active).
- ERROR log once per alert transition (process-local memo keyed `(kind, subject)`), INFO on clear.
- Store needs `oldest_queued_by_engine()`: add to the job store protocol as an optional method with a fallback scan over `list_jobs(status=QUEUED)` bounded.
- [ ] Failing tests on a simulated clock: silent fires at 91 s not 89 s; unhealthy on `selftest_ok=false`; orphaned fires with no live node and clears when a node heartbeats; cert_expiring at 47 h; config visible in JSON; route needs API key; transition logged once.
- [ ] Implement; green; commit `feat(nodes): liveness alerts, gauges and a fleet liveness view`.

### Task C3: `worker-link status --check` (stopgap for push nodes)

**Files:** Modify `src/blastbox/host/worker_link_apply.py` / cli `worker-link status` (add `--check --max-handshake-age 180`): exit 2 when any peer's latest handshake is older (or never). Test `tests/host/test_worker_link_check.py` with a fake `wg show dump` runner.
- [ ] Test, implement, commit `feat(worker-link): status --check exits non-zero on a stale handshake`.

**PR C done:** marla; push; PR; bots; merge.

---

## PR C2 — Loadout consumes liveness (Loadout repo, branch `feat/blastbox-node-liveness` off origin/master, in a separate worktree; never touch the dirty `feat/accounts-local-20261027` checkout)

### Task L1: surface node liveness in `/system/status` and on Matrix

**Files:**
- Modify: `backend/loadout/fleet.py` (poll `GET <host>/v1/fleet/liveness` for each configured blastbox host with the host's existing API key handling; cache 15 s; failure recorded, not raised)
- Modify: `backend/loadout/app.py` `/system/status` (`node_liveness: {hosts: {short: {alerts, config, nodes, error?}}}`)
- Modify: `backend/loadout/matrixas.py` or the existing notifier (`notify_ops(text)`) — post once per alert transition (raise and clear) to the ops room as `@loadout-bot`; dedupe by `(host, kind, subject)`
- Modify: `backend/API.md`
- Test: `backend/tests/test_fleet_liveness.py`
- [ ] Failing tests: alerts appear in `/system/status`; a host that 404s (old blastbox) shows `error: "liveness not supported"` not a crash; transition → exactly one Matrix send, clear → one send; repeated polls send nothing.
- [ ] Implement; `.venv/bin/python -m pytest -q` green; commit (with Loadout trailers); marla; PR; merge.

---

## PR D — the Go agent (blastbox, branch `feat/go-agent` off main after PR C merges)

Layout (Go module `github.com/wmetcalf/blastbox/agent`, go 1.23):

```text
agent/go.mod, go.sum
agent/cmd/blastbox-agent/main.go        subcommands: run, enrol, probe, renew, version, __launch (internal)
agent/internal/config/                  TOML config, validation, permission checks
agent/internal/wire/                    HTTPS client, session, claim, input, result, heartbeat, renew, fail/release
agent/internal/conformance/             loaders for ../conformance/v1 (test-only helpers)
agent/internal/canon/                   attest_wire.canonical port (node observation, v1.1-ready)
agent/internal/sandbox/                 seatbelt profile, nsjail argv, launcher (rlimits+exec), probe
agent/internal/runner/                  per-job state machine, scratch, tar writer, memory watchdog
agent/internal/agent/                   main loop: slots, back-off, probes, heartbeat, renewal
```

### Task D1: module skeleton, config, crypto/wire primitives + conformance

**Files:** `agent/go.mod`, `agent/cmd/blastbox-agent/main.go` (version only), `agent/internal/config/{config.go,config_test.go}`, `agent/internal/wire/{payload.go,payload_test.go}`, `agent/internal/canon/{canon.go,canon_test.go}`, `agent/internal/conformance/load.go`

**Interfaces:**
- Config TOML:
  ```toml
  ingress = "https://172.18.101.15:8005"
  ca_file = ".../ca.crt"
  cert_file = ".../node.crt"
  key_file = ".../node.key"
  state_dir = ".../state"
  claim = true                     # false = shadow (handshake, heartbeat, probes only)
  [[engine]]
  name = "williamtells"
  argv = ["/opt/william-tells/bin/wtqrk-scan", "blastbox", "{input}"]   # stdout = envelope OR writes {out}/metadata.json
  output = "stdout-envelope"       # or "dir"
  sandbox = "seatbelt"             # seatbelt | nsjail
  min_sandbox = "seatbelt"
  ro_paths = ["/opt/william-tells"]
  accelerators = ["ane", "gpu"]
  slots = 1
  probe_argv = ["/opt/william-tells/bin/wtqrk-scan", "probe", "--read", "{canary}", "--connect", "{connect}", "--write", "{outside}"]   # optional; else the built-in probe
  [nsjail]
  path = "/usr/local/bin/nsjail"
  sha256 = "<pinned>"
  ```
- `config.Load(path) (*Config, error)`: rejects unknown keys, http:// ingress, missing files, key not 0600/owned by uid/symlink, engine sandbox below `min_sandbox` (order none < seatbelt = nsjail; seatbelt only on darwin, nsjail only on linux), slots 1..16, argv[0] absolute.
- `wire.SigningPayload(challenge, scope, nodeID string) []byte`; `wire.Sign(key *ecdsa.PrivateKey, payload []byte) (string, error)` (DER, std base64).
- `canon.Marshal(v any) ([]byte, error)` — sorted keys, `,`/`:`, ensure_ascii with surrogate pairs, no HTML escaping, float rejection.
- [ ] Go tests consume `conformance/v1/signing_payload.json`, `canonical_json.json`, `ecdsa_cross.json` (verify all `python_signed`; a `-update-go-signed` test flag writes `go_signed` entries that the Python test then verifies), `node_certs/` (agent's own cert pre-check: EKU, CN==node-info node_id, expiry, P-256). Config refusal tests table-driven.
- [ ] Implement; `cd agent && go test ./...` green; commit `feat(agent): Go module, config and the node protocol's byte-level primitives`.

### Task D2: wire client (session, claim, input, result, fail/release, heartbeat, renew)

**Files:** `agent/internal/wire/{client.go,client_test.go}`

**Interfaces:**
- `wire.New(cfg *config.Config, ua string) (*Client, error)` — `http.Transport` with `TLSClientConfig{RootCAs: only ca_file, MinVersion: tls.VersionTLS12, ServerName: host}`, `Proxy: nil`, `CheckRedirect` returning an error, per-request timeouts; rejects any URL not on the ingress origin.
- Methods: `Session(ctx) error` (challenge → sign → session; renews 30 s before `expires_in`; re-handshake once on 401); `Claim(ctx, engine string, exclude []string) (*Claim, error)` (`Claim{Job json.RawMessage, JobID, ClaimID, Receipt, NodeID, Run RunBlock}`; `nil, nil` on 204; `ErrRefused` on 403); `FetchInput(ctx, c *Claim, dst string) (sha256 string, err)` (aborts beyond `Run.Limits.MaxInput`, on short body, on header/content hash mismatch, or on mismatch with `Run.Input.SHA256`); `PutResult(ctx, c, tarPath string, meta ResultMeta) (Outcome, error)` (`Outcome{Status: "accepted"|"done"|"failed", Reason}`; 409/403 → `ErrClaimLost`); `Release(ctx, c)`; `Fail(ctx, c, reason string, finishedAt time.Time)` (`expires_at` omitted; `finished_at` clamped to server time); `Heartbeat(ctx, hb Heartbeat) (HeartbeatResp, error)`; `Renew(ctx, csrPEM []byte) error`; `FetchCert(ctx) ([]byte, error)`; `Disposition(ctx, jobID) (string, error)`.
- Tokens, challenges, receipts are opaque strings, never parsed.
- [ ] Tests against `httptest.NewTLSServer` with a CA from the test: each claim_responses / input_stream / transcripts vector; 3xx → error; wrong CA → error; system roots never used (server cert from a different CA fails even if it is in system roots — simulate by a second CA); 401 → exactly one re-handshake.
- [ ] Implement; green; commit `feat(agent): the node wire client`.

### Task D3: sandboxes, launcher and confinement probe

**Files:** `agent/internal/sandbox/{seatbelt.go,seatbelt_test.go,nsjail.go,nsjail_test.go,launch.go,probe.go,probe_test.go,probe_darwin_test.go,probe_linux_test.go}`, `cmd/blastbox-agent/launch.go`

**Interfaces:**
- `BuildSeatbeltProfile(req Request) (profile string, params map[string]string, err error)` — exact port of `seatbelt.build_profile` (same line order, same param naming, same accelerator rules, same `_pinned_paths`, same ro/rw disjoint refusal). Golden: every `conformance/v1/sandbox/seatbelt/*.json`.
- `BuildNsjailArgv(req Request, nsjailPath, seccompPolicy string) ([]string, error)` — port of `NsjailSandbox._build_argv`. Golden: every `sandbox/nsjail/*.json`.
- `Request{ExecPaths, ROPaths, RWPaths []string; Accelerators []string; Scratch, Canary string}`; all paths `filepath.EvalSymlinks`-resolved by the caller.
- `Command(ctx, sb Kind, req Request, argv []string, lim Limits) *exec.Cmd` — darwin: `blastbox-agent __launch --rlimit-cpu N --rlimit-fsize N --rlimit-nofile N --rlimit-nproc N -- /usr/bin/sandbox-exec -p PROFILE -D K=V... /bin/sh -c HANDSHAKE_SHIM sh NONCE MARKER argv...` (HANDSHAKE_SHIM copied verbatim from seatbelt.py). linux: `__launch ... -- nsjail <argv>` with the same handshake shim inside. `__launch` calls `syscall.Setrlimit` then `syscall.Exec`; `Setpgid: true`; env is an explicit minimal map (HOME/TMPDIR = scratch, PATH=/usr/bin:/bin, LANG=C), never inherited.
- `Probe(ctx, eng config.Engine) ProbeResult{OK bool; Reason string; At time.Time}` — the agent creates a canary file outside grants, opens a loopback TCP listener, and picks an outside-scratch path; runs the engine's `probe_argv` (substituting `{canary}`, `{connect}` = 127.0.0.1:port, `{outside}`) or the built-in probe (`blastbox-agent __probe --read X --connect Y --write Z`, which exits 0 only if ALL THREE are denied) under the engine's exact sandbox. OK requires: handshake nonce present in scratch, exit 0, listener received no connection, canary unread (atime not relied on; the probe reports), outside path absent.
- [ ] Tests: golden profile/argv vectors (all platforms, pure functions); darwin-only `TestProbeDeniesUnderSeatbelt` and `TestProbeFailsWithoutSandbox` (running the built-in probe UNsandboxed must report not-OK — proves the probe can fail); linux-only equivalents under nsjail (skip with reason when nsjail absent; CI `sandbox` job provides it).
- [ ] Implement; green on linux here and on the Mac (`ssh` + `go test` with a copied toolchain or cross-compiled test binary `go test -c`); commit `feat(agent): seatbelt and nsjail confinement with a proof before every claim`.

### Task D4: runner — one job end to end

**Files:** `agent/internal/runner/{runner.go,runner_test.go,tarw.go,tarw_test.go,watchdog_darwin.go,watchdog_linux.go}`

**Interfaces:**
- `Run(ctx, cl *wire.Client, eng config.Engine, c *wire.Claim, stateDir string) Result` state machine:
  1. `run.network != "none"` → `Release`, done.
  2. `state/jobs/<id>/` (0700) — fetch input to `in/<sanitised filename>`; failure → `Release`.
  3. Write `started` marker (fsync) BEFORE launching the sandbox. From here the job is never released.
  4. Launch with deadline `run.deadline_s`; process group killed at deadline (SIGKILL to -pgid); memory watchdog (darwin: `ps -o rss= -g pgid` every 500 ms summing; linux: nsjail `--cgroup_mem_max`) kills at `run.limits` memory cap (engine config `max_rss_mib`, default 2048).
  5. Output: `output = "dir"` → tree in `out/`; `"stdout-envelope"` → stdout (capped at `max_metadata`) written to `out/metadata.json`. Fill artifact `sha256`/`bytes` only for declared artifacts that exist (control plane re-seals anyway).
  6. Enforce `run.limits` locally (defence in depth); over → `Fail`.
  7. `tarw.Write(outDir, tarPath)` deterministic tar of regular files only (refuse symlinks/devices/hardlinks in the tree → `Fail`).
  8. `PutResult`; `accepted` → poll `Disposition` up to 60 s for a log line; `ErrClaimLost` → log, drop.
  9. Wipe `state/jobs/<id>` in all cases (`os.RemoveAll` after chmod-walk).
- `tarw.Write(root, dst string) error` — golden vs `result_tars/writer/*.json`.
- [ ] Tests (fake server from D2 tests + a fake engine script): happy; network≠none → release; input hash mismatch → release; deadline kill → fail with "deadline"; oversize output → fail; symlink in output → fail; lost claim on PUT → no retry, scratch wiped; tar golden vectors.
- [ ] Implement; green; commit `feat(agent): run one claimed job under its sandbox and hand the tree back`.

### Task D5: agent loop, restart safety, enrol/renew, CLI

**Files:** `agent/internal/agent/{agent.go,agent_test.go}`, `agent/cmd/blastbox-agent/{run.go,enrol.go,renew.go}`

**Interfaces:**
- `agent.Run(ctx, cfg) error`: startup checks (cert EKU/expiry/CN, key perms, nsjail sha256 pin, probes for every engine — any red → engine not claimable, heartbeat `selftest_ok=false`); heartbeat every `heartbeat_s` (server-provided, default 30); per engine, `slots` workers: claim (idle back-off 2 s; 5xx/network exponential to 30 s with ±20 % jitter; 403 → 60 s); re-probe every 10 min; `claim=false` = shadow (no Claim calls at all); stop claiming when server `min_agent_version` > own; SIGTERM → stop claiming, wait for in-flight up to their deadlines, exit.
- Restart: on start, every `state/jobs/<id>/started` left behind → `Fail(..., "agent restarted mid-run")` if the claim still verifies (needs claim id + receipt persisted in `state/jobs/<id>/claim.json`, 0600), else just wipe. Jobs without `started` → `Release`.
- Renewal: at ⅓ lifetime remaining, generate a new P-256 key to `node.key.next` (0600), `Renew(csr)`, poll `FetchCert` every 5 min until a cert whose public key matches `.next` appears, then atomically rename key+cert into place and re-handshake. Heartbeat reports `cert_not_after`.
- `blastbox-agent enrol --node-id ID --dir DIR` → writes `node.key` (0600) + `node.csr`, prints the `blastbox pki sign-node-csr` command to run on the CA host. Never prints the key.
- `blastbox-agent probe --config P` → runs probes, prints per-engine verdict, exit 1 on any red.
- [ ] Tests: skew ±10 min (fake server clock) still works; restart with `started` marker → Fail not Release; shadow mode never calls `/claim`; renewal swaps key+cert atomically and re-handshakes; SIGTERM drains.
- [ ] Implement; green; commit `feat(agent): the agent loop, restart safety, enrolment and renewal`.

### Task D6: CI — Go job, both-sides conformance, e2e on linux and macOS

**Files:** Modify `.github/workflows/ci.yml`: job `agent` (ubuntu-24.04, `actions/setup-go` pinned 1.23.x, `gofmt -l`, `go vet`, `go test ./...`, `CGO_ENABLED=0 go build -trimpath`); job `agent-e2e-linux` (reuse the nsjail build steps from `sandbox`; start `blastbox serve` with temp PKI/SQLite/local blobs + `node-finalizer`; enrol via CSR; run agent with a trivial engine; assert job DONE with receipt carrying `node_id`); job `agent-e2e-macos` (`macos-14`, seatbelt, same script). Create `agent/e2e/run_e2e.sh` (shared driver) and `agent/e2e/engine.sh` (trivial engine writing metadata.json).
- [ ] Run e2e driver locally on linux (nsjail present? if not, document skip) and on the Mac; commit `ci(agent): Go tests, conformance and end-to-end runs on linux and macOS`.

**PR D done:** marla; push; PR; bots; merge.

---

## PR E — release workflow and installer (blastbox, branch `feat/agent-release` off main after PR D)

### Task E1: reproducible, cosign-keyless release

**Files:** Create `.github/workflows/agent-release.yml`, `agent/install.sh`, `agent/RELEASING.md`; test `tests/test_agent_install_script.py` (shellcheck-free static assertions + a run of `install.sh` against a fake release dir with `--skip-cosign-for-test` refused unless `BLASTBOX_AGENT_INSTALL_TEST=1`).

- Trigger: tag `agent-v*`. `permissions: {contents: write, id-token: write}`. Build matrix darwin/linux × amd64/arm64 with `CGO_ENABLED=0 go build -trimpath -buildvcs=true -ldflags "-s -w -buildid= -X main.version=${VERSION}"`, twice in separate clean checkouts, `cmp` the outputs (fail on difference). `SHA256SUMS`; `cosign sign-blob --yes --bundle SHA256SUMS.sigstore.json SHA256SUMS` (cosign-installer pinned by commit SHA); SBOM via `go version -m` JSON (no extra tool) as `sbom.txt`; `conformance-digest.txt` = sha256 of `conformance/v1/SHA256SUMS`. Upload with `gh release create`.
- `install.sh --version X.Y.Z --sha256 <pinned sha256 of the binary for this platform> [--prefix /opt/blastbox-agent | ~/.local/blastbox-agent]`: downloads (or `--from DIR`), verifies the pinned sha256 FIRST, then `cosign verify-blob --bundle … --certificate-identity "https://github.com/wmetcalf/blastbox/.github/workflows/agent-release.yml@refs/tags/agent-vX.Y.Z" --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS`, checks the binary's line in SHA256SUMS, installs to `<prefix>/<ver>/blastbox-agent`, flips `<prefix>/current` symlink atomically. `--rollback` flips back to the previous version. Never `curl | sh`; refuses when cosign is absent unless `--no-cosign` AND `--sha256` (stated as weaker).
- [ ] Commit `ci(agent): reproducible cosign-keyless release and a pinned installer`. marla; PR; merge. (No tag is pushed by this task — releasing is out of scope; the deploy uses a locally built binary verified against a local double build.)

---

## PR F — william-tells `wtqrk-scan blastbox` (william-tells repo, branch `feat/wtqrk-scan-blastbox` off origin/main; commits carry the Loadout/Claude trailers)

### Task F1: build the blastbox envelope inside the sandbox

**Files:** Modify `Sources/wtqrk-scan/...` (the CLI entry; add a `blastbox` subcommand), reuse `BlastboxEnvelope.swift` mapping; Test `Tests/...BlastboxModeTests.swift`.

- `wtqrk-scan blastbox <input-path | ->` prints exactly one JSON envelope on stdout (the same document `BlastboxEnvelope.swift` produces for the push path, `engine: "williamtells"`, `input_sha256` of the bytes read) and exits 0; on an engine error prints an `engine_error` envelope and exits 0; usage errors exit 64. Never writes outside `$TMPDIR`/cwd. No network.
- [ ] Failing Swift test: envelope from `blastbox` mode equals the envelope the Python `blastbox_engine.py` mapping yields for the same fixture scan JSON (fixture committed). Build and run on the Mac (`swift build -c release`, `swift test --filter BlastboxMode`).
- [ ] Commit (with trailers); marla; PR; merge.

---

## Deploy and cutover (after PRs A–F merge)

### Task G1: toolz2 `williamtells-bb` stack

- Read the compose file and the stack's current env NAMES (never values). Build the image from merged main (no PyPI release): `docker build` from a fresh clone at the merge SHA with the stack's existing Dockerfile pattern, tag `bb-<sha7>`.
- `blastbox pki init` inside a one-off `docker run --rm --entrypoint blastbox` with the stack's pki volume only (no shared state dirs besides PKI). The CA key stays on the CA side (a dedicated `pki` volume not mounted into ingress RW; ingress gets the PKI dir read-only except `renew/`).
- Add `node-finalizer` service (same image, `command: ["blastbox","node-finalizer"]`, mounts job_root + results + attest key; the attest key is NOT mounted into ingress). Set `BLASTBOX_NODE_CLAIM_RECLAIM_AFTER_S=900`, deadline env for williamtells 180.
- `docker compose up -d --no-deps <ingress> node-finalizer`. Verify `GET /v1/nodes/challenge` 200 (was 404), `/v1/fleet/liveness` shows config.
- Install the renew timer on toolz2 (systemd user timer if no sudo; else report).

### Task G2: Mac shadow → shared queue → cutover

- Build `blastbox-agent` darwin/arm64 locally twice, compare sha256, `scp` to the Mac `~/.local/blastbox-agent/<ver>/`. `enrol --node-id mac-wt1` on the Mac; sign the CSR on toolz2 (`--engine williamtells --tier none --days 7`); copy cert + CA back.
- LaunchAgent `io.blastbox.pull-agent` (user domain, `launchctl bootstrap gui/<uid>` — no sudo), `claim = false`. Verify heartbeat in liveness; stop it; confirm `node_silent` fires at ~90 s; restart.
- **Blocked unless Mac→toolz2:8005 TCP works** (currently REACH_FAIL; route fix is Will's). If still broken: stop, report.
- `claim = true` (alongside static dispatcher). Real QR test scan end to end via Loadout or `/v1/jobs`; compare payloads push vs pull on the william-tells corpus.
- Cut over: `docker compose stop dispatcher` (stop, never run), keep finalizer. Real QR scan again.
- Retire: `launchctl bootout gui/<uid>/io.blastbox.worker-agent`, keep plist in `disabled-launchagents/`; leave `org.blastbox.operator`. `wtwg0`: route pinning → its own LaunchDaemon needs sudo → report exact commands; then peer removal on toolz2.
