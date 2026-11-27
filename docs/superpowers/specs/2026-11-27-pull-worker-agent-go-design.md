# Pull worker agent in Go (design, for approval)

> Status: DRAFT FOR WILL'S APPROVAL. Nothing here is built. Written 2026-11-27 against
> blastbox `main` @ 18744a73 (0.1.52) and william-tells `main` @ 0985483. Line numbers are at
> those commits.

## 1. Intent

A worker host should run one small static binary that dials out to the control plane, proves
which node it is, pulls work it is granted, runs the engine under the platform sandbox, and
hands back the output. There should be no inbound port, no WireGuard tunnel, and no Python,
venv or blastbox wheel on the host. When a node goes quiet, the control plane must say so.

**Goals**

* One Go binary, `CGO_ENABLED=0`, for darwin and linux on amd64 and arm64. Windows later.
* Pull over outbound HTTPS only, reusing the #178 identity and claim machinery unchanged.
* The control plane stays the only party that trusts output. The agent is untrusted, as the
  federation spec requires (`2026-09-15-federated-node-identity-and-placement.md` §5).
* Containment is never weaker than today's for any engine (§4.3).
* Liveness is a first-class signal: a node that stops claiming raises an alert within minutes.
* A Python⇄Go conformance-vector suite gates both sides in CI.

**Non-goals (v1)**

* Egress. v1 nodes are granted `tiers=["none"]` only. Linux egress (netns + exit) comes later.
* Warm pools, snapshots or Firecracker on the node. Each run is a cold exec under a sandbox.
* Leases on long jobs. v1 relies on a per-job deadline and the existing reclaim sweep (§6.6).
* Self-update. Operators install a pinned release (§13).
* Fleet placement (`placement.eligible`/`rank`). Grants decide. Ordering stays oldest-first.

**Anti-goals (never)**

* No database or blob-store credentials on a node, and no attestation key on a node.
* No host-side trust logic in Go. The agent does not re-implement `trust.py`.
* No inbound listener on the node, and no generic egress for engine processes.
* No secrets in argv or environment. Paths to secrets only.
* No silent fallback. A missing sandbox, a failed self-test or an unverifiable server stops
  the agent from claiming. It does not degrade.

## 2. Current state

### 2.1 The Mac today (observed read-only, 2026-11-27)

* The brief describes a Swift `wtqrk-worker`. **What actually runs is Python.** The
  `io.blastbox.worker-agent` LaunchAgent execs
  `~/var/williamtells/venv/bin/python -I …/blastbox_operator/legacy_agent.py --engine-id williamtells`.
  That is a private wrapper around blastbox's `http_agent`, and it refuses to run unless the
  SDK files match pinned 0.1.50 digests. william-tells' README says the same: the remote-Mac
  topology uses the Python `http_agent`, because `wtqrk-worker` "speaks plain HTTP for a local
  dispatcher only" (it refuses TLS env, `Worker.swift:60-63`).
* Loadout seeds `mac-pool` as `loadout_hosted` and states "every image gets a fresh per-run
  **seatbelt** sandbox" (Loadout `app.py` at 6f221994, ~L9930). The agent env was not read,
  because it holds the token.
* The `io.github.wmetcalf.wtwg0` LaunchDaemon runs `/opt/william-tells/bin/wtwg0-watchdog` every
  30 s. It (a) pins /32 routes for 172.18.101.15 and 64.239.105.163 via the LAN gateway, but only
  when en0 sits on 172.18.100.0/24, and (b) restarts the tunnel **only if the interface is
  missing**. It never checks handshake age. That is why a live but dead tunnel raised nothing.
* **The outage is still live.** On toolz2, `wg show wtwg0` reports peer 10.78.0.2's last
  handshake about 23 h ago, from endpoint 172.18.100.179. The Mac is now 172.18.100.132. From
  the Mac, TCP to 172.18.101.15:22 and :8005 does not connect, and ping fails, even though the
  route is pinned via en0. That fits a path or firewall rule keyed on the old address. Nothing
  was changed on either host.
* toolz2's `williamtells-bb` stack runs **blastbox 0.1.48**. `GET /v1/nodes/challenge` answers
  404, so that stack has no PKI and the claim routes are not mounted (`node_claim.py:588-594`).
  Prometheus and Alertmanager are not running on toolz2.

### 2.2 Push path (static pool, today)

* The dispatcher claims from Postgres and picks a box from `BLASTBOX_STATIC_WORKERS`
  (`static_pool.py:10`). It then POSTs raw input to `/detonate?name=` with allowlisted params in
  `X-Blastbox-Params` (`remote_http.py:783-790`) and gets back an `application/x-tar` of
  `metadata.json` plus the declared artifacts (`http_agent.py:14-24`). It refuses redirects
  (`remote_http.py:50`) and extracts with `_safe_extract_tar` (`remote_http.py:671`).
* Caps reach the worker as dispatcher-owned `BLASTBOX_MAX_*` merged last into params
  (`dispatch.py:1369-1378`). The worker rebuilds `Limits` inside that env (`http_agent.py:460-463`).
  Net posture reaches it as `BLASTBOX_NET_EGRESS` (`dispatch.py:2981`). A Mac advertises
  `egress:false` on `/healthz`.
* The trust gate is `validate_worker_output` (`trust.py:33`). It re-seals every artifact
  hash from disk, discards the worker's hashes, checks the engine and the `input_sha256` round
  trip, and enforces caps. The dispatcher then signs the ES256 execution receipt
  `attestation.json` (`attest.py:1-45`, `attest_wire.py:26-28,49`). The receipt omits
  `net_policy_effective` on every remote tier, because the signer did not enforce it.
* Reachability comes from worker-link: the worker dials `wtwg0` (udp/51822, 10.78.0.0/24) and the
  dispatcher reaches `https://10.78.0.x:8765` through it (`worker_link.py:1-10`). Handshake age is
  shown only when someone runs `worker-link status` (`worker_link_apply.py:1113-1170`).

**There is no "signed job bundle" in blastbox.** ADR 002's phrase has no implementation. A job
is a `Job` row (`jobs/base.py:29-80`). On the push path it travels as raw bytes plus params
over mTLS. On the pull path it travels as `job.to_dict()` plus an HMAC claim receipt. The only
signatures in the flow are the node's ECDSA proof of possession and the dispatcher's
receipt. This design does not invent a bundle (§6.2 says what stands in for one).

### 2.3 Pull path (#178/#181/#183, mounted only when a PKI exists)

| step | wire | code |
|---|---|---|
| challenge | `GET /v1/nodes/challenge` → `{challenge, expires_in: 60, scope: "claim-next"}`. `challenge = repr(expiry) + ":" + hex HMAC-SHA256(secret, "blastbox/node-challenge/v1"‖0‖scope‖0‖repr(expiry))` | `node_claim.py:609-627`, `node_auth.py:50-59,371-397` |
| session | `POST /v1/nodes/session {cert_pem, challenge, signature}`. The signature is base64 DER ECDSA-P256-SHA256 over `"blastbox/node-claim/v1"‖0‖challenge‖0‖scope‖0‖node_id`, and the server rebuilds `node_id` from the verified cert. → `{token, expires_in: 600, node_id}`. Token = `node_id:repr(expiry):hexmac` | `node_claim.py:668-704`, `node_auth.py:268-296,418-445,448-499` |
| claim | `POST /v1/nodes/claim {engine?, exclude[≤256]}` + header `x-blastbox-node-session`. `claimant_tier` → 400. → 200 `{job, node_id, receipt}`, or 204 for none, 401 to re-handshake, 403 for refused (one message) | `node_claim.py:94,407-432,707-878` |
| read | `GET /v1/nodes/jobs/{id}` with `x-blastbox-claim-id`, `x-blastbox-receipt`, and `…/disposition` | `node_claim.py:1293-1337` |
| write | `POST /v1/nodes/jobs/{id} {claim_id, receipt, fields, expect_status?}`. Fields are allowlisted, and the write is CAS-fenced on (status, claim_id). 409 means lost | `node_claim.py:107-116,1191-1290,1339-1385` |
| backlog | `GET /v1/nodes/backlog` → `{queued, engines}` | `node_claim.py:1003-1059` |

Receipt = hex HMAC(secret, `"blastbox/claim-receipt/v1"‖0‖job_id‖0‖claim_id‖0‖node_id`)
(`node_auth.py:325-348`). The claim id carries the `node:` prefix (`jobs/base.py:216`).
Grants are re-resolved from the ingress host's own cert directory on every request, cached
for at most 15 s (`node_claim.py:227,651-666`). The API key does not apply on `/v1/nodes/`
(`middleware.py:148`). Node certs are P-256 with a critical private EKU `OID_NODE_AUTH` and
never `clientAuth`, so a node cert cannot do TLS client auth (`pki.py:61-71`,
`node_auth.py:10-21`).

**What the pull path assumes about a node, and why that blocks a Go agent.** Today's node is
a full Python dispatcher with `HttpJobStore` (`http_store.py:120`):

1. **It fetches input from the shared blob store** by `input_sha256` (`dispatch.py:3297`).
   `BLASTBOX_BLOB_URL=s3://…` is required (DEPLOYMENT.md, credential-less node section). That
   puts bucket credentials on the node. The node can then read every sample and overwrite
   every result.
2. **It runs the trust gate and signs the receipt itself.** That puts the attestation key on
   the very host §5 of the federation spec calls untrusted.
3. **Nothing reports liveness.** `node_registry` is "NOT YET WIRED" (`node_registry.py:3`).
   No metric names a node. The only backstop is the opt-in reclaim sweep
   (`node_reclaim.py:59-64,263`), which fails orphaned jobs after ≥900 s and says nothing about
   the node.
4. **Enrolment generates the node key on the CA host and requires a WireGuard key.**
   `issue_node` generates the key (`pki.py:258`), refuses a missing `wg_pubkey` (`pki.py:254`),
   and `node_identity` rejects a cert without one (`pki.py:439`). There is no renewal path, and
   a hardened ingress holds no CA key (`cli.py:274`).
5. **The claim hands over `job.to_dict()`** (`node_claim.py:870`), which includes `result_dir`
   (an ingress-internal path) and the full `params`. That is harmless for a co-operating Python
   dispatcher, but it is more than an untrusted agent needs.

## 3. Approaches

### 3.1 Protocol

**A. Speak the existing node routes exactly as they are.** The Go agent becomes a port of
`HttpJobStore` plus the dispatcher's terminal writes.

* For: no server change.
* Against: it inherits all of §2.3(1-2). Every node would hold S3 credentials and an attest
  key, and the Go agent would need its own copy of `trust.py`, envelope parsing and receipt
  signing. Those are the hostile-output validator and the signed contract with Loadout. A
  second implementation of either is a drift and escalation surface. toolz2's williamtells
  stack also has no S3 at all (local blob store), so A cannot run there without a new
  dependency.
* **Rejected.**

**B. Keep identity, session and claim exactly as they are. Add a narrow node data plane.**
The agent uses `/challenge`, `/session`, `/claim` and `/jobs/{id}` (for fail and release) as
they exist today. Four additions carry what A would have smuggled through S3:

* stream the input,
* upload the result tar,
* heartbeat,
* an additive `run` block on the claim response.

Trust gate, re-seal and receipt run on the control plane, in the process that already holds
the attest key.

* For: the node holds one P-256 key and an ingress CA. A refusal is prevention, not advice.
  The Go surface is HTTP, ECDSA, tar and exec, all auditable. The hard-won parts are reused
  verbatim: the claim walk, refusal memo, CAS fencing and field allowlist.
* Against: server work (§6.4, §6.5), and the result now crosses the ingress.
* **Recommended.**

**C. Keep push and fix the alarm.** Teach the watchdog and the dispatcher to alarm on
handshake age.

* For: this is the cheapest stopgap. Its alerting half (§10) is worth doing anyway.
* Against: it keeps WireGuard, the inbound port, SAN-pinned certs and Python on the Mac, and
  it does not fix an address-keyed path.
* **Rejected as the target.** Its alerting is folded into §10.

### 3.2 Where the engine runs

**E1. The agent execs a local command under a sandbox step it owns.** It applies the
platform sandbox itself (seatbelt on macOS, nsjail on Linux) and checks a confinement proof
before every run. The engine is a CLI that reads one input and writes `metadata.json` plus
artifacts, or prints a payload-only envelope to stdout.

* For: one process, the sandbox is owned by the auditable binary, and the same contract holds
  on every OS.
* **Recommended.**

**E2. The agent shims to a local engine agent over loopback.** For example, it forwards to
`wtqrk-worker` on 127.0.0.1.

* For: fastest migration, and the Swift sandbox stays as it is.
* Against: two daemons, a loopback HTTP hop, and the sandbox outside the audited binary.
* **Allowed only as a migration crutch.** Not the target.

**E3. The agent drives blastbox's Python worker SDK.** Rejected: it brings Python back.

### 3.3 The macOS sandbox, and the "never weaker" floor

The brief says "App Sandbox on macOS". blastbox's own design says App Sandbox is **not**
stronger. It is Seatbelt with Apple's general application profile, while `seatbelt` is a
per-run `(deny default)` profile and is "strictly narrower" (`2026-10-10-macos-sandbox-design.md`,
"Why seatbelt is the default"). Loadout records today's Mac as seatbelt. App Sandbox alone
would therefore be **weaker** than today. Recommendation:

* **macOS floor = seatbelt.** The agent runs `/usr/bin/sandbox-exec -p <profile>` with the
  same profile `worker/sandbox/seatbelt.py` generates. That needs no cgo. The profile text is a
  conformance vector (§8), so Go cannot generate a looser one than Python.
* **App Sandbox is an extra layer, never a substitute.** That means `wtqrk-scan`'s own ad-hoc
  re-signed slots (`QRSandbox/Slots.swift`) and the image passed as a stdin fd. Whether an App
  Sandbox exec nests under `sandbox-exec` needs a spike (Q1).
* **Linux floor = nsjail.** It provides user, mount, PID, IPC, UTS and net namespaces with no
  network, a read-only bind of the engine, tmpfs scratch, seccomp from
  `worker/sandbox/seccomp_denylist.py`, and rlimits plus a cgroup v2 memory cap. The config is
  a conformance vector.
* **The floor is declared per engine** in the agent config (`sandbox = "seatbelt"`,
  `min_sandbox = "seatbelt"`, plus accelerator grants `ane`/`gpu` as in seatbelt.py). The
  agent refuses to start an engine configured below its floor.
* **Confinement proof before claiming.** At start and every 10 min, the agent runs a probe
  under the engine's exact sandbox. The probe must fail to read a canary file outside its
  grants, fail to connect to a loopback listener the agent opens, and fail to write outside
  scratch. For williamtells, `wtqrk-scan probe --read --connect` already exists. If the proof
  fails, the agent stops claiming and the heartbeat reports `selftest:false`. This mirrors
  `http_agent`'s self-test and 503.

## 4. Recommendation

1. **B plus E1.** Reuse `/challenge`, `/session` and `/claim` byte for byte. Add input stream,
   result upload, heartbeat and a `run` block. Trust gate, re-seal and ES256 receipt stay on the
   control plane, so the node holds no DB, blob or attest secret.
2. **The sandbox belongs to the agent.** macOS uses seatbelt deny-default as the floor, with App
   Sandbox only as an added layer. Linux uses nsjail. A confinement probe gates every claim.
3. **Enrol by CSR.** The key is generated on the node. Node-info v2 makes `wg` optional. Certs
   last 7 days, renewal is online, and revocation is "remove the cert / stop renewing"
   (effective in ≤15 s).
4. **Liveness is a control-plane duty.** Last heartbeat and last claim are recorded per
   enrolled node. "Enrolled but silent" and "engine queued with no live node" both alert.
5. **Mac first.** The Go agent runs alongside the current agent on the same queue, then the
   static-pool dispatcher is cut over, with a one-command rollback. `wtwg0` is retired, but its
   route pinning is kept.

## 5. The agent in one paragraph

`blastbox-agent run --config <path>` loads a TOML config. The config gives the ingress URL,
the CA path, the cert and key paths, a state dir, and one entry per engine (name, argv
template, sandbox, floor, accelerators, slots). The agent verifies its own cert's expiry and
EKU, runs the confinement probes, and opens a session. It then loops: heartbeat every 30 s;
for each free slot, claim (idle back-off 2 s, 5xx/network back-off exponential to 30 s with
jitter), stream the input to `state/jobs/<id>/in`, verify its sha256, run the sandboxed
command with a hard deadline, tar the output, upload it, wipe the scratch. Each job runs in
its own process group. The agent kills the group at the deadline and polls memory with
`ps -o rss=` on darwin (no cgo, and RLIMIT_AS is not enforced there) or a cgroup cap on Linux.
It follows no redirects, sets no proxy, and sends no request anywhere but the ingress origin.

## 6. Wire protocol (v1)

### 6.1 Transport

* HTTPS only, TLS ≥1.2 with server auth only. The root pool is **only** the configured ingress
  CA file, not system roots. The SAN must match the configured host. A 3xx is a failure.
* `User-Agent: blastbox-agent/<semver> (<goos>/<goarch>)`. No API key: `/v1/nodes/` is exempt.
* Session header `x-blastbox-node-session`. Per-job headers `x-blastbox-claim-id` and
  `x-blastbox-receipt`. Proof goes in headers, never in query strings (`node_claim.py:1298`).

### 6.2 Identity, session and claim (unchanged)

As in §2.3. The agent treats the challenge, token and receipt as **opaque strings**. They
contain Python `repr(float)`, and the agent never parses or re-renders them. It signs the
exact bytes `"blastbox/node-claim/v1"‖0x00‖challenge‖0x00‖"claim-next"‖0x00‖node_id`. Here
`node_id` is the cert CN, and the agent checks it against node-info before use. The signature
is `ecdsa.SignASN1` (DER) and is sent base64 std-padded. The agent re-handshakes on 401, once
per request, and renews 30 s before `expires_in`, as `http_store.py:84` does. 403 means "not
granted" and is never retried hot.

The agent claims with `{"engine": "<name>"}` per engine with a free slot. It never sends
`claimant_tier`. `exclude` carries ids it is locally cooling down from.

**Additive `run` block on the 200 claim response** (server change, old clients ignore it
because `http_store.py:346` reads only `body["job"]`). It stands in for a "job bundle". It is
server-authored and bound to the job by the receipt, the same way every later request is:

```text
run.deadline_s            hard wall clock for the sandboxed run (engine timeout + grace)
run.limits                {max_input, max_metadata, max_artifact, max_total_artifacts, max_artifacts}  (the control plane's Limits)
run.network               "none"  (v1: anything else → agent fails the job unstarted)
run.params                the engine-allowlisted params, minus every BLASTBOX_* key
run.input                 {sha256, bytes, filename}  (filename already sanitised)
```

The agent enforces `run.limits` locally as defence in depth. The control plane enforces them
again and that check is authoritative. Also proposed: the claim stops returning `result_dir`
(§2.3 item 5).

### 6.3 Input: new route

`GET /v1/nodes/jobs/{id}/input` with session, claim-id and receipt headers. It is authorised
by `_owned_job` (`node_claim.py:1081`) plus `status == running`. It returns 200
`application/octet-stream`, `Content-Length`, and `x-blastbox-input-sha256`. It streams from
the local spool or the blob store via `BlobStore.get_sample` on the **control plane**. The
agent aborts beyond `run.limits.max_input` and refuses a hash mismatch. A refusal is the
`_REFUSED` 403. A second fetch is allowed, because the receipt is the gate and nothing else
is learned.

### 6.4 Result: new route

`PUT /v1/nodes/jobs/{id}/result` with session, claim-id and receipt headers. Body:
`application/x-tar` in **the same layout `/detonate` returns**. That is regular files only,
`metadata.json` at the root, and the declared artifact paths, with no links or devices.
Optional header `x-blastbox-node-observation` (§6.7).

The server does:

1. Caps on bytes and members, as `remote_http.py:805-816` computes them.
2. Extract into a fresh quarantine dir with `_safe_extract_tar`.
3. Hand the dir to the finalizer (Q2), which runs `validate_worker_output` against
   `job.engine` and `job.input_sha256`, the engine contract check, `put_output`, and
   `build_receipt` (`attest.py:355`). The receipt records what the **signer** observed: the
   input it served, the metadata it re-sealed, `worker_runtime`/`worker_tier` as node-reported,
   and **no** network fields.
4. CAS `running→done` on the claim id.

It answers 200 `{status: "done"}`. Otherwise it answers 422 `{status: "failed", reason}`, and
the job is FAILED with a sanitised error. 409 means the claim was lost. The upload is
idempotent per (job, claim): a retry after a lost response returns the stored outcome.

### 6.5 Fail and release (existing route, constrained use)

The agent writes through `POST /v1/nodes/jobs/{id}` in exactly two shapes:

* **Release, before the input reached a sandbox:** `{status: "queued", claim_id: null}`.
  Examples: the probe went red, the input fetch failed, `run.network != none`.
* **Fail, after it did:** `{status: "failed", error, finished_at, expires_at}`, sent when no
  envelope exists. Examples: the sandbox could not start, or the run was killed at the deadline.

A sample that has been handed to a sandbox is never released. This is the same rule the
reclaim sweep follows: no re-detonation (`node_reclaim.py:17-20`). Timestamps stay inside
`MAX_FUTURE_SKEW_S` (`node_claim.py:233`).

### 6.6 Heartbeat: new route. Lease renewal deferred.

`POST /v1/nodes/heartbeat` with the session header and body:

```text
agent_version, binary_sha256, goos, goarch, started_at
engines[]         {name, sandbox, floor, slots, busy, selftest_ok, selftest_at}
in_flight[]       {job_id, claim_id, started_at, deadline_at}
cert_not_after
```

It returns 200 `{server_time, min_agent_version, heartbeat_s}`. The agent logs skew greater
than 60 s and stops claiming when the version is below the floor. Everything in the body is a
**claim** (federation §4.3), used for observability and never for authorisation.

v1 has no `renew`. A run's ceiling is `run.deadline_s`, and the operator sets
`BLASTBOX_NODE_CLAIM_RECLAIM_AFTER_S` above the largest deadline (the 900 s floor comfortably
covers williamtells' 120 s). An engine needing longer runs gets a fenced `renew` that pushes
`started_at` forward, as a follow-up.

### 6.7 Node observation (optional, v1.1)

The agent signs `canonical({v:1, job_id, claim_id, node_id, input_sha256, metadata_sha256,
sandbox, started_at_ms, finished_at_ms})` with its node key. The encoding is ES256 in exactly
the form of `attest_wire.canonical`: sorted keys, `(",",":")` separators, `ensure_ascii`, no
floats. The control plane verifies it against the session's cert and records its sha256 in
the receipt. It proves which **key** reported the run, not that the run was honest.

## 7. What the agent seals

The agent produces `metadata.json` exactly as the engine wrote it, plus artifacts. It fills
artifact `sha256` and `bytes` so the envelope parses, but the control plane discards them and
re-seals (`trust.py` step 4). The agent never parses engine payloads. For williamtells, E1
needs the scanner to emit the envelope itself, so the `wtqrk.scan/1` → envelope mapping runs
**inside** the sandbox. That needs either a new `wtqrk-scan blastbox -` mode printing the
envelope on stdout, or a tiny sandboxed adapter (Q3). Today that mapping lives in Swift
(`BlastboxEnvelope.swift`) and Python (`blastbox_engine.py`).

## 8. Conformance vectors

`conformance/v1/` in the blastbox repo. Python is the generator and the reference. The Go
suite consumes it. CI on **both** sides fails if a vector changes without a version bump.

```text
challenge.json          fixed secret+time → challenge string; valid/expired/wrong-scope/malformed verdicts
signing_payload.json    (challenge, scope, node_id) → exact payload bytes (hex)
ecdsa_cross.json        Python-signed payloads Go must verify; Go-signed payloads (committed by the Go job) Python must verify
session_token.json      token mint + verify cases (expiry, tamper, ':' in node_id)
receipt.json            (job_id, claim_id, node_id, secret) → receipt; mismatch cases
node_certs/             v1 and v2 node certs + CA; negatives: wrong EKU, clientAuth, CN≠node_id, expired, RSA key, missing/garbled node-info
claim_responses/        200/204/401/403 bodies incl. the run block → expected agent decision
input_stream/           good, short, long, hash-mismatch, 3xx → accept/abort
result_tars/            tars the Go writer emits for fixed trees; adversarial tars (.., abs path, symlink, hardlink, device, dup member, over-cap) → server verdict
envelope_seal/          output trees → sealed metadata.json (artifact sha256/bytes)
canonical_json.json     attest_wire.canonical edge cases: non-BMP, control chars, '<>&', key ordering, float rejection
node_observation.json   canonical doc → signature verifies (both directions)
sandbox/seatbelt/       request (paths, accelerators) → profile text, golden vs worker/sandbox/seatbelt.py
sandbox/nsjail/         request → nsjail config, golden vs the Python generator
transcripts/            one full HTTP exchange per scenario (happy, refused, lost-claim 409, session expiry mid-upload)
```

Two of these exist because Go's defaults differ from Python's.

* `encoding/json` escapes `<>&` and does not reproduce `ensure_ascii` surrogate pairs.
* ECDSA signatures are randomised, so vectors check payload bytes exactly and check
  signatures by cross-verification, never by byte equality.

CI also runs the Go agent end to end against a real `blastbox serve`: temp PKI, SQLite, local
blobs, a trivial engine, on linux (nsjail) and macos-14 arm64 (seatbelt) runners.

## 9. Keys, certs, enrolment, rotation, revocation

* **Storage.**
  * macOS: `~/Library/Application Support/blastbox-agent/` (0700) holds `node.key` (0600,
    PKCS#8 P-256), `node.crt` and `ca.crt`, owned by the per-user LaunchAgent's user. It must
    be per-user because sandbox launch fails from the system domain (william-tells README).
  * Linux: systemd `StateDirectory=blastbox-agent` (0700) under a dedicated user.
  * The agent refuses to start if the key is group- or world-readable or a symlink. It never
    logs key material.
  * Secure Enclave or TPM keys need cgo or a helper (Q8).
* **Enrolment** (server change). `blastbox-agent enrol --node-id <id>` writes the key and a CSR
  on the node. Only the CSR moves. On the CA host, `blastbox pki sign-node-csr --csr … --engines
  williamtells --tiers none --days 7` stamps the EKU and node-info from **CLI flags, never from
  the CSR**.
* **Node-info v2** makes `wg` optional (`pki.py:132,439`). `node_identity` keeps accepting v1.
  The cert is copied to the node and **to every ingress host's PKI dir** (DEPLOYMENT.md: grants
  resolve from the ingress host).
* **Rotation.** At ⅓ of lifetime remaining, the agent `POST`s a fresh CSR to
  `/v1/nodes/renew` under its session. The ingress has no CA key, so it only queues the CSR. A
  CA-holding timer (`blastbox pki renew-pending`) signs queued CSRs with **the grants of the
  node's current cert**. The agent polls for the new cert and swaps it atomically. The heartbeat
  reports `cert_not_after`, and the control plane alerts at T-48 h. Q4 covers whether to build
  this or accept manual weekly re-issue for one Mac.
* **Revocation.** Delete the cert from the ingress PKI dir. Every node route then 403s within
  the 15 s grants cache (`node_claim.py:227`), whatever the session. If the cert is not renewed,
  it lapses within 7 days on its own. The challenge key rotates with `blastbox claim-key reset`
  (`node_auth.py:234`).

## 10. Liveness and alerting

The control plane derives liveness from what it can see, not from what nodes publish about
peers:

* **Record.** Each heartbeat and each claim attempt (including 204) writes
  `last_heartbeat_at` and `last_claim_at` per node id into `node_registry`. This wires the SQL
  registry that is "NOT YET WIRED".
* **Expected set = enrolled certs** in the ingress PKI dir (`fleet_grants`). A node is expected
  to exist because it holds a valid cert, not because it said hello.
* **Alerts.** Each alert is logged at ERROR once per state change, exported as a gauge, and
  pushed to a sink (Q6):
  * `node_silent`: enrolled, not expired, and no heartbeat for > 3 × `heartbeat_s` (default
    90 s). This would have fired 90 s into yesterday's outage.
  * `node_unhealthy`: heartbeats arrive, but `selftest_ok=false` or no engine is ready.
  * `engine_orphaned`: QUEUED work for an engine older than N s (default 300) with **no** live
    node granted it. This is the user-visible symptom, and it fires even if node bookkeeping is
    wrong.
  * `cert_expiring`: less than 48 h to `not_after`.
* **Metrics** on `/metrics`:
  `blastbox_node_last_heartbeat_seconds{node}`, `blastbox_node_last_claim_seconds{node}`,
  `blastbox_node_selftest_ok{node,engine}`, `blastbox_node_cert_expiry_seconds{node}`,
  `blastbox_engine_oldest_queued_seconds{engine}`.
* Until the agent ships, approach C's half: `worker-link` gets a `--check` exit code on
  handshake age, so a timer can alarm today.

## 11. Network, and what happens to `wtwg0`

* The agent needs only TCP from the node to the ingress origin (toolz2 `:8005`). Today that
  path **does not work from the Mac** (§2.1). Restoring it is a network decision for Will
  (Q5). Nothing here changes a firewall.
* **Pull removes one failure mode, not all of them.** It removes the inbound direction and the
  tunnel. It does not stop a path that is keyed on the node's address from breaking when that
  address changes. §10 is what turns that into an alert instead of 11 silent hours.
* **`wtwg0` after cutover.**
  * Remove peer 10.78.0.2 on toolz2 with `worker-link` peer removal. Other peers (10.78.0.3/.4)
    stay.
  * Unload `io.github.wmetcalf.wtwg0` on the Mac.
  * **First, move `pin_private_service_routes` into its own LaunchDaemon.** It keeps toolz2
    traffic off the Mac's VPN, and the agent needs that just as the tunnel did.
  * Keep the rollback window (§14) before deleting configs.

## 12. Safety Label and trust-boundary fields

The job row and receipt are what Loadout reads. They must carry:

```text
worker_runtime     the sandbox backend the agent ran: "seatbelt" | "appsandbox+seatbelt" | "nsjail"   (node-reported; Loadout files it under worker_reported, attested=false)
worker_tier        "node-agent"
node_id            the cert CN of the node that held the claim   (receipt field; new)
node_cert_sha256   sha256 of that cert DER                        (receipt field; new)
node_observation   sha256 of the signed node observation, when present   (receipt field; new, v1.1)
net                no net_policy_effective / net_exit: the signer did not enforce posture (as every remote tier today)
input_sha256 / metadata_sha256   observed by the control plane itself
```

On the Loadout side, the boundary block is unchanged for the Mac. `mac-pool` stays
`provider_type: loadout_hosted`, `infra_owner: loadout`, `allowed_network: ["none"]`, with
`data_left_customer_boundary` and `raw_sample_visible_to_loadout` as today: the raw sample
still reaches the Mac. A third-party node would be a different pool with its own
`provider_type`. That is the federation spec's step 5 and is out of scope.

## 13. Update and distribution

* Built in CI with a pinned Go toolchain, `CGO_ENABLED=0 -trimpath -buildvcs=true`, for 4
  targets. Builds are reproducible: CI builds twice and compares hashes. darwin/arm64 binaries
  carry the linker's ad-hoc signature.
* A release is tagged `agent-vX.Y.Z` and ships the binaries, `SHA256SUMS` and a detached
  signature over `SHA256SUMS` (Q7). It also ships a SBOM and the conformance vectors digest it
  passed.
* Install is `install.sh --version X.Y.Z --sha256 <pinned>`. It checks the pinned hash and the
  release signature, installs to `/opt/blastbox-agent/<ver>/`, and flips a `current` symlink.
  Rollback flips it back. Binaries are copied, not browser-downloaded, so no quarantine xattr
  is set.
* No self-update. The heartbeat reports `binary_sha256`, and the control plane alerts on a node
  whose hash is not a released one. `min_agent_version` stops outdated agents claiming. Both
  are self-reported hygiene, not security.
* nsjail on Linux is a separately pinned dependency (version and sha256 in the agent config),
  verified at start.

## 14. Migration: the Mac first

0. **Prerequisites (toolz2).**
   * Upgrade `williamtells-bb` from 0.1.48 to the release with §6 routes and the finalizer.
   * `blastbox pki init` for that stack.
   * Set `BLASTBOX_NODE_CLAIM_RECLAIM_AFTER_S=900`.
   * Restore Mac→`:8005` (Q5).
   * Enrol `mac-wt1` with grants `engines=[williamtells], tiers=[none]`.
1. **Shadow.**
   * Install the agent beside the existing LaunchAgent, with `claim = false`. It handshakes,
     heartbeats and runs probes.
   * Prove the alerts by stopping it and watching `node_silent` fire.
   * Nothing is claimed.
2. **Alongside.** Set `claim = true`. The static-pool dispatcher (push via `wtwg0`) and the
   agent (pull) now drain **the same queue**, and each job goes to whichever claims first.
   Gates:
   * the william-tells corpus through both paths with identical payloads;
   * the confinement probes green;
   * zero `node_claim` refusals;
   * at least 24 h without an alert.
3. **Cut over.** `docker compose stop dispatcher` (stop, never `run`) and start the finalizer
   service in its place. The pull agent now takes every job. The old LaunchAgent stays loaded
   but idle.
4. **Rollback (any time ≤7 days).**
   * Start the dispatcher again.
   * Delete `mac-wt1`'s cert from the ingress PKI dir (claims refused within 15 s), or
     `launchctl bootout` the agent.
   * In-flight node jobs are failed by the reclaim sweep, never re-run.
5. **Retire.**
   * Unload the old agent and remove its venv.
   * §11 `wtwg0` steps.
   * Drop `BLASTBOX_STATIC_WORKERS`.

## 15. What Loadout needs to change

* **Required: nothing.** Loadout submits to the same ingress `/v1/jobs` and reads the same
  envelope and receipt.
* **Before receipt fields are added (§12):** confirm Loadout's receipt verifier accepts unknown
  keys inside the signed doc. Otherwise ship the new fields behind a receipt `v` bump.
* **Optional:**
  * show `node_id` and `worker_runtime` on the RunCard;
  * update the `mac-pool` seed comment ("blastbox `static` dispatcher" becomes "pull agent");
  * when §6.7 lands, Loadout may verify the node observation and flip `attested` for runtime.
    That is a separate decision.

## 16. Test strategy

* **Go unit tests:** wire client, state machine (claim → input → run → upload/fail/release),
  back-off, session renewal, config and permission refusals.
* **Conformance (§8):** both languages in both CIs.
* **Server tests (Python):**
  * new routes: authorisation matrix (wrong node, stale claim, revoked cert, expired session,
    job not running);
  * upload adversarial tars;
  * finalizer idempotency;
  * the `run` block contents;
  * `result_dir` no longer handed out;
  * liveness state machine on a simulated clock.
* **End to end in CI:** a real `serve` with the Go agent on linux and macOS runners. Scenarios:
  happy path; kill -9 mid-run (reclaim fails the job, no re-run); cert deleted mid-run (upload
  403, job reclaimed); ingress restart mid-upload; clock skew ±10 min; 3xx and oversize from a
  hostile test server.
* **Confinement:** per-platform probe tests that must fail. A canary file read, a loopback
  connect, a write outside scratch, and network to 1.1.1.1 must each fail under the generated
  profile.
* **Corpus gate before done:** the william-tells corpus through push and pull with payloads
  diffed, on the real Mac, before step 3 of §14.

## 17. Open questions only Will can answer

1. **macOS floor.** The brief says App Sandbox. Today's Mac is seatbelt, and blastbox's own
   doc says App Sandbox is broader. Do you accept seatbelt as the floor, with App Sandbox only
   as an added layer (pending a nesting spike)?
2. **Who finalises.** Should the trust gate, `put_output` and receipt signing run in a separate
   `blastbox node-finalizer` (holds DB, blobs and attest key, never claims), as recommended?
   Or in the ingress, which then needs the attest key the williamtells stack deliberately keeps
   off the API container?
3. **The williamtells envelope inside the sandbox.** Add a `wtqrk-scan blastbox` mode, or ship
   a small sandboxed adapter?
4. **Renewal.** Build online CSR renewal (`/v1/nodes/renew` plus a CA-host timer), or accept
   manual weekly re-issue while there is one Mac?
5. **Network path.** Mac→toolz2 TCP is down right now (WG peer last handshake about 23 h ago,
   from the old .179 address). Which fix: a DHCP reservation, or a subnet-wide rule for
   `:8005`? Also, is the live outage something you want fixed now, separately from this design?
6. **Alert sink.** Matrix via the local Synapse `@loadout-bot`, a webhook, or Loadout
   `/system/status`? Are the defaults (90 s silent, 300 s orphaned) right?
7. **Release signing.** An offline minisign/ed25519 key you hold, or cosign keyless via
   GitHub OIDC?
8. **Node key on macOS.** Is a 0600 file in the user's Application Support acceptable for v1,
   or is the Secure Enclave required (cgo or a signed Swift helper)?
9. **Code home.** Put `agent/` in the blastbox repo (vectors next to the Python, one PR changes
   both), or a separate repo pinning the vectors by commit and hash?
10. **Which agent is being replaced.** The brief names Swift `wtqrk-worker`, but the Mac runs
    the Python `legacy_agent.py` (blastbox_operator, SDK pinned to 0.1.50). Is that operator
    wrapper also yours to retire, or does it serve something else (`org.blastbox.operator` is
    loaded too)?
11. **Node-info v2.** Make `wg` optional (recommended), or keep v1 and stamp an unused
    WireGuard key?

## 18. Residual risk, stated

* A node holding its key is that node. Enrolment, the 7-day lifetime and revocation within
  15 s bound this. Nothing removes it.
* The control plane cannot verify that a node ran the sandbox it reports. `worker_runtime` is a
  claim, and the label says so (`attested=false`). The confinement probe protects an honest
  node from its own misconfiguration. It is no defence against a hostile node.
* Results now cross the ingress. Upload caps and quarantine extraction are new attack surface
  on the control plane. They reuse the push path's extractor and limits rather than new code.
