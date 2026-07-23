# Distributed blob storage — design

Status: **proposed**
Date: 2026-07-21
Scope: `blastbox.host` (ingress, dispatch, retention) + new `blastbox.host.blobs`

## Problem

Today a job's bytes live on one host's filesystem. `BLASTBOX_JOB_ROOT` is a plain
path, and `deploy/docker/docker-compose.yml` documents the binding constraint:

> Host-CONSISTENT path, NOT a named volume: the dispatcher launches workers whose
> job-dir bind-mounts are resolved by the host docker daemon on the HOST, so
> job_root must exist at the SAME path on host + container.

So the ingress that accepts an upload and the dispatcher that runs it must be the
same machine. That forces a shared-nothing fleet: every node runs a full stack with
its own database, and results scatter across N stores. It blocks three things we
want:

1. **Role separation** — serving the API from 2 nodes while workers run elsewhere.
2. **Firewalled / NAT'd workers** — spare hardware that cannot accept inbound
   connections and cannot mount a shared filesystem across a firewall.
3. **A shared queue** — `claim_next()` already does lock-free multi-node dispatch
   via `FOR UPDATE SKIP LOCKED`, but a claimant that cannot read the input bytes
   cannot use it.

NFS was considered and rejected: it needs portmapper plus several stateful ports,
behaves poorly across a firewall and NAT, and its failure mode (hung mounts, stale
handles) is worse than a retryable HTTP request.

### Measured constraints

From a 24k-file production run of the MalwareBazaar corpus on 2026-07-21:

| quantity | value |
|----------|-------|
| corpus (inputs) | 47 GB / 83,167 files |
| results (projected, 72,327 files) | ~113 GB |
| per-result size | median 48 KB, **mean 1.5 MB**, max 40 MB |
| sample naming | `<sha256>.<ext>` — already content-addressed |

Two consequences drive the design. **Results are ~2.4x larger than inputs**, so the
upload path from workers dominates bandwidth, not sample distribution. And results
are heavily skewed (median 48 KB vs mean 1.5 MB), so compression and not moving them
twice both matter.

## Goals

- A worker anywhere — behind a firewall or NAT — can execute a claimed job using
  **outbound connections only**.
- The **single-node deployment keeps working with zero configuration changes and no
  new dependencies**. This is a hard requirement, not a nice-to-have.
  Note this is a guarantee about EXTERNAL behaviour — submit, run, retrieve — and
  about dependencies. It is NOT a guarantee that bytes stay in the same place on
  disk: `job_root` becomes ephemeral per-job scratch and durable copies move under
  `blob_root` (see "LocalBlobStore is a real filesystem-backed store"). An operator
  sets nothing and sees no behavioural difference; the on-disk layout does change.
- No change to the Firecracker execution path or its isolation properties.

## Non-goals

- Replacing `job_root`. Firecracker bind-mounts need a real local path; the local
  job dir stays as the per-job working set. What changes is that it becomes purely
  ephemeral scratch — durable bytes live in the blob store in every mode.
- Cross-region replication, lifecycle policies, or a storage control plane. Out of
  scope; MinIO/S3 handle these natively if wanted later.
- Changing `claim_next()` semantics. They already work for this.

## Design

### A `BlobStore` abstraction selected by URL

Mirror the existing `blastbox.host.jobs.factory` pattern, which selects a JobStore
from `BLASTBOX_DATABASE_URL` (unset -> in-memory, `sqlite://` / `postgresql://` ->
SQL, `redis://` -> Redis). Reusing that idiom keeps configuration uniform and makes
the new knob predictable for anyone who has configured the job store.

```
BLASTBOX_BLOB_URL
  unset            -> LocalBlobStore   (default: today's behaviour, no new deps)
  s3://bucket/pfx  -> S3BlobStore      (MinIO or AWS S3)
```

```python
class BlobStore(Protocol):
    def put_sample(self, sha256: str, src: Path) -> str: ...   # -> key; no-op if present
    def get_sample(self, sha256: str, dest: Path) -> None: ...  # materialise locally
    def put_output(self, job_id: str, out_dir: Path) -> str: ...
    def open_output(self, job_id: str, name: str) -> BinaryIO: ...
    def delete_job(self, job_id: str) -> None: ...              # retention
```

**`LocalBlobStore` is a real filesystem-backed store**, not a no-op.

An earlier draft made it a no-op that merely verified the file already sitting in
`job_root/<job_id>/input/`, on the theory that this kept single-node behaviour
byte-identical. That was wrong, and it broke in two places at once:

1. **It is incompatible with the worker purge invariant.** Once a worker deletes its
   job dir on every terminal path, a store whose only copy *was* the job dir has
   nothing left to serve — results would vanish and a re-claim could never
   re-materialise its sample.
2. **It made the abstraction dishonest.** `LocalBlobStore.get_sample` could only ever
   fail; it was not an implementation of the protocol so much as a stub pretending to
   be one. That forced a mode-specific branch into the dispatcher (*"purge only if a
   remote store is configured"*), which encodes "am I colocated with my peers?" as "is
   S3 configured?" — two different questions that will drift apart.

So the local backend stores bytes for real, under a root **outside `job_root`**:

```
<blob_root>/samples/<input_sha256>      content-addressed, shared between jobs
<blob_root>/results/<job_id>/…          job-scoped
```

`BLASTBOX_BLOB_LOCAL_ROOT` selects it (default: `blobs` as a sibling of the job root).
This keeps the worker-purge invariant intact — everything under `job_root` is still
destroyed — while making re-materialisation always possible.

**The payoff is that mode 1 and mode 3 become the same code path.** The dispatcher
purges unconditionally, with no knowledge of which backend is configured and no
branch to rot. Single-node stops being a special case that only *looks* like the
distributed one.

What a single-node operator notices: nothing externally. Uploads, jobs, and result
retrieval behave exactly as before. What changes is *where bytes live on disk* —
`job_root` becomes ephemeral per-job scratch, and the durable copies live under
`blob_root`. That is a better arrangement independent of this feature, because it is
what makes `job_root` safe to put on tmpfs.

**Optional dependency, lazily imported.** `sql_store.py` already imports
`psycopg_pool` *inside* the postgres branch so sqlite users need not install it.
`S3BlobStore` imports `boto3`/`minio` the same way, so `pip install blastbox[host]`
gains no mandatory dependency. S3 support goes behind a `blastbox[s3]` extra.

### Content-addressed samples

Samples are keyed `samples/<job.input_sha256>` — the **hash the ingress computes over
the uploaded bytes**, never anything derived from the filename.

This distinction is load-bearing. Our MalwareBazaar corpus happens to be mostly
`<sha256>.<ext>`-named, but that is an artifact of one downloader, not a property of
the system: the same corpus also contains ~17k files with original names
(`PO_08312020.xls`), plus md5- and sha1-named ones, and any API client may upload a
file called anything at all. Keying off the filename would be wrong for most real
input and trivially spoofable by a caller.

The ingress already does the right thing — `ingress/app.py` streams the upload
through `hashlib.sha256` and assigns `job.input_sha256` — so content addressing costs
nothing new and holds for arbitrary filenames.

**Workers cache nothing. This is a security invariant, not an optimisation choice.**

An earlier draft had workers keep fetched samples to skip refetches. That is wrong
for this workload: a worker is a malware-analysis node, frequently spare hardware
(a laptop, an old desktop) that is not a hardened sample repository. Caching would
have every such box silently accumulate a malware corpus on local disk — a liability
and an incident waiting to happen, and precisely the outcome an operator adding
"spare compute" would not expect.

Therefore, on a worker:

- the job dir (**input and output**) is purged after the job reaches a terminal
  state and its output upload is confirmed;
- no sample survives between jobs, and no sample cache exists;
- `BLASTBOX_BLOB_KEEP_LOCAL` applies to the **head node only** and is ignored on
  workers, which have no configuration that lets them retain sample bytes.

**The purge is unconditional — including when a peer reclaims the job mid-flight.**
A worker that loses its claim still destroys its job dir. It must not leave bytes
behind "for the new owner": that only works when peers share a filesystem, which is
precisely the arrangement this design rejects, and it is an invisible coupling —
correctness would depend on co-location that nothing enforces. In a real fleet the
peer is on another host, so those bytes are simply orphaned malware with no retention
backstop (this worker never writes a terminal status, so `expires_at` is never set).

This is why every node — in every mode, including mode 2 — MUST have its OWN
private `job_root`, never one shared across nodes. `job_root` is ephemeral per-node
scratch, unconditionally purgeable BECAUSE nothing else can be reading it; a shared
`job_root` would make that false and turn this same unconditional purge into one peer
deleting another peer's ACTIVE job dir mid-flight. Nowhere in this design does
"shared filesystem" mean a shared `job_root` — see the mode-2 section below, where
the only thing a shared filesystem may back is the **blob store** (`blob_root`),
which is durable, content-addressed, and designed to be read from multiple nodes.

This is safe *because* the blob store can always re-materialise, in every mode — which
is the concrete reason `LocalBlobStore` had to become a real store rather than a
no-op. The two requirements are the same requirement.

`vm_dispatch.py` already unlinks the input after processing; this design makes that
guarantee explicit, extends it to the output, and forbids the cache that would
otherwise be the obvious optimisation.

**The cost is near zero for the primary workload.** In a corpus run each sample is
processed exactly once, so a cache would almost never hit; it only pays off on
re-runs of the same sample on the same node. We give up a benefit we largely do not
receive, and in exchange no malware persists on distributed hardware.

**Recommended: put `job_root` on tmpfs on workers** (these nodes already run
Firecracker slots out of `/tmp`). Then sample bytes never touch persistent storage at
all, and a power cycle is a guaranteed clean slate. This is a deployment
recommendation rather than an enforced requirement because not every worker has the
RAM headroom for it.

**The blob key and the local filename are deliberately decoupled:**

| | value | why |
|---|---|---|
| blob key | `samples/<input_sha256>` | content identity; dedupe and integrity |
| local path | `job_dir/input/<job.filename>` | engines type-detect on the extension |

`Job.filename` is a separate field (`jobs/base.py`: "sanitized input basename") and
`vm_dispatch.py:_input_path()` resolves the local path from it. So two uploads of
identical bytes under different names share **one** blob but each materialise under
their own name — which is both correct for the engines and free deduplication.

Integrity follows: a worker rehashes what it fetched and compares to the key, so a
corrupted or substituted object is detected before it reaches an engine. Note this
checks the *bytes*, independent of whatever the file is called.

**Ordering requirement.** `put_sample()` MUST succeed before the job becomes
claimable. Otherwise a worker can claim a job whose blob does not exist yet and is
forced down the release-and-retry path for a sample that was never missing — a
self-inflicted race that would look like object-store flakiness. Ingress therefore
uploads first and inserts the row as `queued` second.

Outputs are keyed `results/<job_id>/…` — job-scoped, not content-addressed, since
they are written once and read rarely.

### Data flow

Distributed mode (`BLASTBOX_BLOB_URL=s3://…`):

```
head node (blastbox serve)
  receive upload -> stream through sha256, write job_root/<id>/input/<filename>
                 -> put_sample(input_sha256)    -> s3://samples/<input_sha256>
                 -> THEN insert job row queued  -> postgres   (order matters: see above)

worker (behind a firewall; outbound only)
  claim_next(engine=<engines this node runs>)   -- outbound -> postgres:5432
  get_sample(input_sha256)                      -- outbound -> minio:443  (ALWAYS; no cache)
      -> materialise at job_dir/input/<job.filename>   (ORIGINAL name, not the hash)
      -> rehash and compare to the key
  run Firecracker microVM                        (UNCHANGED, local path)
  put_output(job_id, job_dir/output/)           -- outbound -> minio:443
  mark done                                     -- outbound -> postgres
  PURGE job_dir (input + output)                 <- mandatory; nothing persists here
```

Single-node mode (`BLASTBOX_BLOB_URL` unset) is byte-identical to today: `put_*`
verifies, `get_*` is a no-op, nothing leaves the box.

Only **two egress rules** are needed for a remote worker: postgres and the object
store. No inbound ports, so NAT and firewalls are irrelevant.

### Compression

`put_output` gzips on upload. Results are JSON-dominated and should compress 5-10x,
taking the projected 113 GB to roughly 15 GB. Given the measured mean of 1.5 MB per
result this is the single highest-leverage bandwidth decision, so it is on by default
(`BLASTBOX_BLOB_COMPRESS=1`) rather than opt-in.

### Failure handling

The important case is a worker that claims a job it then cannot materialise — the
object store is unreachable, or the object is missing.

**On `get_sample` failure the worker MUST release the claim back to `queued`, not
fail the job.** A fetch failure is a property of *this worker's* connectivity, not of
the sample; failing the job would permanently discard work because one node's link
was down. Releasing lets another node claim it. The `claim_id` CAS already makes this
safe against a stale owner (`base.py`: terminal writes CAS on `(status, claim_id)` so
a stale owner cannot clobber a RECLAIMED job).

To avoid a flapping worker repeatedly claiming and releasing the whole queue, a node
that fails N consecutive fetches marks itself unhealthy and stops claiming until a
probe succeeds.

`put_output` failure is different: the work is already done and discarding it is
expensive. Retry with backoff, and on persistent failure leave the job `RUNNING` for
the reclaim sweeper rather than losing the result.

This makes the object store a hard dependency for execution in distributed mode. That
is an accepted trade — but it is why the release-don't-fail rule above is mandatory
rather than advisory.

### Retention

The existing store-driven retention sweeper reaps `job_root/<job_id>` (see
`jobs/factory.py`). It gains a `delete_job()` call so blobs are reaped with the row.
Sample objects are content-addressed and shared between jobs, so they are **not**
deleted with a job; they age out on their own policy (or a MinIO lifecycle rule).

## Compatibility and migration

- Unset `BLASTBOX_BLOB_URL` -> current behaviour, no new dependency, no migration.
- Existing single-node deployments are unaffected; this is purely additive.
- A node may be switched to S3 by setting the URL and restarting; in-flight jobs
  complete under the old mode because the store is resolved per job.

## Testing

- `LocalBlobStore` conformance: the full existing test suite must pass unchanged with
  `BLASTBOX_BLOB_URL` unset — this is the regression gate for the simple path.
- Shared `BlobStore` contract tests run against both backends (MinIO in a container).
- Integrity: a tampered object fails the rehash check and does not reach an engine.
- **Naming independence**: upload the same bytes under several unrelated filenames
  (`invoice.doc`, `PO_08312020.xls`, a bare `<md5>`, and a name with no extension at
  all) and assert one blob is stored, each job materialises under its OWN filename,
  and every job succeeds. This is the regression test for the filename/key
  conflation — the corpus that motivated this design is only ~66% sha256-named.
- Ordering: a job row must never be `queued` before its blob exists; assert a worker
  never observes a claimable job whose sample is missing.
- **Shared-sample retention**: expiring one job must NOT delete a `samples/<hash>`
  blob another job still references. This is the highest-risk failure in the design —
  it silently breaks unrelated jobs — so it gets an explicit test rather than relying
  on the sweeper being written correctly.
- **Worker leaves nothing behind** (security invariant): after a job reaches a
  terminal state, assert the worker's `job_root` contains no trace of the sample —
  for the success path, the engine-failure path, the timeout path, AND the
  release-back-to-queued path. The failure paths matter most: they are where a purge
  is easiest to omit, and a sample abandoned on a laptop by an error path is exactly
  the outcome this invariant exists to prevent.

Configuration coverage is deliberately asymmetric: the **defaults** get full
end-to-end coverage (they are what almost everyone runs), while each non-default
setting gets one focused test proving it changes the behaviour it claims to. This
keeps the matrix from multiplying while still exercising every knob.

**Mode-1 regression gate.** The full existing suite must pass with
`BLASTBOX_BLOB_URL` unset, on a box with no object store installed and `boto3` not
importable. This is the single most important test in the plan: it proves the simple
single-node deployment neither gained a dependency nor changed behaviour. If it needs
any modification to pass, the abstraction is wrong and should be reworked rather than
the test relaxed.
- Failure injection: object store down during `get_sample` returns the job to
  `queued` and another node completes it; verify no job is failed and none is lost.
- Dedupe: submitting the same sample twice performs one upload.
- Two-node integration: one head + one worker with **no shared filesystem**,
  end-to-end through Firecracker.

## Deployment modes

This design must not turn blastbox into a distributed-only system. The simple modes
stay first-class: **one binary, one set of code paths, mode selected purely by
configuration.** There is no "distributed edition" and no separate install.

The ladder below is strictly additive — each rung adds one piece of infrastructure,
and you climb only as far as you need.

Every mode below assumes each node has its OWN private `job_root` — never one
shared across nodes (see "The purge is unconditional" above). The `job store`
column is genuinely shared between nodes in modes 2-3 (that is what makes work
stealing possible); the `blob store` column is what may OPTIONALLY be shared —
either a `local` backend pointed at a shared mount via `BLASTBOX_BLOB_LOCAL_ROOT`
(kept separate from any node's private `job_root`), or `s3://`.

| # | mode | job store | blob store | processes | when |
|---|------|-----------|------------|-----------|------|
| 0 | embedded | in-memory (unset) | local (unset) | 1 | tests, `bench`, library use |
| 1 | **single node** | `sqlite://` | local (unset) | serve + dispatch | **default; small installs** |
| 2 | multi-node LAN | shared `postgresql://` | local on a shared MOUNT (`BLASTBOX_BLOB_LOCAL_ROOT`), or `s3://` | serve xN + dispatch xM | role separation |
| 3 | distributed | HA postgres (Patroni) | `s3://` MinIO/S3 | serve x2 behind LB + workers anywhere | firewalled fleet |

### Mode 0 — embedded (single process)

`BLASTBOX_DATABASE_URL` unset gives an `InMemoryJobStore`. Note the factory warns
that this is "SINGLE-PROCESS only — because `serve` + `dispatch` won't share it", so
this is for in-process use (tests, `blastbox bench`, embedding the library), **not**
a deployment mode.

### Mode 1 — single node (the default, unchanged)

Two processes on one box — `blastbox serve` and `blastbox dispatch` — sharing a
sqlite (or local postgres) store and the local filesystem. `BLASTBOX_BLOB_URL` is
unset, `LocalBlobStore` is a near-no-op, no object store exists, and nothing traverses
a network. **This is exactly today's behaviour and this design must not perturb it**;
the regression gate is the existing suite passing unchanged with the variable unset.

Worth stating plainly since it is a common misreading: the simplest deployment today
is *two processes*, not one invocation. A true single-invocation mode (a `run-all`
that supervises both in one process, backed by sqlite) is a small, optional
convenience — noted here as a possible follow-up, deliberately **not** part of this
design.

### Mode 2 — multi-node on a LAN

Point several nodes at one postgres and `claim_next()`'s `FOR UPDATE SKIP LOCKED`
gives lock-free work stealing with no further machinery. Blobs can move either via
`s3://`, or — with `BLASTBOX_BLOB_URL` still unset — via `LocalBlobStore` pointed at
a shared mount through `BLASTBOX_BLOB_LOCAL_ROOT` (e.g. an NFS export common to every
node). Either way this is a **shared `blob_root`, never a shared `job_root`**: each
node keeps its own private, ephemeral `job_root` regardless of how the blob store is
configured — see "The purge is unconditional" earlier in this document for why a
shared `job_root` is not a supported configuration in any mode. This rung is where
role separation becomes possible: API nodes and worker nodes are just different
subcommands against the same store.

### Mode 3 — distributed / firewalled

Adds HA postgres, MinIO/S3, and a load balancer in front of two `serve` nodes.
Workers run anywhere with outbound access to exactly two endpoints — postgres and the
object store — and hold no inbound ports. This is the only rung that requires the
blob store, and the only one where the worker purge invariant is doing security work
rather than housekeeping.

### Guarantees across modes

- Climbing a rung is **configuration only** — no code change, no different package,
  no data migration for new jobs.
- Falling back down a rung works: unset `BLASTBOX_BLOB_URL` and the node behaves as
  a mode-1 node again.
- The **worker purge invariant holds in every mode.** In mode 1 it is merely tidy; in
  mode 3 it is what stops spare hardware accumulating malware. Implementing it
  uniformly avoids a mode-specific code path that would inevitably rot.

## Configuration

Three behaviours are configurable because real deployments genuinely differ on them
(a re-run corpus vs a production pipeline; a head node that also works vs a dedicated
one; clients that can reach the object store vs clients that cannot). Each still has
a default chosen so that an operator who sets nothing gets the safe, common case.

Configurability is deliberately NOT extended past these three: every knob multiplies
the test matrix, and the rest of the design has a single correct answer.

| variable | values | default | rationale |
|----------|--------|---------|-----------|
| `BLASTBOX_BLOB_URL` | unset \| `s3://bucket/prefix` | unset | unset = today's single-node behaviour, no new deps |
| `BLASTBOX_BLOB_SAMPLE_RETENTION` | `never` \| duration (`90d`) | `never` | see below |
| `BLASTBOX_BLOB_KEEP_LOCAL` | `0` \| `1` | `0` in S3 mode | **head node only**; see below |
| `BLASTBOX_BLOB_RESULT_ACCESS` | `stream` \| `presigned` | `stream` | see below |
| `BLASTBOX_BLOB_COMPRESS` | `0` \| `1` | `1` | ~113 GB -> ~15 GB on measured data |

### Sample retention (`BLASTBOX_BLOB_SAMPLE_RETENTION`)

Sample blobs are content-addressed and therefore **shared across jobs**, so they must
never be reaped by the per-job retention sweeper — deleting `samples/<hash>` when one
job expires would break every other job referencing the same bytes, including future
re-runs.

Default `never`: for a malware corpus the cost of deleting a sample you later need
(re-running the corpus against a new engine build — exactly what we do) exceeds the
cost of the disk. Deployments with legal, contractual, or TLP-driven retention limits
set a duration. Note MinIO/S3 lifecycle rules can also express this outside blastbox;
the knob exists so the behaviour is explicit rather than hidden in bucket policy.

### Head-node local copy (`BLASTBOX_BLOB_KEEP_LOCAL`)

After ingress uploads a sample, the local copy under `job_root` is redundant in
distributed mode.

Default `0` (delete after successful upload): a dedicated head node should not
accumulate the full corpus on local disk. Set `1` when the head node is *also* a
worker — then the copy it already has avoids an immediate round trip to fetch back
bytes it just uploaded. Ignored in local mode, where there is no upload and the file
is the only copy.

**This knob is head-node only and has no worker equivalent.** Workers purge
unconditionally (see "Workers cache nothing"); there is deliberately no setting that
lets sample bytes persist on a worker, so no operator can accidentally turn spare
hardware into a malware store.

### Result access (`BLASTBOX_BLOB_RESULT_ACCESS`)

Default `stream`: `/v1/jobs/{id}/result` and `/metadata` read from the object store
and stream through the API. This keeps the object store **private** — reachable only
by head nodes and workers — and means a client needs no credentials or network path
to it. That matters for the firewalled topology this design targets, where clients
frequently cannot reach the object store at all.

`presigned` issues a time-limited URL and redirects. Materially cheaper for large
results (measured max 40 MB, mean 1.5 MB) since bytes bypass the API, but it requires
clients to reach the object store directly and widens exposure. It is opt-in
precisely because the cheaper option is the less safe one, and that trade should be a
deliberate act rather than a default.

## Open questions

None outstanding — the three previously open items are resolved as configuration
above.

## Known limitations

### Result-upload TOCTOU residual (Finding C2) — accepted, not closed

Both dispatchers re-check claim ownership (`_claim_is_still_ours`) immediately before
`put_output`, so a stale worker whose claim was already reclaimed will not upload. That
recheck narrows the window but does not fully close it: `put_output` writes to a
deterministic per-job key (`results/<job_id>/…`) and is a per-key overwrite, not a
claim-fenced compare-and-set. If a worker's claim is reclaimed *during* the `put_output`
call itself (after the recheck passed), and a peer meanwhile re-runs the job and
CAS-commits DONE, the stale worker's write can land divergent bytes over the peer's
already-correct result. The job's status/`result_summary` then describe the peer's run
while the served bytes are the stale run's.

**This is accepted, not a bug to fix now**, for three reasons:

1. **The window is narrow and the trigger is a rare conjunction** — a job slow enough to
   be reclaimed, a peer re-running it, the reclaim landing inside the upload call, *and*
   non-deterministic run-to-run output (identical output is a harmless overwrite). It is
   recoverable: a `DELETE` + re-submit produces a correct result.
2. **It is the same residual the whole design already lives with** — the identical TOCTOU
   applies to the metadata write, and three independent review passes (two adversarial
   multi-model rounds + a cloud review) examined and accepted it.
3. **The fix is riskier than the residual.** Fully closing it requires the result write to
   be claim-fenced at the storage layer — e.g. each worker writes to a claim-scoped key
   (`results/<job_id>/<claim_id>/…`), the winning claim is persisted on the DONE
   transition, and `open_output`/`delete_job` resolve through it; or object-level
   conditional writes (S3 `If-None-Match`). Either touches the read path, the job schema,
   both dispatchers, and both blob backends — the hottest concurrency code, where every
   prior change in this feature's review history introduced a regression that a later pass
   had to catch. Refactoring it for a narrow, recoverable, already-reviewed residual is a
   net negative on risk.

If a future workload makes the residual matter (high reclaim rates on non-deterministic
engines), the claim-scoped-key approach above is the documented closure path.

### Pre-upgrade result serving (Finding C1) — resolved for the local backend

An in-place upgrade of a single-node install carries DONE jobs whose results were written
to `job_root/<id>/output` before this feature and were never uploaded to the store.
`LocalBlobStore.open_output` falls back to that legacy on-disk location when the store copy
is absent (scoped to the local backend; S3 has no such path; self-limiting because
current-code jobs purge their job dir after uploading). No migration step is required for
local upgrades. A distributed (S3) deployment starting fresh never has pre-upgrade local
results, so no fallback is needed there.
