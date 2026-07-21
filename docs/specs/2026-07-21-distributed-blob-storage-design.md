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
- No change to the Firecracker execution path or its isolation properties.

## Non-goals

- Replacing `job_root`. Firecracker bind-mounts need a real local path; the local
  job dir stays. Object storage is a *transport between nodes*, not the working set.
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

**`LocalBlobStore` is a near-no-op.** Ingress already writes the input into
`job_root/<job_id>/input/`, and the dispatcher already reads it there, so
`put_sample`/`get_sample` reduce to "verify it exists". This is what keeps the
single-node path unchanged: same filesystem layout, same code path, no S3 client,
no network. A single-node operator sets nothing and notices nothing.

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

| # | mode | job store | blob store | processes | when |
|---|------|-----------|------------|-----------|------|
| 0 | embedded | in-memory (unset) | local (unset) | 1 | tests, `bench`, library use |
| 1 | **single node** | `sqlite://` | local (unset) | serve + dispatch | **default; small installs** |
| 2 | multi-node LAN | shared `postgresql://` | local + shared FS, or `s3://` | serve xN + dispatch xM | role separation |
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
gives lock-free work stealing with no further machinery. Blobs can move either via a
shared filesystem (keeping `BLASTBOX_BLOB_URL` unset) or via `s3://`. This rung is
where role separation becomes possible: API nodes and worker nodes are just different
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
