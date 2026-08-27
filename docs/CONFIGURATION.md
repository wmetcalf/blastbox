# Configuration reference

Every `BLASTBOX_*` knob, grouped by subsystem, with its default. **You set almost none of
these** — the defaults run a secure single-host deployment. The large surface is for tuning
the optional warm-pool / runtime / sandbox tiers. Engine-specific knobs (e.g. ClippyShot's
`CLIPPYSHOT_*`) are documented by the engine; the host forwards a per-engine **allowlist** of
them (see *Per-engine params* below), never the whole environment.

> **How values are read.** Most knobs are read as `os.environ.get(...) or default` — a
> **set-but-empty** value (e.g. `FOO=` from a compose `${FOO:-}`) is treated as *unset*.
> Booleans are truthy unless one of `"" 0 false no`.
>
> **Numeric warm-pool knobs are validated at startup.** A value that parses as a float but
> cannot mean a duration — `nan`, `inf`, `-inf`, or any negative — is **ignored with a warning**
> and the default is used (the same convention as `BLASTBOX_CANARY_INTERVAL_S`), rather than
> being honoured. Both directions used to misbehave silently: a *negative*
> interval makes `now - last >= interval` always true, so the thing it rate-limits runs every
> tick; `nan` makes every comparison against it false, so whatever it gates never happens. Use
> **`0`** for "disabled" where the row says so. Note that a RATE LIMIT has no meaningful "off":
> `BLASTBOX_POOL_MAINTAIN_INTERVAL_S=0` would mean *no cooldown* — the maintenance seam on every
> tick (~10Hz) — so it is ignored with a warning and the default is used instead.

See **[DEPLOYMENT.md](DEPLOYMENT.md)** for which of these to set for each deployment shape
and the tier-capability matrix.

---

## Core / ingress / job store

| Var | Default | Notes |
|---|---|---|
| `BLASTBOX_DATABASE_URL` | in-memory | **Required for the 2-process (serve+dispatch) flow.** `sqlite:///…`, `postgresql://…`, or `redis://…`. Unset → each process gets its own in-memory store (jobs invisible across processes; a warning is logged). |
| `BLASTBOX_JOB_ROOT` | `/var/lib/blastbox/jobs` | Shared per-job directory root (staged input + sealed output). Must be the same path for serve, dispatch, and the worker mount. **A network-tier dispatcher (`VmJobDispatcher`: aws/static pools) must NOT share this path with a container dispatcher.** Its terminal purge is unconditional by design — its peers are on other hosts, so bytes left here are unreadable orphans — whereas the container dispatcher's purge is claim-gated precisely because two of THOSE do share one job_root (`docker-compose.yml` + `docker-compose.firecracker.yml`). Point both kinds at one path and the network dispatcher will delete a live container job's tree. The shipped compose keeps them apart (`docker-compose.aws-burst.yml` pins `/tmp/bbjobs`). |
| `BLASTBOX_ENGINES` | `""` | Engine registry: `name=worker_image[,name2=image2]`. The dispatcher launches the mapped image per job. |
| `BLASTBOX_ALLOWED_ENGINES` | `""` (all) | Restrict which engine names ingress will accept. Empty ⇒ accept any (a warning is logged); set `BLASTBOX_REQUIRE_ENGINE_ALLOWLIST=1` to make an empty allowlist a hard startup error instead. |
| `BLASTBOX_REQUIRE_ENGINE_ALLOWLIST` | `0` | When truthy, ingress refuses to start if `BLASTBOX_ALLOWED_ENGINES` is empty (fail-closed; rejects unknown engines before the disk spool instead of at dispatch). |
| `BLASTBOX_INPUT_DIR` / `BLASTBOX_OUTPUT_DIR` | `/input` / `/output` | **Worker-side** mount points — the dispatcher injects these into the worker container env. They do **not** relocate host staging, which is always `JOB_ROOT/<job_id>/{input,output}`. |
| `BLASTBOX_JOB_RETENTION_SECONDS` | store default | TTL after which finished jobs + artifacts are reaped. **This governs RESULT lifecycle, not local scratch**: the sweeper it drives also calls `BlobStore.delete_job()`, so a non-zero value deletes results from the blob store that many seconds after each job finishes — on a long run, while the run is still in flight. Leave it `0` unless you actually want results expired; use `BLASTBOX_SCRATCH_MAX_AGE_S` for disk hygiene. |
| `BLASTBOX_SCRATCH_MAX_AGE_S` | `21600` (6h) | Age after which a per-job scratch dir under `JOB_ROOT` is reclaimed. Runs in BOTH dispatchers' maintenance **and** in `blastbox serve` (a serve-only node spools every upload to `JOB_ROOT/<id>/input/` and would otherwise never reclaim it). **Local scratch only — never touches the blob store.** It bounds the trees the terminal purge deliberately keeps: one whose worker container was never confirmed dead, and one whose result upload exhausted its retries (then the only copy). A tree is reclaimed only when the newest mtime *anywhere* beneath it is older than this **and** its job is terminal or unknown to the store. Two holds delay that, and BOTH have a ceiling — neither is permanent, because an unbounded hold is the leak this setting exists to stop: (1) a tree whose worker container is not yet confirmed dead is held until it is, or until **2×** this value, whichever comes first; (2) a tree holding a sealed result with no durable copy is held while its job is still `FAILED` and awaiting retry. Once that row is `EXPIRED` or gone (deleted, or a Redis key past its TTL) nothing can ever upload it, so it IS reclaimed — and because that destroys the only copy of a host-sealed result, it is logged at **ERROR** as data loss, not as hygiene. A pre-blob-store legacy job (`DONE`, only copy on local disk) is held indefinitely, since it is servable. If you run with `BLASTBOX_WORKER_TIMEOUT_S` above this value, raise it to match. `0` disables the reclaim only — see `BLASTBOX_PENDING_UPLOAD_RETRY` for the write side. Sweeps are BOUNDED (200 candidates per tick) and **yield entirely while every dispatch slot is busy** — measured on a 190k-dir node, an unbounded sweep cost ~13s of disk and object-store I/O per tick and halved pipeline throughput (11 → 6 concurrent jobs, 70 → 48 completions/min). Housekeeping never competes with detonation. |
| `BLASTBOX_PENDING_UPLOAD_RETRY` | `1` | Whether maintenance re-uploads a retained result whose upload exhausted its retries, and repairs that job's row `FAILED` → `DONE` once the bytes are durable (re-stamping `finished_at`/`expires_at` from the recovery, not the original failure). This is the WRITE side of the same machinery `BLASTBOX_SCRATCH_MAX_AGE_S` governs the delete side of, and the two are separate on purpose: setting the age knob to `0` to stage an upgrade does **not** stop the dispatcher writing to the blob store and rewriting job rows that a client may already have been told failed. Set `0` to opt out of that. |
| *(command)* `blastbox migrate-results` | — | Uploads the results of **pre-blob-store DONE jobs** into the blob store. The reclaim deliberately refuses to delete those (their only copy is the local tree the API still serves), and nothing else ever uploads them — so on an upgraded node they accumulate as trees the sweep can only retain (~82k on the fleet this was written for). Run it to end that state: once a result is durable the reclaim collects its tree normally. `--dry-run` to see the count first, `--limit N` to work in batches on a busy node. |
| `BLASTBOX_REDIS_TTL_SECONDS` | `86400` (24h) | Per-key expiry for the Redis job store. Keep it `>= BLASTBOX_JOB_RETENTION_SECONDS`, or `0` to disable key expiry — otherwise a key can expire before retention sweeps it, orphaning the on-disk job dir under `JOB_ROOT` (no record left for retention/API-delete). Redis store only. |
| `BLASTBOX_API_KEY` | `""` (open) | Optional bearer token required on the API. Usually unset — auth is delegated to a reverse proxy. |
| `BLASTBOX_API_WORKERS` | `4` | uvicorn worker processes for `blastbox serve`. |
| `BLASTBOX_METRICS_PUBLIC` | `true` | Serve `/metrics` without auth. |
| `BLASTBOX_INGRESS_EXTENSION` | `""` | Optional ingress extension entry point. |
| `BLASTBOX_ZIP_PASSWORD` | `infected` | Password tried for password-protected sample archives (the malware-corpus convention). |
| `BLASTBOX_EXPOSE_DOCS` | `0` (off) | Truthy (`1/true/yes/on`) publishes `/docs`, `/redoc`, `/openapi.json`; otherwise all three are disabled. A malware-processing service withholds its API surface by default. |
| `BLASTBOX_CSP` | *(strict default, below)* | Overrides the `Content-Security-Policy` header. Set to an **empty string** to drop the CSP header entirely. Only the CSP is env-configurable — `x-frame-options: DENY`, `x-content-type-options: nosniff`, and `referrer-policy: no-referrer` are always sent unconditionally. |

The default CSP (`middleware.DEFAULT_CSP`) is `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'`.

## Dispatch

| Var | Default | Notes |
|---|---|---|
| `BLASTBOX_DISPATCH_CONCURRENCY` | `1` | Dispatch-loop worker threads. **On a warm tier this MUST equal the warm pool size** — the warm path blocks until the job finishes, so N threads are needed to keep N slots busy (default 1 starves the pool). |
| `BLASTBOX_DISPATCH_WARM_ONLY` | `""` (off) | Claim-gate primitive: only claim jobs when a warm slot is free, and **never cold-fall-back** — overflow stays queued for the cold dispatcher. This is what makes a process a *warm sidecar*. |
| `BLASTBOX_MAX_QUEUED_AGE_S` | `0` (off) | Opt-in **stale-queued reaper**: TTL after which a job still QUEUED is FAILed and its (untrusted) input deleted — bounds the `target_tier` footgun (a job pinned to a tier no dispatcher serves) and a >1k batch backlog. Honored by **every** dispatcher variant: the cold container `Dispatcher` and the network-endpoint `VmJobDispatcher` (libvirt-VM / static / AWS / cascade). `0` ⇒ never reap on age (correct for huge legitimate batches). |
| `BLASTBOX_ALLOW_TIER_ROUTING` | `0` | Allow a job to **request a specific warm backend** via a `target_tier` field at submit (claim-predicate honored by every store: memory / sql / redis). **Off (default) ⇒ `target_tier` is silently ignored** (like a per-job override that isn't permitted). The `worker_tier` label (e.g. `firecracker` / `gvisor` / `libvirt-vm`) is what a warm sidecar advertises and what UIs show. Gate this *with* `BLASTBOX_MAX_QUEUED_AGE_S` — a job pinned to a tier whose dispatcher is down would otherwise queue forever. |
| `BLASTBOX_DISPATCH_SOLE_OWNER` | `0` | Network-endpoint dispatcher only. `1` ⇒ this is the **only** dispatcher on the store, so orphan recovery may also reclaim a claim that crashed before the `worker_runtime="warm"` stamp. Leave `0` on a **shared** store (a cold dispatcher for the same engine) — it would otherwise FAIL that peer's live jobs. |

## Runtime selection (docker: runc / runsc)

| Var | Default | Notes |
|---|---|---|
| `BLASTBOX_WORKER_RUNTIME` | auto | Force `runsc` or `runc`. Forcing `runc` still requires `BLASTBOX_ALLOW_RUNC=1`. |
| `BLASTBOX_ALLOW_RUNC` | `0` | Explicit consent to run the worker under plain `runc` (no gVisor) in deliberate degraded mode. Without it, the dispatcher **fails closed** (`InsecureRuntimeRefused`) when no secure runtime exists. |
| `BLASTBOX_REQUIRE_SECURE_RUNTIME` | `0` | Hard lockdown — refuse `runc` **even if** `ALLOW_RUNC` is set. |
| `BLASTBOX_SECCOMP_JSON_HOST` | `""` | **Host** path to the worker seccomp profile (`--security-opt=seccomp=…`). Unset → docker-default seccomp applies (a warning is recorded). |
| `BLASTBOX_APPARMOR_PROFILES` | `""` | Hint that the host AppArmor worker profile is available. |
| `BLASTBOX_WARN_ON_INSECURE` | — | Set by the dispatcher into the worker (under runsc — `/proc` can't reflect host flags; or under opted-in runc) so the worker's sandbox self-check runs leniently instead of aborting. Not normally set by hand. |

## Worker resource caps

| Var | Default | Notes |
|---|---|---|
| `BLASTBOX_WORKER_MEMORY` | `4g` | `--memory` (and `--memory-swap`, swap disabled). |
| `BLASTBOX_WORKER_PIDS_LIMIT` | `256` | `--pids-limit` (fork-bomb cap). |
| `BLASTBOX_WORKER_CPUS` | `1.0` | `--cpus`. |
| `BLASTBOX_WORKER_NOFILE` | `4096` | `--ulimit nofile`. |
| `BLASTBOX_WORKER_TIMEOUT_S` | engine | Per-job wall-clock budget. |
| `BLASTBOX_WARM_CLAIM_TIMEOUT_S` | `60` | *(network-endpoint tiers)* Max seconds a job waits for a warm slot before requeuing (capacity pressure ≠ failure). Bounded **separately** from `WORKER_TIMEOUT_S` so a late claim can't eat the detonation budget; the heartbeat watchdog covers `claim + detonate`. |

**Output-trust / extraction-DoS caps** (`Limits.from_env`) — strict-by-default bounds on what an untrusted worker may read in and write back. Each must be a positive integer in `[1, ceiling]` (byte ceiling 256 GiB, count ceiling 65536); `0` / negative / unparseable raises a `ValueError` naming the offending var.

| Var | Default | Notes |
|---|---|---|
| `BLASTBOX_MAX_INPUT` | `104857600` (100 MiB) | Max accepted input-file size (also enforced pre-spool by the ingress 413 body guard). |
| `BLASTBOX_MAX_METADATA` | `4194304` (4 MiB) | Max size of the worker's `metadata.json`. |
| `BLASTBOX_MAX_ARTIFACT` | `52428800` (50 MiB) | Max size of a **single** output artifact. |
| `BLASTBOX_MAX_TOTAL_ARTIFACTS` | `524288000` (500 MiB) | Max **total bytes** across all artifacts (a byte cap, despite the name — not a count). |
| `BLASTBOX_MAX_ARTIFACTS` | `1000` | Max **number** of artifacts. |

## Worker in-process sandbox + nono

| Var | Default | Notes |
|---|---|---|
| `BLASTBOX_SANDBOX` | auto | Force the inner backend: `nsjail` → `bwrap` → `nono` → `container`. Auto picks the best available; `container` is chosen inside an OCI host. |
| `BLASTBOX_NONO_BIN` | `nono` on PATH | nono binary for the standalone `NonoSandbox` backend. |
| `BLASTBOX_NONO_STATE_DIR` | `/var/lib/blastbox/nono-state` | nono's relocated `$HOME/.nono` state root (must be **off** the grants). |
| `BLASTBOX_WORKER_NONO_WRAP` | off | **Outer** nono-wrap of the *whole worker command* (cold path). Landlock-gated: applied under `runc`, **skipped+warned under `runsc`** (gVisor Sentry has no Landlock — see DEPLOYMENT). |
| `BLASTBOX_WORKER_NONO_BIN` | `/usr/local/bin/nono` | nono binary for the outer wrap (baked into the worker image). |
| `BLASTBOX_WORKER_NONO_PROFILE` | `""` | nono profile JSON (e.g. a `blastbox.profile`-generated policy) for the outer wrap; preferred over the coarse baseline grants. |
| `BLASTBOX_WORKER_NONO_STATE_DIR` | `/run/nono` | Dedicated writable tmpfs for the outer wrap's nono state (off the grants). |
| `BLASTBOX_ENGINE` | `""` | Worker-side engine selector breadcrumb (reserved; not client-settable). |

## Warm pool

| Var | Default | Notes |
|---|---|---|
| `BLASTBOX_POOL_RUNTIME` | runtime default | Warm backend: `firecracker`, `gvisor`, `aws-lambda-microvm`, `aws-lambda-snapstart` (warm AWS — suspend/resume), `aws-ec2`, `aws-ec2-hibernate` (warm AWS — hibernate C/R), `static`, or `cascade` (tiered local→overflow). |
| `BLASTBOX_POOL_WARM_SIZE` | — | Number of pre-warmed slots. |
| `BLASTBOX_POOL_CEILING` | — | Max concurrent slots (warm + burst). |
| `BLASTBOX_POOL_BURST_SIZE` | — | Extra cold-burst slots above the warm set under load. |
| `BLASTBOX_POOL_SPAWN_RATE` | — | Slot replenish rate. |
| `BLASTBOX_POOL_WARMING_TIMEOUT_S` | `120` | Max seconds a slot may sit WARMING before eviction. **Raise for cloud tiers** (`aws-ec2` first-boot can exceed 120s) or healthy-but-slow slots get churned. |
| `BLASTBOX_POOL_WARM_SNAPSHOT` | `0` | FC only: restore from a memory snapshot (warm-UNO) instead of cold-booting the guest. |

### Pool safety controls

These decide when the pool **evicts a slot** or **destroys and rebuilds a snapshot base**. All
default to values derived from `BLASTBOX_POOL_WARM_SIZE`, so leaving them unset is the supported
configuration — set them when an incident or a specific tier demands it.

| Variable | Default | Meaning |
|---|---|---|
| `BLASTBOX_POOL_SNAPSHOT_REBUILD_AFTER` | `2 × warm_size` (min 4) | Consecutive restore/warm failures before the snapshot base is invalidated and rebuilt. **`0` disables automatic base invalidation entirely** — the incident escape hatch. It applies to every rebuild path, including per-tier repair inside a `cascade`. |
| `BLASTBOX_POOL_PRE_GUEST_REBUILD_AFTER` | `3` | How many **distinct** slots must fail *before their guest ever executes* before the base is judged poisoned. Far lower than `SNAPSHOT_REBUILD_AFTER` on purpose: that threshold is sized for failures which might be the **documents**, so it must tolerate a run of bad samples. A slot that never reached its guest carries no such ambiguity — it did not fail *on* a sample, it failed to become able to run one. At `warm_size=24` the ordinary threshold is 48, so without this a wedged base costs 48 real jobs, each burning the full worker timeout, before the tier repairs itself — which is how a warm tier silently degrades to cold-only for hours. Distinct slots, because one wedged worker is not a wedged base. The guest itself reports the start: it sends a START frame the moment it has the job and before it begins work, so a document that **hangs a healthy slot** acks first and is never attributed to the base. A worker image too old to send one leaves the answer UNKNOWN, which also never convicts — so a mixed-version fleet degrades to today's behaviour rather than misfiring. `0` disables the fast path; values below 2 are floored to 2. |
| `BLASTBOX_POOL_MAX_EVICTIONS_PER_WINDOW` | `max(2, warm_size)` | Cap on slots evicted per window, so one bad signal cannot churn the whole warm set at once. **`0` blocks heuristic eviction entirely** — the incident escape hatch, and the direction a zero reads in; it is *not* an "unlimited" sentinel. This stops only the *wedge heuristic*: a slot the runtime CONFIRMS dead is still reaped. |
| `BLASTBOX_POOL_MAX_CONSECUTIVE_FAILURES` | pool default (`2`) | Worker-attributed failures in a row before a reusable slot is burned out. Only failures attributed to the *worker* count — a bad sample (`engine_error`) or a host-side failure does not. |
| `BLASTBOX_POOL_UNKNOWN_GRACE_S` | `300` | How long a slot may stay **continuously UNKNOWN** (control plane not answering) before it may be replaced. Must comfortably outlast a real control-plane brownout. `0` disables the escalation, which lets a slot stay unknown forever and wedges the tier. **Also bounds the WARMING exemption (issue #79): a slot whose readiness is UNKNOWN is not aged against `warming_timeout_s` while an episode is open, and the unobservable interval is credited back when it closes.** ⚠️ `0` therefore does the OPPOSITE on the two paths: it disables escalation for an IDLE slot (which can then stay unknown forever), but it also disables the WARMING exemption — so every WARMING slot is aged and evicted on the control plane's silence, which is the brownout failure this setting otherwise prevents. Do not set `0` as an incident escape hatch. |
| `BLASTBOX_POOL_CAPACITY_STARVED_AFTER_S` | `300` | How long the pool may be unable to spawn **for capacity reasons** before that stops being backpressure and is logged as `pool.spawn_capacity_starved` (ERROR, once per episode). `0` disables the alert. |
| `BLASTBOX_POOL_MAINTAIN_INTERVAL_S` | `5` | Per-slot cooldown for the idle-maintenance seam. The hook may make uncached control-plane calls and `tick()` runs at ~10Hz, so without an interval an `aws-ec2-hibernate` pool issues a describe every 0.1s per slot and **manufactures the very brownout** the rest of this page exists to survive. This is the pool's control-plane CALL RATE; turn it up during an incident. **`0` is NOT an off switch here** — it would mean *no cooldown*, i.e. the opposite — so it is ignored with a warning and this default is used. |
| `BLASTBOX_POOL_MAINTAIN_BUDGET_S` | `5` | How long ONE maintenance pass may occupy the pool's **single tick thread** — the thread that also drives promotion, health checks, reaping and replacement spawning. The runtime's own ceiling (`BLASTBOX_AWS_HEALTH_PROBE_TIMEOUT_S`, 30s) is sized for a *background* probe, and the rotation reaches a different slot each tick, so a control-plane brownout stalls that thread **continuously** rather than once. Expiry is **not a verdict**: the bounded call answers UNKNOWN and the slot is reconsidered on a later rotation, never retired for it. `0` ⇒ fall back to the runtime's own ceiling. |

> Capacity misses are deliberately *not* failures: a full cascade, a cooling static fleet or a
> saturated tier must never invalidate a base. `pool_spawn_capacity_miss_total` counts them
> separately from spawn failures so a dashboard cannot confuse "we are busy" with
> "spawning is broken".

## Node pool autosizer (opt-in)

Right-sizes every node-managed pool on one physical host from live demand under the host's
RAM/vCPU budget, instead of hand-tuning `BLASTBOX_POOL_CEILING` per engine. Runs inside
`blastbox dispatch`; **OFF by default** — a node behaves exactly as today unless a switch below is
on. Each dispatcher publishes a demand snapshot to a shared node dir and reads its peers', then
runs the same deterministic allocation over the whole-node view and resizes its own pool. See
`src/blastbox/host/node_sizer.py`.

It manages **firecracker/gvisor** warm pools, the **pool-less cold-only dispatcher** (which
publishes a cold-worker reservation + gets a budgeted admission gate), and an **all-local cascade**
(a `BLASTBOX_POOL_TIERS` cascade whose tiers are all fc/gvisor — a cascade with any off-node tier
stays unmanaged). The same engine on two tiers is two `(engine, tier)` pools that **share** the
budget, and their shared **untargeted** backlog (jobs with no pinned `target_tier`, claimable by
either tier) is counted **once** across the tiers rather than once per tier. Worked multi-worker /
multi-tier examples: [DEPLOYMENT.md → *Auto-sizing a multi-worker host*](DEPLOYMENT.md#4-auto-sizing-a-multi-worker-host-node-pool-autosizer).

**Node-wide participation is required.** The budget is only honored if **every** dispatcher on a
host participates with a **consistent** config. Coordination is a whole-node protocol: the plan
is a pure function of the shared view, so all dispatchers must agree on it. Concretely, on one
host:
- **Enable node management on ALL co-located dispatchers, or none.** A dispatcher left with
  `RESOURCE_MANAGEMENT`/`BALANCING` off publishes no reservation and keeps running its static pool,
  but its footprint is then invisible to the managed peers, which allocate the whole budget as if
  it weren't there — persistent oversubscription. This cannot be detected from the shared view (a
  non-participant is silent), so it is an operating requirement, not something the sizer can guard.
- **Use a consistent `BLASTBOX_NODE_ID`** (all unset for one host, or one shared tag) and a
  consistent `BLASTBOX_NODE_BALANCING` / budget config (`RAM_HEADROOM`, `VCPU_OVERSUBSCRIPTION`).
  Divergences the sizer *can* see it reconciles safely — a mixed balancing mode falls back to
  static for all, a divergent budget reconciles to the elementwise minimum, and a mixed
  tagged/untagged node view fails closed to the warm floor — each with a one-time warning. These
  are safety nets, not a substitute for consistent config: they degrade capacity to avoid
  oversubscribing, and clear once the config is aligned.

**Budget bounding.** When the autosizer manages a pool (`RESOURCE_MANAGEMENT`/`BALANCING` on,
firecracker/gvisor tier): the pool ceiling is capped at `BLASTBOX_DISPATCH_CONCURRENCY` (the
sizer never warms more slots than the dispatcher can run — each in-flight job, warm *or* cold,
is one slot of RAM), and the pool starts **unspawned** (`warm=0`) and is sized synchronously
from the node budget before it serves, so a full/rolling startup can't transiently over-spawn.
The autosizer does **not** force `warm_only` — that would break jobs needing a cold egress
personality (which bypass the warm pool) and doesn't bound cold RAM anyway. Instead the cold
path is bounded against the same budget: a cold worker spawns footprint **outside** the warm
pool, so the sizer drives a live gate to the budget's **cold headroom** (`ceiling − warm
reservation`) on every resize. Only the cold path takes a permit (warm dispatch reuses a
resident slot and is never gated); when there's no headroom a cold job is requeued rather than
oversubscribing. So **warm residency + cold workers stay within the ceiling** instead of each
independently reaching it. This is **best-effort**, not a hard guarantee — a warm burst within a
sizing interval can transiently overshoot before the gate catches up, a bounded overshoot that
self-corrects next tick (plus idle-slot reaping). Set `BLASTBOX_DISPATCH_CONCURRENCY` per engine
so that Σ(concurrency·slot-footprint) ≤ the node budget across the engines a node serves.
For a SQL job store an index on `jobs(status, engine, target_tier)` is created — `CONCURRENTLY`
on Postgres so upgrading a large table doesn't block writes — keeping the per-tick backlog
counts cheap.

| Var | Default | Notes |
|---|---|---|
| `BLASTBOX_NODE_RESOURCE_MANAGEMENT` | `0` | Enforce the node RAM/vCPU budget: cap total slots so engines can't oversubscribe the host. With balancing off, each engine gets a static, weight-proportional share. |
| `BLASTBOX_NODE_BALANCING` | `0` | Dynamically rebalance the budget across engines by live queue backlog (implies `RESOURCE_MANAGEMENT`). |
| `BLASTBOX_NODE_ADAPTIVE` | `0` | Nudge the RAM budget from observed free memory (bounded; never exceeds physical RAM). |
| `BLASTBOX_NODE_ENGINES` | — | Inventory of engines on this host: `name` or `name=url`, comma-separated (e.g. `clippyshot,redtusk,titanarum`). Engine names must be plain slugs (`[A-Za-z0-9._-]`, no path separators). |
| `BLASTBOX_NODE_ENGINE_<NAME>_RAM_MIB` | `2048` | Per-slot RAM footprint for that engine (a warm microVM). |
| `BLASTBOX_NODE_ENGINE_<NAME>_VCPUS` | `1` | Per-slot vCPU footprint. |
| `BLASTBOX_NODE_ENGINE_<NAME>_MIN_WARM` | `0` | Warm floor (slots kept hot even at zero backlog; soft — shed to the afforded ceiling under a tight budget). |
| `BLASTBOX_NODE_ENGINE_<NAME>_MAX_CEILING` | `64` | Per-engine hard cap. |
| `BLASTBOX_NODE_ENGINE_<NAME>_WEIGHT` | `1.0` | Static budget share when balancing is off. |
| `BLASTBOX_NODE_RAM_HEADROOM` | `0.8` | Fraction (0,1] of MemTotal the sizer may allocate to pools. |
| `BLASTBOX_NODE_VCPU_OVERSUBSCRIPTION` | `2.0` | vCPU multiplier over `cpu_count()`. |
| `BLASTBOX_NODE_MIN_FREE_MIB` | `2048` | Adaptive: keep at least this much host RAM free. |
| `BLASTBOX_NODE_INTERVAL_S` | `5` | Sizer tick interval. |
| `BLASTBOX_NODE_STALE_AFTER_S` | `20` | A peer snapshot older than this drops out of the node view (floored at 2× interval). |
| `BLASTBOX_NODE_SHARE_DIR` | `/var/lib/blastbox/node` | Shared dir every engine's dispatcher on this host publishes to + reads from. **Bind-mount it into each engine stack on the host.** It is a single-trust-domain surface (written only by dispatchers). |
| `BLASTBOX_NODE_ID` | unset | Physical-host id. Leave unset when the share dir is local to one host (the default). **Only** set it — to a distinct slug per host — if a share dir is (accidentally) shared across hosts (NFS): every participating host must then set a *distinct* id, and never mix tagged + untagged hosts on one shared dir. |

## Runtime: Firecracker

| Var | Default | Notes |
|---|---|---|
| `BLASTBOX_FC_BIN` / `BLASTBOX_FC_KERNEL` / `BLASTBOX_FC_ROOTFS` | — | Paths to the firecracker binary, guest `vmlinux`, and `rootfs.ext4`. |
| `BLASTBOX_FC_VCPU` | `1` | **Pinned at 1** — the vsock stream-corruption mitigation. Do not raise without validating the guest vsock driver under concurrency. |
| `BLASTBOX_FC_MEM_MIB` | `512` | Guest RAM (compose sets 2048 for LibreOffice). |
| `BLASTBOX_FC_OUTDISK_MIB` | — | Size of the per-slot ext4 output disk the host reads via `debugfs`. |
| `BLASTBOX_SNAPSHOT_MEM_DIR` / `BLASTBOX_SNAPSHOT_MEM_TMPFS` | — | Where the warm memory-snapshot base lives; `_TMPFS` pins the CoW base in RAM (per-host toggle). |
| `BLASTBOX_SNAPSHOT_RECLAIM_LEGACY` | unset (off) | Delete pre-generation snapshot artifacts (`warm.snapshot` / `warm.mem`) left by a build older than generation stamping. **Set this only once no pre-upgrade dispatcher is still running**: those files carry no owner lease, so nothing can prove an overlapping old process is not still mapping them, and unlinking a live one corrupts its microVMs. Left off, the tier logs `fc_snapshot.legacy_artifacts_present` with the paths and size — the RAM-sized `warm.mem` often occupies the very tmpfs the replacement generation needs, so it is a common cause of an upgraded tier failing every build with ENOSPC. |
| `BLASTBOX_SNAPSHOT_SETTLE_S` | `""` | Settle delay before snapshotting a freshly-warmed guest. |

## Runtime: gVisor C/R (runsc checkpoint/restore)

| Var | Default | Notes |
|---|---|---|
| `BLASTBOX_GVISOR_RUNSC` / `BLASTBOX_GVISOR_ROOT` / `BLASTBOX_GVISOR_ROOTFS` | — | runsc binary, `--root` state dir, and the warm OCI rootfs. |
| `BLASTBOX_GVISOR_PLATFORM` | `systrap` | `systrap` (modern default) vs `ptrace`/`kvm`. systrap is required for the C/R warm OCR throughput. |
| `BLASTBOX_GVISOR_NETWORK` | `none` | runsc `-network`. |
| `BLASTBOX_GVISOR_NPROC` | `4096` | RLIMIT_NPROC (fork-bomb cap; cgroups are ignored under `-ignore-cgroups`). |
| `BLASTBOX_GVISOR_NOFILE` | `65536` | RLIMIT_NOFILE (fd-exhaustion cap). |
| `BLASTBOX_GVISOR_WARM_ARGV` | — | The in-guest warm entrypoint argv (JSON list). |
| `BLASTBOX_GVISOR_LD_PRELOAD` | — | `LD_PRELOAD` inside the guest (the accept-retry shim for soffice-on-restore). |
| `BLASTBOX_GVISOR_EXTRA_ENV` | — | Extra guest env (JSON list), e.g. `CLIPPYSHOT_SANDBOX=container`. |
| `BLASTBOX_GVISOR_CPUFEATURES` | — | CPU-feature mask for snapshot portability across hosts. |

## Runtime: CRaC (JVM engines, e.g. Tika)

| Var | Default | Notes |
|---|---|---|
| `BLASTBOX_CRAC_CRIU_BIN` | `criu` | CRIU binary for JVM checkpoint/restore. |
| `BLASTBOX_CRAC_JAVA_BIN` | `java` | JVM used for the CRaC warmup. |
| `BLASTBOX_CRAC_JCMD_BIN` | `jcmd` | `jcmd` for triggering the checkpoint. |
| `BLASTBOX_CRAC_ENGINE_ARGV` | `""` | The JVM engine's launch argv (JSON list). |

## Runtime: AWS disposable workers (Lambda MicroVM / disposable EC2)

A **family** of managed-cloud backends behind the same warm-pool seam (`SlotRuntime`), for running
workers on AWS with no host infra. Selected by `BLASTBOX_POOL_RUNTIME=aws-lambda-microvm` or
`aws-ec2`. Both are **network-endpoint, disposable** tiers (one job per worker, then terminate — no
reuse), driven by `VmJobDispatcher` with a transport (the generic `remote_http` HTTP+tar transport, or
an engine-supplied one). They shell the `aws` CLI (no boto3 dep) and are **fail-closed**: a tier is
refused at selection unless `sts get-caller-identity` and a read-only service probe both pass. Only
**sealed-Linux** engines fit (ARM64 worker image running `python -m blastbox.worker.http_agent`;
win-validator stays libvirt — no Windows/nested-virt on either).

| Var | Default | Notes |
|---|---|---|
| `BLASTBOX_AWS_REGION` | `AWS_REGION` or `us-east-1` | Region for all AWS calls. |
| `BLASTBOX_AWS_PROFILE` | — | Named CLI profile (else default cred chain). |
| `BLASTBOX_AWS_AGENT_PORT` | `8765` | Port the in-worker HTTP agent listens on. |
| `BLASTBOX_AWS_MAX_DURATION_S` | `3600` | Hard lifetime cap requested of the worker (belt-and-braces reap). |
| `BLASTBOX_AWS_HEALTH_PROBE_TIMEOUT_S` | `30` | Ceiling on ONE background/health `describe` for an AWS tier. Generous (it is not on dispatch latency) but finite, so a control-plane brownout cannot stall the pool's single tick thread for the full `cli_timeout_s` (120s) per IDLE slot. Non-finite or `<= 0` falls back to the default rather than disabling the bound — an unbounded probe is the stall this exists to prevent. See also `BLASTBOX_POOL_MAINTAIN_BUDGET_S`, which bounds the whole maintenance pass. |
| **Lambda MicroVM** (`aws-lambda-microvm`) | | transport = per-VM HTTPS URL + JWE token |
| `BLASTBOX_LAMBDA_IMAGE` | — | **Required.** An **in-account** MicroVM image ARN built via `create-microvm-image` (the managed base `…:aws:microvm-image:al2023-1` is **not** directly runnable — verified live). |
| `BLASTBOX_LAMBDA_EXEC_ROLE_ARN` | — | Execution role for `run-microvm`. |
| `BLASTBOX_LAMBDA_EGRESS_CONNECTORS` | `""` | Comma-list of egress-connector ids (list arg). **Empty ⇒ AWS default `INTERNET_EGRESS` (not sealed).** Pass a no-internet connector to seal outbound. **Without one the tier refuses to start** (fail-closed — see `ALLOW_DEFAULT_EGRESS`) because default internet egress silently contradicts a `net_policy='none'` engine. |
| `BLASTBOX_LAMBDA_ALLOW_DEFAULT_EGRESS` | `0` | `1` ⇒ explicitly accept AWS's default **public internet** egress when no egress connector is set (otherwise the tier fail-closes). Use only when internet egress is intended; set the engine's `net_policy` accordingly. |
| `BLASTBOX_LAMBDA_INGRESS_CONNECTORS` | `""` | Comma-list of ingress-connector ids (empty ⇒ none configured). |
| `BLASTBOX_LAMBDA_AUTH_TTL_MIN` | `15` | JWE lifetime for `create-microvm-auth-token` (`--expiration-in-minutes`); minted fresh at probe time, scoped to the agent port, and **reused across readiness ticks within half its TTL** (no per-tick control-plane call). |
| **Lambda MicroVM WARM / SnapStart** (`aws-lambda-snapstart`) | | the WARM AWS tier — per-microvm suspend/resume |
| _(reuses all `BLASTBOX_LAMBDA_*` + `BLASTBOX_AWS_*` above)_ | | Same image/egress/token config as `aws-lambda-microvm`. |
| `BLASTBOX_LAMBDA_SNAPSTART_IDLE_S` | `120` | `idlePolicy.maxIdleDurationSeconds` — idle time (running, billing) before AWS auto-suspends a warm slot. Lower = cheaper park, more resume churn. |
| `BLASTBOX_LAMBDA_SNAPSTART_SUSPENDED_TTL_S` | `3600` | `idlePolicy.suspendedDurationSeconds` — how long a PARKED slot persists before AWS auto-terminates it (then the pool replenishes). |
| `BLASTBOX_LAMBDA_SNAPSTART_AUTO_RESUME` | `1` | `idlePolicy.autoResumeEnabled` — wake on inbound traffic (belt-and-braces with the dispatcher's explicit `resume-microvm` on claim). |
| `BLASTBOX_LAMBDA_SNAPSTART_RESUME_TIMEOUT_S` | `60` | Budget for `resume-microvm` + `/healthz` to answer when a job claims a parked slot (the transport POSTs with no retry). |
| `BLASTBOX_LAMBDA_SNAPSTART_RESUME_POLL_S` | `1` | Health re-probe interval while a resumed slot settles. |
| **Disposable EC2** (`aws-ec2`) | | transport = instance IP:port (private by default) |
| `BLASTBOX_EC2_AMI` | — | **Required.** Worker AMI (agent brought up via user-data). |
| `BLASTBOX_EC2_INSTANCE_TYPE` | `m7g.large` | ARM64 default (matches the sealed-Linux ARM image); override for x86. |
| `BLASTBOX_EC2_SUBNET_ID` / `BLASTBOX_EC2_SECURITY_GROUPS` | — | VPC placement + SGs (comma-list). |
| `BLASTBOX_EC2_IAM_PROFILE` / `BLASTBOX_EC2_KEY_NAME` | — | Instance profile name / SSH key name. |
| `BLASTBOX_EC2_PUBLIC_IP` | `0` | `1` ⇒ talk to the public IP (default: private, host in-VPC). Requires dispatcher TLS (`BLASTBOX_DISPATCH_TLS_CA`) — the runtime **fails closed** on public-IP-without-TLS (the token + samples would cross the public internet in cleartext). |
| `BLASTBOX_EC2_ALLOW_PLAINTEXT_PUBLIC` | `0` | `1` ⇒ explicitly accept a public-IP worker with **no** TLS (opt out of the fail-closed guard above). Only for a trusted/private-fronted public endpoint. |
| `BLASTBOX_EC2_USER_DATA_B64` | — | base64 cloud-init that starts the worker agent on `AGENT_PORT` (any format — merged into MIME-multipart with the auto TTL). |
| `BLASTBOX_EC2_SELF_TERMINATE` | `1` | Inject a guest self-shutdown after `MAX_DURATION_S` (MIME-multipart, on top of your user-data) so a **crashed dispatcher can't leak a running instance** — `--instance-initiated-shutdown-behavior terminate` then reaps it. Set `0` if the AMI handles its own TTL. |
| `BLASTBOX_EC2_AGENT_TOKEN` | — | Bearer token the AMI's agent expects (`BLASTBOX_WORKER_AGENT_TOKEN`); forwarded on both the readiness probe and `/detonate`. |
| **EC2 WARM / Hibernate** (`aws-ec2-hibernate`) | | the WARM EC2 tier — `stop --hibernate` / `start` C/R |
| _(reuses all `BLASTBOX_EC2_*` + `BLASTBOX_AWS_*` above)_ | | Same AMI/subnet/SG/agent-token config as `aws-ec2`, PLUS: needs a **hibernation-capable** instance type (t4g/m6g/m7g/…, RAM ≤ 150 GB) and an AMI that supports hibernation (AL2023 does). Fail-closed preflight refuses an incapable type or an undersized root volume. |
| `BLASTBOX_EC2_ROOT_VOLUME_GB` | `30` | Encrypted root EBS size — must be **≥ the instance RAM** (hibernation saves RAM to it). Raise for large-memory types. |
| `BLASTBOX_EC2_ROOT_DEVICE` | `/dev/xvda` | Root device name (AL2023 ARM64). |
| `BLASTBOX_EC2_HIBERNATE_READY_TIMEOUT_S` | `600` | Warming budget — must cover boot + `engine.warmup()` + the `ec2-hibinit` reserve wait + `stop --hibernate` → stopped (all in `is_ready`). |
| `BLASTBOX_EC2_HIBERNATE_RESUME_TIMEOUT_S` | `180` | Budget for `start-instances` + `/healthz` on claim (kept below the job timeout). |
| `BLASTBOX_EC2_HIBERNATE_TIMEOUT_S` | `300` | Per-slot budget for `stop --hibernate` → `stopped`; if hibernation doesn't take (instance lands back `running`) the slot re-drives. ⚠️ This is now a WHOLE-EPISODE give-up budget, not a retry budget: it is not reset by a re-drive, it is frozen and credited across no-verdict episodes, and on expiry the slot is RETIRED (`maintain_idle` returns False and the pool reaps it) with **no worker-fault attribution** — a park give-up is control-plane evidence, so it deliberately does NOT charge the tier's failure streak and never triggers base repair rather than re-driven. Size it as the point at which you want the slot destroyed. |
| `BLASTBOX_EC2_HIBERNATE_RESUME_POLL_S` | `5` | Health re-probe interval while a resumed slot settles (`start-instances` → `/healthz`). |
| `BLASTBOX_EC2_SELF_TERMINATE` | `1` (on) | Crash backstop, **default-on** here too but **uptime-based** (`systemd-run --on-active`, a monotonic timer that doesn't advance while hibernated) — so unlike the disposable tier's wall-clock TTL it **can't fire on resume**. A leaked *running* instance self-terminates after `MAX_DURATION_S` of cumulative running time; a parked one never accrues it. Set `0` to disable. |
| `BLASTBOX_EC2_ORPHAN_MAX_AGE_S` | `0` (off) | **Host-side orphan sweep.** The uptime backstop above is frozen while an instance is *hibernated*, so a slot **parked when its dispatcher crashed** never self-terminates (encrypted-root-EBS cost only). When `>0`, the dispatcher runs `sweep_orphans()` — `describe-instances` filtered by the `blastbox-tier` tag + `stopped`/`stopping` state, terminating any **not** carrying *this* dispatcher process's `blastbox-run` id and older than this many seconds. `0` ⇒ never sweep. Recommend a value **≥ peak park duration** (e.g. `3600`). Runs once at dispatcher start (reclaims a *predecessor's* leaks — never this run's live parked slots), **and once more for a tier that was DEFERRED at startup, at the moment it is admitted** — admission is the first instant that tier exists, so it is that tier's equivalent of start-up, not an extra periodic sweep. The single-deployment assumption below applies to both. **Assumes ONE `aws-ec2-hibernate` deployment per account+region.** The sweep filters only by the `blastbox-tier` tag, so a *second* independent hibernate deployment in the same account would match here; the per-process run-id fence protects this run's live slots but **not** another deployment's — so enable this only where a single hibernate deployment owns the account/region, and size the age generously if you run several dispatchers of it. Needs `ec2:DescribeInstances` + `ec2:TerminateInstances`. |

The **generic worker agent** (`python -m blastbox.worker.http_agent`, `BLASTBOX_ENGINE=module:Class`)
serves any engine over `GET /healthz` + `POST /detonate`; bake it + the engine + its deps into the
worker image. `BLASTBOX_WORKER_AGENT_PORT` / `BLASTBOX_WORKER_AGENT_TOKEN` / `BLASTBOX_WORKER_AGENT_MAX_BYTES`
tune it. The agent runs `engine.warmup()` **before** it binds, so a MicroVM whose `/healthz` answers is
already warm (JVM booted / soffice UNO up) — which is what makes the SnapStart tier's parked slots warm.

**`aws-lambda-snapstart` — the WARM AWS tier.** AWS exposes `suspend-microvm`/`resume-microvm` (per-VM
live state; endpoint stable across the cycle) but **no snapshot-template/fan-out**, so each pool slot is
individually boot+warmed then parked. The tier: (1) `run-microvm`s each slot with an `--idle-policy` so
AWS auto-suspends it once warm+idle (full mem+disk preserved); (2) the dispatcher `resume-microvm`s the
claimed slot and health-gates it **before** the job POSTs (sub-second — JVM/soffice already warm);
(3) **terminates** it after one untrusted job (disposable-warm, never reused across inputs). The
boot + warmup cost is paid off the critical path during background replenishment. Same fail-closed
egress + JWE + public-AWS-TLS model as `aws-lambda-microvm`; size `BLASTBOX_POOL_WARM_SIZE` to the
warm depth you want parked.

**`aws-ec2-hibernate` — the WARM EC2 tier.** EC2's warm C/R primitive is **Hibernate**: `stop-instances
--hibernate` saves the instance RAM to the encrypted root EBS (→ `stopped`) and `start-instances`
restores it (→ `running`), so the warmed process (JVM/soffice) survives. Unlike Lambda's platform
idle-policy, EC2 has no auto-hibernate, so the runtime parks a warmed slot itself: `is_ready` drives a
per-slot state machine (wait `running` + agent `/healthz` → `stop --hibernate` → wait `stopped` →
parked), and the `resume` seam `start-instances` + health-gates it on claim (the **private IP is
retained** across stop/start, so the endpoint is stable). Terminated after one untrusted job
(disposable-warm). The `ec2-hibinit` agent needs ~1–2 min after boot before `stop --hibernate` is
accepted ("not ready to hibernate yet") — the state machine throttles + retries that automatically.
Both warm-survival cycles are **live-proven on real AWS** (the same warmed PID served the pre-hibernate
and post-resume jobs). Self-hosted agent → worker mTLS applies (unlike the AWS-fronted Lambda tiers).

## Runtime: static worker pool (`static`)

For a **fixed fleet of always-on workers** — bare-metal boxes or long-lived VMs that each already run
`python -m blastbox.worker.http_agent`. Unlike every other tier this backend **creates nothing**: a slot
"spawn" just **claims a free box** from the registered list, and "reap" **returns it** — no boot, no
terminate. Same network-endpoint slot as the AWS tiers, so the `remote_http` transport drives it unchanged.
Selected by `BLASTBOX_POOL_RUNTIME=static`. Fail-closed: refused unless at least one box answers `/healthz`.

| Var | Default | Notes |
|---|---|---|
| `BLASTBOX_STATIC_WORKERS` | — | **Required.** Comma-list of worker endpoints: `host:port`, bare `host`, or a full `http(s)://host:port` URL. |
| `BLASTBOX_STATIC_AGENT_PORT` | `8765` | Default port for `host` / `host:` entries that omit one. |
| `BLASTBOX_STATIC_WORKER_TOKEN` | — | Shared bearer token sent as `X-aws-proxy-auth` to every box (the agent's `BLASTBOX_WORKER_AGENT_TOKEN`). |
| `BLASTBOX_STATIC_HEALTH_PATH` | `/healthz` | Health-probe path. |
| `BLASTBOX_STATIC_PROBE_TIMEOUT_S` | `5` | Per-probe HTTP timeout. |
| `BLASTBOX_STATIC_DIRTY_COOLDOWN_S` | `60` | After a **dirty** release (timeout/trust-fail/agent error) a box is held out of the free set this long, so a stale request still running in the long-lived agent can drain before the box is re-offered. |

The fleet is finite, so **size the pool to it**: keep `BLASTBOX_POOL_CEILING <= len(BLASTBOX_STATIC_WORKERS)`
(a claim beyond the fleet raises `StaticPoolExhausted`). Set `BLASTBOX_DISPATCH_CONCURRENCY` to the fleet
size too. This is the "bare-metal worker pool" shape — the same warm-pool scaler + generic agent as the
cloud tiers, just pointed at machines you already own.

**mTLS:** when `BLASTBOX_DISPATCH_TLS_CA` is set (see *Worker HTTP agent + mTLS*), the pool automatically
probes `/healthz` and drives the transport over **https + client-cert mTLS** — declare workers as
`https://host:port` (bare `host:port` entries are upgraded to `https` in TLS mode). The pool exposes the
client context on `runtime.ssl_context` for the dispatcher's `make_remote_validate`.

## Runtime: cascade (local + overflow tiers) (`cascade`)

**"Run X workers locally, then burst up to Y on other hardware / AWS"** as a single warm pool. A
priority-ordered list of tiers — each an existing backend + a capacity — where `spawn` fills tier 1,
then overflows to tier 2, and so on; `reap` frees the slot on whichever tier owns it. The WarmPool on
top is unchanged (it still sees one runtime); each tier reads its own backend config.

| Var | Default | Notes |
|---|---|---|
| `BLASTBOX_POOL_TIERS` | — | **Required.** Ordered `backend:capacity` list, e.g. `static:4,aws-ec2:16` — 4 warm local + up to 16 overflow on AWS. Backends: `gvisor`, `firecracker`, `static`, `aws-ec2`, `aws-lambda-microvm`. **All tiers must share a dispatch style** (see below) — don't mix file-handshake (`gvisor`/`firecracker`) with network-endpoint (`static`/`aws-*`). |

The **primary** (first) tier must be available at startup (fail-closed); an **overflow** tier that isn't
available is handled by VERDICT (issue #79): a tier CONFIRMED unusable (bad credentials, wrong
instance type) is logged and skipped as before, but one whose availability probe reached NO
VERDICT (throttle, timeout, unparseable answer) is DEFERRED and re-probed every ~60s until it
answers, rather than being lost until restart. An admitted deferred tier joins at the END of the
cascade — a LOWER priority than its position in `BLASTBOX_POOL_TIERS`. A deferred tier's declared
timeouts and transport still count toward the cascade's budgets and its dispatch-style/TLS
uniformity checks, so a mixed-transport cascade is still refused at startup. A PRIMARY tier that
cannot be decided raises a `CascadeMisconfigured` explicitly marked retryable — a supervisor
should retry it, unlike the permanent misconfiguration of the same type.
Set `BLASTBOX_POOL_WARM_SIZE` to the primary tier's capacity (keep those warm), `BLASTBOX_POOL_CEILING` to
the sum, `BLASTBOX_DISPATCH_CONCURRENCY` to the ceiling, and `BLASTBOX_POOL_BURST_SIZE` to the overflow
capacity — the pool only raises its target to `WARM_SIZE + BURST_SIZE` (default burst **4**), so without
this it never spawns into the overflow tier no matter how high the ceiling.

> **All tiers must share a dispatch style.** Every tier is either **network-endpoint** (`static`,
> `aws-ec2`, `aws-lambda-microvm` — driven over `remote_http`) or **file-handshake** (`gvisor`,
> `firecracker`). You can't mix them in one cascade (a job can't use both transports) — the dispatcher
> **fails fast** at startup if you do. So "local + remote overflow" means a network-endpoint local tier
> (`static` boxes you own), not `gvisor`/`firecracker`.

Example — 8 warm workers on a rack of boxes you own, overflow to AWS:
```
BLASTBOX_POOL_RUNTIME=cascade
BLASTBOX_POOL_TIERS=static:8,aws-ec2:16       # all network-endpoint
BLASTBOX_STATIC_WORKERS=box1:8765,box2:8765,box3:8765,box4:8765,box5:8765,box6:8765,box7:8765,box8:8765
BLASTBOX_EC2_AMI=ami-...            # (+ BLASTBOX_EC2_* placement)
BLASTBOX_POOL_WARM_SIZE=8
BLASTBOX_POOL_BURST_SIZE=16         # so the pool can burst 8 warm -> 24 (into the 16 AWS overflow slots)
BLASTBOX_POOL_CEILING=24
BLASTBOX_DISPATCH_CONCURRENCY=24
```

## Worker HTTP agent + mTLS (network-endpoint tiers)

The `static` / `aws-*` / `cascade` tiers run the worker as `python -m blastbox.worker.http_agent`. These
knobs configure it; **default it to loopback + mTLS** for anything off-box (the transport is otherwise
plain HTTP for a *trusted private VPC* — do not expose it to the public internet in the clear).

| Var | Default | Notes |
|---|---|---|
| `BLASTBOX_WORKER_AGENT_PORT` | `8765` | Listen port. |
| `BLASTBOX_WORKER_AGENT_BIND` | `0.0.0.0` | Bind address. A non-loopback bind with **no** mTLS/token/allowlist **fails closed** (the agent refuses to start) unless `BLASTBOX_WORKER_AGENT_ALLOW_INSECURE=1`. |
| `BLASTBOX_WORKER_AGENT_ALLOW_INSECURE` | `0` | Opt back into serving on a non-loopback address with **no** request gate — only when an **external** gate already fences the port (AWS microVM JWE proxy, a security group, a private worker network). Proxy-gated tiers (e.g. `aws-lambda-microvm`) that don't bake in a token must set this in the worker image env. |
| `BLASTBOX_WORKER_AGENT_TOKEN` | — | Bearer token required on `/detonate` (`X-aws-proxy-auth` / `Authorization: Bearer`). |
| `BLASTBOX_WORKER_AGENT_MAX_BYTES` | `512MiB` | Max request body. |
| `BLASTBOX_WORKER_AGENT_HARD_TIMEOUT_S` | `2×timeout+30` | Hard ceiling for one detonation; a hung engine that blows past it **retires the worker** (`os._exit`, the supervisor/pool replaces the box) so it can't hold the single-flight lock forever. Defaults to twice the per-job `timeout_s` + 30s (never trips a normal job); `0` disables. |
| `BLASTBOX_WORKER_AGENT_TLS_CERT` / `_TLS_KEY` | — | Serve **HTTPS** with this server cert/key (mint via `blastbox pki issue-server`). |
| `BLASTBOX_WORKER_AGENT_CLIENT_CA` | — | Require a **client** cert signed by this CA (**mTLS**) — the cryptographic allowed-caller gate. |
| `BLASTBOX_WORKER_AGENT_ALLOW_CIDRS` | — | Comma-list of CIDRs allowed to POST `/detonate` (peer-IP allowlist; 403 otherwise). Defense-in-depth with mTLS + the SG. |

**Dispatcher (client) side** — build the mTLS context the transport presents:

| Var | Default | Notes |
|---|---|---|
| `BLASTBOX_DISPATCH_TLS_CA` | — | CA that signed the workers' server certs (verify them). Setting it turns on `https://`. |
| `BLASTBOX_DISPATCH_TLS_CERT` / `_TLS_KEY` | — | The dispatcher's client cert/key (mTLS; `blastbox pki init` mints `dispatcher.{crt,key}`). |

**PKI / cert generation** — `BLASTBOX_PKI_DIR` (default `/var/lib/blastbox/pki`) holds the CA. The
`blastbox pki` CLI generates + issues everything (pure `cryptography`, no openssl):
```
blastbox pki init                              # CA (ca.crt/ca.key) + dispatcher client cert
blastbox pki issue-server --san 10.0.0.5       # a worker's server cert, SAN-pinned (short-lived)
blastbox pki show-ca                           # the public CA cert -> bake into worker images
```
Bake `ca.crt` into worker images (public trust anchor); keep `ca.key` on the dispatcher only. For
disposable workers, mint the server cert per-spawn (SAN = the instance IP) rather than baking a key.

## Runtime: libvirt VM (full-OS engines)

Unlike the FC/gVisor warm tiers — selected by `BLASTBOX_POOL_RUNTIME` and configured by
`BLASTBOX_*` env — the **libvirt/KVM VM-worker tier is a library primitive, not an env-selected
runtime.** A consuming app (e.g. win-validator) builds a `VmWorkerSpec` (`host/runtime/vm_compose.py`)
and drives it through the generic `WarmPool` + `VmJobDispatcher`. So these knobs are **spec fields the
consumer sets** (often mapped from its *own* env, e.g. win-validator's `AUTHENTICODE_IP_POOL`), not
`BLASTBOX_*` vars. They are listed here because their **security semantics** are blastbox's.

| `VmWorkerSpec` field | Default | Notes |
|---|---|---|
| `image` (`VmImageSpec`) | — | The golden qcow2. A **string** ⇒ the path (e.g. `image: /dev/shm/golden-base.qcow2`); a **mapping** ⇒ a build recipe (`image.golden` = where to bake it, plus `base_qcow2`/provisioner). Each job gets a disposable overlay. *(The field is `image`, not `golden` — a top-level `golden:` key raises `ValueError` at `VmWorkerSpec.from_dict`.)* Golden **rotation is not automatic** — it's a separate helper the consuming app schedules (build a fresh golden, then flip the spec). |
| `warm_size` / `concurrent_ceiling` / `jobs_per_recycle` / `max_jobs_per_slot` | `2` / `16` / `1` / `0` | Warm slots / max concurrent / jobs a slot serves before `recycle()` **reverts it to the clean snapshot in place and reuses it** / total jobs before it's reaped+respawned (`0` = unlimited). Safety comes from the per-job snapshot revert, not a fresh VM; for **true destroy-and-respawn per document** (no slot reuse at all) set `max_jobs_per_slot=1`. |
| `worker_ip_pool` | `""` | **Assign+enforce.** `"START-END"` within a single /16 (size it for the **peak concurrent** worker count — the pool bursts from `warm_size` toward `concurrent_ceiling` under load, so `≥ concurrent_ceiling` avoids exhaustion) ⇒ blastbox reserves a DHCP host entry and **pins an explicit IP** per worker (`CTRL_IP_LEARNING=none` + nwfilter `IP=`), with a deterministic MAC derived from the IP. A root-compromised guest then **can't re-IP** around the egress rooter. **`""` ⇒ DHCP-learning** (`clean-traffic` `CTRL_IP_LEARNING=dhcp`) — convenient, but a long-idle warm worker's learned pin lapses with the lease, so assign-enforce is the **snapshot-robust / secure** mode. |
| `nwfilter` | `clean-traffic` | libvirt nwfilter bound to the worker NIC (`no-mac-spoofing` + `no-ip-spoofing` + `allow-dhcp-server`). `""` ⇒ no filterref (no L2 anti-spoof — only do this behind another boundary). |
| `nwfilter_ip_learning` | `dhcp` | `CTRL_IP_LEARNING` for the DHCP-learning path (`dhcp` or `any`; `none` is rejected here because it needs `worker_ip_pool`). Unused once `worker_ip_pool` is set. |
| `dhcp_server` | `""` | `clean-traffic` `DHCPSERVER` parameter — the **trusted** dnsmasq a worker may accept leases from, so it can't rogue-DHCP itself a different one. `""` ⇒ derived as `subnet_prefix` + `.1`. |
| `mac_prefix` | `52:54:00:bb` | OUI for assign-enforce MACs; the last 2 octets are the IP's 3rd+4th, giving a 1:1 MAC↔IP map within the /16. |
| `subnet_prefix` | `192.168.122.` | The libvirt network's subnet, used for the `DHCPSERVER` default and pool sanity. |
| `egress` (`VmEgressPolicy`) / `routing` (`ExitRouting`) | `None` | Optional per-worker egress through `LibvirtEgress` (a CAPE-style per-IP `iptables` `BBVM_<ip>` chain + `FORWARD` jump): exit driver, port allowlist, `block_internal`, VPN/SOCKS routing. `None` ⇒ no egress wired. |

## Per-engine params (engine ↔ host boundary)

| Var | Default | Notes |
|---|---|---|
| `BLASTBOX_ENGINE_<NAME>_PARAM_KEYS` | unset | **Allowlist** of `job.params` keys forwardable to that engine's worker as env. **Unset** ⇒ legacy shape+denylist only (a hostile job's params could reach engine knobs — so set this on **every** tier that runs the engine). **Set** (even to an empty value) ⇒ strict allowlist: only the listed keys pass, and an empty value blocks **all** params. e.g. `BLASTBOX_ENGINE_CLIPPYSHOT_PARAM_KEYS=CLIPPYSHOT_OCR,CLIPPYSHOT_QR,…`. |
| `BLASTBOX_ENGINE_<NAME>_DEFAULT_PARAMS` | `""` | **Operator default params**: `KEY=VAL,KEY2=VAL2` applied for any key a job does **not** set (the per-job value always wins). Makes an enablement default — e.g. a scanner toggle — a **runtime** decision in the dispatcher env instead of a value hardcoded in the engine: flip it + restart the dispatcher, no image/snapshot rebuild, and it reaches **cold and warm** tiers alike. Each defaulted key must itself be forwardable (in `_PARAM_KEYS`) and non-reserved — it passes the same gate as a client param, so the default reaches the worker only where a client param with that key would have. Set on **every** tier that runs the engine (it's read where params are forwarded). e.g. `BLASTBOX_ENGINE_REDTUSK_DEFAULT_PARAMS=REDTUSK_ENABLE_QR=1,REDTUSK_ENABLE_OCR=0`. |
| `BLASTBOX_ENGINE_<NAME>_RESERVED_KEYS` | unset | Extra param keys **dropped unconditionally** (cold **and** warm), unioned into the engine's built-in `reserved_param_keys` floor. For knobs that must *never* be client/job-settable because they're RCE-adjacent — a JVM engine's `JAVA_BIN`/`JAVA_OPTS`/`WORKER_JAR`, a sandbox-downgrade switch. Keys are upper-cased and stripped **before** the `_PARAM_KEYS` allowlist is applied, so a reserved key can't be re-admitted by also listing it. The framework core carries **no** hardcoded `CLIPPYSHOT_*`/engine-specific reserved keys — each engine declares its own floor (via `EngineSpec.reserved_param_keys`) and the operator extends it here. e.g. `BLASTBOX_ENGINE_REDTUSK_RESERVED_KEYS=JAVA_BIN,JAVA_OPTS,WORKER_JAR`. |
| `BLASTBOX_ENGINE_<NAME>_ALLOWED_RUNTIMES` | unset (any tier) | Comma-list of dispatcher **tiers** this engine may run on, from the canonical vocabulary `cold` / `firecracker` / `gvisor` / `libvirt-vm` / `aws-ec2` / `aws-ec2-hibernate` / `aws-lambda-microvm` / `aws-lambda-snapstart` / `static` / `cascade`. **Unset or empty ⇒ any tier.** Set ⇒ the dispatcher **refuses to start** (before the pool spawns any slot) if its own tier — `cold`, or `BLASTBOX_POOL_RUNTIME` — isn't listed, so a runtime misconfig can't silently route a locally-vetted engine onto a public-AWS/remote worker with a different egress posture. Must list **every** tier the engine is meant to run on (fail-closed). An unknown tier name is a hard error. e.g. `BLASTBOX_ENGINE_CLIPPYSHOT_ALLOWED_RUNTIMES=cold,firecracker,gvisor`. |

## Network policy / egress overlay (netpolicy)

Egress control has two layers: the **dispatcher** resolves a per-job *personality* (a named egress policy) and picks the worker's Docker `--network`; the privileged **`blastbox-netd`** helper (a host systemd unit, out-of-band from the cap-dropped dispatcher) wires the actual exit — netns TUN + tun2socks, host REDIRECT → tor, a VPN gateway route, or an MITM inspect gateway. Everything is **fail-closed**: unset/malformed knobs leave the worker with **no route out**, and the whole feature is inert until an operator declares a personality.

| Var | Default | Notes |
|---|---|---|
| `BLASTBOX_NETPOLICY_<NAME>` | (only `none`) | Operator personality registry — one env var per named policy; value is `exit=<driver>,k=v,…`. `exit=` drivers: `none`, `drop`, `direct`, `inetsim`, `tor`, `socks`, `httpproxy`, `wireguard`, `openvpn` (unknown/missing `exit` ⇒ warned + not selectable). `inspect=1` routes through the MITM gateway. `BLASTBOX_NETPOLICY_NONE` is reserved (the fail-closed default) and ignored with a warning. |
| `BLASTBOX_ALLOW_NETPOLICY_OVERRIDE` | `0` (off) | Truthy ⇒ a job may pick a *declared* personality by name; otherwise the per-engine default (else `none`) is forced. An undeclared name always collapses to `none`. |
| `BLASTBOX_NET_CAPTURE` | `0` (off) | Truthy ⇒ egress workers are labelled for `blastbox-netd` to capture a host-side pcap, sealed into the result envelope as a trusted artifact. Needs netd running; the dispatcher stays cap-drop=ALL. |
| `BLASTBOX_NET_CAPTURE_WAIT_S` | `5` | Seconds the dispatcher waits for netd's `<pcap>.done` sentinel before sealing (so the capture isn't copied mid-write). Clamped `[0, 60]`. |
| `BLASTBOX_NET_DECRYPT` | `0` (off) | Truthy **and** a TLS keylog present in the job's capture dir ⇒ run GoGoRoboCap to seal `decrypted.pcap` + `mixed.pcap`. Best-effort: a missing/hostile keylog is a silent no-op, never fails the job. |
| `BLASTBOX_NET_DECRYPT_KEYLOG_WAIT_S` | `8` | Seconds the dispatcher polls for the per-job keylog (`sslkeys.log`) before decrypt (netd drops it on the worker DIE event, which races the seal). Clamped `[0, 60]`. |
| `BLASTBOX_GOGOROBOCAP_BIN` | `gogorobocap` | Path/name of the GoGoRoboCap TLS-replay binary used by `BLASTBOX_NET_DECRYPT`. |
| `BLASTBOX_NETD_SOCKS_PROXY` | `""` (disabled) | **netd:** SOCKS5 URL (`socks5://[user:pass@]host:port`) for the `socks` tier — enables netns TUN + tun2socks for workers labelled `blastbox.net.wire=socks`. |
| `BLASTBOX_NETD_VPN_GATEWAY` | `""` (disabled) | **netd:** VPN+NAT gateway sidecar IP for the `vpn`/`openvpn`/`wireguard` tier; default-routes labelled workers through it. |
| `BLASTBOX_NETD_INSPECT_GATEWAY` | `""` (disabled) | **netd:** sslproxy/MITM gateway IP for the `inspect` tier; default-routes inspected workers through it. |
| `BLASTBOX_NETD_INSPECT_KEYLOG` | `""` (disabled) | **netd:** host path to the sslproxy gateway's `SSLKEYLOGFILE`, snapshotted into each inspect job's capture dir as `sslkeys.log` so the dispatcher can decrypt. |
| `BLASTBOX_NETD_TRANSPROXY_GATEWAY` | `""` (disabled) | **netd:** host bridge gateway IP that `tor` (CAPE-transparent) workers default-route through before the host REDIRECTs their TCP/DNS to tor. |
| `BLASTBOX_NETD_TRANSPROXY_TRANS_PORT` | `9040` | **netd:** tor `TransPort` the host REDIRECTs worker TCP to. |
| `BLASTBOX_NETD_TRANSPROXY_DNS_PORT` | `5353` | **netd:** tor `DNSPort` the host REDIRECTs worker `:53` to. |

**Wired vs. fail-closed on the Docker path.** Only `direct` (bridge `bb-net0`) and `inetsim` (`bb-fakenet`) are self-contained docker-native exits (operator pre-creates the bridge). `socks`/`tor`/`httpproxy` attach to an internal `bb-socks` bridge and `openvpn`/`wireguard` to `bb-vpn` — neither has direct egress on its own; the real exit is wired by `blastbox-netd`. So **without netd running and the matching `BLASTBOX_NETD_*` knob set, those workers sit on an internal bridge with no route** — fail-closed, but by "internal bridge, no egress" rather than literally `--network=none` (used only for `none`/`drop`/unknown drivers). `BLASTBOX_NET_EGRESS` (a `Limits` field) is set **per-job by the dispatcher** (`1` for a personality with a real exit, else `0`, merged last so a hostile `job.param` can't flip it) and only decides whether an inner namespace sandbox net-*shares* the worker netns — operators don't normally hand-set it.
