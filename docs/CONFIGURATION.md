# Configuration reference

Every `BLASTBOX_*` knob, grouped by subsystem, with its default. **You set almost none of
these** — the defaults run a secure single-host deployment. The large surface is for tuning
the optional warm-pool / runtime / sandbox tiers. Engine-specific knobs (e.g. ClippyShot's
`CLIPPYSHOT_*`) are documented by the engine; the host forwards a per-engine **allowlist** of
them (see *Per-engine params* below), never the whole environment.

> **How values are read.** Most knobs are read as `os.environ.get(...) or default` — a
> **set-but-empty** value (e.g. `FOO=` from a compose `${FOO:-}`) is treated as *unset*.
> Booleans are truthy unless one of `"" 0 false no`.

See **[DEPLOYMENT.md](DEPLOYMENT.md)** for which of these to set for each deployment shape
and the tier-capability matrix.

---

## Core / ingress / job store

| Var | Default | Notes |
|---|---|---|
| `BLASTBOX_DATABASE_URL` | in-memory | **Required for the 2-process (serve+dispatch) flow.** `sqlite:///…`, `postgresql://…`, or `redis://…`. Unset → each process gets its own in-memory store (jobs invisible across processes; a warning is logged). |
| `BLASTBOX_JOB_ROOT` | `/var/lib/blastbox/jobs` | Shared per-job directory root (staged input + sealed output). Must be the same path for serve, dispatch, and the worker mount. |
| `BLASTBOX_ENGINES` | `""` | Engine registry: `name=worker_image[,name2=image2]`. The dispatcher launches the mapped image per job. |
| `BLASTBOX_ALLOWED_ENGINES` | `""` (all) | Restrict which engine names ingress will accept. Empty ⇒ accept any (a warning is logged); set `BLASTBOX_REQUIRE_ENGINE_ALLOWLIST=1` to make an empty allowlist a hard startup error instead. |
| `BLASTBOX_REQUIRE_ENGINE_ALLOWLIST` | `0` | When truthy, ingress refuses to start if `BLASTBOX_ALLOWED_ENGINES` is empty (fail-closed; rejects unknown engines before the disk spool instead of at dispatch). |
| `BLASTBOX_INPUT_DIR` / `BLASTBOX_OUTPUT_DIR` | `/input` / `/output` | **Worker-side** mount points — the dispatcher injects these into the worker container env. They do **not** relocate host staging, which is always `JOB_ROOT/<job_id>/{input,output}`. |
| `BLASTBOX_JOB_RETENTION_SECONDS` | store default | TTL after which finished jobs + artifacts are reaped. |
| `BLASTBOX_REDIS_TTL_SECONDS` | `86400` (24h) | Per-key expiry for the Redis job store. Keep it `>= BLASTBOX_JOB_RETENTION_SECONDS`, or `0` to disable key expiry — otherwise a key can expire before retention sweeps it, orphaning the on-disk job dir under `JOB_ROOT` (no record left for retention/API-delete). Redis store only. |
| `BLASTBOX_API_KEY` | `""` (open) | Optional bearer token required on the API. Usually unset — auth is delegated to a reverse proxy. |
| `BLASTBOX_API_WORKERS` | `4` | uvicorn worker processes for `blastbox serve`. |
| `BLASTBOX_METRICS_PUBLIC` | `true` | Serve `/metrics` without auth. |
| `BLASTBOX_INGRESS_EXTENSION` | `""` | Optional ingress extension entry point. |
| `BLASTBOX_ZIP_PASSWORD` | `infected` | Password tried for password-protected sample archives (the malware-corpus convention). |

## Dispatch

| Var | Default | Notes |
|---|---|---|
| `BLASTBOX_DISPATCH_CONCURRENCY` | `1` | Dispatch-loop worker threads. **On a warm tier this MUST equal the warm pool size** — the warm path blocks until the job finishes, so N threads are needed to keep N slots busy (default 1 starves the pool). |
| `BLASTBOX_DISPATCH_WARM_ONLY` | `""` (off) | Claim-gate primitive: only claim jobs when a warm slot is free, and **never cold-fall-back** — overflow stays queued for the cold dispatcher. This is what makes a process a *warm sidecar*. |

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
| `BLASTBOX_POOL_RUNTIME` | runtime default | Warm backend: `firecracker`, `gvisor`, `aws-lambda-microvm`, `aws-ec2`, `static`, or `cascade` (tiered local→overflow). |
| `BLASTBOX_POOL_WARM_SIZE` | — | Number of pre-warmed slots. |
| `BLASTBOX_POOL_CEILING` | — | Max concurrent slots (warm + burst). |
| `BLASTBOX_POOL_BURST_SIZE` | — | Extra cold-burst slots above the warm set under load. |
| `BLASTBOX_POOL_SPAWN_RATE` | — | Slot replenish rate. |
| `BLASTBOX_POOL_WARMING_TIMEOUT_S` | `120` | Max seconds a slot may sit WARMING before eviction. **Raise for cloud tiers** (`aws-ec2` first-boot can exceed 120s) or healthy-but-slow slots get churned. |
| `BLASTBOX_POOL_WARM_SNAPSHOT` | `0` | FC only: restore from a memory snapshot (warm-UNO) instead of cold-booting the guest. |

## Runtime: Firecracker

| Var | Default | Notes |
|---|---|---|
| `BLASTBOX_FC_BIN` / `BLASTBOX_FC_KERNEL` / `BLASTBOX_FC_ROOTFS` | — | Paths to the firecracker binary, guest `vmlinux`, and `rootfs.ext4`. |
| `BLASTBOX_FC_VCPU` | `1` | **Pinned at 1** — the vsock stream-corruption mitigation. Do not raise without validating the guest vsock driver under concurrency. |
| `BLASTBOX_FC_MEM_MIB` | `512` | Guest RAM (compose sets 2048 for LibreOffice). |
| `BLASTBOX_FC_OUTDISK_MIB` | — | Size of the per-slot ext4 output disk the host reads via `debugfs`. |
| `BLASTBOX_SNAPSHOT_MEM_DIR` / `BLASTBOX_SNAPSHOT_MEM_TMPFS` | — | Where the warm memory-snapshot base lives; `_TMPFS` pins the CoW base in RAM (per-host toggle). |
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
| **Lambda MicroVM** (`aws-lambda-microvm`) | | transport = per-VM HTTPS URL + JWE token |
| `BLASTBOX_LAMBDA_IMAGE` | — | **Required.** An **in-account** MicroVM image ARN built via `create-microvm-image` (the managed base `…:aws:microvm-image:al2023-1` is **not** directly runnable — verified live). |
| `BLASTBOX_LAMBDA_EXEC_ROLE_ARN` | — | Execution role for `run-microvm`. |
| `BLASTBOX_LAMBDA_EGRESS_CONNECTORS` | `""` | Comma-list of egress-connector ids (list arg). **Empty ⇒ AWS default `INTERNET_EGRESS` (not sealed)** — pass a no-internet connector to seal outbound. |
| `BLASTBOX_LAMBDA_INGRESS_CONNECTORS` | `""` | Comma-list of ingress-connector ids (empty ⇒ none configured). |
| `BLASTBOX_LAMBDA_AUTH_TTL_MIN` | `15` | JWE lifetime for `create-microvm-auth-token` (`--expiration-in-minutes`); token is minted fresh at probe time + scoped to the agent port. |
| **Disposable EC2** (`aws-ec2`) | | transport = instance IP:port (private by default) |
| `BLASTBOX_EC2_AMI` | — | **Required.** Worker AMI (agent brought up via user-data). |
| `BLASTBOX_EC2_INSTANCE_TYPE` | `m7g.large` | ARM64 default (matches the sealed-Linux ARM image); override for x86. |
| `BLASTBOX_EC2_SUBNET_ID` / `BLASTBOX_EC2_SECURITY_GROUPS` | — | VPC placement + SGs (comma-list). |
| `BLASTBOX_EC2_IAM_PROFILE` / `BLASTBOX_EC2_KEY_NAME` | — | Instance profile name / SSH key name. |
| `BLASTBOX_EC2_PUBLIC_IP` | `0` | `1` ⇒ talk to the public IP (default: private, host in-VPC). |
| `BLASTBOX_EC2_USER_DATA_B64` | — | base64 cloud-init that starts the worker agent on `AGENT_PORT`. **Bake a self-terminate TTL** (`shutdown` after `MAX_DURATION_S`) so a crashed dispatcher can't leak a running instance — `--instance-initiated-shutdown-behavior terminate` only fires if the guest shuts itself down. |
| `BLASTBOX_EC2_AGENT_TOKEN` | — | Bearer token the AMI's agent expects (`BLASTBOX_WORKER_AGENT_TOKEN`); forwarded on both the readiness probe and `/detonate`. |

The **generic worker agent** (`python -m blastbox.worker.http_agent`, `BLASTBOX_ENGINE=module:Class`)
serves any engine over `GET /healthz` + `POST /detonate`; bake it + the engine + its deps into the
worker image. `BLASTBOX_WORKER_AGENT_PORT` / `BLASTBOX_WORKER_AGENT_TOKEN` / `BLASTBOX_WORKER_AGENT_MAX_BYTES`
tune it.

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
| `BLASTBOX_POOL_TIERS` | — | **Required.** Ordered `backend:capacity` list, e.g. `gvisor:4,aws-ec2:16` — 4 warm local + up to 16 overflow on AWS. Backends: `gvisor`, `firecracker`, `static`, `aws-ec2`, `aws-lambda-microvm`. |

The **primary** (first) tier must be available at startup (fail-closed); an **overflow** tier that isn't
available is logged and skipped, so local capacity still comes up if the cloud/remote tier is
misconfigured. Set `BLASTBOX_POOL_WARM_SIZE` to the local tier's capacity (keep those warm),
`BLASTBOX_POOL_CEILING` to the sum (local + overflow), and `BLASTBOX_DISPATCH_CONCURRENCY` to the ceiling.

Example — 4 warm gVisor locally, overflow to a rack of other boxes, then AWS:
```
BLASTBOX_POOL_RUNTIME=cascade
BLASTBOX_POOL_TIERS=gvisor:4,static:8,aws-ec2:16
BLASTBOX_STATIC_WORKERS=box1:8765,box2:8765,box3:8765,box4:8765
BLASTBOX_EC2_AMI=ami-...            # (+ BLASTBOX_EC2_* placement)
BLASTBOX_POOL_WARM_SIZE=4
BLASTBOX_POOL_CEILING=28
BLASTBOX_DISPATCH_CONCURRENCY=28
```

## Worker HTTP agent + mTLS (network-endpoint tiers)

The `static` / `aws-*` / `cascade` tiers run the worker as `python -m blastbox.worker.http_agent`. These
knobs configure it; **default it to loopback + mTLS** for anything off-box (the transport is otherwise
plain HTTP for a *trusted private VPC* — do not expose it to the public internet in the clear).

| Var | Default | Notes |
|---|---|---|
| `BLASTBOX_WORKER_AGENT_PORT` | `8765` | Listen port. |
| `BLASTBOX_WORKER_AGENT_BIND` | `0.0.0.0` | Bind address. A non-loopback bind with **no** mTLS/token/allowlist logs a loud warning. |
| `BLASTBOX_WORKER_AGENT_TOKEN` | — | Bearer token required on `/detonate` (`X-aws-proxy-auth` / `Authorization: Bearer`). |
| `BLASTBOX_WORKER_AGENT_MAX_BYTES` | `512MiB` | Max request body. |
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

## Per-engine params (engine ↔ host boundary)

| Var | Default | Notes |
|---|---|---|
| `BLASTBOX_ENGINE_<NAME>_PARAM_KEYS` | unset | **Allowlist** of `job.params` keys forwardable to that engine's worker as env. **Unset** ⇒ legacy shape+denylist only (a hostile job's params could reach engine knobs — so set this on **every** tier that runs the engine). **Set** (even to an empty value) ⇒ strict allowlist: only the listed keys pass, and an empty value blocks **all** params. e.g. `BLASTBOX_ENGINE_CLIPPYSHOT_PARAM_KEYS=CLIPPYSHOT_OCR,CLIPPYSHOT_QR,…`. |
| `BLASTBOX_ENGINE_<NAME>_DEFAULT_PARAMS` | `""` | **Operator default params**: `KEY=VAL,KEY2=VAL2` applied for any key a job does **not** set (the per-job value always wins). Makes an enablement default — e.g. a scanner toggle — a **runtime** decision in the dispatcher env instead of a value hardcoded in the engine: flip it + restart the dispatcher, no image/snapshot rebuild, and it reaches **cold and warm** tiers alike. Each defaulted key must itself be forwardable (in `_PARAM_KEYS`) and non-reserved — it passes the same gate as a client param, so the default reaches the worker only where a client param with that key would have. Set on **every** tier that runs the engine (it's read where params are forwarded). e.g. `BLASTBOX_ENGINE_REDTUSK_DEFAULT_PARAMS=REDTUSK_ENABLE_QR=1,REDTUSK_ENABLE_OCR=0`. |
