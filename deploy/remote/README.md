# Network-endpoint worker profiles (static / AWS / cascade)

The network-endpoint tiers (`static`, `aws-ec2`, `aws-lambda-microvm`, `cascade`) run the
**generic HTTP worker agent** (`python -m blastbox.worker.http_agent`) off-box and drive it over the
`remote_http` HTTP+tar transport. The **host/tier config is engine-agnostic** — which runtime, EC2
placement, mTLS, cascade sizing are identical whatever engine you run. What differs per engine is a
small, well-bounded slice, captured in the profiles here:

| Per-engine delta | ClippyShot | RedTusk |
|---|---|---|
| **Worker image** (prebaked, NOT env) | `clippyshot-cold-worker` (LibreOffice + PDFium) | `redtusk-cold-worker` (JDK 25 + Tika-fork jar) |
| `BLASTBOX_ENGINE` (baked in the image) | `clippyshot.engine:ClippyShotEngine` | `redtusk.engine:RedTuskEngine` |
| Param allowlist / reserved keys | `CLIPPYSHOT_*` | `REDTUSK_*` |
| Egress `net_policy` | `none` | `none` |
| Resource caps | defaults | `2g` / `2` cpu / `100 MiB` metadata |

The **only thing that isn't config** is the worker image: it bakes the engine + its runtime deps, so
you build one image per engine. Everything else is env.

> **Cold vs warm AWS tiers.** `aws-ec2` / `aws-lambda-microvm` are COLD/disposable — a fresh worker
> boots per job and terminates. `aws-lambda-snapstart` is the **WARM** AWS tier: it runs each MicroVM
> with an idle-policy so AWS auto-suspends idle warm slots (full mem+disk preserved — JVM/soffice stay
> booted) and the dispatcher `resume-microvm`s one per job (sub-second), then terminates it after one
> untrusted job. The boot + `engine.warmup()` cost is paid **off the critical path** during background
> pool replenishment. It is still disposable-per-job (never reuses a slot across untrusted inputs).
> The separate **local** warm-snapshot family (FC microVM snapshot, gVisor C/R, CRaC — file-handshake,
> needs `/dev/kvm` or `runsc`) is `docs/DEPLOYMENT.md` shape 2. All AWS tiers share the `*-cold-worker`
> image (its agent runs `engine.warmup()` before serving, so a healthy endpoint means warm).

## Usage

Pick a **tier** and pick an **engine profile**. Source the engine profile, then set the tier knobs
(see `docs/CONFIGURATION.md` → *Runtime: static / AWS / cascade* and `docs/DEPLOYMENT.md` → shape 3):

```sh
# 1. engine slice (this dir)
set -a; . deploy/remote/redtusk.env.example; set +a

# 2. tier slice — e.g. a fixed fleet of boxes you own:
export BLASTBOX_POOL_RUNTIME=static
export BLASTBOX_STATIC_WORKERS=box1:8765,box2:8765,box3:8765
export BLASTBOX_STATIC_WORKER_TOKEN=…            # or mTLS: BLASTBOX_DISPATCH_TLS_CA/CERT/KEY
export BLASTBOX_DISPATCH_CONCURRENCY=3

# …or disposable AWS EC2:
#   export BLASTBOX_POOL_RUNTIME=aws-ec2
#   export BLASTBOX_EC2_AMI=ami-…  BLASTBOX_EC2_SUBNET_ID=…  BLASTBOX_EC2_SECURITY_GROUPS=…

blastbox serve   &   # ingress
blastbox dispatch    # network-endpoint dispatcher (auto-routes on runtime.dispatch_style)
```

The same engine profile works across **all** network-endpoint tiers — swap only the tier slice.

> **The worker image must be prebaked with the matching engine.** For `static` you build it into the
> box's own image (run it under runsc there). For `aws-ec2` the AMI's user-data starts the agent; for
> `aws-lambda-microvm` the MicroVM image ARN is built from the engine image. The profiles below assume
> that image exists — they configure the **dispatcher's** view of the engine, not the image build.
