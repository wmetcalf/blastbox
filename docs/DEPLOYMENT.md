# Deployment guide

How to choose a deployment shape, which knobs each needs, and the per-tier capability
constraints. For the full knob list see **[CONFIGURATION.md](CONFIGURATION.md)**.

## The two axes

A blastbox deployment is **an outer runtime × an inner sandbox**, optionally **warm**:

```
OUTER runtime (host isolation)          INNER sandbox (in-worker, wraps the engine's subprocesses)
  runc        OCI container only          nsjail     namespaces + KAFEL seccomp + rlimits  (needs userns)
  runsc       gVisor userspace kernel      bwrap      user-namespace mounts, no seccomp     (needs userns)
  firecracker hardware KVM microVM         nono       Landlock fs+net, NO userns            (composes anywhere Landlock exists)
                                           container  trust the enclosing OCI boundary      (the default inside runsc/FC)
```

The outer runtime is the real isolation boundary; the inner sandbox is defense-in-depth.
**Inside `runsc`/`firecracker` the inner sandbox is `container`** — nesting namespaces is
redundant, and (for nono) Landlock isn't even available under runsc (below).

## Tier-capability matrix

| Tier | Host isolation | Inner sandbox | Landlock (nono) usable? | Warm path |
|---|---|---|---|---|
| **runc** (cold) | container only (weak) | nsjail / bwrap / nono / container | ✅ host kernel (ABI v4) | — |
| **runsc** (cold) | gVisor Sentry (strong) | container | ❌ **Sentry returns ENOSYS** | — |
| **gVisor C/R** (warm) | gVisor Sentry | container | ❌ ENOSYS | runsc checkpoint/restore |
| **firecracker** (warm/cold) | hardware KVM microVM (strongest) | container (+ nono in-guest) | ✅ guest kernel ships `landlock_*` | FC mem snapshot (warm-UNO) |

> **The Landlock footgun.** nono needs the `landlock_*` syscalls. The **gVisor Sentry does
> not implement them** (verified: `landlock_create_ruleset` → ENOSYS) — so the inner-nono
> layer **cannot** run under runsc/gVisor and `select_sandbox` / `build_worker_docker_run_argv`
> **fail-fast or skip+warn** there. nono-nesting belongs on **runc** (its main value — the one
> tier with a weak outer boundary) and **the FC guest**. gVisor relies on its Sentry, which is
> itself a syscall sandbox, so nono adds nothing there — they're *substitutes, not layers*.

## Which tier do I want?

- **Bare-metal host, no KVM, no gVisor** → `runc` + an inner namespace sandbox. Prefer
  **`nsjail`** (full seccomp); use **`nono`** where unprivileged user namespaces are
  disabled (`nsjail`/`bwrap` can't run) — Landlock needs no userns. On Ubuntu 24.04+ load the
  AppArmor userns profiles first (`deploy/apparmor/`), or `nsjail`/`bwrap` can't create userns.
- **Host with gVisor** → `runsc` (the secure default; `runc` is fail-closed-refused unless
  `BLASTBOX_ALLOW_RUNC=1`). Inner sandbox = `container`.
- **Host with KVM** → `firecracker` — the strongest boundary (hardware VM, no guest NIC).
  Add the **warm-UNO snapshot** tier for LibreOffice to hide the ~750 ms soffice boot.
- **Throughput-sensitive** → a **warm pool** (FC snapshot or gVisor C/R), sized so
  `BLASTBOX_DISPATCH_CONCURRENCY == BLASTBOX_POOL_WARM_SIZE`.

Defense-in-depth on the weak tier: enable **`BLASTBOX_WORKER_NONO_WRAP=1`** on the **runc**
cold path to Landlock-confine the whole worker (write-confinement + network block) on top of
the container. It is a no-op/skip under runsc.

## Security defaults (don't have to be configured)

- Disposable worker per job: `--network=none --cap-drop=ALL --no-new-privileges --read-only`;
  input deleted after conversion; output re-sealed from disk (worker hashes never trusted).
- **runsc is required by default, fail-closed.** No secure runtime + no `BLASTBOX_ALLOW_RUNC`
  ⇒ the dispatcher refuses the job early (`InsecureRuntimeRefused`).
- Per-engine param **allowlist** is default-deny — set `BLASTBOX_ENGINE_<NAME>_PARAM_KEYS` on
  every tier that runs the engine (cold dispatcher **and** every warm sidecar).

## Deployment shapes

### 1. Single host, one process pair (simplest)

```sh
export BLASTBOX_DATABASE_URL=sqlite:////var/lib/blastbox/jobs.db
export BLASTBOX_ENGINES=clippyshot=clippyshot-worker:latest
blastbox serve --host 127.0.0.1 --port 8000   # ingress
blastbox dispatch                              # launches a hardened runsc worker per job
```
Inner sandbox auto-selects `container` inside the worker image; runsc is required (fail-closed).

### 2. Warm-pool sidecar topology (the production shape)

A **socket-less cold dispatcher** (break-glass / overflow) plus one **warm sidecar per warm
backend**, each `BLASTBOX_DISPATCH_WARM_ONLY=1` so it claim-gates on free warm slots and never
cold-falls-back. The FC sidecar needs only `/dev/kvm`; the gVisor-C/R sidecar needs a scoped
cap set + `seccomp=unconfined` for `runsc` (confined to that single-purpose, socket-less box).
See `deploy/docker/docker-compose.{firecracker,gvisor}.yml` for the exact services. Every
sidecar **must** repeat `BLASTBOX_ENGINE_<NAME>_PARAM_KEYS` and its pool sizing
(`BLASTBOX_DISPATCH_CONCURRENCY == BLASTBOX_POOL_WARM_SIZE`).

Tier-specific gotchas, captured here so they aren't re-discovered:
- gVisor C/R sidecar: `BLASTBOX_GVISOR_PLATFORM=systrap` (ptrace is too slow — blows the OCR
  deadline); needs `SYS_ADMIN`/`SYS_PTRACE`/`NET_ADMIN` (not `cap_drop=ALL`) + a clean state
  dir on startup; do **not** set `BLASTBOX_WORKER_NONO_WRAP` (Landlock ENOSYS).
- FC sidecar: `BLASTBOX_FC_VCPU=1` (pinned), guest output via virtio-blk ext4 (read by
  `debugfs`), no guest NIC. Landlock *is* available in the guest, so inner-nono works there.

## Generating a sandbox policy (optional, advanced)

`blastbox.profile` traces an engine over a corpus and emits candidate seccomp/Landlock
policies, and a **drift-gate** (`tests/profile/test_drift_gate.py`) asserts the engine uses
no escape-only syscall and opens no network egress — run it in CI to catch a dependency bump
that widens the surface. Feed a generated nono profile to `BLASTBOX_WORKER_NONO_PROFILE`
(outer wrap) or the engine's inner-nono profile knob. Candidate seccomp allowlists are
**reviewed artifacts**, not auto-shipped — the denylist stays the default.
