# gVisor C/R warm tier — deploy guide

## What it is

A second warm-snapshot backend for blastbox alongside the Firecracker tier.  Instead
of a full microVM, it uses **gVisor** (`runsc`) checkpoint/restore to snapshot a warm
`unoserver`/soffice process and restore one disposable instance per job.

**Advantages over Firecracker:** requires no nested-virt support — `runsc` runs on any
cloud VM where KVM is unavailable or prohibited (e.g. GCP Tau T2D, ARM spots, VMs-in-VMs).
**Validated on toolz2.**  Full design and rationale:
`docs/specs/2026-06-05-gvisor-cr-snapshot-design.md`.

## Prerequisites

- A host with `runsc` (gVisor) installed and checkpoint/restore support enabled.
  Verify: `runsc help` lists `checkpoint` and `restore` subcommands.
- Drive `runsc` **directly** (not via containerd/CRI): the OCI checkpoint extension is
  still unimplemented upstream, so `docker checkpoint` and `ctr checkpoint` do not work.
  blastbox's `select_gvisor_snapshot_runtime` calls `runsc` directly.
- The accept-retry shim `.so` baked into the soffice image (see below).

## The accept-retry shim

### Why it is needed

gVisor's restore forces **EINTR on every blocked syscall** regardless of `SA_RESTART`
or signal mask.  Most software retries `accept()` and recovers.  LibreOffice's
`osl_acceptPipe` in `sal/osl/unx/pipe.cxx` does a **single non-retrying `accept()`**,
so its UNO-pipe acceptor bails on the restore-time EINTR and the warm conversion
hangs indefinitely.

The shim (`accept_retry.c`) interposes `accept` and `accept4` via `LD_PRELOAD` and
loops on `EINTR` — the one line of retry logic that `osl` omits.  It is **inert
outside a restore** (the retry path only fires when `errno == EINTR`).

### The Tika/JVM tier does NOT need the shim

The JVM retries `accept` automatically on EINTR.  Only the soffice warm container
needs the shim.

### Building the warm image

`Dockerfile.shim` builds the **complete** warm image from a clippyshot soffice base: it
compiles the shim **and** bakes the warm entrypoint (`run_warm.py` + `engines.py` + the
engine name in `/opt/blastbox/engine`). Recommended:

```sh
docker build \
    --build-arg BASE=clippyshot:dev \
    -f deploy/gvisor/Dockerfile.shim \
    -t clippyshot-warm:gvisor .
# soffice-free smoke image (ProbeEngine, no LibreOffice): add --build-arg ENGINE=probe
```

Shim-only (compile + COPY the `.so` into an existing image layer manually):

```sh
gcc -shared -fPIC -O2 -o /opt/clippyshot/accept-retry.so \
    deploy/gvisor/accept_retry.c -ldl
```

## The warm entrypoint (`run_warm.py`)

There is **no `worker warm` CLI**. The file-trigger warm loop is `deploy/gvisor/run_warm.py`
— the gVisor analog of the Firecracker tier's vsock `run_guest.py`. It runs `serve_warm` with a
`FileWarmControl` over the bind-mounted `/ctrl` dir (input at `/in`, output at `/out`) and picks
its engine from `/opt/blastbox/engine` (or `BLASTBOX_GVISOR_ENGINE`). `Dockerfile.shim` installs
it at `/opt/blastbox/run_warm.py`, which is why the default `BLASTBOX_GVISOR_WARM_ARGV` is
`["python3","/opt/blastbox/run_warm.py"]`. If engine setup fails it logs + drops a
`ctrl/setup_error` breadcrumb (so a misconfig is diagnosable rather than a silent ready-timeout).

### Activating the shim

Set `LD_PRELOAD=/opt/clippyshot/accept-retry.so` **only** in the environment of the
soffice/unoserver warm container (not the job-restore environment, not Tika).
blastbox reads this from `BLASTBOX_GVISOR_LD_PRELOAD` and passes it to the warm
container's env at snapshot time.

> **Required for the soffice tier — fails SILENTLY if omitted.** The gVisor OCI spec
> is built from scratch (image `ENV` is dropped), so baking the `.so` into the image is
> **not** enough — you must also set `BLASTBOX_GVISOR_LD_PRELOAD` on the **dispatcher host**.
> If you forget it, a **pipe-based** soffice (`--accept=pipe`) restore hangs on the
> osl_acceptPipe EINTR, the slot never reaches READY, and the pool silently churns + falls back
> to the cold path (no warm speedup, no loud error). The Tika/JVM tier is unaffected (it doesn't
> need the shim). **Note:** ClippyShot's unoserver uses `--accept=socket` (not a pipe), so it
> does *not* hang on this — but its warm-UNO has a different limitation under gVisor C/R; see the
> ClippyShot recipe under [Enabling the tier](#enabling-the-tier).

## Enabling the tier

Set `BLASTBOX_POOL_RUNTIME=gvisor` before starting the pool, or pass it to the
blastbox engine config.  blastbox calls `select_gvisor_snapshot_runtime()` which
reads the following env vars (all optional, defaults shown):

| Variable | Default | Purpose |
|---|---|---|
| `BLASTBOX_GVISOR_RUNSC` | `runsc` | Path to the `runsc` binary |
| `BLASTBOX_GVISOR_ROOT` | `/var/lib/blastbox/gvisor-root` | `--root` state directory for runsc |
| `BLASTBOX_GVISOR_ROOTFS` | _(image rootfs)_ | OCI rootfs path for the warm container |
| `BLASTBOX_GVISOR_NETWORK` | `none` | `none` or `sandbox` (use `none` for the warm tier) |
| `BLASTBOX_GVISOR_WARM_ARGV` | `["python3","/opt/blastbox/run_warm.py"]` | JSON list; argv of the warm entrypoint (see below). Must be a non-empty list of strings or it falls back to the default. **venv-based engine images** (e.g. clippyshot installs into `/opt/clippyshot`) must point this at the venv interpreter — `["/opt/clippyshot/bin/python3", …]` — because the default bare `python3` resolves on the spec `PATH` to the *system* interpreter, which can't `import blastbox`/the engine package (silent `ModuleNotFoundError` → never reaches READY → ready-timeout) |
| `BLASTBOX_GVISOR_LD_PRELOAD` | _(unset)_ | Set to `/opt/clippyshot/accept-retry.so` for the soffice warm container |
| `BLASTBOX_GVISOR_EXTRA_ENV` | `[]` | JSON array of `"KEY=VALUE"` strings appended to the worker's OCI `process.env`. Engine-agnostic passthrough for env the image can't bake (the OCI spec is built from scratch; image `ENV` is dropped). Malformed input is ignored, not fatal. ClippyShot needs `CLIPPYSHOT_SANDBOX=container` + `CLIPPYSHOT_WARN_ON_INSECURE=1` here (see recipe below) |
| `BLASTBOX_GVISOR_PLATFORM` | _(runsc default)_ | `ptrace` or `kvm`; leave unset to let runsc choose |
| `BLASTBOX_GVISOR_CPUFEATURES` | _(unset)_ | `dev.gvisor.internal.cpufeatures` OCI annotation for cross-host CPU pinning |
| `BLASTBOX_SNAPSHOT_SETTLE_S` | `1.0` | Seconds to wait after restore before sending the job (post-restore settle) |
| `BLASTBOX_GVISOR_NPROC` | `4096` | `RLIMIT_NPROC` for the warm worker tree (fork-bomb bound) |
| `BLASTBOX_GVISOR_NOFILE` | `65536` | `RLIMIT_NOFILE` for the warm worker tree (fd-exhaustion bound) |
| `BLASTBOX_GVISOR_CLI_TIMEOUT_S` | `900` | Seconds any single `runsc` call may take (`run`/`restore`/`checkpoint`/`exec` and their teardown). Generous on purpose: a checkpoint writes the guest's whole memory image. Raise it for a large base; it exists so a wedged `runsc` cannot block the build thread forever, which would stop the warm tier rebuilding for the life of the process. Must be finite and > 0. |
| `BLASTBOX_SNAPSHOT_READY_S` | `120` | Seconds a warm BASE gets to signal READY while the snapshot is built (both the FC and gVisor tiers -- one shared `SnapshotManager`). Distinct from the build-phase budget: raising that one cannot help a base that is simply slow to warm, which is the case a cold OCR/soffice start on a loaded node hits. Must be finite and > 0. |

`_gvisor_config_from_env()` assembles a `GvisorConfig` dataclass from these
vars; `select_gvisor_snapshot_runtime()` returns the configured runtime object.

### ClippyShot warm tier recipe

ClippyShot installs into a venv at `/opt/clippyshot` and runs an **inner** sandbox
(`CLIPPYSHOT_SANDBOX`). Inside gVisor the inner backend must be `container` (gVisor is the
outer isolation; nested nsjail/bwrap need a user namespace gVisor does not provide), and the
inner ContainerSandbox's `/proc/self/status` hardening checks always read insecure under
gVisor (the sentry virtualizes `Seccomp`/`NoNewPrivs`), so it needs `CLIPPYSHOT_WARN_ON_INSECURE=1`
— the exact env the production dispatcher already auto-sets for `runsc`. Build the warm image
from a base that has `unoserver` (`deploy/firecracker/Dockerfile.clippyshot`) if you want warm-UNO,
then:

```sh
BLASTBOX_POOL_RUNTIME=gvisor
BLASTBOX_GVISOR_ROOTFS=/var/lib/blastbox/clippyshot-gvisor-rootfs
BLASTBOX_GVISOR_WARM_ARGV='["/opt/clippyshot/bin/python3","/opt/blastbox/run_warm.py"]'   # venv interpreter
BLASTBOX_GVISOR_LD_PRELOAD=/opt/clippyshot/accept-retry.so
BLASTBOX_GVISOR_EXTRA_ENV='["CLIPPYSHOT_SANDBOX=container","CLIPPYSHOT_WARN_ON_INSECURE=1","CLIPPYSHOT_WARM_UNO=1"]'
```

> **Reality check — clippyshot's warm-UNO does NOT survive gVisor C/R, and that is OK.**
> ClippyShot's `unoserver` listens on a **TCP socket** (`--accept=socket,port=2002`), not a
> named pipe, so the restore-time EINTR does **not** hang it on `osl_acceptPipe` — the soffice
> tier does *not* silently churn here. But the established unoserver↔soffice loopback connection
> does **not** cleanly survive `runsc checkpoint`/`restore`, so the post-restore `unoconvert`
> fails and the converter **fail-safes to the cold `--convert-to` path** (correct output,
> `status=ok`). Measured: warm-UNO is ~1.9 s faster than cold *without* C/R (5.5 s vs 7.4 s), but
> *with* gVisor C/R warm ≈ cold (no speedup) — with or without the accept-retry shim. So for
> clippyshot the gVisor tier is effectively a **warm-container** tier (it saves the python +
> engine import, ~1–2 s), not warm-soffice. The accept-retry shim is still wired (it is harmless
> and correct for a future pipe-based UNO config), but it is **not** load-bearing for the
> socket-based warm-UNO. **Firecracker is the proven warm-soffice tier** — its full-VM memory
> snapshot preserves the established UNO connection (see `project_warm_uno_snapshot`).

## I/O plane

The gVisor warm tier uses the same file-trigger control protocol as the Firecracker
tier — no vsock, no ext4 image:

- **`in/`** — bind-mounted read-only into the restore container; contains the input doc.
- **`out/`** — bind-mounted read-write; the worker writes PNGs + `metadata.json` here.
- **`ctrl/`** — bind-mounted read-write; blastbox writes a trigger file
  (`HostWarmControl` / `FileWarmControl`) that the in-guest worker polls; the guest
  writes a completion sentinel when done.

Output is read directly from `out/` on the host after the job completes.  Each restore
is **disposable**: one untrusted document per restore, then the container is destroyed.

## Resource & filesystem isolation

The warm worker runs **non-root (uid 65532), no capabilities, no-new-privs, read-only rootfs,
network=none**. The OCI spec applies `RLIMIT_NPROC` (4096) + `RLIMIT_NOFILE` (65536) — the gVisor
sentry enforces these even though `-ignore-cgroups` disables cgroup pids/memory — so a
malicious-doc fork-bomb or fd-exhaustion can't degrade the pool. These are generous
defense-in-depth bounds (the whole python + soffice + pdfium worker tree shares one limit), not
tight quotas. Worker **memory** is bounded
per-soffice by the inner sandbox's `RLIMIT_AS`; for a worker-tree RSS bound, place the `runsc`
process under a host memory cgroup (the spec's cgroup is intentionally ignored).

Per-slot `out/` + `ctrl/` are mode `0o777` (shared cross-uid scratch between the non-root worker
and the host services) but live inside a **`0o700`** slot dir created atomically — another local
user can't traverse into it to reach them, independent of the deploy parent. blastbox additionally
**warns** if the deploy state parent (`/var/lib/blastbox/...`) is group/other-writable; lock it to
root-owned `0o700`.

## Snapshot sensitivity

The checkpoint image encodes the host CPU feature set and the `runsc` version.  **Rebuild
the snapshot** whenever:

- `runsc` is upgraded on the host.
- The soffice/clippyshot image is rebuilt.
- The host changes (different CPU microarchitecture).

Use `BLASTBOX_GVISOR_CPUFEATURES` to annotate the snapshot with a portable CPU feature
subset, which allows restoring across minor microarchitecture differences within the
same vendor family.  Cross-vendor (Intel ↔ AMD) restore is not supported by gVisor.
