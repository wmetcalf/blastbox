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
| `BLASTBOX_GVISOR_WARM_ARGV` | `["python3","/opt/blastbox/run_warm.py"]` | JSON list; argv of the warm entrypoint (see below). Must be a non-empty list of strings or it falls back to the default |
| `BLASTBOX_GVISOR_LD_PRELOAD` | _(unset)_ | Set to `/opt/clippyshot/accept-retry.so` for the soffice warm container |
| `BLASTBOX_GVISOR_PLATFORM` | _(runsc default)_ | `ptrace` or `kvm`; leave unset to let runsc choose |
| `BLASTBOX_GVISOR_CPUFEATURES` | _(unset)_ | `dev.gvisor.internal.cpufeatures` OCI annotation for cross-host CPU pinning |
| `BLASTBOX_SNAPSHOT_SETTLE_S` | `1.0` | Seconds to wait after restore before sending the job (post-restore settle) |

`_gvisor_config_from_env()` assembles a `GvisorConfig` dataclass from these
vars; `select_gvisor_snapshot_runtime()` returns the configured runtime object.

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

## Snapshot sensitivity

The checkpoint image encodes the host CPU feature set and the `runsc` version.  **Rebuild
the snapshot** whenever:

- `runsc` is upgraded on the host.
- The soffice/clippyshot image is rebuilt.
- The host changes (different CPU microarchitecture).

Use `BLASTBOX_GVISOR_CPUFEATURES` to annotate the snapshot with a portable CPU feature
subset, which allows restoring across minor microarchitecture differences within the
same vendor family.  Cross-vendor (Intel ↔ AMD) restore is not supported by gVisor.
