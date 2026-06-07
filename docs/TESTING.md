# Testing blastbox

Two tiers: **unit tests** (mocked, run anywhere) and **gated integration tests** (real
sandboxes/microVMs, skipped unless their prerequisites are present).

## TL;DR — ready-to-run scripts

```sh
scripts/test-unit.sh            # tier 1: unit + ruff + mypy.  NO sudo, NO runtimes.
scripts/test-gvisor-cr.sh       # tier 2: gVisor C/R warm round-trip.  NEEDS sudo (rootful runsc).
scripts/install-firecracker.sh  # one-time: firecracker binary + guest kernel into ~/.local.  NO sudo.
scripts/test-fc.sh              # tier 2: Firecracker warm round-trip.  NO sudo if you can access /dev/kvm.
```

Each script self-bootstraps the venv, builds the rootfs it needs, and prints what's missing. The
rest of this doc explains what they do and the one gotcha (Ubuntu 24.04 userns) behind the scenes.

## Unit tests + lint + types (no setup)

```sh
python3 -m venv .venv
.venv/bin/pip install -e .[dev]
.venv/bin/pytest tests            # gated integration/docker tests self-skip without prereqs
.venv/bin/ruff check src tests
.venv/bin/mypy src
```

These mock `subprocess`/`runsc`/redis/sockets, so they need no real runtimes. They cover the
dispatch/jobstore/contract logic against **real** SQLite/fakeredis/filesystem/seal — only the
worker subprocess and the sandbox runtime are stubbed.

## Gated integration tests (real runtimes)

The `integration` (and `docker`) suites exercise REAL gVisor/Firecracker/sandbox + a real
worker, and `skip` unless their prerequisites exist. They are the only thing that validates the
warm-snapshot backends, the FC vsock wire path, and the seccomp policies end-to-end.

### ⚠️ Ubuntu 24.04+ unprivileged-userns restriction (read first)

On Ubuntu 24.04+ and similar hardened kernels, `kernel.apparmor_restrict_unprivileged_userns=1`
blocks the unprivileged user namespaces that `runsc`, `bwrap`, and `nsjail` need. Symptom:

```
runsc ... : Error executing inside namespace: re-executing self:
            fork/exec /proc/self/exe: permission denied
```

(`cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns` → `1` confirms it.)

**This only affects the namespace-based sandboxes** (`runsc`, `bwrap`, `nsjail`) — **not
Firecracker**, which is a KVM hypervisor and doesn't create user namespaces. For the affected
tests, **run them as root** (`sudo -E env BLASTBOX_*=… .venv/bin/pytest …`) — the gVisor backend
drives `runsc` rootful anyway, and root isn't subject to the restriction. (You *can* `sudo sysctl
kernel.apparmor_restrict_unprivileged_userns=0`, but that lowers a system-wide kernel-attack-surface
control until reboot and only helps *unprivileged* `bwrap`/`nsjail` — it does **not** remove the
root requirement for the rootful gVisor C/R tests, so it buys nothing here. Don't.) A permissioned
host without the restriction (e.g. toolz2) is the other option.

`docker run --runtime=runsc …` *does* work unprivileged (the daemon is root), but that only
runs a worker **inside** gVisor — it does not expose the `checkpoint`/`restore` the warm tier
needs, so the warm round-trip below must drive `runsc` directly (hence the root requirement).

### gVisor C/R warm round-trip

**`scripts/test-gvisor-cr.sh` does all of the below for you.** Needs: `runsc` with C/R
(`runsc help | grep -E 'checkpoint|restore'`), root (above), and an OCI rootfs that runs the warm
entrypoint. Build a **soffice-free `probe`-engine** rootfs for a quick smoke (no LibreOffice needed):

```sh
# 1. wheel + minimal warm image (run_warm.py is the gVisor file-trigger entrypoint)
.venv/bin/pip install -q build
.venv/bin/python -m build --wheel -o /tmp/w .
mkdir -p /tmp/warm && cp deploy/gvisor/run_warm.py deploy/firecracker/engines.py /tmp/w/blastbox-*.whl /tmp/warm/
cat > /tmp/warm/Dockerfile <<'EOF'
FROM python:3.12-slim
COPY *.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl
COPY run_warm.py /opt/blastbox/run_warm.py
COPY engines.py /opt/blastbox/engines.py
RUN printf 'probe' > /opt/blastbox/engine
EOF
docker build -t blastbox-warm-probe:test /tmp/warm

# 2. export its filesystem to a rootfs dir (Docker ENV is dropped — engine is baked in a FILE)
mkdir -p /tmp/gvisor-rootfs
cid=$(docker create blastbox-warm-probe:test); docker export "$cid" | tar -C /tmp/gvisor-rootfs -xf -; docker rm "$cid"

# 3. run the round-trip AS ROOT
sudo -E env BLASTBOX_GVISOR_ROOTFS=/tmp/gvisor-rootfs BLASTBOX_GVISOR_RUNSC="$(command -v runsc)" \
  .venv/bin/pytest tests/integration/test_gvisor_snapshot_roundtrip.py -v
```

It boots a base container → `runsc checkpoint` → `runsc restore` → stages a fixture → file-trigger
`go` → probe detonation → asserts `metadata.json status=="ok"` → reaps. For a REAL conversion,
build the rootfs from a soffice engine image instead:
`docker build -f deploy/gvisor/Dockerfile.shim --build-arg BASE=clippyshot:dev -t clippyshot-warm:gvisor .`
(and set `BLASTBOX_GVISOR_LD_PRELOAD=/opt/clippyshot/accept-retry.so` — see `deploy/gvisor/README.md`).

### Firecracker warm round-trip

**`scripts/install-firecracker.sh` then `scripts/test-fc.sh` do all of the below for you.**

Needs: the `firecracker` binary, `/dev/kvm`, a vmlinux kernel, and a **blastbox-format** FC rootfs.
Build the rootfs with `ENGINE=probe deploy/firecracker/build-rootfs.sh out.ext4` (no root — it uses
`mke2fs -d`, never mounts the disk). The live-boot tests un-skip when `firecracker_available()`
succeeds.

**No sudo needed** if you can access `/dev/kvm`: firecracker is a KVM hypervisor, **not** a userns
sandbox, so the Ubuntu 24.04 restriction above does not apply. Grant access once with
`sudo usermod -aG kvm "$USER"` (re-login), then:

```sh
BLASTBOX_FC_BIN=/path/to/firecracker \
BLASTBOX_FC_KERNEL=/path/to/vmlinux \
BLASTBOX_FC_ROOTFS=/path/to/blastbox-probe-rootfs.ext4 \
  .venv/bin/pytest tests/host/runtime/test_firecracker.py -v -k FirecrackerLiveBoot
```

(If you can't join the kvm group, prefix with `sudo -E env BLASTBOX_FC_*=…`.) `test_live_job_roundtrip_trust_validated`
is the only test that exercises a real guest decoding the host's streamed input frame
(`send_frame_from_file`) — a wire-format change won't show up in the mocked unit tests.

### bwrap / nsjail / container sandbox

The cold-path sandbox backends are selected by `CLIPPYSHOT_SANDBOX`/`BLASTBOX_SANDBOX`. On a
restricted-userns host, `bwrap`/`nsjail` need root or the AppArmor profiles loaded; the
`container` backend works wherever Docker does. seccomp policies can be smoke-checked without a
full conversion: `docker run --security-opt seccomp=deploy/seccomp/blastbox.seccomp.json ...`
and `nsjail --seccomp_policy=deploy/seccomp/blastbox.seccomp.policy -- /bin/true`.
