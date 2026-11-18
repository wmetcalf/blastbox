# Host preparation

What a Linux host needs **before** a blastbox dispatcher or worker agent runs on it, per runtime
tier, and the incidents behind each requirement. [DEPLOYMENT.md](DEPLOYMENT.md) picks the tier;
this page makes the host ready for it; [CONFIGURATION.md](CONFIGURATION.md) is the knob reference.

Check a host with the read-only preflight. It never changes anything; every finding prints the
fix and a pointer back to a section of this page:

```sh
blastbox preflight                      # cold docker tier + BLASTBOX_POOL_RUNTIME's tier
blastbox preflight --tier all           # docker, gvisor, firecracker, remote
blastbox preflight --tier firecracker --json
blastbox preflight --strict             # exit 1 on WARN too (CI / provisioning gates)
```

Exit code: `0` = no FAIL, `1` = at least one FAIL (or a WARN under `--strict`), `2` = bad usage.
Tiers:

```
docker       the cold dispatcher: one disposable docker container per job (runsc by default)
gvisor       the gVisor C/R warm tier (runsc driven directly)
firecracker  the Firecracker warm/cold microVM tier
remote       static / aws-* / cascade: the worker runs elsewhere; this host only dispatches
```

`blastbox preflight` checks the **host**; `blastbox doctor` checks what is **running** on it
(container and rootfs versions). Run both after an upgrade.

## What each tier needs

| Tier | Needs on the host | Preflight checks |
|---|---|---|
| **docker** (cold) | docker daemon, `runsc` registered as a docker runtime (fail-closed without it) | `docker`, `docker-runsc-runtime` |
| **gvisor** (warm C/R) | the above + the `runsc` binary (driven directly; root) | + `runsc`, `snapshot-age` |
| **firecracker** (warm/cold) | `/dev/kvm` read/write, `firecracker` ≥ 1.15.1, guest kernel + rootfs | `kvm`, `firecracker`, `fc-guest`, `snapshot-age` |
| **remote** (static / AWS) | nothing runtime-specific locally; the remote box runs the worker image under its own runsc | common checks only |
| every tier | AppArmor state known, synced clock, CPU flags reviewed, scratch off `/tmp` | `apparmor`, `bwrap-userns-restrict`, `userns`, `clock`, `cpu-flags`, `scratch` |

Prefer the **warm Firecracker** tier where KVM exists: it is the stronger boundary and, with
memory snapshots, the faster warm path. gVisor is the fallback for hosts without KVM.

## Plain docker (cold tier)

- Docker Engine reachable by the dispatcher user (or the dispatcher container mounts the socket).
- `runsc` registered as a docker runtime — see [gVisor (runsc)](#gvisor-runsc). Without it the
  dispatcher refuses jobs (`InsecureRuntimeRefused`) unless you set `BLASTBOX_ALLOW_RUNC=1`,
  which is a deliberate degraded mode (preflight then reports `WARN` instead of `FAIL`).
- Under plain `runc` the inner sandbox (nsjail/bwrap) needs user namespaces; see
  [AppArmor and user namespaces](#apparmor-and-user-namespaces).

### Rolling services: `--no-deps`

When rolling an engine or dispatcher service in a compose stack, **always** pass `--no-deps`:

```sh
docker compose up -d --no-deps --force-recreate <engine-or-dispatcher-service>
```

Without it compose may also recreate the service's dependencies. On 2026-11-18 a dispatcher roll
recreated `postgres` and the new container came up on a **stale anonymous volume**: the job store
silently reverted. Two rules follow:

- Roll the service you mean, `--no-deps`, and never `docker compose up -d` the whole stack to
  "pick up" one image.
- Give stateful services (postgres, redis) a **named** volume, never an anonymous one, so a
  recreate re-attaches the same data. `docker compose down -v` deletes named volumes too.

### Networking: docker isolated gateway, not host firewall rules

blastbox must **not** add, edit or hook host `nftables`/`iptables` rules (tables, chains,
`nftables.service` drop-ins). The host firewall is usually shared with other stacks. Workers run
`--network=none`; the only egress is the opt-in overlay (see DEPLOYMENT *Egress netpolicy*).

When services need a bridge network that must not reach the host, use docker's own isolation
(Docker Engine 28+):

```sh
docker network create --internal \
  -o com.docker.network.bridge.gateway_mode_ipv4=isolated \
  -o com.docker.network.bridge.gateway_mode_ipv6=isolated \
  bb-engines
```

```yaml
networks:
  bb-engines:
    internal: true
    driver_opts:
      com.docker.network.bridge.gateway_mode_ipv4: isolated
      com.docker.network.bridge.gateway_mode_ipv6: isolated
```

`--internal` removes the route out; `gateway_mode_*=isolated` gives the **host** no address on the
bridge, so containers cannot reach host services either. Peer containers on the same network still
reach each other. Verified on docker 29.1.3: v4 and v6 to the host blocked, peers reachable.

## gVisor (runsc)

Install `runsc` (and its containerd shim) per the gVisor docs, then register it with docker:

```sh
sudo runsc install              # adds ONLY the runsc runtime to /etc/docker/daemon.json
sudo systemctl reload docker    # SIGHUP: re-reads daemon.json, running containers stay UP
docker info --format '{{json .Runtimes}}'   # must list "runsc"
```

**Reload, never restart.** `systemctl restart docker` stops every running container on the host
(databases, other stacks, sensors). Runtimes are among the settings dockerd reloads on SIGHUP, so
`reload` is enough; it was used to add runsc on a host running unrelated critical containers, all of
which stayed up. Do not add the dispatcher user to the `docker` group just for this: that is a
root-equivalent, persistent grant.

What the sandbox sees:

- **AppArmor is not enforced inside the sandbox.** gVisor's Sentry implements the guest kernel;
  host LSMs never see guest syscalls. Docker's `docker-default` profile applies to the **runsc
  processes on the host** (Sentry/gofer), which is where it belongs.
- **Nested sandboxes don't work under gVisor.** Engines that wrap their own work in bwrap or
  nsjail must use their container / no-nested-sandbox mode inside runsc (and inside Firecracker):
  e.g. ClippyShot sets `CLIPPYSHOT_SANDBOX=container` (passed via `BLASTBOX_GVISOR_EXTRA_ENV` on
  the warm tier). Landlock (nono) is also unavailable: the Sentry returns `ENOSYS`.
- **Rootful only for the warm tier.** gVisor cannot `restore` rootless. Rootless runsc (no current
  tier uses it) needs `deploy/apparmor/blastbox-runsc` on Ubuntu 24.04+.

## Firecracker

```sh
ls -l /dev/kvm                      # crw-rw---- root kvm: the dispatcher user must be in "kvm"
sudo usermod -aG kvm <dispatcher-user>     # then re-login; or --device /dev/kvm for a container
firecracker --version               # >= v1.15.1 (older: virtio-rng entropy DoS)
```

- `/dev/kvm` missing = no hardware virtualisation: enable VT-x/AMD-V, load `kvm_intel`/`kvm_amd`,
  or enable nested virt if the host is itself a VM. No KVM → use the gVisor tier.
- Set `BLASTBOX_FC_BIN`, `BLASTBOX_FC_KERNEL`, `BLASTBOX_FC_ROOTFS`. Run preflight in the FC
  dispatcher's environment so `fc-guest` can confirm the artifacts exist; build the rootfs per
  [WARM-ROOTFS.md](WARM-ROOTFS.md) and confirm it with `blastbox doctor --rootfs`.
- **Host AppArmor profiles don't apply to the job.** The engine runs on the guest kernel. Host
  userns restrictions are irrelevant to Firecracker itself (a KVM hypervisor, not a userns
  sandbox); confinement inside the guest is the guest's business (nono works there).

## AppArmor and user namespaces

Ubuntu 24.04+ sets `kernel.apparmor_restrict_unprivileged_userns=1`. What that means per tier:

| Tier | Effect of the restriction |
|---|---|
| docker + runsc (rootful) | none: runsc runs as root and is exempt |
| gVisor warm (rootful) | none |
| Firecracker | none: no host user namespaces involved |
| runc + nsjail/bwrap inner sandbox | **blocks** them: load the scoped `deploy/apparmor/blastbox-{bwrap,nsjail}` profiles |
| rootless runsc | **blocks** it: load `deploy/apparmor/blastbox-runsc` |

Use the **scoped per-binary profiles** in [`deploy/apparmor/`](../deploy/apparmor/README.md). Do
**not** set `kernel.apparmor_restrict_unprivileged_userns=0`: that lowers a host-wide
attack-surface control for every process. Preflight's `userns` check warns only when the
environment actually configures something that needs a user namespace (`BLASTBOX_SANDBOX=bwrap|nsjail`,
`BLASTBOX_WORKER_RUNTIME=runc`, `BLASTBOX_GVISOR_ROOTLESS`), and passes when the scoped profiles
are visibly loaded (securityfs is root-only; run preflight as root to confirm). `max_user_namespaces=0`
or `unprivileged_userns_clone=0` switches user namespaces off outright.

AppArmor itself should be **enabled** (`/sys/module/apparmor/parameters/enabled` = `Y`): without it
docker-default is not applied to runsc/worker processes and the `blastbox-sandbox` child profile
cannot be attached (nsjail/bwrap then report `apparmor_missing`).

### The stock `bwrap-userns-restrict` profile

Newer Ubuntu AppArmor packages (24.04+, depending on the package version) ship
`/etc/apparmor.d/bwrap-userns-restrict`. It grants `/usr/bin/bwrap` a user namespace but runs
everything bwrap launches under a restricted child profile (`unpriv_bwrap`) that denies
capabilities inside the namespace. Consequences:

- Engines that run bwrap **on the host or under runc** (an engine's own bwrap sandbox, or
  blastbox's `bwrap` inner backend) can fail with permission errors inside the namespace, and its
  attachment to `/usr/bin/bwrap` overlaps with `blastbox-bwrap` / an engine's own bwrap profile.
  Two profiles attaching the same binary is ambiguous; keep one.
- Under **runsc** and **Firecracker** it is irrelevant: host profiles don't reach the guest, and
  engines there use their container mode anyway.

Disable it **only** on a dedicated blastbox host where bwrap-based engines run on the host/runc
tier and the scoped `blastbox-bwrap` (or the engine's own) profile replaces it. On a shared
desktop/server whose other bwrap users (Flatpak, etc.) rely on it, leave it and move those engines
under runsc/Firecracker instead. To disable persistently:

```sh
sudo ln -s /etc/apparmor.d/bwrap-userns-restrict /etc/apparmor.d/disable/
sudo apparmor_parser -R /etc/apparmor.d/bwrap-userns-restrict   # unload now
sudo grep -E '^(bwrap|unpriv_bwrap) ' /sys/kernel/security/apparmor/profiles   # expect nothing
```

The symlink keeps it from loading at boot or on a policy reload; `-R` removes the loaded copy.
Preflight reports `PASS` when it is absent or disabled-and-unloaded, and `WARN` when it is active or
disabled but still loaded. Reverse with `sudo rm /etc/apparmor.d/disable/bwrap-userns-restrict &&
sudo apparmor_parser -r /etc/apparmor.d/bwrap-userns-restrict`.

## Clock and aged warm checkpoints

Keep the host clock NTP-synchronised (`timedatectl` reports `NTPSynchronized=yes`, or chrony's
`Leap status : Normal`). Warm restores replay a guest whose clocks were frozen at checkpoint time,
so wall-clock steps and checkpoint age both matter.

The incident: warm RedTusk on toolz2 worked the day its checkpoint was built and failed every job
~24h later with nothing changed. gVisor/FC restore advances `CLOCK_MONOTONIC` by the time spent
checkpointed; the worker's idle deadline was computed before the checkpoint, so a checkpoint older
than the 24h idle timeout timed out on its first poll and exited without processing the job
(empty output, `metadata.json not found`). The worker now detects the jump and restarts its idle
countdown, and `BLASTBOX_SNAPSHOT_MAX_AGE_S` (default 6h) refreshes warm bases before they age.

- Do **not** set `BLASTBOX_SNAPSHOT_MAX_AGE_S=0` (preflight warns): it disables refresh.
- After upgrading blastbox, a host clock fix, or any long outage, **rebuild warm snapshots**
  (restart the warm sidecar so it re-checkpoints) rather than serving the old base.

## CPU features

Preflight reads `/proc/cpuinfo` and warns on flags with operational consequences:

- **`avx512vbmi`** (Ice Lake and later, Zen 4 and later): JVM engines (RedTusk/Tika and any other
  Java engine) must run with `-XX:-UseBASE64Intrinsics` (the Java4Shell mitigation,
  CVE-2026-114938). Set it in the engine image or its `JAVA_TOOL_OPTIONS`, on every tier the engine
  runs on: Firecracker guests and gVisor sandboxes see the host CPU's features unless masked.
- CPU features also bind warm snapshots to hardware: a CRaC checkpoint must be pinned to what the
  restore environment exposes (`blastbox.host.runtime.cpu_probe` asks the FC guest;
  `BLASTBOX_GVISOR_CPUFEATURES` for gVisor). Moving a snapshot to a different CPU generation means
  rebuilding it.

## Disk and scratch

- Keep blastbox state **off `/tmp`** (and `/var/tmp`): `systemd-tmpfiles` ages it out, tmpfs caps
  it at a fraction of RAM, and a reboot loses sealed results that may be the only copy. Preflight
  warns when `BLASTBOX_JOB_ROOT` (default `/var/lib/blastbox/jobs`), `BLASTBOX_SNAPSHOT_MEM_DIR` or
  `BLASTBOX_GVISOR_ROOT` sits under them.
- `BLASTBOX_JOB_ROOT` must be the same path for serve, dispatch and the worker mount, and must
  **not** be shared between a container dispatcher and a network-tier (aws/static) dispatcher
  (CONFIGURATION *Core*).
- A warm snapshot base is RAM-sized, and a refresh needs room for a second generation until the
  swap. Size `BLASTBOX_SNAPSHOT_MEM_DIR` (a dedicated tmpfs such as `/dev/shm/...` with
  `BLASTBOX_SNAPSHOT_MEM_TMPFS`, or fast local disk) for two bases per warm tier.
- Disk-free is exported on `/metrics` (`blastbox_host_disk_free_bytes`).

## AWS and static workers

A `remote` dispatcher host needs only the common checks (clock, scratch) plus network reach to its
workers. Each static box or cloud worker is its own host: prepare it as a **docker + gVisor** host
(the worker image runs under runsc there) and run `blastbox preflight --tier docker` on it. AWS
tiers are fail-closed on credentials and entitlement; see CONFIGURATION *Runtime: AWS*.
