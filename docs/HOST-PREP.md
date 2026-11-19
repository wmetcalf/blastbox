# Host preparation

What a Linux host needs **before** a blastbox dispatcher or worker agent runs on it, per runtime
tier, and the incidents behind each requirement. [DEPLOYMENT.md](DEPLOYMENT.md) picks the tier;
this page makes the host ready for it; [CONFIGURATION.md](CONFIGURATION.md) is the knob reference.

Check a host with the read-only preflight. It never changes anything; every finding prints the
fix and a pointer back to a section of this page:

```sh
blastbox preflight                      # BLASTBOX_POOL_RUNTIME's tier(s) (+ cold docker if local)
blastbox preflight --tier all           # docker, gvisor, firecracker, remote
blastbox preflight --tier firecracker --json
blastbox preflight --strict             # exit 1 on WARN too (CI / provisioning gates)
blastbox preflight --strict --ack cpu-flags   # ...except a WARN you have reviewed and accepted
```

Exit code: `0` = no FAIL, `1` = at least one FAIL (or an un-`--ack`ed WARN under `--strict`),
`2` = bad usage. `--ack CHECK` never acknowledges a FAIL.
Tiers:

```
docker       the cold dispatcher: one disposable docker container per job (runsc by default)
gvisor       the gVisor C/R warm tier (runsc driven directly)
firecracker  the Firecracker warm/cold microVM tier
remote       static / aws-*: the worker runs elsewhere; this host only dispatches
```

With nothing configured (`BLASTBOX_POOL_RUNTIME` unset) and no `--tier`, preflight previews every
local tier, but a warm tier's FAIL is reported as a WARN ("not selected"): that dispatcher runs cold
docker only. Pass `--tier` to gate on a tier. Otherwise, without `--tier`, preflight checks whatever
`BLASTBOX_POOL_RUNTIME` selects; for `cascade` that is
each member named in `BLASTBOX_POOL_TIERS` (local `firecracker` / `gvisor` members get their local
checks, `static` / `aws-*` members map to `remote`). The cold docker tier is added only for a local
(file-handshake) dispatcher that is not `BLASTBOX_DISPATCH_WARM_ONLY`: network-endpoint pools have
no cold path. The `pool-runtime` check FAILs a pool name or cascade spec the dispatcher refuses
(unknown or set-but-empty name, unknown cascade primary, missing/zero capacity, a mix of local and
remote tiers, worker-mTLS and public-TLS tiers mixed under `BLASTBOX_DISPATCH_TLS_CA`,
`BLASTBOX_DISPATCH_WARM_ONLY` without a pool) and WARNs on an unknown overflow member,
which the dispatcher skips at startup.

`blastbox preflight` checks the **host**; `blastbox doctor` checks what is **running** on it
(container and rootfs versions). Run both after an upgrade.

## What each tier needs

| Tier | Needs on the host | Preflight checks |
|---|---|---|
| **docker** (cold) | docker daemon, `runsc` registered as a docker runtime (fail-closed without it) | `docker`, `docker-runsc-runtime`, `runsc-host-root`, `sandbox-confinement` |
| **gvisor** (warm C/R) | the `runsc` binary with checkpoint/restore (driven directly, no docker; root) | `runsc`, `gvisor-rootfs`, `gvisor-rootless`, `snapshot-age`, `runsc-host-root`, `sandbox-confinement` |
| **firecracker** (warm/cold) | `/dev/kvm` read/write, `firecracker` ≥ 1.15.1, guest kernel + rootfs | `kvm`, `firecracker`, `fc-guest`, `snapshot-age` (with `BLASTBOX_POOL_WARM_SNAPSHOT`), `sandbox-confinement`, `fc-scratch` |
| **remote** (static / AWS) | nothing runtime-specific locally; the remote box runs the worker image under its own runsc | common checks only (no docker: no cold path) |
| every tier | a pool the dispatcher accepts, synced clock, scratch off `/tmp`, a valid `BLASTBOX_CONFINEMENT` | `pool-runtime`, `confinement`, `clock`, `scratch` |
| every local tier | AppArmor state known, CPU flags reviewed | `apparmor`, `bwrap-userns-restrict`, `userns`, `cpu-flags` |

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
  host LSMs never see guest syscalls. Docker asks for its `docker-default` profile on the **runsc
  processes on the host** (Sentry/gofer), which is where confinement belongs. But a path-attached
  profile wins: once `deploy/apparmor/blastbox-runsc` (for rootless runsc, `flags=(unconfined)`)
  is loaded it attaches to `/usr/bin/runsc` and rootful docker's runsc processes run under
  `blastbox-runsc (unconfined)` instead. Don't load it on a rootful host; preflight's
  `sandbox-confinement` check reports it.
- **Nested sandboxes don't work under gVisor.** Engines that wrap their own work in bwrap or
  nsjail must use their container / no-nested-sandbox mode inside runsc (and inside Firecracker):
  e.g. ClippyShot sets `CLIPPYSHOT_SANDBOX=container` (passed via `BLASTBOX_GVISOR_EXTRA_ENV` on
  the warm tier). Landlock (nono) is also unavailable: the Sentry returns `ENOSYS`.
- **The warm tier needs C/R.** `runsc help` must list `checkpoint` and `restore` (the tier's own
  capability probe); preflight's `runsc` check FAILs a build without them.
- **Rootful only for the warm tier.** gVisor cannot `restore` rootless, so the tier refuses
  `BLASTBOX_GVISOR_ROOTLESS` (preflight's `gvisor-rootless` FAIL). Rootless runsc (no current
  tier uses it) needs `deploy/apparmor/blastbox-runsc` on Ubuntu 24.04+.

### runsc processes and host root

With docker's stock (non-remapped) setup, the host-side `runsc-sandbox` (Sentry) and
`runsc-gofer` processes are **real host root**: their `/proc/<pid>/uid_map` is the identity map
`0 0 4294967295` and `Uid` is 0, with capabilities such as `CAP_DAC_OVERRIDE`/`CAP_DAC_READ_SEARCH`
(sandbox) and `CAP_SYS_CHROOT` (gofer). gVisor is the boundary, but a Sentry or gofer escape then
lands as host root. Preflight's `runsc-host-root` check warns when it sees this. The recommended
direction is a **user-namespace-remapped** setup: a separate docker daemon with `userns-remap`
for the blastbox runtime, or containerd per-container uid/gid mappings. This is pending a spike
(warm checkpoint/restore under a remapped daemon is unverified), so treat the warning as known
residual risk until then; do not flip `userns-remap` on a shared daemon, which remaps every
existing container and its volumes.

Reading another user's `/proc/<pid>/uid_map`/`status` can need privileges; preflight then says
`unknown (run as root)` and does not fail.

## Firecracker

```sh
ls -l /dev/kvm                      # crw-rw---- root kvm: the dispatcher user must be in "kvm"
sudo usermod -aG kvm <dispatcher-user>     # then re-login; or --device /dev/kvm for a container
firecracker --version               # >= v1.15.1 (older: virtio-rng entropy DoS)
```

- `/dev/kvm` missing = no hardware virtualisation: enable VT-x/AMD-V, load `kvm_intel`/`kvm_amd`,
  or enable nested virt if the host is itself a VM. No KVM → use the gVisor tier.
- The warm snapshot tier (`BLASTBOX_POOL_WARM_SNAPSHOT=1`) needs a guest kernel >= 5.18 (VMGenID
  reseeds the CRNG on restore); `fc-guest` FAILs a detectably older vmlinux. Cold FC does not care.
- Set `BLASTBOX_FC_BIN`, `BLASTBOX_FC_KERNEL`, `BLASTBOX_FC_ROOTFS`. Run preflight in the FC
  dispatcher's environment so `fc-guest` can confirm the artifacts exist; build the rootfs per
  [WARM-ROOTFS.md](WARM-ROOTFS.md) and confirm it with `blastbox doctor --rootfs`.
- **Host AppArmor profiles don't apply to the job.** The engine runs on the guest kernel. Host
  userns restrictions are irrelevant to Firecracker itself (a KVM hypervisor, not a userns
  sandbox); confinement inside the guest is the guest's business (nono works there).

### Confining firecracker and runsc processes

Warm Firecracker slots share one scratch tree (`/tmp/blastbox-fc-slots`): the base's `warm-*.mem`
snapshot (written before any job runs; slots restore it copy-on-write, so job memory itself never
lands there) and, per slot, `outdisk.ext4`, `in/`, and the slot's `fc-api.sock` / `vsock.sock`. A
firecracker process that is not jailed and not confined by AppArmor, sharing a uid with the others,
can read another slot's input and output disks or drive another slot's VMM through its API socket
if it is compromised. Recommended:

- start firecracker through the **jailer** (chroot, its own uid/gid, cgroup and namespaces), so a
  slot's VMM only sees its own files;
- attach a **per-slot AppArmor profile** that allows only that slot's files.

Preflight's `sandbox-confinement` check warns when a firecracker or runsc process is not confined
by AppArmor (its AppArmor label, `/proc/<pid>/attr/apparmor/current` or else an AppArmor-shaped
`attr/current`, is `unconfined`, or a profile in `(unconfined)` or `(complain)` mode; another LSM's
label means AppArmor confinement cannot be verified) or a firecracker was not started by the jailer (the jailer always passes
`--start-time-us`; a non-`/` root proves nothing, a container has one too). When it cannot read
those it reports `unknown (run as root)` and does not fail. A firecracker inside a docker
container shows the container's profile (e.g. `docker-default (enforce)`), which counts as
confined, but it is not jailed.

### Confinement tier

*Detection only in this release: nothing is enforced yet.* The confinement tier will put the
HOST-side sandbox processes (runsc's CLI, gofer and sentry; firecracker) into blastbox's own LSM
policy -- runsc ignores the OCI `apparmorProfile`/`selinuxLabel` and firecracker has no LSM hook.
Today blastbox reports what the host offers and which LSM each sandbox kind WOULD use:

```text
SELinux enforcing  >  AppArmor enabled  >  Landlock (firecracker only)  >  none
```

Three kinds: `cold` (runsc started by dockerd for the cold tier), `gvisor` (the warm tier's runsc)
and `firecracker`, the last two started by the dispatcher itself.

| Host | cold | gvisor (warm) | firecracker |
|---|---|---|---|
| Ubuntu / Debian (AppArmor) | apparmor | apparmor | apparmor |
| Rocky / RHEL 9 (SELinux enforcing) | selinux | selinux | selinux |
| Amazon Linux 2023 (SELinux **permissive** by default) | none | none | landlock |
| Alpine (Landlock only) | none | none | landlock |
| dispatcher in a container on an AppArmor host (no `/sys/kernel/security`, or under `docker-default`) | apparmor | none | landlock, if the kernel offers it |
| dispatcher in a container on an SELinux host (read-only or no selinuxfs) | selinux if visible, else none | none | landlock, if the kernel offers it |

Permissive SELinux only logs, so it never counts (`setenforce 1` and `SELINUX=enforcing` in
`/etc/selinux/config` to change that). Landlock cannot hold runsc, which mounts; for Firecracker
it is applied by a launch shim just before firecracker runs. For the kinds the dispatcher starts
itself, an LSM that is on but cannot be used from the dispatcher's context is reported with the
reason and does not count: no securityfs to load AppArmor policy through, a caller already
confined by another AppArmor profile (e.g. `docker-default`, which has no `change_profile`
rule), or a read-only selinuxfs. `cold` is judged on the host's state alone, because dockerd
(through a docker runtime wrapper) starts that runsc, not the dispatcher -- but only with the
default docker endpoint. Any other endpoint configuration counts as another daemon, and `cold`
as none, without resolving where it points: `DOCKER_HOST`, `DOCKER_TLS_VERIFY`/`DOCKER_TLS`, a
`DOCKER_CONTEXT` other than `default`, a `docker context use` choice in `config.json`, or a
`config.json` that cannot be read.

`BLASTBOX_CONFINEMENT=auto|require|off` (default `auto`). `require` makes `blastbox dispatch`
refuse to start, and preflight FAIL, when a sandbox kind the dispatcher can run (including
`cold`, the fallback of a non-warm-only warm tier) has no usable LSM. Any other value is refused rather than read as `off`.

Preflight's `confinement` check prints the LSM stack, SELinux mode, AppArmor state and
`apparmor_parser` version, the Landlock ABI, the runsc release, and firecracker/jailer presence;
`--json` carries the same as `facts`. (The runsc release shown is the warm tier's binary; the
cold tier's runsc is whatever dockerd has registered, see `docker-runsc-runtime`.) Usability is judged from the process that runs the check
(its AppArmor label, what it can see of `/sys`), so run preflight where the dispatcher runs:
inside its container, or under its unit's profile. A `require` miss is a WARN, not a FAIL, when
it comes only from tiers this dispatcher will not run: the no-pool preview (the dispatcher runs
cold only), or a cascade overflow tier that is itself unavailable (the dispatcher drops it at
startup). An available overflow tier is admitted, and then the dispatcher refuses to start. Two conditions it calls out:

- **apparmor_parser 4.0.1** (WARN): pairing `audit deny umount,` with another `audit deny`
  mount-class rule compiles to ALLOW mount (measured with kernel 6.8). This matters today, not
  only for the future tier: the shipped `deploy/apparmor/blastbox-sandbox` child profile has
  that pair (`audit deny mount,` + `audit deny umount,`).
- **runsc older than `release-20261012`** ships the Sentry inside the runsc binary, so AppArmor
  cannot give it a domain separate from the CLI and gofer ("single binary" in the report).

The dispatcher logs its detection at startup (`confinement (detection only, nothing
enforced): mode=..., cold=..., gvisor=..., firecracker=...`). Signed receipts do not carry it
yet. `blastbox.client.verify` accepts an optional receipt `confinement: {mode, available,
applied}` from this release on, so that the enforcement change can sign it. Verifiers older than
that refuse unknown receipt fields: upgrade every verifier before any dispatcher signs it.

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
environment actually configures something that needs a user namespace on a tier being checked
(cold docker workers running plain runc, forced by `BLASTBOX_WORKER_RUNTIME=runc` or the
`BLASTBOX_ALLOW_RUNC` fallback when runsc is not registered, with `BLASTBOX_SANDBOX` pinned to
`bwrap`/`nsjail`: the only case where an inner sandbox creates a user namespace on the host kernel
(inside a container the worker otherwise auto-selects the `container` backend, which does not); under runsc, gVisor's Sentry implements namespaces itself;
`BLASTBOX_GVISOR_ROOTLESS` is the `gvisor-rootless` check's concern), and passes when the scoped profiles
are visibly loaded (securityfs is root-only; run preflight as root to confirm). `max_user_namespaces=0`
or `unprivileged_userns_clone=0` switches user namespaces off outright: a FAIL only when something
configured needs one, otherwise a fine hardening choice (PASS).

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
Preflight reports `PASS` when it is absent or disabled-and-unloaded, or active on a host where
nothing runs host bwrap; it reports `WARN` when it is active and cold docker workers run plain runc
with `BLASTBOX_SANDBOX=bwrap`, or disabled but still
loaded. The profile attaches to bwrap only, so nsjail and rootless runsc don't trigger it. Reverse with `sudo rm /etc/apparmor.d/disable/bwrap-userns-restrict &&
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

- Do **not** set `BLASTBOX_SNAPSHOT_MAX_AGE_S=0` (preflight warns): it disables refresh. Keep it
  under 12h: a base keeps serving while its refresh fails until 2x max-age, so 12h or more lets it
  reach the ~24h restore clock-jump edge (preflight warns).
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
  `BLASTBOX_GVISOR_ROOT` sits under them, and when the job root is missing or not writable by the
  user preflight runs as (run it as the dispatcher user).
- The Firecracker slot scratch is hard-wired to `/tmp/blastbox-fc-slots` (no knob today): slot
  disks, sockets, and the warm base unless `BLASTBOX_SNAPSHOT_MEM_DIR` moves it. Preflight's
  `fc-scratch` check warns when the mount holding `/tmp/blastbox-fc-slots` is a tmpfs; since there is no knob,
  `--ack fc-scratch` once the RAM budget is understood.
- `BLASTBOX_JOB_ROOT` (dispatcher) and `BLASTBOX_GVISOR_ROOT` (warm gVisor tier) are read
  unstripped: set-but-empty means the process's working directory. Preflight warns on an empty or
  padded value.
- Without `--tier`, a local tier that a cascade lists only as an **overflow** member is skipped by the dispatcher
  when its startup gate fails, so those FAILs (`kvm` when `/dev/kvm` is missing, `firecracker`,
  `fc-guest`, `runsc`, `gvisor-rootless`) are reported as WARNs saying so. A non-rw `/dev/kvm` or a
  missing gVisor rootfs is not a startup gate: a warm overflow tier is admitted but its base never
  builds, so the cascade runs without it (WARN); a cold Firecracker overflow tier really spawns
  there and every spawn fails (FAIL). With `--tier <that tier>` its prerequisites gate as usual.
- `gvisor-rootfs` and `fc-guest` also apply the runtime's rootfs stamp check: a tree stamped for another release,
  architecture or runtime FAILs; an unstamped legacy tree is allowed.
- `BLASTBOX_JOB_ROOT` must be the same path for serve, dispatch and the worker mount, and must
  **not** be shared between a container dispatcher and a network-tier (aws/static) dispatcher
  (CONFIGURATION *Core*).
- A warm snapshot base is RAM-sized, and a refresh needs room for a second generation until the
  swap. Size `BLASTBOX_SNAPSHOT_MEM_DIR` (a dedicated tmpfs such as `/dev/shm/...` with
  `BLASTBOX_SNAPSHOT_MEM_TMPFS`, or fast local disk) for two bases per warm tier.
- Disk-free is exported on `/metrics` (`blastbox_host_disk_free_bytes`).

## AWS and static workers

A `remote` dispatcher host needs only the common checks (pool-runtime, confinement, clock, scratch; preflight
skips the AppArmor, userns and CPU-flag checks there) plus network reach to its
workers. Each static box or cloud worker is its own host: prepare it as a **docker + gVisor** host
(the worker image runs under runsc there) and run `blastbox preflight --tier docker` on it. AWS
tiers are fail-closed on credentials and entitlement; see CONFIGURATION *Runtime: AWS*.
