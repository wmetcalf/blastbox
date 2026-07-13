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
| **libvirt VM** (warm/cold) | full KVM guest OS per job | the guest OS itself (N/A) | N/A (full guest) | libvirt warm pool (golden overlay; snapshot-revert recycle) |

> The **libvirt VM tier** is for engines whose analysis *is* a full OS (e.g. validating Windows
> code signatures inside real Windows) — not an in-process sandbox model. It's a **library primitive**
> (`vm_compose` + `VmJobDispatcher`), wired by the consuming app, **not** selected by
> `BLASTBOX_POOL_RUNTIME`. See *Which tier* and CONFIGURATION's *Runtime: libvirt VM*.

> **The Landlock footgun.** nono needs the `landlock_*` syscalls. The **gVisor Sentry does
> not implement them** (verified: `landlock_create_ruleset` → ENOSYS) — so the inner-nono
> layer **cannot** run under runsc/gVisor and `select_sandbox` / `build_worker_docker_run_argv`
> **fail-fast or skip+warn** there. nono-nesting belongs on **runc** (its main value — the one
> tier with a weak outer boundary) and **the FC guest**. gVisor relies on its Sentry, which is
> itself a syscall sandbox, so nono adds nothing there — they're *substitutes, not layers*.

> **Network-endpoint tiers are a different axis.** `static` (other hardware), `aws-ec2` /
> `aws-lambda-microvm` (cloud), and `cascade` (local + overflow) decide **where the worker runs**, not
> how it's isolated — each remote worker runs the same hardened worker image and provides its own
> boundary (typically runsc). The host drives them over the generic HTTP+tar transport (`remote_http`,
> the same sealed-envelope contract as a local sandbox). See *Which tier* below + deployment shape 3.

## Which tier do I want?

- **Bare-metal host, no KVM, no gVisor** → `runc` + an inner namespace sandbox. Prefer
  **`nsjail`** (full seccomp); use **`nono`** where unprivileged user namespaces are
  disabled (`nsjail`/`bwrap` can't run) — Landlock needs no userns.
  - **Ubuntu 24.04+ userns gate:** `kernel.apparmor_restrict_unprivileged_userns=1` blocks the
    user namespaces `nsjail`/`bwrap` need. Load the **scoped per-binary** AppArmor profiles
    (`deploy/apparmor/blastbox-{bwrap,nsjail}` — they grant `userns` to *only* those two binaries,
    leaving the host-wide restriction in force; see `deploy/apparmor/README.md`). Do **not** use
    `sysctl …unprivileged_userns=0` — that lowers the control host-wide.
- **Host with gVisor** → `runsc` (the secure default; `runc` is fail-closed-refused unless
  `BLASTBOX_ALLOW_RUNC=1`). Inner sandbox = `container`.
- **Host with KVM** → `firecracker` — the strongest boundary (hardware VM, no guest NIC).
  Add the **warm-UNO snapshot** tier for LibreOffice to hide the ~750 ms soffice boot.
- **Throughput-sensitive** → a **warm pool** (FC snapshot or gVisor C/R), sized so
  `BLASTBOX_DISPATCH_CONCURRENCY == BLASTBOX_POOL_WARM_SIZE`.
- **Other physical machines you already own** → `static` — point the pool at a fixed fleet of
  always-on boxes each running `python -m blastbox.worker.http_agent` (`BLASTBOX_STATIC_WORKERS`).
  Spawn claims a free box, reap returns it — nothing boots/terminates; each box provides its own
  isolation (run the worker image under runsc there).
- **Cloud burst** → `aws-ec2` (throwaway EC2 per job) or `aws-lambda-microvm` (Lambda MicroVM + JWE) —
  disposable, one job then terminate; fail-closed on creds/entitlement (`BLASTBOX_EC2_*` / `BLASTBOX_LAMBDA_*`).
  Add the **warm** cloud tiers — `aws-lambda-snapstart` (per-microvm suspend/resume) or
  `aws-ec2-hibernate` (`stop --hibernate`/`start`) — to keep pre-warmed slots parked between jobs.
- **X primary + burst to Y elsewhere** → `cascade` — an ordered `BLASTBOX_POOL_TIERS` list, e.g.
  `static:8,aws-ec2:16`: fills the primary first, overflows to the next tier. **All tiers must share a
  dispatch style** (all network-endpoint `static`/`aws-*`, or all file-handshake `gvisor`/`firecracker`
  — a mix fails fast at startup). Set `BLASTBOX_POOL_WARM_SIZE`=the primary's capacity, `_CEILING`=the sum.
- **The analysis *is* a full OS** (Windows code-sign validation, an engine that needs a real
  desktop) → the **libvirt/KVM VM tier**: a whole disposable guest per job. Library-wired via a
  `VmWorkerSpec` (`vm_compose`), not `BLASTBOX_POOL_RUNTIME`. **Pin worker IPs** with
  `worker_ip_pool` (assign-enforce) so a root-compromised guest can't re-IP around the egress
  rooter — see *Egress enforcement on the VM tier* below.

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

### Egress enforcement on the VM tier

A container/microVM worker has **no `CAP_NET_ADMIN`** and a host-managed netns/veth, so it
*cannot* re-IP itself — its egress rooter keys safely on the worker's address. A **full libvirt
VM worker is root in its own guest**, so it *can*. Two layers close that:

- **Assign+enforce IP** (`worker_ip_pool`): blastbox reserves a deterministic MAC+IP per worker and
  pins it with a libvirt `clean-traffic` nwfilter (`CTRL_IP_LEARNING=none` + `IP=`). The guest can
  set whatever address it likes internally; the host **drops spoofed source IPs at L2**, so the
  `LibvirtEgress` per-IP `iptables` chain (`BBVM_<ip>`) stays authoritative. This is the
  **recommended** mode for any VM worker with egress.
- **DHCP-learning** (`worker_ip_pool=""`, the zero-config default) learns the worker's IP from its
  DHCP lease and restricts `DHCPSERVER` to the trusted bridge. It's convenient but the learned pin
  **lapses with the lease** on a long-idle warm worker — so it's not snapshot-robust. Prefer
  assign-enforce when egress is enabled.

> **toolz3 gotcha:** with `net.bridge.bridge-nf-call-iptables=0`, bridged traffic bypasses the host
> `FORWARD` chain, so `physdev`-keyed rules silently don't match. The `LibvirtEgress` rooter keys on
> the **source IP** (which assign-enforce makes unspoofable) rather than the bridge port, sidestepping
> that sysctl entirely.

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

### 3. Network-endpoint workers — other hardware, cloud, or a cascade

Run the worker **off-box** instead of launching a local container per job. Bake
`python -m blastbox.worker.http_agent` (`BLASTBOX_ENGINE=<module:Class>`) + the engine into an image;
the host POSTs each job's input and gets the sealed output tar back over the generic `remote_http`
transport (same sealed-envelope contract as a local sandbox; auth via a shared bearer token or the
Lambda JWE). All wiring is env — no code changes to add/resize/retarget a tier.

```sh
# (a) a fleet of boxes you own — claims a free box, returns it; nothing boots/terminates
BLASTBOX_POOL_RUNTIME=static
BLASTBOX_STATIC_WORKERS=box1:8765,box2:8765,box3:8765     # +BLASTBOX_STATIC_WORKER_TOKEN

# (b) disposable cloud workers (one job -> terminate; fail-closed on creds)
BLASTBOX_POOL_RUNTIME=aws-ec2                             # or aws-lambda-microvm
BLASTBOX_EC2_AMI=ami-...                                  # +BLASTBOX_EC2_* placement

# (c) fixed fleet + overflow to cloud — a single pool (all tiers network-endpoint; can't mix with gvisor/fc)
BLASTBOX_POOL_RUNTIME=cascade
BLASTBOX_POOL_TIERS=static:8,aws-ec2:16                   # your boxes -> AWS
BLASTBOX_POOL_WARM_SIZE=8                                 # keep the 8 static warm
BLASTBOX_POOL_CEILING=24                                  # 8 + 16
BLASTBOX_DISPATCH_CONCURRENCY=24
```

In the cascade the **primary (local) tier is fail-closed**; an overflow tier that isn't available at
startup is logged and **skipped**, so local capacity still comes up if the cloud/remote tier is
misconfigured. Full knob tables: the *Runtime: static / AWS / cascade* sections of CONFIGURATION.md.

**Per-engine profiles.** The tier config above is engine-agnostic; the engine-specific slice
(`BLASTBOX_ENGINE`, param allowlist/reserved keys, egress policy, resource caps, worker env) lives in
ready-to-source examples under `deploy/remote/` — `clippyshot.env.example` and `redtusk.env.example`.
Source one, add a tier slice, done. The only non-config difference between engines is the prebaked
worker image (ClippyShot bakes LibreOffice+PDFium; RedTusk bakes JDK+the Tika jar). Both are
live-proven on the `aws-ec2` disposable tier.

## Egress netpolicy + `blastbox-netd` (optional)

Egress is **off by default** (workers run `--network=none`). To let a worker reach the network
under a controlled exit — capture a pcap, route through SOCKS/tor/VPN, or MITM-decrypt TLS — you
declare a **personality** (`BLASTBOX_NETPOLICY_<NAME>`, see CONFIGURATION.md → *Network policy /
egress overlay*) and run the privileged **`blastbox-netd`** helper alongside the dispatcher. netd
is out-of-band from the cap-dropped dispatcher: it watches labeled worker containers and wires
their real exit (netns TUN + tun2socks, a host REDIRECT → tor, a default route to a VPN/NAT or
sslproxy gateway) and seals a host-side pcap into the result envelope. **Without netd running, an
egress worker sits on an internal bridge with no route — fail-closed.**

Run it as a systemd unit (packaged in `deploy/systemd/`):

```sh
sudo cp deploy/systemd/blastbox-netd.service /etc/systemd/system/
sudo install -Dm600 deploy/systemd/blastbox-netd.env /etc/blastbox/netd.env   # then edit
sudo systemctl daemon-reload && sudo systemctl enable --now blastbox-netd
```

The unit runs the `blastbox-netd` console script with `AmbientCapabilities=CAP_NET_RAW
CAP_NET_ADMIN …` (raw sockets + netns/route manipulation, not full root) and reads its config from
`/etc/blastbox/netd.env` (the `BLASTBOX_NETD_*` knobs; all empty = inert). It needs
`tcpdump`/`iproute2`/`nsenter`/`tun2socks` on the host and access to the docker socket.

## Generating a sandbox policy (optional, advanced)

`blastbox.profile` traces an engine over a corpus and emits candidate seccomp/Landlock
policies, and a **drift-gate** (`tests/profile/test_drift_gate.py`) asserts the engine uses
no escape-only syscall and opens no network egress — run it in CI to catch a dependency bump
that widens the surface. Feed a generated nono profile to `BLASTBOX_WORKER_NONO_PROFILE`
(outer wrap) or the engine's inner-nono profile knob. Candidate seccomp allowlists are
**reviewed artifacts**, not auto-shipped — the denylist stays the default.
