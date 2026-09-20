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
  - **The CHILD profile is a separate thing, and it now gates selection.** The two profiles
    above let the sandbox *binaries* create a userns; `blastbox-sandbox` is the profile applied
    to the detonated child. Without it loaded, `nsjail` and `bwrap` both report
    `apparmor_missing` and are **skipped** by `select_sandbox` — nsjail included, which used to
    be silently exempt because it gated the reason on a flag nsjail never had (#160). So load
    it with the others:

    ```sh
    sudo cp deploy/apparmor/blastbox-sandbox /etc/apparmor.d/
    sudo apparmor_parser -r -W /etc/apparmor.d/blastbox-sandbox
    grep '^blastbox-sandbox ' /sys/kernel/security/apparmor/profiles   # name AND mode
    ```

    It is shipped in this repo (it was not, before #160, which is what made the requirement
    unsatisfiable). Read `deploy/apparmor/README.md` before adapting it: attaching a profile is
    also what makes nsjail pass `--proc_rw`, and the profile's deny rules are the mitigation for
    the `/proc` surface that opens. The alternative is accepting the gap knowingly with
    `BLASTBOX_WARN_ON_INSECURE=1`; the "no sandbox backend available" message names both.

    Dispatcher-launched workers under `runsc` carry that variable already (both launchers —
    `host/runtime/docker.py` and the warm/snapshot tier), so this bites bare-metal and
    directly-invoked workers first.
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

### 4. Auto-sizing a multi-worker host (node pool autosizer)

Shapes 2 and 3 hand-tune `BLASTBOX_POOL_CEILING`/`WARM_SIZE` per dispatcher. On a host that runs
**several engines and/or several tiers**, the **node pool autosizer** instead sizes every warm pool
from live queue demand under the host's RAM/vCPU budget, so you no longer size each ceiling by hand.
Opt-in, OFF by default; full knob table in [CONFIGURATION.md](CONFIGURATION.md#node-pool-autosizer-opt-in).
Keep a sane `BLASTBOX_POOL_CEILING`/`WARM_SIZE` on each dispatcher as a **fallback**: if the sizer
can't start (shared dir unavailable, incomplete engine inventory, any setup error) the dispatcher
restores its configured static pool rather than running unsized. It is a whole-node protocol, so
**every dispatcher on the host must participate with a consistent config** and share one dir:

```sh
# on EVERY dispatcher on the host (each warm sidecar AND the cold dispatcher):
BLASTBOX_NODE_RESOURCE_MANAGEMENT=1              # enforce the host budget (static weight shares)
# BLASTBOX_NODE_BALANCING=1                      # optional: rebalance the budget live by queue backlog (implies RESOURCE_MANAGEMENT)
BLASTBOX_NODE_ENGINES=clippyshot,redtusk,titanarum
BLASTBOX_NODE_ENGINE_CLIPPYSHOT_RAM_MIB=2048     # per-slot footprint, per engine
BLASTBOX_NODE_SHARE_DIR=/var/lib/blastbox/node   # bind-mount this into every engine stack on the host
BLASTBOX_DISPATCH_CONCURRENCY=16                 # per dispatcher; the sizer caps the pool at this
```

The modes this unlocks on one host:

- **Same engine on two tiers** (a firecracker AND a gVisor sidecar for one engine): each is a
  distinct `(engine, tier)` pool that **shares** the host budget — they don't each size to the whole
  node. Untargeted jobs (no pinned `target_tier`) are claimable by either tier, so the sizer counts
  that shared queue **once** across the engine's tiers, not once per tier (no double-provisioning).
- **The cold dispatcher is budgeted too.** The pool-less cold-only dispatcher (the break-glass /
  overflow process from shape 2) publishes a cold-worker reservation and gets a budgeted admission
  gate, so the warm sidecars account for its docker workers instead of handing the whole budget to
  warm slots. The gate always keeps **one** cold permit available (a deliberate liveness floor so an
  egress/warm-miss job never fully starves — a bounded overshoot); beyond that, cold jobs with no
  budget headroom are **deferred** (re-queued with a `claimable_after` timestamp) rather than
  dropped, and become claimable again once capacity frees.
- **An all-local cascade is budgeted as one pool.** A cascade whose tiers are all local
  (`BLASTBOX_POOL_TIERS=firecracker:4,gvisor:8`) is now sized like any warm pool. Declare that
  engine's `BLASTBOX_NODE_ENGINE_<NAME>_RAM_MIB` at the **heavier** tier's footprint — the cascade
  fills tiers in order and one footprint prices the whole ceiling. A cascade with any **off-node**
  tier (`aws-ec2`/`aws-lambda-*`/`static`) is left unmanaged: its off-box slots don't belong in the
  local budget.

Validate the sizing on a real host without touching production containers with
`examples/node_sizer_exercise.py` (fake pools, real `/proc/meminfo` budget; prints a per-check
PASS/FAIL — it uses its own temp dirs, so it never touches your share dir) and
`examples/node_sizer_xnode_demo.py` (cross-host snapshot isolation). The xnode demo takes the share
dir as its **first argument** (default `/tmp/bb-xnode`) — give it a scratch path, never your live
`BLASTBOX_NODE_SHARE_DIR`: it publishes fake demand snapshots it doesn't clean up, which would
pollute a production node view.

## Egress netpolicy + `blastbox-netd` (optional)

Egress is **off by default** (workers run `--network=none`). To let a worker reach the network
under a controlled exit — capture a pcap, route through SOCKS/tor/VPN, or MITM-decrypt TLS — you
declare a **personality** (`BLASTBOX_NETPOLICY_<NAME>`, see CONFIGURATION.md → *Network policy /
egress overlay*) and run the privileged **`blastbox-netd`** helper alongside the dispatcher. netd
is out-of-band from the cap-dropped dispatcher: it watches labeled worker containers and wires
their real exit (netns TUN + tun2socks, a host REDIRECT → tor, a default route to a VPN/NAT or
sslproxy gateway) and seals a host-side pcap into the result envelope. For the **netd-route-wired**
personalities (`socks` / `tor` / `wireguard` / `openvpn` / `inspect`), **without netd running the
worker sits on an internal bridge with no route — fail-closed.** (This is *not* an egress
kill-switch for `direct` / `inetsim`, which attach to their own self-contained `bb-net0` /
`bb-fakenet` bridge, nor for `httpproxy`, whose only exit is the injected `HTTP(S)_PROXY` env
pointing at a proxy sidecar — those don't depend on netd's routing.)

**Prerequisites** (the overlay needs more than just the netd process):
- **Create the bridges with `sudo blastbox egress apply`** — it creates `bb-socks`
  (socks/tor), `bb-vpn` (openvpn/wireguard), `bb-net0` (`direct`) and `bb-fakenet`
  (`inetsim`), and relocates any whose default subnet collides with something already on
  the host (see *Two exit modes* below). Do **not** hand-create these: a hand-pinned
  bridge is adopted as-is, which silently discards that collision avoidance.
  `bb-inspect` is still manual: `docker network create --internal bb-inspect`.
- **Use the `runc` runtime for netd-wired tiers.** netd needs a **host-visible netns** to wire the
  worker, so the dispatcher refuses `tor`/`socks`/`openvpn`/`wireguard`/route-inspected jobs unless
  the runtime is `runc` (gVisor/FC hide the netns). Set `BLASTBOX_ALLOW_RUNC=1` accordingly.
- **Declare `gateway=` in the personality** for `tor`/`openvpn`/`wireguard`/`inspect` (e.g.
  `BLASTBOX_NETPOLICY_TORNET='exit=tor,gateway=<netd-transproxy-gw-ip>'`) so the worker waits for
  netd's route before detonating — the `BLASTBOX_NETD_*` gateway alone isn't enough.
- **Enable capture/decrypt on the dispatcher.** netd only captures a pcap when
  `BLASTBOX_NET_CAPTURE=1` is set on the dispatcher (and TLS decrypt needs `BLASTBOX_NET_DECRYPT=1`);
  both default off.

### Two exit modes: per-host exits and a global overlay

The prerequisites above assume every node runs its own exit sidecars — which means copying VPN
profiles and proxy credentials to every node. `blastbox egress --mode global` is the
alternative: **one** host runs the real exits, every other node reaches them over a WireGuard
overlay and holds no credentials at all.

**The gateway address is identical in both modes.** In `local` mode `172.31.0.10` *is* the
OpenVPN client sidecar; in `global` mode it is a credential-free forwarder
(`deploy/egress-forwarder`) that carries traffic to the central host. Personalities, netd
flags, worker labels and the in-netns routes are byte-identical either way — a node's mode is
only ever *which container sits at that address*. Nothing in Python changes:
`netwire.gateway_route_commands` takes a plain IP.

| | per-host (`--mode local`) | global (`--mode global`) |
|---|---|---|
| credentials | on every node | on the exit host only |
| `172.31.0.10` | the exit sidecar | credential-free forwarder |
| blast radius of a node compromise | a VPN profile / proxy key | a wg transport key |
| exit IP | this node's provider session | shared, central |

Bring-up, exit host first (order matters — the forwarder refuses to start until the node-side
source route exists):

```sh
# 1. exit host — already runs the sidecars
sudo blastbox egress gateway                       # prints the EXIT HOST's public key
sudo blastbox egress gateway-exit                  # records the exit role; replayed at boot

# 2. worker node — generates its OWN key and prints it; the private half never travels
sudo blastbox egress peer --peer-ip 10.77.0.3 \
     --gateway-addr <exit host> --gateway-pubkey <exit host public key>

# 3. back on the exit host — enrol the peer with the key step 2 just printed
sudo blastbox pki issue-node --node-id toolz3 --wg-pubkey <the peer's public key> \
     --engine boxjs --tier openvpn --tier wireguard
sudo blastbox egress peer-add --peer-ip 10.77.0.3 --cert /var/lib/blastbox/pki/node-toolz3.crt

# 4. worker node again — bring up the tier
sudo blastbox egress apply --mode global --upstream-gw 10.77.0.1

# 5. prove it — including that killing the overlay removes egress
sudo blastbox egress check
# reads the gateway and interface from /etc/blastbox/egress.env, so it follows a
# subnet reallocation; pass --gateway-ip / --wg-if only to override
sudo scripts/test-egress-leak.sh --mode global
```

**libvirt VM workers get no internet unless they are given it.** The VM tier attaches
workers to `bb-isolated` — a libvirt network with **no `<forward>` element**, which is
libvirt's own idiom for "guests reach each other and the host, nothing forwards to the
physical NIC". Define it once per VM host:

```bash
sudo virsh net-define deploy/libvirt/bb-isolated.xml
sudo virsh net-start bb-isolated
sudo virsh net-autostart bb-isolated
sudo virsh net-dumpxml bb-isolated | grep -c '<forward'    # must print 0
```

Verify against **`net-dumpxml`**, not the file. The shipped XML's comments mention
`<forward>` several times (warning you not to add one), so `grep -c '<forward'` on
`deploy/libvirt/bb-isolated.xml` prints 3 and proves nothing; `net-dumpxml` returns what
libvirt actually parsed, comments stripped. Confirmed on a live host: the file greps 3,
the dump greps 0.

If `net-start` fails with `Unable to create: /var/lib/libvirt/dnsmasq/<bridge>.status`
(`errno=13`), the cause is host ownership, not this definition: `/var/lib/libvirt/dnsmasq`
must be `root:root`. dnsmasq drops to `nobody` and cannot create a new status file in a
directory owned by someone else — and networks defined *before* the ownership changed keep
working, because their status files already exist, so the breakage only ever shows up on
the next new network.

This replaces libvirt's shipped `default` network, which is `<forward mode='nat'/>` and
has working internet. That was the previous default, and combined with `egress_policy`
being optional it meant a VM worker configured with nothing at all detonated malware with
direct NAT egress and no host-side rules — two individually reasonable defaults
conspiring, which is why neither looked wrong.

The default is not the control. `spawn()` reads the network the guest will **actually**
attach to and refuses to boot a worker that has no `egress_policy` onto anything that
forwards — including `route`, which does not translate addresses but still puts the guest
on your LAN — and refuses just as firmly when it cannot read the network definition at
all. A worker that *needs* egress gets it the governed way: a per-worker `egress_policy`
applied to its IP by the rooter, not by being placed on a network that forwards.

**Arming the grants gate on a worker (optional).** `pki issue-node` writes the cert on
the host you ran it on — step 3 above runs on the EXIT HOST — so enabling enforcement on
a worker means copying two files to it and pointing one variable at them:

```bash
# on the exit host
scp /var/lib/blastbox/pki/node-toolz3.crt /var/lib/blastbox/pki/ca.crt toolz3:/var/lib/blastbox/pki/
# ...and the KEY, if this node will claim through the control plane (#178). The local
# grants gate only VERIFIES and needs the cert alone; signing a claim needs the key.
# It is 0600 and must stay that way on the far side.
scp -p /var/lib/blastbox/pki/node-toolz3.key toolz3:/var/lib/blastbox/pki/
# on the worker, in the dispatcher's environment
BLASTBOX_NODE_CERT=/var/lib/blastbox/pki/node-toolz3.crt
```

`ca.crt` is required and is easy to forget: verification needs the CA's **public** half
on the worker (never `ca.key`, which stays on the issuing host). Then
`blastbox pki node-status` on the worker says whether the gate is armed, whether the
certificate verifies, and what it would accept. A node whose certificate does not verify
**refuses all work** — that is revocation working, and it is also what an unnoticed
missing `ca.crt` looks like, so check `node-status` before concluding the fleet is idle.

Note that once the gate is armed, the paragraph below about the worker side looking fine
no longer holds: an expired certificate stops the worker taking any job at all, not just
its egress ones.

**Enforcing grants at the hand-over, not only on the node (#178).** Everything above is
the node checking *itself*: the gate runs on the machine it limits. It is the right control
for a lapsed certificate or an operator mistake, and it is not a control against the node,
because the node executes it.

If the ingress host has a CA (`blastbox pki init`), ingress also serves two routes that
move the decision to the *other* side of the hand-over:

```
GET  /v1/nodes/challenge        → a short-lived challenge
POST /v1/nodes/session          → cert + signature → a session token (10 min)
POST /v1/nodes/claim            → the job, or 403          }  both carry the token in
GET  /v1/nodes/jobs/{id}        → read a job this node holds }  X-Blastbox-Node-Session
POST /v1/nodes/jobs/{id}        → report on it              }
```

A node signs the challenge with the private key beside its `node-*.crt` **once per session**
— signing every request would cost a challenge round trip and a signature per call. The
token names the node and carries **no grants**: what it may do is re-resolved from this
host's certificate store on every request, so removing or narrowing a certificate takes
effect on the next call rather than at token expiry.

The token travels in `X-Blastbox-Node-Session`, **not** `Authorization` — that header is the
API key's, and one header cannot carry both credentials.

The engine check happens before any job moves. Tier and credentials requirements are derived
here from the job's own network personality, never asked of the node: a caller that could
omit `tier` would be choosing its own authorisation check. Because a job's requirements are
only knowable once one is picked, an unentitled job is claimed, refused and **released back
to `QUEUED`** with its claim cleared — the node never receives the record.

**TLS.** This protocol authenticates the node but assumes the channel is server-authenticated.
`blastbox serve` now issues its own certificate from the local CA when a PKI is present, so
the secure path needs no extra step; `--tls-cert/--tls-key` uses your own, and `--no-tls` is
available for a listener behind a TLS-terminating proxy.

There is nothing to configure. The routes appear because a trust anchor exists; with no CA
they are not registered at all and nodes claim from the store exactly as before. The
challenge-signing key is created in the PKI directory on first use, `0600`.

Three things an operator must know:

* **Whether this is prevention or merely defence in depth is a configuration choice.** A
  node pointed at a *database* claims from the store directly and walks around these routes
  entirely; for that node they are an audit trail. A node pointed at the *control plane* has
  no other path, and then a refusal here is prevention. Choose deliberately:

  ```sh
  # federated node — no database credential anywhere on the box
  BLASTBOX_DATABASE_URL=https://control-plane.example:8443
  BLASTBOX_NODE_CERT=/var/lib/blastbox/pki/node-toolz3.crt   # key is the sibling .key
  BLASTBOX_NODE_CA=/var/lib/blastbox/pki/ca.crt              # PUBLIC half only
  ```

  That is the same variable, not a new one, because a node talks to one or the other and
  never both. Such a node also loses capabilities it never needed: it cannot submit jobs,
  delete records, or enumerate the queue — those raise rather than silently doing nothing, so
  a process mis-deployed with this URL fails loudly instead of looking healthy.

  **What a restart costs.** The proof that a job was handed to *this* node is held in memory
  by the process that claimed it, so a node restarting mid-job cannot report on its in-flight
  work. That is deliberate — a restarted dispatcher lost the worker running the job too — and
  those jobs are picked up by the existing reclaim-on-timeout path.
* **With `BLASTBOX_API_KEY` set, these routes require it too.** They are not in the
  always-public list. The API key is the *submitter's* credential, so giving it to every
  node also lets every node submit jobs. Either accept that, or run nodes against a listener
  with no API key and let the certificate be the only authentication — which is what it is
  designed to be.
* **A refusal never says why.** Wrong CA, unheld key, ungranted engine and expired challenge
  all return the same message, so a caller cannot map the fleet's grants by probing. The
  reason is in the ingress log (`node_claim: refused …`); look there, not at the response.

**Step 3 RECURS.** `pki issue-node` defaults to a 7-day lifetime — that short lifetime is
what makes "revocation is stop renewing" work without a CRL or any online check — and the
exit host's `prune_expired_peers` runs on every `apply`, which now includes the reconcile
timer. So a fleet enrolled in one afternoon loses every tunnel on the same afternoon a
week later unless step 3 is repeated for each node with the same node id and wg key,
followed by `egress peer-add --cert`. From the worker's own side nothing looks wrong when
this happens: its rules are intact and `enforcement_present` passes; only the forwarder's
gate starts failing. `blastbox egress check` on the exit host and its `health` line both
warn two days ahead, naming each peer and the hours it has left.

**Peers are registered from a CA-signed node cert, not a pasted key.** `pki issue-node`
binds three things into one signed object: the node's identity, its WireGuard public key,
and its **grants** — which engines and netpolicy tiers it may be assigned, and whether it
may hold provider credentials at all. `peer-add --cert` then verifies the CA signature and
takes the identity and key from the payload, so registering a peer is a signature check
rather than trust in a string an operator retyped. Grants default to **nothing**, so a cert
issued without them produces an idle node rather than an unrestricted one, and revocation is
"stop renewing" — which is why the default lifetime is a week.

`--name`/`--public-key` still work for nodes not yet enrolled, and say plainly that the key
is unauthenticated. The certificate's node-info extension uses a **placeholder OID arc that
is not an IANA Private Enterprise Number**; it is fine while these certs never leave this
CA, and must be replaced before they do. Design context: `docs/superpowers/specs/2026-09-15-federated-node-identity-and-placement.md`.

`apply` is **idempotent** (every step is guarded or best-effort) and installs
`blastbox-egress.service`, which re-applies at boot. That unit is not optional bookkeeping:
ip rules, the routing table and the `BB-WG-*` chains are all runtime state and none of it
survives a reboot. Without it a node comes back with its bridges intact and its *enforcement*
gone — failing closed, correctly, and staying that way until a human notices.

`apply` also **allocates subnets**. The defaults (`172.28`–`172.31`) collide on a busy CAPE
host with `cape_default`, `fakenet-ng` and per-branch compose stacks; a colliding bridge is
moved to the first free pool and any address pinned inside it moves with it, keeping its host
offset. Two rules keep that safe: the candidate set excludes **everything the host already
routes**, not just docker's pools — the management LAN is a `/16` inside the first pool tried,
and picking it would cut ssh to the node — while a summary route (`/8` or broader, e.g. a
corporate `10.0.0.0/8`) is advisory rather than blocking, or it vetoes every candidate. A
bridge that already exists is adopted, never re-decided. Pass `--no-auto-subnets` to fail on a
conflict instead.

**The overlay carries the `bb-vpn` tiers only — `openvpn` and `wireguard`.** The forwarder
is started with `BLASTBOX_WORKER_SUBNET=<vpn_subnet>` and the node-side source route keys on
its single uplink `/32`, so `tor` (a host REDIRECT into a local tor daemon), `socks` (an
in-netns TUN to a SOCKS sidecar) and `httpproxy` egress through their own local sidecars in
**both** modes. Two consequences worth stating plainly: their liveness is independent of the
forwarder, so a dead overlay does not gate them; and **a global-mode node running those tiers
is not credential-free for them** — it still holds whatever its tor/SOCKS/proxy sidecars need,
and their traffic leaves by this node, not the central exit. If you want every tier
centralised, run only `openvpn`/`wireguard` personalities on global-mode nodes.

**The dispatcher defers egress jobs on a degraded node.** `blastbox egress health` is a
one-line JSON verdict, and the dispatcher consults a cached copy before launching any
netd-wired tier: if this node's exit is down, the job is requeued with `defer` so a healthy
peer takes it, rather than being failed one at a time for a reason that has nothing to do with
the sample. The gate is **opt-in** — armed when `/etc/blastbox/egress.env` exists (the marker
that this module manages the node), and forceable with `BLASTBOX_EGRESS_HEALTH_GATE=1/0`. A
broken probe never gates.

**Four things fail open if you build this by hand.** All four were found by measurement on a
live two-node setup, each presenting as "it works" or as a plain outage; all four are now
pinned by `tests/host/test_egress.py` and by `test-egress-leak.sh --mode global`:

- An `ip rule` that matches but finds an empty table **falls through to `main`** — so a dead
  tunnel silently becomes direct WAN egress. A blackhole rule sits behind every lookup.
- WireGuard `AllowedIPs` is cryptokey routing, not a route. Set to the overlay prefix alone it
  discards every internet-bound packet *inside* the tunnel, with no error anywhere. It is
  `0.0.0.0/0` with `Table = off`, so wg-quick installs no routes and only what we deliberately
  source-route enters the tunnel.
- Both hosts run `FORWARD` policy `DROP`. Chains that match on source cover only the outbound
  leg; the **return leg needs its own conntrack chain**, pointed at the bridge rather than the
  tunnel, or the path works and the client still times out.
- **"Running" is not health.** A container that failed its startup gate looks healthy in
  `docker ps` forever under a restart policy. Health is asserted from the gate's log line
  *scoped to the current incarnation* — restart count is informational, because it is
  monotonic and disqualifying on it ejects a recovered node permanently.

Every rule lives in a dedicated `BB-WG-*` chain reached by one jump and is torn down by match,
so a co-resident CAPE rooter is never touched — `check` counts foreign `FORWARD` rules to
assert it.

Run netd as a systemd unit (packaged in `deploy/systemd/`):

```sh
sudo cp deploy/systemd/blastbox-netd.service /etc/systemd/system/
sudo install -Dm600 deploy/systemd/blastbox-netd.env /etc/blastbox/netd.env   # then edit
sudo systemctl daemon-reload && sudo systemctl enable --now blastbox-netd
```

Run netd as **the same user (or group) that owns the job tree** (or share a group + `UMask=0007`)
so the dispatcher can later `rmtree` the root-created `<job>/capture/` — otherwise a non-root
dispatcher can't remove netd's root-owned capture dir on job retention.

The unit runs the `blastbox-netd` console script and reads its config from `/etc/blastbox/netd.env`
(`BLASTBOX_JOB_ROOT` + the `BLASTBOX_NETD_*` knobs; each tier is inert until its gateway/proxy is
set). netd genuinely needs privilege (docker socket, `nsenter` into worker netns, route/iptables/tun
manipulation), so the unit runs it as **root** with a `CapabilityBoundingSet` limiting it to the
network/admin capabilities it uses (tighten to taste). It needs `tcpdump`/`iproute2`/`nsenter`/
`tun2socks` on the host. Note the `ExecStart` path (`/usr/local/bin/blastbox-netd`) — adjust it to
wherever the console script installed (`/usr/bin` for a distro package).

## Generating a sandbox policy (optional, advanced)

`blastbox.profile` traces an engine over a corpus and emits candidate seccomp/Landlock
policies, and a **drift-gate** (`tests/profile/test_drift_gate.py`) asserts the engine uses
no escape-only syscall and opens no network egress — run it in CI to catch a dependency bump
that widens the surface. Feed a generated nono profile to `BLASTBOX_WORKER_NONO_PROFILE`
(outer wrap) or the engine's inner-nono profile knob. Candidate seccomp allowlists are
**reviewed artifacts**, not auto-shipped — the denylist stays the default.
