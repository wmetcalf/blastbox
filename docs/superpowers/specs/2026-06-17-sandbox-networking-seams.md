# Blastbox sandbox ↔ networking seams (reference)

> Status: LOCAL/untracked draft (per the no-draft-commit rule). Promote into the repo docs once
> reviewed. Captures how the egress tiers compose with each worker sandbox, grounded in code +
> live toolz2 validation (2026-06-16/17).

## The one-netns model (the whole thing in one picture)

```
host
 └─ worker netns      (exactly ONE per worker, IP = 172.x.y.z)
     │                     ▲
     │                     └── ROOTER (host-side):  ip rule from 172.x.y.z  table <tier>
     │                          → forces ALL traffic from this IP through none/fakenet/socks/vpn
     └─ inner sandbox (bwrap / nsjail / nono)   ← rides INSIDE the netns; no NET_ADMIN
          └─ LibreOffice / Tika / the sample    ← has IP 172.x.y.z → routed automatically
```

Three roles, kept separate:
1. **Launcher** creates the ONE netns + IP per worker (docker for runc/gVisor; a TAP for FC; a
   plain `ip netns` for bare-metal). 
2. **Rooter** (host, privileged — lives in `netd`) routes that IP through the chosen tier with
   `ip rule` + policy routing (+ `tun2socks` for socks). **Sandbox-agnostic** — proven to route a
   gVisor worker host-side (tun2socks saw its flows).
3. **Sandbox** confines the process *inside* the netns. It does NOT route; at most it owns/shares
   the netns and drops `CAP_NET_ADMIN` so the sample can't re-route or spoof its way out.

## Sandbox backends: what each PROVIDES (the seams)

| backend | namespaces | netns it gives the worker | network control it has | can it carry the routing model? |
|---|---|---|---|---|
| **container** (`container.py`) | (outer container's) | the **outer docker netns** (gets a real IP) | the outer container/CNI net policy | **YES — natural fit.** docker hands it an IP; the rooter targets that IP directly. This is what every tier was validated on. |
| **bwrap** (`bwrap.py`) | user+mount+pid+**net**+… | **own, fresh netns** — TODAY `--unshare-net` ⇒ *isolated, no egress* (fail-closed) | owns the netns | **YES, but needs a change.** Owns a netns ⇒ either (a) wire it (veth → bridge, rooter on its IP) or (b) drop `--unshare-net` and net-share the outer routed netns. Today it just isolates. |
| **nsjail** (`nsjail.py`) | clones new net+mount+pid+… (`--iface_no_lo`) | **own, fresh netns** — *isolated today* | owns the netns; can `macvlan`/iface-config | **YES, but needs a change.** Same as bwrap: it owns a netns that *can* be wired or net-shared; today it isolates. |
| **nono** (`worker/sandbox/nono.py`) | **NONE** (Landlock LSM only) | **none — inherits the parent's netns** | `--block-net` = all-or-nothing outbound block; (Landlock ABI≥4 *could* clamp connect-ports) | **NO — cannot route, cannot own a netns.** It can only block-or-allow and must borrow a netns from an outer layer. Under gVisor, Landlock is **ENOSYS** → even the block/clamp is a no-op. |

### INVARIANT: nono never carries network in standalone mode

Because nono owns no netns, "network access" under nono = the untrusted sample running on the
**inherited (host) netns**, with no per-worker IP, no rooter, no egress policy. Therefore:

- **Standalone nono** (`BLASTBOX_SANDBOX=nono`, the `NonoSandbox` backend): **`--block-net` is
  mandatory and non-negotiable.** It is unconditional in the code today (`nono.py:238`) — keep it
  that way; never add a toggle that allows egress in standalone mode. Standalone nono = fs
  containment + hard net kill, period.
- **nono as a cli-wrapper** (`nono_wrap` nested inside container/bwrap/nsjail): network is owned and
  controlled by the **outer** netns sandbox + rooter. This is the ONLY mode where nono may let
  traffic through. Today `nono_wrap` *also* hard-blocks (`--block-net`), so a nono-wrapped worker
  can't use an egress tier — the change (when we want nono + egress) is to make the wrapper's block
  CONDITIONAL: drop `--block-net` (or swap it for a Landlock connect-port clamp) **only** in wrapper
  mode when an egress tier is active, while standalone stays hard-blocked.

One-line rule: **nono never *provides* network — it may only *ride* network an outer netns-owning
layer already controls.** (TODO: a unit test asserting `NonoSandbox` argv always contains
`--block-net`, so the invariant can't be refactored away.) — DONE for blastbox `NonoSandbox`
(`test_block_net_invariant_regardless_of_net_egress`).

### nono at TWO levels — and the nested case must follow net_egress

nono is used two ways; they behave differently w.r.t. egress:

1. **Standalone backend** (`BLASTBOX_SANDBOX=nono` / `clippyshot.sandbox` not involved): nono IS
   the sandbox, owns no netns ⇒ **always `--block-net`**, can never carry egress. Consequence: an
   egress detonation simply does NOT pick standalone nono as its primary — it uses
   container/bwrap/nsjail (a netns owner). Standalone nono = sealed-case only.
2. **Nested wrapper** (nono *inside* a netns-owning sandbox, for a Landlock fs-clamp on top): the
   OUTER sandbox provides the routed netns (bwrap `--share-net` / container). If the nested nono
   blocks net, it **defeats the egress the outer layer granted**. So nested nono must follow the
   policy: **`block_net = not net_egress`** (block when sealed; when granted, ideally a Landlock
   connect-port CLAMP to the proxy/exit rather than a full block).

Current code: blastbox's nono is standalone-ONLY (a peer in `_ALL_BACKENDS`, no nested decorator) →
no 2-level conflict in the detonation path today. ClippyShot's nested `nono_wrap` (`block_net=True`
default) is a rasterizer → always sealed → correct. **Rule to apply WHEN a nested nono decorator is
added to blastbox: drive its `block_net` from `net_egress` (`block_net = not net_egress`).**

### Why nono is the odd one out (your question, exactly)
nono's niche is *containment without user namespaces* — it runs where bwrap/nsjail can't (userns
disabled, no `CAP_SYS_ADMIN`, nested-in-a-container). The price of "no namespaces" is **no netns**:
nono can never *be* the per-worker routed netns. It rides whatever netns the outer layer gives it
and adds an fs clamp + an optional **all-or-nothing** net block. So:
- **nono CANNOT enforce the egress *routing*** (fakenet/socks/vpn). It has no netns to target and
  no policy routing. ✓ (your claim)
- **bwrap / nsjail / container CAN** — they're namespace sandboxes; the rooter targets their netns
  by IP. ✓ (your claim)
- nono's *positive* networking role is narrow: **block-net** (kill all egress) or, with Landlock
  net rules, a **port clamp** that *complements* the rooter as defense-in-depth (runc/FC only;
  ENOSYS under gVisor). It enforces "may only connect to the proxy"; it does not move the traffic.

## Egress tiers (what the rooter can route a worker into)

| tier | driver | bridge | what it is |
|---|---|---|---|
| **none** / **drop** | none/drop | `--network=none` | sealed (the safe default) |
| **fakenet** | inetsim | bb-fakenet (internal) | FakeNet-NG sidecar answers everything; gVisor-able; live-proven |
| **direct** | direct | bb-net0 (egress) | real internet (+ resolv.conf DNS fix for gVisor) |
| **socks** | socks | bb-socks (internal) | tun2socks → SOCKS5 exit (tor/BrightData); DNS-over-TCP; exit-IP=proxy proven |
| **vpn** | openvpn/wireguard | bb-vpn (internal) | default route → VPN+NAT gateway sidecar (all-IP); NAT-gw proven, PIA host-side pending |
| **capture** | (orthogonal) | — | netd tcpdump on the bridge by worker-IP → sealed pcap artifact |
| **decrypt** | (orthogonal) | — | GoGoRoboCap over the pcap given keys → decrypted/mixed pcap artifacts |

## Worker-mechanism × tier support (corrected with the host-side rooter)

| worker | capture | direct/fakenet | socks | vpn |
|---|---|---|---|---|
| **container + runc** | ✓ | ✓ | ✓ | ✓ |
| **container + gVisor** | ✓ | ✓ (DNS fix) | ✓ **via rooter** | ✓ **via rooter** |
| **FC microVM** | ✓ (TAP) | needs TAP* | needs TAP* | needs TAP* |
| inner **bwrap/nsjail** | inherits worker's | inherits (net-share) or wire own netns | same | same |
| inner **nono** | inherits worker's | inherits only (can't provide) | inherits only | inherits only |

\* FC today is **vsock-only — no network device at all**; egress needs a TAP netdev added to the
Firecracker config first, then the rooter applies to `tap_<vm>` like any host iface.

**Earlier "gVisor can't do socks/vpn" was wrong** — that was true only for the *nsenter* technique
(gVisor exposes no host netns to enter). The **host-side rooter** routes gVisor fine because the
Sentry still emits real packets to the bridge; live-proven (tun2socks logged a runsc worker's flows).

## Two routing techniques (both valid, different trade-offs)

| | nsenter wiring (built: netd `_wire_socks`/`_wire_vpn`) | host-side rooter (proven for gVisor) |
|---|---|---|
| where | inside the worker netns (TUN/route) | host: `ip rule from <ip>` + tun2socks/VPN |
| gVisor | ✗ (no host netns) | **✓** |
| runc / FC | ✓ | ✓ |
| bypass resistance | **strong** (worker's only route IS the TUN) | relies on source-IP → needs egress **anti-spoof** |
| matches CAPE | no | **yes** |

Recommended synthesis: **rooter is the primary, universal router** (covers gVisor+runc+FC, matches
CAPE), with **source-IP anti-spoof** (`FORWARD -s <bridge> ! --src <assigned> -j DROP`) as its
enforcement; namespace sandboxes (bwrap/nsjail/container) ride the routed netns and *help* enforce
by dropping NET_ADMIN; **nono** is an orthogonal in-kernel clamp on top, not a router.

## Current gaps (to make this real per backend)
- **bwrap/nsjail**: change from "unshare-net + nothing" to net-shared (or wire the owned netns).
- **FC**: add a TAP netdev (vsock-only today), then rooter on the TAP.
- **rooter**: lift netd from nsenter-only to host-side `ip rule` + anti-spoof (unlocks gVisor).
- **PIA**: run OpenVPN host-side (CAPE-style, where it works) — container tun data-plane is dead.
- **decrypt keys**: a sslproxy/MITM sidecar (or instrumented runtime) to drop the keylog.
