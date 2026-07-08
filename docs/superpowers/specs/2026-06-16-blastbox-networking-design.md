# blastbox networking — design spec

**Status:** draft (local, uncommitted) · **Date:** 2026-06-16

> Controlled, observable, policy-driven egress for **detonation** engines — a **per-worker**
> network *personality* model (netns + per-backend attachment, no central privileged rooter),
> with TLS capture decrypted by **GoGoRoboCap** (`wmetcalf/GoGoRoboCap`, CAPE's decrypt driver).

> **Routing vs decryption:** the *routing* is blastbox's own per-worker design (below). Only the
> *TLS decryption* pipeline (§7) follows CAPE (GoGoRoboCap, keylog / sslproxy-clean modes).

---

## 1. Purpose & context

blastbox today runs every worker with **no network** (docker `--network=none`, gVisor
`-network=none`, FC vsock-only) — correct for the rasterizers (clippyshot/redtusk) and the
default. **Detonation engines** (the generic `feat(engines)` tool-runner) need *controlled*
egress so a sample's network behaviour can be **observed**: reach a fakenet/tor/VPN/inspected
exit, capture everything, decrypt TLS. The capture/decrypt bundle is sealed into the same
zero-trust envelope as every other artifact.

### Non-goals
- Networking for the rasterizer engines (stay `none`).
- A general SDN / multi-host overlay. One host, per-worker egress.
- A **central privileged rooter** mutating global iptables per job (CAPE's model) — we use
  per-worker netns isolation instead.
- Defeating TLS **cert pinning** (a structural MITM ceiling).
- Line-rate throughput (userspace stacks are fine for detonation).

---

## 2. Core model

**Per-worker transparent L3 egress.** The detonated tool runs in a **network namespace** whose
*only* route out is a TUN/tunnel. Everything it emits (TCP/UDP/ICMP/raw-IP) is routed
transparently — no in-app proxy config, nothing the sample can opt out of.

A **personality** is a named **chain**: `intercept → [inspect?] → exit-driver`.
- **intercept** — the netns entry (TUN / tunnel / socks listener) traffic enters.
- **inspect** *(optional)* — a TLS-MITM stage (mitmproxy / PolarProxy / sslproxy) spliced in
  for `:80/:443` while the rest is routed around it (in-netns `nftables` split — unprivileged,
  the netns has its own `CAP_NET_ADMIN` via userns).
- **exit-driver** — `direct | socks | wireguard | openvpn | inetsim | drop`.

### 2.1 netns-ownership rule (load-bearing)

> **Exactly one layer owns the egress netns** (the attachment adapter, §5.1). The inner sandbox
> is a **consumer**: `nsjail`/`bwrap` run **net-shared** (no `--unshare_net`) and inherit the
> routed netns; `nono` (Landlock) touches no netns and just adds an in-kernel port clamp.

So routing is uniform across *every* sandbox type — the user-mode inner sandboxes get egress by
consuming a pre-routed netns, never by providing it or holding privilege.

---

## 3. Two tiers (protocol coverage ↔ privilege)

All-IP transparent routing is **first-class**, and it splits the mechanism in two. A
personality's tier is implied by its exit-driver.

| tier | mechanism | protocols | privilege | backends |
|---|---|---|---|---|
| **Unprivileged SOCKS** | `slirp4netns`/`passt` parent-side userspace bridge → `tun2socks` → SOCKS exit | **TCP + UDP** (SOCKS5 UDP-assoc) | **none** | runc · FC · gVisor |
| **Privileged-plumbing all-IP** | tiny helper drops a `wg`/`veth` into the netns → `wireguard`/`openvpn`/direct/inetsim exit | **all IP** (TCP/UDP/ICMP/raw) | `CAP_NET_ADMIN` (per-worker iface plumbing only) | runc · FC |

**Why the split is physics, not choice:** a SOCKS proxy (BrightData, tor) cannot carry
ICMP/raw-IP — TCP+UDP forever. Userspace bridges (passt/slirp) are connection-terminating, not
raw-IP tunnels. So "all IP" *requires* an IP-tunnel exit (wg/openvpn) wired into the netns via a
real interface → `CAP_NET_ADMIN`, on any backend. No fully-unprivileged all-IP path exists.

That `CAP_NET_ADMIN` is confined to a **small per-worker plumbing helper** (`blastbox-netd`,
§5.2) that only creates/moves per-worker interfaces — **not** a central rooter, **no** global
iptables/ip-rule churn.

**gVisor is SOCKS-class only.** Its Sentry is a connection-terminating userspace netstack — it
can never pass ICMP/raw-IP into a tunnel. Per "drop incapable backends," gVisor gets SOCKS-class
personalities (its netstack → host-side socks/forwarder does the chain) and is
**fail-closed-excluded from all-IP**.

---

## 4. Three network zones

```
 ZONE 1 untrusted (per worker)     ZONE 2 trusted service-net (bb-svc0)        ZONE 3
  worker netns                      ┌ mitmproxy/PolarProxy(inspect) ┐           real
   └ TUN/tunnel ─transparent L3─▶ entry┤                            ├─▶ wg/openvpn ─▶ uplink
     all IP, ONLY route out             └ tor · inetsim · brightdata-conn ┘
     can't address sidecars             servers chain over bb-svc0; sample never on it
```

- **Zone 1 — sample:** confined to its netns; only path out is the tunnel to the chain entry.
  Cannot address the service-net or other workers laterally.
- **Zone 2 — sidecar service-net `bb-svc0`:** personality servers live + interconnect to form
  chains (`inspect → exit`, `tun2socks → mitm → brightdata`, `mitm → wg → PIA`). Operator-
  trusted, isolated from samples (worker reaches only the entry port). Shared sidecars (one
  mitm/tor) serve many workers; the per-worker funnel keeps traffic attributable for capture.
- **Zone 3 — uplink:** the last stage's real connectivity (host internet / VPN / tor / BrightData).

---

## 5. Components

### 5.1 Attachment adapter (per-backend)
Owns the egress netns and hands the tool a routed network + (for all-IP) a stable iface. The
only backend-specific piece.

| backend | attachment | all-IP? |
|---|---|---|
| docker **runc** | netns + `passt`/`tun2socks` (SOCKS) or `wg`/`veth` (all-IP) | ✅ |
| **FC** microVM | virtio-net guest NIC + host TAP; full chain runnable **in-guest** | ✅ (most capable) |
| docker **runsc** / **gVisor C/R** | Sentry netstack `-network=sandbox` → host-side socks/forwarder | ❌ SOCKS-only |
| inner **nsjail/bwrap** | net-shared consumer of the worker netns | inherits |

### 5.2 `blastbox-netd` (per-worker privileged plumbing helper)
Small, single-purpose, `CAP_NET_ADMIN`, separate from the Docker-socket dispatcher. API:
`attach(worker_id, personality) → src_handle` / `detach(worker_id)`. Creates/moves per-worker
interfaces (`wg`/`veth`) into the worker netns and joins the chain entry. **Does not** mutate
global iptables. Only invoked for the **all-IP tier**; the SOCKS tier needs no privileged helper.

### 5.3 Personality registry
Named personalities → chain spec `{intercept, inspect?, exit_driver, exit_config, dns}`.
- **Shipped sidecars:** `none` (no attach), `drop`, `fakenet` (inetsim), `tor`, `inspect`
  (mitmproxy / PolarProxy / sslproxy).
- **BYO (operator creds/config):** `vpn` (WireGuard conf / OpenVPN `tun0`), `socks` (BrightData /
  upstream SOCKS endpoint + auth).
- bypass/block domain lists per inspect personality.

### 5.4 Policy resolver (§6). 5.5 Sidecar service-net `bb-svc0` + sidecars (stood up once at
deploy, not per job). 5.6 Capture/decrypt pipeline (§7).

---

## 6. Policy & config model

Mirrors blastbox's per-engine env patterns (`_PARAM_KEYS`, `_DEFAULT_PARAMS`,
`ALLOW_TIER_ROUTING`). **Safe-by-default:** egress is `none` unless an operator opts in.

| knob | meaning |
|---|---|
| `BLASTBOX_NETPOLICY_<NAME>` | operator declares a personality (chain spec / sidecar refs / exit config / dns) |
| `BLASTBOX_ENGINE_<NAME>_NETPOLICY` | per-engine **default** (ships `none`; runtime-flip like `DEFAULT_PARAMS`) |
| `BLASTBOX_ALLOW_NETPOLICY_OVERRIDE` | gate (default **off**) — only then may a job choose |
| job param `net_policy` | per-job selection, honored only when gated **and** in the declared set (default-deny) |

Resolution: job override (if gated+allowlisted) → engine default → `none`. **Fail-closed:**
unknown/incapable personality (all-IP under gVisor), or any attachment/wiring failure → `none`.

---

## 7. Capture & TLS observability  *(this pipeline follows CAPE)*

Per-job, **sealed into the envelope** (host re-seals + size-caps, same zero-trust path). CAPE
model: capture raw, decrypt as post-processing.

- `dump.pcap` — per-job capture (tcpdump on the worker iface / chain entry / per-worker funnel).
- `tls-keys.keylog` — union of: **browser/client `SSLKEYLOGFILE`** (cooperative clients:
  browsers, curl, doc engines fetching over TLS) + **mitm/PolarProxy master secrets**
  (`master_keys.log`, uncooperative C2) + `tlsdump.log`.
- `mitm-ca.pem` — the inspect CA, **exported** and **injected** into the sandbox trust stores:
  system bundle (`/etc/ssl/certs`), **browser NSS db** (`cert9.db`, Firefox/Chromium — "for
  browsers"), Java `cacerts`, language runtimes (`NODE_EXTRA_CA_CERTS`, certifi, `CURL_CA_BUNDLE`).
- `dump_decrypted.pcap` + `dump_mixed.pcap` — produced by **GoGoRoboCap**
  (`wmetcalf/GoGoRoboCap`, `gogorobocap-linux-amd64`). Two auto-detected modes (CAPE
  `decryptpcap` parity):
  - **sslproxy-synthetic:** `--sslproxy-clean` strips the prepended TLS ClientHello from
    `sslproxy.pcap`, merges with the original → `dump_mixed.pcap`.
  - **keylog:** `-keylog <secrets> -tlsmode decrypted|mixed` on `dump.pcap`; keys =
    `SSLKEYLOGFILE` ∪ `tlsdump.log` ∪ sslproxy `master_keys.log`, or an embedded PcapNG
    Decryption-Secrets-Block.
  Downstream prefers `mixed → decrypted → original` (CAPE `resolve_processing_pcap_path`).
- `flows.json` *(optional)* — mitm decrypted flows. GoGoRoboCap also ingests mitm **HAR/SAZ**
  exports → pcap (`-i` HAR/SAZ, `-split`, `-http11`, `-resolve`, `-deproxy`).

**Ceiling:** cert-pinned clients detect the MITM CA and refuse — captured-but-encrypted is the
fallback (same as CAPE/PolarProxy).

---

## 8. Per-backend capability matrix

| backend | SOCKS personalities | all-IP personalities | nono clamp |
|---|---|---|---|
| docker **runc** | ✅ | ✅ (wg/veth + netns) | ✅ kernel |
| **FC** guest | ✅ | ✅ (most capable; chain in-guest) | ✅ kernel (in-guest) |
| docker **runsc** / **gVisor C/R** | ✅ (Sentry → host socks) | ❌ structural → fail-closed | ❌ Sentry ENOSYS → host-iptables |
| inner **nsjail/bwrap** | inherits | inherits | nono nests |

---

## 9. Security model
- **Default fail-closed:** `none` unless opted in; any failure → `none`.
- **Zone isolation:** untrusted sample confined to its netns + the chain entry; cannot reach
  `bb-svc0` laterally or other workers' traffic.
- **Privilege containment:** `CAP_NET_ADMIN` only in `blastbox-netd` (per-worker iface plumbing),
  separate from the Docker-socket dispatcher; no global iptables mutation.
- **nono clamp:** in-kernel port allow/deny on runc/FC; host-iptables equivalent under gVisor.
- **Teardown guarantee:** every per-worker iface/route removed on finish (no leaked state) —
  enforced + tested (§11).
- **Capture trust:** capture output is untrusted worker output — re-sealed + size-capped like
  every artifact, never served raw.

---

## 10. Data flow
```
claim job
  → resolve personality (job override? gated+allowlisted → else engine default → none)
  → capability-gate (all-IP under gVisor? → fail-closed none)
  → attachment adapter: create/own egress netns
  → [all-IP tier] blastbox-netd.attach(): wire wg/veth into netns + join chain entry
  → [SOCKS tier]  passt/slirp + tun2socks → chain entry (unprivileged)
  → nono clamp (runc/FC) innermost; inner sandbox runs net-shared
  → start capture (tcpdump) + set SSLKEYLOGFILE env
  → DETONATE
  → stop capture
  → blastbox-netd.detach() / teardown netns + ifaces  (guaranteed)
  → GoGoRoboCap: dump.pcap + keys → dump_decrypted.pcap / dump_mixed.pcap (+ flows)
  → seal capture bundle + mitm-ca.pem into the envelope (host re-seal + size-cap)
```

---

## 11. Testing
- **Unit:** policy resolver (gate/allowlist/default/fail-closed); chain-spec parse; capability
  gate (all-IP×gVisor → none); env-knob shape.
- **Integration (per-backend):** `none` = no packets; `fakenet` = inetsim reached; `direct/wg` =
  all-IP incl **ICMP**; `tor/socks` = TCP+UDP at the proxy; gVisor all-IP request → fail-closed.
- **Security:** zone isolation; fail-closed on attach failure; **no-leak teardown** (no residual
  ifaces/routes after N jobs); capture goes through seal/size-cap.
- **Capture/decrypt:** pcap non-empty + attributable; `dump_decrypted.pcap` decrypts MITM'd TLS;
  CA present in NSS/system stores in-sandbox; GoGoRoboCap keylog + sslproxy-clean modes.

---

## 12. Phasing (build order; target = all of it)
1. **Skeleton + SOCKS tier on runc:** attachment adapter, personality registry, policy resolver
   + gate, `none/drop/direct/fakenet/tor` via passt+tun2socks, per-job tcpdump capture, seal.
2. **All-IP tier on runc:** `blastbox-netd` plumbing helper, `wg`/`openvpn` exits, ICMP/raw.
3. **Inspect + decrypt:** mitmproxy/PolarProxy/sslproxy sidecar, in-netns 80/443 split, CA inject
   (incl **NSS**), SSLKEYLOGFILE, **GoGoRoboCap** decrypt (keylog + sslproxy-clean), `flows.json`.
4. **gVisor (SOCKS-class)** + **FC (TAP + in-guest chain, all-IP)**.
5. **Polish:** BrightData connector, VPN conf ingestion, bypass/block lists, warm-tier wiring.

---

## 13. Open items
- FC TAP + virtio-net guest-NIC bring-up (rootfs net config, per-slot TAP).
- gVisor Sentry host-egress → host-side SOCKS/forwarder wiring details.
- Warm-tier per-job personality reconfig (set chain endpoint at restore vs pool-per-personality
  via `target_tier`).
- Cert-pinning policy (record-encrypted vs per-personality bypass list).
- nono network *allowlist* (Landlock ABI v4 port rules) vs current `--block-net`.
- GoGoRoboCap binary provisioning into the host/processing image (`gogorobocap-linux-amd64`).
