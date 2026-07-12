# Blastbox sandboxing landscape + warm-snapshot service tier (reference)

> Status: LOCAL/untracked (no-draft-commit rule). Companion to
> `2026-06-17-sandbox-networking-seams.md` (inner-sandbox × netns × rooter detail). This doc is
> the BOUNDARY spectrum + the snapshot-service tier + Windows workers + a "where we are" inventory.
> Captured from the 2026-06-17 design thread.

## 1. The boundary spectrum (what *runs* the worker)

### Linux
| tier | isolation | speed | networking | built in blastbox? |
|---|---|---|---|---|
| **docker + runc** | shared kernel (ns+seccomp+caps) | fastest | bridge/veth → rooter | yes (opt-in, BLASTBOX_ALLOW_RUNC; refused by default) |
| **docker + gVisor (runsc)** | userspace kernel (Sentry) | fast | bridge/veth → rooter (host-side); Landlock=ENOSYS | **yes — DEFAULT** |
| **Kata** | VM-isolated container (separate kernel) | medium | TAP → rooter | NO (toolz2 docker exposes `kata`; cheap win if we want VM-grade via the docker path) |
| **Firecracker microVM** | KVM microVM, Linux guest, fast boot | medium | TAP → rooter | yes (warm-snapshot tier) |
| **QEMU/KVM** | full KVM VM, any guest incl Windows, snapshots | slow boot | TAP → rooter (canonical, CAPE-style) | NO (the "full-OS / CAPE" tier) |

### Windows (all need a Windows kernel ⇒ a Windows host OR a QEMU/KVM Windows guest on Linux)
| tier | isolation | nested virt? | fits |
|---|---|---|---|
| **AppContainer / LPAC** | in-kernel default-deny capability sandbox (lowbox token) | **NO** (native speed) | the **validation/lookup** tier — Chromium-renderer-grade vs userland; shared-kernel (kernel 0-day escapes); lock down win32k for headless |
| process-isolated Win container | shared guest kernel | no | light, server SKU |
| **Hyper-V-isolated container / Windows Sandbox** | per-workload Utility VM | **YES** (when Windows is a guest) | per-process VM isolation *inside* Windows |
| Hyper-V / QEMU-KVM Windows VM | full VM | n/a (it IS the VM) | the detonation chamber |

**Key Windows insight:** AppContainer = no nesting, native speed, real (capability default-deny, what
Edge/Chrome use) but shared-kernel. **One disposable Windows guest per sample (clone-from-snapshot)
gives VM isolation with NO nested Hyper-V** — the L1 KVM guest *is* the boundary; nested Hyper-V is
only for multiplexing many untrusted samples in one long-lived guest (avoidable). Nested-virt is
real + ENABLED on toolz2 (bare metal, Intel vmx+ept, `kvm_intel nested=Y`) but the Xeon E5-2680 is
Sandy Bridge (2012, no VMCS-shadowing → nested Hyper-V slow); fine to prove out, want newer silicon
for a fleet. Don't double-nest (bare-metal host only).

## 2. Inner sandbox layer — see the seams doc
nsjail/bwrap/container/nono in `blastbox.worker.sandbox`. `net_egress` (shipped b0ec088): bwrap
`--share-net` / nsjail `--disable_clone_newnet` when granted, else isolate; **nono always
`--block-net` (invariant); container rides the outer netns.** Rasterizers (ClippyShot/RedTusk) stay
sealed at the LO/UNO config — egress is detonation-engine-only.

## 3. Networking — see the netpolicy/rooter docs
Tiers none/drop/direct/fakenet/socks/vpn + capture (netd) + decrypt (GoGoRoboCap). **Host-side
rooter** (`ip rule from <worker-ip> table <tier>`) is the universal router — works for gVisor too.
Per-engine default + gated per-job override, fail-closed to none.

## 4. Warm-snapshot SERVICE tier (NEW — generalizes the cert-store + static-list ideas)
A **golden** holds expensive/perishable state, updates it with **controlled (allowlisted) egress**,
gets **health-gated**, is **snapshotted (running/memory+disk) on a cadence**; workers **restore +
run N tasks + recycle**. Five knobs:
1. **snapshot source + its egress allowlist** — the ONE place with (scoped) egress; workers sealed.
2. **refresh cadence** — when to re-snapshot (split light cert/list rolls from heavy patch/reboot rolls).
3. **tasks-per-restore `N`** — the isolation↔throughput dial: N=1 detonation; N=large benign lookup
   (recycle = leak-guard + list-refresh, not isolation). Per-engine-class config.
4. **promotion health-gate** — uptime + service health + **positive AND negative canary** (a
   known-revoked/bad input MUST come back bad — broken cert stores fail *open*) + state-actually-
   advanced check. All green → promote (blue/green for the golden); else keep old + alert.
5. **version provenance** — stamp snapshot/patch/cert/list version into EVERY result (rolling
   updates break reproducibility; retain a window of snapshots for exact re-runs).

Worked examples:
- **Cert-current Windows detonation** (N=1): golden = Windows guest, egress allowlisted to WU +
  `ctldl.windowsupdate.com` + Defender; detonation clones run sealed/fakenet; verdict stamped with
  patch+cert-store timestamp.
- **Static-list lookup** (N=large): golden loads a big list (blocklist/reputation/YARA), egress to
  the list source; lookup workers run thousands of benign checks per restore, recycle on list roll.

Snapshots earn their keep when warmup is expensive AND you scale AND want atomic versioned rolls
AND/OR clean recycle — else a plain reload may do.

## 5. WHERE WE ARE — sandboxing inventory
**BUILT + validated:** inner sandbox (nsjail/bwrap/container/nono) + net_egress + nono-invariant;
worker boundaries docker+runc/+gVisor + Firecracker; netpolicy tiers P1-P5 (fakenet, capture,
socks, vpn-mechanism, decrypt) live on toolz2; host-side rooter proven for gVisor; FC + gVisor-C/R
warm-snapshot tiers.
**DESIGNED, not built:** warm-snapshot SERVICE tier (this doc); Windows workers; QEMU/KVM tier;
the rooter as the *primary* (host-side `ip rule` + anti-spoof) vs the per-netns nsenter we shipped.
**GAPS / TODO:** Kata wire-up (cheap VM-grade via docker); QEMU/KVM tier (full-OS); Windows
worker(s) (AppContainer validator + optional Hyper-V/QEMU detonation); FC TAP for FC egress; PIA
data-plane host-side (container tun is dead); decrypt key-acquisition sidecar (sslproxy/MITM);
nested-nono-follows-net_egress decorator (when a nested nono lands in blastbox); anti-spoof for the
rooter; net_egress producer wired (dispatcher sets BLASTBOX_NET_EGRESS — DONE).
**FIRST EGRESS CONSUMER — BUILT + validated through fakenet (commit e857334):**
`blastbox.engines.urlgrab.UrlGrabEngine` — fetch one URL, seal body+structured meta (status/final-
url/content-type/sha256); fetch is an injected seam (7 unit tests, no real I/O); dead URL=ok-not-
error, bad URL=rejected, 4xx/5xx=real response. Worker image `blastbox-urlgrab-worker:dev` (FROM
redtusk-cold-worker:0122 + the 0.1.15 wheel + ENV BLASTBOX_ENGINE=blastbox.engines.urlgrab:
UrlGrabEngine + BLASTBOX_DETONATE_NAME=urlgrab). LIVE: runsc worker on bb-fakenet, real corpus URL
hordlepc.com → resolved to FakeNet → fetched → status 200, server FakeNet/1.3, body sealed (safe).
Corpus = 12,442 unique URLs / 3,065 hosts extracted from 10,985 redtusk envelopes →
`~/redtusk-bench/corpus_urls.txt` on toolz2.
**DISPATCHER-INTEGRATED BATCH — DONE + validated 2026-06-17:** urlgrab registered (override:
BLASTBOX_ENGINES adds urlgrab=blastbox-urlgrab-worker:dev, api BLASTBOX_ALLOWED_ENGINES=redtusk,
urlgrab, BLASTBOX_ENGINE_URLGRAB_NETPOLICY=fakenet, NETPOLICY_FAKENET=exit=inetsim,dns=172.28.100.2).
25 random corpus URLs submitted via the API → **all 25 done**; 8 HTTP → FakeNet 200 (body sealed),
17 HTTPS → TLS handshake REJECTED (worker doesn't trust FakeNet's MITM CA → fetch_failed/status=ok,
NOT job failure — correct); 23/25 netd pcaps sealed. Full chain proven through the product: API →
netpolicy(fakenet) → gVisor-DNS-fix → fetch → FakeNet → netd capture → seal → serve.
**HTTPS THROUGH FAKENET — DONE 2026-06-17 (commits d7ec304 + 2663b85):** urlgrab `verify_tls`
knob (default ON; BLASTBOX_URLGRAB_VERIFY_TLS=0) — in off mode also relaxes TLS (DEFAULT@SECLEVEL=0
+ TLSv1 + OP_LEGACY_SERVER_CONNECT) since modern OpenSSL3 rejects weak/MITM certs at the HANDSHAKE
(before cert check), not just verification. PLUS a FAKENET IMAGE FIX: pin **pyOpenSSL<23**
(+cryptography<40) — pyOpenSSL 23 removed `X509Extension`, crashing FakeNet's on-the-fly SNI cert
gen → HTTPS listener dead. After both: HTTPS corpus batch **15/15 fetched FakeNet** (was 0/15),
MITM'd, body sealed, tls_verified=False. urlgrab worker image set BLASTBOX_URLGRAB_VERIFY_TLS=0.
**FAKENET CA IN WORKER TRUST STORE — DONE 2026-06-17:** stable `blastbox FakeNet CA` generated +
baked into the FakeNet image (`configs/fakenet_ca.crt`+`.key`, static_ca:Yes → FakeNet signs MITM
certs with it, verified issuer); CA injected into the urlgrab worker store (update-ca-certificates
+ SSL_CERT_FILE) + BLASTBOX_URLGRAB_VERIFY_TLS=1 → HTTPS batch **15/15 fetched, tls_verified=True**
(validates the MITM cert incl hostname/SAN — cleaner than skip-verify). Proves the CA-injection
mechanism the sslproxy/inspect tier reuses. (Did baked-image; the REUSABLE form = per-personality
dispatcher CA injection, built with the inspect tier.)
**INSPECT/SSLPROXY DECRYPT TIER — END-TO-END PROVEN 2026-06-17 (both decrypt paths).**
- Sidecar `blastbox-sslproxy:dev` (FROM ubuntu:24.04 — CAPE glibc 2.38; libnet1/libpcap/libsqlite3/
  libevent*) running CAPE's binary `/usr/local/bin/sslproxy` = **SSLproxy v0.9.10 GIT (dev branch)**
  pulled from cape@172.18.101.17 (`~/redtusk-bench/sslproxy-build/`). Only the **dev** branch
  works with Will's pipeline (the -M master-key export). Stable `blastbox sslproxy CA` generated.
- WORKING gateway recipe (REDIRECT/netfilter, NOT tproxy — simpler, no policy routing):
  entrypoint `iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8443` +
  `sslproxy -D -k ca.key -c ca.crt -l connections.log -X /logs/capture.pcap -M /logs/master_keys.log
  -P -e netfilter ssl 0.0.0.0 8443`. THREE startup bugs fixed vs first attempt: (a) `-D` takes NO
  arg (had `-D 1` → sslproxy parsed `1` as a proxyspec type → "Unknown connection type '1'");
  (b) engine is `netfilter` (REDIRECT/SO_ORIGINAL_DST), NOT `nat` (only `netfilter`+`tproxy` exist,
  see `sslproxy -E`); (c) `-X` wants a FILE not a dir. proxyspec `ssl 0.0.0.0 8443` with NO `up:`
  = SSLsplit-style split mode (transparent MITM→original dst), exactly what we want.
- KEY GOTCHA — **passthrough fail**: with `-P`, sslproxy passes-through (no split, empty keylog)
  if it can't verify the UPSTREAM cert. sslproxy uses the SYSTEM trust store for upstream verify
  (that's why CAPE works vs real public CAs). FIX = bake the upstream-side CA into the sslproxy
  image trust store (`COPY fakenet_ca.crt /usr/local/share/ca-certificates/ && update-ca-certificates`).
  After that: connections.log shows `CONN: ssl ...` (split, not passthrough), leaf forged + signed
  by `blastbox sslproxy CA`, keylog populated. (Also: never `rm` the live logs — sslproxy holds the
  FD, writes go to the unlinked inode; restart the gw to roll logs.)
- TOPOLOGY proven: client on bb-inspect (172.32.0.0/16), default route → gateway bb-sslproxy-gw
  (172.32.0.10, dual-homed onto bb-fakenet), DNS/dst → FakeNet 172.28.100.2:443. Route set via
  `nsenter -t <pid> -n ip route replace default via 172.32.0.10` (the rooter does this in prod).
- **PROOF 1 (sslproxy-as-decryptor, the CAPE pipeline):** `gogorobocap -pcap -i capture.pcap
  -keylog master_keys.log -sslproxy-clean -tlsmode decrypted -o decrypted.pcap` → recovered
  plaintext `GET / HTTP/1.1` + `GET /evil.exe` + FakeNet `HTTP/1.0 200 OK` + HTML body.
- **PROOF 2 (independent, -M keylog decrypts a RAW encrypted wire capture):** tcpdump'd the
  genuinely-encrypted client↔sslproxy leg (`secret-c2-beacon` URL absent in plaintext, grep -c 0),
  then `gogorobocap -pcap -i raw_client.pcap -keylog master_keys.log -tlsmode decrypted` (NO
  -sslproxy-clean) → "detected 1 TLS flows, replayed 1 decrypted flows" → recovered `GET
  /secret-c2-beacon HTTP/1.1`. Proves the master-key export itself decrypts TLS 1.3, independent
  of sslproxy's synthetic pcap. `gogorobocap` binary @ `~/netd-run/gogorobocap` on toolz2.
- **PROOF 3 (the PRODUCT engine, validated TLS — not curl, not skip-verify):** built
  `blastbox-urlgrab-inspect:dev` = urlgrab worker + the sslproxy CA in its trust store (VERIFY_TLS=1).
  Routed it on bb-inspect through the gateway (`--add-host fakenet.flare:172.28.100.2`; sslproxy
  forges the leaf with the UPSTREAM cert CN = `fakenet.flare`, so the worker must fetch THAT host to
  pass hostname validation). Ran the real `blastbox.engines.urlgrab` module → envelope `status=ok,
  fetched=true, status=200, server=FakeNet/1.3, tls_verified=TRUE` (worker VALIDATED the MITM leaf:
  trusts sslproxy CA + CN matches), body sealed (32768 B). Gateway log: `CONN: ssl 172.32.0.3 …
  sni:fakenet.flare … usedcrt:5F90…` (split, forged leaf). GoGoRoboCap decrypt → recovered the
  engine's own request `GET /malware-config.bin HTTP/1.1 / Host: fakenet.flare` + FakeNet 200.
- **PRODUCTIZED in committed code (blastbox commit 8c4ecdb, feat/netpolicy-phase1, 1174 green):**
  the `inspect` wire mode end-to-end through the pure routing path — netwire (`inspect` wire-mode
  allowlist), netapply (`personality.inspect`+egress → rides `bb-inspect`, fail-closed otherwise),
  netd (`inspect_gateway_ip` + `_wire_inspect` reusing gateway_route_commands + `--inspect-gateway`/
  BLASTBOX_NETD_INSPECT_GATEWAY), dispatch (`blastbox.net.wire=inspect`, wins over socks/vpn). The
  policy core already modeled `Personality.inspect` (parsed from `inspect=1` in the decl).
- **DISPATCHER-DRIVEN BATCH — PROVEN end-to-end through the real product 2026-06-17.** Stood up a
  fully ISOLATED stack (own Postgres `bb-inspect-pg` + own socket-proxy + own `blastbox serve` API on
  :8009 + a runc inspect dispatcher, on net `bb-inspect-stack`) so the runc worker provably only ever
  sees benign urlgrab-corpus jobs — never a production/malware job (this is the answer to "runc on the
  shared queue is unsafe": isolate the queue). Flow validated: API → dispatcher resolves
  personality=inspect → labels net.wire=inspect + net.capture=1 → netapply `bb-inspect` → runc worker
  → netd `_wire_inspect` (route→gw) + capture (by IP) + keylog snapshot → `_seal_decrypted_capture`
  runs GoGoRoboCap → envelope sealed with body + network.capture.pcap + .decrypted.pcap + .mixed.pcap.
  Single job: `tls_verified=True`, decrypted to `GET /gate.php`. Real-corpus batch: **6/6** fetched,
  tls_verified, AND decrypted-sealed (usrfiles.com → `GET /ugd/...txt` recovered in plaintext).
- **CONCURRENCY RACES found + FIXED (blastbox commit c2b173a, 1181 green).** The first batch was 2/6
  — the nsenter wire-on-start model races a fast one-shot worker (and latently affects socks/vpn):
  (1) worker fetched before netd wired the route → "Temporary failure in name resolution"; (2) netd's
  keylog snapshot (on die) raced the dispatcher's seal → decrypt skipped. Fixes: harness
  egress-readiness BARRIER (BLASTBOX_NET_WAIT_GATEWAY → block on /proc/net/route until default-via-gw,
  netd's wiring signal; dispatcher forwards the personality's `gateway=`) + dispatcher
  `_seal_decrypted_capture` briefly polls for the keylog (BLASTBOX_NET_DECRYPT_KEYLOG_WAIT_S). After:
  6/6. (The race-free alternative remains the host-side rooter, which pre-installs routing BEFORE the
  worker starts — still the intended primary model; the barrier makes the nsenter model robust today.)
- Worker CA trust = bake the stable inspect CA into the worker image (same pattern as the FakeNet CA,
  the right production approach for a per-deployment-stable CA — a runtime bind-mount injector would
  add complexity for no gain). Per-job key ATTRIBUTION needs no slicing: netd snapshots the whole
  shared keylog per job; GoGoRoboCap matches keys to the worker's own pcap flows by client_random.
- STILL TODO: PIA/socks real-fetch batch (needs an anonymizing exit — `bb-socks-proxy` egresses from
  the host IP today, so not attribution-safe for live malware fetches).
