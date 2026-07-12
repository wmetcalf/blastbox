# Blastbox networking — multi-phase grind tracker (LOCAL, UNTRACKED)

> Working tracker for "grind through all the tiers in order" (Will, 2026-06-16).
> Branch: `feat/netpolicy-phase1`. Keep local-uncommitted per the no-draft-commits rule.

## Settled architecture
- **Per-worker netns is the foundation, always.** The worker already runs in its own netns
  (docker-created). A privileged host helper (`blastbox-netd`) operates ON that netns; the
  dispatcher stays cap-drop-ALL and only *signals* netd. One layer owns the netns; inner
  sandbox consumes net-shared; nono clamps orthogonally.
- **Capture = host-side on the bridge iface, filtered by the worker's per-job IP** (PROVEN to
  work under runsc — gVisor's userspace netstack means nsenter-in-netns capture won't see
  traffic, but the veth/bridge does). Uniform across runtimes; runc/FC could also do in-netns.
- **gVisor = SOCKS-class only** for richer exits (Sentry terminates connections); runc + FC =
  full incl all-IP. Fail-closed-exclude gVisor from all-IP.
- **DNS injection (DONE, commit d098968):** per-personality `dns=` → resolv.conf bind-mount.
  Reused everywhere: fakenet worker points `dns=` at the fakenet container.

## CAPE inputs (grounded 2026-06-16, cape@172.18.101.17)
- **FakeNet-NG** `/opt/CAPEv2/docker/fakenet-ng/` → staged local `~/redtusk-bench/fakenet-ng/`.
  python:3.11-slim + flare-fakenet-ng, **listen-only (DivertTraffic=No)**, DNS answers every
  query with its own IP, comprehensive listeners (53/80/443/25/21/110/69/6667/445/22/123 +
  C2 1337/4444/8888 + catch-all port 1). TLS-MITM listeners (443/8443/465/990/995) use the
  fakenet CA (→ decrypt phase). No NFQUEUE in listen-only → gVisor-able. Regen CA for blastbox
  (don't reuse CAPE's private key in prod).
- **PIA OpenVPN** `/etc/openvpn/pia/*.ovpn` (dozens of countries) + `pia-cape.conf` → the VPN
  tier exits. routing.conf model: route=vpn0, rooter sets routing (we do per-netns instead).

## Phases (grind in order)
- [~] **P1 — gVisored fakenet on bb-fakenet + capture — CORE PROVEN on toolz2 2026-06-16**
  - DONE: `blastbox-fakenet:dev` built from CAPE's fakenet-ng ctx (`~/redtusk-bench/fakenet-ng/`),
    runs under **runsc** on bb-fakenet at **172.28.100.2** (`docker run -d --name bb-fakenet-ng
    --runtime=runsc --network bb-fakenet --ip 172.28.100.2`). Listen-only → no NFQUEUE → gVisor-OK.
  - DONE: runsc worker on bb-fakenet w/ `dns=172.28.100.2` (the injector) resolves ANY domain →
    172.28.100.2 → HTTP 200 Server:FakeNet/1.3 (served a fake `MZ` PE). fakenet logged the queries.
  - DONE: capture proven — `tcpdump -i br-<bb-fakenet> host 172.28.100.2` → 18-pkt pcap (ARP+DNS
    c2panel.evil.tld+GET /gate.php+200) at `~/redtusk-bench/netcaps/fakenet-detonation-demo.pcap`.
  - TODO P1-rest: regen a blastbox fakenet CA (don't reuse CAPE's key); fakenet as a managed
    compose sidecar; DNAT-all-ports→fakenet in the worker netns (catch-all beyond listed ports);
    set FAKENET decl `dns=172.28.100.2`; productize capture (→ P2).
- [x] **P2 — netd capture helper, productized — DONE + live-validated toolz2 2026-06-16**
  - SHIPPED (3 commits on feat/netpolicy-phase1): `host/capture.py` (pure: bridge-iface map,
    tcpdump argv w/ IP-validated BPF filter, capture-target-from-inspect → HOST-ONLY pcap path),
    `host/netd.py` (CaptureDaemon: docker-events → start/die handlers, injected seams, `python -m
    blastbox.host.netd` entry), dispatcher (`BLASTBOX_NET_CAPTURE` opt-in: labels egress workers
    `blastbox.net.capture=1`; `_seal_network_capture` folds netd's pcap into the envelope as a
    TRUSTED host artifact kind=`network_capture`, best-effort). 20 new tests, 766 host green.
  - LIVE E2E on toolz2: API `direct` job → worker labeled → netd captured (br-ed7fd8287f2a, per-job
    IP) → dispatcher sealed → `GET /v1/jobs/<id>/artifacts/network.capture.pcap` (HTTP 200, served
    hash == sealed hash). Dispatcher stayed cap-drop=ALL; netd (host, setsid, `--job-root
    /home/coz/redtusk-bb-data/jobs`) did the privileged tcpdump. Rich DNS+HTTP capture proven via
    the beaconing fakenet test; rasterizer job pcap = ARP-only (no beacon) but full plumbing proven.
  - TODO: netd as a systemd unit (currently a manual setsid proc); netd in the deployed image.
- [x] **P3 — SOCKS/tor tier — DONE + live-validated toolz2 2026-06-17 (commit f376e95 + e93da06)**
  - netapply `socks`→ INTERNAL `bb-socks` (fail-closed: no egress until netd wires it);
    worker_resolv_conf adds `options use-vc` (DNS over TCP — SOCKS can't carry UDP DNS).
  - netwire.py (pure, 20 tests): socks_proxy_url, tun2socks_argv (loglevel allow-list — 'warning'
    is fatal), tun_setup_commands (addr TUN/up/move default→TUN), socks_resolv_conf, WireTarget.
  - netd `_maybe_wire_socks`: runs tun2socks in the runc worker netns via nsenter, waits for TUN,
    moves default route; teardown on die. Opt-in `--socks-proxy`/`BLASTBOX_NETD_SOCKS_PROXY`.
    gVisor workers (no host pid) skipped — SOCKS-excluded as designed.
  - dispatcher: socks personality → label `blastbox.net.wire=socks`. 793 host tests green.
  - LIVE: tun2socks 2.6.0 extracted from xjasonlyu image (`~/netd-run/tun2socks`); SOCKS5 proxy =
    serjs/go-socks5-proxy dual-homed (bb-socks 172.30.0.10 + bb-net0 egress). runc worker on
    bb-socks, labeled → netd wired it (`wired socks job=socktest1 pid=…`) → worker EXIT_IP =
    199.0.195.197 = proxy egress IP, HTTP 200. Fail-closed pre-check: no egress before wiring.
    netd runs as systemd unit `blastbox-netd` (--socks-proxy socks5://bb:bb@172.30.0.10:1080).
- [~] **P4 — all-IP/VPN tier — MECHANISM DONE + validated; PIA data-path pending (commit bd7b951)**
  - netapply openvpn/wireguard → INTERNAL bb-vpn; netwire.gateway_route_commands; netd `_wire_vpn`
    (default route → gateway sidecar, no in-netns TUN); dispatcher labels wire=vpn. 799 tests green.
  - LIVE-VALIDATED with a NAT gateway sidecar (alpine, MASQUERADE, dual-homed bb-vpn 172.31.0.10 +
    bb-net0): netd wired runc worker (`wired vpn job=vpntest1 -> gateway 172.31.0.10`) → **UDP DNS
    resolved + HTTP 200** (all-IP — SOCKS needed use-vc, VPN doesn't). netd runs --vpn-gateway 172.31.0.10.
  - OpenVPN-PIA gateway (`blastbox-vpn-gw:dev`, `~/redtusk-bench/pia-gw/`, PIA creds/ca/crl from
    CAPE): **DEBIAN base required** (alpine/musl OpenSSL → "unknown CA"; CAPE uses Ubuntu OpenSSL).
    Control channel CONNECTS (tun0 up, Init Completed) but **data path doesn't forward** (gateway's
    own egress via tun0 fails; disable-dco didn't fix). CAPE's working config uses `route-nopull` +
    manual routing, NOT redirect-gateway — that's the PIA-specific tuning left for the user. The
    netd wiring is identical regardless of gateway internals, so this is a sidecar-config detail.
    NAT gateway restored at 172.31.0.10 so the tier stays demonstrable.
- [x] **P5 — inspect + GoGoRoboCap decrypt — DONE + validated toolz2 2026-06-17 (commit 63668a7)**
  - decrypt.py (pure, 9 tests): gogorobocap_keylog_argv (`-i/-keylog/-tlsmode {decrypted|mixed}/-o`)
    + gogorobocap_sslproxy_clean_argv, CLI grounded in CAPE decryptpcap.py. decrypt_capture
    orchestration (seam-injected, both modes, best-effort).
  - dispatcher: opt-in BLASTBOX_NET_DECRYPT — after sealing the raw capture, if a keylog sits in
    the host-only capture dir, run GoGoRoboCap → seal decrypted.pcap (network_capture_decrypted)
    + mixed.pcap. BLASTBOX_GOGOROBOCAP_BIN configures the binary. 810 host tests green.
  - LIVE: GoGoRoboCap binary from CAPE (`/opt/CAPEv2/data/gogorobocap/gogorobocap-linux-amd64` →
    `~/netd-run/gogorobocap`). curl HTTPS + SSLKEYLOGFILE → 5-line TLS1.3 keylog → tcpdump pcap →
    `decrypt_capture` produced decrypted.pcap (1197B, "replayed 1 decrypted flows") + mixed.pcap
    (10202B). Key MATERIAL acquisition (sslproxy MITM / instrumented runtime / fakenet CA writing
    the keylog to the capture dir) is the remaining deployment piece — the decrypt path consumes it.

## Done
- Plans 1-2 (personality→docker --network) + gVisor DNS fix. Live-validated toolz2. 746 tests.
