"""``blastbox-netd`` — the privileged host capture daemon.

netd is the netpolicy analogue of CAPE's separate ``rooter``: a small root helper that runs on
the host (it holds the real docker socket and ``CAP_NET_RAW`` for ``tcpdump``), while the
hardened dispatcher stays ``cap-drop=ALL`` and reaches docker only through the locked-down proxy.
The dispatcher never captures; it merely LABELS an egress worker (``blastbox.net.capture=1`` +
``blastbox.job_id``). netd watches ``docker events`` and, per labeled worker, sniffs that
worker's traffic off the docker bridge into a per-job pcap.

The pure decisions (which iface, which BPF filter, where to write) live in
:mod:`blastbox.host.capture`; this module is the I/O shell: a docker-events loop plus
start/die handlers. The handlers take injected seams (``inspect_fn`` / ``network_iface_fn`` /
``spawn_fn``) so the lifecycle is unit-testable without docker or root.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from blastbox.host.capture import (
    CaptureTarget,
    bridge_iface_for_network,
    capture_target_from_inspect,
    tcpdump_argv,
)
from blastbox.host.netwire import (
    TUN_DEV,
    egress_filter_from_inspect,
    gateway_route_commands,
    leak_guard_rules,
    leak_guard_rules_v6,
    leakguard_from_inspect,
    transproxy_redirect_rules,
    tun2socks_argv,
    tun_setup_commands,
    validate_socks_url,
    wire_target_from_inspect,
)

_log = logging.getLogger("blastbox.host.netd")

# How long to wait for tcpdump to flush + exit after SIGTERM before giving up (the pcap is
# line-buffered via -U, so even a hard miss leaves a usable capture).
_STOP_TIMEOUT_S = 5.0
# How long to wait for tun2socks to create the TUN before configuring routes (tries × interval).
_TUN_WAIT_TRIES = 40
_TUN_WAIT_INTERVAL_S = 0.25
# Name the per-job TLS keylog snapshot takes in the capture dir; the dispatcher's
# _seal_decrypted_capture reads exactly this (alongside dump.pcap) to run GoGoRoboCap.
_SSLKEYS_NAME = "sslkeys.log"
# Probe address used to decide whether the worker netns actually HAS IPv6 egress: `ip -6 route get`
# returns rc 0 iff a route to it exists. If the ip6tables leak guard fails but there's no v6 route,
# the host is v4-only and the failure is harmless; if a v6 route DOES exist, the failure is a real
# leak path → fail closed. (Cloudflare's public v6 resolver — only used as a routing target.)
_V6_PROBE_ADDR = "2606:4700:4700::1111"


def _terminate(proc: Any) -> None:
    """Best-effort terminate a Popen-like handle (None-safe, never raises). Used to avoid orphaning
    a spawned tun2socks when wiring aborts after the spawn."""
    if proc is None:
        return
    try:
        proc.terminate()
    except Exception as exc:  # noqa: BLE001 — teardown is best-effort
        _log.warning("netd: terminate failed: %s", exc)


@dataclass
class _ActiveCapture:
    target: CaptureTarget
    proc: Any  # a Popen-like handle: terminate() / wait(timeout) / poll()


@dataclass
class CaptureDaemon:
    """Event-driven per-job capture lifecycle.

    ``inspect_fn(container_id) -> dict``          : ``docker inspect`` payload for one container.
    ``network_iface_fn() -> Mapping[netid,iface]``: docker NetworkID → host bridge iface.
    ``spawn_fn(argv, pcap_path) -> proc``         : start the capture process (Popen-like).
    """

    job_root: str
    inspect_fn: Callable[[str], Mapping[str, object]]
    network_iface_fn: Callable[[], Mapping[str, str]]
    spawn_fn: Callable[[list[str], str], Any]
    active: dict[str, _ActiveCapture] = field(default_factory=dict)
    # --- netns wiring (P3/P4), all optional: wiring is inert unless an operator configures the
    # exit (socks proxy / vpn gateway) AND provides the nsenter seams. ---
    socks_proxy_url: str | None = None      # socks mode: tun2socks → this SOCKS5 URL
    vpn_gateway_ip: str | None = None       # vpn mode: default route → this gateway sidecar IP
    inspect_gateway_ip: str | None = None   # inspect mode: default route → the sslproxy/MITM gw IP
    # inspect mode: host path to the shared sslproxy gateway's SSLKEYLOGFILE (-M). On an inspect
    # worker's die, netd snapshots it next to that worker's pcap as sslkeys.log, so the dispatcher
    # can decrypt. Per-job attribution is free: GoGoRoboCap matches keys to flows by client_random,
    # so the worker's own pcap + the whole keylog decrypts ONLY that worker's TLS.
    inspect_keylog_path: str | None = None
    # transproxy (CAPE tor): host gateway the worker default-routes through + tor TransPort/DNSPort
    # the host REDIRECTs to. host_run_fn runs iptables in the HOST netns (where tor listens), NOT
    # the worker netns — so it is a SEPARATE seam from nsenter_run_fn. All optional; inert unless set.
    transproxy_gateway: str | None = None
    transproxy_trans_port: int = 9040
    transproxy_dns_port: int = 5353
    host_run_fn: Callable[[list[str]], int] | None = None  # run argv in the host netns → rc
    nsenter_spawn_fn: Callable[[int, list[str]], Any] | None = None  # long-lived in worker netns
    nsenter_run_fn: Callable[[int, list[str]], int] | None = None    # run cmd in netns → rc
    keylog_copy_fn: Callable[[str, str], Any] = shutil.copyfile       # src,dst keylog snapshot seam
    sleep_fn: Callable[[float], None] = time.sleep
    # Lists currently-running worker container ids (for startup/post-reconnect reconciliation). If
    # the docker-events stream dies (daemon restart, transient exit) netd reconnects and replays
    # handle_start over the already-running workers, so a stream gap doesn't silently drop their
    # capture/wiring. None disables reconciliation (unit tests that drive handlers directly).
    list_running_fn: Callable[[], list[str]] | None = None
    wired: dict[str, Any] = field(default_factory=dict)  # container_id → proc-or-None
    inspect_wired: set[str] = field(default_factory=set)  # container_ids wired in inspect mode
    # container_id → worker_ip for transproxy workers (so die can tear down the host REDIRECT rules)
    transproxy_wired: dict[str, str] = field(default_factory=dict)
    leakguarded: set[str] = field(default_factory=set)  # container_ids with an in-netns leak guard
    # container_ids whose REQUIRED leak guard could not be installed → wiring is refused (fail
    # closed: no egress without the guard, so a sample can't leak non-TCP past a TCP-only tier).
    leakguard_failed: set[str] = field(default_factory=set)

    # ------------------------------------------------------------------ handlers
    def handle_start(self, container_id: str) -> None:
        """A container started — capture and/or wire it if labeled. Never raises: a container that
        vanished between the event and the inspect must not kill the daemon."""
        try:
            inspect = self.inspect_fn(container_id)
        except Exception as exc:  # noqa: BLE001 — daemon resilience: log + skip, never crash
            _log.warning("netd: inspect for %s failed: %s", container_id[:12], exc)
            return
        self._maybe_capture(container_id, inspect)
        # Install the non-TCP leak guard BEFORE wiring egress: _maybe_wire installs the worker's
        # only route out, and the worker's egress barrier releases as soon as it observes that
        # route — so if the guard went last there would be a window where the worker is unblocked
        # and egressing while the non-TCP DROP is not yet in place. The guard only appends OUTPUT
        # rules and does not depend on the route existing, so this ordering is strictly safer.
        self._maybe_leakguard(container_id, inspect)
        # The leak guard is a precondition for egress: if a REQUIRED guard could not be installed,
        # refuse to wire the route out — a sample must never get egress without the non-TCP DROP.
        if container_id in self.leakguard_failed:
            _log.warning("netd: leak guard required but failed for %s; refusing to wire egress",
                         container_id[:12])
            return
        self._maybe_wire(container_id, inspect)

    def _maybe_leakguard(self, container_id: str, inspect: Mapping[str, object]) -> None:
        """Install the in-netns non-TCP leak guard for a TCP-only proxy-tier worker (labeled
        ``blastbox.net.leakguard``). Defense-in-depth: even if the internal bridge / tun2socks
        containment failed, the worker's UDP/ICMP/raw cannot leave its netns. Best-effort, never
        crashes the daemon."""
        if self.nsenter_run_fn is None or container_id in self.leakguarded:
            return
        try:
            lg = leakguard_from_inspect(inspect)
        except Exception as exc:  # noqa: BLE001
            _log.warning("netd: leakguard inspect for %s failed: %s", container_id[:12], exc)
            return
        if lg is None:
            return
        pid, allow_udp_dns, drop_non_tcp = lg
        # Optional per-personality egress-hardening knobs (web-only port allowlist + RFC1918/metadata
        # block), carried via labels. A no-op for workers that didn't opt in.
        allowed_ports, block_internal = egress_filter_from_inspect(inspect)
        # The leak guard is a PRECONDITION for wiring: if it can't be installed, handle_start refuses
        # to wire egress (no egress without the guard). The v4 rules are the hard guarantee — any
        # failure fails closed.
        try:
            for rule in leak_guard_rules(
                allow_udp_dns=allow_udp_dns,
                allowed_ports=allowed_ports,
                block_internal=block_internal,
                drop_non_tcp=drop_non_tcp,
            ):
                if self.nsenter_run_fn(pid, rule) != 0:
                    _log.warning("netd: leak-guard rule failed for %s; failing closed", container_id[:12])
                    self.leakguard_failed.add(container_id)
                    return
        except Exception as exc:  # noqa: BLE001
            _log.warning("netd: failed to install leak guard for %s: %s", container_id[:12], exc)
            self.leakguard_failed.add(container_id)
            return
        # IPv6 twin. A v4-only host may lack the ip6tables module — that failure is harmless (no v6 to
        # leak). But if the netns actually HAS a v6 egress route, a failed v6 guard IS a real leak path
        # → fail closed. So on any v6-rule failure, probe for a v6 route and decide.
        if not self._install_v6_guard(pid, container_id):
            self.leakguard_failed.add(container_id)
            return
        self.leakguarded.add(container_id)
        _log.info("netd: leak guard installed (non-TCP DROP v4+v6, udp_dns=%s) for %s",
                  allow_udp_dns, container_id[:12])

    def _install_v6_guard(self, pid: int, container_id: str) -> bool:
        """Install the ip6tables leak guard. Returns True if v6 is safely covered (rules applied, OR
        the netns has no v6 egress so the absence of ip6tables is harmless), False if a v6 leak path
        exists that we could not close (→ caller fails closed)."""
        assert self.nsenter_run_fn is not None
        try:
            for rule in leak_guard_rules_v6():
                if self.nsenter_run_fn(pid, rule) != 0:
                    # v6 guard couldn't install. Treat v6 as present (→ fail closed) if the netns has
                    # ANY usable v6: a routable global address (off-bridge leak) OR link-local (the
                    # all-nodes ff02::1 route exists iff an interface has IPv6 up at all — catches a
                    # bridge with only link-local v6). Only "no v6 whatsoever" is safe to continue v4.
                    v6_present = (
                        self.nsenter_run_fn(pid, ["ip", "-6", "route", "get", _V6_PROBE_ADDR]) == 0
                        or self.nsenter_run_fn(pid, ["ip", "-6", "route", "get", "ff02::1"]) == 0
                    )
                    if v6_present:
                        _log.warning("netd: ip6 leak guard failed AND IPv6 egress present for %s; "
                                     "failing closed", container_id[:12])
                        return False
                    _log.warning("netd: ip6 leak-guard rule failed for %s but no IPv6 egress; "
                                 "continuing v4-only", container_id[:12])
                    return True
        except Exception as exc:  # noqa: BLE001
            _log.warning("netd: ip6 leak guard error for %s: %s; failing closed", container_id[:12], exc)
            return False
        return True

    def _maybe_capture(self, container_id: str, inspect: Mapping[str, object]) -> None:
        if container_id in self.active:
            return  # duplicate start event
        try:
            target = capture_target_from_inspect(
                inspect, job_root=self.job_root, network_iface=self.network_iface_fn()
            )
        except Exception as exc:  # noqa: BLE001
            _log.warning("netd: capture target for %s failed: %s", container_id[:12], exc)
            return
        if target is None:
            return
        try:
            os.makedirs(os.path.dirname(target.pcap_path), exist_ok=True)
            # A retried job reuses its job_id with output/ wiped but capture/ kept, so the prior
            # attempt's pcap + .done sentinel could survive. Clear BOTH before the fresh tcpdump: a
            # stale .done would make the dispatcher copy THIS capture mid-flush; a stale pcap would be
            # sealed as this job's capture if the fresh tcpdump fails to spawn (leaving the old file).
            for stale in (target.pcap_path + ".done", target.pcap_path):
                try:
                    os.unlink(stale)
                except OSError:
                    pass
            proc = self.spawn_fn(
                tcpdump_argv(target.iface, target.worker_ip, target.pcap_path), target.pcap_path
            )
        except Exception as exc:  # noqa: BLE001 — capture is best-effort; the job still runs
            _log.warning("netd: failed to start capture for job %s: %s", target.job_id, exc)
            return
        self.active[container_id] = _ActiveCapture(target=target, proc=proc)
        _log.info(
            "netd: capturing job=%s iface=%s ip=%s -> %s",
            target.job_id, target.iface, target.worker_ip, target.pcap_path,
        )

    def _maybe_wire(self, container_id: str, inspect: Mapping[str, object]) -> None:
        """Wire a worker's netns for its exit. Dispatches on the wire mode (socks → tun2socks;
        vpn → default route via a gateway sidecar). Inert unless the matching exit + nsenter seams
        are configured. Best-effort — a failure leaves the worker on its internal (no-egress)
        bridge, i.e. fail-closed, and never crashes the daemon."""
        if self.nsenter_run_fn is None or container_id in self.wired:
            return
        try:
            wt = wire_target_from_inspect(inspect)
        except Exception as exc:  # noqa: BLE001
            _log.warning("netd: wire target for %s failed: %s", container_id[:12], exc)
            return
        if wt is None:
            return
        if wt.mode == "socks":
            self._wire_socks(container_id, wt)
        elif wt.mode == "vpn":
            self._wire_vpn(container_id, wt)
        elif wt.mode == "inspect":
            self._wire_inspect(container_id, wt)
        elif wt.mode == "transproxy":
            self._wire_transproxy(container_id, wt)

    def _wire_socks(self, container_id: str, wt: Any) -> None:
        # Per-worker SOCKS endpoint (the personality's proxy=, e.g. a specific country tor exit)
        # wins over netd's global --socks-proxy, so one netd serves a whole fleet of socks backends.
        proxy_url = getattr(wt, "socks_proxy", "") or self.socks_proxy_url
        if not proxy_url or self.nsenter_spawn_fn is None or self.nsenter_run_fn is None:
            return
        # Validate the (operator-supplied) URL through the same endpoint/cred checks as netd's CLI
        # default — a per-worker proxy label otherwise reaches tun2socks unvalidated. Fail closed
        # on a malformed URL: refuse to wire ⇒ the worker stays on its no-egress internal bridge.
        try:
            proxy_url = validate_socks_url(proxy_url)
        except ValueError as exc:
            _log.warning("netd: invalid socks proxy url for job %s (%s); refusing to wire",
                         wt.job_id, exc)
            return
        proc = None
        try:
            proc = self.nsenter_spawn_fn(wt.pid, tun2socks_argv(proxy_url))
            # tun2socks creates the TUN asynchronously; wait for it before configuring routes.
            ready = False
            for _ in range(_TUN_WAIT_TRIES):
                if self.nsenter_run_fn(wt.pid, ["ip", "link", "show", TUN_DEV]) == 0:
                    ready = True
                    break
                self.sleep_fn(_TUN_WAIT_INTERVAL_S)
            if not ready:
                _log.warning("netd: tun2socks TUN never appeared for job %s; aborting wire", wt.job_id)
                _terminate(proc)
                return
            # Check each route command: a silently-ignored failure leaves the worker half-wired
            # (no default route → no egress) yet recorded as wired. Fail closed: kill tun2socks.
            for cmd in tun_setup_commands():
                if self.nsenter_run_fn(wt.pid, cmd) != 0:
                    _log.warning("netd: socks route cmd %s failed for job %s; aborting wire",
                                 cmd, wt.job_id)
                    _terminate(proc)
                    return
        except Exception as exc:  # noqa: BLE001
            _log.warning("netd: failed to wire socks for job %s: %s", wt.job_id, exc)
            _terminate(proc)  # don't orphan tun2socks if setup raised after the spawn
            return
        self.wired[container_id] = proc
        _log.info("netd: wired socks job=%s pid=%s -> %s", wt.job_id, wt.pid, proxy_url)

    def _wire_vpn(self, container_id: str, wt: Any) -> None:
        """VPN tier: point the worker's default route at the VPN+NAT gateway sidecar. No in-netns
        TUN/proc — the gateway owns the tunnel; the route dies with the netns, so nothing to tear
        down (we still record the wire so a duplicate start event is a no-op)."""
        if not self.vpn_gateway_ip or self.nsenter_run_fn is None:
            return
        try:
            for cmd in gateway_route_commands(self.vpn_gateway_ip):
                rc = self.nsenter_run_fn(wt.pid, cmd)
                if rc != 0:
                    _log.warning("netd: vpn route cmd failed (rc=%s) for job %s", rc, wt.job_id)
                    return
        except Exception as exc:  # noqa: BLE001
            _log.warning("netd: failed to wire vpn for job %s: %s", wt.job_id, exc)
            return
        self.wired[container_id] = None  # route-only; nothing to terminate on die
        _log.info("netd: wired vpn job=%s pid=%s -> gateway %s", wt.job_id, wt.pid, self.vpn_gateway_ip)

    def _wire_inspect(self, container_id: str, wt: Any) -> None:
        """Inspect tier: point the worker's default route at the sslproxy/MITM gateway sidecar
        (which transparently REDIRECTs :443 → its sslproxy, forges certs with the inspect CA the
        worker trusts, exports TLS master keys for decrypt, and forwards to the real exit). Same
        route-only mechanism as the VPN tier — the gateway owns the interception; the route dies
        with the netns. Inert unless an operator configured the gateway IP."""
        if not self.inspect_gateway_ip or self.nsenter_run_fn is None:
            return
        try:
            for cmd in gateway_route_commands(self.inspect_gateway_ip):
                rc = self.nsenter_run_fn(wt.pid, cmd)
                if rc != 0:
                    _log.warning("netd: inspect route cmd failed (rc=%s) for job %s", rc, wt.job_id)
                    return
        except Exception as exc:  # noqa: BLE001
            _log.warning("netd: failed to wire inspect for job %s: %s", wt.job_id, exc)
            return
        self.wired[container_id] = None  # route-only; nothing to terminate on die
        self.inspect_wired.add(container_id)  # mark for keylog snapshot on die
        _log.info("netd: wired inspect job=%s pid=%s -> gateway %s",
                  wt.job_id, wt.pid, self.inspect_gateway_ip)

    def _wire_transproxy(self, container_id: str, wt: Any) -> None:
        """CAPE's tor recipe: point the worker's default route at the host bridge gateway, then
        install HOST-netns iptables REDIRECTs (keyed on the worker IP) sending its TCP → tor
        TransPort and DNS → tor DNSPort, dropping everything else. tor runs on the host so its
        TransPort can read SO_ORIGINAL_DST. Inert unless the gateway + host_run seam are configured.
        Best-effort: a partial failure tears its own rules back down (fail-closed: no egress)."""
        if (not self.transproxy_gateway or self.host_run_fn is None
                or self.nsenter_run_fn is None or not wt.worker_ip):
            return
        rules = transproxy_redirect_rules(
            wt.worker_ip, trans_port=self.transproxy_trans_port,
            dns_port=self.transproxy_dns_port, add=True,
        )
        try:
            # Install the HOST REDIRECT/DROP enforcement FIRST, then the in-netns default route
            # LAST. The worker's egress barrier releases on the route, so the route must be the final
            # step — otherwise a worker could observe the route and egress through the host gateway
            # while the REDIRECT/DROP rules aren't in place yet (a leak window), and a host-rule
            # failure would leave a live route with no enforcement (fail-OPEN). This mirrors the
            # socks tier (route onto tun0 is its last step). On any failure, nothing is left wired:
            # a host-rule failure rolls back the host rules and never installs the route; a route
            # failure rolls back the host rules (the route `replace` failed, so none is installed).
            for rule in rules:
                if self.host_run_fn(rule) != 0:
                    _log.warning("netd: transproxy rule failed for job %s; rolling back", wt.job_id)
                    self._teardown_transproxy(wt.worker_ip)
                    return
            for cmd in gateway_route_commands(self.transproxy_gateway):
                if self.nsenter_run_fn(wt.pid, cmd) != 0:
                    _log.warning("netd: transproxy route failed for job %s; rolling back", wt.job_id)
                    self._teardown_transproxy(wt.worker_ip)
                    return
        except Exception as exc:  # noqa: BLE001
            _log.warning("netd: failed to wire transproxy for job %s: %s", wt.job_id, exc)
            self._teardown_transproxy(wt.worker_ip)
            return
        self.wired[container_id] = None  # the in-netns part is route-only
        self.transproxy_wired[container_id] = wt.worker_ip  # host rules to remove on die
        _log.info("netd: wired transproxy job=%s ip=%s -> tor TransPort %s / DNSPort %s",
                  wt.job_id, wt.worker_ip, self.transproxy_trans_port, self.transproxy_dns_port)

    def _teardown_transproxy(self, worker_ip: str) -> None:
        """Remove the host REDIRECT/DROP rules for ``worker_ip`` (best-effort, idempotent)."""
        if self.host_run_fn is None or not worker_ip:
            return
        for rule in transproxy_redirect_rules(
            worker_ip, trans_port=self.transproxy_trans_port,
            dns_port=self.transproxy_dns_port, add=False,
        ):
            try:
                self.host_run_fn(rule)
            except Exception as exc:  # noqa: BLE001
                _log.warning("netd: transproxy teardown rule failed for %s: %s", worker_ip, exc)

    def handle_die(self, container_id: str) -> None:
        """A container died — stop its capture and/or SOCKS wiring. Never raises."""
        ac = self.active.pop(container_id, None)
        if ac is not None:
            # The .done sentinel must only be written once tcpdump has ACTUALLY exited — otherwise
            # the dispatcher would treat a still-flushing pcap as complete. terminate→wait; if it
            # won't stop, force-kill; only mark done when we've confirmed it's gone.
            stopped = True
            try:
                ac.proc.terminate()
                ac.proc.wait(timeout=_STOP_TIMEOUT_S)
            except Exception as exc:  # noqa: BLE001
                _log.warning("netd: stopping capture for job %s: %s", ac.target.job_id, exc)
                stopped = self._force_stop(ac.proc, ac.target.job_id)
            _log.info("netd: capture finalized job=%s -> %s", ac.target.job_id, ac.target.pcap_path)
            # Best-effort: if we couldn't confirm tcpdump exited, skip the sentinel — the dispatcher
            # then falls back to its bounded wait rather than sealing a possibly-incomplete pcap.
            if stopped:
                self._write_capture_done(ac.target.pcap_path)
        # Inspect tier: snapshot the gateway's TLS keylog next to this worker's pcap so the
        # dispatcher can decrypt it. Needs the worker's pcap (the per-flow client_random binds the
        # right keys), so it's a no-op without an active capture. Best-effort: never fail on die.
        if container_id in self.inspect_wired:
            self.inspect_wired.discard(container_id)
            self._snapshot_inspect_keylog(ac)
        # transproxy tier: remove this worker's host REDIRECT/DROP rules (the netns dies with the
        # container, but the HOST-side rules don't — they must be torn down explicitly).
        tp_ip = self.transproxy_wired.pop(container_id, None)
        if tp_ip is not None:
            self._teardown_transproxy(tp_ip)
        # leak-guard rules live in the worker netns → die with the container; just forget the id.
        self.leakguarded.discard(container_id)
        self.leakguard_failed.discard(container_id)
        wproc = self.wired.pop(container_id, None)
        if wproc is not None:
            try:
                wproc.terminate()
                wproc.wait(timeout=_STOP_TIMEOUT_S)
            except Exception as exc:  # noqa: BLE001
                _log.warning("netd: stopping socks wire for %s: %s", container_id[:12], exc)

    def _force_stop(self, proc: Any, job_id: str) -> bool:
        """SIGKILL a capture proc that ignored SIGTERM and confirm it's gone. Returns True if the
        process has exited (so its pcap is final), False if we still can't confirm it stopped."""
        try:
            proc.kill()
            proc.wait(timeout=_STOP_TIMEOUT_S)
        except Exception as exc:  # noqa: BLE001
            _log.warning("netd: could not force-stop capture for job %s: %s", job_id, exc)
        try:
            return proc.poll() is not None
        except Exception:  # noqa: BLE001
            return False

    def _write_capture_done(self, pcap_path: str) -> None:
        """Drop a ``<pcap>.done`` marker once tcpdump has fully terminated (capture is complete).
        The dispatcher's _seal_network_capture waits for this before copying the pcap, closing the
        race where it would otherwise seal a still-active capture. Best-effort — never fail on die."""
        try:
            with open(pcap_path + ".done", "w") as fh:
                fh.write("done")
        except Exception as exc:  # noqa: BLE001 — sentinel is an optimisation, not load-bearing
            _log.warning("netd: failed to write capture done-sentinel for %s: %s", pcap_path, exc)

    def _snapshot_inspect_keylog(self, ac: _ActiveCapture | None) -> None:
        """Copy the shared sslproxy gateway keylog into this job's capture dir as ``sslkeys.log``
        (sibling of the pcap), so _seal_decrypted_capture can run GoGoRoboCap. No-op unless a keylog
        path is configured, the file exists+non-empty, and the worker had a capture to pair it with.
        Copying the WHOLE shared keylog is correct: GoGoRoboCap only uses keys whose client_random
        matches a flow in THIS worker's pcap, so cross-job keys are inert."""
        if ac is None or not self.inspect_keylog_path:
            return
        try:
            src = self.inspect_keylog_path
            if not os.path.isfile(src) or os.path.getsize(src) == 0:
                return
            dst = os.path.join(os.path.dirname(ac.target.pcap_path), _SSLKEYS_NAME)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            self.keylog_copy_fn(src, dst)
        except Exception as exc:  # noqa: BLE001 — decrypt enrichment is best-effort
            _log.warning("netd: snapshot inspect keylog for job %s failed: %s",
                         ac.target.job_id, exc)
            return
        _log.info("netd: snapshot inspect keylog job=%s -> %s", ac.target.job_id, dst)

    # ------------------------------------------------------------------ reconcile
    def _reconcile(self) -> None:
        """Replay ``handle_start`` over the workers already running — on first boot (netd started
        after a job) and after every events-stream reconnect (a docker-daemon restart / stream
        hiccup would otherwise leave already-running workers uncaptured and unwired). ``handle_start``
        is idempotent (each ``_maybe_*`` is membership-gated), so re-running it over a worker netd
        already tracks is a no-op. No-op if no ``list_running_fn`` seam is configured."""
        if self.list_running_fn is None:
            return
        try:
            running = set(self.list_running_fn())
        except Exception as exc:  # noqa: BLE001 — reconcile is best-effort, never crash the daemon
            _log.warning("netd: reconcile listing failed: %s", exc)
            return
        # Tear down workers we still track that are no longer running: if a worker DIED during the
        # events-stream gap, netd never saw its `die` event, so its capture proc, tun2socks, and —
        # critically — its HOST-side transproxy REDIRECT/DROP rules would survive. On bridge-IP reuse
        # those stale host rules would mis-route/capture an unrelated container. handle_die is
        # idempotent, so replaying it for a vanished id cleanly releases everything.
        tracked = (set(self.active) | set(self.wired) | set(self.transproxy_wired)
                   | set(self.leakguarded) | set(self.inspect_wired))
        for cid in tracked - running:
            _log.info("netd: reconcile tearing down vanished worker %s", cid[:12])
            self.handle_die(cid)
        # Pick up workers that started during the gap (or before netd) — handle_start is idempotent.
        for cid in running:
            self.handle_start(cid)

    # ------------------------------------------------------------------ event loop
    def run(  # pragma: no cover - I/O loop
        self, events_cmd: list[str] | None = None, *, reconnect: bool = True
    ) -> None:
        """Follow ``docker events`` and dispatch start/die to the handlers, RECONNECTING with capped
        backoff if the stream ends (docker-daemon restart, transient exit). Reconciles already-running
        workers on each (re)connect. The thin untestable shell around the (tested) handlers/reconcile;
        ``reconnect=False`` runs a single pass (kept for the on-host integration harness)."""
        cmd = events_cmd or [
            "docker", "events", "--format", "{{json .}}",
            "--filter", "type=container",
            "--filter", "event=start", "--filter", "event=die",
        ]
        backoff = 1.0
        while True:
            self._reconcile()
            try:
                self._follow_events(cmd)
            except Exception as exc:  # noqa: BLE001 — never let a stream error kill the daemon
                _log.warning("netd: docker events stream error: %s", exc)
            if not reconnect:
                return
            _log.warning("netd: docker events stream ended; reconnecting in %.0fs", backoff)
            self.sleep_fn(backoff)
            backoff = min(backoff * 2.0, 30.0)

    def _follow_events(self, cmd: list[str]) -> None:  # pragma: no cover - I/O loop
        """One connection to ``docker events``: read+dispatch until the stream ends. A malformed
        line or an event for a non-worker container is skipped; an exception handling one event is
        contained so it can never kill the daemon (the handlers are themselves non-raising)."""
        _log.info("netd: watching docker events: %s", " ".join(cmd))
        with subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True) as proc:
            assert proc.stdout is not None
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    evt = json.loads(line)
                except json.JSONDecodeError:
                    continue
                status = evt.get("status") or evt.get("Action")
                cid = evt.get("id") or evt.get("Actor", {}).get("ID")
                if not cid:
                    continue
                try:
                    if status == "start":
                        self.handle_start(cid)
                    elif status == "die":
                        self.handle_die(cid)
                except Exception as exc:  # noqa: BLE001 — belt-and-suspenders: handlers don't raise
                    _log.warning("netd: error handling %s for %s: %s", status, str(cid)[:12], exc)


def build_network_iface_map(network_inspect_all: list[Mapping[str, object]]) -> dict[str, str]:
    """Build a docker NetworkID → host bridge iface map from ``docker network inspect`` output
    (the list form). Skips non-bridge networks that have no derivable iface."""
    out: dict[str, str] = {}
    for net in network_inspect_all:
        net_id = net.get("Id")
        if not net_id:
            continue
        try:
            out[str(net_id)] = bridge_iface_for_network(net)
        except ValueError:
            continue
    return out


# --------------------------------------------------------------------------- production seams
# These talk to the real docker daemon + spawn real tcpdump; they are the daemon's I/O edge and
# are exercised by the on-host integration run, not the unit tests (which inject fakes).

def _docker_inspect(container_id: str) -> Mapping[str, object]:  # pragma: no cover - I/O
    out = subprocess.run(
        ["docker", "inspect", container_id],
        capture_output=True, text=True, check=True, timeout=10,
    ).stdout
    data = json.loads(out)
    return data[0] if isinstance(data, list) and data else {}


def _docker_network_iface_map() -> Mapping[str, str]:  # pragma: no cover - I/O
    ids = subprocess.run(
        ["docker", "network", "ls", "-q"],
        capture_output=True, text=True, check=True, timeout=10,
    ).stdout.split()
    if not ids:
        return {}
    out = subprocess.run(
        ["docker", "network", "inspect", *ids],
        capture_output=True, text=True, check=True, timeout=10,
    ).stdout
    return build_network_iface_map(json.loads(out))


def _docker_list_workers() -> list[str]:  # pragma: no cover - I/O
    # Currently-running worker containers (for reconcile). Filter on the dispatcher's role label so
    # netd only re-inspects workers, not every container on the host.
    out = subprocess.run(
        ["docker", "ps", "-q", "--no-trunc", "--filter", "label=blastbox.role=worker"],
        capture_output=True, text=True, check=True, timeout=10,
    ).stdout
    return out.split()


def _spawn_tcpdump(argv: list[str], pcap_path: str) -> subprocess.Popen:  # pragma: no cover - I/O
    # tcpdump writes the pcap itself (-w); inherit no stdin, drop stdout, keep stderr for diag.
    return subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)


def _nsenter_spawn(pid: int, argv: list[str]) -> subprocess.Popen:  # pragma: no cover - I/O
    # Run a long-lived command (tun2socks) inside the worker's network namespace.
    return subprocess.Popen(
        ["nsenter", "-t", str(pid), "-n", *argv],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
    )


def _nsenter_run(pid: int, argv: list[str]) -> int:  # pragma: no cover - I/O
    # Run a short command (ip route/link/addr, tun0 probe) inside the worker's netns; return rc.
    return subprocess.run(
        ["nsenter", "-t", str(pid), "-n", *argv],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode


def _host_run(argv: list[str]) -> int:  # pragma: no cover - I/O
    # Run a short command (iptables) in the HOST netns — netd already runs there as root.
    return subprocess.run(
        argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode


def main(argv: list[str] | None = None) -> int:  # pragma: no cover - entry point
    import argparse

    parser = argparse.ArgumentParser(prog="blastbox-netd", description=__doc__)
    parser.add_argument(
        "--job-root",
        default=os.environ.get("BLASTBOX_JOB_ROOT", "/var/lib/blastbox/jobs"),
        help="per-job root; pcaps land under <job_root>/<job_id>/capture/ (must match dispatcher)",
    )
    parser.add_argument(
        "--socks-proxy",
        default=os.environ.get("BLASTBOX_NETD_SOCKS_PROXY", ""),
        help="SOCKS5 proxy URL (socks5://[user:pass@]host:port) for the socks tier; enables "
             "netns wiring of workers labeled blastbox.net.wire=socks. Empty = disabled.",
    )
    parser.add_argument(
        "--vpn-gateway",
        default=os.environ.get("BLASTBOX_NETD_VPN_GATEWAY", ""),
        help="VPN+NAT gateway sidecar IP for the vpn tier; default-routes workers labeled "
             "blastbox.net.wire=vpn through it. Empty = disabled.",
    )
    parser.add_argument(
        "--inspect-gateway",
        default=os.environ.get("BLASTBOX_NETD_INSPECT_GATEWAY", ""),
        help="sslproxy/MITM gateway sidecar IP for the inspect tier; default-routes workers "
             "labeled blastbox.net.wire=inspect through it. Empty = disabled.",
    )
    parser.add_argument(
        "--inspect-keylog",
        default=os.environ.get("BLASTBOX_NETD_INSPECT_KEYLOG", ""),
        help="host path to the sslproxy gateway's SSLKEYLOGFILE (-M master_keys.log); snapshotted "
             "into each inspect job's capture dir as sslkeys.log so the dispatcher can decrypt.",
    )
    parser.add_argument(
        "--transproxy-gateway",
        default=os.environ.get("BLASTBOX_NETD_TRANSPROXY_GATEWAY", ""),
        help="host bridge gateway IP that transproxy (CAPE tor) workers default-route through "
             "before the host REDIRECTs their TCP/DNS to tor. Empty = transproxy disabled.",
    )
    parser.add_argument(
        "--transproxy-trans-port", type=int,
        default=int(os.environ.get("BLASTBOX_NETD_TRANSPROXY_TRANS_PORT") or "9040"),
        help="tor TransPort the host REDIRECTs worker TCP to (default 9040).",
    )
    parser.add_argument(
        "--transproxy-dns-port", type=int,
        default=int(os.environ.get("BLASTBOX_NETD_TRANSPROXY_DNS_PORT") or "5353"),
        help="tor DNSPort the host REDIRECTs worker :53 to (default 5353).",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    ns = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if ns.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    socks = ns.socks_proxy.strip() or None
    vpn = ns.vpn_gateway.strip() or None
    inspect_gw = ns.inspect_gateway.strip() or None
    inspect_keylog = ns.inspect_keylog.strip() or None
    transproxy_gw = ns.transproxy_gateway.strip() or None
    daemon = CaptureDaemon(
        job_root=ns.job_root,
        inspect_fn=_docker_inspect,
        network_iface_fn=_docker_network_iface_map,
        spawn_fn=_spawn_tcpdump,
        socks_proxy_url=socks,
        vpn_gateway_ip=vpn,
        inspect_gateway_ip=inspect_gw,
        inspect_keylog_path=inspect_keylog,
        transproxy_gateway=transproxy_gw,
        transproxy_trans_port=ns.transproxy_trans_port,
        transproxy_dns_port=ns.transproxy_dns_port,
        host_run_fn=_host_run if transproxy_gw else None,
        # Always provide the worker-netns seams. They are inert unless a worker carries a
        # dispatcher-set wire/leakguard label, and gating them on a configured GLOBAL exit broke the
        # per-worker socks-proxy fleet (a worker labeled blastbox.net.socks-proxy with no global
        # --socks-proxy) AND the leak guard (which only needs nsenter, not any global exit).
        nsenter_spawn_fn=_nsenter_spawn,
        nsenter_run_fn=_nsenter_run,
        list_running_fn=_docker_list_workers,
    )
    _log.info(
        "blastbox-netd starting; job_root=%s socks=%s vpn=%s inspect=%s keylog=%s transproxy=%s",
        ns.job_root, "on" if socks else "off", "on" if vpn else "off",
        "on" if inspect_gw else "off", "on" if inspect_keylog else "off",
        "on" if transproxy_gw else "off",
    )
    try:
        daemon.run()
    except KeyboardInterrupt:
        _log.info("blastbox-netd stopping")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
