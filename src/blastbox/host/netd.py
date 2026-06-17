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
    gateway_route_commands,
    tun2socks_argv,
    tun_setup_commands,
    wire_target_from_inspect,
)

_log = logging.getLogger("blastbox.host.netd")

# How long to wait for tcpdump to flush + exit after SIGTERM before giving up (the pcap is
# line-buffered via -U, so even a hard miss leaves a usable capture).
_STOP_TIMEOUT_S = 5.0
# How long to wait for tun2socks to create the TUN before configuring routes (tries × interval).
_TUN_WAIT_TRIES = 40
_TUN_WAIT_INTERVAL_S = 0.25


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
    nsenter_spawn_fn: Callable[[int, list[str]], Any] | None = None  # long-lived in worker netns
    nsenter_run_fn: Callable[[int, list[str]], int] | None = None    # run cmd in netns → rc
    sleep_fn: Callable[[float], None] = time.sleep
    wired: dict[str, Any] = field(default_factory=dict)  # container_id → proc-or-None

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
        self._maybe_wire(container_id, inspect)

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

    def _wire_socks(self, container_id: str, wt: Any) -> None:
        if not self.socks_proxy_url or self.nsenter_spawn_fn is None or self.nsenter_run_fn is None:
            return
        try:
            proc = self.nsenter_spawn_fn(wt.pid, tun2socks_argv(self.socks_proxy_url))
            # tun2socks creates the TUN asynchronously; wait for it before configuring routes.
            ready = False
            for _ in range(_TUN_WAIT_TRIES):
                if self.nsenter_run_fn(wt.pid, ["ip", "link", "show", TUN_DEV]) == 0:
                    ready = True
                    break
                self.sleep_fn(_TUN_WAIT_INTERVAL_S)
            if not ready:
                _log.warning("netd: tun2socks TUN never appeared for job %s; aborting wire", wt.job_id)
                proc.terminate()
                return
            for cmd in tun_setup_commands():
                self.nsenter_run_fn(wt.pid, cmd)
        except Exception as exc:  # noqa: BLE001
            _log.warning("netd: failed to wire socks for job %s: %s", wt.job_id, exc)
            return
        self.wired[container_id] = proc
        _log.info("netd: wired socks job=%s pid=%s -> %s", wt.job_id, wt.pid, self.socks_proxy_url)

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

    def handle_die(self, container_id: str) -> None:
        """A container died — stop its capture and/or SOCKS wiring. Never raises."""
        ac = self.active.pop(container_id, None)
        if ac is not None:
            try:
                ac.proc.terminate()
                ac.proc.wait(timeout=_STOP_TIMEOUT_S)
            except Exception as exc:  # noqa: BLE001
                _log.warning("netd: stopping capture for job %s: %s", ac.target.job_id, exc)
            _log.info("netd: capture finalized job=%s -> %s", ac.target.job_id, ac.target.pcap_path)
        wproc = self.wired.pop(container_id, None)
        if wproc is not None:
            try:
                wproc.terminate()
                wproc.wait(timeout=_STOP_TIMEOUT_S)
            except Exception as exc:  # noqa: BLE001
                _log.warning("netd: stopping socks wire for %s: %s", container_id[:12], exc)

    # ------------------------------------------------------------------ event loop
    def run(self, events_cmd: list[str] | None = None) -> None:  # pragma: no cover - I/O loop
        """Follow ``docker events`` and dispatch start/die to the handlers. The thin untestable
        shell around the (tested) handlers."""
        cmd = events_cmd or [
            "docker", "events", "--format", "{{json .}}",
            "--filter", "type=container",
            "--filter", "event=start", "--filter", "event=die",
        ]
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
                if status == "start":
                    self.handle_start(cid)
                elif status == "die":
                    self.handle_die(cid)


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
    parser.add_argument("-v", "--verbose", action="store_true")
    ns = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if ns.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    socks = ns.socks_proxy.strip() or None
    vpn = ns.vpn_gateway.strip() or None
    wiring_on = bool(socks or vpn)
    daemon = CaptureDaemon(
        job_root=ns.job_root,
        inspect_fn=_docker_inspect,
        network_iface_fn=_docker_network_iface_map,
        spawn_fn=_spawn_tcpdump,
        socks_proxy_url=socks,
        vpn_gateway_ip=vpn,
        nsenter_spawn_fn=_nsenter_spawn if wiring_on else None,
        nsenter_run_fn=_nsenter_run if wiring_on else None,
    )
    _log.info(
        "blastbox-netd starting; job_root=%s socks=%s vpn=%s",
        ns.job_root, "on" if socks else "off", "on" if vpn else "off",
    )
    try:
        daemon.run()
    except KeyboardInterrupt:
        _log.info("blastbox-netd stopping")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
