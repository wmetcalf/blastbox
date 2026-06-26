"""Watch a VPN/tunnel interface; on drop, surface an alert and invoke recovery.

This is the active half of the anonymizing-egress story. The iptables KILL-SWITCH (egress ACCEPT
scoped to the tunnel interface — see ``libvirt_egress.forward_chain_rules``) already FAILS CLOSED the
instant a tunnel drops: a worker's packets fall back to the host's default route and hit the chain's
catch-all DROP instead of leaking out the host WAN. So the data plane is safe with zero monitoring.

``TunnelGuard`` adds what the kill-switch can't: it DETECTS the drop, SURFACES it (error log +
``on_down`` callback for paging/metrics) and tries to AUTO-RECOVER (``recover`` callback, e.g. restart
the VPN). Run one per tunnel from the dispatcher/host. It never weakens the kill-switch — recovery is
best-effort; while the tunnel is down, workers simply can't egress.
"""
from __future__ import annotations

import logging
import subprocess
import threading
from collections.abc import Callable

logger = logging.getLogger(__name__)


def systemctl_restart(service: str, runner: Callable = subprocess.run) -> bool:
    """Restart a systemd unit — the usual VPN recovery (``openvpn@pia``, a ``wg-quick@wg0``, …).
    Returns True on success; logs and returns False otherwise (recovery is best-effort)."""
    r = runner(["systemctl", "restart", service], capture_output=True, text=True)
    if r.returncode != 0:
        logger.warning("systemctl restart %s failed: %s", service, (r.stderr or "").strip()[:160])
    return r.returncode == 0


def interface_is_up(tun: str, runner: Callable = subprocess.run) -> bool:
    """True iff ``tun`` exists and carries the UP flag. A dropped OpenVPN/WireGuard tunnel usually
    removes the interface (rc != 0) or clears UP."""
    r = runner(["ip", "-o", "link", "show", tun], capture_output=True, text=True)
    if r.returncode != 0:
        return False
    out = r.stdout
    try:
        flags = out[out.index("<") + 1:out.index(">")].split(",")
    except ValueError:
        return False
    return "UP" in flags


class TunnelGuard:
    """Edge-triggered tunnel monitor. Call :meth:`check` periodically (or :meth:`run` to loop).

    Recovery: pass ``service`` (the systemd unit backing the tunnel) and the guard just
    ``systemctl restart``s it on each down-edge — the common case. For a non-systemd tunnel (a
    container, a custom script) pass ``recover`` instead to override. on_down(tun)/on_up(tun) are
    notification hooks (page, bump a metric). is_up is the liveness probe (injectable; defaults to
    the interface UP check)."""

    def __init__(self, tun: str, *,
                 service: str | None = None,
                 on_down: Callable[[str], None] | None = None,
                 on_up: Callable[[str], None] | None = None,
                 recover: Callable[[str], None] | None = None,
                 is_up: Callable[[str], bool] | None = None) -> None:
        self.tun = tun
        self._on_down = on_down
        self._on_up = on_up
        # Default recovery = restart the tunnel's systemd unit; `recover` overrides for non-systemd.
        if recover is None and service is not None:
            def recover(_t: str, _s: str = service) -> None:
                systemctl_restart(_s)
        self._recover = recover
        self._is_up = is_up or interface_is_up
        self._last_up: bool | None = None  # unknown until the first check

    def check(self) -> bool:
        """One probe. Fires the down/up hooks (+ recovery) on a state transition. Returns current up."""
        up = bool(self._is_up(self.tun))
        if up != self._last_up:
            if not up:
                logger.error("tunnel %s is DOWN — worker egress is fail-closed (kill-switch); "
                             "attempting recovery", self.tun)
                self._safe(self._on_down)
                self._safe(self._recover)
            elif self._last_up is not None:  # don't log "recovered" on the very first healthy probe
                logger.warning("tunnel %s recovered (UP) — egress restored", self.tun)
                self._safe(self._on_up)
            self._last_up = up
        return up

    def _safe(self, cb: Callable[[str], None] | None) -> None:
        if cb is None:
            return
        try:
            cb(self.tun)
        except Exception:
            logger.warning("tunnel %s: guard callback failed (non-fatal)", self.tun, exc_info=True)

    def run(self, interval_s: float = 5.0, stop: threading.Event | None = None) -> None:
        """Blocking monitor loop; stop by setting the ``stop`` event."""
        stop = stop or threading.Event()
        while not stop.is_set():
            try:
                self.check()
            except Exception:
                logger.warning("tunnel %s: check failed (non-fatal)", self.tun, exc_info=True)
            stop.wait(interval_s)

    def start(self, interval_s: float = 5.0) -> threading.Event:
        """Run :meth:`run` on a daemon thread; returns the stop event."""
        stop = threading.Event()
        threading.Thread(target=self.run, args=(interval_s, stop), daemon=True,
                         name=f"tunnel-guard-{self.tun}").start()
        return stop
