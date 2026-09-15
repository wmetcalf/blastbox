"""Verify a peer's containment FROM THE EXIT HOST, where it is actually observable.

Step 4 of the federation design
(``docs/superpowers/specs/2026-09-15-federated-node-identity-and-placement.md``), and the
gate that should precede any third-party node holding egress.

WHY THIS CANNOT LIVE ON THE PEER
--------------------------------
``egress_apply.enforcement_present()`` asks a node whether its own containment is
installed. Four review rounds went into making that answer honest, and none of it helps
once the node reporting it is the adversary: a peer that has removed its source route can
report whatever it likes, and the node-side check is exactly the code it would disable.

The exit host is the one place with an independent view. It terminates the tunnel, so it
can see whether a peer's traffic arrives here **at all** — and that is the question that
matters. A node that is detonating samples and whose traffic is NOT arriving at the exit
is not idle; it is egressing somewhere else. That contradiction is observable from here
and nowhere else, and it is what this module reports.

WHAT IT CAN AND CANNOT SHOW
---------------------------
Can:  a peer is connected; how much it has actually sent; whether its traffic is
      flowing while it claims to be working (the leak signal).
Cannot: prove a peer is *not* also egressing directly. Absence of a second path is not
      observable from this end — a node with a working overlay can still have a
      side-channel. The honest bound is "its work is not arriving here", which catches
      the whole-hog leak and misses the partial one, so this is a gate rather than a
      proof. §6 of the spec says as much.

WireGuard's cryptokey routing does one piece of verification for free and it is worth
naming: a peer's ``AllowedIPs`` is pinned to a single ``/32``, so it cannot source
traffic as another peer. That is enforced by the kernel, not by this module.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Mapping, Sequence

__all__ = [
    "PeerObservation",
    "keepalive_allowance",
    "Verdict",
    "parse_wg_dump",
    "attest",
    "STALE_HANDSHAKE_S",
    "QUIET_WINDOWS_BEFORE_LEAK",
]

#: A peer that has not completed a handshake in this long is not connected. WireGuard
#: rekeys every ~2 minutes while traffic flows and sends keepalives at 25s, so several
#: minutes of silence means the tunnel is down, not quiet.
STALE_HANDSHAKE_S = 300.0

#: KEEPALIVES MOVE THE COUNTERS. This was found by running the check against a live
#: tunnel, not by reasoning about it: peers are configured `PersistentKeepalive = 25`, so
#: rx/tx increase every 25 seconds forever whether or not a single byte of work flows.
#: A naive "did the counters move" test is therefore ALWAYS true and the contradiction
#: never fires — the signal looked like it worked and detected nothing.
#:
#: So a delta only counts as real traffic if it exceeds what keepalives alone explain.
#: A keepalive is a 32-byte payload; the allowance below is deliberately several times
#: that per interval, because being generous here costs sensitivity to trivially small
#: leaks while being stingy would produce false accusations on an idle tunnel — and a
#: false accusation takes a working node out of service.
KEEPALIVE_INTERVAL_S = 25.0
KEEPALIVE_BYTES_ALLOWANCE = 512
#: Floor, so a very short sampling window cannot make the allowance near-zero.
MIN_TRAFFIC_BYTES = 4096

#: CONSECUTIVE quiet windows before a working node is called a leak.
#:
#: A single quiet window means nothing, and assuming otherwise would make this unusable.
#: Most detonations are quiet: plenty of samples never open a socket, many resolve one
#: name and stop, and a job can be dispatched and still be unpacking when the window
#: closes. Accusing on one sample would take working nodes out of service constantly,
#: and an alarm that cries wolf is worse than no alarm — it trains the operator to
#: ignore the one real leak.
#:
#: Sustained silence across several windows while the control plane keeps dispatching
#: egress work is a different claim, and a much stronger one.
QUIET_WINDOWS_BEFORE_LEAK = 3


def keepalive_allowance(elapsed_s: float) -> int:
    """Bytes a peer can accumulate from keepalives alone over ``elapsed_s``."""
    intervals = max(0.0, elapsed_s) / KEEPALIVE_INTERVAL_S
    return int(MIN_TRAFFIC_BYTES + intervals * KEEPALIVE_BYTES_ALLOWANCE)


@dataclass(frozen=True)
class PeerObservation:
    """One peer as the EXIT HOST sees it. Every field is observed, none is claimed."""

    public_key: str
    endpoint: str
    allowed_ips: tuple[str, ...]
    #: Unix seconds, 0 when the peer has never completed a handshake.
    latest_handshake: float
    rx_bytes: int
    tx_bytes: int
    #: When we looked, so two observations can be differenced.
    observed_at: float

    @property
    def ever_connected(self) -> bool:
        return self.latest_handshake > 0

    def connected(self, *, now: float | None = None) -> bool:
        if not self.ever_connected:
            return False
        return ((time.time() if now is None else now) - self.latest_handshake) <= STALE_HANDSHAKE_S


@dataclass(frozen=True)
class Verdict:
    """What the exit host can say about one peer, and why."""

    node_id: str
    contained: bool
    reason: str
    #: True only where the exit host has POSITIVE evidence of a contradiction, as opposed
    #: to merely having nothing to report. Callers should treat these very differently:
    #: the first is a node to take out of service, the second is a node to keep watching.
    contradicted: bool = False
    #: Consecutive quiet-while-working windows behind this verdict. Carried so the
    #: caller can persist it, and so a report can say "2 of 3" rather than only ever
    #: showing the final accusation.
    quiet_windows: int = 0


def parse_wg_dump(dump: str, *, observed_at: float | None = None) -> list[PeerObservation]:
    """Parse ``wg show <iface> dump`` into observations.

    THE FIRST LINE IS DISCARDED AND MUST STAY DISCARDED. Its first field is the
    interface's PRIVATE KEY — `wg show dump` prints it unmasked. Nothing here retains,
    returns or logs it; a future edit that starts parsing the interface line needs to
    keep that true, because these objects end up in log lines and API responses.

    Malformed lines are skipped rather than raised on: this runs on a schedule against
    output from a tool that may change, and one odd line must not blind the whole check.
    """
    at = time.time() if observed_at is None else observed_at
    out: list[PeerObservation] = []
    for line in (dump or "").splitlines()[1:]:      # [1:] drops the private key. Keep it.
        f = line.split("\t")
        if len(f) < 8:
            continue
        try:
            out.append(PeerObservation(
                public_key=f[0],
                endpoint=f[2],
                allowed_ips=tuple(x for x in f[3].split(",") if x),
                latest_handshake=float(f[4]),
                rx_bytes=int(f[5]),
                tx_bytes=int(f[6]),
                observed_at=at,
            ))
        except (ValueError, IndexError):
            continue
    return out


def attest(
    now: Sequence[PeerObservation],
    *,
    key_to_node: Mapping[str, str],
    working: Mapping[str, bool] | None = None,
    previous: Sequence[PeerObservation] | None = None,
    quiet_streak: Mapping[str, int] | None = None,
    at: float | None = None,
) -> list[Verdict]:
    """Judge each peer from the exit host's own observations.

    ``key_to_node`` maps a WireGuard public key to the node identity that registered it —
    resolved from the node's CERTIFICATE by the caller, never from anything the node
    said. A key with no mapping is a stale or unauthorised registration and is reported.

    ``working`` says which nodes the CONTROL PLANE believes are currently running egress
    work. That is the crucial input, and it must come from the job store — what this node
    was dispatched — not from the node's own heartbeat, or the adversary supplies both
    sides of the comparison.

    ``previous`` is an earlier observation of the same peers. WireGuard's counters are
    monotonic, so a delta is the only way to distinguish "has sent traffic at some point"
    from "is sending traffic now".

    THE CONTRADICTION. A node the control plane dispatched egress work to, whose counters
    have not moved since the last look, is not idle — its traffic is going somewhere that
    is not here. That is the leak signal, and the only one this vantage point can produce.
    """
    when = time.time() if at is None else at
    prev_by_key = {p.public_key: p for p in (previous or ())}
    working = working or {}
    verdicts: list[Verdict] = []

    for obs in sorted(now, key=lambda o: o.public_key):
        node_id = key_to_node.get(obs.public_key)
        if node_id is None:
            verdicts.append(Verdict(
                node_id=f"<unknown key {obs.public_key[:12]}…>", contained=False,
                reason="a registered WireGuard peer that no current node certificate "
                       "authorises — a stale registration, or one that was never "
                       "legitimate. Remove it (`egress peer-prune`, or by hand).",
                contradicted=True))
            continue

        if not obs.ever_connected:
            # "Never handshook" is innocuous for an idle node and damning for a working
            # one: its work has to be going somewhere, and it has never once reached
            # this exit. The earlier version returned contained=True regardless, which
            # discarded the clearest signal available.
            is_working = bool(working.get(node_id))
            verdicts.append(Verdict(
                node_id=node_id, contained=not is_working, contradicted=is_working,
                reason=("the control plane dispatched egress work to it and it has NEVER "
                        "completed a handshake — its traffic has never once reached this "
                        "exit" if is_working else
                        "registered but has never completed a handshake; nothing to "
                        "contain yet")))
            continue

        if not obs.connected(now=when):
            age = int(when - obs.latest_handshake)
            is_working = bool(working.get(node_id))
            verdicts.append(Verdict(
                node_id=node_id, contained=not is_working,
                reason=(f"no handshake for {age}s AND the control plane dispatched "
                        "egress work to it — its traffic is not arriving here, so it is "
                        "reaching the internet another way"
                        if is_working else
                        f"no handshake for {age}s; idle, tunnel down"),
                contradicted=is_working))
            continue

        prev = prev_by_key.get(obs.public_key)
        if prev is None:
            verdicts.append(Verdict(
                node_id=node_id, contained=True,
                reason="connected; first observation, nothing to compare against yet"))
            continue

        elapsed = max(0.0, obs.observed_at - prev.observed_at)
        delta = max(0, obs.rx_bytes - prev.rx_bytes) + max(0, obs.tx_bytes - prev.tx_bytes)
        allowance = keepalive_allowance(elapsed)
        real_traffic = delta > allowance

        if working.get(node_id) and not real_traffic:
            streak = (quiet_streak or {}).get(node_id, 0) + 1
            if streak < QUIET_WINDOWS_BEFORE_LEAK:
                # Not yet an accusation. Most detonations are quiet — see
                # QUIET_WINDOWS_BEFORE_LEAK — so one window proves nothing.
                verdicts.append(Verdict(
                    node_id=node_id, contained=True, quiet_windows=streak,
                    reason=(f"connected; only {delta}B in {int(elapsed)}s while work was "
                            f"dispatched ({streak} of {QUIET_WINDOWS_BEFORE_LEAK} quiet "
                            "windows). Many samples never open a socket, so this is "
                            "only suspicious once it persists")))
                continue
            verdicts.append(Verdict(
                node_id=node_id, contained=False, contradicted=True, quiet_windows=streak,
                reason=(f"egress work dispatched across {streak} consecutive windows and "
                        f"only {delta}B crossed its tunnel in the last {int(elapsed)}s — "
                        f"under the {allowance}B keepalives alone explain. Its traffic is "
                        "leaving by some path that is not this exit")))
            continue

        verdicts.append(Verdict(
            node_id=node_id, contained=True,
            reason=(f"connected; {delta}B through this exit in {int(elapsed)}s"
                    if real_traffic else
                    f"connected; {delta}B in {int(elapsed)}s is keepalive-only, and no "
                    "work was dispatched here")))
    return verdicts


def missing_peers(
    now: Sequence[PeerObservation], *, key_to_node: Mapping[str, str]
) -> tuple[str, ...]:
    """Nodes with a certificate-registered key that is NOT present on the interface.

    The inverse oversight to an unknown peer: a node believes it is enrolled, the exit
    host has no peer for it, and every job placed there will fail closed. Silent
    otherwise — the node's own health check passes right up to the point its traffic has
    nowhere to go.
    """
    present = {o.public_key for o in now}
    return tuple(sorted(node for key, node in key_to_node.items() if key not in present))
