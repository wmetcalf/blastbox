"""Containment verified from the exit host, where the peer cannot edit the answer.

The node-side check (`enforcement_present`) asks a machine about its own containment and
is worthless once that machine is the adversary. These tests are about the one question
the exit host can answer independently: is this peer's work arriving here at all?
"""
from __future__ import annotations

import time

from blastbox.host.exit_attest import (
    STALE_HANDSHAKE_S,
    PeerObservation,
    attest,
    missing_peers,
    parse_wg_dump,
)

# A real `wg show bbwg0 dump`, captured from the live exit host. The first line's first
# field is the interface PRIVATE KEY — that is exactly why the parser drops it.
REAL_DUMP = (
    "PRIVATEKEYWOULDBEHERE0000000000000000000000=\tfRLf4rTe4hBDQNftYbW6wF6mhc4CLBb9wpbNC2smeRU=\t51821\toff\n"
    "SZuAZVtRZk7N2NQaTg+IHsw8z/DDxRCHwKqr1G50238=\t(none)\t172.18.101.16:39499\t10.77.0.3/32\t1789496175\t1183660\t1002996\toff\n"
)
PEER_KEY = "SZuAZVtRZk7N2NQaTg+IHsw8z/DDxRCHwKqr1G50238="
MAP = {PEER_KEY: "toolz3"}


def obs(key=PEER_KEY, *, handshake_age=1.0, rx=1000, tx=1000, at=None):
    at = time.time() if at is None else at
    return PeerObservation(
        public_key=key, endpoint="172.18.101.16:39499", allowed_ips=("10.77.0.3/32",),
        latest_handshake=0.0 if handshake_age is None else at - handshake_age,
        rx_bytes=rx, tx_bytes=tx, observed_at=at)


# --------------------------------------------------------------------------- parsing

def test_a_real_dump_parses():
    peers = parse_wg_dump(REAL_DUMP)
    assert len(peers) == 1
    p = peers[0]
    assert p.public_key == PEER_KEY
    assert p.allowed_ips == ("10.77.0.3/32",)
    assert p.rx_bytes == 1183660 and p.tx_bytes == 1002996


def test_the_interface_private_key_is_never_retained():
    """`wg show dump` prints the interface's PRIVATE KEY as the first field of the first
    line, unmasked. These objects reach log lines and API responses, so the parser drops
    that line and must keep dropping it."""
    peers = parse_wg_dump(REAL_DUMP)
    blob = repr(peers)
    assert "PRIVATEKEYWOULDBEHERE" not in blob
    assert all("PRIVATEKEY" not in p.public_key for p in peers)


def test_a_malformed_line_is_skipped_not_raised():
    """This runs on a schedule against a tool whose output may change; one odd line must
    not blind the whole check."""
    dump = REAL_DUMP + "garbage\tnot\tenough\n" + "a\tb\tc\td\tNOPE\tx\ty\tz\n"
    assert len(parse_wg_dump(dump)) == 1


def test_an_empty_dump_is_not_an_error():
    assert parse_wg_dump("") == []
    assert parse_wg_dump("only-an-interface-line\tx\ty\tz\n") == []


# ------------------------------------------------------- the contradiction: the whole point

def test_a_working_node_whose_counters_do_not_move_is_contradicted():
    """THE test. A node the CONTROL PLANE dispatched egress work to, whose tunnel
    counters have not moved, is not idle — its traffic is leaving by some other path."""
    t0 = time.time() - 60
    before = obs(rx=1000, tx=1000, at=t0)
    after = obs(rx=1000, tx=1000, at=t0 + 60)          # identical counters
    [v] = attest([after], key_to_node=MAP, working={"toolz3": True}, previous=[before])
    assert v.contained is False and v.contradicted
    assert "not this exit" in v.reason


def test_a_working_node_whose_counters_move_is_contained():
    t0 = time.time() - 60
    before = obs(rx=1000, tx=1000, at=t0)
    after = obs(rx=99000, tx=42000, at=t0 + 60)
    [v] = attest([after], key_to_node=MAP, working={"toolz3": True}, previous=[before])
    assert v.contained and not v.contradicted


def test_an_idle_node_with_still_counters_is_not_accused():
    """No work dispatched, no traffic expected. Accusing it would make the signal
    useless — every quiet node would look like a leak."""
    t0 = time.time() - 60
    [v] = attest([obs(at=t0 + 60)], key_to_node=MAP, working={"toolz3": False},
                 previous=[obs(at=t0)])
    assert v.contained and not v.contradicted


def test_the_working_signal_must_come_from_the_control_plane_not_the_node():
    """Pinned as an API shape: `working` is a separate argument precisely so the caller
    supplies it from the job store. If it were read off the node's heartbeat the
    adversary would supply both sides of the comparison."""
    import inspect

    from blastbox.host import exit_attest

    sig = inspect.signature(exit_attest.attest)
    assert "working" in sig.parameters
    assert "must come from the job store" in exit_attest.attest.__doc__


# --------------------------------------------------------------------- tunnel is down

def test_a_down_tunnel_on_a_working_node_is_a_contradiction():
    """Its work has to be going somewhere, and it is not coming through here."""
    [v] = attest([obs(handshake_age=STALE_HANDSHAKE_S + 60)],
                 key_to_node=MAP, working={"toolz3": True})
    assert v.contained is False and v.contradicted
    assert "another way" in v.reason


def test_a_down_tunnel_on_an_idle_node_is_merely_down():
    [v] = attest([obs(handshake_age=STALE_HANDSHAKE_S + 60)],
                 key_to_node=MAP, working={"toolz3": False})
    assert v.contained and not v.contradicted


def test_a_peer_that_never_handshook_is_not_accused():
    [v] = attest([obs(handshake_age=None)], key_to_node=MAP, working={"toolz3": True})
    assert v.contained and not v.contradicted
    assert "never completed a handshake" in v.reason


# ------------------------------------------------------------ registration hygiene

def test_a_peer_no_certificate_authorises_is_reported():
    """A key on the interface that no current cert maps to is a stale registration, or
    one that was never legitimate. Either way it has a live tunnel into the exit."""
    [v] = attest([obs(key="STRANGER" + "A" * 35 + "=")], key_to_node=MAP)
    assert v.contained is False and v.contradicted
    assert "no current node certificate" in v.reason


def test_a_node_with_no_peer_on_the_interface_is_reported():
    """The inverse oversight: the node believes it is enrolled, every job placed there
    fails closed, and its own health check passes right up to the point its traffic has
    nowhere to go."""
    assert missing_peers([], key_to_node={PEER_KEY: "toolz3", "K2": "toolz4"}) == \
        ("toolz3", "toolz4")
    assert missing_peers([obs()], key_to_node=MAP) == ()


# ----------------------------------------------------------------------- determinism

def test_verdicts_are_deterministically_ordered():
    peers = [obs(key=f"{c}" + "A" * 42 + "=") for c in "cab"]
    mapping = {p.public_key: f"node-{p.public_key[0]}" for p in peers}
    got = [v.node_id for v in attest(peers, key_to_node=mapping)]
    assert got == sorted(got)


def test_no_previous_observation_means_no_accusation():
    """Counters are monotonic, so a single sample cannot distinguish "sent traffic once,
    long ago" from "sending now". Without a delta there is nothing to contradict."""
    [v] = attest([obs()], key_to_node=MAP, working={"toolz3": True}, previous=None)
    assert v.contained and not v.contradicted


# ------------------------------------------------- keepalives: found by running it live

def test_keepalive_traffic_alone_does_not_count_as_work():
    """THE bug live testing found and the unit tests could not.

    Peers run `PersistentKeepalive = 25`, so rx/tx increase every 25 seconds forever
    whether or not a byte of work flows. A naive "did the counters move" check is
    therefore always true, the contradiction never fires, and the signal detects nothing
    while looking like it works. Pin the keepalive-sized delta explicitly.
    """
    from blastbox.host.exit_attest import keepalive_allowance

    t0 = time.time() - 120
    # Two minutes at 25s keepalives: a handful of tiny packets each way.
    before = obs(rx=1_000_000, tx=1_000_000, at=t0)
    after = obs(rx=1_000_160, tx=1_000_160, at=t0 + 120)
    assert (after.rx_bytes - before.rx_bytes) + (after.tx_bytes - before.tx_bytes) \
        < keepalive_allowance(120)

    [v] = attest([after], key_to_node=MAP, working={"toolz3": True}, previous=[before])
    assert v.contradicted, "keepalive-only traffic must not mask a leak"
    assert "keepalives alone explain" in v.reason


def test_real_work_clears_the_keepalive_allowance():
    t0 = time.time() - 120
    before = obs(rx=1_000_000, tx=1_000_000, at=t0)
    after = obs(rx=1_900_000, tx=1_400_000, at=t0 + 120)     # ~1.3MB of actual traffic
    [v] = attest([after], key_to_node=MAP, working={"toolz3": True}, previous=[before])
    assert v.contained and not v.contradicted


def test_an_idle_peer_with_keepalive_traffic_is_not_accused():
    """No work dispatched, so keepalive-only is exactly what should be seen. Accusing
    here would take working nodes out of service for being quiet."""
    t0 = time.time() - 120
    [v] = attest([obs(rx=1_000_160, tx=1_000_160, at=t0 + 120)], key_to_node=MAP,
                 working={"toolz3": False},
                 previous=[obs(rx=1_000_000, tx=1_000_000, at=t0)])
    assert v.contained and not v.contradicted
    assert "keepalive-only" in v.reason


def test_the_allowance_scales_with_the_sampling_window_and_has_a_floor():
    """A long window legitimately accumulates more keepalive bytes; a very short one
    must not make the allowance near-zero and produce false accusations."""
    from blastbox.host.exit_attest import MIN_TRAFFIC_BYTES, keepalive_allowance

    assert keepalive_allowance(0) >= MIN_TRAFFIC_BYTES
    assert keepalive_allowance(3600) > keepalive_allowance(60)


def test_a_counter_reset_is_not_read_as_negative_traffic():
    """A peer restarting wg zeroes its counters. Treating that as a negative delta would
    make the arithmetic nonsense; it reads as no traffic, which is the safe direction."""
    t0 = time.time() - 60
    [v] = attest([obs(rx=10, tx=10, at=t0 + 60)], key_to_node=MAP,
                 working={"toolz3": True},
                 previous=[obs(rx=5_000_000, tx=5_000_000, at=t0)])
    assert v.contradicted and "0B crossed" in v.reason
