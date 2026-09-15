"""Node certificates: identity + WireGuard key + grants, signed by the existing CA.

These replace an operator reading a public key off one host and pasting it into a command
on another — an unauthenticated channel performing authorisation. Every test here is
about that substitution actually being worth something: a signature that is checked, an
expiry that is enforced, and a payload that cannot be edited after issuance.
"""
from __future__ import annotations

import datetime
import json
import re

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from blastbox.host import pki
from blastbox.host.pki import NodeGrants


@pytest.fixture()
def ca(tmp_path):
    return pki.ensure_ca(tmp_path / "pki")


@pytest.fixture()
def other_ca(tmp_path):
    return pki.ensure_ca(tmp_path / "other-pki")


WG = "A" * 43 + "="
WG2 = "B" * 43 + "="


def test_a_node_cert_round_trips_identity_key_and_grants(ca):
    grants = NodeGrants(engines=("boxjs", "clamav"), tiers=("openvpn", "wireguard"),
                        credentials=True)
    issued = ca.issue_node("toolz3", wg_pubkey=WG, grants=grants)
    ident = pki.node_identity(ca, issued.cert_pem)
    assert ident.node_id == "toolz3"
    assert ident.wg_pubkey == WG
    assert ident.grants == grants
    assert not ident.expired


# --------------------------------------------------------------- the signature is the point

def test_a_cert_from_another_ca_is_refused(ca, other_ca):
    """The whole substitution is worthless if an unsigned or foreign cert is accepted —
    that would be a pasted public key again, with extra steps."""
    foreign = other_ca.issue_node("attacker", wg_pubkey=WG2)
    with pytest.raises(ValueError, match="not signed by this CA"):
        pki.node_identity(ca, foreign.cert_pem)


def test_editing_the_grants_after_issuance_breaks_the_signature(ca):
    """Grants live inside the signed structure precisely so a node cannot present a valid
    identity and a forged capability. Prove the binding rather than assume it."""
    issued = ca.issue_node("toolz3", wg_pubkey=WG, grants=NodeGrants(engines=("boxjs",)))
    cert = x509.load_pem_x509_certificate(issued.cert_pem)
    der = cert.public_bytes(serialization.Encoding.DER)

    # Swap the payload in place: same length, different content.
    original = json.dumps({"v": 1, "node_id": "toolz3", "wg": WG,
                           "engines": ["boxjs"], "tiers": [], "credentials": False},
                          separators=(",", ":"), sort_keys=True).encode()
    assert original in der, "payload should be embedded verbatim"
    forged = original.replace(b'"credentials":false', b'"credentials":true ')
    assert len(forged) == len(original)
    tampered = der.replace(original, forged)

    pem = x509.load_der_x509_certificate(tampered).public_bytes(serialization.Encoding.PEM)
    with pytest.raises(ValueError, match="not signed by this CA"):
        pki.node_identity(ca, pem)


def test_a_cn_that_disagrees_with_the_payload_is_refused(ca, monkeypatch):
    """The human-readable subject must not be able to say one thing while the authorising
    payload says another — an operator reading `openssl x509 -text` should see the
    identity that is actually in force."""
    monkeypatch.setattr(
        pki, "_node_info_bytes",
        lambda node_id, wg, grants: json.dumps(
            {"v": 1, "node_id": "someone-else", "wg": wg,
             "engines": [], "tiers": [], "credentials": False},
            separators=(",", ":"), sort_keys=True).encode())
    issued = ca.issue_node("toolz3", wg_pubkey=WG)
    with pytest.raises(ValueError, match="does not match the node id"):
        pki.node_identity(ca, issued.cert_pem)


# ----------------------------------------------------------------- expiry IS the revocation

def test_an_expired_node_cert_is_refused(ca, monkeypatch):
    """"Stop renewing" is the revocation mechanism, so an unchecked expiry silently
    disables revocation entirely."""
    issued = ca.issue_node("toolz3", wg_pubkey=WG, days=1)
    later = pki._now() + datetime.timedelta(days=2)
    monkeypatch.setattr(pki, "_now", lambda: later)
    with pytest.raises(ValueError, match="expired"):
        pki.node_identity(ca, issued.cert_pem)
    # ...but an operator inspecting a lapsed node can still read it.
    assert pki.node_identity(ca, issued.cert_pem, allow_expired=True).node_id == "toolz3"


def test_node_certs_are_short_lived_by_default(ca):
    issued = ca.issue_node("toolz3", wg_pubkey=WG)
    ident = pki.node_identity(ca, issued.cert_pem)
    assert (ident.not_after - pki._now()) <= datetime.timedelta(days=7, minutes=5)


# ------------------------------------------------------------------------- fail closed

def test_grants_default_to_nothing_not_everything(ca):
    """Forgetting to set grants must produce an idle node, not an unrestricted one."""
    ident = pki.node_identity(ca, ca.issue_node("bare", wg_pubkey=WG).cert_pem)
    assert ident.grants.engines == () and ident.grants.tiers == ()
    assert ident.grants.credentials is False
    assert not ident.grants.allows_engine("boxjs")
    assert not ident.grants.allows_tier("openvpn")


def test_a_transport_cert_is_not_a_node_cert(ca):
    """`issue_client` produces a valid CA-signed cert with no node-info. Accepting it as
    a node identity would let any worker/dispatcher cert authorise an overlay peer."""
    with pytest.raises(ValueError, match="not a node cert"):
        pki.node_identity(ca, ca.issue_client("dispatcher").cert_pem)


@pytest.mark.parametrize("bad", ["", "UPPER", "has space", "../etc", "x" * 64, "-lead"])
def test_unsafe_node_ids_are_refused(ca, bad):
    """The node id reaches filenames, log lines and a wg config comment."""
    with pytest.raises(ValueError, match="invalid node id"):
        ca.issue_node(bad, wg_pubkey=WG)


@pytest.mark.parametrize("bad", ["", "not-a-key", "A" * 10, "A" * 43 + "!"])
def test_a_non_wireguard_key_is_refused_at_issuance(ca, bad):
    with pytest.raises(ValueError, match="WireGuard public key"):
        ca.issue_node("toolz3", wg_pubkey=bad)


def test_the_extension_is_non_critical_so_standard_tools_ignore_it(ca):
    """The OID arc is an unregistered placeholder. Marking the extension critical would
    make every standard verifier reject these certs outright."""
    cert = x509.load_pem_x509_certificate(ca.issue_node("toolz3", wg_pubkey=WG).cert_pem)
    ext = cert.extensions.get_extension_for_oid(pki.OID_NODE_INFO)
    assert ext.critical is False


def test_the_placeholder_oid_arc_is_flagged_in_the_source():
    """1.3.6.1.4.1.99999 is not an IANA Private Enterprise Number. That is acceptable for
    certs that never leave this CA and unacceptable the moment they do, so the warning
    must stay next to the constant where someone changing it will read it."""
    import inspect

    src = inspect.getsource(pki)
    assert "NOT REGISTERED" in src
    assert re.search(r"1\.3\.6\.1\.4\.1\.99999", src)


# ------------------------------------------------------------------- peer-add integration

def _peer_add(monkeypatch, tmp_path, argv_extra, *, registered):
    """Drive `blastbox egress peer-add` with the wg-writing side stubbed out."""
    from blastbox.host import cli
    from blastbox.host import egress_apply as ea

    def fake_add_peer(cfg, name, peer_ip, public_key):
        registered.append((name, peer_ip, public_key))
        return True

    monkeypatch.setattr(ea, "add_peer", fake_add_peer)
    monkeypatch.setattr(ea, "persisted_config", lambda: __import__(
        "blastbox.host.egress", fromlist=["EgressConfig"]).EgressConfig())
    return cli.main(["egress", "peer-add", "--peer-ip", "10.77.0.3",
                     "--pki-dir", str(tmp_path / "pki"), *argv_extra])


def test_peer_add_takes_the_identity_and_key_from_the_cert(ca, tmp_path, monkeypatch):
    """The point of the whole exercise: registration becomes a signature check, and the
    operator supplies a file rather than retyping a key."""
    issued = ca.issue_node("toolz3", wg_pubkey=WG)
    cert = tmp_path / "toolz3.crt"
    cert.write_bytes(issued.cert_pem)

    got: list = []
    rc = _peer_add(monkeypatch, tmp_path, ["--cert", str(cert)], registered=got)
    assert rc == 0
    assert got == [("toolz3", "10.77.0.3", WG)]


def test_peer_add_refuses_a_cert_this_ca_did_not_sign(other_ca, ca, tmp_path, monkeypatch):
    foreign = tmp_path / "foreign.crt"
    foreign.write_bytes(other_ca.issue_node("attacker", wg_pubkey=WG2).cert_pem)

    got: list = []
    rc = _peer_add(monkeypatch, tmp_path, ["--cert", str(foreign)], registered=got)
    assert rc == 1
    assert got == [], "a foreign cert must register nothing"


def test_peer_add_refuses_a_name_that_contradicts_the_cert(ca, tmp_path, monkeypatch):
    """Otherwise an operator could register a verified key under someone else's name,
    and the wg config comment — the only human-readable trace — would lie."""
    cert = tmp_path / "toolz3.crt"
    cert.write_bytes(ca.issue_node("toolz3", wg_pubkey=WG).cert_pem)

    got: list = []
    rc = _peer_add(monkeypatch, tmp_path,
                   ["--cert", str(cert), "--name", "something-else"], registered=got)
    assert rc == 1 and got == []


def test_peer_add_still_accepts_a_raw_key_for_unenrolled_nodes(ca, tmp_path, monkeypatch):
    """The legacy path stays until every node is enrolled — but it is the fallback, not
    the default, and the output says the key is unauthenticated."""
    got: list = []
    rc = _peer_add(monkeypatch, tmp_path,
                   ["--name", "legacy", "--public-key", WG2], registered=got)
    assert rc == 0 and got == [("legacy", "10.77.0.3", WG2)]


def test_peer_add_requires_one_of_the_two_forms(ca, tmp_path, monkeypatch):
    got: list = []
    assert _peer_add(monkeypatch, tmp_path, [], registered=got) == 2
    assert got == []
