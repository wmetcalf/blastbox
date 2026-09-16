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
    with pytest.raises(ValueError, match="not a node identity"):
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


def test_a_node_cert_carries_no_standard_purpose_so_it_cannot_double_as_a_client_cert(ca):
    """Why the private arc exists at all: a node cert authorises WireGuard peering and
    federated placement, and nothing else. If it carried `clientAuth` it would also
    authenticate to the dispatcher's mTLS, so enrolling someone's hardware as a peer
    would hand them a control-plane credential.

    This used to assert that the string "NOT REGISTERED" appeared in the module source
    — true of any change to the OID handling as long as the comment survived. The
    property worth pinning is what the certificate permits.
    """
    from cryptography.x509.oid import ExtendedKeyUsageOID

    cert = x509.load_pem_x509_certificate(ca.issue_node('toolz3', wg_pubkey=WG).cert_pem)
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    oids = {u.dotted_string for u in eku}
    assert oids == {pki.OID_NODE_AUTH.dotted_string}, oids
    standard = {v.dotted_string for k, v in vars(ExtendedKeyUsageOID).items()
                if not k.startswith("_")}
    assert not (oids & standard), (
        f"a node cert must carry no standard EKU; got {oids & standard}"
    )


def test_the_node_eku_is_critical_so_a_verifier_cannot_ignore_it(ca):
    """A non-critical EKU may be skipped by a verifier that does not recognise it,
    which turns "authorised for nothing standard" into "unconstrained"."""
    cert = x509.load_pem_x509_certificate(ca.issue_node('toolz3', wg_pubkey=WG).cert_pem)
    assert cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).critical


def test_the_placeholder_oid_arc_is_still_the_documented_one():
    """1.3.6.1.4.1.99999 is not an IANA Private Enterprise Number. Acceptable for certs
    that never leave this CA, and not the moment they do — so a change to it should be
    deliberate, and this fails loudly when one happens."""
    assert pki.OID_NODE_AUTH.dotted_string.startswith("1.3.6.1.4.1.99999."), (
        "if this arc was replaced with a registered PEN, update the comment beside the "
        "constant and this test together"
    )


# ------------------------------------------------------------------- peer-add integration

def _peer_add(monkeypatch, tmp_path, argv_extra, *, registered):
    """Drive `blastbox egress peer-add` with the wg-writing side stubbed out."""
    from blastbox.host import cli
    from blastbox.host import egress_apply as ea

    def fake_add_peer(cfg, name, peer_ip, public_key, expires=None):
        registered.append((name, peer_ip, public_key))
        # The expiry must reach the registration, or the wg stanza outlives the cert
        # and "revocation is stop renewing" revokes nothing at the overlay.
        registered.append(("expires", expires))
        return True

    monkeypatch.setattr(ea, "add_peer", fake_add_peer)
    monkeypatch.setattr(ea, "persisted_config", lambda: __import__(
        "blastbox.host.egress", fromlist=["EgressConfig"]).EgressConfig())
    return cli.main(["egress", "peer-add", "--peer-ip", "10.77.0.3",
                     "--pki-dir", str(tmp_path / "pki"), *argv_extra])


def test_peer_add_takes_the_identity_and_key_from_the_cert(ca, tmp_path, monkeypatch):
    """The point of the whole exercise: registration becomes a signature check, and the
    operator supplies a file rather than retyping a key."""
    issued = ca.issue_node("toolz3", wg_pubkey=WG,
                           grants=NodeGrants(tiers=("openvpn",)))
    cert = tmp_path / "toolz3.crt"
    cert.write_bytes(issued.cert_pem)

    got: list = []
    rc = _peer_add(monkeypatch, tmp_path, ["--cert", str(cert)], registered=got)
    assert rc == 0
    assert got[0] == ("toolz3", "10.77.0.3", WG)
    assert got[1][0] == "expires" and got[1][1], "the cert expiry must be recorded"


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
    cert.write_bytes(ca.issue_node("toolz3", wg_pubkey=WG,
                                   grants=NodeGrants(tiers=("openvpn",))).cert_pem)

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
    assert rc == 0 and got[0] == ("legacy", "10.77.0.3", WG2)
    assert got[1] == ("expires", None), "a raw key has no expiry to enforce"


def test_peer_add_requires_one_of_the_two_forms(ca, tmp_path, monkeypatch):
    got: list = []
    assert _peer_add(monkeypatch, tmp_path, [], registered=got) == 2
    assert got == []


def test_peer_add_refuses_a_verified_node_with_no_overlay_grant(ca, tmp_path, monkeypatch):
    """Identity is not authorisation. A cert granting no overlay tier belongs to a node
    that was never meant to peer — local-mode, or enrolled for engine work only — and
    registering it anyway would let the signature check stand in for a policy decision."""
    cert = tmp_path / "engine-only.crt"
    cert.write_bytes(ca.issue_node("engine-only", wg_pubkey=WG,
                                   grants=NodeGrants(engines=("boxjs",))).cert_pem)

    got: list = []
    assert _peer_add(monkeypatch, tmp_path, ["--cert", str(cert)], registered=got) == 1
    assert got == []


def test_peer_add_accepts_an_overlay_granted_node(ca, tmp_path, monkeypatch):
    cert = tmp_path / "peer.crt"
    cert.write_bytes(ca.issue_node("toolz3", wg_pubkey=WG,
                                   grants=NodeGrants(tiers=("wireguard",))).cert_pem)
    got: list = []
    assert _peer_add(monkeypatch, tmp_path, ["--cert", str(cert)], registered=got) == 0
    assert got[0] == ("toolz3", "10.77.0.3", WG)
    assert got[1][0] == "expires" and got[1][1], "the cert expiry must be recorded"


def test_force_registers_an_ungranted_node_but_says_so(ca, tmp_path, monkeypatch, capsys):
    """The escape hatch stays — a rollout will have nodes enrolled before their grants
    are right — but the output must not read like a clean registration."""
    cert = tmp_path / "engine-only.crt"
    cert.write_bytes(ca.issue_node("engine-only", wg_pubkey=WG,
                                   grants=NodeGrants(engines=("boxjs",))).cert_pem)
    got: list = []
    rc = _peer_add(monkeypatch, tmp_path, ["--cert", str(cert), "--force"], registered=got)
    assert rc == 0 and got[0][0] == "engine-only"
    assert "NONE (--force)" in capsys.readouterr().out


# ------------------------------------------------- a node cert is not a transport cert

def test_a_node_cert_cannot_authenticate_as_the_dispatcher():
    """`tls.py` verifies the CA chain only — no EKU check, no CN check — so a node cert
    carrying `clientAuth` is accepted by every worker as the dispatcher's client cert.
    On a federated fleet that is privilege escalation: any registered third party could
    drive workers directly."""
    from cryptography import x509
    from cryptography.x509.oid import ExtendedKeyUsageOID

    import tempfile
    from pathlib import Path as _P

    ca_ = pki.ensure_ca(_P(tempfile.mkdtemp()))
    node = x509.load_pem_x509_certificate(
        ca_.issue_node("rando", wg_pubkey=WG).cert_pem)
    eku = list(node.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
    assert ExtendedKeyUsageOID.CLIENT_AUTH not in eku
    assert ExtendedKeyUsageOID.SERVER_AUTH not in eku
    assert pki.OID_NODE_AUTH in eku
    # ...and critical, so a verifier that does not understand it refuses rather than
    # treating the cert as a general-purpose leaf.
    assert node.extensions.get_extension_for_class(x509.ExtendedKeyUsage).critical


def test_a_dispatcher_cert_is_refused_as_a_node_identity(ca):
    with pytest.raises(ValueError, match="not a node identity"):
        pki.node_identity(ca, ca.issue_client("dispatcher").cert_pem)


def test_a_worker_server_cert_is_refused_as_a_node_identity(ca):
    with pytest.raises(ValueError, match="not a node identity"):
        pki.node_identity(ca, ca.issue_server(["10.0.0.1"]).cert_pem)


def test_a_wireguard_key_must_decode_to_exactly_32_bytes(ca):
    """A character-shape regex accepts a 43-char unpadded value, or 44 unpadded chars
    decoding to 33 bytes. Such a key passed issuance, was SIGNED into a certificate, and
    passed again on the way into the WireGuard config — poisoning the interface instead
    of producing an immediate CLI error."""
    import base64

    assert len(base64.b64decode(WG)) == 32
    ca.issue_node("ok", wg_pubkey=WG)                      # a real key still works

    for bad in ("A" * 43, "A" * 44, "A" * 40 + "=", "not base64 at all!!"):
        with pytest.raises(ValueError, match="32-byte"):
            ca.issue_node("x", wg_pubkey=bad)


def test_the_exit_host_stanza_also_refuses_an_out_of_overlay_address():
    """The overlay check was added to the PEER's own config and not to the exit host's
    stanza — and the exit host is the side that matters, since its source route and
    BB-WG-EXIT chain both match the overlay prefix."""
    from blastbox.host.egress import EgressConfig, gateway_peer_stanza

    cfg = EgressConfig(mode="global", upstream_gw="10.77.0.1")
    with pytest.raises(ValueError, match="outside the overlay"):
        gateway_peer_stanza("toolz3", "10.78.0.3", WG, None, cfg)
    assert "AllowedIPs = 10.77.0.3/32" in gateway_peer_stanza(
        "toolz3", "10.77.0.3", WG, None, cfg)


def test_verifying_a_node_cert_needs_only_the_public_half(ca, tmp_path):
    """`egress peer-add --cert` checks a signature. The only loader was `load_ca`,
    which reads ca.key and raises without it — so an operation that verifies required
    the key that MINTS every node identity to be present on the exit host, the machine
    carrying every peer's traffic, contradicting CertAuthority's own docstring."""
    issued = ca.issue_node("toolz3", wg_pubkey=WG, grants=NodeGrants(tiers=("wireguard",)))

    # An exit host that holds ca.crt and NOTHING else.
    exit_pki = tmp_path / "exit-pki"
    exit_pki.mkdir()
    (exit_pki / "ca.crt").write_bytes(pki.load_trust_anchor(tmp_path / "pki").cert_pem)
    assert not (exit_pki / "ca.key").exists()

    ident = pki.node_identity(pki.load_trust_anchor(exit_pki), issued.cert_pem)
    assert ident.node_id == "toolz3"
    assert ident.wg_pubkey == WG

    # And it is still a real check, not a parse.
    with pytest.raises(ValueError):
        pki.node_identity(pki.load_trust_anchor(exit_pki),
                          pki.ensure_ca(tmp_path / "rogue").issue_node(
                              "toolz3", wg_pubkey=WG).cert_pem)


def test_a_trust_anchor_cannot_issue_anything():
    """It must be the public half, not a CertAuthority with a missing attribute."""
    assert not hasattr(pki.TrustAnchor, "issue_node")
    assert not hasattr(pki.TrustAnchor, "key_pem")
