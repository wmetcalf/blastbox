"""Two ingress hosts, one queue, one key (#178).

Before this, each host generated its own signing key and a node's handshake failed whenever the
challenge and the session landed on different hosts behind a load balancer. The file knob made it
correct only if an operator shared a file — and the role-separated topology rejects a shared
filesystem. Now the hosts agree through the job store, which they share by definition.
"""
from __future__ import annotations

import base64

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from blastbox.host import node_auth, pki
from blastbox.host.ingress.node_claim import SESSION_HEADER, register_node_claim_routes
from blastbox.host.jobs.memory import InMemoryJobStore

WG = "A" * 42 + "B="


def _host(tmp_path, name, store, *, enrol=None):
    """An ingress host with its OWN pki directory — the shape that used to diverge."""
    d = tmp_path / name
    ca = pki.ensure_ca(d) if enrol is None else enrol
    d.mkdir(exist_ok=True)
    (d / "ca.crt").write_bytes(ca.cert_pem)
    # Each ingress host holds the node certificates, exactly as enrolment copies them: grants are
    # resolved from THIS host's certificate store, so a host without them refuses correctly.
    for crt in (tmp_path / "issuer").glob("node-*.crt"):
        (d / crt.name).write_bytes(crt.read_bytes())
    app = FastAPI()
    assert register_node_claim_routes(app, job_store=store, pki_dir=d) is True
    return TestClient(app), d


@pytest.fixture
def fleet(tmp_path, monkeypatch):
    monkeypatch.delenv(node_auth.SECRET_FILE_ENV, raising=False)
    store = InMemoryJobStore()
    ca = pki.ensure_ca(tmp_path / "issuer")
    ca.issue_node("alpha", wg_pubkey=WG, grants=pki.NodeGrants(engines=("clamav",))).write(
        tmp_path / "issuer", "node-alpha")
    a, _ = _host(tmp_path, "hostA", store, enrol=ca)
    b, _ = _host(tmp_path, "hostB", store, enrol=ca)
    return a, b, tmp_path / "issuer", store


def _session_on(c, issuer, challenge):
    sig = base64.b64encode(node_auth.sign_claim(
        (issuer / "node-alpha.key").read_bytes(), challenge,
        node_auth.SCOPE_CLAIM_NEXT, "alpha")).decode()
    return c.post("/v1/nodes/session", json={
        "cert_pem": (issuer / "node-alpha.crt").read_text(),
        "challenge": challenge, "signature": sig})


def test_a_challenge_from_one_host_is_redeemable_on_the_other(fleet):
    """THE LOAD-BALANCER CASE. Challenge from A, session on B."""
    a, b, issuer, _ = fleet
    ch = a.get("/v1/nodes/challenge").json()["challenge"]
    r = _session_on(b, issuer, ch)
    assert r.status_code == 200, r.text


def test_a_session_from_one_host_is_honoured_on_the_other(fleet):
    a, b, issuer, _ = fleet
    ch = a.get("/v1/nodes/challenge").json()["challenge"]
    tok = _session_on(a, issuer, ch).json()["token"]
    r = b.post("/v1/nodes/claim", json={"engine": "clamav"}, headers={SESSION_HEADER: tok})
    assert r.status_code in (200, 204), r.text     # authenticated; queue happens to be empty


def test_the_store_holds_exactly_one_key_for_the_fleet(fleet):
    _a, _b, _issuer, store = fleet
    assert store.get_signing_key() is not None


def test_hosts_that_do_not_share_a_store_still_diverge(tmp_path, monkeypatch):
    """Not a regression test — a statement of what the store is FOR. Two stores, two keys."""
    monkeypatch.delenv(node_auth.SECRET_FILE_ENV, raising=False)
    ca = pki.ensure_ca(tmp_path / "issuer")
    ca.issue_node("alpha", wg_pubkey=WG, grants=pki.NodeGrants(engines=("clamav",))).write(
        tmp_path / "issuer", "node-alpha")
    a, _ = _host(tmp_path, "hostA", InMemoryJobStore(), enrol=ca)
    b, _ = _host(tmp_path, "hostB", InMemoryJobStore(), enrol=ca)
    ch = a.get("/v1/nodes/challenge").json()["challenge"]
    # 403, not 401: a challenge that fails its MAC is refused at the handshake. 401 is reserved
    # for a bad SESSION token, which is the only case a client should re-handshake on.
    assert _session_on(b, tmp_path / "issuer", ch).status_code == 403


def test_an_explicit_file_override_outranks_the_store(tmp_path, monkeypatch):
    """An operator who set the variable said so. Both hosts read the file, not the store, and
    the store is left untouched."""
    shared = tmp_path / "shared.key"
    monkeypatch.setenv(node_auth.SECRET_FILE_ENV, str(shared))
    store = InMemoryJobStore()
    ca = pki.ensure_ca(tmp_path / "issuer")
    ca.issue_node("alpha", wg_pubkey=WG, grants=pki.NodeGrants(engines=("clamav",))).write(
        tmp_path / "issuer", "node-alpha")
    a, _ = _host(tmp_path, "hostA", store, enrol=ca)
    b, _ = _host(tmp_path, "hostB", store, enrol=ca)
    assert store.get_signing_key() is None, "the override was ignored and the store consulted"
    ch = a.get("/v1/nodes/challenge").json()["challenge"]
    assert _session_on(b, tmp_path / "issuer", ch).status_code == 200


def test_an_unconfirmed_claim_fails_closed_at_registration(tmp_path):
    """None from the registry means UNKNOWN. Generating a local key there would sign with a key
    no peer holds — the split, produced by the machinery meant to prevent it."""

    class Unreadable(InMemoryJobStore):
        def claim_signing_key(self, candidate):
            return None

    d = tmp_path / "pki"
    pki.ensure_ca(d)
    with pytest.raises(RuntimeError, match="could not confirm"):
        register_node_claim_routes(FastAPI(), job_store=Unreadable(), pki_dir=d)


def test_a_store_without_the_registry_falls_back_to_the_file_and_says_so(tmp_path, caplog,
                                                                         monkeypatch):
    """Only a third-party store lands here. It must warn that a second host will not interoperate,
    so the old failure is at least announced."""
    monkeypatch.delenv(node_auth.SECRET_FILE_ENV, raising=False)

    class Bare:
        """Satisfies what the routes call, implements no registry."""
        def claim_next(self, **kw):
            return None
        def get(self, job_id):
            return None
        def update(self, job_id, **f):
            raise KeyError(job_id)
        def update_if_status(self, *a, **k):
            return False
        def count(self, *a, **k):
            return 0

    d = tmp_path / "pki"
    pki.ensure_ca(d)
    with caplog.at_level("WARNING"):
        assert register_node_claim_routes(FastAPI(), job_store=Bare(), pki_dir=d) is True
    assert any("per-host file" in r.message for r in caplog.records), caplog.text
