from __future__ import annotations

import base64

from fastapi import FastAPI
from fastapi.testclient import TestClient

from blastbox.host import node_auth, node_renew, pki
from blastbox.host.ingress.node_claim import SESSION_HEADER, register_node_claim_routes
from blastbox.host.jobs.memory import InMemoryJobStore
from tests.host.test_node_renew import GRANTS, make_csr


def _setup(tmp_path, monkeypatch, nodes=("n1",)):
    monkeypatch.delenv(node_auth.SECRET_FILE_ENV, raising=False)
    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    keys = {}
    for n in nodes:
        csr, key = make_csr(n)
        (d / f"node-{n}.crt").write_bytes(ca.sign_node_csr(csr, node_id=n, grants=GRANTS))
        keys[n] = key
    app = FastAPI()
    assert register_node_claim_routes(app, job_store=InMemoryJobStore(), pki_dir=d)
    return TestClient(app), d, ca, keys


_DUMMY = {"csr_pem": "x", "cert_pem": "x", "issued_at": 0, "signature": "x"}


def _queue(d, ca, node, key, csr):
    import time
    at = int(time.time())
    node_renew.queue_csr(d, node, csr, cert_pem=(d / f"node-{node}.crt").read_bytes(),
                         issued_at=at,
                         signature=node_renew.sign_renew_proof(key, node, csr.decode(), at))


def _session(c, d, node, key, cert_path=None):
    from cryptography.hazmat.primitives import serialization
    ch = c.get("/v1/nodes/challenge").json()["challenge"]
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    sig = base64.b64encode(node_auth.sign_claim(
        pem, ch, node_auth.SCOPE_CLAIM_NEXT, node)).decode()
    cert = (cert_path or d / f"node-{node}.crt").read_text()
    r = c.post("/v1/nodes/session", json={"cert_pem": cert, "challenge": ch, "signature": sig})
    assert r.status_code == 200, r.text
    return {SESSION_HEADER: r.json()["token"]}


def test_renew_requires_session(tmp_path, monkeypatch):
    c, d, _, _ = _setup(tmp_path, monkeypatch)
    assert c.post("/v1/nodes/renew", json=_DUMMY).status_code == 401
    assert c.get("/v1/nodes/cert").status_code == 401


def _body(d, node, key, csr: bytes, *, at=None, signer=None, cert_name=None):
    import time
    at = int(time.time()) if at is None else at
    return {"csr_pem": csr.decode(),
            "cert_pem": (d / (cert_name or f"node-{node}.crt")).read_text(),
            "issued_at": at,
            "signature": node_renew.sign_renew_proof(signer or key, node, csr.decode(), at)}


def test_renew_queues_202(tmp_path, monkeypatch):
    import json
    c, d, _, keys = _setup(tmp_path, monkeypatch)
    h = _session(c, d, "n1", keys["n1"])
    csr, _ = make_csr("n1")
    r = c.post("/v1/nodes/renew", json=_body(d, "n1", keys["n1"], csr), headers=h)
    assert r.status_code == 202 and r.json() == {"queued": True}
    assert json.loads((d / "renew" / "n1.csr").read_bytes())["csr_pem"] == csr.decode()
    bad, _ = make_csr("n2")
    r = c.post("/v1/nodes/renew", json=_body(d, "n1", keys["n1"], bad), headers=h)
    assert r.status_code == 400


def test_renew_without_a_proof_is_422_and_queues_nothing(tmp_path, monkeypatch):
    c, d, _, keys = _setup(tmp_path, monkeypatch)
    h = _session(c, d, "n1", keys["n1"])
    csr, _ = make_csr("n1")
    assert c.post("/v1/nodes/renew", json={"csr_pem": csr.decode()},
                  headers=h).status_code == 422
    assert not (d / "renew" / "n1.csr").exists()


def test_renew_with_a_session_but_another_key_is_403(tmp_path, monkeypatch):
    """A stolen session token is not enough: the proof needs the cert's key."""
    from cryptography.hazmat.primitives.asymmetric import ec
    c, d, _, keys = _setup(tmp_path, monkeypatch)
    h = _session(c, d, "n1", keys["n1"])
    csr, _ = make_csr("n1")
    thief = ec.generate_private_key(ec.SECP256R1())
    r = c.post("/v1/nodes/renew", json=_body(d, "n1", keys["n1"], csr, signer=thief),
               headers=h)
    assert r.status_code == 403 and r.json()["detail"] == "not authorised to claim this work"
    assert not (d / "renew" / "n1.csr").exists()


def test_renew_with_another_nodes_cert_is_403(tmp_path, monkeypatch):
    c, d, _, keys = _setup(tmp_path, monkeypatch, nodes=("n1", "n2"))
    h = _session(c, d, "n1", keys["n1"])
    csr, _ = make_csr("n1")
    r = c.post("/v1/nodes/renew",
               json=_body(d, "n1", keys["n2"], csr, cert_name="node-n2.crt"), headers=h)
    assert r.status_code == 403


def test_renew_with_a_stale_proof_is_400(tmp_path, monkeypatch):
    import time
    c, d, _, keys = _setup(tmp_path, monkeypatch)
    h = _session(c, d, "n1", keys["n1"])
    csr, _ = make_csr("n1")
    r = c.post("/v1/nodes/renew",
               json=_body(d, "n1", keys["n1"], csr, at=int(time.time()) - 301), headers=h)
    assert r.status_code == 400 and "issued_at" in r.json()["detail"]


def test_renew_issued_at_must_be_a_json_integer(tmp_path, monkeypatch):
    c, d, _, keys = _setup(tmp_path, monkeypatch)
    h = _session(c, d, "n1", keys["n1"])
    csr, _ = make_csr("n1")
    body = _body(d, "n1", keys["n1"], csr)
    body["issued_at"] = str(body["issued_at"])
    assert c.post("/v1/nodes/renew", json=body, headers=h).status_code == 422


def test_cert_route_returns_latest(tmp_path, monkeypatch):
    c, d, ca, keys = _setup(tmp_path, monkeypatch, nodes=("n1", "n2"))
    h = _session(c, d, "n1", keys["n1"])
    # a second, shorter-lived cert for the same node sits beside the live one; the
    # route must return the one with the later not_after.
    csr0, _k = make_csr("n1")
    short = ca.sign_node_csr(csr0, node_id="n1", grants=GRANTS, days=1)
    (d / "old-n1.crt").write_bytes(short)
    new_key_csr, new_key = make_csr("n1")
    _queue(d, ca, "n1", keys["n1"], new_key_csr)
    assert node_renew.sign_pending(ca, d) == [("n1", "renewed")]
    r = c.get("/v1/nodes/cert", headers=h)
    assert r.status_code == 200
    body = r.json()
    assert body["cert_pem"].encode() == node_renew.current_cert(d, "n1")
    assert body["cert_pem"] == (d / "node-n1.crt").read_text()
    assert body["not_after"]
    assert body["cert_pem"].encode() != short
    import datetime
    assert datetime.datetime.fromisoformat(body["not_after"]) > (
        pki.node_identity(pki.load_trust_anchor(d), short).not_after)
    # never another node's cert (parse it: "n2" can occur in random base64)
    ident = pki.node_identity(pki.load_trust_anchor(d), body["cert_pem"].encode())
    assert ident.node_id == "n1"
    assert body["cert_pem"] != (d / "node-n2.crt").read_text()


def test_old_cert_session_still_works_until_it_expires(tmp_path, monkeypatch):
    c, d, ca, keys = _setup(tmp_path, monkeypatch)
    old_copy = d.parent / "old.crt"           # outside the PKI dir, as on the node
    old_copy.write_bytes((d / "node-n1.crt").read_bytes())
    csr, new_key = make_csr("n1")
    _queue(d, ca, "n1", keys["n1"], csr)
    node_renew.sign_pending(ca, d)
    h = _session(c, d, "n1", keys["n1"], cert_path=old_copy)
    assert c.get("/v1/nodes/cert", headers=h).status_code == 200
    h2 = _session(c, d, "n1", new_key)
    assert c.get("/v1/nodes/cert", headers=h2).status_code == 200


def test_cert_404_when_revoked_is_403(tmp_path, monkeypatch):
    c, d, _, keys = _setup(tmp_path, monkeypatch)
    h = _session(c, d, "n1", keys["n1"])
    (d / "node-n1.crt").unlink()
    assert c.get("/v1/nodes/cert", headers=h).status_code == 403
    assert c.post("/v1/nodes/renew", json=_DUMMY, headers=h).status_code == 403


def test_cert_route_store_read_fault_is_503_not_404(tmp_path, monkeypatch):
    c, d, _, keys = _setup(tmp_path, monkeypatch)
    h = _session(c, d, "n1", keys["n1"])

    def boom(*_a):
        raise OSError("EIO")
    monkeypatch.setattr(node_renew, "_find_current", boom)
    assert c.get("/v1/nodes/cert", headers=h).status_code == 503
