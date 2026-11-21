from __future__ import annotations

import base64
import http.client
import io
import json
import logging
import os
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from email.message import Message

import pytest

from blastbox.engines.rea import model_gateway as mg

NOW = 1_800_000_000
SYN_GRANT_KEY = "sk-or-v1-SYNTHETIC-grant-key-0001"
SYN_ANTH_KEY = "sk-ant-SYNTHETIC-grant-key-0002"
SYN_OP_KEY = "sk-or-v1-SYNTHETIC-operator-key-0003"
OR_PATH = "/api/v1/chat/completions"
AN_PATH = "/anthropic/v1/chat/completions"
# The gateway's own rejection, byte for byte: the agent tells it from a provider 401 by the code.
GRANT_REJECTED = b'{"error":{"code":"rea_grant_rejected","message":"grant rejected"}}'


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _keypair() -> tuple[bytes, bytes]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    priv = X25519PrivateKey.generate()
    raw = priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return raw, pub


GW_PRIV, GW_PUB = _keypair()


def _seal(claims: dict) -> str:
    """Test-local sealer following the wire format."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    info = b"rea-model-grant/1"
    eph = X25519PrivateKey.generate()
    epk = eph.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    shared = eph.exchange(X25519PublicKey.from_public_bytes(GW_PUB))
    k = HKDF(hashes.SHA256(), 32, epk + GW_PUB, info).derive(shared)
    nonce = os.urandom(12)
    pt = json.dumps(claims, separators=(",", ":")).encode()
    return "g1." + _b64e(epk + nonce + AESGCM(k).encrypt(nonce, pt, info))


def _grant(provider: str = "openrouter", model: str = "vendor/model-a",
           key: str = SYN_GRANT_KEY, exp: int = NOW + 3600) -> str:
    return _seal({"v": 1, "job": "job-1", "provider": provider, "model": model,
                  "key": key, "exp": exp})


class FakeOpener:
    def __init__(self, status: int = 200, body: bytes = b'{"ok":true}',
                 error: Exception | None = None) -> None:
        self.requests: list[urllib.request.Request] = []
        self.status = status
        self.body = body
        self.error = error

    def open(self, req: urllib.request.Request, timeout: float | None = None):
        self.requests.append(req)
        if self.error is not None:
            raise self.error
        hdrs = Message()
        hdrs["Content-Type"] = "application/json"
        if self.status >= 400:
            raise urllib.error.HTTPError(
                req.full_url, self.status, "err", hdrs, io.BytesIO(self.body)
            )
        resp = io.BytesIO(self.body)
        resp.status = self.status  # type: ignore[attr-defined]
        resp.headers = hdrs  # type: ignore[attr-defined]
        return resp

    def hdr(self, name: str) -> str | None:
        req = self.requests[-1]
        for k, v in req.header_items():
            if k.lower() == name.lower():
                return v
        return None


@pytest.fixture
def gw() -> Iterator:
    servers = []

    def start(opener: FakeOpener, operator_keys: dict[str, str] | None = None,
              private_key: bytes | None = GW_PRIV, require_grant: bool = False):
        cfg = mg.GatewayConfig(
            private_key=private_key,
            operator_keys=operator_keys or {},
            upstream={"openrouter": "https://up.invalid/or",
                      "anthropic": "https://up.invalid/an"},
            opener=opener,
            now=lambda: NOW,
            require_grant=require_grant,
        )
        srv = mg.make_server(cfg, ("127.0.0.1", 0))
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        servers.append(srv)
        return srv.server_address[1]

    yield start
    for s in servers:
        s.shutdown()
        s.server_close()


def _call(port: int, path: str = OR_PATH, body: object = None,
          grant: str | None = None, method: str = "POST",
          extra: dict[str, str] | None = None) -> tuple[int, bytes]:
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Content-Type": "application/json"}
    if grant is not None:
        headers["X-Rea-Grant"] = grant
    headers.update(extra or {})
    data = None if body is None else json.dumps(body).encode()
    if data is None and method == "POST":
        data = b""
    c.request(method, path, body=data, headers=headers)
    r = c.getresponse()
    out = r.read()
    c.close()
    return r.status, out


def _body(model: str = "vendor/model-a", **kw) -> dict:
    return {"model": model, "messages": [{"role": "user", "content": "hi"}], **kw}


def test_grant_injects_its_key_and_forces_zdr(gw):
    op = FakeOpener()
    port = gw(op, {"openrouter": SYN_OP_KEY})
    st, out = _call(port, body=_body(provider={"zdr": False, "data_collection": "allow",
                                              "only": ["x"]}),
                    grant=_grant(),
                    extra={"Cookie": "c=1", "X-Forwarded-For": "1.2.3.4",
                           "Authorization": "Bearer client"})
    assert st == 200 and out == b'{"ok":true}'
    req = op.requests[0]
    sent = json.loads(req.data)
    assert sent["provider"] == {"zdr": True, "data_collection": "deny", "only": ["x"]}
    assert sent["model"] == "vendor/model-a"
    assert op.hdr("Authorization") == f"Bearer {SYN_GRANT_KEY}"
    assert op.hdr("X-Title") == "loadout-rea"
    assert op.hdr("Content-Type") == "application/json"
    for h in ("Cookie", "X-Forwarded-For", "X-Rea-Grant"):
        assert op.hdr(h) is None
    assert req.full_url == "https://up.invalid/or"


def test_zdr_forced_when_provider_absent(gw):
    op = FakeOpener()
    port = gw(op)
    st, _ = _call(port, body=_body(), grant=_grant())
    assert st == 200
    assert json.loads(op.requests[0].data)["provider"] == {
        "zdr": True, "data_collection": "deny"}


def test_grant_model_mismatch_is_400_without_upstream_call(gw):
    op = FakeOpener()
    port = gw(op, {"openrouter": SYN_OP_KEY})
    st, out = _call(port, body=_body(model="vendor/pricey-b"), grant=_grant())
    assert st == 400
    assert json.loads(out) == {"error": {"message": "model not granted"}}
    st2, _ = _call(port, body=["not", "an", "object"], grant=_grant())
    assert st2 == 400
    assert op.requests == []


@pytest.mark.parametrize("token", [
    "garbage",
    "expired",
    "wrong-route",
    "oversize",
])
def test_bad_grant_is_401_and_never_uses_operator_key(gw, token):
    tok = {
        "garbage": "g1.AAAA",
        "expired": _grant(exp=NOW - 1),
        "wrong-route": _grant(provider="anthropic"),
        "oversize": "g1." + "A" * 5000,
    }[token]
    op = FakeOpener()
    port = gw(op, {"openrouter": SYN_OP_KEY})
    st, out = _call(port, body=_body(), grant=tok)
    assert st == 401
    assert out == GRANT_REJECTED
    assert op.requests == []


def test_grant_without_private_key_is_401(gw):
    op = FakeOpener()
    port = gw(op, {"openrouter": SYN_OP_KEY}, private_key=None)
    st, out = _call(port, body=_body(), grant=_grant())
    assert st == 401 and out == GRANT_REJECTED
    assert op.requests == []


def test_no_grant_uses_operator_key(gw):
    op = FakeOpener()
    port = gw(op, {"openrouter": SYN_OP_KEY})
    st, _ = _call(port, body=_body(provider={"zdr": False}))
    assert st == 200
    assert op.hdr("Authorization") == f"Bearer {SYN_OP_KEY}"
    assert json.loads(op.requests[0].data)["provider"] == {
        "zdr": True, "data_collection": "deny"}


def test_no_grant_no_operator_key_is_401(gw):
    op = FakeOpener()
    port = gw(op, {"anthropic": "sk-ant-SYNTHETIC-op"})
    st, out = _call(port, body=_body())
    assert st == 401 and out == GRANT_REJECTED
    assert op.requests == []


def test_anthropic_headers(gw):
    op = FakeOpener()
    port = gw(op)
    st, _ = _call(port, path=AN_PATH, body=_body(model="claude-x"),
                  grant=_grant(provider="anthropic", model="claude-x",
                               key=SYN_ANTH_KEY),
                  extra={"Authorization": "Bearer client"})
    assert st == 200
    assert op.hdr("x-api-key") == SYN_ANTH_KEY
    assert op.hdr("anthropic-version") == "2023-06-01"
    assert op.hdr("Authorization") is None
    assert op.hdr("X-Rea-Grant") is None
    sent = json.loads(op.requests[0].data)
    assert "provider" not in sent
    assert op.requests[0].full_url == "https://up.invalid/an"


def test_upstream_402_relayed(gw):
    body = b'{"error":{"message":"insufficient credits","code":402}}'
    op = FakeOpener(status=402, body=body)
    port = gw(op)
    st, out = _call(port, body=_body(), grant=_grant())
    assert st == 402 and out == body


def test_upstream_connection_failure_is_502(gw):
    op = FakeOpener(error=urllib.error.URLError("refused"))
    port = gw(op)
    st, _ = _call(port, body=_body(), grant=_grant())
    assert st == 502


def test_unknown_path_and_get_are_403(gw):
    op = FakeOpener()
    port = gw(op, {"openrouter": SYN_OP_KEY})
    assert _call(port, path="/v1/models", body=_body())[0] == 403
    assert _call(port, path=OR_PATH, method="GET")[0] == 403
    assert _call(port, path=OR_PATH + "?x=1", body=_body())[0] == 403
    assert op.requests == []


def test_oversize_body_is_413(gw):
    op = FakeOpener()
    port = gw(op, {"openrouter": SYN_OP_KEY})
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.putrequest("POST", OR_PATH)
    c.putheader("Content-Length", str(16 * 1024 * 1024 + 1))
    c.endheaders()
    r = c.getresponse()
    assert r.status == 413
    c.close()
    assert op.requests == []


def test_missing_content_length_is_411(gw):
    op = FakeOpener()
    port = gw(op, {"openrouter": SYN_OP_KEY})
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.putrequest("POST", OR_PATH, skip_accept_encoding=True)
    c.endheaders()
    assert c.getresponse().status == 411
    c.close()
    assert op.requests == []


def test_logs_carry_no_secret(gw, caplog, capsys):
    caplog.set_level(logging.DEBUG)
    op = FakeOpener()
    port = gw(op, {"openrouter": SYN_OP_KEY})
    tok = _grant()
    _call(port, body=_body(), grant=tok)
    _call(port, body=_body(model="other"), grant=tok)
    _call(port, body=_body(), grant=_grant(exp=NOW - 5))
    _call(port, body=_body())
    _call(port, path=OR_PATH + "?k=" + SYN_OP_KEY, body=_body())
    cap = capsys.readouterr()
    logs = caplog.text + cap.out + cap.err
    assert OR_PATH in logs  # the per-request line is emitted
    for secret in (tok, SYN_GRANT_KEY, SYN_OP_KEY, "hi"):
        assert secret not in logs


def test_request_log_names_the_grant_job_and_nothing_secret(gw, caplog):
    caplog.set_level(logging.INFO, logger="blastbox.rea.model_gateway")
    op = FakeOpener()
    port = gw(op, {"openrouter": SYN_OP_KEY})
    tok = _seal({"v": 1, "job": "job-77", "provider": "openrouter",
                 "model": "vendor/model-a", "key": SYN_GRANT_KEY, "exp": NOW + 60})
    assert _call(port, body=_body(), grant=tok)[0] == 200
    assert _call(port, body=_body())[0] == 200
    lines = [r.getMessage() for r in caplog.records
             if r.name == "blastbox.rea.model_gateway"]
    assert len(lines) == 2
    assert lines[0].startswith(f"POST {OR_PATH} 200 ") and lines[0].endswith(" job=job-77")
    assert "job=" not in lines[1]  # operator path: no grant, no job
    for line in lines:
        assert tok not in line and SYN_GRANT_KEY not in line and SYN_OP_KEY not in line


def test_operator_key_file_hardening(tmp_path, monkeypatch):
    good = tmp_path / "or.key"
    good.write_text(SYN_OP_KEY + "\n")
    good.chmod(0o400)
    assert mg.read_operator_key(str(good)) == SYN_OP_KEY
    loose = tmp_path / "loose.key"
    loose.write_text(SYN_OP_KEY)
    loose.chmod(0o644)
    with pytest.raises(ValueError) as ei:
        mg.read_operator_key(str(loose))
    assert SYN_OP_KEY not in str(ei.value)
    with pytest.raises(ValueError):
        mg.read_operator_key(str(tmp_path / "missing"))
    monkeypatch.setenv("REA_GW_OPERATOR_KEY_FILE_OPENROUTER", str(good))
    monkeypatch.delenv("REA_GW_OPERATOR_KEY_FILE_ANTHROPIC", raising=False)
    assert mg.operator_keys_from_env() == {"openrouter": SYN_OP_KEY}


def test_production_opener_refuses_redirects_and_ignores_proxy_env(monkeypatch):
    monkeypatch.setenv("https_proxy", "http://proxy.invalid:3128")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    op = mg.production_opener()
    kinds = {type(h) for h in op.handlers}
    assert mg._NoRedirect in kinds
    assert urllib.request.HTTPRedirectHandler not in kinds
    # An empty ProxyHandler registers no proxy_open, and suppresses the default
    # env-reading one, so no handler routes through a proxy.
    assert not [h for h in op.handlers if isinstance(h, urllib.request.ProxyHandler)]
    assert "https_open" in {m for h in op.handlers for m in dir(h)}


# --- review fixes: model pinning, require-grant, request hygiene ---


@pytest.mark.parametrize("extra", [
    {"models": ["vendor/model-a", "vendor/pricey-b"]},
    {"models": ["vendor/pricey-b"]},
    {"models": "vendor/model-a"},
    {"route": "fallback"},
    {"route": None},
    {"plugins": [{"id": "web"}]},
    {"plugins": []},
])
def test_grant_refuses_fallback_routing_and_plugins(gw, extra):
    op = FakeOpener()
    port = gw(op, {"openrouter": SYN_OP_KEY})
    st, out = _call(port, body=_body(**extra), grant=_grant())
    assert st == 400
    assert json.loads(out) == {"error": {"message": "model not granted"}}
    assert op.requests == []


def test_grant_models_exactly_the_granted_model_is_forwarded(gw):
    op = FakeOpener()
    port = gw(op)
    st, _ = _call(port, body=_body(models=["vendor/model-a"]), grant=_grant())
    assert st == 200
    assert json.loads(op.requests[0].data)["models"] == ["vendor/model-a"]


def test_require_grant_refuses_operator_fallback(gw):
    op = FakeOpener()
    port = gw(op, {"openrouter": SYN_OP_KEY}, require_grant=True)
    st, out = _call(port, body=_body())
    assert st == 401 and out == GRANT_REJECTED
    assert op.requests == []
    st2, _ = _call(port, body=_body(), grant=_grant())
    assert st2 == 200
    assert op.hdr("Authorization") == f"Bearer {SYN_GRANT_KEY}"


def test_require_grant_env(monkeypatch):
    monkeypatch.setenv("REA_GW_REQUIRE_GRANT", "1")
    assert mg.require_grant_from_env() is True
    monkeypatch.setenv("REA_GW_REQUIRE_GRANT", "0")
    assert mg.require_grant_from_env() is False
    monkeypatch.delenv("REA_GW_REQUIRE_GRANT")
    assert mg.require_grant_from_env() is False
    monkeypatch.setenv("REA_GW_REQUIRE_GRANT", "yes")
    with pytest.raises(ValueError):
        mg.require_grant_from_env()


def _raw(port: int, head: bytes, body: bytes = b"") -> int:
    import socket

    with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
        s.sendall(head + b"\r\n" + body)
        data = b""
        while b"\r\n" not in data:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    return int(data.split(b" ", 2)[1])


@pytest.mark.parametrize("headers, want", [
    (b"Transfer-Encoding: chunked\r\n", 411),
    (b"Transfer-Encoding: chunked\r\nContent-Length: 2\r\n", 411),
    (b"Content-Length: 2\r\nContent-Length: 2\r\n", 400),
    (b"Content-Length: 1e3\r\n", 400),
    (b"Content-Length: -2\r\n", 400),
])
def test_request_framing(gw, headers, want):
    op = FakeOpener()
    port = gw(op, {"openrouter": SYN_OP_KEY})
    head = b"POST " + OR_PATH.encode() + b" HTTP/1.1\r\nHost: x\r\n" + headers
    assert _raw(port, head, b"{}") == want
    assert op.requests == []


def test_query_string_and_head_are_403(gw):
    op = FakeOpener()
    port = gw(op, {"openrouter": SYN_OP_KEY})
    assert _call(port, path=OR_PATH + "?a=b", body=_body())[0] == 403
    assert _call(port, path=OR_PATH, method="HEAD")[0] == 403
    assert op.requests == []


@pytest.mark.parametrize("body", [
    {"messages": []},
    "a string",
    [{"model": "vendor/model-a"}],
    None,
])
def test_grant_body_without_model_or_not_object_is_400(gw, body):
    op = FakeOpener()
    port = gw(op, {"openrouter": SYN_OP_KEY})
    st, out = _call(port, body=body, grant=_grant())
    assert st == 400
    assert json.loads(out) == {"error": {"message": "model not granted"}}
    assert op.requests == []


@pytest.mark.parametrize("const", ["NaN", "Infinity", "-Infinity"])
@pytest.mark.parametrize("granted", [True, False])
def test_non_finite_numbers_are_400(gw, const, granted):
    op = FakeOpener()
    port = gw(op, {"openrouter": SYN_OP_KEY})
    raw = ('{"model":"vendor/model-a","temperature":%s}' % const).encode()
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    hdrs = {"Content-Type": "application/json"}
    if granted:
        hdrs["X-Rea-Grant"] = _grant()
    c.request("POST", OR_PATH, body=raw, headers=hdrs)
    assert c.getresponse().status == 400
    c.close()
    assert op.requests == []


def test_main_bind_failure_exits_2_without_traceback(monkeypatch, capsys, caplog):
    import socket

    held = socket.socket()
    held.bind(("127.0.0.1", 0))
    held.listen(1)
    try:
        port = held.getsockname()[1]
        monkeypatch.setenv("REA_GW_LISTEN", f"127.0.0.1:{port}")
        for v in ("REA_GW_PRIVATE_KEY_FILE", "REA_GW_OPERATOR_KEY_FILE_OPENROUTER",
                  "REA_GW_OPERATOR_KEY_FILE_ANTHROPIC", "REA_GW_REQUIRE_GRANT"):
            monkeypatch.delenv(v, raising=False)
        with pytest.raises(SystemExit) as ei:
            mg.main()
        assert ei.value.code == 2
        assert ei.value.__cause__ is None and ei.value.__context__ is None
    finally:
        held.close()
    cap = capsys.readouterr()
    text = caplog.text + cap.out + cap.err
    assert "Traceback" not in text
    assert "cannot listen" in text
