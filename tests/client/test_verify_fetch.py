"""fetch_and_verify over real HTTP (a stdlib server on loopback): status mapping, caps,
timeouts, redirects, URL/job-id validation, and the bearer token."""
from __future__ import annotations

import hashlib
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from blastbox.attest_wire import canonical
from blastbox.client import verify as v
from blastbox.host import attest

JOB = "0b9d6a0e-6c1d-4f43-9d55-0f6a3c1c7e21"
INPUT_SHA = hashlib.sha256(b"sample").hexdigest()
METADATA = b'{"engine":"williamtells"}'


@pytest.fixture
def key(tmp_path):
    return attest.load_or_create_key(tmp_path / "attest.key")


@pytest.fixture
def pinned(key):
    return v.load_pinned_keys(key.public_key_pem)


def _receipt(key, metadata=METADATA, job_id=JOB, **over) -> bytes:
    obs = attest.RunObservation(job_id=job_id, engine="williamtells", input_sha256=INPUT_SHA,
                                worker_runtime="warm", worker_tier="static", started_at_ms=1,
                                finished_at_ms=2)
    doc = attest.build_receipt(obs, key_id=key.key_id,
                               metadata_sha256=hashlib.sha256(metadata).hexdigest(), host="h",
                               **over)
    return canonical({"attestation": doc, "signature": key.sign(doc)})


class _Server:
    """routes: path -> (status, body bytes, extra headers) or a callable(handler)."""

    def __init__(self):
        self.routes: dict = {}
        self.seen: list[tuple[str, dict]] = []
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                server.seen.append((self.path, dict(self.headers)))
                route = server.routes.get(self.path)
                if route is None:
                    route = (404, b'{"detail":"not routed"}', {})
                if callable(route):
                    return route(self)
                status, body, headers = route
                self.send_response(status)
                for k, val in headers.items():
                    self.send_header(k, val)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def srv():
    s = _Server()
    yield s
    s.close()


A = f"/v1/jobs/{JOB}/attestation"
M = f"/v1/jobs/{JOB}/metadata"


def test_fetches_both_and_verifies(srv, key, pinned):
    srv.routes[A] = (200, _receipt(key), {})
    srv.routes[M] = (200, METADATA, {})
    out = v.fetch_and_verify(srv.url, JOB, keys=pinned, expect_input_sha256=INPUT_SHA,
                             token="s3cret")
    assert out.metadata == METADATA and out.receipt.metadata_bound and out.receipt.input_bound
    assert [p for p, _ in srv.seen] == [A, M]
    for _, headers in srv.seen:
        assert headers["Authorization"] == "Bearer s3cret"


def test_a_base_path_prefix_is_kept(srv, key, pinned):
    srv.routes["/bb" + A] = (200, _receipt(key), {})
    srv.routes["/bb" + M] = (200, METADATA, {})
    assert v.fetch_and_verify(srv.url + "/bb/", JOB, keys=pinned).metadata == METADATA


def test_metadata_swapped_after_the_seal_fails(srv, key, pinned):
    srv.routes[A] = (200, _receipt(key), {})
    srv.routes[M] = (200, METADATA + b" ", {})
    with pytest.raises(v.ReceiptMismatch) as ei:
        v.fetch_and_verify(srv.url, JOB, keys=pinned)
    assert ei.value.code == "metadata_mismatch"


def test_a_receipt_for_another_job_fails(srv, key, pinned):
    srv.routes[A] = (200, _receipt(key, job_id="11111111-1111-4111-8111-111111111111"), {})
    srv.routes[M] = (200, METADATA, {})
    with pytest.raises(v.ReceiptMismatch) as ei:
        v.fetch_and_verify(srv.url, JOB, keys=pinned)
    assert ei.value.code == "job_id_mismatch"


def test_404_is_no_receipt_with_the_sanitised_detail(srv, pinned):
    detail = "no execution receipt for this job: the uploader stored no receipt\x1b[2J"
    srv.routes[A] = (404, json.dumps({"detail": detail}).encode(), {})
    with pytest.raises(v.NoReceipt) as ei:
        v.fetch_and_verify(srv.url, JOB, keys=pinned)
    assert ei.value.code == "no_receipt"
    assert "stored no receipt" in ei.value.reason and "\x1b" not in ei.value.reason
    assert [p for p, _ in srv.seen] == [A]                  # metadata never fetched


def test_410_is_expired(srv, pinned):
    srv.routes[A] = (410, b'{"detail":"result expired"}', {})
    with pytest.raises(v.NoReceipt) as ei:
        v.fetch_and_verify(srv.url, JOB, keys=pinned)
    assert ei.value.code == "expired"


def test_a_served_tombstone_is_no_receipt(srv, pinned):
    srv.routes[A] = (200, canonical(attest.tombstone_body("signing failed")), {})
    srv.routes[M] = (200, METADATA, {})
    with pytest.raises(v.NoReceipt) as ei:
        v.fetch_and_verify(srv.url, JOB, keys=pinned)
    assert ei.value.code == "tombstone"


def test_a_tombstone_is_no_receipt_even_when_metadata_is_unavailable(srv, pinned):
    """The receipt is settled before the metadata is fetched: a tombstone is NoReceipt, not a
    retryable 503 from a metadata request that should never have been made."""
    srv.routes[A] = (200, canonical(attest.tombstone_body("signing failed")), {})
    srv.routes[M] = (503, b'{"detail":"down"}', {})
    with pytest.raises(v.NoReceipt) as ei:
        v.fetch_and_verify(srv.url, JOB, keys=pinned)
    assert ei.value.code == "tombstone"
    assert [p for p, _ in srv.seen] == [A]


def _other_key(tmp_path):
    return attest.load_or_create_key(tmp_path / "other" / "attest.key")


@pytest.mark.parametrize("case", ["malformed", "unknown_key", "bad_signature", "job_id",
                                  "input", "engine", "stale"])
def test_an_unusable_receipt_never_fetches_the_metadata(srv, key, pinned, tmp_path, case):
    other = _other_key(tmp_path)
    receipt = _receipt(key)
    kw: dict = {}
    if case == "malformed":
        receipt = b'{"attestation": {"v": 1}, "signature": 5}'
        exc = v.ReceiptMalformed
    elif case == "unknown_key":
        receipt = _receipt(other)
        exc = v.UnknownSigningKey
    elif case == "bad_signature":
        body = json.loads(_receipt(key))
        body["signature"] = json.loads(_receipt(other))["signature"]
        receipt = canonical(body)
        exc = v.BadSignature
    elif case == "job_id":
        receipt = _receipt(key, job_id="11111111-1111-4111-8111-111111111111")
        exc = v.ReceiptMismatch
    elif case == "input":
        kw["expect_input_sha256"] = "0" * 64
        exc = v.ReceiptMismatch
    elif case == "engine":
        kw["expect_engine"] = "other-engine"
        exc = v.ReceiptMismatch
    else:
        receipt = _receipt(key, issued_at_ms=1_000)          # 1970: far past any max_age
        kw["max_age"] = 60
        exc = v.ReceiptMismatch
    srv.routes[A] = (200, receipt, {})
    srv.routes[M] = (200, METADATA, {})
    with pytest.raises(exc):
        v.fetch_and_verify(srv.url, JOB, keys=pinned, **kw)
    assert [p for p, _ in srv.seen] == [A]                  # metadata never fetched


@pytest.mark.parametrize("status,code,retryable", [
    (409, "not_ready", True), (503, "unavailable", True), (500, "unavailable", True),
    (429, "unavailable", True), (401, "unauthorized", False), (403, "unauthorized", False),
    (400, "http_error", False), (204, "http_error", False), (408, "timeout", True),
])
def test_http_statuses_map_to_typed_fetch_errors(srv, pinned, status, code, retryable):
    srv.routes[A] = (status, b"" if status == 204 else b'{"detail":"x"}', {})
    with pytest.raises(v.FetchError) as ei:
        v.fetch_and_verify(srv.url, JOB, keys=pinned)
    assert (ei.value.code, ei.value.retryable, ei.value.status) == (code, retryable, status)


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_redirects_are_refused_and_the_token_never_follows(srv, pinned, status):
    other = _Server()
    try:
        srv.routes[A] = (status, b"", {"Location": other.url + A})
        with pytest.raises(v.FetchError) as ei:
            v.fetch_and_verify(srv.url, JOB, keys=pinned, token="s3cret")
        assert ei.value.code == "redirect" and not ei.value.retryable
        assert other.seen == []
    finally:
        other.close()


def test_metadata_404_after_a_receipt_is_a_fetch_error(srv, key, pinned):
    srv.routes[A] = (200, _receipt(key), {})
    srv.routes[M] = (404, b'{"detail":"metadata.json not found"}', {})
    with pytest.raises(v.FetchError) as ei:
        v.fetch_and_verify(srv.url, JOB, keys=pinned)
    assert ei.value.code == "metadata_missing"


def test_metadata_408_is_a_retryable_timeout(srv, key, pinned):
    srv.routes[A] = (200, _receipt(key), {})
    srv.routes[M] = (408, b'{"detail":"request timeout"}', {})
    with pytest.raises(v.FetchError) as ei:
        v.fetch_and_verify(srv.url, JOB, keys=pinned)
    assert (ei.value.code, ei.value.retryable, ei.value.status) == ("timeout", True, 408)


def test_metadata_409_is_retryable(srv, key, pinned):
    srv.routes[A] = (200, _receipt(key), {})
    srv.routes[M] = (409, b"{}", {})
    with pytest.raises(v.FetchError) as ei:
        v.fetch_and_verify(srv.url, JOB, keys=pinned)
    assert ei.value.retryable


def test_an_oversized_receipt_is_refused(srv, pinned):
    srv.routes[A] = (200, b" " * (v.RECEIPT_MAX_BYTES + 1), {})
    with pytest.raises(v.FetchError) as ei:
        v.fetch_and_verify(srv.url, JOB, keys=pinned)
    assert ei.value.code == "too_large"


def test_oversized_metadata_is_refused_even_without_a_content_length(srv, key, pinned):
    big = b"x" * 5000
    srv.routes[A] = (200, _receipt(key, metadata=big), {})

    def chunked(h):
        h.send_response(200)
        h.send_header("Transfer-Encoding", "chunked")
        h.end_headers()
        for _ in range(5):
            h.wfile.write(b"3e8\r\n" + b"x" * 1000 + b"\r\n")
        h.wfile.write(b"0\r\n\r\n")

    srv.routes[M] = chunked
    with pytest.raises(v.FetchError) as ei:
        v.fetch_and_verify(srv.url, JOB, keys=pinned, max_metadata_bytes=4096)
    assert ei.value.code == "too_large"
    assert v.fetch_and_verify(srv.url, JOB, keys=pinned, max_metadata_bytes=5000).metadata == big


def test_a_stalled_server_times_out_retryably(srv, pinned):
    release = threading.Event()

    def stall(h):
        release.wait(5)

    srv.routes[A] = stall
    t0 = time.monotonic()
    try:
        with pytest.raises(v.FetchError) as ei:
            v.fetch_and_verify(srv.url, JOB, keys=pinned, timeout=0.3)
    finally:
        release.set()
    assert ei.value.retryable and time.monotonic() - t0 < 4


def test_a_trickling_server_hits_the_total_deadline(srv, pinned):
    """Each byte arrives inside the socket timeout; the request's TOTAL budget still ends it."""
    release = threading.Event()

    def trickle(h):
        h.send_response(200)
        h.send_header("Content-Length", "100000")
        h.end_headers()
        for _ in range(100):
            if release.wait(0.1):
                return
            try:
                h.wfile.write(b" ")
                h.wfile.flush()
            except OSError:
                return

    srv.routes[A] = trickle
    t0 = time.monotonic()
    try:
        with pytest.raises(v.FetchError) as ei:
            v.fetch_and_verify(srv.url, JOB, keys=pinned, timeout=0.5)
    finally:
        release.set()
    assert ei.value.code == "timeout" and ei.value.retryable
    assert time.monotonic() - t0 < 3


def test_a_body_stall_after_slow_headers_ends_at_the_total_deadline(srv, pinned):
    """Headers use most of the budget, then the body stalls: the read is interrupted when the
    REMAINING budget runs out, not after a fresh full socket timeout, and it is a timeout."""
    release = threading.Event()

    def slow_then_stall(h):
        if release.wait(0.8):
            return
        h.send_response(200)
        h.send_header("Content-Length", "1000")
        h.end_headers()
        h.wfile.write(b" ")
        h.wfile.flush()
        release.wait(10)

    srv.routes[A] = slow_then_stall
    t0 = time.monotonic()
    try:
        with pytest.raises(v.FetchError) as ei:
            v.fetch_and_verify(srv.url, JOB, keys=pinned, timeout=1.0)
    finally:
        release.set()
    elapsed = time.monotonic() - t0
    assert ei.value.code == "timeout" and ei.value.retryable
    assert elapsed < 1.6, elapsed                           # not ~0.8 + a fresh 1.0


def test_trickled_headers_hit_the_total_deadline(srv, pinned):
    """Each header byte arrives inside the socket timeout; the total budget still ends it."""
    release = threading.Event()

    def trickle_headers(h):
        h.wfile.write(b"HTTP/1.1 200 OK\r\n")
        for _ in range(100):
            if release.wait(0.1):
                return
            try:
                h.wfile.write(b"X")
                h.wfile.flush()
            except OSError:
                return

    srv.routes[A] = trickle_headers
    t0 = time.monotonic()
    try:
        with pytest.raises(v.FetchError) as ei:
            v.fetch_and_verify(srv.url, JOB, keys=pinned, timeout=0.5)
    finally:
        release.set()
    assert ei.value.code == "timeout" and ei.value.retryable
    assert time.monotonic() - t0 < 1.5


def test_a_body_cut_by_the_deadline_is_a_timeout_not_a_short_body(srv, pinned):
    """A close-delimited body (no Content-Length, no chunking) interrupted at the deadline reads
    as EOF; it must be reported as a timeout, never parsed as a complete body."""
    release = threading.Event()

    def close_delimited(h):
        h.protocol_version = "HTTP/1.0"
        h.send_response(200)
        h.end_headers()
        h.wfile.write(b'{"attestation": ')
        h.wfile.flush()
        release.wait(10)

    srv.routes[A] = close_delimited
    try:
        with pytest.raises(v.FetchError) as ei:
            v.fetch_and_verify(srv.url, JOB, keys=pinned, timeout=0.5)
    finally:
        release.set()
    assert ei.value.code == "timeout"


def test_a_stalled_connect_phase_is_a_timeout(srv, pinned):
    """No response at all within the budget is code timeout (retryable), not network."""
    release = threading.Event()
    srv.routes[A] = lambda h: release.wait(5)
    try:
        with pytest.raises(v.FetchError) as ei:
            v.fetch_and_verify(srv.url, JOB, keys=pinned, timeout=0.3)
    finally:
        release.set()
    assert ei.value.code == "timeout" and ei.value.retryable


def test_a_receipt_that_goes_stale_during_the_metadata_download_fails(srv, key, pinned):
    """Fresh at the first check, past max_age by the time the metadata has arrived: the
    returned result would break the caller's freshness policy, so it is refused."""
    srv.routes[A] = (200, _receipt(key, issued_at_ms=time.time_ns() // 1_000_000 - 59_500),
                     {})

    def slow_metadata(h):
        time.sleep(1.0)
        h.send_response(200)
        h.send_header("Content-Length", str(len(METADATA)))
        h.end_headers()
        h.wfile.write(METADATA)

    srv.routes[M] = slow_metadata
    with pytest.raises(v.ReceiptMismatch) as ei:
        v.fetch_and_verify(srv.url, JOB, keys=pinned, max_age=60, timeout=5)
    assert ei.value.code == "stale"
    assert [p for p, _ in srv.seen] == [A, M]               # failed AFTER the download
    # Without max_age the same slow pair still verifies.
    assert v.fetch_and_verify(srv.url, JOB, keys=pinned, timeout=5).metadata == METADATA


@pytest.mark.parametrize("status", [401, 400, 404, 503])
def test_an_error_status_whose_body_stalls_is_a_timeout(srv, pinned, status):
    """Error headers arrive, then the body stalls past the budget: that is a retryable
    timeout, not the non-retryable status (or NoReceipt) it began as."""
    release = threading.Event()

    def stall_error_body(h):
        h.send_response(status)
        h.send_header("Content-Length", "1000")
        h.end_headers()
        h.wfile.write(b'{"detail": "')
        h.wfile.flush()
        release.wait(10)

    srv.routes[A] = stall_error_body
    t0 = time.monotonic()
    try:
        with pytest.raises(v.FetchError) as ei:
            v.fetch_and_verify(srv.url, JOB, keys=pinned, timeout=0.5)
    finally:
        release.set()
    assert ei.value.code == "timeout" and ei.value.retryable
    assert time.monotonic() - t0 < 1.5


def test_connection_refused_is_retryable(pinned):
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    with pytest.raises(v.FetchError) as ei:
        v.fetch_and_verify(f"http://127.0.0.1:{port}", JOB, keys=pinned, timeout=2)
    assert ei.value.code == "network" and ei.value.retryable


@pytest.mark.parametrize("url", [
    "file:///etc", "ftp://h/", "h:8000", "http://", "http://u:p@h/", "http://h/?q=1",
    "http://h/#f", "javascript:alert(1)", "http://h:abc", "http://h:70000", "http://h:65536",
    "http://h:0", "http://h:-1", "http://h:+80", "https://[::1]:99999",
    "http://bad host", "http://h/base path", "http://h\t/", "http://h/\n", " http://h",
    "http://h/ ", "http://h\x00/", "http://h/\x7f", "http://b\u00fccher.example",
])
def test_only_plain_http_and_https_base_urls(pinned, url):
    with pytest.raises(ValueError):
        v.fetch_and_verify(url, JOB, keys=pinned)


@pytest.mark.parametrize("url", ["http://127.0.0.1:abc", "http://127.0.0.1:70000",
                                 "http://127.0.0.1:0"])
def test_an_invalid_port_is_a_usage_error_before_any_request(url, pinned, monkeypatch):
    """A malformed port is a ValueError up front, never a (retryable) network/http error."""
    def no_request(*a, **kw):
        raise AssertionError("a request was issued for an invalid URL")

    monkeypatch.setattr(v, "_get", no_request)
    with pytest.raises(ValueError, match="port"):
        v.fetch_and_verify(url, JOB, keys=pinned)


def test_valid_ports_still_work(srv, key, pinned):
    srv.routes[A] = (200, _receipt(key), {})
    srv.routes[M] = (200, METADATA, {})
    assert v.fetch_and_verify(srv.url, JOB, keys=pinned).metadata == METADATA


@pytest.mark.parametrize("job_id", [
    "../../etc/passwd", JOB.upper(), "{" + JOB + "}", "urn:uuid:" + JOB, JOB.replace("-", ""),
    "", "x",
])
def test_the_job_id_must_be_a_canonical_uuid(pinned, job_id):
    with pytest.raises(ValueError):
        v.fetch_and_verify("http://127.0.0.1:9", job_id, keys=pinned)


@pytest.mark.parametrize("kw", [
    {"token": "a\r\nX-Evil: 1"}, {"token": ""}, {"timeout": 0}, {"timeout": -1},
    {"max_metadata_bytes": 0}, {"max_metadata_bytes": 1.5}, {"timeout": float("inf")},
    {"timeout": float("nan")}, {"max_age": -5}, {"max_age": float("inf")},
    {"token": "t\u00f6ken\u2603"}, {"token": "a\tb"}, {"token": "a\x85b"}, {"token": "a\x01b"},
    {"timeout": 1e20}, {"timeout": 86400.5},
    {"token": "a\x7fb"},
])
def test_bad_fetch_arguments(pinned, kw):
    with pytest.raises((TypeError, ValueError)):
        v.fetch_and_verify("http://127.0.0.1:9", JOB, keys=pinned, **kw)


def test_tls_certificate_failures_are_not_retryable(pinned):
    """An https URL to a plain-HTTP server fails the handshake; a cert error must never be
    retried into success, and nothing is verified."""
    import socket
    import ssl
    import tempfile

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    import datetime

    k = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(k.public_key()).serial_number(1)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
            .sign(k, hashes.SHA256()))
    with tempfile.TemporaryDirectory() as d:
        cf, kf = f"{d}/c.pem", f"{d}/k.pem"
        with open(cf, "wb") as fh:
            fh.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(kf, "wb") as fh:
            fh.write(k.private_bytes(serialization.Encoding.PEM,
                                     serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(cf, kf)
        lsock = socket.socket()
        lsock.bind(("127.0.0.1", 0))
        lsock.listen()
        port = lsock.getsockname()[1]

        def serve():
            try:
                conn, _ = lsock.accept()
                with sctx.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(1)
            except (OSError, ssl.SSLError):
                pass

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        try:
            with pytest.raises(v.FetchError) as ei:
                v.fetch_and_verify(f"https://localhost:{port}", JOB, keys=pinned, timeout=3)
        finally:
            lsock.close()
        assert ei.value.code == "tls" and not ei.value.retryable


def _raw_listener(handle):
    """A bare TCP listener on loopback whose accepted connections go to ``handle(conn)``."""
    import socket
    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen()

    def serve():
        while True:
            try:
                conn, _ = lsock.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    return lsock, lsock.getsockname()[1]


def test_a_tls_handshake_dropped_by_the_peer_is_retryable(pinned):
    """A load balancer closing the connection mid-handshake (SSLEOFError) is transport
    trouble, retryable -- not the non-retryable `tls` a certificate failure is."""
    def drop(conn):
        try:
            conn.recv(4096)                                 # the ClientHello
        finally:
            conn.close()

    lsock, port = _raw_listener(drop)
    try:
        with pytest.raises(v.FetchError) as ei:
            v.fetch_and_verify(f"https://localhost:{port}", JOB, keys=pinned, timeout=3)
    finally:
        lsock.close()
    assert ei.value.code == "network" and ei.value.retryable


def test_a_stalled_tls_handshake_after_a_slow_connect_ends_at_the_total_deadline(
        pinned, monkeypatch):
    """TCP connect eats half the budget, then the peer never answers the ClientHello: the
    handshake must end at the request's TOTAL deadline (the TLS socket is registered with the
    watchdog before its handshake), not after a fresh socket timeout set before connect."""
    import socket
    release = threading.Event()

    def stall(conn):
        try:
            conn.recv(4096)
            release.wait(10)
        finally:
            conn.close()

    lsock, port = _raw_listener(stall)
    delayed: list[tuple] = []

    class SlowConnectSocket(socket.socket):
        """The socket class the production connect path constructs: its connect() to the
        listener takes 0.5s, as a slow TCP connect would."""

        def connect(self, address):
            if address[:2] == ("127.0.0.1", port):
                delayed.append(address)
                time.sleep(0.5)
            return super().connect(address)

    real_getaddrinfo = socket.getaddrinfo

    def ipv4_only(host, p, *a, **kw):
        if host == "localhost":     # one deterministic address: the delayed listener
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", p))]
        return real_getaddrinfo(host, p, *a, **kw)

    monkeypatch.setattr(socket, "getaddrinfo", ipv4_only)
    monkeypatch.setattr(socket, "socket", SlowConnectSocket)
    t0 = time.monotonic()
    try:
        with pytest.raises(v.FetchError) as ei:
            v.fetch_and_verify(f"https://localhost:{port}", JOB, keys=pinned, timeout=1.0)
    finally:
        release.set()
        lsock.close()
    assert delayed, "the slow connect path was not exercised"
    elapsed = time.monotonic() - t0
    assert ei.value.code == "timeout" and ei.value.retryable
    assert elapsed < 1.35, elapsed                          # not ~0.5 + a fresh 1.0


def test_a_multi_address_host_cannot_spend_one_budget_per_address(srv, pinned, monkeypatch):
    """A hostname resolving to several unreachable addresses: every candidate connect gets only
    the REMAINING budget (and is registered with the watchdog first), so the request ends at
    its total deadline instead of after one full timeout per address."""
    import socket

    real_getaddrinfo = socket.getaddrinfo
    real_socket = socket.socket

    def getaddrinfo(host, port, *a, **kw):
        if host == "multi.test":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 9))] * 3
        return real_getaddrinfo(host, port, *a, **kw)

    class BlackholeSocket(real_socket):
        """connect() to port 9 behaves like an unanswered SYN: it waits out the socket's
        timeout (or a shutdown) and then times out."""

        def connect(self, address):
            if address[1] != 9:
                return super().connect(address)
            budget = self.gettimeout()
            end = time.monotonic() + (5 if budget is None else budget)
            while time.monotonic() < end:
                time.sleep(0.01)
            raise TimeoutError("timed out")

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(socket, "socket", BlackholeSocket)
    t0 = time.monotonic()
    with pytest.raises(v.FetchError) as ei:
        v.fetch_and_verify("http://multi.test:9", JOB, keys=pinned, timeout=0.6)
    elapsed = time.monotonic() - t0
    assert ei.value.code == "timeout" and ei.value.retryable
    assert elapsed < 1.0, elapsed                           # not ~3 x 0.6


def test_a_latin1_token_with_inner_spaces_is_sent_exactly(srv, key, pinned):
    """The ingress strips outer whitespace and compares the rest as Latin-1: a key with inner
    spaces or Latin-1 letters is a valid credential and is sent byte-for-byte."""
    srv.routes[A] = (200, _receipt(key), {})
    srv.routes[M] = (200, METADATA, {})
    out = v.fetch_and_verify(srv.url, JOB, keys=pinned, token="  my key caf\u00e9  ")
    assert out.metadata == METADATA
    for _, headers in srv.seen:
        assert headers["Authorization"] == "Bearer my key caf\u00e9"


def test_a_request_that_cannot_be_built_is_a_usage_error_not_a_retry():
    """Whatever slips past argument validation and is refused by http.client or the socket API
    while BUILDING the request (InvalidURL, UnicodeEncodeError, OverflowError) is a permanent
    ValueError, never a retryable network FetchError."""
    with pytest.raises(ValueError, match="cannot be sent"):
        v._get("http://127.0.0.1:9/a b", headers={}, timeout=2, cap=10, what="attestation",
               ssl_context=None)
    with pytest.raises(ValueError, match="cannot be sent"):
        v._get("http://127.0.0.1:9/", headers={"Authorization": "Bearer \u2603"}, timeout=2,
               cap=10, what="attestation", ssl_context=None)
