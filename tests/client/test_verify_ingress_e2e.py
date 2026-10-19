"""End to end against the REAL ingress app, served by uvicorn on loopback: a client submits bytes
with POST /v1/jobs, a dispatcher-side seal signs the receipt exactly as the dispatcher does
(input hashed from the spooled file, metadata hashed from the sealed envelope), and the client
verifies it with nothing but blastbox.client (urllib) -- and with `blastbox attest verify`."""
from __future__ import annotations

import hashlib
import json
import socket
import threading
import time
import urllib.request
import uuid

import pytest

pytest.importorskip("fastapi")
uvicorn = pytest.importorskip("uvicorn")

from blastbox.client import cli as client_cli
from blastbox.client import verify as v
from blastbox.contract.envelope import DeclaredArtifact, seal_envelope
from blastbox.contract.leaf import ArtifactRef, Detection, Dimensions
from blastbox.contract.nodes import Page
from blastbox.host import attest
from blastbox.host.jobs.base import JobStatus
from tests.host.ingress.test_app import _make_client, _push_to_blob

TOKEN = "e2e-token"
SAMPLE = b"%PDF-1.7\nthe bytes the client submitted\n"


@pytest.fixture(autouse=True)
def _no_key_env(monkeypatch):
    monkeypatch.delenv("BLASTBOX_ATTEST_KEY", raising=False)
    monkeypatch.delenv("BLASTBOX_API_KEY", raising=False)


@pytest.fixture
def key(tmp_path):
    return attest.load_or_create_key(tmp_path / "keys" / "attest.key")


@pytest.fixture
def ingress(tmp_path, request):
    # indirect parametrisation may substitute the ingress's BLASTBOX_API_KEY
    client, store = _make_client(tmp_path, api_key=getattr(request, "param", TOKEN))
    server = uvicorn.Server(uvicorn.Config(client.app, log_level="warning", lifespan="off"))
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    url = f"http://127.0.0.1:{sock.getsockname()[1]}"
    t = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    t.start()
    deadline = time.monotonic() + 10
    while not server.started:
        assert time.monotonic() < deadline, "uvicorn did not start"
        time.sleep(0.02)
    try:
        yield url, store
    finally:
        server.should_exit = True
        t.join(10)
        sock.close()


def _submit(url: str, token: str = TOKEN) -> str:
    """POST /v1/jobs over real HTTP, as a client does."""
    boundary = uuid.uuid4().hex
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"engine\"\r\n\r\n"
            f"clippyshot\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
            f"filename=\"sample.pdf\"\r\nContent-Type: application/pdf\r\n\r\n").encode() \
        + SAMPLE + f"\r\n--{boundary}--\r\n".encode()
    req = urllib.request.Request(f"{url}/v1/jobs", data=body, method="POST", headers={
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        assert resp.status == 202
        return json.loads(resp.read())["job_id"]


def _dispatch(tmp_path, store, job_id: str, key, *, net: dict | None = None,
              sign: bool = True) -> None:
    """What the dispatcher does for a DONE run: hash the spooled input it hands the sandbox,
    seal the envelope, seal the receipt over it, upload, mark DONE."""
    job = store.get(job_id)
    input_path = tmp_path / "jobs" / job_id / "input" / "sample.pdf"
    out = tmp_path / "jobs" / job_id / "output"
    out.mkdir(parents=True, exist_ok=True)
    (out / "page-001.png").write_bytes(b"PNGDATA")
    env = seal_envelope(
        engine=job.engine, outdir=out, input_sha256=job.input_sha256,
        detected=Detection(label="pdf", mime="application/pdf", confidence=0.9, source="magika"),
        declared=[DeclaredArtifact(id="page-001", path="page-001.png", kind="image")],
        warnings=[],
        payload=Page(index=0, dims=Dimensions(width=1, height=1, unit="px"),
                     image=ArtifactRef(id="page-001")))
    (out / "metadata.json").write_text(env.model_dump_json(by_alias=True))
    obs = attest.RunObservation(
        job_id=job_id, engine=job.engine, input_sha256=attest.sha256_file(input_path),
        worker_runtime="warm", worker_tier="static", started_at_ms=attest.now_ms() - 10,
        finished_at_ms=attest.now_ms(), **(net or {}))
    attest.seal_receipt(out, key=key if sign else None, observation=obs,
                        reason=None if sign else attest.NO_ATTEST_KEY_REASON)
    _push_to_blob(tmp_path, job_id, out)
    store.update(job_id, status=JobStatus.DONE, result_dir=str(out))


def test_a_submitted_job_verifies_end_to_end(tmp_path, ingress, key):
    url, store = ingress
    job_id = _submit(url)
    _dispatch(tmp_path, store, job_id, key)
    keys = v.load_pinned_keys(key.public_key_pem)
    out = v.fetch_and_verify(url, job_id, keys=keys, token=TOKEN, expect_engine="clippyshot",
                             expect_input_sha256=hashlib.sha256(SAMPLE).hexdigest(),
                             max_age=60)
    r = out.receipt
    assert r.job_id == job_id and r.input_bound and r.metadata_bound
    assert r.metadata_sha256 == hashlib.sha256(out.metadata).hexdigest()
    assert json.loads(out.metadata)["engine"] == "clippyshot"
    assert r.network is None                     # static tier: posture NOT attested


def test_the_signed_network_posture_survives_the_ingress(tmp_path, ingress, key):
    url, store = ingress
    job_id = _submit(url)
    _dispatch(tmp_path, store, job_id, key,
              net={"net_policy_effective": "none", "net_exit": "none"})
    r = v.fetch_and_verify(url, job_id, keys=v.load_pinned_keys(key.public_key_pem),
                           token=TOKEN).receipt
    assert r.network == v.AttestedNetwork("none", "none", downgraded=False, inspect=False)


def test_a_different_input_fails_end_to_end(tmp_path, ingress, key):
    url, store = ingress
    job_id = _submit(url)
    _dispatch(tmp_path, store, job_id, key)
    with pytest.raises(v.ReceiptMismatch) as ei:
        v.fetch_and_verify(url, job_id, keys=v.load_pinned_keys(key.public_key_pem),
                           token=TOKEN, expect_input_sha256=hashlib.sha256(b"other").hexdigest())
    assert ei.value.code == "input_mismatch"


def test_an_unpinned_signer_fails_end_to_end(tmp_path, ingress, key):
    url, store = ingress
    job_id = _submit(url)
    _dispatch(tmp_path, store, job_id, key)
    stranger = attest.load_or_create_key(tmp_path / "keys" / "stranger.key")
    with pytest.raises(v.UnknownSigningKey):
        v.fetch_and_verify(url, job_id, keys=v.load_pinned_keys(stranger.public_key_pem),
                           token=TOKEN)


def test_a_keyless_dispatcher_tombstone_is_no_receipt_end_to_end(tmp_path, ingress, key):
    url, store = ingress
    job_id = _submit(url)
    _dispatch(tmp_path, store, job_id, key, sign=False)
    with pytest.raises(v.NoReceipt) as ei:
        v.fetch_and_verify(url, job_id, keys=v.load_pinned_keys(key.public_key_pem),
                           token=TOKEN)
    assert ei.value.code == "no_receipt"
    assert ei.value.reason and attest.NO_ATTEST_KEY_REASON in ei.value.reason


def test_a_running_job_is_retryable(ingress, key):
    url, _ = ingress
    job_id = _submit(url)
    with pytest.raises(v.FetchError) as ei:
        v.fetch_and_verify(url, job_id, keys=v.load_pinned_keys(key.public_key_pem),
                           token=TOKEN)
    assert ei.value.code == "not_ready" and ei.value.retryable


def test_without_the_token_it_is_unauthorized(tmp_path, ingress, key):
    url, store = ingress
    job_id = _submit(url)
    _dispatch(tmp_path, store, job_id, key)
    with pytest.raises(v.FetchError) as ei:
        v.fetch_and_verify(url, job_id, keys=v.load_pinned_keys(key.public_key_pem))
    assert ei.value.code == "unauthorized" and not ei.value.retryable


def test_the_key_route_body_pins_as_is(tmp_path, ingress, key, monkeypatch):
    """GET /v1/attestation/key's body is a valid pin source -- but only because the operator
    chose to pin it (here, out of band); the verifier never fetches keys itself."""
    url, store = ingress
    monkeypatch.setenv("BLASTBOX_ATTEST_KEY", str(tmp_path / "keys" / "attest.key"))
    req = urllib.request.Request(f"{url}/v1/attestation/key",
                                 headers={"Authorization": f"Bearer {TOKEN}"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        body = resp.read()
    assert list(v.load_pinned_keys(body)) == [key.key_id]


# ---------------------------------------------------------------------------
# `blastbox attest verify`
# ---------------------------------------------------------------------------


def _cli(argv, capsys):
    # The client CLI's own main, not blastbox.host.cli.main: that one configures structlog
    # against the CAPTURED stdout, which then leaks into later tests as a closed stream. The
    # registration on the `blastbox` entry point is covered in test_lean_import.py.
    rc = client_cli.main(argv)
    return rc, capsys.readouterr()


def test_cli_verifies_and_prints_fields(tmp_path, ingress, key, capsys, monkeypatch):
    url, store = ingress
    job_id = _submit(url)
    _dispatch(tmp_path, store, job_id, key)
    (tmp_path / "pin.pem").write_text(key.public_key_pem)
    (tmp_path / "sample.pdf").write_bytes(SAMPLE)
    monkeypatch.setenv("BLASTBOX_API_KEY", TOKEN)
    rc, cap = _cli(["attest", "verify", "--url", url, "--job", job_id,
                    "--key", str(tmp_path / "pin.pem"), "--input", str(tmp_path / "sample.pdf"),
                    "--metadata-out", str(tmp_path / "meta.json")], capsys)
    assert rc == 0, cap.err
    assert f"VERIFIED: job {job_id}" in cap.out
    assert "(matches --input)" in cap.out and "NOT ATTESTED" in cap.out
    meta = (tmp_path / "meta.json").read_bytes()
    assert hashlib.sha256(meta).hexdigest() in cap.out

    rc, cap = _cli(["attest", "verify", "--url", url, "--job", job_id,
                    "--key", str(tmp_path / "pin.pem"), "--json"], capsys)
    assert rc == 0, cap.err
    d = json.loads(cap.out)
    assert d["verified"] and d["job_id"] == job_id and d["network"] is None
    assert d["input_bound"] is False and d["metadata_bound"] is True


def test_cli_token_file(tmp_path, ingress, key, capsys):
    url, store = ingress
    job_id = _submit(url)
    _dispatch(tmp_path, store, job_id, key)
    (tmp_path / "pin.pem").write_text(key.public_key_pem)
    (tmp_path / "tok").write_text(TOKEN + "\n")
    rc, cap = _cli(["attest", "verify", "--url", url, "--job", job_id, "--key",
                    str(tmp_path / "pin.pem"), "--token-file", str(tmp_path / "tok")], capsys)
    assert rc == 0, cap.err


def test_cli_fails_nonzero_on_a_mismatched_input(tmp_path, ingress, key, capsys, monkeypatch):
    url, store = ingress
    job_id = _submit(url)
    _dispatch(tmp_path, store, job_id, key)
    (tmp_path / "pin.pem").write_text(key.public_key_pem)
    (tmp_path / "other").write_bytes(b"not what was submitted")
    monkeypatch.setenv("BLASTBOX_API_KEY", TOKEN)
    rc, cap = _cli(["attest", "verify", "--url", url, "--job", job_id, "--key",
                    str(tmp_path / "pin.pem"), "--input", str(tmp_path / "other"),
                    "--metadata-out", str(tmp_path / "meta.json")], capsys)
    assert rc == client_cli.EXIT_NOT_VERIFIED
    assert "NOT VERIFIED (input_mismatch)" in cap.err
    assert not (tmp_path / "meta.json").exists()          # nothing unverified is written


def test_cli_exit_codes_for_retry_and_usage(tmp_path, ingress, key, capsys, monkeypatch):
    url, _ = ingress
    job_id = _submit(url)
    (tmp_path / "pin.pem").write_text(key.public_key_pem)
    monkeypatch.setenv("BLASTBOX_API_KEY", TOKEN)
    rc, cap = _cli(["attest", "verify", "--url", url, "--job", job_id, "--key",
                    str(tmp_path / "pin.pem"), "--json"], capsys)
    assert rc == client_cli.EXIT_RETRY
    assert json.loads(cap.out) == {"verified": False, "code": "not_ready", "retryable": True,
                                   "error": json.loads(cap.out)["error"]}
    (tmp_path / "bad.pem").write_text("not a key")
    rc, cap = _cli(["attest", "verify", "--url", url, "--job", job_id, "--key",
                    str(tmp_path / "bad.pem")], capsys)
    assert rc == client_cli.EXIT_USAGE and "--key" in cap.err
    rc, cap = _cli(["attest", "verify", "--url", "file:///etc", "--job", job_id, "--key",
                    str(tmp_path / "pin.pem")], capsys)
    assert rc == client_cli.EXIT_USAGE


@pytest.mark.parametrize("unsupported_key", [False, True])
def test_cli_usage_errors_never_fetch(tmp_path, key, capsys, monkeypatch, unsupported_key):
    """`--input ""` (an unset shell variable) is a usage error, never a verification that
    silently skips input binding; a PEM key of a type the backend cannot load is a --key
    refusal (exit 2), never a traceback. Neither issues a request."""
    def no_fetch(*a, **kw):
        raise AssertionError("fetch_and_verify was called")

    monkeypatch.setattr(v, "fetch_and_verify", no_fetch)
    (tmp_path / "pin.pem").write_text(key.public_key_pem)
    job_id = "0b9d6a0e-6c1d-4f43-9d55-0f6a3c1c7e21"
    argv = ["attest", "verify", "--url", "http://127.0.0.1:9", "--job", job_id, "--key"]
    if unsupported_key:
        (tmp_path / "odd.pem").write_bytes(_unknown_algorithm_pem())
        rc, cap = _cli(argv + [str(tmp_path / "odd.pem")], capsys)
        assert rc == client_cli.EXIT_USAGE and "--key" in cap.err
    else:
        rc, cap = _cli(argv + [str(tmp_path / "pin.pem"), "--input", ""], capsys)
        assert rc == client_cli.EXIT_USAGE and "--input" in cap.err


def _unknown_algorithm_pem() -> bytes:
    """A well-formed SubjectPublicKeyInfo PEM whose algorithm OID (1.2.3.4) no backend
    implements: load_pem_public_key raises UnsupportedAlgorithm, not ValueError."""
    import base64
    oid = bytes([0x06, 0x03, 0x2A, 0x03, 0x04])
    alg = bytes([0x30, len(oid)]) + oid
    bits = bytes([0x03, 0x03, 0x00, 0x01, 0x02])
    spki = bytes([0x30, len(alg) + len(bits)]) + alg + bits
    return (b"-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(spki)
            + b"\n-----END PUBLIC KEY-----\n")


@pytest.mark.parametrize("extra,env_token,token_file", [
    (["--cacert", ""], None, None),
    (["--metadata-out", ""], None, None),
    (["--token-file", ""], None, None),
    (["--engine", ""], None, None),
    (["--key", ""], None, None),
    (["--max-age", "inf"], None, None),
    (["--max-age", "1e999"], None, None),
    (["--max-age", "nan"], None, None),
    (["--timeout", "inf"], None, None),
    ([], "töken☃", None),                        # not encodable as a header
    ([], "a\tb", None),
    (["--timeout", "1e20"], None, None),
    (["--url", "http://bad host"], None, None),
    ([], None, "t☃ken\n"),
])
def test_cli_empty_or_malformed_options_are_usage_errors(
        tmp_path, key, capsys, monkeypatch, extra, env_token, token_file):
    """An option given with an empty value is never treated as absent (that would silently
    use the system CAs, skip the metadata write, or drop the token file); an infinite
    freshness bound or a token that cannot be a bearer header is a usage error (exit 2), never
    a verification or a retryable network failure. The URL is a closed port: had a request
    been issued it would be exit 3."""
    monkeypatch.delenv("BLASTBOX_API_KEY", raising=False)
    if env_token is not None:
        monkeypatch.setenv("BLASTBOX_API_KEY", env_token)
    if token_file is not None:
        (tmp_path / "tok").write_text(token_file, encoding="utf-8")
        extra = ["--token-file", str(tmp_path / "tok")]
    (tmp_path / "pin.pem").write_text(key.public_key_pem)
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    rc, cap = _cli(["attest", "verify", "--url", f"http://127.0.0.1:{port}", "--job",
                    "0b9d6a0e-6c1d-4f43-9d55-0f6a3c1c7e21", "--key", str(tmp_path / "pin.pem"),
                    *extra], capsys)
    assert rc == client_cli.EXIT_USAGE, cap.err
    for secret in ("töken", "a\tb", "t☃ken"):
        assert secret not in cap.err                        # the token is never echoed


LATIN1_KEY = "my key caf\u00e9"


@pytest.mark.parametrize("ingress", [LATIN1_KEY], indirect=True)
def test_a_key_the_ingress_accepts_works_with_the_client(tmp_path, ingress, key, capsys,
                                                        monkeypatch):
    """An API key with an inner space and a Latin-1 letter is a valid ingress credential (it
    strips outer whitespace and compares the rest): the client and the CLI must accept and
    send it unchanged, and a WRONG key must still be refused by the ingress."""
    url, store = ingress
    job_id = _submit(url, token=LATIN1_KEY)
    _dispatch(tmp_path, store, job_id, key)
    keys = v.load_pinned_keys(key.public_key_pem)
    out = v.fetch_and_verify(url, job_id, keys=keys, token=f" {LATIN1_KEY}\n")
    assert out.receipt.job_id == job_id
    with pytest.raises(v.FetchError) as ei:
        v.fetch_and_verify(url, job_id, keys=keys, token="my key cafe")
    assert ei.value.code == "unauthorized"

    (tmp_path / "pin.pem").write_text(key.public_key_pem)
    monkeypatch.setenv("BLASTBOX_API_KEY", LATIN1_KEY)
    rc, cap = _cli(["attest", "verify", "--url", url, "--job", job_id, "--key",
                    str(tmp_path / "pin.pem")], capsys)
    assert rc == client_cli.EXIT_VERIFIED, cap.err
    monkeypatch.delenv("BLASTBOX_API_KEY")
    (tmp_path / "tok").write_text(LATIN1_KEY + "\n", encoding="utf-8")
    rc, cap = _cli(["attest", "verify", "--url", url, "--job", job_id, "--key",
                    str(tmp_path / "pin.pem"), "--token-file", str(tmp_path / "tok")], capsys)
    assert rc == client_cli.EXIT_VERIFIED, cap.err
