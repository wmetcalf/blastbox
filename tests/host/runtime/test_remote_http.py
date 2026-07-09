"""Unit tests for the generic remote-HTTP host transport (no network)."""

from __future__ import annotations

import io
import json
import tarfile
from types import SimpleNamespace

import pytest

from blastbox.host.runtime.remote_http import (
    _safe_extract_tar,
    detonate_remote,
    make_remote_validate,
    slot_base_url,
)


def _tar(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in files.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


class _Resp:
    def __init__(self, data: bytes) -> None:
        self._bio = io.BytesIO(data)

    def read(self, n: int = -1) -> bytes:
        return self._bio.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _opener(tar_bytes: bytes, capture: list | None = None):
    def op(req, timeout, context=None):
        if capture is not None:
            capture.append(req)
        return _Resp(tar_bytes)
    return op


# --------------------------------------------------------------------- slot_base_url

def test_slot_base_url_lambda_prefers_url():
    slot = SimpleNamespace(url="https://mv.lambda-url.aws/", ip=None, agent_port=8765)
    assert slot_base_url(slot) == "https://mv.lambda-url.aws"


def test_slot_base_url_ec2_ip_port():
    slot = SimpleNamespace(url=None, ip="10.0.1.9", agent_port=8765)
    assert slot_base_url(slot) == "http://10.0.1.9:8765"


def test_slot_base_url_tls_scheme():
    slot = SimpleNamespace(url=None, ip="10.0.0.4", agent_port=8765)
    assert slot_base_url(slot, tls=True) == "https://10.0.0.4:8765"
    assert slot_base_url(slot, tls=False) == "http://10.0.0.4:8765"


def test_slot_base_url_no_endpoint_raises():
    with pytest.raises(ValueError):
        slot_base_url(SimpleNamespace(url=None, ip=None, agent_port=8765))


# --------------------------------------------------------------------- safe extraction

def test_safe_extract_writes_regular_files(tmp_path):
    written = _safe_extract_tar(_tar({"metadata.json": b"{}", "p0.png": b"x"}), tmp_path)
    assert set(written) == {"metadata.json", "p0.png"}
    assert (tmp_path / "p0.png").read_bytes() == b"x"


def test_safe_extract_rejects_traversal(tmp_path):
    dest = tmp_path / "out"
    dest.mkdir()
    _safe_extract_tar(_tar({"../escape.bin": b"evil", "ok.png": b"good"}), dest)
    assert (dest / "ok.png").exists()
    assert not (tmp_path / "escape.bin").exists()   # traversal dropped


# --------------------------------------------------------------------- detonate_remote

def test_detonate_remote_extracts_and_returns_meta(tmp_path):
    tar = _tar({"metadata.json": json.dumps({"status": "ok"}).encode(), "page-001.png": b"\x89PNG"})
    cap: list = []
    out = tmp_path / "out"
    inp = tmp_path / "in.docx"
    inp.write_bytes(b"z")
    meta = detonate_remote("http://10.0.0.5:8765", inp, out, http_open=_opener(tar, cap))
    assert meta == {"status": "ok"}
    assert (out / "page-001.png").read_bytes() == b"\x89PNG"
    # posted to /detonate with the sanitized name
    assert cap[0].full_url == "http://10.0.0.5:8765/detonate?name=in.docx"
    assert cap[0].method == "POST"


def test_detonate_remote_sends_jwe_header_when_token(tmp_path):
    (tmp_path / "in.bin").write_bytes(b"z")
    cap: list = []
    detonate_remote("https://mv.aws", tmp_path / "in.bin", tmp_path / "o",
                    token="jwe.tok", agent_port=8765, http_open=_opener(_tar({"metadata.json": b"{}"}), cap))
    assert cap[0].headers.get("X-aws-proxy-auth") == "jwe.tok"
    assert cap[0].headers.get("X-aws-proxy-port") == "8765"


def _header_ci(req, name: str):
    return next((v for k, v in req.headers.items() if k.lower() == name.lower()), None)


def test_detonate_remote_forwards_params(tmp_path):
    (tmp_path / "in.bin").write_bytes(b"z")
    cap: list = []
    detonate_remote("http://h:8765", tmp_path / "in.bin", tmp_path / "o",
                    params={"CLIPPYSHOT_OCR": "1", "CLIPPYSHOT_OCR_ALL": "1"},
                    http_open=_opener(_tar({"metadata.json": b"{}"}), cap))
    assert json.loads(_header_ci(cap[0], "X-Blastbox-Params")) == {"CLIPPYSHOT_OCR": "1", "CLIPPYSHOT_OCR_ALL": "1"}


def test_detonate_remote_no_params_header_when_none(tmp_path):
    (tmp_path / "in.bin").write_bytes(b"z")
    cap: list = []
    detonate_remote("http://h:8765", tmp_path / "in.bin", tmp_path / "o",
                    http_open=_opener(_tar({"metadata.json": b"{}"}), cap))
    assert _header_ci(cap[0], "X-Blastbox-Params") is None


def test_dispatch_ssl_context_from_env_none_without_ca():
    from blastbox.host.runtime.remote_http import dispatch_ssl_context_from_env
    assert dispatch_ssl_context_from_env({}.get) is None


def test_dispatch_ssl_context_from_env_builds(tmp_path):
    import ssl

    from blastbox.host.pki import ensure_ca
    from blastbox.host.runtime.remote_http import dispatch_ssl_context_from_env
    ensure_ca(tmp_path)     # writes tmp_path/ca.crt
    ctx = dispatch_ssl_context_from_env({"BLASTBOX_DISPATCH_TLS_CA": str(tmp_path / "ca.crt")}.get)
    assert isinstance(ctx, ssl.SSLContext)


def test_dispatch_ssl_context_partial_fails_closed():
    from blastbox.host.runtime.remote_http import dispatch_ssl_context_from_env
    with pytest.raises(RuntimeError):
        dispatch_ssl_context_from_env({"BLASTBOX_DISPATCH_TLS_CERT": "c"}.get)   # cert, no CA -> not plaintext


def test_detonate_remote_caps_output(tmp_path):
    from blastbox.host.runtime.remote_http import RemoteOutputTooLarge
    (tmp_path / "in.bin").write_bytes(b"z")
    big = _tar({"metadata.json": b"{}", "blob.bin": b"x" * 5000})
    with pytest.raises(RemoteOutputTooLarge):
        detonate_remote("http://h:8765", tmp_path / "in.bin", tmp_path / "o",
                        http_open=_opener(big), max_output_bytes=1000)


def test_make_remote_validate_releases_dirty_on_failure(tmp_path):
    (tmp_path / "in.docx").write_bytes(b"z")
    slot = SimpleNamespace(url=None, ip="10.0.1.4", auth_token=None, agent_port=8765)
    seen = []

    def boom(req, timeout, context=None):
        raise OSError("connection refused")

    validate = make_remote_validate(
        claim=lambda: slot, release=lambda s, dirty=False: seen.append(dirty),
        output_dir_for=lambda p: tmp_path / "out", http_open=boom,
    )
    validate(tmp_path / "in.docx")
    assert seen == [True]   # transport failure -> retire the slot dirty


def test_make_remote_validate_releases_clean_on_success(tmp_path):
    (tmp_path / "in.docx").write_bytes(b"z")
    slot = SimpleNamespace(url=None, ip="10.0.1.4", auth_token=None, agent_port=8765)
    seen = []
    validate = make_remote_validate(
        claim=lambda: slot, release=lambda s, dirty=False: seen.append(dirty),
        output_dir_for=lambda p: tmp_path / "out",
        http_open=_opener(_tar({"metadata.json": json.dumps({"status": "ok"}).encode()})),
    )
    validate(tmp_path / "in.docx")
    assert seen == [False]   # clean success -> reusable


def test_make_remote_validate_fails_on_engine_error(tmp_path):
    (tmp_path / "in.docx").write_bytes(b"z")
    slot = SimpleNamespace(url=None, ip="10.0.1.4", auth_token=None, agent_port=8765)
    validate = make_remote_validate(
        claim=lambda: slot, release=lambda s: None,
        output_dir_for=lambda p: tmp_path / "out",
        http_open=_opener(_tar({"metadata.json": json.dumps({"status": "engine_error"}).encode()})),
    )
    _, ok = validate(tmp_path / "in.docx")
    assert ok is False   # a sealed engine_error envelope is not a successful job


def test_make_remote_validate_trust_failure_keeps_slot_dirty(tmp_path):
    # host trust gate runs BEFORE the slot is released: a transport-ok job that FAILS host validation
    # must fail AND retire the slot dirty (not re-offer a worker that produced untrusted output).
    (tmp_path / "in.docx").write_bytes(b"z")
    slot = SimpleNamespace(url=None, ip="10.0.1.4", auth_token=None, agent_port=8765)
    seen = []

    def bad_trust(_in_path, _out_dir):
        raise RuntimeError("hash mismatch")

    validate = make_remote_validate(
        claim=lambda: slot, release=lambda s, dirty=False: seen.append(dirty),
        output_dir_for=lambda p: tmp_path / "out",
        http_open=_opener(_tar({"metadata.json": json.dumps({"status": "ok"}).encode()})),
        output_trust=bad_trust,
    )
    _, ok = validate(tmp_path / "in.docx")
    assert ok is False and seen == [True]   # trust failed -> job fails, slot retired dirty


def test_make_remote_validate_trust_ok_rereads_sealed_metadata(tmp_path):
    # a passing trust gate re-writes metadata.json (host-sealed) -> validate returns the re-read version.
    (tmp_path / "in.docx").write_bytes(b"z")
    slot = SimpleNamespace(url=None, ip="10.0.1.4", auth_token=None, agent_port=8765)
    out = tmp_path / "out"

    def reseal(_in_path, out_dir):
        (out_dir / "metadata.json").write_text(json.dumps({"status": "ok", "sealed": True}))

    validate = make_remote_validate(
        claim=lambda: slot, release=lambda s, dirty=False: None,
        output_dir_for=lambda p: out,
        http_open=_opener(_tar({"metadata.json": json.dumps({"status": "ok"}).encode()})),
        output_trust=reseal,
    )
    meta, ok = validate(tmp_path / "in.docx")
    assert ok is True and meta.get("sealed") is True   # returns the host-sealed metadata, not the worker's


# --------------------------------------------------------------------- make_remote_validate

def test_make_remote_validate_happy(tmp_path):
    (tmp_path / "in.docx").write_bytes(b"z")
    slot = SimpleNamespace(url=None, ip="10.0.1.4", auth_token=None, agent_port=8765)
    claimed, released = [], []
    validate = make_remote_validate(
        claim=lambda: (claimed.append(slot) or slot),
        release=lambda s: released.append(s),
        output_dir_for=lambda p: tmp_path / "out",
        http_open=_opener(_tar({"metadata.json": json.dumps({"status": "ok"}).encode()})),
    )
    meta, ok = validate(tmp_path / "in.docx")
    assert ok is True and meta == {"status": "ok"}
    assert claimed == [slot] and released == [slot]   # slot claimed AND released


def test_make_remote_validate_failure_releases_slot(tmp_path):
    (tmp_path / "in.docx").write_bytes(b"z")
    slot = SimpleNamespace(url=None, ip="10.0.1.4", auth_token=None, agent_port=8765)
    released = []

    def boom(req, timeout, context=None):
        raise OSError("connection refused")

    validate = make_remote_validate(
        claim=lambda: slot, release=lambda s: released.append(s),
        output_dir_for=lambda p: tmp_path / "out", http_open=boom,
    )
    meta, ok = validate(tmp_path / "in.docx")
    assert ok is False and meta is None
    assert released == [slot]   # released even on failure
