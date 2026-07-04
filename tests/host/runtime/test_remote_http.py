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
    def op(req, timeout):
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

    def boom(req, timeout):
        raise OSError("connection refused")

    validate = make_remote_validate(
        claim=lambda: slot, release=lambda s: released.append(s),
        output_dir_for=lambda p: tmp_path / "out", http_open=boom,
    )
    meta, ok = validate(tmp_path / "in.docx")
    assert ok is False and meta is None
    assert released == [slot]   # released even on failure
