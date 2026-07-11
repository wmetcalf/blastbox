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


def test_safe_extract_caps_member_count(tmp_path):
    from blastbox.host.runtime.remote_http import RemoteOutputTooLarge
    tar = _tar({f"f{i}.bin": b"x" for i in range(10)})
    with pytest.raises(RemoteOutputTooLarge):
        _safe_extract_tar(tar, tmp_path, max_members=5)   # inode-exhaustion guard


def test_safe_extract_refuses_symlink_leaf(tmp_path):
    # a stale symlink at the member's leaf (even one that resolves IN-bounds) must not be written
    # THROUGH: O_NOFOLLOW makes the open fail ELOOP and the member is skipped.
    import os
    dest = tmp_path / "out"
    dest.mkdir()
    inside = dest / "inside.txt"
    inside.write_text("original")
    os.symlink(inside, dest / "p0.png")   # dest/p0.png -> dest/inside.txt (in-bounds, passes bounds check)
    _safe_extract_tar(_tar({"p0.png": b"overwrite"}), dest)
    assert inside.read_text() == "original"   # not written through the symlink


def test_safe_extract_symlink_escape_blocked(tmp_path):
    # a symlink whose target is OUTSIDE dest is dropped by the resolve()+bounds check.
    import os
    dest = tmp_path / "out"
    dest.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text("original")
    os.symlink(secret, dest / "p0.png")   # dest/p0.png -> ../secret.txt (out of bounds)
    _safe_extract_tar(_tar({"p0.png": b"overwrite"}), dest)
    assert secret.read_text() == "original"


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


def test_detonate_remote_clears_stale_output(tmp_path):
    # a prior/requeued attempt's leftover file must be removed before extraction, so the trust gate
    # re-seals ONLY this attempt's output.
    out = tmp_path / "out"
    out.mkdir()
    (out / "stale.png").write_bytes(b"old")
    (tmp_path / "in.bin").write_bytes(b"z")
    tar = _tar({"metadata.json": json.dumps({"status": "ok"}).encode(), "page-001.png": b"new"})
    detonate_remote("http://h:8765", tmp_path / "in.bin", out, http_open=_opener(tar))
    assert not (out / "stale.png").exists()          # stale file dropped
    assert (out / "page-001.png").read_bytes() == b"new"


def test_extracted_artifacts_are_group_readable(tmp_path):
    # 0644 so a serve process on a different UID can read the artifacts (serve+dispatch split).
    import stat
    _safe_extract_tar(_tar({"p0.png": b"x"}), tmp_path)
    mode = stat.S_IMODE((tmp_path / "p0.png").stat().st_mode)
    assert mode & 0o044   # world/group readable


def test_detonate_remote_caps_member_count(tmp_path):
    from blastbox.host.runtime.remote_http import RemoteOutputTooLarge
    (tmp_path / "in.bin").write_bytes(b"z")
    many = _tar({"metadata.json": b"{}", **{f"f{i}.bin": b"x" for i in range(20)}})
    with pytest.raises(RemoteOutputTooLarge):
        detonate_remote("http://h:8765", tmp_path / "in.bin", tmp_path / "o",
                        http_open=_opener(many), max_members=5)


def test_extract_excludes_metadata_from_artifact_budget(tmp_path):
    # a job whose ARTIFACTS fit the budget but whose metadata.json would tip the byte total over must
    # NOT be rejected -- metadata is a control file with its own cap (matches the cold trust gate).
    big_meta = b'{"x":"' + b"a" * 900 + b'"}'      # ~910 bytes of metadata
    tar = _tar({"metadata.json": big_meta, "p0.png": b"x" * 200})
    # artifact budget 500: p0.png (200) fits; if metadata counted, 200+910 > 500 would (wrongly) fail.
    written = _safe_extract_tar(tar, tmp_path, max_total_bytes=500)
    assert set(written) == {"metadata.json", "p0.png"}


def test_detonate_remote_stream_cap_covers_metadata_budget(tmp_path):
    # a result whose ARTIFACTS fit max_output_bytes but whose (separately-capped) metadata is large must
    # NOT be rejected by the pre-extraction stream cap -- the stream cap must include the metadata budget.
    (tmp_path / "in.bin").write_bytes(b"z")
    big_meta = b'{"status":"ok","pad":"' + b"a" * 100_000 + b'"}'      # 100KB metadata (within its cap)
    tar = _tar({"metadata.json": big_meta, "p0.png": b"x" * 200})       # tiny artifact (within 1000)
    meta = detonate_remote("http://h:8765", tmp_path / "in.bin", tmp_path / "o",
                           http_open=_opener(tar), max_output_bytes=1000, max_metadata_bytes=4_000_000)
    assert meta.get("status") == "ok"   # not rejected: stream cap = artifact + metadata budgets + overhead


def test_detonate_remote_stream_cap_covers_member_headroom(tmp_path):
    # many tiny artifacts whose CONTENT fits max_output_bytes but whose per-member tar headers (512B each)
    # push the raw stream past artifact+metadata budgets. The stream cap must add per-member headroom
    # (~max_members*1KB) or a legitimate many-page result is (wrongly) rejected before extraction.
    (tmp_path / "in.bin").write_bytes(b"z")
    files = {"metadata.json": b'{"status":"ok"}'}
    files.update({f"p{i}.png": b"x" * 10 for i in range(200)})   # 2KB of content across 200 members
    tar = _tar(files)   # ~206KB stream (200 x 1KB tar blocks) -- exceeds 5000*1.1 + 2000 + 64KB naive cap
    meta = detonate_remote("http://h:8765", tmp_path / "in.bin", tmp_path / "o",
                           http_open=_opener(tar), max_output_bytes=5000, max_metadata_bytes=2000,
                           max_members=300)
    assert meta.get("status") == "ok"   # not rejected: stream cap includes max_members*1024 header headroom


def test_safe_extract_metadata_cap_applies_to_normalized_path(tmp_path):
    # F7 (security): a worker disguising the control file as "./metadata.json" still lands at
    # output/metadata.json, so it must get the METADATA cap -- not the (much larger) artifact byte budget.
    from blastbox.host.runtime.remote_http import RemoteOutputTooLarge
    tar = _tar({"./metadata.json": b'{"x":"' + b"a" * 5000 + b'"}'})   # ~5KB "metadata"
    with pytest.raises(RemoteOutputTooLarge):
        _safe_extract_tar(tar, tmp_path, max_total_bytes=1_000_000, max_metadata_bytes=1000)


def test_make_remote_validate_params_for_raise_releases_dirty(tmp_path):
    # F2: a raising params_for hook must NOT leak the claimed slot -- it is released DIRTY (retired) and
    # the caller gets the sanitized (error, False) contract, not an exception out of validate().
    from blastbox.host.runtime.remote_http import make_remote_validate
    released = []
    slot = SimpleNamespace(slot_id="s1", auth_token=None, agent_port=8765)

    def boom(_p):
        raise ValueError("bad hook")

    validate = make_remote_validate(
        lambda: slot, lambda s, dirty=False: released.append((s.slot_id, dirty)),
        output_dir_for=lambda p: tmp_path, params_for=boom)
    meta, ok = validate(tmp_path / "in.bin")
    assert ok is False and "error" in meta       # sanitized failure, not a raise
    assert released == [("s1", True)]            # claimed slot released DIRTY, not leaked ASSIGNED


def test_detonate_remote_caps_metadata_size(tmp_path):
    from blastbox.host.runtime.remote_http import RemoteOutputTooLarge
    (tmp_path / "in.bin").write_bytes(b"z")
    huge_meta = _tar({"metadata.json": b'{"x":"' + b"a" * 10000 + b'"}'})
    with pytest.raises(RemoteOutputTooLarge):
        detonate_remote("http://h:8765", tmp_path / "in.bin", tmp_path / "o",
                        http_open=_opener(huge_meta), max_metadata_bytes=1000)


def test_make_remote_validate_forwards_input_sha_to_trust(tmp_path):
    # the dispatcher-supplied authoritative ingress SHA reaches output_trust (not a recompute).
    (tmp_path / "in.docx").write_bytes(b"z")
    slot = SimpleNamespace(url=None, ip="10.0.1.4", auth_token=None, agent_port=8765)
    got = {}

    def trust(_in_path, _out_dir, sha, _owns=None):
        got["sha"] = sha

    validate = make_remote_validate(
        claim=lambda: slot, release=lambda s, dirty=False: None,
        output_dir_for=lambda p: tmp_path / "out",
        http_open=_opener(_tar({"metadata.json": json.dumps({"status": "ok"}).encode()})),
        output_trust=trust,
    )
    validate(tmp_path / "in.docx", input_sha256="deadbeef")
    assert got["sha"] == "deadbeef"


def test_make_remote_validate_forwards_owns_to_trust(tmp_path):
    # the ownership predicate reaches output_trust so it can fence the metadata write.
    (tmp_path / "in.docx").write_bytes(b"z")
    slot = SimpleNamespace(url=None, ip="10.0.1.4", auth_token=None, agent_port=8765)
    got = {}

    def trust(_in_path, _out_dir, _sha, owns=None):
        got["owns"] = owns() if owns else None

    validate = make_remote_validate(
        claim=lambda: slot, release=lambda s, dirty=False: None,
        output_dir_for=lambda p: tmp_path / "out",
        http_open=_opener(_tar({"metadata.json": json.dumps({"status": "ok"}).encode()})),
        output_trust=trust,
    )
    validate(tmp_path / "in.docx", owns=lambda: False)
    assert got["owns"] is False   # predicate threaded through


def test_detonate_remote_streams_input_with_content_length(tmp_path):
    # the input is streamed (open file handle + Content-Length), not read fully into memory.
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"x" * 1234)
    cap: list = []
    tar = _tar({"metadata.json": json.dumps({"status": "ok"}).encode()})
    detonate_remote("http://h:8765", inp, tmp_path / "out", http_open=_opener(tar, cap))
    req = cap[0]
    assert req.get_header("Content-length") == "1234"      # explicit length -> streamed body
    assert hasattr(req.data, "read")                        # data is a file object, not bytes


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

    def bad_trust(_in_path, _out_dir, _sha, _owns=None):
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

    def reseal(_in_path, out_dir, _sha, _owns=None):
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
    assert ok is False
    assert meta == {"error": "remote worker transport error"}   # sanitized reason surfaced
    assert released == [slot]   # released even on failure
