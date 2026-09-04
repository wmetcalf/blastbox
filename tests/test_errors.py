"""Tests for blastbox.errors."""
from __future__ import annotations


from blastbox.errors import (
    BlastboxError,
    DetectionError,
    SandboxError,
    SandboxTimeout,
    SandboxUnavailable,
    EngineError,
    DetonationError,
    ValidationError,
    sanitize_public_error,
)


# ---------------------------------------------------------------------------
# sanitize_public_error — root-agnostic absolute-path scrubber
# ---------------------------------------------------------------------------

def test_scrubber_redacts_etc_passwd():
    msg = "open /etc/passwd failed"
    result = sanitize_public_error(msg)
    assert "/etc/passwd" not in result
    assert "<path>" in result


def test_scrubber_redacts_var_lib_path():
    msg = "no such file /var/lib/blastbox/jobs/abc123/result"
    result = sanitize_public_error(msg)
    assert "/var/lib/" not in result
    assert "<path>" in result


def test_scrubber_redacts_proc_self():
    msg = "cannot read /proc/self/mem"
    result = sanitize_public_error(msg)
    assert "/proc/self" not in result
    assert "<path>" in result


def test_scrubber_leaves_and_or():
    """'and/or' is not an absolute path and must not be touched."""
    msg = "you can use option A and/or option B"
    assert sanitize_public_error(msg) == msg


def test_scrubber_leaves_plain_text():
    msg = "conversion failed: timeout exceeded"
    assert sanitize_public_error(msg) == msg


def test_scrubber_replaces_multiple_paths():
    msg = "copying /etc/hosts to /tmp/foo/bar"
    result = sanitize_public_error(msg)
    assert "/etc/hosts" not in result
    assert "/tmp/foo/bar" not in result
    assert result.count("<path>") == 2


def test_scrubber_long_nested_path():
    msg = "error at /home/user/uploads/123/input.docx line 1"
    result = sanitize_public_error(msg)
    assert "/home/user/uploads" not in result
    assert "<path>" in result


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------

def test_blastbox_error_is_exception():
    e = BlastboxError("base error")
    assert isinstance(e, Exception)
    assert str(e) == "base error"


def test_detection_error_attrs():
    e = DetectionError("rejected", detail="zip bomb")
    assert e.reason == "rejected"
    assert e.detail == "zip bomb"
    assert "rejected" in str(e)
    assert "zip bomb" in str(e)
    assert isinstance(e, BlastboxError)


def test_detection_error_no_detail():
    e = DetectionError("bad type")
    assert e.reason == "bad type"
    assert e.detail == ""
    assert str(e) == "bad type"


def test_sandbox_error_hierarchy():
    e = SandboxError("sandbox failed")
    assert isinstance(e, BlastboxError)


def test_sandbox_timeout_hierarchy():
    e = SandboxTimeout("timed out")
    assert isinstance(e, SandboxError)
    assert isinstance(e, BlastboxError)


def test_sandbox_unavailable_hierarchy():
    e = SandboxUnavailable("no sandbox available")
    assert isinstance(e, SandboxError)


def test_engine_error_hierarchy():
    e = EngineError("engine crashed")
    assert isinstance(e, BlastboxError)


def test_detonation_error_with_cause():
    cause = RuntimeError("underlying")
    e = DetonationError("detonation failed", cause=cause)
    assert e.cause is cause
    assert e.__cause__ is cause
    assert isinstance(e, BlastboxError)


def test_detonation_error_no_cause():
    e = DetonationError("failed")
    assert e.cause is None


def test_validation_error_hierarchy():
    e = ValidationError("bad envelope")
    assert isinstance(e, BlastboxError)


def test_sanitize_public_error_redacts_dsn_credentials():
    from blastbox.errors import sanitize_public_error
    out = sanitize_public_error("conn failed: postgresql://u:secret@db.internal:5432/jobs")
    assert "secret" not in out and "<redacted>" in out
    out2 = sanitize_public_error("could not connect host=db.internal port=5432 password=hunter2")
    assert "hunter2" not in out2 and "db.internal" not in out2 and "5432" not in out2
