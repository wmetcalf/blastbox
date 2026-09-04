"""Tests for blastbox.host.jobs.base — Job model + JobStore protocol."""

from __future__ import annotations

import time
import uuid


from blastbox.host.jobs.base import Job, JobStatus, JobStore


# ---------------------------------------------------------------------------
# Job.new() shape
# ---------------------------------------------------------------------------


def test_new_generates_uuid():
    job = Job.new(engine="test-engine", filename="test.docx")
    # Should be a valid UUID4
    parsed = uuid.UUID(job.job_id, version=4)
    assert str(parsed) == job.job_id


def test_new_status_queued():
    job = Job.new(engine="test-engine", filename="test.docx")
    assert job.status == JobStatus.QUEUED


def test_new_created_at_recent():
    before = time.time()
    job = Job.new(engine="test-engine", filename="test.docx")
    after = time.time()
    assert before <= job.created_at <= after


def test_new_engine_set():
    job = Job.new(engine="my-engine", filename="file.pdf")
    assert job.engine == "my-engine"


def test_new_filename_set():
    job = Job.new(engine="e", filename="report.xlsx")
    assert job.filename == "report.xlsx"


def test_new_optional_fields_none_or_empty():
    job = Job.new(engine="e", filename="f.txt")
    assert job.started_at is None
    assert job.finished_at is None
    assert job.expires_at is None
    assert job.input_sha256 is None
    assert job.result_dir is None
    assert job.worker_runtime is None
    assert job.error is None
    assert job.security_warnings == []
    assert job.params == {}
    assert job.result_summary is None


# ---------------------------------------------------------------------------
# to_dict / from_dict round-trip
# ---------------------------------------------------------------------------


def test_to_dict_from_dict_roundtrip():
    job = Job.new(engine="engine-a", filename="doc.docx")
    job.params = {"key": "value", "flag": "1"}
    job.result_summary = {"pages": 3, "format": "pdf"}
    job.security_warnings = ["macro_enabled"]

    d = job.to_dict()
    restored = Job.from_dict(d)

    assert restored.job_id == job.job_id
    assert restored.engine == job.engine
    assert restored.filename == job.filename
    assert restored.status == job.status
    assert restored.created_at == job.created_at
    assert restored.params == {"key": "value", "flag": "1"}
    assert restored.result_summary == {"pages": 3, "format": "pdf"}
    assert restored.security_warnings == ["macro_enabled"]


def test_to_dict_status_is_string():
    job = Job.new(engine="e", filename="f.txt")
    d = job.to_dict()
    assert isinstance(d["status"], str)
    assert d["status"] == "queued"


def test_from_dict_preserves_result_dir():
    job = Job.new(engine="e", filename="f.txt")
    job.result_dir = "/var/data/results/abc"
    d = job.to_dict()
    restored = Job.from_dict(d)
    assert restored.result_dir == "/var/data/results/abc"


# ---------------------------------------------------------------------------
# to_public_dict — strips result_dir + params, sanitizes error
# ---------------------------------------------------------------------------


def test_public_dict_strips_result_dir():
    job = Job.new(engine="e", filename="f.txt")
    job.result_dir = "/internal/path/to/result"
    pub = job.to_public_dict()
    assert "result_dir" not in pub


def test_public_dict_strips_params():
    job = Job.new(engine="e", filename="f.txt")
    job.params = {"secret_key": "abc123"}
    pub = job.to_public_dict()
    assert "params" not in pub


def test_public_dict_strips_claimable_after():
    # claimable_after is an internal capacity-deferral scheduling detail — not exposed publicly,
    # but retained in the internal dict for persistence.
    job = Job.new(engine="e", filename="f.txt")
    job.claimable_after = 1234.5
    assert "claimable_after" not in job.to_public_dict()
    assert job.to_dict().get("claimable_after") == 1234.5


def test_public_dict_strips_materialise_attempts():
    # materialise_attempts is an internal bounded-retry scheduling counter — a sibling
    # of claimable_after -- not exposed publicly, but retained in the internal dict.
    job = Job.new(engine="e", filename="f.txt")
    job.materialise_attempts = 2
    pub = job.to_public_dict()
    assert "materialise_attempts" not in pub
    assert job.to_dict().get("materialise_attempts") == 2


def test_public_dict_still_contains_genuinely_public_fields():
    job = Job.new(engine="e", filename="f.txt")
    pub = job.to_public_dict()
    for field in ("job_id", "engine", "filename", "status", "created_at"):
        assert field in pub


def test_public_dict_sanitizes_error():
    job = Job.new(engine="e", filename="f.txt")
    job.error = "file not found: /var/lib/blastbox/jobs/abc/input.docx"
    pub = job.to_public_dict()
    assert "/var/lib" not in pub["error"]
    assert "<path>" in pub["error"]


def test_public_dict_preserves_result_summary():
    job = Job.new(engine="e", filename="f.txt")
    job.result_summary = {"pages": 5}
    pub = job.to_public_dict()
    assert pub["result_summary"] == {"pages": 5}


def test_public_dict_no_error_passthrough():
    job = Job.new(engine="e", filename="f.txt")
    job.error = None
    pub = job.to_public_dict()
    assert pub.get("error") is None


# ---------------------------------------------------------------------------
# JobStore protocol check
# ---------------------------------------------------------------------------


def test_jobstore_is_protocol():
    # Verify the protocol declares all expected methods via its annotations
    # (works on Python 3.12 where get_protocol_members is not yet available)
    members = set(JobStore.__protocol_attrs__)  # type: ignore[attr-defined]
    assert "create" in members
    assert "get" in members
    assert "update" in members
    assert "list" in members
    assert "claim_next" in members
    assert "delete" in members


# ---------------------------------------------------------------------------
# Job.net_policy field
# ---------------------------------------------------------------------------


def test_job_net_policy_defaults_none():
    from blastbox.host.jobs.base import Job

    j = Job.new(engine="redtusk", filename="x.doc")
    assert j.net_policy is None


def test_job_net_policy_roundtrips_through_dict():
    from blastbox.host.jobs.base import Job

    j = Job.new(engine="redtusk", filename="x.doc")
    j.net_policy = "fakenet"
    assert Job.from_dict(j.to_dict()).net_policy == "fakenet"
