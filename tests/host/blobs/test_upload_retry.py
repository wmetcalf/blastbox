"""Shared upload-failure policy (Finding D1): a few bounded inline attempts, then
give up and report the last error to the caller — never left "pending" for a
consumer that does not exist.
"""
from pathlib import Path


from blastbox.host.blobs.base import upload_output_with_retry


class _FlakyStore:
    """put_output fails `fail_times` times, then succeeds."""

    def __init__(self, fail_times: int) -> None:
        self.fail_times = fail_times
        self.calls = 0

    def put_output(self, job_id: str, out_dir: Path) -> None:
        self.calls += 1
        if self.calls <= self.fail_times:
            raise OSError("object store down")


class _AlwaysFailsStore:
    def __init__(self) -> None:
        self.calls = 0

    def put_output(self, job_id: str, out_dir: Path) -> None:
        self.calls += 1
        raise OSError(f"object store down (attempt {self.calls})")


def test_succeeds_on_a_later_attempt_without_exhausting_the_budget(tmp_path):
    store = _FlakyStore(fail_times=2)
    exc = upload_output_with_retry(store, "job-1", tmp_path, attempts=3, backoff_s=0)
    assert exc is None
    assert store.calls == 3


def test_first_attempt_success_calls_put_output_exactly_once(tmp_path):
    store = _FlakyStore(fail_times=0)
    exc = upload_output_with_retry(store, "job-1", tmp_path, attempts=3, backoff_s=0)
    assert exc is None
    assert store.calls == 1


def test_returns_the_last_exception_after_exhausting_every_attempt(tmp_path):
    store = _AlwaysFailsStore()
    exc = upload_output_with_retry(store, "job-1", tmp_path, attempts=3, backoff_s=0)
    assert isinstance(exc, OSError)
    assert "attempt 3" in str(exc)
    assert store.calls == 3


def test_attempts_is_bounded_not_infinite(tmp_path):
    store = _AlwaysFailsStore()
    upload_output_with_retry(store, "job-1", tmp_path, attempts=5, backoff_s=0)
    assert store.calls == 5
