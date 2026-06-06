"""build_job_store_from_env — the shared-store selector for serve + dispatch."""
from blastbox.host.jobs.base import Job
from blastbox.host.jobs.factory import build_job_store_from_env
from blastbox.host.jobs.memory import InMemoryJobStore


def test_unset_url_returns_in_memory():
    assert isinstance(build_job_store_from_env({}), InMemoryJobStore)


def test_sqlite_url_returns_sql_store(tmp_path):
    from blastbox.host.jobs.sql_store import SqlJobStore

    store = build_job_store_from_env(
        {"BLASTBOX_DATABASE_URL": f"sqlite:///{tmp_path / 'j.db'}"}
    )
    assert isinstance(store, SqlJobStore)


def test_serve_and_dispatch_share_a_sqlite_store(tmp_path):
    """The fix: a job created via one handle is visible via a SECOND handle built from the
    same URL — i.e. `serve` (creates the job) and `dispatch` (claims it) actually share state,
    which a per-process in-memory store does NOT."""
    url = f"sqlite:///{tmp_path / 'shared.db'}"
    serve_store = build_job_store_from_env({"BLASTBOX_DATABASE_URL": url})
    dispatch_store = build_job_store_from_env({"BLASTBOX_DATABASE_URL": url})

    job = Job.new(engine="probe", filename="x.txt")
    serve_store.create(job)
    assert dispatch_store.get(job.job_id) is not None
