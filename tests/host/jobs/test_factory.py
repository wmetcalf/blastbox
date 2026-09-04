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


def test_redis_ttl_seconds_passed_through(monkeypatch):
    """BLASTBOX_REDIS_TTL_SECONDS is parsed and forwarded to RedisJobStore (0 => no expiry)."""
    import redis

    import blastbox.host.jobs.redis_store as redis_store_mod

    captured = {}

    class _FakeRedisStore:
        def __init__(self, client, *, ttl_seconds=86400):
            captured["ttl_seconds"] = ttl_seconds

    monkeypatch.setattr(redis, "from_url", lambda url: object())
    monkeypatch.setattr(redis_store_mod, "RedisJobStore", _FakeRedisStore)

    build_job_store_from_env(
        {
            "BLASTBOX_DATABASE_URL": "redis://localhost:6379/0",
            "BLASTBOX_REDIS_TTL_SECONDS": "0",
        }
    )
    assert captured["ttl_seconds"] == 0


def test_redis_ttl_seconds_unset_uses_store_default(monkeypatch):
    """Unset TTL => factory passes no ttl_seconds kwarg, so the store default applies."""
    import redis

    import blastbox.host.jobs.redis_store as redis_store_mod

    captured = {}

    class _FakeRedisStore:
        def __init__(self, client, *, ttl_seconds="STORE_DEFAULT"):
            captured["ttl_seconds"] = ttl_seconds

    monkeypatch.setattr(redis, "from_url", lambda url: object())
    monkeypatch.setattr(redis_store_mod, "RedisJobStore", _FakeRedisStore)

    build_job_store_from_env({"BLASTBOX_DATABASE_URL": "redis://localhost:6379/0"})
    assert captured["ttl_seconds"] == "STORE_DEFAULT"


def test_redis_ttl_seconds_negative_uses_store_default(monkeypatch):
    """A negative TTL is rejected (logged) and the store default applies — not silent no-expiry."""
    import redis

    import blastbox.host.jobs.redis_store as redis_store_mod

    captured = {}

    class _FakeRedisStore:
        def __init__(self, client, *, ttl_seconds="STORE_DEFAULT"):
            captured["ttl_seconds"] = ttl_seconds

    monkeypatch.setattr(redis, "from_url", lambda url: object())
    monkeypatch.setattr(redis_store_mod, "RedisJobStore", _FakeRedisStore)

    build_job_store_from_env(
        {
            "BLASTBOX_DATABASE_URL": "redis://localhost:6379/0",
            "BLASTBOX_REDIS_TTL_SECONDS": "-5",
        }
    )
    assert captured["ttl_seconds"] == "STORE_DEFAULT"
