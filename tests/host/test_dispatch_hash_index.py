"""The dispatcher indexes per-page hashes on DONE — best-effort, capability-gated.

`_index_page_hashes` is called after the (cold + warm) DONE CAS; it must call the
store's `index_page_hashes` only when `supports_hash_search()` is True (PG+bktree),
no-op when the store lacks the capability (memory/redis) or has it but returns
False (SQLite / plain Postgres), and never let an indexing error fail a DONE job.
"""

from __future__ import annotations

from blastbox.host.dispatch import Dispatcher, EngineSpec
from blastbox.host.jobs.memory import InMemoryJobStore
from blastbox.limits import Limits


def _disp(store, tmp_path) -> Dispatcher:
    return Dispatcher(
        job_store=store,
        engines={"e": EngineSpec(name="e", image="img:t", worker_argv=[])},
        limits=Limits.from_env(),
        job_root=tmp_path,
    )


class _SpyStore(InMemoryJobStore):
    def __init__(self, *, supported: bool = True) -> None:
        super().__init__()
        self.indexed: list = []
        self._supported = supported

    def supports_hash_search(self) -> bool:
        return self._supported

    def index_page_hashes(self, job_id, envelope):
        self.indexed.append((job_id, envelope))


def test_indexes_when_store_supports_search(tmp_path):
    store = _SpyStore(supported=True)
    _disp(store, tmp_path)._index_page_hashes("job1", "ENV")
    assert store.indexed == [("job1", "ENV")]


def test_noop_when_store_lacks_capability(tmp_path):
    # InMemoryJobStore has no supports_hash_search/index_page_hashes — silent no-op
    _disp(InMemoryJobStore(), tmp_path)._index_page_hashes("job1", "ENV")


def test_noop_when_store_has_methods_but_search_unsupported(tmp_path):
    # SQLite / plain-PG case: methods present but supports_hash_search() is False
    # -> the dispatcher must NOT call index_page_hashes (it would raise).
    store = _SpyStore(supported=False)
    _disp(store, tmp_path)._index_page_hashes("job1", "ENV")
    assert store.indexed == []


def test_indexing_error_never_fails_the_job(tmp_path):
    class _Boom(_SpyStore):
        def index_page_hashes(self, *a):
            raise RuntimeError("boom")

    _disp(_Boom(supported=True), tmp_path)._index_page_hashes("job1", "ENV")  # no raise
