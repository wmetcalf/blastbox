"""The dispatcher indexes per-page hashes on DONE — best-effort, capability-gated.

`_index_page_hashes` is called after the (cold + warm) DONE CAS; it must call the
store's `index_page_hashes` when present, no-op when absent (memory/redis), and
never let an indexing error fail an otherwise-DONE job.
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
    def __init__(self) -> None:
        super().__init__()
        self.indexed: list = []

    def index_page_hashes(self, job_id, envelope):
        self.indexed.append((job_id, envelope))


def test_indexes_when_store_has_capability(tmp_path):
    store = _SpyStore()
    _disp(store, tmp_path)._index_page_hashes("job1", "ENV")
    assert store.indexed == [("job1", "ENV")]


def test_noop_when_store_lacks_capability(tmp_path):
    # InMemoryJobStore has no index_page_hashes — must be a silent no-op
    _disp(InMemoryJobStore(), tmp_path)._index_page_hashes("job1", "ENV")


def test_indexing_error_never_fails_the_job(tmp_path):
    class _Boom(InMemoryJobStore):
        def index_page_hashes(self, *a):
            raise RuntimeError("boom")

    _disp(_Boom(), tmp_path)._index_page_hashes("job1", "ENV")  # best-effort: no raise
