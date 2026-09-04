"""TDD for concurrent dispatch (BLASTBOX_DISPATCH_CONCURRENCY).

run_forever(concurrency=N) runs N dispatch-loop threads that claim+dispatch
independently; correctness comes from the claim fence + thread-safe stores. The
serial path (concurrency<=1) is unchanged (runs in the calling thread).
"""
from __future__ import annotations

import threading

from blastbox.host.dispatch import Dispatcher, EngineSpec
from blastbox.host.jobs.memory import InMemoryJobStore
from blastbox.limits import Limits


def _disp(tmp_path) -> Dispatcher:
    return Dispatcher(
        job_store=InMemoryJobStore(),
        engines={"e": EngineSpec(name="e", image="img:t", worker_argv=[])},
        limits=Limits.from_env(),
        job_root=tmp_path,
    )


def test_concurrency_n_uses_multiple_threads(tmp_path, monkeypatch):
    d = _disp(tmp_path)
    calls: list[int] = []
    seen: set[str] = set()
    lock = threading.Lock()

    def fake_dispatch_once() -> bool:
        with lock:
            calls.append(1)
            seen.add(threading.current_thread().name)
        return False  # no progress -> short sleep, keep looping

    monkeypatch.setattr(d, "dispatch_once", fake_dispatch_once)
    d.run_forever(
        poll_interval_s=0.001,
        maintenance_interval_s=0,
        stop=lambda: len(calls) >= 40,
        concurrency=4,
    )
    assert len(calls) >= 40
    assert len(seen) >= 2  # multiple dispatch threads ran concurrently


def test_concurrency_1_runs_in_calling_thread(tmp_path, monkeypatch):
    d = _disp(tmp_path)
    calls: list[int] = []
    seen: set[str] = set()

    def fake_dispatch_once() -> bool:
        seen.add(threading.current_thread().name)
        calls.append(1)
        return False

    monkeypatch.setattr(d, "dispatch_once", fake_dispatch_once)
    d.run_forever(
        poll_interval_s=0.001,
        maintenance_interval_s=0,
        stop=lambda: len(calls) >= 5,
        concurrency=1,
    )
    assert seen == {threading.current_thread().name}  # serial path unchanged
