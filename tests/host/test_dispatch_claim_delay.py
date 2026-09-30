"""BLASTBOX_CLAIM_UNTARGETED_AFTER_S: a dispatcher that leaves fresh untargeted work to its peers.

Measured on a production host: a warm Firecracker dispatcher and a cold dispatcher share one
store, untargeted jobs are claimable by both, and the cold one took 2-8 of 16 while warm slots
were free. Setting the knob on the COLD dispatcher only (e.g. 3) makes it decline an untargeted
job until it is that old, so a warm dispatcher with a free slot gets it first and cold is the
overflow. The store-side semantics are tested per backend in
tests/host/jobs/test_claim_untargeted_after.py; this file covers the Dispatcher and CLI wiring.
"""
from __future__ import annotations

import argparse
import math
import time

import pytest

from blastbox.host.dispatch import Dispatcher
from blastbox.host.jobs.base import JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore
from tests.host.test_dispatch import (
    _ENGINE_NAME,
    _engine_spec,
    _fake_runtime,
    _limits,
    _make_job,
)


def _dispatcher(store, tmp_path, **kw) -> Dispatcher:
    return Dispatcher(job_store=store, engines={_ENGINE_NAME: _engine_spec()}, limits=_limits(),
                      job_root=tmp_path, runtime_selector=_fake_runtime, **kw)


class _Recording(InMemoryJobStore):
    def __init__(self) -> None:
        super().__init__()
        self.calls: list[dict] = []

    def claim_next(self, **kw):  # type: ignore[override]
        self.calls.append(kw)
        return super().claim_next(**kw)


# --- Dispatcher --------------------------------------------------------------------------------

def test_default_dispatcher_does_not_pass_the_kwarg(tmp_path):
    store = _Recording()
    assert _dispatcher(store, tmp_path).dispatch_once() is False
    assert store.calls == [{"claimant_tier": "cold"}]


def test_zero_delay_keeps_a_legacy_store_working(tmp_path):
    # A store implementing only the original claim_next(*, claimant_tier=) shape must not get a
    # TypeError from a dispatcher that has the knob at its default.
    store = InMemoryJobStore()
    orig = store.claim_next

    def legacy(*, claimant_tier=None):
        return orig(claimant_tier=claimant_tier)

    store.claim_next = legacy  # type: ignore[method-assign]
    assert _dispatcher(store, tmp_path, claim_untargeted_after_s=0.0).dispatch_once() is False


def test_nonzero_delay_is_passed_to_the_store(tmp_path):
    store = _Recording()
    _dispatcher(store, tmp_path, claim_untargeted_after_s=3.0).dispatch_once()
    assert store.calls == [{"claimant_tier": "cold", "untargeted_min_age_s": 3.0}]


def test_delay_composes_with_engine_scoping(tmp_path, monkeypatch):
    monkeypatch.setenv("BLASTBOX_DISPATCHER_ENGINE_SCOPED", "1")
    store = _Recording()
    _dispatcher(store, tmp_path, claim_untargeted_after_s=3.0).dispatch_once()
    assert store.calls == [{"claimant_tier": "cold", "engine": frozenset({_ENGINE_NAME}),
                            "untargeted_min_age_s": 3.0}]


def test_delayed_dispatcher_leaves_a_fresh_untargeted_job_queued(tmp_path):
    store = InMemoryJobStore()
    job = _make_job()
    store.create(job)
    assert _dispatcher(store, tmp_path, claim_untargeted_after_s=30.0).dispatch_once() is False
    assert store.get(job.job_id).status == JobStatus.QUEUED


def test_delayed_dispatcher_takes_an_aged_untargeted_job(tmp_path):
    store = _Recording()
    job = _make_job()
    job.created_at = time.time() - 60
    store.create(job)
    d = _dispatcher(store, tmp_path, claim_untargeted_after_s=30.0)
    d._dispatch_claimed_job = lambda j, **kw: None  # type: ignore[method-assign]
    assert d.dispatch_once() is True
    assert store.get(job.job_id).status == JobStatus.RUNNING


@pytest.mark.parametrize("bad", [math.nan, math.inf, -1.0])
def test_dispatcher_refuses_a_nonsense_delay(tmp_path, bad):
    with pytest.raises(ValueError, match="claim_untargeted_after_s"):
        _dispatcher(InMemoryJobStore(), tmp_path, claim_untargeted_after_s=bad)


# --- CLI env parsing ---------------------------------------------------------------------------

@pytest.mark.parametrize(("raw", "want"), [
    (None, 0.0), ("", 0.0), ("  ", 0.0), ("0", 0.0), ("3", 3.0), ("2.5", 2.5),
])
def test_env_parsing_valid(monkeypatch, raw, want):
    from blastbox.host.cli import _claim_untargeted_after_s
    if raw is None:
        monkeypatch.delenv("BLASTBOX_CLAIM_UNTARGETED_AFTER_S", raising=False)
    else:
        monkeypatch.setenv("BLASTBOX_CLAIM_UNTARGETED_AFTER_S", raw)
    assert _claim_untargeted_after_s() == want


@pytest.mark.parametrize("raw", ["nan", "inf", "-inf", "-1", "soon"])
def test_env_parsing_refuses_nonsense(monkeypatch, raw):
    # refuse, don't drop: a typo'd delay silently becoming 0 would turn an overflow-only cold
    # dispatcher back into one racing its warm peer for every untargeted job
    from blastbox.host.cli import _claim_untargeted_after_s
    monkeypatch.setenv("BLASTBOX_CLAIM_UNTARGETED_AFTER_S", raw)
    with pytest.raises(ValueError, match="BLASTBOX_CLAIM_UNTARGETED_AFTER_S"):
        _claim_untargeted_after_s()


class _Built(Exception):
    pass


def _run_dispatch_cmd(monkeypatch, store):
    """Drive `_dispatch_cmd` up to Dispatcher construction and return the kwargs it used."""
    import blastbox.host.dispatch as dispatch_mod
    import blastbox.host.jobs.factory as factory

    seen: dict = {}

    def fake_dispatcher(**kw):
        seen.update(kw)
        raise _Built

    monkeypatch.setattr(factory, "build_job_store_from_env", lambda: store)
    monkeypatch.setattr(dispatch_mod, "Dispatcher", fake_dispatcher)
    monkeypatch.delenv("BLASTBOX_POOL_RUNTIME", raising=False)
    from blastbox.host.cli import _dispatch_cmd
    with pytest.raises(_Built):
        _dispatch_cmd(argparse.Namespace(engines=f"{_ENGINE_NAME}=img:tag"))
    return seen


def test_dispatch_cmd_threads_the_env_value_into_the_dispatcher(monkeypatch):
    monkeypatch.setenv("BLASTBOX_CLAIM_UNTARGETED_AFTER_S", "3")
    assert _run_dispatch_cmd(monkeypatch, InMemoryJobStore())["claim_untargeted_after_s"] == 3.0


def test_dispatch_cmd_default_is_zero(monkeypatch):
    monkeypatch.delenv("BLASTBOX_CLAIM_UNTARGETED_AFTER_S", raising=False)
    assert _run_dispatch_cmd(monkeypatch, InMemoryJobStore())["claim_untargeted_after_s"] == 0.0


def test_dispatch_cmd_refuses_the_knob_on_a_control_plane_store(monkeypatch, tmp_path):
    """The node route cannot carry the delay, so the combination fails at startup rather than
    on every claim."""
    import blastbox.host.dispatch as dispatch_mod
    import blastbox.host.jobs.factory as factory
    from blastbox.host.cli import _dispatch_cmd
    from blastbox.host.jobs.http_store import HttpJobStore

    def built(**kw):
        raise _Built

    store = HttpJobStore.__new__(HttpJobStore)   # never contacted: refused before any claim
    monkeypatch.setattr(factory, "build_job_store_from_env", lambda: store)
    monkeypatch.setattr(dispatch_mod, "Dispatcher", built)
    monkeypatch.delenv("BLASTBOX_POOL_RUNTIME", raising=False)
    monkeypatch.setenv("BLASTBOX_CLAIM_UNTARGETED_AFTER_S", "3")
    with pytest.raises(ValueError, match="BLASTBOX_CLAIM_UNTARGETED_AFTER_S"):
        _dispatch_cmd(argparse.Namespace(engines=f"{_ENGINE_NAME}=img:tag"))


def test_dispatch_cmd_refuses_the_knob_on_a_network_endpoint_tier(monkeypatch):
    """VmJobDispatcher (aws/static/cascade) does not implement the delay; refuse, don't ignore."""
    import types

    import blastbox.host.jobs.factory as factory
    import blastbox.host.pool_config as pool_config
    from blastbox.host.cli import _dispatch_cmd

    started: list = []
    pool = types.SimpleNamespace(runtime=types.SimpleNamespace(dispatch_style="network"),
                                 start=lambda: started.append(True))
    monkeypatch.setattr(factory, "build_job_store_from_env", lambda: InMemoryJobStore())
    monkeypatch.setattr(pool_config, "build_warm_pool", lambda: pool)
    monkeypatch.setenv("BLASTBOX_POOL_RUNTIME", "static")
    monkeypatch.setenv("BLASTBOX_CLAIM_UNTARGETED_AFTER_S", "3")
    with pytest.raises(ValueError, match="network-endpoint"):
        _dispatch_cmd(argparse.Namespace(engines=f"{_ENGINE_NAME}=img:tag"))
    assert started == []                        # refused before any slot was spawned


# --- review round 1 (#193) ---------------------------------------------------------------------

def test_a_nonzero_delay_refuses_a_store_that_cannot_take_it(tmp_path):
    """A store with only the original claim_next(*, claimant_tier=) shape would raise TypeError on
    EVERY poll once the delay is on -- a dispatcher that never claims. Refused at construction."""
    store = InMemoryJobStore()
    orig = store.claim_next

    def legacy(*, claimant_tier=None):
        return orig(claimant_tier=claimant_tier)

    store.claim_next = legacy  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="untargeted_min_age_s"):
        _dispatcher(store, tmp_path, claim_untargeted_after_s=3.0)


def test_a_store_taking_kwargs_is_accepted(tmp_path):
    assert _dispatcher(_Recording(), tmp_path, claim_untargeted_after_s=3.0) is not None


@pytest.mark.parametrize(("delay", "ttl"), [(3.0, 3.0), (10.0, 5.0)])
def test_a_delay_at_or_past_the_queued_ttl_is_refused(tmp_path, delay, ttl):
    """BLASTBOX_MAX_QUEUED_AGE_S fails any job still QUEUED past its TTL (and deletes its input).
    With the delay >= the TTL, every job only this dispatcher would take is expired first."""
    with pytest.raises(ValueError, match="max_queued_age"):
        _dispatcher(InMemoryJobStore(), tmp_path, claim_untargeted_after_s=delay,
                    max_queued_age_s=ttl)


@pytest.mark.parametrize(("delay", "ttl"), [(3.0, 0.0), (3.0, 60.0)])
def test_a_delay_below_the_ttl_or_with_no_ttl_is_fine(tmp_path, delay, ttl):
    assert _dispatcher(InMemoryJobStore(), tmp_path, claim_untargeted_after_s=delay,
                       max_queued_age_s=ttl) is not None


# --- review round 2 (#193) ---------------------------------------------------------------------

def test_a_store_that_declares_but_refuses_the_delay_is_refused_at_construction(tmp_path):
    """HttpJobStore DECLARES untargeted_min_age_s only to raise on it: a signature check passed it,
    and every poll then failed. Stores state support explicitly."""
    from blastbox.host.jobs.http_store import HttpJobStore

    store = HttpJobStore.__new__(HttpJobStore)
    with pytest.raises(ValueError, match="supports_untargeted_delay"):
        _dispatcher(store, tmp_path, claim_untargeted_after_s=5.0)


@pytest.mark.parametrize("store_name", ["InMemoryJobStore", "SqlJobStore", "RedisJobStore"])
def test_the_stores_that_honour_the_delay_say_so(store_name):
    import blastbox.host.jobs as jobs_pkg  # noqa: F401
    from blastbox.host.jobs import memory, redis_store, sql_store

    cls = {"InMemoryJobStore": memory.InMemoryJobStore, "SqlJobStore": sql_store.SqlJobStore,
           "RedisJobStore": redis_store.RedisJobStore}[store_name]
    assert getattr(cls, "supports_untargeted_delay", False) is True


def test_dispatch_cmd_refuses_a_delay_past_the_ttl_before_spawning_slots(monkeypatch):
    """The Dispatcher refused this only AFTER pool.start(): the warm slots it had spawned were never
    stopped (orphaned VMs/containers on every restart)."""
    import types

    import blastbox.host.jobs.factory as factory
    import blastbox.host.pool_config as pool_config
    from blastbox.host.cli import _dispatch_cmd

    started: list = []
    pool = types.SimpleNamespace(runtime=types.SimpleNamespace(dispatch_style="file"),
                                 start=lambda: started.append(True))
    monkeypatch.setattr(factory, "build_job_store_from_env", lambda: InMemoryJobStore())
    monkeypatch.setattr(pool_config, "build_warm_pool", lambda: pool)
    monkeypatch.setenv("BLASTBOX_POOL_RUNTIME", "firecracker")
    monkeypatch.setenv("BLASTBOX_CLAIM_UNTARGETED_AFTER_S", "300")
    monkeypatch.setenv("BLASTBOX_MAX_QUEUED_AGE_S", "300")
    with pytest.raises(ValueError, match="MAX_QUEUED_AGE_S"):
        _dispatch_cmd(argparse.Namespace(engines=f"{_ENGINE_NAME}=img:tag"))
    assert started == []


# --- review round 9 (#193) ---------------------------------------------------------------------

def test_a_store_that_does_not_state_delay_support_is_refused(tmp_path):
    """Fail closed: a wrapper whose claim_next takes **kw passed the signature check and silently
    DROPPED the delay (a fresh untargeted job was claimed at once). A store must state
    supports_untargeted_delay = True."""
    class _Wrapper:
        def __init__(self):
            self.inner = InMemoryJobStore()

        def __getattr__(self, name):
            if name == "supports_untargeted_delay":
                raise AttributeError(name)
            return getattr(self.inner, name)

        def claim_next(self, *, claimant_tier=None, **kw):
            return self.inner.claim_next(claimant_tier=claimant_tier)

    with pytest.raises(ValueError, match="supports_untargeted_delay"):
        _dispatcher(_Wrapper(), tmp_path, claim_untargeted_after_s=30.0)


def test_a_wrapper_without_a_delay_is_still_fine(tmp_path):
    class _Wrapper:
        def __init__(self):
            self.inner = InMemoryJobStore()

        def __getattr__(self, name):
            return getattr(self.inner, name)
    assert _dispatcher(_Wrapper(), tmp_path, claim_untargeted_after_s=0.0) is not None


@pytest.mark.parametrize("raw", ["nan", "-1", "soon"])
def test_dispatch_cmd_refuses_an_invalid_delay_before_spawning_slots(monkeypatch, raw):
    import types

    import blastbox.host.jobs.factory as factory
    import blastbox.host.pool_config as pool_config
    from blastbox.host.cli import _dispatch_cmd

    started: list = []
    pool = types.SimpleNamespace(runtime=types.SimpleNamespace(dispatch_style="file"),
                                 start=lambda: started.append(True))
    monkeypatch.setattr(factory, "build_job_store_from_env", lambda: InMemoryJobStore())
    monkeypatch.setattr(pool_config, "build_warm_pool", lambda: pool)
    monkeypatch.setenv("BLASTBOX_POOL_RUNTIME", "firecracker")
    monkeypatch.setenv("BLASTBOX_CLAIM_UNTARGETED_AFTER_S", raw)
    with pytest.raises(ValueError, match="BLASTBOX_CLAIM_UNTARGETED_AFTER_S"):
        _dispatch_cmd(argparse.Namespace(engines=f"{_ENGINE_NAME}=img:tag"))
    assert started == []
