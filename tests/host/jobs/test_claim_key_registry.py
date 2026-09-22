"""One signing key for every ingress process, held where they already agree: the queue (#178).

Node challenges, session tokens and claim receipts are MACs. Two ingress hosts behind a load
balancer each generating their own key mint credentials the other rejects, and the documented
role-separated topology rejects a shared filesystem — so the key lives in the job store, by the
same argument `BlobTargetRegistry` makes. These tests hold every backend to the same contract.
"""
from __future__ import annotations

import secrets
import tempfile
import threading

import pytest

from blastbox.host.jobs.base import ClaimKeyRegistry
from blastbox.host.jobs.memory import InMemoryJobStore
from blastbox.host.jobs.sql_store import SqlJobStore


def _sql() -> SqlJobStore:
    return SqlJobStore(f"sqlite:///{tempfile.mkdtemp()}/j.db")


ALL_BACKENDS = [pytest.param(InMemoryJobStore, id="memory"), pytest.param(_sql, id="sql")]


@pytest.mark.parametrize("make", ALL_BACKENDS)
def test_every_shipped_store_implements_the_registry(make):
    """A store this repo ships must not fall back to the per-host file: that fallback is the
    multi-host bug, and it exists only for third-party stores."""
    assert isinstance(make(), ClaimKeyRegistry)


@pytest.mark.parametrize("make", ALL_BACKENDS)
def test_the_first_claim_wins_and_every_later_claim_reads_it(make):
    store = make()
    first, second = secrets.token_hex(32), secrets.token_hex(32)
    assert store.claim_signing_key(first) == first
    assert store.claim_signing_key(second) == first, "a later boot overwrote the fleet's key"
    assert store.get_signing_key() == first


@pytest.mark.parametrize("make", ALL_BACKENDS)
def test_get_is_read_only(make):
    """A diagnostic that writes is not a diagnostic: `show` must never register anything."""
    store = make()
    assert store.get_signing_key() is None
    assert store.get_signing_key() is None
    assert store.claim_signing_key("k") == "k"


@pytest.mark.parametrize("make", ALL_BACKENDS)
def test_clear_then_claim_is_a_rotation(make):
    store = make()
    store.claim_signing_key("old")
    store.clear_signing_key()
    assert store.get_signing_key() is None
    assert store.claim_signing_key("new") == "new"


@pytest.mark.parametrize("make", ALL_BACKENDS)
def test_a_boot_storm_has_exactly_one_winner(make):
    """Eight ingress processes starting together, each with its own candidate. Every one must end
    up holding the SAME key, or the load balancer splits the fleet on the first request."""
    store = make()
    seen: list[str | None] = []
    barrier = threading.Barrier(8)

    def boot():
        candidate = secrets.token_hex(32)
        barrier.wait()
        seen.append(store.claim_signing_key(candidate))

    threads = [threading.Thread(target=boot) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(seen) == 8 and None not in seen
    assert len(set(seen)) == 1, f"the fleet resolved {len(set(seen))} different keys"


def test_the_node_store_holds_no_part_of_this():
    """Structural: a node has no database credentials, so it cannot read the key. If HttpJobStore
    ever grows this protocol, a node could mint its own sessions."""
    from blastbox.host.jobs.http_store import HttpJobStore

    assert not isinstance(HttpJobStore, ClaimKeyRegistry)
    for name in ("claim_signing_key", "get_signing_key", "clear_signing_key"):
        assert not hasattr(HttpJobStore, name)
