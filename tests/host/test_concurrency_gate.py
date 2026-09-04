"""DynamicConcurrencyGate — the sizer's live cap on concurrent job processing."""

from __future__ import annotations

import threading
import time

from blastbox.host.concurrency_gate import DynamicConcurrencyGate


def test_gate_bounds_concurrency():
    g = DynamicConcurrencyGate(2)
    assert g.acquire(0.1) and g.acquire(0.1)  # two permits available
    assert not g.acquire(0.05)  # third blocks → times out
    assert g.in_flight == 2
    g.release()
    assert g.acquire(0.1)  # a permit freed → available again


def test_gate_shrink_does_not_interrupt_in_flight():
    g = DynamicConcurrencyGate(3)
    assert g.acquire(0.1) and g.acquire(0.1) and g.acquire(0.1)  # 3 in flight
    g.set_limit(1)  # shrink below in-flight (not interrupted)
    assert g.in_flight == 3
    assert not g.acquire(0.05)  # new acquires blocked until it drains
    g.release()
    g.release()  # 1 left — still at the new limit
    assert not g.acquire(0.05)
    g.release()  # 0 in flight
    assert g.acquire(0.1)  # now under the limit → available


def test_gate_grow_wakes_a_waiter():
    g = DynamicConcurrencyGate(1)
    assert g.acquire(0.1)  # limit reached
    got: list[bool] = []

    def waiter() -> None:
        got.append(g.acquire(2.0))

    t = threading.Thread(target=waiter)
    t.start()
    time.sleep(0.1)  # ensure it's blocked
    g.set_limit(2)  # grow → the waiter should acquire
    t.join(2.0)
    assert got == [True]


def test_gate_acquire_times_out_without_blocking_forever():
    g = DynamicConcurrencyGate(1)
    assert g.acquire(0.1)
    t0 = time.monotonic()
    assert not g.acquire(0.15)  # returns False, doesn't hang
    assert 0.1 <= time.monotonic() - t0 < 1.0
