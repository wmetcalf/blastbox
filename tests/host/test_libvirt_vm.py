"""Unit tests for the libvirt VM warm-worker runtime (pure parts; no libvirt needed).

The VM lifecycle (spawn/recycle/reap) needs a real libvirt host + golden image and is
exercised by an integration test on the host; here we cover config, domain-XML generation,
the slot/endpoint record, fail-closed availability, and SlotRuntime conformance.
"""
from __future__ import annotations

import pytest

from blastbox.host.pool import SlotRuntime, SlotState
from blastbox.host.runtime.libvirt_vm import LibvirtVmConfig, LibvirtVmRuntime, VmSlot


def _rt(**kw) -> LibvirtVmRuntime:
    return LibvirtVmRuntime(LibvirtVmConfig(golden_base="/dev/shm/golden.qcow2", **kw))


def test_slotruntime_protocol_conformance():
    assert isinstance(_rt(), SlotRuntime)
    assert hasattr(_rt(), "recycle")  # the snapshot-restore extension


def test_config_defaults():
    cfg = LibvirtVmConfig(golden_base="/g.qcow2")
    assert cfg.agent_port == 8765
    assert cfg.overlay_dir == "/dev/shm"
    assert cfg.snapshot_name == "clean"
    assert cfg.sudo is True


@pytest.mark.parametrize(
    "kw,needle",
    [
        ({}, "<name>bbvm-x</name>"),
        ({"mem_mb": 8192}, "MiB'>8192<"),
        ({"vcpus": 4}, "placement='static'>4<"),
        ({"network": "cape-100"}, "network='cape-100'"),
        ({"disk_bus": "virtio"}, "bus='virtio'"),
        ({"nic_model": "virtio"}, "<model type='virtio'/>"),
        ({"machine": "q35"}, "machine='q35'"),
    ],
)
def test_domain_xml_reflects_config(kw, needle):
    xml = _rt(**kw)._domain_xml("bbvm-x", "/dev/shm/bbvm-x.qcow2")
    assert needle in xml
    assert "/dev/shm/bbvm-x.qcow2" in xml
    assert xml.startswith("<domain type='kvm'>") and xml.endswith("</domain>")


def test_vmslot_endpoint():
    s = VmSlot(slot_id="a", domain="bbvm-a", overlay="/o.qcow2", agent_port=8765, ip="192.168.122.5")
    assert s.endpoint == ("192.168.122.5", 8765)
    # no IP yet -> no endpoint
    assert VmSlot(slot_id="b", domain="d", overlay="/o", agent_port=8765).endpoint is None


def test_available_fail_closed_without_golden():
    # missing golden short-circuits to False before any virsh call
    assert LibvirtVmRuntime(LibvirtVmConfig(golden_base="/no/such/golden.qcow2")).available() is False


def test_ip_for_mac_none_when_no_mac():
    assert _rt()._ip_for_mac(None) is None


class _OK:
    returncode = 0
    stdout = "running"


def _stub_virsh(rt, monkeypatch, *, domtime_ok=False):
    """Make the host-touching calls inert so is_ready/recycle run their hook logic in-process.
    ``domtime_ok`` controls whether the libvirt-native clock sync 'succeeds' (gating the on_ready
    fallback)."""
    monkeypatch.setattr(rt, "_virsh", lambda *a, **k: _OK())
    monkeypatch.setattr(rt, "_port_up", lambda *a, **k: True)
    monkeypatch.setattr(rt, "_sync_time", lambda *a, **k: domtime_ok)


def test_on_ready_fallback_fires_at_finalize_and_recycle_when_no_qemuga(monkeypatch):
    # When the libvirt-native domtime sync is unavailable (no qemu-ga), the on_ready clock-sync
    # FALLBACK must run on BOTH ready transitions: finalize and every recycle.
    calls: list[str] = []
    smoke_at: list[str] = []
    rt = _rt(on_ready=lambda slot: calls.append("ready"),
             health_check=lambda slot: (smoke_at.append("smoke"), True)[1])
    _stub_virsh(rt, monkeypatch, domtime_ok=False)
    slot = VmSlot(slot_id="z", domain="bbvm-z", overlay="/o.qcow2", agent_port=8765,
                  ip="192.168.122.9", mac="52:54:00:aa:bb:cc")

    assert rt.is_ready(slot) is True          # finalize
    assert calls == ["ready"]
    assert smoke_at == ["smoke"]              # fallback ran before the smoke

    rt.recycle(slot, ready_timeout_s=5)        # revert
    assert calls == ["ready", "ready"]         # fired again post-revert
    assert slot.recycles == 1


class _RevertFail:
    returncode = 1
    stdout = ""
    stderr = "snapshot 'clean' not found"


def test_recycle_raises_on_revert_failure(monkeypatch):
    # A failed snapshot-revert leaves the contaminated VM (its port may still answer); recycle must
    # raise so WarmPool.release() reaps instead of returning a dirty slot to IDLE.
    rt = _rt()
    monkeypatch.setattr(rt, "_virsh", lambda *a, **k: _RevertFail())
    monkeypatch.setattr(rt, "_port_up", lambda *a, **k: True)
    slot = VmSlot(slot_id="z", domain="bbvm-z", overlay="/o", agent_port=8765, ip="192.168.122.9")
    with pytest.raises(RuntimeError):
        rt.recycle(slot, ready_timeout_s=2)
    assert slot.state == SlotState.DRAINING


def test_recycle_does_not_reset_cumulative_jobs(monkeypatch):
    # WarmPool owns slot.jobs (it drives max_jobs_per_slot); recycle must NOT zero it.
    rt = _rt()
    _stub_virsh(rt, monkeypatch, domtime_ok=True)
    slot = VmSlot(slot_id="z", domain="bbvm-z", overlay="/o", agent_port=8765,
                  ip="192.168.122.9", jobs=7)
    rt.recycle(slot, ready_timeout_s=2)
    assert slot.jobs == 7 and slot.recycles == 1


def test_on_ready_skipped_when_domtime_succeeds(monkeypatch):
    # When domtime --sync succeeds (qemu-ga baked in), the on_ready fallback must NOT fire — the
    # libvirt-native UTC sync already set the clock; double-setting risks TZ corruption.
    calls: list[str] = []
    rt = _rt(on_ready=lambda slot: calls.append("ready"))
    _stub_virsh(rt, monkeypatch, domtime_ok=True)
    slot = VmSlot(slot_id="z", domain="bbvm-z", overlay="/o.qcow2", agent_port=8765,
                  ip="192.168.122.9", mac="52:54:00:aa:bb:cc")
    assert rt.is_ready(slot) is True
    rt.recycle(slot, ready_timeout_s=5)
    assert calls == []                         # domtime won; fallback never ran


def test_on_ready_failure_is_non_fatal(monkeypatch):
    # a raising fallback hook must not strand the worker — finalize still completes.
    def boom(slot):
        raise RuntimeError("clock host unreachable")

    rt = _rt(on_ready=boom)
    _stub_virsh(rt, monkeypatch, domtime_ok=False)
    slot = VmSlot(slot_id="z", domain="bbvm-z", overlay="/o.qcow2", agent_port=8765,
                  ip="192.168.122.9", mac="52:54:00:aa:bb:cc")
    assert rt.is_ready(slot) is True and slot.finalized is True
