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
    # missing golden short-circuits to False before any virsh call. sudo=False so the privileged
    # existence probe runs `test -e` WITHOUT sudo — a real `sudo` call would block on a CI runner
    # that prompts for a password (the production default sudo=True needs passwordless sudo, which a
    # libvirt host already has). See test_available_uses_privileged_existence_probe for the sudo path.
    assert LibvirtVmRuntime(
        LibvirtVmConfig(golden_base="/no/such/golden.qcow2", sudo=False)).available() is False


def test_available_uses_privileged_existence_probe(monkeypatch):
    # a root-only golden dir: an unprivileged Path.exists() would falsely report unavailable. available()
    # must probe with the configured privilege model (sudo test -e), matching spawn's qemu-img/virsh.
    import blastbox.host.runtime.libvirt_vm as mod
    rt = _rt()  # golden_base=/dev/shm/golden.qcow2 — not present on the unprivileged fs here
    calls = []
    monkeypatch.setattr(rt, "_sh", lambda args, **k: calls.append(args) or _OK())   # sudo test -e → rc0
    monkeypatch.setattr(mod, "_run", lambda *a, **k: _OK())                          # virsh version → rc0
    assert rt.available() is True
    assert ["test", "-e", "/dev/shm/golden.qcow2"] in calls


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


def test_trust_anchors_installed_at_finalize_before_snapshot(monkeypatch):
    # When trust_anchors + SSH creds are set, finalize installs them into the guest BEFORE the
    # snapshot-create-as, so the warm baseline captures them.
    order: list[str] = []
    rt = LibvirtVmRuntime(LibvirtVmConfig(
        golden_base="/dev/shm/g.qcow2",
        trust_anchors=["/host/fakenet_ca.crt"],
        guest_ssh_user="Administrator", guest_ssh_key="/k"))
    _stub_virsh(rt, monkeypatch, domtime_ok=True)

    def _snap(*a, **k):
        if "snapshot-create-as" in a:
            order.append("snapshot")
        return _OK()
    monkeypatch.setattr(rt, "_virsh", _snap)
    import blastbox.host.runtime.libvirt_vm as mod
    monkeypatch.setattr(mod.guest_ca, "install_trust_anchors",
                        lambda *a, **k: (order.append("anchors"), True)[1])
    slot = VmSlot(slot_id="z", domain="bbvm-z", overlay="/o", agent_port=8765,
                  ip="192.168.122.9", mac="52:54:00:aa:bb:cc")
    assert rt.is_ready(slot) is True
    assert order == ["anchors", "snapshot"]


def test_trust_anchors_skipped_without_creds(monkeypatch):
    # No anchors / no SSH creds -> install is never attempted (no behavior change for normal workers).
    called = []
    rt = _rt(trust_anchors=["/c.crt"])  # creds missing -> skip
    _stub_virsh(rt, monkeypatch, domtime_ok=True)
    import blastbox.host.runtime.libvirt_vm as mod
    monkeypatch.setattr(mod.guest_ca, "install_trust_anchors",
                        lambda *a, **k: called.append(1) or True)
    slot = VmSlot(slot_id="z", domain="bbvm-z", overlay="/o", agent_port=8765, ip="1.2.3.4")
    rt.is_ready(slot)
    assert called == []


def test_on_ready_failure_is_non_fatal(monkeypatch):
    # a raising fallback hook must not strand the worker — finalize still completes.
    def boom(slot):
        raise RuntimeError("clock host unreachable")

    rt = _rt(on_ready=boom)
    _stub_virsh(rt, monkeypatch, domtime_ok=False)
    slot = VmSlot(slot_id="z", domain="bbvm-z", overlay="/o.qcow2", agent_port=8765,
                  ip="192.168.122.9", mac="52:54:00:aa:bb:cc")
    assert rt.is_ready(slot) is True and slot.finalized is True


# --- reap ordering + fail-closed finalize (containment) ----------------------------
from blastbox.host.runtime import libvirt_vm as _mod  # noqa: E402
from blastbox.host.runtime.libvirt_egress import VmEgressPolicy  # noqa: E402


class _RecEgress:
    events: list[str] = []

    def __init__(self, **kw):
        pass

    def remove(self, *a, **k):
        _RecEgress.events.append("egress-remove")

    def preboot_unblock(self, *a, **k):
        _RecEgress.events.append("preboot-unblock")


def _reap_rt(monkeypatch, *, destroyed: bool):
    rt = _rt(egress_policy=VmEgressPolicy(exit_driver="direct"))
    _RecEgress.events = []
    order: list[str] = []
    monkeypatch.setattr(rt, "_destroy_domain", lambda name: order.append("destroy") or destroyed)
    monkeypatch.setattr(rt, "_sh", lambda *a, **k: order.append("rm-overlay") or _OK())
    monkeypatch.setattr(_mod, "LibvirtEgress", _RecEgress)
    return rt, order


def test_reap_destroys_guest_before_removing_egress(monkeypatch):
    rt, order = _reap_rt(monkeypatch, destroyed=True)
    slot = VmSlot(slot_id="r", domain="bbvm-r", overlay="/o.qcow2", agent_port=8765,
                  ip="192.168.122.5", mac="52:54:00:aa:bb:cc")
    rt.reap(slot)
    # destroy the guest FIRST (while egress is up), THEN unhook egress, THEN free the overlay.
    assert order == ["destroy", "rm-overlay"]
    assert _RecEgress.events == ["egress-remove", "preboot-unblock"]  # policy unhooked + boot-block lifted
    assert order.index("destroy") < order.index("rm-overlay")


def test_reap_keeps_egress_and_overlay_when_destroy_fails(monkeypatch):
    rt, order = _reap_rt(monkeypatch, destroyed=False)  # guest may still be running
    slot = VmSlot(slot_id="r", domain="bbvm-r", overlay="/o.qcow2", agent_port=8765,
                  ip="192.168.122.5", mac="52:54:00:aa:bb:cc")
    rt.reap(slot)
    assert order == ["destroy"]          # bailed after the failed destroy
    assert _RecEgress.events == []        # egress LEFT in place — possibly-live guest stays contained
    assert "rm-overlay" not in order      # overlay not freed under a live guest


def test_finalize_fails_closed_without_mac(monkeypatch):
    rt = _rt(egress_policy=VmEgressPolicy(exit_driver="direct"))
    _stub_virsh(rt, monkeypatch, domtime_ok=True)
    reaped: list[str] = []
    monkeypatch.setattr(rt, "reap", lambda slot: reaped.append(slot.domain))
    slot = VmSlot(slot_id="m", domain="bbvm-m", overlay="/o.qcow2", agent_port=8765,
                  ip="192.168.122.5", mac=None)  # domiflist missed the MAC
    assert rt.is_ready(slot) is False    # an under-firewalled finalize is rejected...
    assert reaped == ["bbvm-m"]          # ...and the VM is reaped (fail-closed)
