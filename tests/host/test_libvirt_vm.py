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


def _pooled_rt(monkeypatch, pool: str = "192.168.122.200-192.168.122.201", **kw) -> LibvirtVmRuntime:
    # A pooled runtime's __init__ calls _reconcile_reservations() which shells to virsh. Mock the
    # module runner BEFORE construction so a unit test can NEVER delete real DHCP reservations from
    # the dev/CI host's libvirt network (net-dumpxml returns nothing → nothing reconciled).
    import blastbox.host.runtime.libvirt_vm as mod
    monkeypatch.setattr(mod, "_run", lambda *a, **k: type("C", (), {"returncode": 0, "stdout": ""})())
    return _rt(worker_ip_pool=pool, **kw)


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


def test_domain_xml_omits_emulator_by_default():
    # default omits <emulator> so libvirt picks its capabilities default (portable across distros that
    # package qemu outside /usr/bin); an explicit path is emitted when pinned.
    assert "<emulator>" not in _rt()._domain_xml("bbvm-x", "/o.qcow2")
    assert "<emulator>/opt/q</emulator>" in _rt(emulator="/opt/q")._domain_xml("bbvm-x", "/o.qcow2")


def test_domain_xml_pins_mac_ip_via_nwfilter():
    # clean-traffic nwfilter pins MAC+IP at the ebtables layer so a root guest can't spoof both to
    # escape the IP/MAC-keyed host policy. Default emits CTRL_IP_LEARNING=dhcp so no-ip-spoofing
    # learns the worker IP from DHCP (the libvirt "any" default is racy and black-holes some guests).
    xml = _rt()._domain_xml("bbvm-x", "/o.qcow2")
    assert "filter='clean-traffic'" in xml
    assert "<parameter name='CTRL_IP_LEARNING' value='dhcp'/>" in xml
    assert "<filterref filter='clean-traffic'/>" not in xml          # wrapped, not self-closing
    # configurable / disable-able
    assert "filterref" not in _rt(nwfilter="")._domain_xml("bbvm-x", "/o.qcow2")
    assert "filter='custom-nf'" in _rt(nwfilter="custom-nf")._domain_xml("bbvm-x", "/o.qcow2")
    # learning mode tunable; "" omits the parameter (libvirt default), back to a bare filterref
    anyx = _rt(nwfilter_ip_learning="any")._domain_xml("bbvm-x", "/o.qcow2")
    assert "<parameter name='CTRL_IP_LEARNING' value='any'/>" in anyx
    barex = _rt(nwfilter_ip_learning="")._domain_xml("bbvm-x", "/o.qcow2")
    assert "<filterref filter='clean-traffic'/>" in barex and "CTRL_IP_LEARNING" not in barex
    # a typo'd learning mode fails fast with a clear error (not a cryptic libvirt XML error later)
    with pytest.raises(ValueError, match="Invalid nwfilter_ip_learning"):
        _rt(nwfilter_ip_learning="dhpc")._domain_xml("bbvm-x", "/o.qcow2")


def test_domain_xml_virtio_disk_omits_invalid_controller():
    # libvirt has no `<controller type='virtio'>` — emitting one makes virsh define reject the XML.
    xml = _rt(disk_bus="virtio")._domain_xml("bbvm-x", "/o.qcow2")
    assert "controller type='virtio'" not in xml
    assert "dev='vda'" in xml and "bus='virtio'" in xml          # virtio-blk targets vd*
    # a bus that DOES take a controller still emits one
    xml2 = _rt(disk_bus="sata")._domain_xml("bbvm-x", "/o.qcow2")
    assert "controller type='sata'" in xml2 and "dev='sda'" in xml2


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


def test_available_fails_closed_without_qemu_img(monkeypatch):
    # golden present + virsh OK, but qemu-img missing → spawn would fail at overlay creation, so the
    # tier must report unavailable rather than be selected and fail every job.
    import blastbox.host.runtime.libvirt_vm as mod
    rt = _rt()

    def fake_sh(args, **k):
        ok = not (args and args[0] == "qemu-img")        # everything passes EXCEPT qemu-img
        return type("C", (), {"returncode": 0 if ok else 1, "stdout": ""})()

    monkeypatch.setattr(rt, "_sh", fake_sh)
    monkeypatch.setattr(mod, "_run", lambda *a, **k: _OK())   # virsh version → rc0
    assert rt.available() is False


def test_available_probes_qemu_img_when_present(monkeypatch):
    import blastbox.host.runtime.libvirt_vm as mod
    rt = _rt()
    calls = []
    monkeypatch.setattr(rt, "_sh", lambda args, **k: calls.append(args[0]) or _OK())
    monkeypatch.setattr(mod, "_run", lambda *a, **k: _OK())
    assert rt.available() is True
    assert "qemu-img" in calls


def test_ip_pool_parse_and_mac_derivation():
    from blastbox.host.runtime.libvirt_vm import _mac_for_ip, _parse_ip_pool
    assert _parse_ip_pool("192.168.122.200-192.168.122.203") == [
        "192.168.122.200", "192.168.122.201", "192.168.122.202", "192.168.122.203"]
    assert _mac_for_ip("52:54:00:bb", "192.168.122.240") == "52:54:00:bb:7a:f0"   # 122->7a, 240->f0
    assert _mac_for_ip("52:54:00:bb", "10.1.2.3") == "52:54:00:bb:02:03"
    with pytest.raises(ValueError):
        _parse_ip_pool("192.168.122.200")           # no '-'
    with pytest.raises(ValueError):
        _parse_ip_pool("192.168.122.250-192.168.122.200")  # END < START
    with pytest.raises(ValueError, match="one /16"):
        _parse_ip_pool("10.0.0.1-10.1.0.1")         # spans 2 /16s → MACs would collide


def test_learning_none_without_pool_rejected():
    # CTRL_IP_LEARNING=none needs an explicit IP (assign-enforce); without worker_ip_pool there is
    # none, and libvirt rejects 'none' on a referenced no-ip-spoofing — fail fast with a clear error.
    with pytest.raises(ValueError, match="needs an assigned IP"):
        _rt(nwfilter_ip_learning="none")._domain_xml("bbvm-x", "/o.qcow2")


def test_ip_allocator_hands_out_distinct_and_frees(monkeypatch):
    rt = _pooled_rt(monkeypatch, "192.168.122.200-192.168.122.201")
    ip1, mac1 = rt._alloc_ip_mac()
    ip2, mac2 = rt._alloc_ip_mac()
    assert {ip1, ip2} == {"192.168.122.200", "192.168.122.201"} and mac1 != mac2
    with pytest.raises(RuntimeError, match="exhausted"):
        rt._alloc_ip_mac()                          # pool of 2 is empty
    rt._free_ip(ip1)
    assert rt._alloc_ip_mac()[0] == ip1             # freed IP is handed back out


def test_domain_xml_assign_enforce_pins_explicit_mac_and_ip(monkeypatch):
    # assign-enforce: explicit <mac> + no-ip-spoofing pinned to OUR ip (CTRL_IP_LEARNING=none), so a
    # root guest can neither spoof a different IP nor poison DHCP learning (there is none).
    rt = _pooled_rt(monkeypatch, "192.168.122.200-192.168.122.250")
    x = rt._domain_xml("bbvm-x", "/o.qcow2", mac="52:54:00:bb:7a:f0", assigned_ip="192.168.122.240")
    assert "<mac address='52:54:00:bb:7a:f0'/>" in x
    assert "<parameter name='CTRL_IP_LEARNING' value='none'/>" in x
    assert "<parameter name='IP' value='192.168.122.240'/>" in x
    assert "value='dhcp'" not in x                  # NOT learning mode


def _sh_ok_free_name(args, **k):
    # `test -e <overlay>` -> rc1 (name free); everything else (qemu-img/chmod/rm) -> rc0
    if args[:1] == ["test"]:
        return type("C", (), {"returncode": 1, "stdout": ""})()
    return _OK()


def test_spawn_reserves_and_assigns_then_reap_unreserves(monkeypatch):
    # spawn() in assign-enforce mode adds a DHCP reservation + assigns slot.ip/mac upfront; reap()
    # removes the reservation + returns the IP to the pool.
    rt = _pooled_rt(monkeypatch, "192.168.122.200-192.168.122.201")
    calls: list[list[str]] = []
    monkeypatch.setattr(rt, "_virsh", lambda *a, **k: calls.append(list(a)) or _OK())
    monkeypatch.setattr(rt, "_sh", _sh_ok_free_name)
    monkeypatch.setattr(rt, "_destroy_domain", lambda *a, **k: True)
    slot = rt.spawn()
    assert slot.ip in ("192.168.122.200", "192.168.122.201") and slot.mac
    assert any(a[:3] == ["net-update", "default", "add"] and slot.ip in " ".join(a) for a in calls)
    held = slot.ip
    calls.clear()
    rt.reap(slot)
    assert any(a[:3] == ["net-update", "default", "delete"] and held in " ".join(a) for a in calls)
    assert held in rt._ip_free                       # IP returned to the pool after reap


def test_spawn_reserve_failure_does_not_delete_others_reservation(monkeypatch):
    # if our _reserve() fails (IP already reserved by another live runtime), the except->reap path
    # must NOT delete that other reservation — only free our own allocation back to the pool.
    rt = _pooled_rt(monkeypatch, "192.168.122.200-192.168.122.201")
    calls: list[list[str]] = []

    def fake_virsh(*a, **k):
        calls.append(list(a))
        if a[:3] == ("net-update", "default", "add"):
            return type("C", (), {"returncode": 1, "stdout": "", "stderr": "already in use"})()
        return _OK()

    monkeypatch.setattr(rt, "_virsh", fake_virsh)
    monkeypatch.setattr(rt, "_sh", _sh_ok_free_name)
    monkeypatch.setattr(rt, "_destroy_domain", lambda *a, **k: True)
    with pytest.raises(RuntimeError, match="reservation add failed"):
        rt.spawn()
    # the failed spawn's reap must NOT have issued a net-update delete (it never owned the reservation)
    assert not any(a[:3] == ["net-update", "default", "delete"] for a in calls)
    # but our allocated IP is returned to the pool (no leak)
    assert len(rt._ip_free) == 2


def test_reconcile_keeps_running_workers_ip_and_clears_stale(monkeypatch):
    # startup reconcile: an IP whose domain is STILL RUNNING (crashed manager) is marked in-use; a
    # reservation with no live domain is deleted as stale.
    import blastbox.host.runtime.libvirt_vm as mod
    deletes: list[str] = []

    def fake_run(args, **k):
        s = " ".join(args)
        if "list --name" in s:
            return type("C", (), {"returncode": 0, "stdout": "bbvm-live\n"})()
        if "domiflist bbvm-live" in s:
            return type("C", (), {"returncode": 0,
                "stdout": " vnet9  network  default  e1000  52:54:00:bb:7a:c8\n"})()  # .200 live
        if "net-dumpxml" in s:
            return type("C", (), {"returncode": 0, "stdout":
                "<host mac='52:54:00:bb:7a:c8' ip='192.168.122.200'/>"     # running -> keep
                "<host mac='52:54:00:bb:7a:c9' ip='192.168.122.201'/>"}    # stale   -> delete
                )()
        if "net-update" in s and "delete" in s:
            deletes.append(s)
        return type("C", (), {"returncode": 0, "stdout": ""})()

    monkeypatch.setattr(mod, "_run", fake_run)
    rt = mod.LibvirtVmRuntime(mod.LibvirtVmConfig(
        golden_base="/g.qcow2", worker_ip_pool="192.168.122.200-192.168.122.201"))
    assert "192.168.122.200" not in rt._ip_free        # live worker's IP not handed out
    assert "192.168.122.201" in rt._ip_free            # stale IP freed for reuse
    assert any("192.168.122.201" in d for d in deletes) and not any("192.168.122.200" in d for d in deletes)


def test_dhcp_learning_mode_no_reservation(monkeypatch):
    # without a pool, spawn() does NOT touch DHCP reservations (DHCP-learning mode); MAC is read back.
    rt = _rt()  # no worker_ip_pool
    calls: list[list[str]] = []
    monkeypatch.setattr(rt, "_virsh", lambda *a, **k: calls.append(list(a)) or _OK())
    monkeypatch.setattr(rt, "_sh", _sh_ok_free_name)
    monkeypatch.setattr(rt, "_destroy_domain", lambda *a, **k: True)
    monkeypatch.setattr(rt, "_domain_mac", lambda name: "52:54:00:aa:bb:cc")
    slot = rt.spawn()
    assert slot.ip is None and slot.mac == "52:54:00:aa:bb:cc"   # learned later via DHCP/neigh
    assert not any("net-update" in a for a in calls)


def test_available_fails_closed_when_helper_binary_missing(monkeypatch):
    # sudo/virsh not installed → subprocess.run raises FileNotFoundError; available() must return
    # False (fail closed), not crash runtime selection with a raw OSError.
    import blastbox.host.runtime.libvirt_vm as mod

    def no_binary(args, **k):
        raise FileNotFoundError(2, "No such file or directory", args[0] if args else "?")

    monkeypatch.setattr(mod.subprocess, "run", no_binary)
    assert mod.LibvirtVmRuntime(
        mod.LibvirtVmConfig(golden_base="/g.qcow2", sudo=True)).available() is False


def test_alloc_overlay_name_uses_64_bits_and_unique_path(monkeypatch):
    # 16 hex (64 bits), not 8 — a 32-bit space birthday-collides in a long-lived pool, and a collision
    # is destructive (spawn destroys+overwrites the sibling's domain/overlay).
    rt = _rt()
    monkeypatch.setattr(rt, "_sh", lambda args, **k: type("C", (), {"returncode": 1})())  # nothing exists
    sid, name, overlay = rt._alloc_overlay_name()
    assert len(sid) == 16 and name == f"bbvm-{sid}"
    assert overlay.endswith(f"{name}.qcow2")


def test_alloc_overlay_name_rerolls_past_existing_overlay(monkeypatch):
    # if the first candidate overlay already exists (a live sibling), re-roll instead of returning a
    # name spawn() would destroy+overwrite.
    rt = _rt()
    seen: list[str] = []

    def fake_sh(args, **k):
        overlay = args[-1]
        seen.append(overlay)
        return type("C", (), {"returncode": 0 if len(seen) == 1 else 1})()  # 1st exists, 2nd free

    monkeypatch.setattr(rt, "_sh", fake_sh)
    sid, name, overlay = rt._alloc_overlay_name()
    assert len(seen) == 2 and overlay == seen[1] and overlay != seen[0]  # re-rolled past the collision


def test_alloc_overlay_name_raises_when_no_free_name(monkeypatch):
    rt = _rt()
    monkeypatch.setattr(rt, "_sh", lambda args, **k: type("C", (), {"returncode": 0})())  # all "exist"
    with pytest.raises(RuntimeError, match="unique VM overlay name"):
        rt._alloc_overlay_name()


def test_destroy_domain_command_not_found_is_a_failed_destroy(monkeypatch):
    # `sudo virsh` with virsh missing from root's PATH → "virsh: command not found": NOT a benign
    # absent-domain case (no destroy happened), so reap() must treat it as failed (→ quarantine).
    rt = _rt()
    monkeypatch.setattr(rt, "_virsh", lambda *a, **k: type(
        "C", (), {"returncode": 127, "stdout": "", "stderr": "sudo: virsh: command not found"})())
    assert rt._destroy_domain("bbvm-x") is False


def test_destroy_domain_absent_domain_is_benign(monkeypatch):
    rt = _rt()
    monkeypatch.setattr(rt, "_virsh", lambda *a, **k: type(
        "C", (), {"returncode": 1, "stdout": "", "stderr": "error: failed to get domain 'bbvm-x'"})())
    assert rt._destroy_domain("bbvm-x") is True       # domain already gone → benign


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


def test_finalize_snapshot_is_atomic(monkeypatch):
    # the clean snapshot must be created with --atomic (all-or-nothing) so a failed create can't leave
    # partial metadata that breaks the retry on a duplicate name.
    rt = _rt()
    calls = []
    monkeypatch.setattr(rt, "_virsh", lambda *a, **k: calls.append(a) or _OK())
    monkeypatch.setattr(rt, "_port_up", lambda *a, **k: True)
    monkeypatch.setattr(rt, "_sync_time", lambda *a, **k: True)
    slot = VmSlot(slot_id="z", domain="bbvm-z", overlay="/o.qcow2", agent_port=8765,
                  ip="192.168.122.9", mac="52:54:00:aa:bb:cc")
    rt.is_ready(slot)
    snap = [c for c in calls if c and c[0] == "snapshot-create-as"]
    assert snap and "--atomic" in snap[0]


def test_on_ready_runs_even_when_domtime_succeeds(monkeypatch):
    # on_ready is a per-ready-transition hook (guest readiness repair beyond the clock), so it runs at
    # finalize AND each revert EVEN when domtime succeeded — not only as the clock fallback.
    calls: list[str] = []
    rt = _rt(on_ready=lambda slot: calls.append("ready"))
    _stub_virsh(rt, monkeypatch, domtime_ok=True)
    slot = VmSlot(slot_id="z", domain="bbvm-z", overlay="/o.qcow2", agent_port=8765,
                  ip="192.168.122.9", mac="52:54:00:aa:bb:cc")
    assert rt.is_ready(slot) is True
    rt.recycle(slot, ready_timeout_s=5)
    assert calls == ["ready", "ready"]         # finalize + revert, despite domtime winning


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
    assert _RecEgress.events == ["egress-remove"]   # policy unhooked after the guest is destroyed
    assert order.index("destroy") < order.index("rm-overlay")


def test_reap_keeps_egress_and_overlay_when_destroy_fails(monkeypatch):
    rt, order = _reap_rt(monkeypatch, destroyed=False)  # guest may still be running
    slot = VmSlot(slot_id="r", domain="bbvm-r", overlay="/o.qcow2", agent_port=8765,
                  ip="192.168.122.5", mac="52:54:00:aa:bb:cc")
    with pytest.raises(RuntimeError, match="quarantined"):   # raise so the pool quarantines the slot
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
