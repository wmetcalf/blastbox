"""TDD tests for blastbox.host.capture — pure capture-target + argv logic.

The capture facility (``blastbox-netd``) is a privileged host helper that sniffs an egress
worker's traffic off the docker bridge, filtered to that worker's per-job IP, into a host-only
pcap. This module holds the *pure* decisions (which iface, which filter, where to write, whether
to capture at all) so they are unit-testable without docker or root.
"""
from __future__ import annotations

import pytest

from blastbox.host.capture import (
    CaptureTarget,
    bridge_iface_for_network,
    capture_target_from_inspect,
    tcpdump_argv,
)


# ---------------------------------------------------------------------------
# bridge_iface_for_network — docker network → host bridge iface
# ---------------------------------------------------------------------------

def test_bridge_iface_defaults_to_br_id_prefix():
    # No custom bridge name → docker names the host iface br-<first 12 of network id>.
    net = {"Id": "ed7fd8287f2a1234deadbeef", "Options": {}}
    assert bridge_iface_for_network(net) == "br-ed7fd8287f2a"


def test_bridge_iface_honors_custom_name():
    net = {
        "Id": "0123456789abcdef",
        "Options": {"com.docker.network.bridge.name": "bb-fakenet"},
    }
    assert bridge_iface_for_network(net) == "bb-fakenet"


def test_bridge_iface_missing_id_raises():
    with pytest.raises(ValueError):
        bridge_iface_for_network({"Options": {}})


# ---------------------------------------------------------------------------
# tcpdump_argv — capture command
# ---------------------------------------------------------------------------

def test_tcpdump_argv_filters_to_worker_ip_and_writes_pcap():
    argv = tcpdump_argv("br-abc123", "172.20.0.5", "/jobs/J/capture/dump.pcap")
    assert argv[0] == "tcpdump"
    # iface, write target, and a host filter on the worker IP must all be present.
    assert "br-abc123" in argv
    assert "/jobs/J/capture/dump.pcap" in argv
    assert any("172.20.0.5" in tok for tok in argv)
    # -U/line-buffered or -w write target follows -w as a value (never a bare flag).
    assert argv[argv.index("-w") + 1] == "/jobs/J/capture/dump.pcap"


def test_tcpdump_argv_ip_is_in_a_bpf_host_filter_not_a_flag():
    argv = tcpdump_argv("br-x", "10.1.2.3", "/p.pcap")
    joined = " ".join(argv)
    assert "host 10.1.2.3" in joined


def test_tcpdump_argv_rejects_non_ip_worker_addr():
    # The worker IP lands in a BPF expression; a non-IP (or injection attempt) must be rejected
    # rather than shelled into the filter.
    with pytest.raises(ValueError):
        tcpdump_argv("br-x", "10.0.0.1 or not host evil", "/p.pcap")
    with pytest.raises(ValueError):
        tcpdump_argv("br-x", "not-an-ip", "/p.pcap")


# ---------------------------------------------------------------------------
# capture_target_from_inspect — decide whether/what to capture for a container
# ---------------------------------------------------------------------------

def _inspect(*, labels, networks, job_root="/jobs"):
    return {
        "Name": "/blastbox-worker-abc123-1",
        "Config": {"Labels": labels},
        "NetworkSettings": {"Networks": networks},
    }


def test_no_capture_when_label_absent():
    insp = _inspect(
        labels={"blastbox.role": "worker", "blastbox.job_id": "J1"},
        networks={"bb-net0": {"IPAddress": "172.20.0.2", "NetworkID": "netid"}},
    )
    assert capture_target_from_inspect(insp, job_root="/jobs", network_iface={}) is None


def test_no_capture_for_network_none():
    # A sealed (none) worker has no egress network → nothing to capture even if labeled.
    insp = _inspect(
        labels={"blastbox.net.capture": "1", "blastbox.job_id": "J1"},
        networks={},
    )
    assert capture_target_from_inspect(insp, job_root="/jobs", network_iface={}) is None


def test_capture_target_built_for_labeled_egress_worker():
    insp = _inspect(
        labels={"blastbox.net.capture": "1", "blastbox.job_id": "J1"},
        networks={"bb-net0": {"IPAddress": "172.20.0.7", "NetworkID": "ed7fd8287f2a00"}},
    )
    tgt = capture_target_from_inspect(
        insp, job_root="/srv/jobs", network_iface={"ed7fd8287f2a00": "br-ed7fd8287f2a"}
    )
    assert isinstance(tgt, CaptureTarget)
    assert tgt.job_id == "J1"
    assert tgt.iface == "br-ed7fd8287f2a"
    assert tgt.worker_ip == "172.20.0.7"
    # Host-only pcap path under the per-job root, NOT inside the worker /output mount.
    assert tgt.pcap_path == "/srv/jobs/J1/capture/dump.pcap"
    assert "/output" not in tgt.pcap_path


def test_capture_target_strips_cidr_suffix_from_ip():
    # docker sometimes reports IPAddress bare but IPAMConfig with /16; ensure a CIDR is trimmed.
    insp = _inspect(
        labels={"blastbox.net.capture": "1", "blastbox.job_id": "J2"},
        networks={"bb-fakenet": {"IPAddress": "172.28.100.9/16", "NetworkID": "abc"}},
    )
    tgt = capture_target_from_inspect(insp, job_root="/jobs", network_iface={"abc": "br-abc"})
    assert tgt is not None
    assert tgt.worker_ip == "172.28.100.9"
