"""Pure capture-target + argv logic for ``blastbox-netd`` (the privileged capture helper).

``blastbox-netd`` is a small host-side privileged daemon — the netpolicy analogue of CAPE's
separate ``rooter`` — that sniffs an egress worker's traffic off the docker bridge and writes a
per-job pcap. The hardened dispatcher stays ``cap-drop=ALL`` and never captures itself; it only
LABELS a worker (``blastbox.net.capture=1`` + ``blastbox.job_id``). netd watches docker events,
and for each labeled worker derives *where* to sniff (the host bridge iface for the worker's
egress network) and *what* to filter (the worker's per-job IP), then runs ``tcpdump``.

This module is the pure, unit-testable core of those decisions — no docker calls, no root, no
side effects. The daemon (``netd.py``) feeds it ``docker inspect`` output and a
network-id → bridge-iface map, and consumes the returned :class:`CaptureTarget`.

Why bridge-level (not in-netns) capture: a gVisor (runsc) worker's network lives in the Sentry's
userspace netstack — host ``nsenter`` into its netns sees nothing. The veth/bridge on the host
DOES carry the packets, so a bridge-iface capture filtered to the worker IP is the one topology
that works uniformly across runc / runsc / FC.

Why the pcap is HOST-ONLY (under the job root, never the worker ``/output`` mount): the worker is
untrusted and ``/output`` is writable by it — a captured-traffic file living there could be
tampered with or deleted by the very sample being observed. netd writes to
``<job_root>/<job_id>/capture/`` (host-owned), and the dispatcher seals it into the envelope as a
TRUSTED host artifact after the worker exits.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from collections.abc import Mapping

# Docker label an egress worker carries to opt into capture (set by the dispatcher).
CAPTURE_LABEL = "blastbox.net.capture"
JOB_ID_LABEL = "blastbox.job_id"

# tcpdump snap length — full frames (matches docker's default capture behavior). 256 KiB covers
# jumbo frames; the per-job IP filter keeps the volume to one worker's traffic.
_DEFAULT_SNAPLEN = 262144

# Sub-path (under the per-job root) where netd writes the capture. A sibling of ``output/``, so it
# is never inside the worker's ``/output`` bind-mount.
_CAPTURE_SUBDIR = "capture"
_PCAP_NAME = "dump.pcap"


@dataclass(frozen=True)
class CaptureTarget:
    """Everything netd needs to start one worker's capture."""

    job_id: str
    container: str
    iface: str
    worker_ip: str
    pcap_path: str


def bridge_iface_for_network(network_inspect: Mapping[str, object]) -> str:
    """Map a docker network's ``inspect`` JSON to its host bridge interface name.

    A custom bridge name (``Options['com.docker.network.bridge.name']``) wins; otherwise docker
    names the iface ``br-<first 12 chars of the network Id>``.
    """
    options = network_inspect.get("Options") or {}
    if isinstance(options, Mapping):
        name = options.get("com.docker.network.bridge.name")
        if name:
            return str(name)
    net_id = network_inspect.get("Id")
    if not net_id:
        raise ValueError("network inspect has no Id and no explicit bridge name")
    return f"br-{str(net_id)[:12]}"


def _validate_ip(addr: str) -> str:
    """Return a bare IP (strip an optional ``/prefix``), raising ValueError if it is not a single
    valid IP literal. The address lands in a BPF ``host`` filter, so anything that is not a plain
    IP (a second token, a BPF keyword, whitespace) must be rejected, never shelled through."""
    bare = addr.split("/", 1)[0].strip()
    # ipaddress rejects embedded spaces / BPF keywords / multiple tokens outright.
    ipaddress.ip_address(bare)  # raises ValueError on anything not a single IP literal
    return bare


def tcpdump_argv(
    iface: str, worker_ip: str, pcap_path: str, *, snaplen: int = _DEFAULT_SNAPLEN
) -> list[str]:
    """Build the ``tcpdump`` argv that captures ``iface`` traffic to/from ``worker_ip`` into
    ``pcap_path``. ``worker_ip`` is validated as a single IP literal before it reaches the BPF
    filter (it is the only caller-influenced token in the expression)."""
    ip = _validate_ip(worker_ip)
    # -U line-buffers writes (pcap usable even if netd is killed mid-capture); -n no DNS;
    # the BPF expression is the FINAL positional arg. ip is validated, so it cannot inject.
    return [
        "tcpdump",
        "-i", iface,
        "-n",
        "-U",
        "-s", str(snaplen),
        "-w", pcap_path,
        f"host {ip}",
    ]


def _pcap_path(job_root: str, job_id: str) -> str:
    # Plain string join (not pathlib) so the pure layer makes no FS assumptions; netd creates it.
    root = job_root.rstrip("/")
    return f"{root}/{job_id}/{_CAPTURE_SUBDIR}/{_PCAP_NAME}"


def capture_target_from_inspect(
    inspect: Mapping[str, object],
    *,
    job_root: str,
    network_iface: Mapping[str, str],
) -> CaptureTarget | None:
    """Decide whether (and how) to capture a container, from its ``docker inspect`` payload.

    Returns ``None`` (skip) when the container is not capture-labeled or has no egress network
    (e.g. ``--network=none`` → no ``NetworkSettings.Networks`` entry). Otherwise returns the
    :class:`CaptureTarget` for its first egress network.

    ``network_iface`` maps a docker NetworkID → host bridge iface (netd builds it from
    ``docker network inspect``; the pure layer just looks it up).
    """
    config = inspect.get("Config") or {}
    labels = config.get("Labels") if isinstance(config, Mapping) else None
    labels = labels or {}
    if not isinstance(labels, Mapping):
        return None
    if str(labels.get(CAPTURE_LABEL, "")).strip().lower() not in ("1", "true", "yes", "on"):
        return None
    job_id = labels.get(JOB_ID_LABEL)
    if not job_id:
        return None

    netsettings = inspect.get("NetworkSettings") or {}
    networks = netsettings.get("Networks") if isinstance(netsettings, Mapping) else None
    if not isinstance(networks, Mapping) or not networks:
        return None  # no egress network (none/drop) → nothing to capture

    # First network with a usable IP wins (an egress worker is single-homed by design).
    for _net_name, net in networks.items():
        if not isinstance(net, Mapping):
            continue
        ip_raw = net.get("IPAddress")
        net_id = net.get("NetworkID")
        if not ip_raw or not net_id:
            continue
        iface = network_iface.get(str(net_id))
        if not iface:
            continue
        try:
            worker_ip = _validate_ip(str(ip_raw))
        except ValueError:
            continue
        name = str(inspect.get("Name") or "").lstrip("/") or str(job_id)
        return CaptureTarget(
            job_id=str(job_id),
            container=name,
            iface=iface,
            worker_ip=worker_ip,
            pcap_path=_pcap_path(job_root, str(job_id)),
        )
    return None
