"""Declarative VM-worker definitions — "docker-compose, but for libvirt/kvm/qemu".

One ``VmWorkerSpec`` ties together everything needed to stand up a tier of warm VM workers:

    image   — a golden qcow2 (prebuilt, or a build recipe to bake one)
    domain  — mem / vcpus / network / disk-bus / nic (the libvirt domain shape)
    agent   — the in-guest agent port (the warm-ready signal + job transport)
    egress  — the rooter-model exit policy (filter + routing) for the worker
    pool    — warm_size / jobs_per_recycle / max_jobs_per_slot (the reuse policy)

From a spec you get a ready-to-run :class:`~blastbox.host.pool.WarmPool` over the
:class:`~blastbox.host.runtime.libvirt_vm.LibvirtVmRuntime`:

    spec = VmWorkerSpec.from_dict(yaml.safe_load(open("vmcompose.yml"))["workers"]["authenticode"])
    pool = spec.build_pool(jobs_per_recycle=25)   # engine's risk×cost call wins if provided
    pool.start()
    slot = pool.claim(timeout_s=30)               # a warm VmSlot; talk to slot.endpoint
    ...
    pool.release(slot)                            # reuse-with-recycle per the pool policy

``build_image()`` bakes a golden when one isn't present (the "build" half) — a thin wrapper over
``qemu-img`` + SSH provisioners (overlay-on-base), or a Packer template for a from-ISO install.
The image build is inherently OS-specific; this module owns the *orchestration*, the per-OS
provisioner scripts stay with the engine (e.g. the win-validator golden).
"""
from __future__ import annotations

import logging
import subprocess
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from blastbox.errors import is_answered_http_rejection, is_transport_error
from blastbox.host.netwire import parse_egress_ports
from blastbox.host.pool import Slot, WarmPool, _accepts_kwarg, release_kwargs
from blastbox.host.runtime.libvirt_egress import ExitRouting, VmEgressPolicy
from blastbox.host.runtime.libvirt_vm import LibvirtVmConfig, LibvirtVmRuntime

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Image (the "build" half)
# ---------------------------------------------------------------------------
@dataclass
class VmImageSpec:
    """A golden qcow2 — prebuilt, or a recipe to bake one."""

    golden: str
    """Path to the (read-only) golden qcow2 the workers overlay. If it doesn't exist and a
    recipe is given, ``build_image()`` bakes it here."""

    # --- optional build recipe ---
    base_qcow2: str | None = None     # base image to provision on top of (overlay-then-flatten)
    base_iso: str | None = None       # OR an install ISO (Packer from-scratch build)
    provisioners: list[str] = field(default_factory=list)  # shell/ssh provisioner commands
    builder: str = "qemu"             # "qemu" (overlay+ssh) | "packer" (from-ISO template)
    packer_template: str | None = None

    def exists(self) -> bool:
        return Path(self.golden).exists()


# ---------------------------------------------------------------------------
# Worker (the "service")
# ---------------------------------------------------------------------------
@dataclass
class VmWorkerSpec:
    """A declarative VM-worker tier — the libvirt analogue of a compose service."""

    name: str
    image: VmImageSpec

    # domain shape
    mem_mb: int = 4096
    vcpus: int = 2
    network: str = "default"
    disk_bus: str = "sata"
    nic_model: str = "e1000"
    nwfilter: str = "clean-traffic"
    nwfilter_ip_learning: str = "dhcp"  # CTRL_IP_LEARNING (DHCP-learning mode; unused when worker_ip_pool set)
    worker_ip_pool: str = ""            # "START-END" → assign+enforce: reserve+pin a fixed IP per worker
    mac_prefix: str = "52:54:00:bb"     # OUI for assign-enforce MACs (last 2 octets derived from the IP)
    dhcp_server: str = ""               # clean-traffic DHCPSERVER (trusted dnsmasq); "" → subnet+".1"
    overlay_dir: str = "/dev/shm"
    subnet_prefix: str = "192.168.122."

    # guest agent
    agent_port: int = 8765

    # egress (optional; None = whatever the libvirt network allows)
    egress: VmEgressPolicy | None = None
    routing: ExitRouting | None = None
    gateway: str | None = None

    # guest TLS trust anchors (for HTTPS/TLS interception workers — NOT trust-judging ones)
    trust_anchors: list[str] = field(default_factory=list)
    guest_os: str = "windows"
    guest_ssh_user: str | None = None
    guest_ssh_key: str | None = None
    guest_ssh_port: int = 22

    # pool / reuse policy
    warm_size: int = 2
    jobs_per_recycle: int = 1
    max_jobs_per_slot: int = 0
    concurrent_ceiling: int = 16
    spawn_rate_limit: float = 1.0     # VM boots are heavy → throttle spawns
    sudo: bool = True

    # ---- construction ----
    @classmethod
    def from_dict(cls, name: str, d: dict) -> "VmWorkerSpec":
        """Build a spec from a plain dict (e.g. one entry of a parsed ``vmcompose.yml``)."""
        img = d.get("image", {})
        image = VmImageSpec(**img) if isinstance(img, dict) else VmImageSpec(golden=str(img))
        eg = d.get("egress")
        egress = None
        routing = None
        if eg is not None and not isinstance(eg, dict):
            # A PROVIDED but malformed egress block (e.g. `egress: drop` or a list) must NOT silently
            # leave egress=None — that starts the VM with NO per-worker firewall (whatever the libvirt
            # network permits). Reject so the operator fixes the typo (they meant `egress: {exit: ..}`).
            raise ValueError(f"{name}: 'egress' must be a mapping (e.g. {{exit: drop}}), got "
                             f"{type(eg).__name__}")
        if isinstance(eg, dict):
            # Reject UNKNOWN keys before applying permissive defaults: a typoed key (`exitt: tor`,
            # `block_internl: true`) would otherwise be ignored and the VM provisioned with the
            # default exit_driver="direct" / block_internal=False — clearnet or unblocked internal
            # egress instead of the intended policy. Fail closed like the malformed-value paths.
            # DERIVE the routing keys from ExitRouting's fields so the allowlist + passthrough can
            # never drift out of sync with the dataclass (e.g. rule_priority_base was missed before).
            _ROUTING_KEYS = set(ExitRouting.__dataclass_fields__)
            _ALLOWED_EGRESS_KEYS = {"exit", "egress_ports", "block_internal"} | _ROUTING_KEYS
            unknown = set(eg) - _ALLOWED_EGRESS_KEYS
            if unknown:
                raise ValueError(f"{name}: unknown egress key(s) {sorted(unknown)} "
                                 f"(did you mean one of {sorted(_ALLOWED_EGRESS_KEYS)}?)")
            egress = VmEgressPolicy(
                exit_driver=eg.get("exit", "direct"),
                egress_ports=_ports(eg.get("egress_ports")),
                block_internal=_truthy(eg.get("block_internal", False)),
            )
            # gateway_masquerade needs bool coercion (handled below); every other ExitRouting field
            # passes through as-is (ints/strings land on the dataclass directly).
            routing_kw = {k: eg[k] for k in _ROUTING_KEYS if k in eg and k != "gateway_masquerade"}
            if "gateway_masquerade" in eg:
                # Coerce with the SAME boolean parser as block_internal: a quoted YAML scalar like
                # `gateway_masquerade: "false"` is a non-empty (truthy) string otherwise, so routing
                # would still install MASQUERADE and silently collapse a disable-SNAT policy.
                routing_kw["gateway_masquerade"] = _truthy(eg["gateway_masquerade"])
            routing = ExitRouting(**routing_kw)
        known = {f for f in cls.__dataclass_fields__ if f not in ("name", "image", "egress", "routing")}
        # Reject UNKNOWN top-level keys (mirroring the nested egress-key check): a misspelled
        # security-critical key — e.g. `egres:` instead of `egress:` — would otherwise be silently
        # dropped, leaving egress=None and starting the VM with NO per-worker rooter on the
        # unrestricted libvirt network. `image`/`egress` are consumed above; everything else must be a
        # known spec field. Fail closed so the typo surfaces.
        allowed_top = known | {"image", "egress"}
        unknown_top = set(d) - allowed_top
        if unknown_top:
            raise ValueError(f"{name}: unknown top-level key(s) {sorted(unknown_top)} "
                             f"(did you mean one of {sorted(allowed_top)}?)")
        # The nwfilter knobs are SECURITY controls (a root guest re-IPing around the host egress
        # policy is exactly what they prevent). A malformed YAML scalar — `nwfilter:` (→ None) or
        # `nwfilter: false` (→ bool) — would otherwise be passed through and read as falsy by
        # _domain_xml, SILENTLY dropping the <filterref>. Require a string; the only disable sentinel
        # is an explicit "". (bool is checked before str since bool is an int, not str — but be explicit.)
        for _k in ("nwfilter", "nwfilter_ip_learning", "worker_ip_pool", "mac_prefix", "dhcp_server"):
            if _k in d and not isinstance(d[_k], str):
                raise ValueError(f"{name}: {_k} must be a string (use \"\" to disable), got "
                                 f"{type(d[_k]).__name__}")
        return cls(name=name, image=image, egress=egress, routing=routing,
                   **{k: v for k, v in d.items() if k in known})

    # ---- libvirt runtime ----
    # health_check (smoke) + pre_snapshot (e.g. CRL warm) are runtime CALLABLES the engine supplies
    # — not part of the YAML spec — so they're passed in here, not stored on the spec.
    def to_vm_config(self, *, health_check=None, pre_snapshot=None, on_ready=None) -> LibvirtVmConfig:
        return LibvirtVmConfig(
            golden_base=self.image.golden,
            overlay_dir=self.overlay_dir,
            agent_port=self.agent_port,
            mem_mb=self.mem_mb,
            vcpus=self.vcpus,
            network=self.network,
            disk_bus=self.disk_bus,
            nic_model=self.nic_model,
            nwfilter=self.nwfilter,
            nwfilter_ip_learning=self.nwfilter_ip_learning,
            worker_ip_pool=self.worker_ip_pool,
            mac_prefix=self.mac_prefix,
            dhcp_server=self.dhcp_server,
            subnet_prefix=self.subnet_prefix,
            sudo=self.sudo,
            egress_policy=self.egress,
            exit_routing=self.routing,
            gateway=self.gateway,
            trust_anchors=self.trust_anchors,
            guest_os=self.guest_os,
            guest_ssh_user=self.guest_ssh_user,
            guest_ssh_key=self.guest_ssh_key,
            guest_ssh_port=self.guest_ssh_port,
            health_check=health_check,
            pre_snapshot=pre_snapshot,
            on_ready=on_ready,
        )

    def runtime(self, *, health_check=None, pre_snapshot=None, on_ready=None) -> LibvirtVmRuntime:
        return LibvirtVmRuntime(self.to_vm_config(
            health_check=health_check, pre_snapshot=pre_snapshot, on_ready=on_ready))

    def build_pool(self, *, jobs_per_recycle: int | None = None, warm_size: int | None = None,
                   health_check=None, pre_snapshot=None, on_ready=None) -> WarmPool:
        """A warm pool of VM workers for this spec. ``jobs_per_recycle`` (e.g. from the engine's
        risk×cost declaration) overrides the spec default — the safe fallback is the spec's value
        (default 1 = reset every job). ``health_check``/``pre_snapshot`` are the engine's smoke-test
        and pre-snapshot (cache-warm) hooks.

        Drive the returned pool with :class:`~blastbox.host.runtime.vm_dispatch.VmJobDispatcher`, NOT
        the container ``Dispatcher``: a ``VmSlot`` is a network endpoint (talk to ``slot.endpoint``),
        not a control/input/output-dir container ``Slot``, so the container dispatcher's file-IPC
        warm path doesn't apply. VmJobDispatcher claims jobs and hands each to the engine's
        ``validate`` callable, which talks the warm VM worker over its own transport."""
        rt = self.runtime(health_check=health_check, pre_snapshot=pre_snapshot, on_ready=on_ready)
        return WarmPool(
            # LibvirtVmRuntime operates on VmSlot (a network endpoint) rather than the container
            # Slot (control/input/output dirs); WarmPool only ever touches the common
            # state/jobs/slot_id/spawned_at fields, so it drives this runtime fine at runtime
            # (Phase-3 validated). The static types diverge — hence the localized ignore.
            runtime=rt,  # type: ignore[arg-type]
            warm_size=warm_size if warm_size is not None else self.warm_size,
            concurrent_ceiling=self.concurrent_ceiling,
            spawn_rate_limit=self.spawn_rate_limit,
            jobs_per_recycle=jobs_per_recycle if jobs_per_recycle is not None else self.jobs_per_recycle,
            max_jobs_per_slot=self.max_jobs_per_slot,
            # A VM cold-boot+finalize takes up to boot_timeout_s (default 240s) — well past the pool's
            # 120s warming default, which would evict workers mid-boot. Give finalize headroom.
            warming_timeout_s=rt.cfg.boot_timeout_s + 60,
        )

    # ---- image build (the "build" half) ----
    def build_image(self, *, force: bool = False) -> str:
        """Bake the golden if it's missing (or ``force``). Returns the golden path.

        ``builder=qemu``: create ``image.golden`` as a fresh qcow2 overlay backed by ``base_qcow2``,
        run ``provisioners`` (operator-supplied shell — OS install/config against the booted overlay),
        then flatten the backing chain so the golden is self-contained (workers boot independent
        copies, so it must not depend on the base path at runtime).
        ``builder=packer``: delegate to a Packer template (from-ISO install). Provisioner *content*
        is OS-specific and lives with the engine; this only drives the lifecycle.
        """
        img = self.image
        if img.exists() and not force:
            return img.golden
        if img.builder == "packer":
            if not img.packer_template:
                raise ValueError(f"{self.name}: builder=packer needs packer_template")
            # On a forced rebuild over an existing golden, a plain `img.exists()` after the build
            # can't tell whether packer actually replaced it — a template that exits 0 while writing
            # elsewhere (or leaving the old file) would return the STALE golden as a successful
            # rebuild. Move the old golden aside first so "exists after build" proves packer produced
            # a fresh one; restore it if the build fails, so a failed rebuild is non-destructive.
            prev = img.golden + ".prev"
            had_golden = img.exists()
            if had_golden:
                _run(["mv", img.golden, prev], check=True)
            try:
                _run(["packer", "build", img.packer_template], check=True)
                if not img.exists():
                    raise RuntimeError(f"{self.name}: packer build ran but {img.golden} was not produced")
            except Exception:
                if had_golden:   # restore the previous working golden
                    _run(["mv", prev, img.golden])
                else:            # FIRST build: drop the partial artifact so a later build_image(
                    _run(["rm", "-f", img.golden])  # force=False) can't return a half-built golden
                raise
            if had_golden:
                _run(["rm", "-f", prev])
            return img.golden
        if img.builder == "qemu":
            if not img.base_qcow2:
                raise ValueError(f"{self.name}: builder=qemu needs image.base_qcow2")
            # Create the golden as a fresh overlay backed by the base, so provisioners boot a ready
            # disk instead of each reimplementing overlay creation. (Provisioners do the OS-specific
            # install/config + guest shutdown against this disk.)
            # Protect an existing golden on a forced rebuild: qemu-img create overwrites img.golden in
            # place, and the provisioners target that path, so a later provisioner/convert failure
            # would otherwise destroy the previous WORKING golden with no recovery. Move it aside
            # first and restore it if the rebuild fails; only drop the backup once the new one is in.
            prev = img.golden + ".prev"
            had_golden = img.exists()
            if had_golden:
                _run(["mv", img.golden, prev], check=True)
            try:
                _run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", img.base_qcow2,
                      img.golden], check=True)
                for cmd in img.provisioners:
                    _run_provisioner(cmd)
                if not img.exists():
                    raise RuntimeError(f"{self.name}: provisioners ran but {img.golden} was not produced")
                # Flatten: collapse the backing chain into a standalone qcow2 so the golden carries no
                # dependency on base_qcow2 (a worker copy with a dangling backing file won't boot).
                flat = img.golden + ".flat"
                _run(["qemu-img", "convert", "-O", "qcow2", img.golden, flat], check=True)
                _run(["mv", flat, img.golden], check=True)
            except Exception:
                if had_golden:   # restore the previous working golden — a failed rebuild is non-destructive
                    _run(["mv", prev, img.golden])
                else:            # FIRST build: delete the partial golden/flat so a later build_image(
                    # force=False) doesn't mistake a half-provisioned image for a valid golden.
                    _run(["rm", "-f", img.golden, img.golden + ".flat"])
                raise
            if had_golden:
                _run(["rm", "-f", prev])
            return img.golden
        raise ValueError(f"{self.name}: unknown builder {img.builder!r}")


def load_compose(path: str) -> dict[str, VmWorkerSpec]:
    """Parse a ``vmcompose.yml`` (``workers: {name: {...}}``) into named specs. PyYAML required."""
    import yaml  # type: ignore[import-untyped]  # lazy: only needed when loading a file
    doc = yaml.safe_load(Path(path).read_text()) or {}
    return {name: VmWorkerSpec.from_dict(name, d) for name, d in (doc.get("workers") or {}).items()}


def slot_bound_validate(
    pool: WarmPool,
    run: Callable[[Slot, Path], tuple[dict | None, bool]],
    *,
    claim_timeout_s: float = 30.0,
    work_timeout_s: float = 1500.0,
) -> Callable[[Path], tuple[dict | None, bool]]:
    """Wrap an engine's per-slot work into a :class:`VmJobDispatcher` ``validate`` callable that
    ALWAYS returns its warm VM slot — the fix for a hung/failed validate leaking pool capacity.

    ``run(slot, in_path)`` is the engine's "talk to the claimed warm VM and decide (summary, ok)".
    The wrapper:

    * claims a slot (up to ``claim_timeout_s``; raises if none is free),
    * runs ``run`` in a bounded daemon thread (``work_timeout_s``) so a hung VM agent can't pin the
      slot forever — set ``work_timeout_s`` BELOW the dispatcher's ``validate_timeout_s`` so this
      reclaim fires first (Python can't kill the abandoned thread, but the slot is freed),
    * releases the slot in a ``finally`` on EVERY exit — ``dirty=True`` unless ``run`` returned
      ``ok=True`` cleanly — so a hung, errored, or contaminated worker is force-recycled (snapshot
      reverted), not handed to the next job.

    Returns ``(summary, ok)`` like any ``validate``; re-raises ``run``'s exception (and ``TimeoutError``
    on a work-timeout) so the dispatcher records the job ``FAILED``."""
    def _validate(in_path: Path) -> tuple[dict | None, bool]:
        slot = pool.claim(timeout_s=claim_timeout_s)
        if slot is None:
            raise RuntimeError(f"no warm VM slot available within {claim_timeout_s}s")
        result: dict[str, object] = {}

        def _work() -> None:
            try:
                result["v"] = run(slot, in_path)
            except BaseException as exc:  # noqa: BLE001 — surfaced to the caller after the join
                result["e"] = exc

        t = threading.Thread(target=_work, name=f"vm-slot-work-{slot.slot_id[:8]}", daemon=True)
        t.start()
        t.join(timeout=work_timeout_s)
        try:
            if t.is_alive():
                raise TimeoutError(f"VM work exceeded {work_timeout_s}s — reclaiming slot "
                                   f"{slot.slot_id} (hung VM agent?)")
            if "e" in result:
                raise result["e"]  # type: ignore[misc]
            return result["v"]  # type: ignore[return-value]
        finally:
            # Always return the slot. If the work thread is STILL ALIVE (the work_timeout path), it
            # may keep talking to this VM — do NOT recycle (a snapshot-revert + reuse would let the
            # abandoned thread corrupt a later job's worker). RETIRE it: destroy the VM, severing the
            # hung interaction, so it's never reused. A finished thread releases normally: dirty=True
            # unless run() returned ok=True cleanly (errored/ok=False → force-recycle a possibly
            # contaminated worker; clean → reuse per the pool's recycle policy).
            try:
                if t.is_alive():
                    # ATTRIBUTE it. A hung VM agent is the most direct worker fault there is, but
                    # retiring recorded nothing: if every VM restored from a poisoned snapshot
                    # hangs, each is destroyed and replaced from that SAME snapshot forever and
                    # the base-rebuild protection is never reached. The hard retire stays -- the
                    # abandoned thread may still be talking to this VM, so it must not be
                    # recycled and re-offered (upstream, PR #82).
                    if _accepts_kwarg(pool.retire, "fault"):
                        pool.retire(slot, fault="worker")
                    else:
                        pool.retire(slot)
                else:
                    v = result.get("v")
                    clean = bool(isinstance(v, tuple) and len(v) == 2 and v[1])
                    # ATTRIBUTE the failure. Releasing dirty with no fault leaves it "unknown",
                    # which force-recycles the slot but advances neither the per-slot nor the
                    # pool-wide streak -- so a broken VM agent failing every request was
                    # snapshot-reverted and offered again indefinitely, never reaching burnout
                    # protection or a base rebuild. Convict only on POSITIVE evidence that the
                    # WORKER, not the sample, misbehaved: a transport failure (VM unreachable,
                    # TLS broken, connection dropped). An engine that ran and returned ok=False
                    # judged the INPUT, and any other exception is ambiguous at this seam --
                    # both stay unattributed (upstream, PR #82).
                    exc = result.get("e")
                    if isinstance(exc, BaseException):
                        # A transport failure is evidence about this worker...
                        fault = (
                            "worker"
                            # ...but NOT a 4xx. HTTPError is a URLError, so an agent that ANSWERED
                            # and rejected the request looked identical to an unreachable box
                            # here. The HTTP transport learned this; its sibling did not (PR #82).
                            if is_transport_error(exc) and not is_answered_http_rejection(exc)
                            # An ANSWERED 4xx is not merely un-convictable: the agent replied, so
                            # it and the base it restored from are demonstrably responsive.
                            # "unknown" only stops the rejection incrementing the streak; it does
                            # not CLEAR the failure before it, so a transport failure, then a 413,
                            # then another transport failure still counted as consecutive. The
                            # HTTP transport learned this; its sibling did not (PR #82).
                            else "job" if is_answered_http_rejection(exc)
                            else None          # ambiguous: never convict on a failure we can't
                        )                      # attribute
                    else:
                        # NO exception: the run COMPLETED and the engine returned ok=False -- a
                        # verdict on the INPUT, and positive proof this VM is responsive. Leaving
                        # it unattributed made release() preserve both streaks, so a transport
                        # failure on either side of a successful run counted as consecutive and
                        # could evict the VM or rebuild its base (upstream, PR #82).
                        fault = "job"
                    pool.release(slot, **release_kwargs(
                        pool.release, dirty=not clean, fault=fault))
            except Exception:  # noqa: BLE001 — slot return must never mask the validate result/error
                _log.exception("slot_bound_validate: slot return failed for slot %s", slot.slot_id)
    return _validate


def _truthy(v: object) -> bool:
    # Coerce a YAML scalar to bool for SECURITY knobs (block_internal, gateway_masquerade). A quoted
    # "false" arrives as the string "false" (bool() would read it True). REJECT an unrecognized string
    # (e.g. a typo `block_internal: "treu"`) rather than silently defaulting it to False — a security
    # control must not be disabled by a typo.
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    if isinstance(v, str):
        s = v.strip().lower()
        if s in ("1", "true", "yes", "on"):
            return True
        if s in ("", "0", "false", "no", "off"):
            return False
        raise ValueError(f"malformed boolean value {v!r} (use true/false)")
    # Anything non-scalar (a YAML list/dict/null, e.g. a typo `block_internal: []`) must NOT fall
    # through to Python truthiness — `bool([])` is False, which would SILENTLY DISABLE the security
    # knob. Reject it, same fail-closed posture as a malformed string.
    raise ValueError(f"unsupported boolean value {v!r} (use true/false)")


def _ports(v: object) -> tuple[int, ...] | None:
    # Normalize whatever YAML produced (int / str / list) to a string, then hand it to the ONE
    # validated parser shared with the container path (range-checks 1-65535, dedups).
    # OMITTED (None / bool) → None = "no allowlist" (direct accepts all; tunneled accepts all over the
    # tunnel). But a PROVIDED value that parses to nothing (e.g. `egress_ports: [70000]`) must FAIL
    # CLOSED — returning None there would silently WIDEN a web-only policy to unrestricted egress —
    # so it collapses to an empty tuple (), which downstream means "drop everything", not "allow all".
    if v is None:                         # OMITTED → None (no allowlist)
        return None
    if isinstance(v, bool):               # bool is an int subclass; a YAML bool is not a port list —
        return ()                         # a PROVIDED bool is malformed → fail CLOSED, not None (open)
    if isinstance(v, int):                # a single port, e.g. `egress_ports: 443`
        raw: str = str(v)
    elif isinstance(v, str):
        raw = v
    elif isinstance(v, (list, tuple)):
        raw = " ".join(str(x) for x in v)
    else:
        return ()   # a PROVIDED but unsupported type (e.g. a mapping `{http: 80}`) fails CLOSED to
        #             () = "drop everything", never None = "no allowlist" (which would widen to all).
    return parse_egress_ports(raw) or ()   # provided-but-all-invalid → () (closed), never None (open)


def _run(args: list[str], check: bool = False) -> subprocess.CompletedProcess:
    cp = subprocess.run(args, capture_output=True, text=True)
    if check and cp.returncode != 0:
        raise RuntimeError(f"{' '.join(args)} failed: {cp.stderr.strip()[:300]}")
    return cp


def _run_provisioner(cmd: "str | list[str]") -> None:
    """Run one provisioner and fail closed on a non-zero exit. The spec documents provisioners as
    SHELL commands, so a STRING runs through the shell — operators rely on ``&&``/pipes/redirection/
    ``VAR=x`` prefixes; argv-splitting one would silently drop everything after a shell operator and
    let a golden build look successful after incomplete provisioning. A LIST runs as argv (no shell).
    These are operator-supplied, trusted compose inputs (not attacker data)."""
    if isinstance(cmd, str):
        cp = subprocess.run(cmd, shell=True, capture_output=True, text=True)  # noqa: S602 — operator-trusted shell command by spec
        shown = cmd
    else:
        cp = subprocess.run(cmd, capture_output=True, text=True)
        shown = " ".join(cmd)
    if cp.returncode != 0:
        raise RuntimeError(f"provisioner failed ({shown[:200]}): {cp.stderr.strip()[:300]}")
