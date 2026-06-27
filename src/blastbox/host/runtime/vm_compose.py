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

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from blastbox.host.netwire import parse_egress_ports
from blastbox.host.pool import WarmPool
from blastbox.host.runtime.libvirt_egress import ExitRouting, VmEgressPolicy
from blastbox.host.runtime.libvirt_vm import LibvirtVmConfig, LibvirtVmRuntime


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
        if isinstance(eg, dict):
            egress = VmEgressPolicy(
                exit_driver=eg.get("exit", "direct"),
                egress_ports=_ports(eg.get("egress_ports")),
                block_internal=_truthy(eg.get("block_internal", False)),
            )
            routing = ExitRouting(**{k: eg[k] for k in (
                "vpn_table", "vpn_tun", "tor_trans_port", "tor_dns_port", "fakenet_addr",
                "gateway", "leg", "gateway_table_base", "gateway_masquerade") if k in eg})
        known = {f for f in cls.__dataclass_fields__ if f not in ("name", "image", "egress", "routing")}
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
            _run(["packer", "build", img.packer_template], check=True)
            return img.golden
        if img.builder == "qemu":
            if not img.base_qcow2:
                raise ValueError(f"{self.name}: builder=qemu needs image.base_qcow2")
            # Create the golden as a fresh overlay backed by the base, so provisioners boot a ready
            # disk instead of each reimplementing overlay creation. (Provisioners do the OS-specific
            # install/config + guest shutdown against this disk.)
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
            return img.golden
        raise ValueError(f"{self.name}: unknown builder {img.builder!r}")


def load_compose(path: str) -> dict[str, VmWorkerSpec]:
    """Parse a ``vmcompose.yml`` (``workers: {name: {...}}``) into named specs. PyYAML required."""
    import yaml  # type: ignore[import-untyped]  # lazy: only needed when loading a file
    doc = yaml.safe_load(Path(path).read_text()) or {}
    return {name: VmWorkerSpec.from_dict(name, d) for name, d in (doc.get("workers") or {}).items()}


def _truthy(v: object) -> bool:
    # A quoted YAML scalar like block_internal: "false" arrives as the string "false", which
    # bool() would read as True. Treat the usual false-y spellings as False.
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "on")
    return bool(v)


def _ports(v: object) -> tuple[int, ...] | None:
    # Normalize whatever YAML produced (int / str / list) to a string, then hand it to the ONE
    # validated parser shared with the container path. That range-checks (1-65535), dedups, and
    # fails closed on nothing-valid — so a compose typo like `egress_ports: [80, 70000]` drops the
    # bad token instead of emitting a broken `--dports` that reaps every worker for the spec.
    if v is None or isinstance(v, bool):  # bool is an int subclass; a YAML bool is not a port list
        return None
    if isinstance(v, int):                # a single port, e.g. `egress_ports: 443`
        raw: str = str(v)
    elif isinstance(v, str):
        raw = v
    elif isinstance(v, (list, tuple)):
        raw = " ".join(str(x) for x in v)
    else:
        return None
    return parse_egress_ports(raw)


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
