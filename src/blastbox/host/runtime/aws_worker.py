"""AWS disposable-worker runtime backends (SlotRuntime family).

blastbox's warm-pool seam (``blastbox.host.pool.SlotRuntime``: ``spawn`` / ``is_ready`` /
``is_alive`` / ``reap``) is transport-agnostic, so "run the worker on AWS" is a *family* of
backends, not one. They all implement the same interface; only the AWS API underneath differs:

  * ``LambdaMicroVmRuntime``   -- Lambda MicroVMs: ``lambda-microvms run-microvm`` -> a per-VM
    HTTPS URL + a JWE auth token (``create-microvm-auth-token``) -> ``terminate-microvm``.
  * ``DisposableEc2Runtime``   -- one throwaway EC2 per slot: ``ec2 run-instances`` (from an AMI,
    the worker agent brought up via user-data) -> the instance's IP:port -> ``terminate-instances``.

Both are *network-endpoint* tiers, so their slot handle (:class:`AwsWorkerSlot`) carries an
``endpoint`` (URL or ip:port) like libvirt's ``VmSlot`` rather than the container file-handshake dirs,
and they're driven by :class:`blastbox.host.runtime.vm_dispatch.VmJobDispatcher` with an
engine-supplied ``validate`` transport.

Design notes:
  * **No boto3 dependency.** We shell out to the ``aws`` CLI through an injectable ``aws_runner``
    seam -- exactly how ``libvirt_vm`` shells ``virsh`` and ``firecracker`` injects a
    ``subprocess_runner``. Tests inject a fake runner that returns canned JSON; nothing real is
    called. The HTTP health probe is injectable the same way.
  * **Fail-closed.** ``available()`` verifies creds + the service before a tier is selected; a spawn
    that can't produce a running, reachable worker raises rather than yielding a dead slot.
  * **Disposable.** No ``recycle`` method -> WarmPool treats every slot as one-job-then-reap (never
    reuse a detonation VM), matching the FC/gVisor cold-spawn tiers.
"""

from __future__ import annotations

import json
import logging
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from blastbox.host.pool import SlotState

_log = logging.getLogger("blastbox.host.runtime.aws_worker")

# Injectable seams (defaults do the real thing; tests pass fakes).
AwsRunner = Callable[[Sequence[str], float], subprocess.CompletedProcess]
HttpProbe = Callable[[str, dict[str, str], float], bool]


class AwsWorkerError(RuntimeError):
    """An AWS CLI call failed or returned an unusable response."""


class AwsUnavailable(RuntimeError):
    """The AWS tier is not usable (missing creds / CLI / entitlement)."""


def _default_aws_runner(argv: Sequence[str], timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout)  # noqa: S603


def _default_http_probe(url: str, headers: dict[str, str], timeout: float) -> bool:
    """GET ``url`` with ``headers``; True iff a 2xx comes back within ``timeout``."""
    req = urllib.request.Request(url, headers=headers, method="GET")  # noqa: S310 (url is host-built)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return 200 <= resp.status < 300
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return False


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def _env(get: Callable[[str], str | None], key: str, default: str | None = None) -> str | None:
    v = get(key)
    return v if (v is not None and v != "") else default


@dataclass(frozen=True)
class AwsWorkerConfig:
    """Shared config for every AWS disposable-worker tier (region/creds/timeouts/agent)."""

    region: str
    profile: str | None = None
    agent_port: int = 8765
    agent_health_path: str = "/healthz"
    ready_timeout_s: float = 300.0     # overall budget the pool gives a slot to become ready
    probe_timeout_s: float = 5.0       # per health-probe HTTP timeout
    cli_timeout_s: float = 120.0       # per aws-cli call timeout
    max_duration_s: int = 3600         # hard lifetime cap requested of the tier (belt+braces reap)

    def aws_argv(self, service: str, op: str, *args: str) -> list[str]:
        argv = ["aws", service, op, "--region", self.region, "--output", "json"]
        if self.profile:
            argv += ["--profile", self.profile]
        argv += list(args)
        return argv


@dataclass(frozen=True)
class LambdaMicroVmConfig(AwsWorkerConfig):
    image_identifier: str = ""         # microvm image ARN/id from create-microvm-image
    execution_role_arn: str | None = None
    egress_connector_ids: tuple[str, ...] = ()   # () => no egress connector == sealed (no outbound)
    ingress: bool = True               # False => NO_INGRESS (no public URL)

    @classmethod
    def from_env(cls, get: Callable[[str], str | None], **overrides: Any) -> LambdaMicroVmConfig:
        region = _env(get, "BLASTBOX_AWS_REGION") or _env(get, "AWS_REGION") or "us-east-1"
        conns = _env(get, "BLASTBOX_LAMBDA_EGRESS_CONNECTORS")
        return cls(
            region=region,
            profile=_env(get, "BLASTBOX_AWS_PROFILE"),
            agent_port=int(_env(get, "BLASTBOX_AWS_AGENT_PORT", "8765") or "8765"),
            image_identifier=_env(get, "BLASTBOX_LAMBDA_IMAGE") or "",
            execution_role_arn=_env(get, "BLASTBOX_LAMBDA_EXEC_ROLE_ARN"),
            egress_connector_ids=tuple(c.strip() for c in (conns or "").split(",") if c.strip()),
            ingress=(_env(get, "BLASTBOX_LAMBDA_NO_INGRESS") or "0") != "1",
            max_duration_s=int(_env(get, "BLASTBOX_AWS_MAX_DURATION_S", "3600") or "3600"),
            **overrides,
        )


@dataclass(frozen=True)
class Ec2Config(AwsWorkerConfig):
    image_id: str = ""                 # AMI id (worker image; agent started via user-data)
    instance_type: str = "m7g.large"   # ARM64 default (matches sealed-Linux ARM image); override for x86
    subnet_id: str | None = None
    security_group_ids: tuple[str, ...] = ()
    iam_instance_profile: str | None = None
    key_name: str | None = None
    use_public_ip: bool = False        # talk to the public IP (default: private IP, host in-VPC)
    user_data_b64: str | None = None   # base64 cloud-init that brings up the worker agent on agent_port

    @classmethod
    def from_env(cls, get: Callable[[str], str | None], **overrides: Any) -> Ec2Config:
        region = _env(get, "BLASTBOX_AWS_REGION") or _env(get, "AWS_REGION") or "us-east-1"
        sgs = _env(get, "BLASTBOX_EC2_SECURITY_GROUPS")
        return cls(
            region=region,
            profile=_env(get, "BLASTBOX_AWS_PROFILE"),
            agent_port=int(_env(get, "BLASTBOX_AWS_AGENT_PORT", "8765") or "8765"),
            image_id=_env(get, "BLASTBOX_EC2_AMI") or "",
            instance_type=_env(get, "BLASTBOX_EC2_INSTANCE_TYPE", "m7g.large") or "m7g.large",
            subnet_id=_env(get, "BLASTBOX_EC2_SUBNET_ID"),
            security_group_ids=tuple(s.strip() for s in (sgs or "").split(",") if s.strip()),
            iam_instance_profile=_env(get, "BLASTBOX_EC2_IAM_PROFILE"),
            key_name=_env(get, "BLASTBOX_EC2_KEY_NAME"),
            use_public_ip=(_env(get, "BLASTBOX_EC2_PUBLIC_IP") or "0") == "1",
            user_data_b64=_env(get, "BLASTBOX_EC2_USER_DATA_B64"),
            max_duration_s=int(_env(get, "BLASTBOX_AWS_MAX_DURATION_S", "3600") or "3600"),
            **overrides,
        )


# ---------------------------------------------------------------------------
# Slot handle
# ---------------------------------------------------------------------------

@dataclass
class AwsWorkerSlot:
    """One AWS disposable worker. Network-endpoint flavored (like libvirt's VmSlot): carries the
    worker's reachable ``endpoint`` (a URL or ip:port) + optional auth token, not file-handshake dirs.
    WarmPool drives it fine -- it only touches state/jobs/slot_id/spawned_at."""

    slot_id: str
    resource_id: str | None = None       # microvm id / ec2 instance id (for describe + terminate)
    ip: str | None = None                # ec2 private/public IP once running
    url: str | None = None               # lambda-microvm HTTPS URL once running
    auth_token: str | None = None        # lambda-microvm JWE (X-aws-proxy-auth); None for ec2
    agent_port: int = 8765
    state: SlotState = SlotState.SPAWNING
    jobs: int = 0
    spawned_at: float = 0.0
    reserved: bool = False

    @property
    def endpoint(self) -> tuple[str, int] | None:
        """(host, port) the engine transport connects to, or None until running."""
        if self.ip is not None:
            return (self.ip, self.agent_port)
        return None


# ---------------------------------------------------------------------------
# Base runtime
# ---------------------------------------------------------------------------

class AwsDisposableRuntime:
    """Shared machinery for AWS disposable-worker tiers. Concrete tiers implement the four hooks
    ``_launch`` / ``_health_ok`` / ``_running`` / ``_terminate``; this base wires them into the
    ``SlotRuntime`` protocol + the injectable aws-cli / http-probe seams. Disposable by design (no
    ``recycle`` -> one job per slot)."""

    kind = "aws"

    def __init__(
        self,
        cfg: AwsWorkerConfig,
        *,
        aws_runner: AwsRunner | None = None,
        http_probe: HttpProbe | None = None,
        clock: Callable[[], float] | None = None,
        ssl_context: Any = None,
    ) -> None:
        self.cfg = cfg
        self._run_aws = aws_runner or _default_aws_runner
        self._probe = http_probe or _default_http_probe
        self._clock = clock or time.monotonic
        # client (m)TLS context for https workers -- exposed for make_remote_validate; when set, the
        # health probe defaults to the TLS-aware one (see the select_* helpers).
        self.ssl_context = ssl_context

    # -- aws cli seam -------------------------------------------------------
    def _aws(self, service: str, op: str, *args: str) -> dict[str, Any]:
        argv = self.cfg.aws_argv(service, op, *args)
        try:
            cp = self._run_aws(argv, self.cfg.cli_timeout_s)
        except subprocess.TimeoutExpired as exc:
            raise AwsWorkerError(f"aws {service} {op}: timed out after {self.cfg.cli_timeout_s}s") from exc
        if cp.returncode != 0:
            raise AwsWorkerError(f"aws {service} {op} failed (rc={cp.returncode}): {(cp.stderr or '').strip()[:400]}")
        out = (cp.stdout or "").strip()
        if not out:
            return {}
        try:
            return json.loads(out)
        except json.JSONDecodeError as exc:
            raise AwsWorkerError(f"aws {service} {op}: non-JSON response") from exc

    # -- fail-closed availability ------------------------------------------
    def available(self) -> bool:
        """True iff creds resolve (sts get-caller-identity) AND the tier's service probe passes."""
        try:
            ident = self._aws("sts", "get-caller-identity")
            if not ident.get("Account"):
                return False
            return self._service_available()
        except (AwsWorkerError, OSError):
            return False

    def _service_available(self) -> bool:  # subclass: a cheap read-only service probe
        raise NotImplementedError

    # -- SlotRuntime protocol ----------------------------------------------
    def spawn(self) -> AwsWorkerSlot:
        slot = self._launch()
        slot.spawned_at = self._clock()
        slot.agent_port = self.cfg.agent_port
        _log.info("%s: spawned slot=%s resource=%s", self.kind, slot.slot_id, slot.resource_id)
        return slot

    def is_ready(self, slot: AwsWorkerSlot) -> bool:
        try:
            return self._health_ok(slot)
        except (AwsWorkerError, OSError) as exc:
            _log.debug("%s: is_ready(%s) probe error: %s", self.kind, slot.slot_id, exc)
            return False

    def is_alive(self, slot: AwsWorkerSlot) -> bool:
        try:
            return self._running(slot)
        except (AwsWorkerError, OSError):
            return False

    def reap(self, slot: AwsWorkerSlot) -> None:
        if slot.resource_id is None:
            return
        self._terminate(slot)
        _log.info("%s: reaped slot=%s resource=%s", self.kind, slot.slot_id, slot.resource_id)

    # -- hooks (subclass) ---------------------------------------------------
    def _launch(self) -> AwsWorkerSlot:
        raise NotImplementedError

    def _health_ok(self, slot: AwsWorkerSlot) -> bool:
        raise NotImplementedError

    def _running(self, slot: AwsWorkerSlot) -> bool:
        raise NotImplementedError

    def _terminate(self, slot: AwsWorkerSlot) -> None:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Lambda MicroVM tier
# ---------------------------------------------------------------------------

class LambdaMicroVmRuntime(AwsDisposableRuntime):
    """One Lambda MicroVM per slot. Transport = the per-VM HTTPS URL + a JWE auth token."""

    kind = "aws-lambda-microvm"

    def __init__(self, cfg: LambdaMicroVmConfig, **kw: Any) -> None:
        if not cfg.image_identifier:
            raise AwsUnavailable("LambdaMicroVmRuntime: BLASTBOX_LAMBDA_IMAGE (image identifier) is required")
        super().__init__(cfg, **kw)
        self.cfg: LambdaMicroVmConfig = cfg

    def _service_available(self) -> bool:
        # entitlement probe: list-microvms returns cleanly iff the account is enabled for the service.
        self._aws("lambda-microvms", "list-microvms")
        return True

    def _launch(self) -> AwsWorkerSlot:
        sid = uuid.uuid4().hex[:16]
        args = ["--image-identifier", self.cfg.image_identifier,
                "--client-token", sid,
                "--maximum-duration-in-seconds", str(self.cfg.max_duration_s)]
        if self.cfg.execution_role_arn:
            args += ["--execution-role-arn", self.cfg.execution_role_arn]
        if self.cfg.egress_connector_ids:
            args += ["--egress-network-connectors", ",".join(self.cfg.egress_connector_ids)]
        if not self.cfg.ingress:
            args += ["--ingress-network-connectors", "NO_INGRESS"]
        resp = self._aws("lambda-microvms", "run-microvm", *args)
        rid = resp.get("microvmId") or resp.get("MicrovmId") or resp.get("id")
        if not rid:
            raise AwsWorkerError("run-microvm: no microvm id in response")
        return AwsWorkerSlot(slot_id=sid, resource_id=str(rid), state=SlotState.WARMING)

    def _describe(self, slot: AwsWorkerSlot) -> dict[str, Any]:
        return self._aws("lambda-microvms", "get-microvm", "--microvm-id", str(slot.resource_id))

    def _running(self, slot: AwsWorkerSlot) -> bool:
        st = str(self._describe(slot).get("state", "")).lower()
        return st in ("running", "active", "ready")

    def _mint_token(self, slot: AwsWorkerSlot) -> str:
        resp = self._aws("lambda-microvms", "create-microvm-auth-token",
                         "--microvm-id", str(slot.resource_id))
        tok = resp.get("token") or resp.get("authToken") or resp.get("Token")
        if not tok:
            raise AwsWorkerError("create-microvm-auth-token: no token in response")
        return str(tok)

    def _health_ok(self, slot: AwsWorkerSlot) -> bool:
        # Resolve the per-VM URL once the microVM is running, then probe the agent with a fresh JWE.
        if slot.url is None:
            desc = self._describe(slot)
            if str(desc.get("state", "")).lower() not in ("running", "active", "ready"):
                return False
            slot.url = desc.get("url") or desc.get("endpointUrl") or desc.get("Url")
            if slot.url is None:
                return False
        token = self._mint_token(slot)
        slot.auth_token = token
        url = slot.url.rstrip("/") + self.cfg.agent_health_path
        headers = {"X-aws-proxy-auth": token, "X-aws-proxy-port": str(self.cfg.agent_port)}
        return self._probe(url, headers, self.cfg.probe_timeout_s)

    def _terminate(self, slot: AwsWorkerSlot) -> None:
        self._aws("lambda-microvms", "terminate-microvm", "--microvm-id", str(slot.resource_id))


def _inject_tls(getter: Callable[[str], str | None], kw: dict[str, Any]) -> dict[str, Any]:
    """If BLASTBOX_DISPATCH_TLS_CA is set (and not already overridden), add the client (m)TLS context +
    a TLS-aware health probe so an https worker agent is probed + talked to over mTLS."""
    if "ssl_context" in kw:
        return kw
    from blastbox.host.runtime.remote_http import dispatch_ssl_context_from_env, make_tls_probe
    ctx = dispatch_ssl_context_from_env(getter)
    if ctx is not None:
        kw = {**kw, "ssl_context": ctx}
        kw.setdefault("http_probe", make_tls_probe(ctx))
    return kw


def select_lambda_microvm_runtime(
    *, cfg: LambdaMicroVmConfig | None = None, get_env: Callable[[str], str | None] | None = None,
    require_available: bool = False, **kw: Any,
) -> LambdaMicroVmRuntime:
    import os
    getter = get_env or os.environ.get
    cfg = cfg or LambdaMicroVmConfig.from_env(getter)
    rt = LambdaMicroVmRuntime(cfg, **_inject_tls(getter, kw))
    if require_available and not rt.available():
        raise AwsUnavailable("aws-lambda-microvm tier unavailable (creds/entitlement/service probe failed)")
    return rt


# ---------------------------------------------------------------------------
# Disposable EC2 tier
# ---------------------------------------------------------------------------

class DisposableEc2Runtime(AwsDisposableRuntime):
    """One throwaway EC2 instance per slot. Transport = the instance IP:port (in-VPC private IP by
    default). Agent is brought up by the AMI's user-data; instance is terminated after one job."""

    kind = "aws-ec2"

    def __init__(self, cfg: Ec2Config, **kw: Any) -> None:
        if not cfg.image_id:
            raise AwsUnavailable("DisposableEc2Runtime: BLASTBOX_EC2_AMI is required")
        super().__init__(cfg, **kw)
        self.cfg: Ec2Config = cfg

    def _service_available(self) -> bool:
        self._aws("ec2", "describe-instances", "--max-items", "1")
        return True

    def _launch(self) -> AwsWorkerSlot:
        sid = uuid.uuid4().hex[:16]
        c = self.cfg
        tag = f"ResourceType=instance,Tags=[{{Key=blastbox-slot,Value={sid}}}]"
        args = ["--image-id", c.image_id, "--instance-type", c.instance_type,
                "--count", "1", "--client-token", sid, "--tag-specifications", tag,
                # auto-terminate on the instance's own shutdown as a backstop reap
                "--instance-initiated-shutdown-behavior", "terminate"]
        if c.subnet_id:
            args += ["--subnet-id", c.subnet_id]
        if c.security_group_ids:
            args += ["--security-group-ids", *c.security_group_ids]
        if c.iam_instance_profile:
            args += ["--iam-instance-profile", f"Name={c.iam_instance_profile}"]
        if c.key_name:
            args += ["--key-name", c.key_name]
        if c.user_data_b64:
            # The aws CLI base64-encodes --user-data itself, so hand it the RAW script (decoded from
            # our stored base64) or it would double-encode and the agent would never start.
            import base64
            args += ["--user-data", base64.b64decode(c.user_data_b64).decode("utf-8", errors="replace")]
        resp = self._aws("ec2", "run-instances", *args)
        insts = resp.get("Instances") or []
        if not insts or not insts[0].get("InstanceId"):
            raise AwsWorkerError("run-instances: no instance id in response")
        return AwsWorkerSlot(slot_id=sid, resource_id=str(insts[0]["InstanceId"]), state=SlotState.WARMING)

    def _describe(self, slot: AwsWorkerSlot) -> dict[str, Any]:
        resp = self._aws("ec2", "describe-instances", "--instance-ids", str(slot.resource_id))
        for res in resp.get("Reservations", []):
            for inst in res.get("Instances", []):
                if inst.get("InstanceId") == slot.resource_id:
                    return inst
        return {}

    def _running(self, slot: AwsWorkerSlot) -> bool:
        return str(self._describe(slot).get("State", {}).get("Name", "")) == "running"

    def _health_ok(self, slot: AwsWorkerSlot) -> bool:
        if slot.ip is None:
            inst = self._describe(slot)
            if str(inst.get("State", {}).get("Name", "")) != "running":
                return False
            slot.ip = inst.get("PublicIpAddress") if self.cfg.use_public_ip else inst.get("PrivateIpAddress")
            if slot.ip is None:
                return False
        url = f"http://{slot.ip}:{self.cfg.agent_port}{self.cfg.agent_health_path}"
        return self._probe(url, {}, self.cfg.probe_timeout_s)

    def _terminate(self, slot: AwsWorkerSlot) -> None:
        self._aws("ec2", "terminate-instances", "--instance-ids", str(slot.resource_id))


def select_disposable_ec2_runtime(
    *, cfg: Ec2Config | None = None, get_env: Callable[[str], str | None] | None = None,
    require_available: bool = False, **kw: Any,
) -> DisposableEc2Runtime:
    import os
    getter = get_env or os.environ.get
    cfg = cfg or Ec2Config.from_env(getter)
    rt = DisposableEc2Runtime(cfg, **_inject_tls(getter, kw))
    if require_available and not rt.available():
        raise AwsUnavailable("aws-ec2 tier unavailable (creds/service probe failed)")
    return rt
