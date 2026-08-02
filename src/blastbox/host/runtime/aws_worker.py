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

import errno
import json
import socket
import logging
import os
import contextlib
import subprocess
import threading
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from dataclasses import field as dc_field
from typing import Any

from blastbox.host.pool import SlotState

_log = logging.getLogger("blastbox.host.runtime.aws_worker")

# Injectable seams (defaults do the real thing; tests pass fakes).
AwsRunner = Callable[[Sequence[str], float], subprocess.CompletedProcess]
# None = "we could not even ask" (local resource exhaustion), distinct from False = "the box
# answered, and the answer was no". Only the health/liveness paths forward the None; everything
# that needs a plain yes/no coerces with `is True` (issue #77 marla-loop 3).
HttpProbe = Callable[[str, dict[str, str], float], "bool | None"]

class AwsWorkerError(RuntimeError):
    """An AWS CLI call failed or returned an unusable response."""



# Which aws-cli failures are evidence that a WORKER IS GONE?
#
# This list is deliberately an ALLOWLIST of confirmed-dead answers, and everything else defaults to
# UNKNOWN. It started life the other way round -- an ever-growing denylist of "transient" markers,
# with DEAD as the default -- and four consecutive review rounds each found another retryable error
# missing from it. The last one was decisive: TooManyRequestsException is Lambda's OWN throttle
# name, i.e. the single likeliest brownout signal on the primary production tier, and it read as
# death. A denylist of everything AWS can transiently say is unbounded and cannot be completed by
# inspection; the set of answers that genuinely PROVE a resource is gone is small and enumerable.
#
# The two failure modes are not symmetric, which is what settles the direction:
#   miss a transient marker  -> terminate a healthy, warmed worker (and, because control-plane
#                               faults are CORRELATED, every other slot in the tier on the same tick)
#   miss a dead marker       -> keep a husk one extra tick; the claim probe skips it, /detonate
#                               fails it, and it is reaped there instead
# So: fail SAFE. Only a definitive "no such resource" costs a slot (issue #77 round 4).
_CONFIRMED_DEAD_AWS_MARKERS = (
    "resourcenotfound",             # ResourceNotFoundException -- lambda / lambda-microvms
    "invalidinstanceid.notfound",   # EC2: no such instance
    "invalidinstanceid.malformed",  # EC2: our recorded id cannot even name an instance
    "invalidinstanceid",            # (any other InvalidInstanceID.* -- all mean "not this instance")
    # NB: entries here must be AWS ERROR CODES, never English prose. A bare "does not exist" lived
    # here for one round and matched InvalidAccessKeyId ("The AWS Access Key Id you provided does
    # not exist in our records"), so rotating a key marked the ENTIRE fleet dead -- and terminate
    # failed under the same credentials, quarantining every slot as DRAINING (issue #77 round 6).
    "no such microvm",
    "has been terminated",
)


def _is_confirmed_dead_aws_error(stderr: str) -> bool:
    """True ONLY if AWS positively told us the resource is gone.

    Everything else -- throttles, 5xx, timeouts, auth/IMDS stalls, validation errors, and anything
    AWS invents next -- is UNKNOWN by default. See the list above for why the default is that way
    round: an unrecognised error must never be read as a dead worker."""
    low = (stderr or "").lower()
    return any(marker in low for marker in _CONFIRMED_DEAD_AWS_MARKERS)


# The shortest resume window in which a HEALTHY warm worker could plausibly answer. Below this we
# refuse to draw any conclusion from an expiry; at or above it, an unanswered probe against a
# control-plane-CONFIRMED-running worker is a real failure (issue #77 marla-loop 2).
# The shortest agent probe worth issuing. Below this we decline and report UNKNOWN rather than
# manufacture a verdict from a socket we never really gave a chance (issue #77 marla-loop 4).
_MIN_PROBE_S = 0.25


class AwsUnknownState(AwsWorkerError):
    """The control plane did not give us an answer about this worker (issue #77).

    UNKNOWN is NOT death. Whether a failure means "unknown" or "confirmed gone" is a property of
    the FAILURE, not of where it was raised: the first cut only applied this reading inside a probe
    budget, so the same throttle/timeout at resume() time — where there is no budget in scope —
    surfaced as a bare AwsWorkerError and _resume_on_claim terminated a healthy PARKED worker.
    Every caller that can destroy a slot must treat this as "skip / try again", never "reap"."""


class AwsProbeTimeout(AwsUnknownState):
    """The control plane didn't answer in time — the timeout flavour of AwsUnknownState. Raised
    whether or not a probe budget was in scope (a 120s cli_timeout_s expiring is no more evidence
    of death than a 5s claim budget expiring)."""


class AwsUnavailable(RuntimeError):
    """The AWS tier is not usable (missing creds / CLI / entitlement)."""


def _default_aws_runner(argv: Sequence[str], timeout: float) -> subprocess.CompletedProcess:
    # AWS_PAGER="" disables the CLI client-side pager for EVERY runtime call (higher precedence than a
    # profile `cli_pager`), so noninteractive JSON never routes through less/more -> no spawn/reap hang or
    # non-JSON parse. Spread os.environ so AWS creds / PATH / AWS_* still resolve.
    env = {**os.environ, "AWS_PAGER": ""}
    return subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout, env=env)  # noqa: S603


# Resolver failures that mean "ask again", as opposed to "this name does not exist".
_TRANSIENT_RESOLVER_ERRORS = frozenset(
    getattr(socket, n) for n in ("EAI_AGAIN", "EAI_SYSTEM", "EAI_MEMORY") if hasattr(socket, n)
)


def _is_local_resource_error(exc: BaseException) -> bool:
    """True if this failure is OUR side running out of resources, not the peer answering.

    ConnectionRefused/Reset and timeouts are OSErrors too, but they are real answers about the
    worker -- only the local-exhaustion errnos mean we never got to ask."""
    # urllib's do_open does a BARE `raise URLError(err)`, which sets __context__ (not __cause__)
    # and stores the original in .reason. URLError is itself an OSError subclass but never calls
    # OSError.__init__, so its .errno is None -- meaning a __cause__-only lookup made this branch
    # UNREACHABLE through the real opener, and local fd exhaustion reaped whole fleets while the
    # guarding test passed against a bare OSError the opener never produces (issue #77 marla-loop 4).
    inner: BaseException = exc
    for _ in range(4):      # bounded: reason/cause/context chains are short and may self-reference
        if isinstance(inner, urllib.error.URLError) and isinstance(inner.reason, BaseException):
            inner = inner.reason
        elif inner.__cause__ is not None:
            inner = inner.__cause__
        elif inner.__context__ is not None and inner.__context__ is not inner:
            inner = inner.__context__
        else:
            break
        if isinstance(inner, OSError) and inner.errno is not None:
            break
    # A RESOLVER failure is its own namespace: socket.gaierror carries EAI_* codes (typically
    # NEGATIVE) which are not errno values at all, so an errno allowlist silently never matched them.
    # Failing to look a name up says nothing about the worker's health -- and one resolver outage
    # hits every hostname-based worker on the same tick, which is the fleet-wipe shape (upstream P1).
    if isinstance(inner, socket.gaierror):
        # Only TEMPORARY resolver failures are "we could not ask". A definitive NXDOMAIN
        # (EAI_NONAME/EAI_NODATA) says the name does not resolve -- for an existing worker that is a
        # real reachability verdict, and treating it as unknown left the slot IDLE and "healthy"
        # for the whole 300s grace while every claim skipped it, when capacity used to be replaced
        # at once (upstream P2). Blanket-unknown was my over-correction.
        return inner.errno in _TRANSIENT_RESOLVER_ERRORS
    return isinstance(inner, OSError) and inner.errno in (
        errno.EMFILE,    # process fd table full
        errno.ENFILE,    # system-wide fd table full
        errno.ENOMEM,    # cannot allocate for the socket
        errno.ENOBUFS,
        errno.EADDRNOTAVAIL,  # ephemeral ports exhausted -- purely LOCAL, and it hits every worker
                              # on the same tick, which is the fleet-wipe shape exactly
        errno.ENETUNREACH,    # no route from THIS host: our networking, not the worker's health
        errno.EINPROGRESS,    # non-blocking connect in flight -- we never waited for an answer
        errno.EAGAIN,         # (== EWOULDBLOCK) same: no answer was ever collected
    )
    # Deliberately NOT here -- these ARE answers about the worker: ETIMEDOUT (it did not respond in
    # time), ECONNREFUSED / ECONNRESET (nothing is listening / it hung up), EHOSTUNREACH (the host
    # itself is unreachable, which for a warm worker is indistinguishable from being down).


def _default_http_probe(url: str, headers: dict[str, str], timeout: float) -> "bool | None":
    """GET ``url`` with ``headers``. True iff a 2xx comes back within ``timeout``; False if the box
    ANSWERED otherwise (non-2xx, refused, reset, timed out); None if we could not even ask because
    the LOCAL side ran out of resources (issue #77 marla-loop 3)."""
    from blastbox.host.runtime.remote_http import _default_open   # no-redirect opener (no import cycle)
    req = urllib.request.Request(url, headers=headers, method="GET")  # noqa: S310 (url is host-built)
    try:
        # NEVER follow a worker-chosen 3xx on /healthz: it would re-send X-aws-proxy-auth (the shared
        # EC2/static agent_token, or a Lambda JWE) to the Location + SSRF-GET, and a 2xx there would
        # falsely mark the slot READY. A redirect -> HTTPError -> not-ready (False) below.
        with _default_open(req, timeout) as resp:
            return 200 <= resp.status < 300
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        # Distinguish "the box gave us an answer" from "we could not even ASK". A refusal, reset or
        # timeout IS a verdict about the worker. Local resource exhaustion is not: it is the HOST
        # failing, it hits every worker on the same tick, and reading it as death evicts the whole
        # fleet in one health pass (issue #77 marla-loop 3 -- reproduced: one _health_check tick
        # evicted a 2-box fleet). Callers that want a plain bool coerce with `is True`.
        if _is_local_resource_error(exc):
            return None
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

    # SHORT bound for the claim-time hand-out probe (issue #77). That probe sits directly on
    # job-dispatch latency and holds the dispatcher's warm-gate reservation (#72), so waiting the
    # full cli_timeout_s on a control-plane brownout stalls dispatch. On timeout the probe reports
    # UNKNOWN (AwsProbeTimeout -> None), never "dead", so the pool skips the slot instead of
    # destroying a possibly-healthy worker. DECLARED LAST so adding it can't silently rebind a
    # positional caller's later fields.
    claim_probe_timeout_s: float = dc_field(default=5.0, kw_only=True)
    # Background/health describe budget. Generous (not on dispatch latency) but finite, so a
    # brownout can't stall the tick thread for cli_timeout_s per IDLE slot.
    health_probe_timeout_s: float = dc_field(default=30.0, kw_only=True)

    def __post_init__(self) -> None:
        # issue #77: a mistyped 0/negative would make the probe deadline already-expired, so EVERY
        # claim reports UNKNOWN and no AWS slot is ever claimable — silently, tier green in metrics.
        # (0 used to mean "disable the bound"; it must not brick instead.) On the BASE so every tier
        # inherits it; subclasses with their own __post_init__ MUST chain to this.
        if self.claim_probe_timeout_s <= 0:
            object.__setattr__(self, "claim_probe_timeout_s", 5.0)
        if self.health_probe_timeout_s <= 0:
            object.__setattr__(self, "health_probe_timeout_s", 30.0)
        # Same class of brick, one floor below: _probe_timeout() DECLINES to probe under
        # _MIN_PROBE_S, so a configured probe_timeout_s beneath it would decline unconditionally and
        # no slot would ever become ready (issue #77 marla-loop 4). Guard it beside its siblings.
        if self.probe_timeout_s < _MIN_PROBE_S:
            object.__setattr__(self, "probe_timeout_s", _MIN_PROBE_S)

    def aws_argv(self, service: str, op: str, *args: str) -> list[str]:
        argv = ["aws", service, op, "--region", self.region, "--output", "json"]
        if self.profile:
            argv += ["--profile", self.profile]
        argv += list(args)
        return argv


@dataclass(frozen=True)
class LambdaMicroVmConfig(AwsWorkerConfig):
    # NOTE: image_identifier MUST be an in-account image ARN built via `create-microvm-image` (the
    # managed base arn:...:aws:microvm-image:al2023-1 is NOT directly runnable -- verified live:
    # "Image ARN must contain a valid customer account ID"). Build one from the base + a code artifact.
    image_identifier: str = ""
    execution_role_arn: str | None = None
    # run-microvm --{egress,ingress}-network-connectors are (list) args -> passed as separate tokens.
    # NOTE (live): omitting them DEFAULTS to INTERNET_EGRESS + HTTP_INGRESS -- NOT sealed. To restrict,
    # pass explicit connector ARNs (a no-internet egress connector to seal outbound).
    egress_connector_ids: tuple[str, ...] = ()
    ingress_connector_ids: tuple[str, ...] = ()
    auth_token_ttl_min: int = 15                 # create-microvm-auth-token --expiration-in-minutes
    # A Lambda MicroVM with NO egress connector gets DEFAULT public internet egress -- which silently
    # contradicts the engine's default net_policy='none'. Fail closed: refuse such a pool unless the
    # operator either supplies a (no-internet) egress connector or explicitly opts into internet here.
    allow_default_egress: bool = False

    def __post_init__(self) -> None:
        super().__post_init__()   # keep the base's probe-budget clamps (issue #77)
        # Clamp to the AWS bounds so a mistyped env can't turn every call into an opaque reject:
        # run-microvm --maximum-duration-in-seconds <= 28800 (8h); create-microvm-auth-token
        # --expiration-in-minutes in [1, 60]. (SnapStart's __post_init__ chains to this via super().)
        dur = min(28800, max(1, int(self.max_duration_s)))
        ttl = min(60, max(1, int(self.auth_token_ttl_min)))
        if (dur, ttl) != (self.max_duration_s, self.auth_token_ttl_min):
            _log.warning("lambda-microvm: clamped max_duration_s=%d auth_token_ttl_min=%d to AWS bounds",
                         dur, ttl)
        object.__setattr__(self, "max_duration_s", dur)
        object.__setattr__(self, "auth_token_ttl_min", ttl)

    @classmethod
    def from_env(cls, get: Callable[[str], str | None], **overrides: Any) -> LambdaMicroVmConfig:
        region = _env(get, "BLASTBOX_AWS_REGION") or _env(get, "AWS_REGION") or "us-east-1"

        def _idlist(key: str) -> tuple[str, ...]:
            return tuple(c.strip() for c in (_env(get, key) or "").split(",") if c.strip())

        return cls(
            region=region,
            profile=_env(get, "BLASTBOX_AWS_PROFILE"),
            agent_port=int(_env(get, "BLASTBOX_AWS_AGENT_PORT", "8765") or "8765"),
            image_identifier=_env(get, "BLASTBOX_LAMBDA_IMAGE") or "",
            execution_role_arn=_env(get, "BLASTBOX_LAMBDA_EXEC_ROLE_ARN"),
            egress_connector_ids=_idlist("BLASTBOX_LAMBDA_EGRESS_CONNECTORS"),
            ingress_connector_ids=_idlist("BLASTBOX_LAMBDA_INGRESS_CONNECTORS"),
            allow_default_egress=(_env(get, "BLASTBOX_LAMBDA_ALLOW_DEFAULT_EGRESS") or "").strip().lower()
                                 in ("1", "true", "yes", "on"),
            auth_token_ttl_min=int(_env(get, "BLASTBOX_LAMBDA_AUTH_TTL_MIN", "15") or "15"),
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
    allow_plaintext_public: bool = False   # opt out of the public-IP-requires-TLS fail-closed guard
    user_data_b64: str | None = None   # base64 cloud-init that brings up the worker agent on agent_port
    agent_token: str | None = None     # BLASTBOX_WORKER_AGENT_TOKEN baked into the AMI -> forwarded here
    self_terminate: bool = True        # inject a guest self-shutdown TTL so a leaked instance dies

    @classmethod
    def from_env(cls, get: Callable[[str], str | None], **overrides: Any) -> Ec2Config:
        region = _env(get, "BLASTBOX_AWS_REGION") or _env(get, "AWS_REGION") or "us-east-1"
        sgs = _env(get, "BLASTBOX_EC2_SECURITY_GROUPS")
        return cls(
            region=region,
            profile=_env(get, "BLASTBOX_AWS_PROFILE"),
            agent_port=int(_env(get, "BLASTBOX_AWS_AGENT_PORT", "8765") or "8765"),
            image_id=_env(get, "BLASTBOX_EC2_AMI") or "",
            agent_token=_env(get, "BLASTBOX_EC2_AGENT_TOKEN"),
            instance_type=_env(get, "BLASTBOX_EC2_INSTANCE_TYPE", "m7g.large") or "m7g.large",
            subnet_id=_env(get, "BLASTBOX_EC2_SUBNET_ID"),
            security_group_ids=tuple(s.strip() for s in (sgs or "").split(",") if s.strip()),
            iam_instance_profile=_env(get, "BLASTBOX_EC2_IAM_PROFILE"),
            key_name=_env(get, "BLASTBOX_EC2_KEY_NAME"),
            use_public_ip=(_env(get, "BLASTBOX_EC2_PUBLIC_IP") or "").strip().lower()
            in ("1", "true", "yes", "on"),
            allow_plaintext_public=(_env(get, "BLASTBOX_EC2_ALLOW_PLAINTEXT_PUBLIC") or "").strip().lower()
            in ("1", "true", "yes", "on"),
            user_data_b64=_env(get, "BLASTBOX_EC2_USER_DATA_B64"),
            self_terminate=(_env(get, "BLASTBOX_EC2_SELF_TERMINATE", "1") or "1").strip().lower()
            not in ("0", "false", "no", "off"),   # strip/lower so False/NO/Off actually disable the backstop
            max_duration_s=int(_env(get, "BLASTBOX_AWS_MAX_DURATION_S", "3600") or "3600"),
            **overrides,
        )


def _userdata_with_self_terminate(raw: str | None, max_duration_s: int, *, uptime: bool = False) -> str:
    """Wrap the operator's user-data (any cloud-init format) + a self-terminate part as MIME multipart,
    so a crashed dispatcher can't leak a running instance (needs shutdown-behavior=terminate, which the
    EC2 launch sets). The operator's part keeps its own cloud-init type.

    ``uptime=False`` (disposable EC2): schedule ``shutdown -h +minutes`` -- a WALL-CLOCK deadline, correct
    for an instance that never hibernates. ``uptime=True`` (ec2-hibernate): a wall-clock deadline would fire
    on RESUME after the clock jumped past it and kill a healthy warm slot; instead arm a ``systemd-run
    --on-active`` transient timer, whose CLOCK_MONOTONIC deadline does NOT advance while the instance is
    hibernated -- so it bounds cumulative RUNNING time (a leaked RUNNING instance self-terminates; a parked
    one never accrues the budget). It survives cloud-init exit (systemd owns the timer)."""
    from email import message_from_string
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    if uptime:
        seconds = max(1, int(max_duration_s))   # clamp: a misconfigured <=0 must still ARM the backstop,
        ttl_body = f"#!/bin/sh\nsystemd-run --on-active={seconds}s /sbin/shutdown -h now\n"
    else:
        minutes = max(1, -(-max_duration_s // 60))   # ceiling: never schedule the backstop BEFORE the budget
        ttl_body = f"#!/bin/sh\nshutdown -h +{minutes}\n"
    ttl = MIMEText(ttl_body, "x-shellscript")
    if raw and raw.strip():
        head = raw[:400].lower()
        # If the operator's user-data is ALREADY a MIME multipart cloud-init document, append the TTL
        # part to it -- wrapping the whole document as a single x-shellscript part (the old behavior)
        # would make cloud-init run it as one opaque script and lose its constituent parts.
        if not raw.lstrip().startswith("#") and ("mime-version:" in head or "multipart/" in head):
            outer = message_from_string(raw)
            if outer.is_multipart():
                outer.attach(ttl)
                return outer.as_string()
        # Preserve the operator part's cloud-init FORMAT (docstring's promise): map its leading header to
        # the right MIME subtype (cloud-init's INCLUSION_TYPES_MAP), most-specific prefix first. A bare
        # #!shebang or an unrecognized payload defaults to x-shellscript (today's behavior). Wrapping a
        # #cloud-boothook/#include/#part-handler as x-shellscript would make cloud-init mis-run it, so the
        # AMI's bootstrap never starts the agent and the slot never readies.
        _lead = raw.lstrip()
        _ci_types = (
            ("#include-once", "x-include-once-url"),
            ("#include", "x-include-url"),
            ("#cloud-config-archive", "cloud-config-archive"),
            ("#cloud-config-jsonp", "cloud-config-jsonp"),
            ("#cloud-config", "cloud-config"),
            ("#cloud-boothook", "cloud-boothook"),
            ("#part-handler", "part-handler"),
            ("#upstart-job", "upstart-job"),
        )
        subtype = next((st for pfx, st in _ci_types if _lead.startswith(pfx)), "x-shellscript")
        msg = MIMEMultipart()
        msg.attach(MIMEText(raw, subtype))
        msg.attach(ttl)
        return msg.as_string()
    msg = MIMEMultipart()
    msg.attach(ttl)
    return msg.as_string()


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
    token_minted_at: float = 0.0         # for TTL-based JWE refresh (lambda)

    @property
    def endpoint(self) -> tuple[str, int] | None:
        """(host, port) the engine transport connects to, or None until running."""
        if self.ip is not None:
            return (self.ip, self.agent_port)
        return None


# ---------------------------------------------------------------------------
# Base runtime
# ---------------------------------------------------------------------------

# EC2 instance tag keys. blastbox-slot = per-slot id (existing); blastbox-tier lets the
# hibernate orphan sweep filter precisely (never touches disposable/lambda); blastbox-run is
# the sweep's per-dispatcher-process ownership fence.
_TAG_SLOT = "blastbox-slot"
_TAG_TIER = "blastbox-tier"
_TAG_RUN = "blastbox-run"


class AwsDisposableRuntime:
    """Shared machinery for AWS disposable-worker tiers. Concrete tiers implement the four hooks
    ``_launch`` / ``_health_ok`` / ``_running`` / ``_terminate``; this base wires them into the
    ``SlotRuntime`` protocol + the injectable aws-cli / http-probe seams. Disposable by design (no
    ``recycle`` -> one job per slot)."""

    kind = "aws"
    dispatch_style = "network"   # driven over http_agent + remote_http (VmJobDispatcher), not file-handshake
    _liveness_cache_s = 5.0      # cache is_alive() so a 0.1s pool tick doesn't spam the AWS describe API

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
        self._live_cache: dict[str, tuple[float, bool | None]] = {}   # None = UNKNOWN verdict
        # Per-THREAD aws-cli budget override, set only for the duration of a claim probe (issue
        # #77). Thread-local so the background tick's concurrent calls keep the full cli_timeout_s.
        self._tls = threading.local()
        self._mint_fail_at: dict[str, float] = {}   # slot_id -> last failed-token-mint time (throttle)
        self._mint_fail_exc: dict[str, Exception] = {}   # ... and WHY, so the back-off stays honest
        # cache the READINESS get-microvm/describe-instances too (is_ready is polled ~10Hz during WARMING,
        # and its endpoint-resolution describe is uncached) so a booting slot doesn't spam the control plane.
        self._desc_cache: dict[str, tuple[float, dict[str, Any]]] = {}
        # Per-PROCESS ownership fence for the aws-ec2-hibernate orphan sweep. A leaked STOPPED slot
        # from a CRASHED dispatcher isn't bounded by the guest uptime timer (it's frozen while
        # hibernated), so sweep_orphans() reclaims stopped slots NOT carrying this id. Deliberately
        # fresh per process (not env-overridable): a restarted dispatcher gets a new id, so its
        # predecessor's parked slots correctly read as orphans; a stable id would make them look
        # "ours" and never be swept.
        self._run_id = uuid.uuid4().hex[:16]

    def _describe_cached(self, slot: "AwsWorkerSlot", ttl: float) -> dict[str, Any]:
        now = self._clock()
        cached = self._desc_cache.get(slot.slot_id)
        if cached is not None and (now - cached[0]) < ttl:
            return cached[1]
        desc = self._describe(slot)
        self._desc_cache[slot.slot_id] = (now, desc)
        return desc

    def _describe(self, slot: "AwsWorkerSlot") -> dict[str, Any]:   # concrete tiers override
        raise NotImplementedError

    @property
    def readiness_timeout_s(self) -> float:
        """The budget a slot needs to become ready (EC2 first boot often >2min). The warm pool reads
        this to size its warming timeout so a healthy-but-slow cloud slot isn't evicted + churned."""
        return float(self.cfg.ready_timeout_s)

    # -- aws cli seam -------------------------------------------------------
    @contextlib.contextmanager
    def _health_probe_budget(self):
        """Bound the BACKGROUND liveness describe (issue #77). It runs on the single tick thread, so
        an unbounded call per IDLE slot stalls promotion, spawn-to-deficit, deferred reaping and
        metrics for the whole pool. More generous than the claim budget — this is not on dispatch
        latency — but finite."""
        prev = getattr(self._tls, "probe_deadline", None)
        self._tls.probe_deadline = self._clock() + self.cfg.health_probe_timeout_s
        try:
            yield
        finally:
            self._tls.probe_deadline = prev

    @contextlib.contextmanager
    def _call_budget(self, seconds: float):
        """Bound EVERY aws call made on this thread inside the block to ``seconds`` total.

        resume()'s budget_s used to gate only the loop's admission check, so the calls INSIDE it
        still ran at cli_timeout_s: with 0.5s of claim window left, one describe could block for
        120s, blowing the claim contract and starving the healthy slots behind it (issue #77
        round 6). Never EXTENDS an outer scope."""
        prev = getattr(self._tls, "probe_deadline", None)
        deadline = self._clock() + max(0.0, seconds)
        self._tls.probe_deadline = deadline if prev is None else min(prev, deadline)
        try:
            yield
        finally:
            self._tls.probe_deadline = prev

    def _probe_timeout(self) -> "float | None":
        """The agent-probe timeout, clamped to whatever call budget is in scope on this thread.

        _call_budget bounds the aws SUBPROCESS calls through a thread-local deadline that ``_aws``
        reads, but the HTTP probe is not an aws call and was handed a flat probe_timeout_s -- so it
        sailed straight past the window and could block for its full timeout with the claim already
        nearly exhausted (issue #77 marla-loop 3)."""
        timeout = float(self.cfg.probe_timeout_s)
        deadline = getattr(self._tls, "probe_deadline", None)
        if deadline is not None:
            timeout = min(timeout, max(0.0, deadline - self._clock()))
        if timeout < _MIN_PROBE_S:
            # None = "there is not enough window left to ask meaningfully". Do NOT hand a zero (or
            # near-zero) timeout to the socket layer: zero is not "fail fast", it switches the
            # socket to NON-BLOCKING, so connect raises BlockingIOError(EINPROGRESS) at once. That
            # errno is not local exhaustion, so it read as "the box answered no" and became evidence
            # against a worker we never actually asked (issue #77 marla-loop 4). A near-zero timeout
            # is just as bad: a perfectly healthy agent would "time out" and be convicted.
            return None
        return timeout

    @contextlib.contextmanager
    def _claim_probe_budget(self, budget_s: float | None = None):
        """Apply the SHORT claim-probe budget to every aws call made on THIS thread inside the
        block (issue #77). Save/restore rather than clear: a subclass override wraps its whole body
        and calls super() inside it, so a hard reset would drop the outer scope's budget and let the
        rest of the probe (e.g. the JWE re-mint) run at the full cli_timeout_s.

        ``budget_s`` is what the CALLER has left on its own claim deadline. The runtime's configured
        bound is a CEILING, not an entitlement: claim(timeout_s=0.5) against claim_probe_timeout_s=5
        otherwise blocked ~5s — a 10x contract violation that also pinned the dispatcher's warm-gate
        reservation for the overrun. Take the smaller of the two. A nested scope never EXTENDS an
        outer one either, for the same reason."""
        bound = self.cfg.claim_probe_timeout_s
        if budget_s is not None:
            bound = min(bound, max(0.0, float(budget_s)))
        prev = getattr(self._tls, "probe_deadline", None)
        deadline = self._clock() + bound
        self._tls.probe_deadline = deadline if prev is None else min(prev, deadline)
        try:
            yield
        finally:
            self._tls.probe_deadline = prev

    def _aws(self, service: str, op: str, *args: str,
             timeout_s: float | None = None) -> dict[str, Any]:
        argv = self.cfg.aws_argv(service, op, *args)
        # A claim-probe budget set by is_alive_for_claim on THIS thread wins over the default. It is
        # thread-local on purpose: the background tick calls _aws concurrently and must keep the full
        # cli_timeout_s (a slow terminate is not a dispatch-latency problem). See issue #77.
        # A claim probe is bounded AS A WHOLE, not per call: a describe at 4.9s followed by a token
        # mint at 4.9s would otherwise blow a claim(timeout_s=2) contract by ~5x while holding the
        # warm-gate reservation. Each call gets only what's left of the probe's deadline.
        probe_deadline = getattr(self._tls, "probe_deadline", None)
        if timeout_s is None and probe_deadline is not None:
            remaining = probe_deadline - self._clock()
            if remaining <= 0:
                raise AwsProbeTimeout(f"aws {service} {op}: claim probe budget exhausted")
            timeout_s = min(remaining, self.cfg.cli_timeout_s)
        budget = self.cfg.cli_timeout_s if timeout_s is None else timeout_s
        try:
            cp = self._run_aws(argv, budget)
        except OSError as exc:
            # The HOST could not even start the aws process (EMFILE, ENOMEM on fork, the binary
            # briefly absent mid-`pip install -U awscli`). That says nothing whatsoever about the
            # worker, and it is maximally CORRELATED -- every slot and every thread hits it at once,
            # so collapsing it to "dead" wipes the tier (issue #77 marla-loop).
            raise AwsUnknownState(f"aws {service} {op}: cannot execute ({exc})") from exc
        except subprocess.TimeoutExpired as exc:
            # UNKNOWN in every scope (issue #77 round 2): a timeout means the control plane never
            # answered. Outside a probe this used to be a plain AwsWorkerError, and resume()'s
            # caller — which string-matches transient markers, none of which cover "timed out" —
            # read it as a dead worker and terminated a healthy warm slot.
            raise AwsProbeTimeout(f"aws {service} {op}: timed out after {budget}s") from exc
        if cp.returncode != 0:
            stderr = (cp.stderr or "").strip()
            # Inside a claim/health probe, a TRANSIENT control-plane answer is UNKNOWN, not failure:
            # otherwise a throttle (which exits 255, never TimeoutExpired) is read as a dead worker
            # and the slot is terminated — the most likely brownout of all (issue #77).
            if _is_confirmed_dead_aws_error(stderr):
                raise AwsWorkerError(f"aws {service} {op} failed (rc={cp.returncode}): {stderr[:400]}")
            # DEFAULT: we did not get a confirmed answer, so we do not have one. Never death.
            raise AwsUnknownState(
                f"aws {service} {op}: unconfirmed failure (rc={cp.returncode}): {stderr[:200]}")
        out = (cp.stdout or "").strip()
        if not out:
            return {}
        try:
            return json.loads(out)
        except json.JSONDecodeError as exc:
            # We could not PARSE the answer -- a truncated pipe, a CLI upgraded mid-flight, a
            # proxy's error page. That is not the worker telling us it is gone, and whatever caused
            # it applies to every call on this host at once (upstream P2).
            raise AwsUnknownState(f"aws {service} {op}: unparseable response") from exc

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
            # "could not ask" is not-ready-yet here; the pool retries next tick. Only resume() and
            # the liveness paths care about the difference (issue #77 marla-loop 3).
            return self._health_ok(slot) is True
        except (AwsWorkerError, OSError) as exc:
            _log.debug("%s: is_ready(%s) probe error: %s", self.kind, slot.slot_id, exc)
            return False

    def is_alive(self, slot: AwsWorkerSlot) -> "bool | None":
        # cache for _liveness_cache_s so the pool's fast tick (~0.1s) doesn't issue an AWS describe per
        # tick per slot.
        now = self._clock()
        cached = self._live_cache.get(slot.slot_id)
        if cached is not None and (now - cached[0]) < self._liveness_cache_s:
            return cached[1]
        try:
            with self._health_probe_budget():
                alive = self._running(slot)
        except AwsUnknownState:
            # The control plane didn't answer in time. NOT evidence of death (issue #77): returning
            # False here makes _health_check evict + reap the slot, which would destroy exactly the
            # workers the UNKNOWN claim path just spared — the whole tier, one tick into a brownout.
            # Keep the last known state (default: alive); the claim-time FRESH probe is the gate that
            # decides hand-out, and a genuinely dead slot is caught there or at detonate.
            # Report UNKNOWN to the POOL rather than masking it as the last-known value. Masking
            # made the pool believe the slot was fine, so it could never apply its own policy --
            # and with no escalation anywhere a slot stayed unclaimable-but-alive forever, wedging
            # the tier at zero capacity. Cache the verdict too: returning early skipped the
            # _live_cache write, so the tick re-probed every IDLE slot at ~10Hz for the whole
            # brownout (measured: 20 aws invocations where 1 was expected).
            _log.warning("aws.health_probe_unknown slot_id=%s — reporting UNKNOWN to the pool",
                         slot.slot_id)
            # Stamped at COMPLETION: a probe that stalled longer than _liveness_cache_s would
            # otherwise be written already-expired, so the next tick re-probes immediately and the
            # sole tick thread burns health_probe_timeout_s per idle slot for the whole outage
            # (upstream P2).
            self._live_cache[slot.slot_id] = (self._clock(), None)
            return None
        except (AwsWorkerError, OSError):
            alive = False
        self._live_cache[slot.slot_id] = (now, alive)
        return alive

    def is_alive_for_claim(self, slot: AwsWorkerSlot, *, budget_s: float | None = None) -> "bool | None":
        """Claim-time hand-out check: BYPASS the liveness cache. A slot seen alive by a background health
        tick may have been terminated by AWS since (SnapStart idle-policy auto-terminate, spot reclaim,
        hibernate expiry), and the cached ``is_alive()`` would still hand it to a user job -- whose remote
        POST then FAILS the job instead of the pool dropping the dead slot + trying another/requeuing.
        Force a fresh describe here (dropping the describe cache too, since a tier's ``_running`` may read
        it); the ~5s cache still throttles the background ~10Hz poll. The pool calls this at claim iff the
        runtime provides it (optional protocol method; file/libvirt tiers fall back to ``is_alive``)."""
        now = self._clock()
        self._desc_cache.pop(slot.slot_id, None)   # force a fresh get-instance/get-microvm this call
        # Bound the describe to the claim-probe budget (issue #77): this call is on job-dispatch
        # latency and holds the dispatcher's warm-gate reservation, so it must not wait out the full
        # cli_timeout_s during a control-plane brownout. A timeout raises AwsWorkerError -> "not
        # alive" here, and the POOL treats an over-budget probe non-destructively (skips the slot).
        with self._claim_probe_budget(budget_s):
            try:
                alive = self._running(slot)
            except AwsUnknownState:
                # The control plane didn't answer inside the claim budget. UNKNOWN, not dead: the
                # pool skips this slot (non-destructively) instead of reaping a healthy worker.
                _log.warning("aws.claim_probe_timeout slot_id=%s — treating as unknown",
                             slot.slot_id)
                return None
            except (AwsWorkerError, OSError):
                alive = False
        self._live_cache[slot.slot_id] = (now, alive)   # keep the background-tick cache coherent
        return alive

    def reap(self, slot: AwsWorkerSlot) -> None:
        self._live_cache.pop(slot.slot_id, None)
        self._desc_cache.pop(slot.slot_id, None)
        self._mint_fail_at.pop(slot.slot_id, None)
        self._mint_fail_exc.pop(slot.slot_id, None)
        if slot.resource_id is None:
            return
        self._terminate(slot)
        _log.info("%s: reaped slot=%s resource=%s", self.kind, slot.slot_id, slot.resource_id)

    # -- hooks (subclass) ---------------------------------------------------
    def _launch(self) -> AwsWorkerSlot:
        raise NotImplementedError

    def _health_ok(self, slot: AwsWorkerSlot) -> "bool | None":
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
        # Fail closed on the fail-OPEN default: no egress connector => AWS gives the MicroVM public
        # internet, but the dispatcher treats the pool as honoring the engine's net_policy (often
        # 'none'). Refuse unless a connector seals egress OR the operator explicitly accepts internet.
        if not cfg.egress_connector_ids and not cfg.allow_default_egress:
            raise AwsUnavailable(
                "aws-lambda-microvm has NO egress connector -> AWS defaults to public internet egress, "
                "which contradicts a no-egress net_policy. Set BLASTBOX_LAMBDA_EGRESS_CONNECTORS to a "
                "no-internet connector, or BLASTBOX_LAMBDA_ALLOW_DEFAULT_EGRESS=1 to accept internet egress."
            )
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
            args += ["--egress-network-connectors", *self.cfg.egress_connector_ids]
        if self.cfg.ingress_connector_ids:
            args += ["--ingress-network-connectors", *self.cfg.ingress_connector_ids]
        args += self._extra_run_args()   # subclass hook (e.g. SnapStart --idle-policy)
        resp = self._aws("lambda-microvms", "run-microvm", *args)
        rid = resp.get("microvmId") or resp.get("MicrovmId") or resp.get("id")
        if not rid:
            raise AwsWorkerError("run-microvm: no microvm id in response")
        return AwsWorkerSlot(slot_id=sid, resource_id=str(rid), state=SlotState.WARMING)

    def _extra_run_args(self) -> list[str]:
        """Extra `run-microvm` args a subclass appends (base: none). SnapStart adds `--idle-policy`."""
        return []

    def _describe(self, slot: AwsWorkerSlot) -> dict[str, Any]:
        return self._aws("lambda-microvms", "get-microvm", "--microvm-identifier", str(slot.resource_id))

    def _running(self, slot: AwsWorkerSlot) -> bool:
        st = str(self._describe(slot).get("state", "")).lower()
        return st in ("running", "active", "ready")

    def _mint_token(self, slot: AwsWorkerSlot) -> str:
        # minted fresh at probe/detonation time with a short TTL + scoped to the agent port (both
        # required by the API) -- a token minted at spawn could expire before a warm slot's job.
        resp = self._aws("lambda-microvms", "create-microvm-auth-token",
                         "--microvm-identifier", str(slot.resource_id),
                         "--expiration-in-minutes", str(self.cfg.auth_token_ttl_min),
                         "--allowed-ports", f"port={self.cfg.agent_port}")  # tagged-union list shorthand
        tok = resp.get("authToken") or resp.get("token") or resp.get("Token")
        # The live `aws` CLI returned a bare JWE string (validated end-to-end: /healthz 200 with this as
        # the X-aws-proxy-auth header). The API reference models authToken as a header-name -> value MAP,
        # so also handle that shape -- extract the X-aws-proxy-auth value (fall back to the sole value) --
        # rather than str()-ing a dict into a "{...}" header that would 403 every Lambda slot.
        if isinstance(tok, dict):
            tok = tok.get("X-aws-proxy-auth") or (next(iter(tok.values())) if len(tok) == 1 else None)
        if not isinstance(tok, str) or not tok:
            raise AwsWorkerError("create-microvm-auth-token: no usable token in response")
        return tok

    def _ensure_token(self, slot: AwsWorkerSlot) -> str:
        """Reuse the slot's JWE while it's younger than half its TTL; mint a fresh one only when it's
        missing or aging. WarmPool polls is_ready()/is_alive() every ~0.1s -- minting per tick would
        spam create-microvm-auth-token and throttle the AWS control plane before the slot warms."""
        half_ttl = self.cfg.auth_token_ttl_min * 60 * 0.5
        if slot.auth_token and (self._clock() - slot.token_minted_at) <= half_ttl:
            return slot.auth_token
        slot.auth_token = self._mint_token(slot)
        slot.token_minted_at = self._clock()
        return slot.auth_token

    def _health_ok(self, slot: AwsWorkerSlot) -> "bool | None":
        # Resolve the per-VM URL once the microVM is running, then probe the agent with a fresh JWE.
        if slot.url is None:
            desc = self._describe_cached(slot, self._liveness_cache_s)   # throttle the ~10Hz warming poll
            if str(desc.get("state", "")).lower() not in ("running", "active", "ready"):
                return False
            # live: get-microvm returns the per-VM host under `endpoint` (a bare hostname, no scheme)
            ep = desc.get("endpoint") or desc.get("url") or desc.get("endpointUrl")
            if not ep:
                return False
            slot.url = str(ep) if str(ep).startswith("http") else f"https://{ep}"
        token = self._ensure_token(slot)   # reuse a fresh token across rapid readiness ticks
        url = slot.url.rstrip("/") + self.cfg.agent_health_path
        headers = {"X-aws-proxy-auth": token, "X-aws-proxy-port": str(self.cfg.agent_port)}
        _t = self._probe_timeout()
        return None if _t is None else self._probe(url, headers, _t)

    def is_alive(self, slot: AwsWorkerSlot) -> "bool | None":
        """Refresh the JWE past half its TTL so an IDLE warm slot's token can't expire before its job
        (the transport reuses ``slot.auth_token`` for /detonate without re-minting)."""
        with self._health_probe_budget():
            alive = super().is_alive(slot)
            if alive and slot.auth_token:
            # The base's health-probe scope ends when super() returns, so this mint ran at the full
            # cli_timeout_s (120s) instead of health_probe_timeout_s — on the SINGLE pool tick
            # thread, stalling promotion/reaping/metrics for minutes across a slow-mint brownout.
            # is_alive_for_claim already holds its budget across the whole probe for this exact
            # reason (issue #77); the health path needs the same treatment.
                # NB inside the SAME budget as the describe above, not a fresh one: opening a
                # second full window let one is_alive() occupy the sole tick thread for nearly
                # twice health_probe_timeout_s, multiplied across idle slots (upstream P2).
                try:
                    self._ensure_token(slot)   # refresh only past half-TTL (cached otherwise)
                except (AwsWorkerError, OSError):
                    pass   # best-effort; a real failure surfaces at readiness/detonate
        return alive

    def is_alive_for_claim(self, slot: AwsWorkerSlot, *, budget_s: float | None = None) -> "bool | None":
        """The claim-time fresh check bypasses is_alive(), which is where the JWE is refreshed -- so also
        re-mint here past half-TTL, else a slot the background tick hasn't refreshed recently (scheduler/
        process pause, long tick gap) is handed out with a near/already-expired token and /detonate 403s a
        healthy worker. Refreshing at hand-out guarantees >= half-TTL remaining for the job about to run.

        Unlike the background is_alive() (best-effort refresh, don't reap a healthy IDLE slot on a transient
        mint blip), a CLAIM-time mint failure means we'd hand /detonate a token we KNOW can't be refreshed
        -> guaranteed 403 -> FAIL the check so the pool drops this slot and tries another / requeues."""
        # Hold the claim-probe budget across the WHOLE probe — the describe AND the JWE re-mint
        # below (issue #77): the base's scope ends when super() returns, so without this the mint
        # ran at the full cli_timeout_s on the claim path, which is what #77 exists to prevent.
        with self._claim_probe_budget(budget_s):
            alive = super().is_alive_for_claim(slot, budget_s=budget_s)
            if alive and slot.auth_token:
                try:
                    self._ensure_token(slot)
                except AwsUnknownState:
                    # The MINT hit the claim budget (control-plane brownout), which says nothing
                    # about this worker's health. UNKNOWN, not unusable: the pool skips the slot
                    # this scan instead of destroying it (issue #77). Listed before the generic
                    # handler below, which stays the "token really can't be refreshed" case.
                    _log.warning("aws.claim_mint_timeout slot_id=%s — treating as unknown",
                                 slot.slot_id)
                    return None
                except (AwsWorkerError, OSError):
                    return False   # un-refreshable token at hand-out -> unusable slot (not a silent 403)
            return alive

    def _terminate(self, slot: AwsWorkerSlot) -> None:
        self._aws("lambda-microvms", "terminate-microvm", "--microvm-identifier", str(slot.resource_id))


def _inject_tls(getter: Callable[[str], str | None], kw: dict[str, Any]) -> dict[str, Any]:
    """If BLASTBOX_DISPATCH_TLS_CA is set (and not already overridden), add the client (m)TLS context +
    a TLS-aware health probe so an https worker agent is probed + talked to over mTLS."""
    from blastbox.host.runtime.remote_http import dispatch_ssl_context_from_env, make_tls_probe
    if "ssl_context" in kw:
        # a caller-supplied context still needs a MATCHING mTLS probe, else _health_ok probes the https
        # worker with the non-mTLS _default_http_probe (no client cert / private CA) and it never readies.
        if kw["ssl_context"] is not None:
            kw.setdefault("http_probe", make_tls_probe(kw["ssl_context"]))
        return kw
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
    # NOTE: no _inject_tls here -- the Lambda tier talks to AWS's per-VM PUBLIC https endpoint + a JWE,
    # so it must use the public trust roots (default context), NOT the private worker-mTLS CA (which is
    # only for self-hosted EC2/static agents). Pinning the worker CA here would break AWS TLS.
    rt = LambdaMicroVmRuntime(cfg, **kw)
    if require_available and not rt.available():
        raise AwsUnavailable("aws-lambda-microvm tier unavailable (creds/entitlement/service probe failed)")
    return rt


# ---------------------------------------------------------------------------
# Lambda MicroVM WARM (SnapStart) tier — suspend/resume, per-microvm
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LambdaSnapStartConfig(LambdaMicroVmConfig):
    # AWS lambda-microvms has NO snapshot-template/fan-out -- only per-microvm suspend/resume. So each
    # warm slot is individually booted+warmed (the agent runs engine.warmup() before serving /healthz,
    # so a healthy endpoint == warm) then PARKED by the platform idle-policy, resumed per job, and
    # TERMINATED after one (untrusted) job. The idle-policy is the platform-native warm controller.
    max_idle_duration_s: int = 120       # idle time (running, billing) before AWS auto-suspends a warm slot
    suspended_duration_s: int = 3600     # how long a PARKED slot persists before AWS auto-terminates it
    auto_resume: bool = True             # wake on inbound traffic (belt-and-braces with explicit resume)
    resume_timeout_s: float = 60.0       # budget for resume-microvm + /healthz to answer on claim
    resume_poll_s: float = 1.0           # health re-probe interval while a resumed slot settles

    def __post_init__(self) -> None:
        super().__post_init__()   # base clamps max_duration_s + auth_token_ttl_min
        # Clamp the AWS run-microvm --idle-policy bounds so a mistyped env value can't turn every spawn
        # into an opaque per-slot AWS reject (silent fail-never-warm): maxIdleDurationSeconds >= 60,
        # suspendedDurationSeconds >= 0.
        idle = max(60, int(self.max_idle_duration_s))
        susp = max(0, int(self.suspended_duration_s))
        if (idle, susp) != (self.max_idle_duration_s, self.suspended_duration_s):
            _log.warning("snapstart: clamped idle-policy to AWS bounds (idle=%ds suspended=%ds)", idle, susp)
        object.__setattr__(self, "max_idle_duration_s", idle)
        object.__setattr__(self, "suspended_duration_s", susp)

    @classmethod
    def from_env(cls, get: Callable[[str], str | None], **overrides: Any) -> LambdaSnapStartConfig:
        import dataclasses
        base = LambdaMicroVmConfig.from_env(get)
        fields = {f.name: getattr(base, f.name) for f in dataclasses.fields(LambdaMicroVmConfig)}
        fields.update(
            max_idle_duration_s=int(_env(get, "BLASTBOX_LAMBDA_SNAPSTART_IDLE_S", "120") or "120"),
            suspended_duration_s=int(_env(get, "BLASTBOX_LAMBDA_SNAPSTART_SUSPENDED_TTL_S", "3600") or "3600"),
            auto_resume=(_env(get, "BLASTBOX_LAMBDA_SNAPSTART_AUTO_RESUME", "1") or "1").strip().lower()
                        not in ("0", "false", "no", "off"),   # "off" must disable too (parity w/ self_terminate)
            resume_timeout_s=float(_env(get, "BLASTBOX_LAMBDA_SNAPSTART_RESUME_TIMEOUT_S", "60") or "60"),
            resume_poll_s=float(_env(get, "BLASTBOX_LAMBDA_SNAPSTART_RESUME_POLL_S", "1") or "1"),
        )
        fields.update(overrides)   # caller overrides win last, no duplicate-keyword collision
        return cls(**fields)


class LambdaSnapStartRuntime(LambdaMicroVmRuntime):
    """WARM Lambda MicroVM tier: pay the boot + engine warmup ONCE per slot in the background, let the
    platform park it (idle-policy suspend), then RESUME it per job (sub-second, JVM/soffice already warm)
    and TERMINATE after one untrusted job. Disposable-warm — never reuses a slot across jobs.

    vs the disposable ``aws-lambda-microvm`` tier this only: (1) runs each microVM with an ``--idle-policy``
    so AWS auto-suspends idle warm slots + auto-resumes on traffic; (2) treats SUSPENDED/SUSPENDING/PENDING
    as ALIVE (else the pool health-check reaps parked slots); (3) exposes a ``resume(slot)`` hook the
    dispatcher calls on claim to wake + re-token + health-gate the slot BEFORE the job POSTs (the transport
    POSTs with no retry, so a not-yet-awake endpoint would lose the job). Everything else inherits."""

    kind = "aws-lambda-snapstart"
    _DEAD_STATES = ("terminating", "terminated")
    # WHITELIST of states that count as alive (fail-CLOSED on empty/unknown/future states -- liveness
    # must be probe-decided, and an unrecognized get-microvm state should reap, not linger IDLE). Include
    # the base Lambda runtime's running aliases (active/ready) so a MicroVM the base considers alive
    # isn't reaped by the SnapStart health check, plus the parked (suspended) states.
    _ALIVE_STATES = ("pending", "running", "active", "ready", "suspending", "suspended")
    # Deliberately NARROWER than _ALIVE_STATES: a parked (suspended) or still-booting (pending) slot
    # is alive but NOT expected to serve, so a failing agent probe against one proves nothing. Only
    # these states make "the VM is up but its agent is dead" a confirmed verdict (issue #77 round 5).
    _RUNNING_STATES = ("running", "active", "ready")

    def __init__(self, cfg: LambdaSnapStartConfig, **kw: Any) -> None:
        super().__init__(cfg, **kw)   # inherits the image-required + fail-closed egress guards + _desc_cache
        self.cfg: LambdaSnapStartConfig = cfg

    def _extra_run_args(self) -> list[str]:
        import json
        policy = {
            "maxIdleDurationSeconds": self.cfg.max_idle_duration_s,
            "suspendedDurationSeconds": self.cfg.suspended_duration_s,
            "autoResumeEnabled": self.cfg.auto_resume,
        }
        return ["--idle-policy", json.dumps(policy)]

    def _state(self, slot: AwsWorkerSlot) -> str:
        return str(self._describe(slot).get("state", "")).lower()   # UNCACHED: resume needs current state

    def _resolve_url(self, slot: AwsWorkerSlot) -> None:
        """Populate slot.url from get-microvm's endpoint if not already set. Unlike the base _health_ok
        (which only reads the endpoint when RUNNING), the microVM endpoint is a STABLE property available
        at any state -- so a parked/suspended slot can still be addressed once resumed. Uses the readiness
        describe cache so the warming poll doesn't issue a get-microvm per tick."""
        if slot.url is not None:
            return
        desc = self._describe_cached(slot, self._liveness_cache_s)
        ep = desc.get("endpoint") or desc.get("url") or desc.get("endpointUrl")
        if ep:
            slot.url = str(ep) if str(ep).startswith("http") else f"https://{ep}"

    def _running(self, slot: AwsWorkerSlot) -> bool:
        # A PARKED (suspended) warm slot is ALIVE -- the base _running (running/active/ready only) would
        # make is_alive() False for a suspended slot and the pool's per-tick health-check would reap every
        # parked slot. WHITELIST the known-alive states (empty/unknown -> not alive -> reaped). A
        # get-microvm error (microvm gone) still raises -> is_alive() catches -> False -> reaped.
        return self._state(slot) in self._ALIVE_STATES

    def _health_ok(self, slot: AwsWorkerSlot) -> "bool | None":
        # SnapStart-specific: resolve the STABLE endpoint independent of state (a parked slot is
        # addressable) via the cached describe, then mint+probe. The base _health_ok gates URL resolution
        # on state==running and does an UNCACHED get-microvm per call -- both wrong for a parked warm slot.
        self._resolve_url(slot)
        if slot.url is None:
            return False
        # THROTTLE re-minting after a failed mint: AWS can surface the stable endpoint while the microVM is
        # still pending, but create-microvm-auth-token needs a RUNNING VM -> it fails. Without this the
        # ~10Hz WARMING readiness poll would re-mint (and fail) every tick, storming the control plane. Skip
        # a re-mint within one throttle window of the last failure; the probe stays the readiness gate.
        # back off after ANY failed mint, not just a first (tokenless) one: a slot with an aged cached
        # token that _ensure_token re-mints past half-TTL can also hit a rejecting (suspended/never-ready)
        # AWS and would otherwise storm the mint API every tick. Skip re-minting + probing within the window.
        throttle = max(self.cfg.resume_poll_s, 1.0)
        if (self._clock() - self._mint_fail_at.get(slot.slot_id, -1e18)) < throttle:
            # We are deliberately NOT retrying the mint right now, so this pass learns nothing. If
            # the failure we are backing off from was UNCONFIRMED, our knowledge is still
            # "unknown" — returning a bare False here would let the caller record a clean pass and
            # conclude the worker is dead purely because we declined to ask (issue #77 round 4).
            suppressed = self._mint_fail_exc.get(slot.slot_id)
            if isinstance(suppressed, AwsUnknownState):
                raise suppressed
            return False
        try:
            token = self._ensure_token(slot)
        except AwsUnknownState as exc:
            # Back off the mint API, but do NOT collapse "the control plane didn't answer" into
            # "this slot isn't ready" (issue #77 round 4): resume() reads only the exceptions that
            # escape here, so swallowing this left last_exc=None and its final raise was a plain
            # AwsWorkerError -> read as death -> a healthy warmed microVM terminated over a
            # throttled token mint. is_ready() still catches it and returns False, as before.
            self._mint_fail_at[slot.slot_id] = self._clock()
            self._mint_fail_exc[slot.slot_id] = exc
            raise
        except (AwsWorkerError, OSError) as exc:
            self._mint_fail_at[slot.slot_id] = self._clock()   # not runnable yet -> back off the mint API
            self._mint_fail_exc[slot.slot_id] = exc if isinstance(exc, Exception) else None
            return False
        url = slot.url.rstrip("/") + self.cfg.agent_health_path
        headers = {"X-aws-proxy-auth": token, "X-aws-proxy-port": str(self.cfg.agent_port)}
        _t = self._probe_timeout()
        return None if _t is None else self._probe(url, headers, _t)

    def is_alive(self, slot: AwsWorkerSlot) -> "bool | None":
        # Skip the LambdaMicroVmRuntime JWE-refresh: minting a token requires RUNNING, so it would fail
        # every idle tick on a PARKED (suspended) slot -- silently, forever -- an AWS control-plane storm
        # that never achieves the refresh. resume() force-mints a fresh JWE on claim, so the idle refresh
        # is unnecessary here. Use the base liveness (cached _running) directly.
        return AwsDisposableRuntime.is_alive(self, slot)

    def is_alive_for_claim(self, slot: AwsWorkerSlot, *, budget_s: float | None = None) -> "bool | None":
        # Also skip the base Lambda claim-time refresh: a claimed slot is usually PARKED (mint needs
        # RUNNING -> always fails), and resume() force-mints a fresh JWE on wake AFTER the claim. Failing
        # the claim on a mint error (the base override) would reap EVERY parked warm slot before resume()
        # could wake it -> destroys the tier. Use the base liveness (fresh describe, no token touch).
        return AwsDisposableRuntime.is_alive_for_claim(self, slot, budget_s=budget_s)

    def reap(self, slot: AwsWorkerSlot) -> None:
        self._desc_cache.pop(slot.slot_id, None)
        super().reap(slot)

    def resume(self, slot: AwsWorkerSlot, *, budget_s: float | None = None) -> None:
        """Wake a (possibly parked) slot and block until its agent answers, BEFORE the job POSTs. Called
        by the dispatcher's claim seam. Raises on failure so the claim retires the slot dirty.

        Readiness is decided by the ENDPOINT PROBE (the get-microvm state field is eventually consistent).
        Whenever the probe is still failing and the slot isn't confirmed dead, (re)issue resume-microvm --
        it is tolerant of a wrong-state target (already running / stale state), so a genuinely-parked slot
        that get-microvm still misreports is actually woken even with autoResumeEnabled=false."""
        import time
        self._resolve_url(slot)     # stable endpoint, addressable even while transitioning
        slot.auth_token = None      # a JWE minted while suspended is invalid; force a fresh mint once awake
        # The runtime's resume_timeout_s is a CEILING; the dispatcher's remaining claim window wins
        # when it is shorter, so one unreachable slot cannot burn the whole window and starve the
        # healthy slots behind it (issue #77 round 4).
        budget = self.cfg.resume_timeout_s if budget_s is None else min(self.cfg.resume_timeout_s,
                                                                        max(0.0, float(budget_s)))
        if budget <= 0:
            # We were handed no time at all (the pool's scan grace can return a slot just past the
            # dispatcher's deadline). We have not probed this worker even ONCE, so we know nothing
            # about it -- and a plain error here reads as a confirmed failure and destroys a healthy
            # parked slot, which is the precise bug this whole change exists to prevent (#77 round 5).
            raise AwsUnknownState(
                f"{self.kind} slot {slot.slot_id}: no claim budget left to attempt a resume")
        deadline = self._clock() + budget
        last_exc: Exception | None = None
        # Did the worker get a FAIR chance to answer? Not "was the budget trimmed at all" -- the
        # dispatcher always passes the claim window's remainder, so ANY time consumed by claim()
        # made the old `budget < resume_timeout_s` test true, in every production resume. The
        # verdict was therefore unconditionally UNKNOWN and the dead-agent path became unreachable
        # (issue #77 marla-loop 2). A window shorter than the fairness floor is not evidence about
        # the worker; anything at or above it is.
        # A window is FAIR iff it can afford at least one FULL agent probe. Derived from
        # probe_timeout_s rather than a magic constant, which makes the guarantee explicit: when
        # fair, the first probe is never squeezed, so a negative answer is genuinely about the
        # worker. An earlier revision carried a separate "was this probe truncated" rule alongside a
        # fixed 5.0s floor -- with the default probe_timeout_s also 5.0 that rule could never fire,
        # i.e. it was dead code guarding a case this single condition already covers.
        unfair = budget < min(self.cfg.resume_timeout_s, float(self.cfg.probe_timeout_s))
        saw_up = False      # did the control plane ever CONFIRM this worker up during the window?
        # ...and did we ever actually GET TO ASK the agent? A probe that RAN and came back silent is
        # positive evidence the worker is bad. A probe we could never even issue -- because the
        # token mint was throttled, say -- teaches us nothing about the agent, however healthy the
        # control plane looked (issue #77 marla-loop 3).
        saw_agent_silent = False
        # Bound the inner calls ONLY when a caller actually shortened the window. Applying it
        # unconditionally made the deadline itself manufacture an AwsProbeTimeout on the last call,
        # which then became the verdict -- turning a HEALTHY control plane plus a dead agent into
        # "unknown" and leaking the husk. Unshortened resumes keep cli_timeout_s exactly as before.
        # ALWAYS bound the calls by the window we actually have. Gating this on `unfair` left the
        # common case (a near-full window) runningper call at cli_timeout_s, so one describe could
        # block 120s inside a 59s claim -- the round-6 finding, reintroduced. The bound and the
        # verdict are independent questions (issue #77 marla-loop 3).
        scope = self._call_budget(budget)
        with scope:
            while self._clock() < deadline:
                # Per-ITERATION, not per-call: the final classification must reflect the latest state of
                # the world (issue #77 round 4). Keeping the first error forever let one early blip mark
                # a full-window agent failure as UNKNOWN; clearing on any single success was worse -- it
                # wiped a throttled mint the moment the describe in the SAME pass succeeded, and that
                # mint failure is exactly what says "we still don't know if this worker is fine".
                iter_exc: Exception | None = None
                try:
                    _ok = self._health_ok(slot)
                    if _ok:
                        return
                    # Only a DEFINITIVE negative counts as evidence. None means we never got to ask --
                    # the local side ran out of resources -- and convicting on that would evict the
                    # fleet on a host hiccup, one level below the probe fix (issue #77 marla-loop 3).
                    if _ok is False:
                        saw_agent_silent = True
                except (AwsWorkerError, OSError) as exc:
                    iter_exc = exc      # not-yet-RUNNING mint/probe failures -> keep trying to wake it
                # probe failed -> the slot isn't serving. Confirm it's not dead, then nudge it awake.
                confirmed_up = False
                try:
                    cur = self._state(slot)
                    # The control plane ANSWERED and says the microVM is up. Combined with a failing
                    # agent probe that is a CONFIRMED bad worker, not an unknown one.
                    confirmed_up = cur in self._RUNNING_STATES
                    saw_up = saw_up or confirmed_up
                except (AwsWorkerError, OSError) as exc:
                    iter_exc, cur = exc, ""
                if cur in self._DEAD_STATES:
                    raise AwsWorkerError(f"snapstart slot {slot.slot_id} is {cur!r}; cannot resume")
                try:
                    self._aws("lambda-microvms", "resume-microvm",
                              "--microvm-identifier", str(slot.resource_id))
                    # discard any JWE minted while the slot was still suspended (invalid): the NEXT probe must
                    # re-mint an awake token, else an AUTO_RESUME=off slot woken here keeps probing/detonating
                    # with the pre-resume token until the deadline. On success the awake-minted token survives.
                    slot.auth_token = None
                except AwsWorkerError as exc:
                    # ResumeMicrovm requires a SUSPENDED target and answers ConflictException for a
                    # RUNNING one -- which the inverted classifier (correctly, in general) calls
                    # UNKNOWN. But when the state query just CONFIRMED the microVM is up, that conflict
                    # tells us nothing new, and letting it become the verdict masks a dead agent as a
                    # brownout forever: the slot is handed back every claim, never replaced, and a
                    # warm_size=1 tier requeues jobs indefinitely (issue #77 round 5). This is the
                    # cost-side of the inversion, and it is paid here rather than by weakening it.
                    if not confirmed_up:
                        iter_exc = exc  # already-running / eventual-consistency wrong-state -> probe is the gate
                last_exc = iter_exc     # this pass's verdict supersedes every earlier one
                time.sleep(min(self.cfg.resume_poll_s, max(0.0, deadline - self._clock())))
        # The deadline expiring does NOT upgrade an unknown to a confirmed death: if every
        # answer we got was "the control plane did not answer", that is still all we know
        # (issue #77 round 3). Round 2 fixed the raise site but this RE-raise flattened the
        # type back to a plain AwsWorkerError, and "timed out" matches no transient marker,
        # so a brownout outlasting resume_timeout_s still terminated a healthy parked worker.
        # A failure with a HEALTHY control plane (agent never came up) stays a hard error.
        # A CALLER-shortened window expiring is "we ran out of the time we were given", not a
        # verdict on the worker: with 10ms left a perfectly healthy warming microVM cannot possibly
        # answer, and calling that a failure destroys it (issue #77 round 6).
        # A trailing AwsUnknownState is usually the bound above expiring on the last call -- that
        # says nothing once we have ALREADY seen the control plane confirm this worker running and
        # watched its agent stay silent for a fair window. Keep the observation.
        # Convict ONLY on positive evidence: a fair window, the control plane confirming the worker
        # up, and a probe that actually RAN and came back silent. Everything else is UNKNOWN.
        #
        # The previous form fell back to AwsWorkerError when none of its branches matched -- so a
        # window in which every probe returned "could not ask" while AWS kept confirming the
        # instance RUNNING would CONVICT a worker we never once questioned. That case is only
        # unreachable today because the always-on call budget makes the next aws call raise UNKNOWN
        # first; it was a latent hazard resting on an unrelated interaction, not on the rule. I
        # could not construct a reaching test, so this is stated as a single positive-evidence rule
        # rather than guarded by a branch no test can hold honest (escalated codex, loop 4).
        exc_type = (AwsWorkerError
                    if (saw_up and saw_agent_silent and not unfair)
                    else AwsUnknownState)
        raise exc_type(
            f"snapstart slot {slot.slot_id} not ready within {self.cfg.resume_timeout_s:.0f}s: {last_exc}"
        ) from last_exc


def select_lambda_snapstart_runtime(
    *, cfg: LambdaSnapStartConfig | None = None, get_env: Callable[[str], str | None] | None = None,
    require_available: bool = False, **kw: Any,
) -> LambdaSnapStartRuntime:
    import os
    getter = get_env or os.environ.get
    cfg = cfg or LambdaSnapStartConfig.from_env(getter)
    # Like the disposable Lambda tier: AWS-managed PUBLIC https endpoint + JWE, so NO _inject_tls (public
    # trust roots, not the private worker CA).
    rt = LambdaSnapStartRuntime(cfg, **kw)
    if require_available and not rt.available():
        raise AwsUnavailable("aws-lambda-snapstart tier unavailable (creds/entitlement/service probe failed)")
    return rt


# ---------------------------------------------------------------------------
# Disposable EC2 tier
# ---------------------------------------------------------------------------

class DisposableEc2Runtime(AwsDisposableRuntime):
    """One throwaway EC2 instance per slot. Transport = the instance IP:port (in-VPC private IP by
    default). Agent is brought up by the AMI's user-data; instance is terminated after one job."""

    kind = "aws-ec2"
    _uptime_backstop = False   # disposable instances never hibernate -> a wall-clock shutdown TTL is fine

    def __init__(self, cfg: Ec2Config, **kw: Any) -> None:
        if not cfg.image_id:
            raise AwsUnavailable("DisposableEc2Runtime: BLASTBOX_EC2_AMI is required")
        super().__init__(cfg, **kw)   # sets self.ssl_context from the injected/kw context
        # FAIL CLOSED on public IP without TLS: both the readiness probe and /detonate would then talk
        # http:// to the PUBLIC EC2 endpoint, sending X-aws-proxy-auth (the shared agent_token) + the
        # sample bytes across the public internet in cleartext. Covers the hibernate tier too (it chains
        # through this __init__). Private-IP deploys (the default, use_public_ip=False) never trip it.
        if cfg.use_public_ip and self.ssl_context is None and not cfg.allow_plaintext_public:
            raise AwsUnavailable(
                "EC2 worker over a PUBLIC IP without dispatcher TLS: the bearer token + sample bytes would "
                "cross the public internet in cleartext. Set BLASTBOX_DISPATCH_TLS_CA (+ _CERT/_KEY for "
                "mTLS to the agent), or BLASTBOX_EC2_ALLOW_PLAINTEXT_PUBLIC=1 to explicitly accept plaintext."
            )
        self.cfg: Ec2Config = cfg

    def _service_available(self) -> bool:
        self._aws("ec2", "describe-instances", "--max-items", "1")
        return True

    def _launch(self) -> AwsWorkerSlot:
        sid = uuid.uuid4().hex[:16]
        c = self.cfg
        # All values are hex/slug (no commas/brackets/spaces) → safe in the CLI shorthand parser.
        tag_pairs = (f"{{Key={_TAG_SLOT},Value={sid}}},"
                     f"{{Key={_TAG_TIER},Value={self.kind}}},"
                     f"{{Key={_TAG_RUN},Value={self._run_id}}}")
        tag = f"ResourceType=instance,Tags=[{tag_pairs}]"
        args = ["--image-id", c.image_id, "--instance-type", c.instance_type,
                "--count", "1", "--client-token", sid, "--tag-specifications", tag,
                # auto-terminate on the instance's own shutdown as a backstop reap
                "--instance-initiated-shutdown-behavior", "terminate"]
        if c.subnet_id:
            args += ["--subnet-id", c.subnet_id]
        if c.use_public_ip:
            # a NONDEFAULT subnet defaults auto-assign-public-IP to FALSE, so without this the instance
            # gets no public address, _health_ok never sees a PublicIpAddress, and the slot churns until
            # the warming timeout. Explicitly request one for public-endpoint mode.
            args += ["--associate-public-ip-address"]
        if c.security_group_ids:
            args += ["--security-group-ids", *c.security_group_ids]
        if c.iam_instance_profile:
            args += ["--iam-instance-profile", f"Name={c.iam_instance_profile}"]
        if c.key_name:
            args += ["--key-name", c.key_name]
        args += self._extra_launch_args()   # subclass hook (e.g. hibernate: --hibernation-options + EBS)
        # The aws CLI base64-encodes --user-data itself, so hand it the RAW text (decoded from our
        # stored base64) or it would double-encode and the agent would never start.
        user_data = None
        if c.user_data_b64:
            import base64
            user_data = base64.b64decode(c.user_data_b64).decode("utf-8", errors="replace")
        if c.self_terminate and c.max_duration_s:
            # backstop reap: guest schedules its own shutdown -> shutdown-behavior=terminate kills it,
            # so a crashed dispatcher can't leak a running instance past MAX_DURATION_S. The hibernate tier
            # uses an UPTIME timer (see _uptime_backstop) so it can't fire on resume.
            user_data = _userdata_with_self_terminate(user_data, c.max_duration_s,
                                                      uptime=self._uptime_backstop)
        if user_data:
            # Keep user-data OUT of the aws process argv: cloud-init that bootstraps the agent may carry a
            # bearer token / TLS private key, and argv is visible via /proc + `ps` to local users / process
            # logging. Hand the CLI a 0600 file:// instead -- it base64-encodes the file's TEXT content
            # exactly as it would a raw --user-data string, so the launched instance is byte-identical.
            fd, ud_path = tempfile.mkstemp(prefix="bb-ec2-ud-", suffix=".txt")   # mode 0600, O_EXCL
            try:
                with os.fdopen(fd, "w") as f:
                    f.write(user_data)
                args += ["--user-data", f"file://{ud_path}"]
                resp = self._aws("ec2", "run-instances", *args)
            finally:
                try:
                    os.unlink(ud_path)
                except OSError:
                    pass
        else:
            resp = self._aws("ec2", "run-instances", *args)
        insts = resp.get("Instances") or []
        if not insts or not insts[0].get("InstanceId"):
            raise AwsWorkerError("run-instances: no instance id in response")
        slot = AwsWorkerSlot(slot_id=sid, resource_id=str(insts[0]["InstanceId"]), state=SlotState.WARMING)
        slot.auth_token = c.agent_token   # forwarded to /healthz + /detonate by the transport
        return slot

    def _describe(self, slot: AwsWorkerSlot) -> dict[str, Any]:
        resp = self._aws("ec2", "describe-instances", "--instance-ids", str(slot.resource_id))
        for res in resp.get("Reservations", []):
            for inst in res.get("Instances", []):
                if inst.get("InstanceId") == slot.resource_id:
                    return inst
        return {}

    def _running(self, slot: AwsWorkerSlot) -> bool:
        return str(self._describe(slot).get("State", {}).get("Name", "")) == "running"

    def _health_ok(self, slot: AwsWorkerSlot) -> "bool | None":
        if slot.ip is None:
            inst = self._describe_cached(slot, self._liveness_cache_s)   # throttle the ~10Hz warming poll
            if str(inst.get("State", {}).get("Name", "")) != "running":
                return False
            slot.ip = inst.get("PublicIpAddress") if self.cfg.use_public_ip else inst.get("PrivateIpAddress")
            if slot.ip is None:
                return False
        scheme = "https" if self.ssl_context else "http"
        url = f"{scheme}://{slot.ip}:{self.cfg.agent_port}{self.cfg.agent_health_path}"
        headers = {"X-aws-proxy-auth": self.cfg.agent_token} if self.cfg.agent_token else {}
        _t = self._probe_timeout()
        return None if _t is None else self._probe(url, headers, _t)

    def _extra_launch_args(self) -> list[str]:
        """Extra `run-instances` args a subclass appends (base: none). The hibernate tier adds
        --hibernation-options + an encrypted root EBS volume."""
        return []

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


# ---------------------------------------------------------------------------
# EC2 WARM (hibernate C/R) tier — stop-hibernate / start, per-instance
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Ec2HibernateConfig(Ec2Config):
    # EC2 Hibernate = the warm C/R primitive: stop-instances --hibernate saves the instance's RAM to the
    # (encrypted) root EBS and start-instances restores it -- the warmed process (JVM/soffice) survives.
    # Unlike Lambda's platform idle-policy, EC2 has NO auto-hibernate, so the RUNTIME parks a warmed slot
    # itself (boot -> warm -> stop --hibernate -> parked) and starts it on claim. The private IP is
    # retained across stop/start, so the endpoint is stable. Requires an encrypted root volume + a
    # hibernation-capable instance type (e.g. t4g/m6g/c6g, RAM <= 150 GB) + a hibernation-enabled AMI.
    # DEFAULT-ON crash backstop: the runtime uses an UPTIME timer (systemd-run --on-active, see
    # Ec2HibernateRuntime._uptime_backstop) whose monotonic deadline doesn't advance while hibernated, so
    # unlike a wall-clock `shutdown -h +minutes` it can't fire on resume -- a leaked RUNNING instance
    # (crashed dispatcher) self-terminates after MAX_DURATION_S of cumulative running time, a parked one
    # never accrues it. (A stopped/hibernated leak from a crashed dispatcher is EBS-cost only and not bounded
    # by a guest timer -- the host-side sweep_orphans() reaps those, opt-in via BLASTBOX_EC2_ORPHAN_MAX_AGE_S.)
    self_terminate: bool = True
    root_device_name: str = "/dev/xvda"   # AL2023 ARM64 root device
    root_volume_gb: int = 30              # >= RAM + OS; the EBS must hold the saved RAM image
    # the pool's WARMING eviction budget must cover boot + engine.warmup + the ec2-hibinit reserve wait
    # + stop --hibernate -> stopped (all in is_ready) -- much longer than a fresh-boot readiness.
    ready_timeout_s: float = 600.0
    resume_timeout_s: float = 180.0       # < worker_timeout (300) so a slow start leaves budget for the job
    resume_poll_s: float = 5.0
    hibernate_timeout_s: float = 300.0    # per-slot budget for stop --hibernate -> stopped before re-driving
    # Host-side orphan sweep: terminate STOPPED/hibernated slots (NOT owned by this dispatcher process)
    # older than this many seconds. 0 (default) = OFF, matching the BLASTBOX_MAX_QUEUED_AGE_S opt-in
    # precedent. Recommend a positive value >= peak park duration (e.g. 3600) to reclaim leaked EBS cost.
    orphan_max_age_s: float = 0.0

    @classmethod
    def from_env(cls, get: Callable[[str], str | None], **overrides: Any) -> Ec2HibernateConfig:
        import dataclasses
        base = Ec2Config.from_env(get)
        fields = {f.name: getattr(base, f.name) for f in dataclasses.fields(Ec2Config)}
        fields["self_terminate"] = (get("BLASTBOX_EC2_SELF_TERMINATE") or "1").strip().lower() not in ("0", "false", "no", "off")
        fields.update(
            root_device_name=_env(get, "BLASTBOX_EC2_ROOT_DEVICE", "/dev/xvda") or "/dev/xvda",
            root_volume_gb=int(_env(get, "BLASTBOX_EC2_ROOT_VOLUME_GB", "30") or "30"),
            ready_timeout_s=float(_env(get, "BLASTBOX_EC2_HIBERNATE_READY_TIMEOUT_S", "600") or "600"),
            resume_timeout_s=float(_env(get, "BLASTBOX_EC2_HIBERNATE_RESUME_TIMEOUT_S", "180") or "180"),
            resume_poll_s=float(_env(get, "BLASTBOX_EC2_HIBERNATE_RESUME_POLL_S", "5") or "5"),
            hibernate_timeout_s=float(_env(get, "BLASTBOX_EC2_HIBERNATE_TIMEOUT_S", "300") or "300"),
            orphan_max_age_s=float(_env(get, "BLASTBOX_EC2_ORPHAN_MAX_AGE_S", "0") or "0"),
        )
        fields.update(overrides)
        return cls(**fields)


class Ec2HibernateRuntime(DisposableEc2Runtime):
    """WARM EC2 tier via hibernate C/R. spawn boots+warms an instance in the background; is_ready drives
    a per-slot state machine (warm -> stop --hibernate -> parked STOPPED); resume(slot) start-instances +
    health-gates it on claim (private IP retained -> stable endpoint); reap terminates it after ONE
    untrusted job (disposable-warm, never reused across inputs). The warmed process survives the
    hibernate/start because EC2 saves+restores RAM."""

    kind = "aws-ec2-hibernate"
    _ALIVE_STATES = ("pending", "running", "stopping", "stopped")
    _DEAD_STATES = ("shutting-down", "terminated")
    _uptime_backstop = True   # a wall-clock shutdown TTL would fire on resume; use a monotonic uptime timer

    def __init__(self, cfg: Ec2HibernateConfig, **kw: Any) -> None:
        super().__init__(cfg, **kw)   # base provides _desc_cache + _describe_cached
        self.cfg: Ec2HibernateConfig = cfg
        self._phase: dict[str, str] = {}   # slot_id -> "warming" | "hibernating" | "parked"
        self._hib_attempt: dict[str, float] = {}   # slot_id -> last stop --hibernate attempt (throttle)
        self._hib_started: dict[str, float] = {}   # slot_id -> when it entered the hibernating phase

    def _service_available(self) -> bool:
        # fail LOUD (once, at pool build) on a hibernation-incapable config instead of churning
        # launch->warm->stop-fails->reap->respawn forever. Verify the instance type supports hibernation
        # and the root volume can hold the RAM image.
        super()._service_available()   # describe-instances probe
        d = self._aws("ec2", "describe-instance-types", "--instance-types", self.cfg.instance_type)
        its = d.get("InstanceTypes", [])
        if not its or not its[0].get("HibernationSupported"):
            raise AwsWorkerError(
                f"aws-ec2-hibernate: instance type {self.cfg.instance_type!r} does not support hibernation "
                "(pick a hibernation-capable type, e.g. t4g/m6g/m7g)")
        ram_mib = int(its[0].get("MemoryInfo", {}).get("SizeInMiB", 0))
        if ram_mib and self.cfg.root_volume_gb * 1024 < ram_mib:
            raise AwsWorkerError(
                f"aws-ec2-hibernate: root_volume_gb={self.cfg.root_volume_gb} is smaller than the "
                f"instance RAM ({ram_mib} MiB) -- hibernation saves RAM to the root EBS; raise "
                "BLASTBOX_EC2_ROOT_VOLUME_GB")
        return True

    def _extra_launch_args(self) -> list[str]:
        import json
        ebs = [{"DeviceName": self.cfg.root_device_name,
                "Ebs": {"Encrypted": True, "VolumeSize": self.cfg.root_volume_gb,
                        "DeleteOnTermination": True}}]
        # hibernation requires an ENCRYPTED root volume large enough to hold the saved RAM image.
        return ["--hibernation-options", "Configured=true", "--block-device-mappings", json.dumps(ebs)]

    def _state(self, slot: AwsWorkerSlot) -> str:
        return str(self._describe(slot).get("State", {}).get("Name", "")).lower()   # UNCACHED

    def _running(self, slot: AwsWorkerSlot) -> bool:
        # a PARKED (stopped/hibernated) warm slot is ALIVE -- whitelist so the pool health-check doesn't
        # reap parked slots; empty/unknown/dead -> not alive -> reaped.
        return self._state(slot) in self._ALIVE_STATES

    def _resolve_ip(self, slot: AwsWorkerSlot, *, refresh: bool = False) -> None:
        if slot.ip is not None and not refresh:
            return
        if refresh:
            # a resumed instance gets a NEW public IP (private IP is retained). Bypass the describe cache
            # and drop the stale IP so we never probe/POST the token to the pre-hibernate (reassigned) IP.
            self._desc_cache.pop(slot.slot_id, None)
            if self.cfg.use_public_ip:
                slot.ip = None
        inst = self._describe_cached(slot, 0.0 if refresh else self._liveness_cache_s)
        ip = inst.get("PublicIpAddress") if self.cfg.use_public_ip else inst.get("PrivateIpAddress")
        if ip:
            slot.ip = str(ip)

    def _agent_healthy(self, slot: AwsWorkerSlot) -> "bool | None":
        self._resolve_ip(slot)
        if slot.ip is None:
            return False
        scheme = "https" if self.ssl_context else "http"
        url = f"{scheme}://{slot.ip}:{self.cfg.agent_port}{self.cfg.agent_health_path}"
        headers = {"X-aws-proxy-auth": self.cfg.agent_token} if self.cfg.agent_token else {}
        _t = self._probe_timeout()
        return None if _t is None else self._probe(url, headers, _t)

    def _try_park(self, slot: AwsWorkerSlot) -> bool:
        """Issue the THROTTLED ``stop --hibernate`` that parks a warmed slot. True iff it was accepted.

        Throttled because the pool polls is_ready at ~10Hz, and TOLERANT of "not ready to hibernate
        yet" (the ec2-hibinit-agent needs ~1-2min after boot to lay down the hibernation reserve):
        a failed attempt leaves the phase alone so a later tick retries. Only a SUCCESSFUL stop
        advances to "hibernating"."""
        now = self._clock()
        if now - self._hib_attempt.get(slot.slot_id, 0.0) < self._liveness_cache_s:
            return False
        self._hib_attempt[slot.slot_id] = now
        try:
            self._aws("ec2", "stop-instances", "--instance-ids", str(slot.resource_id), "--hibernate")
        except AwsWorkerError as exc:
            _log.info("ec2-hibernate: stop --hibernate %s not ready yet (%s); will retry",
                      slot.slot_id, str(exc)[:120])
            return False
        self._desc_cache.pop(slot.slot_id, None)   # force a fresh describe next poll
        self._phase[slot.slot_id] = "hibernating"
        self._hib_started[slot.slot_id] = now
        return True

    def is_ready(self, slot: AwsWorkerSlot) -> bool:
        # Per-slot state machine, polled by the pool during WARMING: boot -> warm -> hibernate -> parked.
        try:
            now = self._clock()
            phase = self._phase.get(slot.slot_id, "warming")
            if phase == "warming":
                if str(self._describe_cached(slot, self._liveness_cache_s)
                       .get("State", {}).get("Name", "")).lower() != "running":
                    return False
                if not self._agent_healthy(slot):
                    return False
                # Warmed -> PARK it: stop --hibernate. THROTTLE the attempt (the pool polls is_ready at
                # ~10Hz) -- and TOLERATE "not ready to hibernate yet" (the ec2-hibinit-agent needs ~1-2min
                # after boot to lay down the hibernation reserve). On a failed/throttled attempt we stay
                # in "warming" and retry on a later tick; only a SUCCESSFUL stop advances to "hibernating".
                self._try_park(slot)
                return False
            if phase == "hibernating":
                st = str(self._describe_cached(slot, self._liveness_cache_s)
                         .get("State", {}).get("Name", "")).lower()
                if st == "stopped":
                    self._phase[slot.slot_id] = "parked"
                    return True
                # RECOVERY: hibernate can be ACCEPTED then fail async (instance lands back 'running'), or
                # hang. Don't sit in 'hibernating' forever spinning until warming_timeout -- re-drive from
                # 'warming' (the stop is re-issued, throttled) if it came back running or blew the budget.
                started = self._hib_started.get(slot.slot_id, now)
                if st in self._DEAD_STATES:
                    return False   # is_alive/_health_check will reap it
                if st == "running" or (now - started) > self.cfg.hibernate_timeout_s:
                    _log.info("ec2-hibernate: %s hibernate did not take (state=%s, %.0fs) -- re-driving",
                              slot.slot_id, st, now - started)
                    self._phase[slot.slot_id] = "warming"
                return False
            return True   # parked -- claimable; resume() wakes it on claim
        except (AwsWorkerError, OSError) as exc:
            _log.debug("ec2-hibernate: is_ready(%s) error: %s", slot.slot_id, exc)
            return False

    def resume(self, slot: AwsWorkerSlot, *, budget_s: float | None = None) -> None:
        """Start a hibernated slot and block until its agent answers, BEFORE the job POSTs. Called by the
        dispatcher's claim seam. Raises on failure so the claim retires the slot dirty."""
        import time
        # Bound the PRE-loop calls by the caller's window as well: describe + start-instances +
        # describe each ran at the full cli_timeout_s (120s) before any budget applied, so a claim
        # with 0.25s left could block for minutes (issue #77 marla-loop 2). Computed here so the
        # scope covers everything this method does.
        # ONE budget for the whole call. The prelude used to open its own scope, which CLOSED
        # before the loop opened another -- so a resume could consume up to TWICE the window it was
        # given (issue #77 marla-loop 3). Compute the deadline once, here, and carve everything
        # (prelude AND poll loop) out of it.
        _total = (self.cfg.resume_timeout_s if budget_s is None
                  else min(self.cfg.resume_timeout_s, max(0.0, float(budget_s))))
        if _total <= 0:
            # The caller handed us no time at all (the pool's scan grace can return a slot just past
            # the dispatcher's deadline). We have not probed this worker even ONCE, so we know
            # nothing about it -- and a plain error here reads as a confirmed failure and destroys a
            # healthy parked slot (issue #77 round 5).
            raise AwsUnknownState(
                f"{self.kind} slot {slot.slot_id}: no claim budget left to attempt a resume")
        _hard_deadline = self._clock() + _total
        with self._call_budget(_total):
            st = self._state(slot)
            if st in self._DEAD_STATES:
                raise AwsWorkerError(f"ec2-hibernate slot {slot.slot_id} is {st!r}; cannot resume")
            if st == "stopped":
                self._aws("ec2", "start-instances", "--instance-ids", str(slot.resource_id))
            # NOTE: no phase bookkeeping here. An earlier revision set _phase="warming" so an
            # is_alive() reconciler could re-park a slot whose resume browned out after the start
            # was accepted -- but that reconciler was removed from this branch (see issue #80), and
            # _phase is read only by is_ready(), which the pool calls for WARMING slots only. So the
            # write had no reader and only advertised machinery that is not here.
            self._resolve_ip(slot, refresh=True)   # private IP retained, but re-describe to be safe
        # The runtime's resume_timeout_s is a CEILING; the dispatcher's remaining claim window wins
        # when it is shorter, so one unreachable slot cannot burn the whole window and starve the
        # healthy slots behind it (issue #77 round 4).
        budget = max(0.0, _hard_deadline - self._clock())   # whatever the prelude LEFT us
        deadline = self._clock() + budget
        last_exc: Exception | None = None
        # Did the worker get a FAIR chance to answer? Not "was the budget trimmed at all" -- the
        # dispatcher always passes the claim window's remainder, so ANY time consumed by claim()
        # made the old `budget < resume_timeout_s` test true, in every production resume. The
        # verdict was therefore unconditionally UNKNOWN and the dead-agent path became unreachable
        # (issue #77 marla-loop 2). A window shorter than the fairness floor is not evidence about
        # the worker; anything at or above it is.
        # A window is FAIR iff it can afford at least one FULL agent probe. Derived from
        # probe_timeout_s rather than a magic constant, which makes the guarantee explicit: when
        # fair, the first probe is never squeezed, so a negative answer is genuinely about the
        # worker. An earlier revision carried a separate "was this probe truncated" rule alongside a
        # fixed 5.0s floor -- with the default probe_timeout_s also 5.0 that rule could never fire,
        # i.e. it was dead code guarding a case this single condition already covers.
        unfair = budget < min(self.cfg.resume_timeout_s, float(self.cfg.probe_timeout_s))
        saw_up = False      # did the control plane ever CONFIRM this worker up during the window?
        # ...and did we ever actually GET TO ASK the agent? A probe that RAN and came back silent is
        # positive evidence the worker is bad. A probe we could never even issue -- because the
        # token mint was throttled, say -- teaches us nothing about the agent, however healthy the
        # control plane looked (issue #77 marla-loop 3).
        saw_agent_silent = False
        # Bound the inner calls ONLY when a caller actually shortened the window. Applying it
        # unconditionally made the deadline itself manufacture an AwsProbeTimeout on the last call,
        # which then became the verdict -- turning a HEALTHY control plane plus a dead agent into
        # "unknown" and leaking the husk. Unshortened resumes keep cli_timeout_s exactly as before.
        # ALWAYS bound the calls by the window we actually have. Gating this on `unfair` left the
        # common case (a near-full window) runningper call at cli_timeout_s, so one describe could
        # block 120s inside a 59s claim -- the round-6 finding, reintroduced. The bound and the
        # verdict are independent questions (issue #77 marla-loop 3).
        scope = self._call_budget(budget)
        with scope:
            while self._clock() < deadline:
                iter_exc: Exception | None = None      # see the snapstart loop: per-PASS verdict
                try:
                    _ok = self._agent_healthy(slot)
                    if _ok:
                        return
                    if _ok is False:
                        saw_agent_silent = True     # the probe ran; the agent did not answer
                except (AwsWorkerError, OSError) as exc:
                    iter_exc = exc
                try:
                    cur = self._state(slot)
                    saw_up = saw_up or cur == "running"
                except (AwsWorkerError, OSError) as exc:
                    iter_exc, cur = exc, ""
                if cur in self._DEAD_STATES:
                    raise AwsWorkerError(f"ec2-hibernate slot {slot.slot_id} is {cur!r}; cannot resume")
                if cur == "stopped":   # not yet starting (or slid back) -> (re)issue start
                    try:
                        self._aws("ec2", "start-instances", "--instance-ids", str(slot.resource_id))
                    except AwsWorkerError as exc:
                        iter_exc = exc
                try:
                    self._resolve_ip(slot, refresh=True)
                except (AwsWorkerError, OSError) as exc:
                    iter_exc = exc
                last_exc = iter_exc     # this pass's verdict supersedes every earlier one
                time.sleep(min(self.cfg.resume_poll_s, max(0.0, deadline - self._clock())))
        # The deadline expiring does NOT upgrade an unknown to a confirmed death: if every
        # answer we got was "the control plane did not answer", that is still all we know
        # (issue #77 round 3). Round 2 fixed the raise site but this RE-raise flattened the
        # type back to a plain AwsWorkerError, and "timed out" matches no transient marker,
        # so a brownout outlasting resume_timeout_s still terminated a healthy parked worker.
        # A failure with a HEALTHY control plane (agent never came up) stays a hard error.
        # A CALLER-shortened window expiring is "we ran out of the time we were given", not a
        # verdict on the worker: with 10ms left a perfectly healthy warming microVM cannot possibly
        # answer, and calling that a failure destroys it (issue #77 round 6).
        # A trailing AwsUnknownState is usually the bound above expiring on the last call -- that
        # says nothing once we have ALREADY seen the control plane confirm this worker running and
        # watched its agent stay silent for a fair window. Keep the observation.
        # Convict ONLY on positive evidence: a fair window, the control plane confirming the worker
        # up, and a probe that actually RAN and came back silent. Everything else is UNKNOWN.
        #
        # The previous form fell back to AwsWorkerError when none of its branches matched -- so a
        # window in which every probe returned "could not ask" while AWS kept confirming the
        # instance RUNNING would CONVICT a worker we never once questioned. That case is only
        # unreachable today because the always-on call budget makes the next aws call raise UNKNOWN
        # first; it was a latent hazard resting on an unrelated interaction, not on the rule. I
        # could not construct a reaching test, so this is stated as a single positive-evidence rule
        # rather than guarded by a branch no test can hold honest (escalated codex, loop 4).
        exc_type = (AwsWorkerError
                    if (saw_up and saw_agent_silent and not unfair)
                    else AwsUnknownState)
        raise exc_type(
            f"ec2-hibernate slot {slot.slot_id} not ready within {self.cfg.resume_timeout_s:.0f}s: {last_exc}"
        ) from last_exc

    def reap(self, slot: AwsWorkerSlot) -> None:
        for d in (self._phase, self._desc_cache, self._hib_attempt, self._hib_started):
            d.pop(slot.slot_id, None)
        super().reap(slot)   # terminate-instances (disposable after one untrusted job)

    def sweep_orphans(self, *, max_age_s: float | None = None, now: float | None = None,
                      dry_run: bool = False) -> list[str]:
        """Terminate STOPPED/hibernated hibernate-tier slots leaked by a CRASHED dispatcher.

        The guest uptime backstop is frozen while hibernated, so a slot PARKED when its dispatcher
        died never self-terminates (EBS cost). This reclaims them, keyed on the ``blastbox-tier`` tag
        and fenced against our OWN live parked slots by ``blastbox-run`` (this process's id). Only
        acts when ``orphan_max_age_s > 0`` (opt-in). Best-effort: any per-instance failure is logged
        and skipped — a sweep error must never crash the pool. Returns the terminated instance ids."""
        max_age = self.cfg.orphan_max_age_s if max_age_s is None else max_age_s
        # `not (max_age > 0)` (not `max_age <= 0`) so a NaN — float("nan") passes both `<= 0` AND the
        # later `age < max_age` as False, which would otherwise terminate EVERY stopped slot — is
        # treated as "disabled". inf is fine: age < inf is always True, so nothing is ever old enough.
        if not (max_age > 0):
            return []
        now = time.time() if now is None else now
        resp = self._aws("ec2", "describe-instances", "--filters",
                         f"Name=tag:{_TAG_TIER},Values={self.kind}",
                         "Name=instance-state-name,Values=stopping,stopped")
        killed: list[str] = []
        for res in resp.get("Reservations", []):
            for inst in res.get("Instances", []):
                iid = inst.get("InstanceId")
                tags = {t.get("Key"): t.get("Value") for t in inst.get("Tags", [])}
                if not iid or tags.get(_TAG_RUN) == self._run_id:
                    continue   # our own live parked slot -- never sweep (primary safety)
                stopped_at = self._stopped_since(inst)
                if stopped_at is None or (now - stopped_at) < max_age:
                    continue   # unparseable age (fail-safe skip) or too young
                if dry_run:
                    killed.append(iid)
                    continue
                try:
                    self._aws("ec2", "terminate-instances", "--instance-ids", iid)
                    killed.append(iid)
                except (AwsWorkerError, OSError) as e:  # noqa: PERF203
                    _log.warning("ec2-hibernate orphan sweep: terminate %s failed: %s", iid, e)
        if killed:
            _log.info("ec2-hibernate orphan sweep %s %d leaked slot(s): %s",
                      "would terminate" if dry_run else "terminated", len(killed), killed)
        return killed

    @staticmethod
    def _stopped_since(inst: dict[str, Any]) -> float | None:
        """Epoch seconds when the instance entered ``stopped``, parsed from ``StateTransitionReason``
        (``'... (YYYY-MM-DD HH:MM:SS GMT)'``). ``None`` when it's missing/unparseable — the caller
        treats ``None`` as "too young" (skip). We deliberately do NOT fall back to ``LaunchTime``:
        that's the instance's CREATION time, so a slot that ran a long while then stopped RECENTLY
        would look ancient and be terminated prematurely — the opposite of fail-safe."""
        import datetime as _dt
        import re as _re

        m = _re.search(r"\((\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) GMT\)",
                       inst.get("StateTransitionReason") or "")
        if not m:
            return None
        try:
            return _dt.datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=_dt.timezone.utc).timestamp()
        except ValueError:
            return None


def select_ec2_hibernate_runtime(
    *, cfg: Ec2HibernateConfig | None = None, get_env: Callable[[str], str | None] | None = None,
    require_available: bool = False, **kw: Any,
) -> Ec2HibernateRuntime:
    import os
    getter = get_env or os.environ.get
    cfg = cfg or Ec2HibernateConfig.from_env(getter)
    rt = Ec2HibernateRuntime(cfg, **_inject_tls(getter, kw))   # self-hosted EC2 agent -> worker mTLS applies
    if require_available and not rt.available():
        raise AwsUnavailable("aws-ec2-hibernate tier unavailable (creds/service probe failed)")
    return rt
