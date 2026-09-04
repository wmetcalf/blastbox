"""Unit tests for the AWS disposable-worker runtime family (no real AWS).

The AWS CLI and the HTTP health probe are injected as fakes, so spawn/is_ready/is_alive/reap are
exercised end-to-end against canned responses. Also checks SlotRuntime protocol conformance, the
fail-closed availability probe, config from_env, and pool_config registration.
"""

from __future__ import annotations

import errno
import contextlib
import json
import os
import subprocess

import pytest

from blastbox.host.pool import SlotRuntime, SlotState
from blastbox.host.runtime.aws_worker import (
    AwsProbeTimeout,
    AwsThrottled,
    AwsUnknownState,
    AwsWorkerConfig,
    AwsUnavailable,
    AwsWorkerError,
    AwsWorkerSlot,
    DisposableEc2Runtime,
    Ec2Config,
    Ec2HibernateConfig,
    Ec2HibernateRuntime,
    LambdaMicroVmConfig,
    LambdaMicroVmRuntime,
    LambdaSnapStartConfig,
    LambdaSnapStartRuntime,
    select_lambda_microvm_runtime,
    select_ec2_hibernate_runtime,
    select_lambda_snapstart_runtime,
)


def _cp(rc: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=["aws"], returncode=rc, stdout=stdout, stderr=stderr)


class FakeAws:
    """Maps ``"<service> <op>"`` -> dict (JSON'd) | CompletedProcess | callable(argv)->CompletedProcess."""

    def __init__(self, responses: dict) -> None:
        self.responses = responses
        self.calls: list[tuple[str, list[str]]] = []

    def __call__(self, argv, timeout):  # noqa: ANN001
        argv = list(argv)
        key = f"{argv[1]} {argv[2]}"
        self.calls.append((key, argv))
        r = self.responses.get(key)
        if r is None:
            return _cp(rc=254, stderr=f"no fake for {key}")
        if callable(r):
            return r(argv)
        if isinstance(r, subprocess.CompletedProcess):
            return r
        return _cp(stdout=json.dumps(r))

    def ops(self) -> list[str]:
        return [k for k, _ in self.calls]


_IDENT = {"sts get-caller-identity": {"Account": "380038281108", "Arn": "arn:aws:iam::x:user/y"}}


def _lambda_rt(responses, probe=lambda url, hdrs, to: True, **kw):  # noqa: ANN001
    cfg = LambdaMicroVmConfig(region="us-east-1", image_identifier="arn:aws:lambda:us-east-1:aws:microvm-image:al2023-1",
                              allow_default_egress=True)
    fake = FakeAws({**_IDENT, **responses})
    return LambdaMicroVmRuntime(cfg, aws_runner=fake, http_probe=probe, clock=lambda: 100.0, **kw), fake


def _ec2_rt(responses, probe=lambda url, hdrs, to: True, **kw):  # noqa: ANN001
    cfg = Ec2Config(region="us-east-1", image_id="ami-0abc")
    fake = FakeAws({**_IDENT, **responses})
    return DisposableEc2Runtime(cfg, aws_runner=fake, http_probe=probe, clock=lambda: 100.0, **kw), fake


def _snapstart_rt(responses, probe=lambda url, hdrs, to: True, clock=lambda: 100.0, **cfgkw):  # noqa: ANN001
    cfg = LambdaSnapStartConfig(region="us-east-1", image_identifier="arn:img",
                                allow_default_egress=True, resume_poll_s=0.0, **cfgkw)
    fake = FakeAws({**_IDENT, **responses})
    return LambdaSnapStartRuntime(cfg, aws_runner=fake, http_probe=probe, clock=clock), fake


# --------------------------------------------------------------------------- SnapStart (warm) tier

def test_snapstart_launch_sets_idle_policy():
    rt, fake = _snapstart_rt({"lambda-microvms run-microvm": {"microvmId": "mv-1"}},
                             max_idle_duration_s=90, suspended_duration_s=1800)
    rt.spawn()
    argv = next(a for k, a in fake.calls if k == "lambda-microvms run-microvm")
    policy = json.loads(argv[argv.index("--idle-policy") + 1])
    assert policy == {"maxIdleDurationSeconds": 90, "suspendedDurationSeconds": 1800, "autoResumeEnabled": True}


def test_snapstart_running_counts_suspended_as_alive():
    # a PARKED (suspended) slot must report alive, or the pool health-check reaps it every tick.
    for state in ("suspended", "suspending", "pending", "running"):
        rt, _ = _snapstart_rt({"lambda-microvms get-microvm": {"state": state}})
        slot = AwsWorkerSlot(slot_id='s', resource_id='mv-1')
        assert rt._running(slot) is True, state


def test_snapstart_running_dead_states():
    for state in ("terminating", "terminated"):
        rt, _ = _snapstart_rt({"lambda-microvms get-microvm": {"state": state}})
        slot = AwsWorkerSlot(slot_id='s', resource_id='mv-1')
        assert rt._running(slot) is False, state


def test_snapstart_is_alive_true_for_suspended_slot():
    # end-to-end through is_alive (which the pool health-check calls on IDLE slots) -> parked stays warm.
    rt, _ = _snapstart_rt({"lambda-microvms get-microvm": {"state": "suspended"},
                           "lambda-microvms create-microvm-auth-token": {"authToken": "jwe"}})
    slot = AwsWorkerSlot(slot_id='s', resource_id='mv-1')
    assert rt.is_alive(slot) is True


def test_snapstart_is_alive_does_not_mint_token_on_parked_slot():
    # regression: the base is_alive JWE-refresh mints a token every idle tick, which FAILS on a SUSPENDED
    # slot (mint needs RUNNING) forever -> control-plane storm. SnapStart's is_alive must NOT mint.
    rt, fake = _snapstart_rt({"lambda-microvms get-microvm": {"state": "suspended"},
                             "lambda-microvms create-microvm-auth-token": {"authToken": "jwe"}},
                            clock=lambda: 100000.0)   # far past any token half-TTL
    slot = AwsWorkerSlot(slot_id='s', resource_id='mv-1')
    slot.auth_token, slot.token_minted_at = "aged", 0.0   # a stale token that base is_alive would try to refresh
    for _ in range(5):
        rt.is_alive(slot)
    assert "lambda-microvms create-microvm-auth-token" not in [k for k, _ in fake.calls]   # no mint storm


def test_snapstart_running_empty_or_unknown_state_not_alive():
    # fail-CLOSED: an empty/unrecognized get-microvm state must NOT read as alive (else a broken slot
    # lingers IDLE and is handed out).
    for resp in ({}, {"state": "weird-future-state"}):
        rt, _ = _snapstart_rt({"lambda-microvms get-microvm": resp})
        assert rt._running(AwsWorkerSlot(slot_id='s', resource_id='mv-1')) is False


def test_snapstart_readiness_describe_is_cached_during_warming():
    # is_ready (WARMING promotion, ~10Hz) must NOT issue a get-microvm per tick before the URL resolves.
    # With no endpoint in the describe, url never resolves; the describe must still be cache-throttled.
    rt, fake = _snapstart_rt({"lambda-microvms get-microvm": {"state": "pending"}},   # no endpoint yet
                            probe=lambda u, h, t: False, clock=lambda: 500.0)   # constant clock -> within TTL
    slot = AwsWorkerSlot(slot_id='s', resource_id='mv-1')
    for _ in range(10):
        rt.is_ready(slot)
    n_desc = sum(1 for k, _ in fake.calls if k == "lambda-microvms get-microvm")
    assert n_desc == 1   # 10 readiness ticks within the cache window -> a single control-plane describe


def test_snapstart_resume_wakes_and_refreshes():
    # a PARKED slot: the endpoint probe fails first (VM suspended/unreachable) -> resume() issues
    # resume-microvm, then the probe succeeds. Readiness is probe-decided, not state-decided.
    n = {"probes": 0}

    def probe(u, h, t):
        n["probes"] += 1
        return n["probes"] > 1        # first probe fails, second (post-resume) succeeds

    rt, fake = _snapstart_rt({
        "lambda-microvms get-microvm": {"state": "suspended", "endpoint": "vm.example"},
        "lambda-microvms resume-microvm": {},
        "lambda-microvms create-microvm-auth-token": {"authToken": "jwe"},
    }, probe=probe)
    slot = AwsWorkerSlot(slot_id='s', resource_id='mv-1')
    slot.auth_token = "STALE"           # a token minted while parked must be discarded
    rt.resume(slot)
    ops = [k for k, _ in fake.calls]
    assert "lambda-microvms resume-microvm" in ops        # nudged the parked slot awake after the probe failed
    assert slot.url == "https://vm.example"               # stable endpoint resolved
    assert slot.auth_token == "jwe"                       # fresh token, not STALE


def test_snapstart_warmup_throttles_failing_token_mint():
    # M2: AWS can surface the stable endpoint while a SnapStart slot is still pending, but minting needs a
    # RUNNING VM -> it fails. The ~10Hz readiness poll must NOT re-mint (and fail) every tick -- throttle it.
    clk = {"t": 100.0}
    rt, fake = _snapstart_rt({
        "lambda-microvms get-microvm": {"state": "pending", "endpoint": "vm.example"},   # endpoint pre-running
        "lambda-microvms create-microvm-auth-token": _cp(rc=254, stderr="microvm not running"),
    }, probe=lambda u, h, t: True, clock=lambda: clk["t"])
    slot = AwsWorkerSlot(slot_id="s", resource_id="mv-1")
    for _ in range(10):                    # 10 ticks 0.1s apart (~1s); throttle window = max(poll,1.0)=1.0
        assert rt.is_ready(slot) is False  # mint fails (pending) -> not ready
        clk["t"] += 0.1
    mints = sum(1 for k, _ in fake.calls if k == "lambda-microvms create-microvm-auth-token")
    assert mints <= 2   # throttled to ~1 per window, NOT one per readiness tick (10)


def test_snapstart_throttles_failing_refresh_with_cached_token():
    # #3: the mint throttle must apply even when a STALE cached token exists -- an aged token re-minted
    # past half-TTL on a never-ready/suspended slot rejects, and without this it storms the mint API every
    # tick (the first fix only covered tokenless first mints).
    clk = {"t": 100.0}
    rt, fake = _snapstart_rt({
        "lambda-microvms get-microvm": {"state": "pending", "endpoint": "vm.example"},
        "lambda-microvms create-microvm-auth-token": _cp(rc=254, stderr="microvm not running"),
    }, probe=lambda u, h, t: True, clock=lambda: clk["t"], auth_token_ttl_min=10)
    slot = AwsWorkerSlot(slot_id="s", resource_id="mv-1")
    slot.auth_token = "AGED"          # a cached token...
    slot.token_minted_at = -1e9       # ...far past half-TTL, so _ensure_token always tries to re-mint
    for _ in range(10):
        assert rt.is_ready(slot) is False
        clk["t"] += 0.1
    mints = sum(1 for k, _ in fake.calls if k == "lambda-microvms create-microvm-auth-token")
    assert mints <= 2   # throttled DESPITE the cached token (was 10 -- one per tick -- before the fix)


def test_snapstart_resume_remints_token_after_wake():
    # I4: a JWE minted while the slot is PARKED is invalid; after resume-microvm the next probe must
    # re-mint an awake token. Model: 1st mint 'jwe-parked' (probe rejects), post-resume mint 'jwe-awake'
    # (probe accepts). Without the post-resume token clear the parked token is cached+reused -> the probe
    # never passes -> resume() would time out.
    minted = {"n": 0}

    def mint(argv):
        minted["n"] += 1
        return _cp(stdout=json.dumps({"authToken": "jwe-parked" if minted["n"] == 1 else "jwe-awake"}))

    def probe(u, h, t):
        return h.get("X-aws-proxy-auth") == "jwe-awake"     # only an awake-minted token is accepted

    clk = {"t": 100.0}

    def clock():
        clk["t"] += 0.5                                     # advancing so a stuck loop RAISES, never hangs
        return clk["t"]

    rt, _ = _snapstart_rt({
        "lambda-microvms get-microvm": {"state": "suspended", "endpoint": "vm.example"},
        "lambda-microvms resume-microvm": {},
        "lambda-microvms create-microvm-auth-token": mint,
    }, probe=probe, clock=clock)
    slot = AwsWorkerSlot(slot_id='s', resource_id='mv-1')
    rt.resume(slot)                          # must NOT raise -> the post-resume re-mint let the probe pass
    assert slot.auth_token == "jwe-awake"    # the awake token survived, not the parked one
    assert minted["n"] >= 2                  # re-minted after the wake instead of reusing the parked JWE


def test_snapstart_resume_skips_resume_when_already_reachable():
    # if the very first probe succeeds (slot already RUNNING+reachable), no resume-microvm is issued.
    rt, fake = _snapstart_rt({
        "lambda-microvms get-microvm": {"state": "running", "endpoint": "vm.example"},
        "lambda-microvms create-microvm-auth-token": {"authToken": "jwe"},
    })
    slot = AwsWorkerSlot(slot_id='s', resource_id='mv-1')
    rt.resume(slot)
    assert "lambda-microvms resume-microvm" not in [k for k, _ in fake.calls]   # probe-first, already reachable


def test_snapstart_resume_wakes_stale_running_state_when_auto_resume_off():
    # the hard case: auto_resume off + get-microvm lies 'running' but the VM is actually parked. Probe
    # fails, so resume() must STILL issue resume-microvm (not trust the eventually-consistent state).
    n = {"probes": 0}

    def probe(u, h, t):
        n["probes"] += 1
        return n["probes"] > 1

    rt, fake = _snapstart_rt({
        "lambda-microvms get-microvm": {"state": "running", "endpoint": "vm.example"},   # stale/lying
        "lambda-microvms resume-microvm": {},
        "lambda-microvms create-microvm-auth-token": {"authToken": "jwe"},
    }, probe=probe, auto_resume=False)
    slot = AwsWorkerSlot(slot_id='s', resource_id='mv-1')
    rt.resume(slot)
    assert "lambda-microvms resume-microvm" in [k for k, _ in fake.calls]   # woke despite 'running' state


def test_snapstart_resume_raises_on_dead_slot():
    rt, _ = _snapstart_rt({"lambda-microvms get-microvm": {"state": "terminated"}})
    slot = AwsWorkerSlot(slot_id='s', resource_id='mv-1')
    with pytest.raises(AwsWorkerError, match="cannot resume"):
        rt.resume(slot)


def test_snapstart_resume_times_out_when_never_healthy():
    # health probe never succeeds -> resume raises after the budget instead of hanging forever. A clock
    # that advances on each call guarantees the deadline is crossed (no wall-clock sleep).
    ticks = [0.0]

    def clock():
        ticks[0] += 1.0
        return ticks[0]

    rt, _ = _snapstart_rt(
        {"lambda-microvms get-microvm": {"state": "running", "endpoint": "vm.example"},
         "lambda-microvms create-microvm-auth-token": {"authToken": "jwe"}},
        probe=lambda u, h, t: False, clock=clock, resume_timeout_s=5.0,
    )
    slot = AwsWorkerSlot(slot_id='s', resource_id='mv-1')
    with pytest.raises(AwsWorkerError, match="not ready"):
        rt.resume(slot)


def test_snapstart_config_from_env():
    env = {
        "BLASTBOX_LAMBDA_IMAGE": "arn:img",
        "BLASTBOX_LAMBDA_ALLOW_DEFAULT_EGRESS": "1",
        "BLASTBOX_LAMBDA_SNAPSTART_IDLE_S": "90",
        "BLASTBOX_LAMBDA_SNAPSTART_SUSPENDED_TTL_S": "1200",
        "BLASTBOX_LAMBDA_SNAPSTART_AUTO_RESUME": "0",
        "BLASTBOX_LAMBDA_SNAPSTART_RESUME_TIMEOUT_S": "30",
    }
    cfg = LambdaSnapStartConfig.from_env(env.get)
    assert cfg.image_identifier == "arn:img" and cfg.allow_default_egress is True   # inherited fields
    assert cfg.max_idle_duration_s == 90 and cfg.suspended_duration_s == 1200
    assert cfg.auto_resume is False and cfg.resume_timeout_s == 30.0


def test_snapstart_config_clamps_to_aws_bounds():
    # maxIdleDurationSeconds min is 60; maximum-duration ceiling is 28800 (8h). A sub-60 / over-8h value
    # must be clamped, not passed through to a per-spawn AWS reject (silent fail-never-warm).
    cfg = LambdaSnapStartConfig(region="us-east-1", image_identifier="img", allow_default_egress=True,
                                max_idle_duration_s=30, suspended_duration_s=-5, max_duration_s=999999)
    assert cfg.max_idle_duration_s == 60
    assert cfg.suspended_duration_s == 0
    assert cfg.max_duration_s == 28800


def test_snapstart_from_env_override_applies_without_collision():
    # the inherited **overrides contract must work (regression: dict-merge, not duplicate kwargs).
    cfg = LambdaSnapStartConfig.from_env(
        {"BLASTBOX_LAMBDA_IMAGE": "img", "BLASTBOX_LAMBDA_ALLOW_DEFAULT_EGRESS": "1"}.get,
        resume_timeout_s=99.0, region="us-west-2")
    assert cfg.resume_timeout_s == 99.0 and cfg.region == "us-west-2"   # base + new fields overridable


def test_snapstart_inherits_egress_failclosed():
    with pytest.raises(AwsUnavailable, match="egress"):
        LambdaSnapStartRuntime(LambdaSnapStartConfig(region="us-east-1", image_identifier="img"))


def test_snapstart_select_and_dispatch_style():
    rt = select_lambda_snapstart_runtime(
        get_env={"BLASTBOX_LAMBDA_IMAGE": "img", "BLASTBOX_LAMBDA_ALLOW_DEFAULT_EGRESS": "1"}.get)
    assert rt.kind == "aws-lambda-snapstart"
    assert rt.dispatch_style == "network"
    assert rt.ssl_context is None       # AWS public TLS + JWE, NOT the private worker CA


# --------------------------------------------------------------------------- protocol conformance

def test_both_runtimes_satisfy_slotruntime_protocol():
    lam, _ = _lambda_rt({})
    ec2, _ = _ec2_rt({})
    assert isinstance(lam, SlotRuntime)
    assert isinstance(ec2, SlotRuntime)
    # disposable: neither exposes recycle (never reuse a detonation worker)
    assert not hasattr(lam, "recycle")
    assert not hasattr(ec2, "recycle")


# --------------------------------------------------------------------------- lambda-microvm lifecycle

def test_lambda_spawn_ready_reap():
    rt, fake = _lambda_rt({
        "lambda-microvms run-microvm": {"microvmId": "mv-123"},
        "lambda-microvms get-microvm": {"state": "running", "url": "https://mv-123.lambda-url.aws/"},
        "lambda-microvms create-microvm-auth-token": {"token": "jwe.abc.def"},
        "lambda-microvms terminate-microvm": {},
    })
    slot = rt.spawn()
    assert slot.resource_id == "mv-123"
    assert slot.state == SlotState.WARMING
    assert slot.spawned_at == 100.0
    assert rt.is_ready(slot) is True
    assert slot.url == "https://mv-123.lambda-url.aws/"
    assert slot.auth_token == "jwe.abc.def"          # a fresh JWE was minted for the probe
    assert rt.is_alive(slot) is True
    rt.reap(slot)
    assert "lambda-microvms terminate-microvm" in fake.ops()


def test_lambda_not_ready_until_running():
    rt, _ = _lambda_rt({
        "lambda-microvms run-microvm": {"microvmId": "mv-9"},
        "lambda-microvms get-microvm": {"state": "pending"},   # not running yet
    })
    slot = rt.spawn()
    assert rt.is_ready(slot) is False
    assert slot.url is None


def test_lambda_ready_false_when_agent_probe_fails():
    rt, _ = _lambda_rt(
        {
            "lambda-microvms run-microvm": {"microvmId": "mv-7"},
            "lambda-microvms get-microvm": {"state": "running", "url": "https://x/"},
            "lambda-microvms create-microvm-auth-token": {"token": "t"},
        },
        probe=lambda url, hdrs, to: False,   # microVM up but agent not answering
    )
    slot = rt.spawn()
    assert rt.is_ready(slot) is False


def test_lambda_requires_image_identifier():
    with pytest.raises(AwsUnavailable):
        LambdaMicroVmRuntime(LambdaMicroVmConfig(region="us-east-1", image_identifier=""))


def test_lambda_reap_is_noop_without_resource():
    rt, fake = _lambda_rt({})
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot

    rt.reap(AwsWorkerSlot(slot_id="s", resource_id=None))
    assert "lambda-microvms terminate-microvm" not in fake.ops()


# --------------------------------------------------------------------------- ec2 lifecycle

def test_ec2_spawn_ready_reap():
    rt, fake = _ec2_rt({
        "ec2 run-instances": {"Instances": [{"InstanceId": "i-abc"}]},
        "ec2 describe-instances": {
            "Reservations": [{"Instances": [{
                "InstanceId": "i-abc", "State": {"Name": "running"}, "PrivateIpAddress": "10.0.1.5",
            }]}]
        },
        "ec2 terminate-instances": {},
    })
    slot = rt.spawn()
    assert slot.resource_id == "i-abc"
    assert rt.is_ready(slot) is True
    assert slot.ip == "10.0.1.5"
    assert slot.endpoint == ("10.0.1.5", 8765)
    assert rt.is_alive(slot) is True
    rt.reap(slot)
    assert "ec2 terminate-instances" in fake.ops()


def test_ec2_not_ready_until_running():
    rt, _ = _ec2_rt({
        "ec2 run-instances": {"Instances": [{"InstanceId": "i-9"}]},
        "ec2 describe-instances": {
            "Reservations": [{"Instances": [{"InstanceId": "i-9", "State": {"Name": "pending"}}]}]
        },
    })
    slot = rt.spawn()
    assert rt.is_ready(slot) is False
    assert slot.ip is None


def test_ec2_requires_ami():
    with pytest.raises(AwsUnavailable):
        DisposableEc2Runtime(Ec2Config(region="us-east-1", image_id=""))


# --------------------------------------------------------------------------- fail-closed availability

def test_available_true_when_creds_and_service_ok():
    rt, _ = _lambda_rt({"lambda-microvms list-microvms": {"items": []}})
    assert rt.available() is True


def test_available_false_when_no_account():
    cfg = LambdaMicroVmConfig(region="us-east-1", image_identifier="img", allow_default_egress=True)
    fake = FakeAws({"sts get-caller-identity": {}})   # no Account
    rt = LambdaMicroVmRuntime(cfg, aws_runner=fake)
    assert rt.available() is False


def test_lambda_refuses_default_egress_without_optin():
    # no egress connector + no explicit opt-in => AWS default is public internet, which would fail OPEN
    # against a no-egress net_policy. The tier must refuse to build.
    with pytest.raises(AwsUnavailable, match="egress"):
        LambdaMicroVmRuntime(LambdaMicroVmConfig(region="us-east-1", image_identifier="img"))


def test_lambda_default_egress_ok_with_connector():
    # a sealing egress connector makes it safe -> builds fine
    LambdaMicroVmRuntime(LambdaMicroVmConfig(region="us-east-1", image_identifier="img",
                                             egress_connector_ids=("e-noinet",)))


def test_lambda_readiness_token_is_cached_across_ticks():
    # is_ready() polled every ~0.1s must NOT mint a fresh JWE each tick (control-plane throttle):
    # within the token's half-TTL the slot reuses its cached token.
    rt, fake = _lambda_rt(
        {"lambda-microvms run-microvm": {"microvmId": "mv-1"},
         "lambda-microvms get-microvm": {"state": "running", "endpoint": "vm.example"},
         "lambda-microvms create-microvm-auth-token": {"authToken": "jwe"}},
    )
    slot = rt._launch()
    for _ in range(20):
        rt.is_ready(slot)
    mints = sum(1 for k, _ in fake.calls if k == "lambda-microvms create-microvm-auth-token")
    assert mints == 1            # minted once, then reused


def test_lambda_mint_token_accepts_string_and_map():
    # the live CLI returned authToken as a bare JWE string (proven: /healthz 200 with it as the header);
    # the API reference models it as a header-name -> value MAP. _mint_token must yield a usable string
    # for BOTH -- never str() a dict into a "{...}" header that would 403 every Lambda slot.
    slot = AwsWorkerSlot(slot_id="s1", resource_id="mv-1", state=SlotState.WARMING)
    rt_s, _ = _lambda_rt({"lambda-microvms create-microvm-auth-token": {"authToken": "jwe-string"}})
    assert rt_s._mint_token(slot) == "jwe-string"
    rt_m, _ = _lambda_rt({"lambda-microvms create-microvm-auth-token":
                          {"authToken": {"X-aws-proxy-auth": "jwe-in-map"}}})
    assert rt_m._mint_token(slot) == "jwe-in-map"


def test_lambda_is_alive_for_claim_refreshes_token():
    # F6: the fresh claim path bypasses is_alive() (where the JWE is refreshed), so it must re-mint the
    # token past half-TTL itself -- else a slot the background tick hasn't refreshed is handed out with an
    # aged/expired token and /detonate 403s a healthy worker.
    clock = {"t": 100.0}
    cfg = LambdaMicroVmConfig(region="us-east-1", image_identifier="arn:img",
                              allow_default_egress=True, auth_token_ttl_min=10)   # half-TTL = 300s
    fake = FakeAws({**_IDENT,
                    "lambda-microvms run-microvm": {"microvmId": "mv-1"},
                    "lambda-microvms get-microvm": {"state": "running", "endpoint": "vm.example"},
                    "lambda-microvms create-microvm-auth-token": {"authToken": "jwe"}})
    rt = LambdaMicroVmRuntime(cfg, aws_runner=fake, http_probe=lambda u, h, t: True,
                              clock=lambda: clock["t"])
    slot = rt._launch()
    rt.is_ready(slot)                                  # mints the token @ t=100
    mints0 = sum(1 for k, _ in fake.calls if k == "lambda-microvms create-microvm-auth-token")
    clock["t"] = 100.0 + 10 * 60 * 0.5 + 1             # advance just past half-TTL
    assert rt.is_alive_for_claim(slot) is True         # fresh describe -> running
    mints1 = sum(1 for k, _ in fake.calls if k == "lambda-microvms create-microvm-auth-token")
    assert mints1 == mints0 + 1                         # re-minted at hand-out


def test_lambda_claim_fails_when_token_unrefreshable():
    # O2: at CLAIM time an un-refreshable JWE means /detonate would 403 -> the claim check must FAIL so the
    # pool drops the slot, rather than hand out a known-bad credential (unlike the best-effort background poll).
    # issue #77 round 4: split by WHAT the mint failure proves. An unrecognised error does not
    # establish the token is un-refreshable, so the slot is SKIPPED (None) -- never handed out (the
    # 403 this test exists to prevent) but never destroyed either. Only a confirmed-dead answer
    # costs the slot.
    rt, _ = _lambda_rt({"lambda-microvms run-microvm": {"microvmId": "mv-1"},
                        "lambda-microvms get-microvm": {"state": "running", "endpoint": "vm.example"},
                        "lambda-microvms create-microvm-auth-token": _cp(rc=254, stderr="mint failed")})
    slot = rt._launch()
    slot.auth_token = "AGED"
    slot.token_minted_at = -1e9        # far past half-TTL -> _ensure_token re-mints (and fails)
    assert rt.is_alive_for_claim(slot) is not True, "a slot with an unmintable token must not be handed out"
    assert rt.is_alive_for_claim(slot) is None, "an UNRECOGNISED mint failure is unknown, not death"

    rt2, _ = _lambda_rt({"lambda-microvms run-microvm": {"microvmId": "mv-2"},
                         "lambda-microvms get-microvm": {"state": "running", "endpoint": "vm.example"},
                         "lambda-microvms create-microvm-auth-token":
                             _cp(rc=254, stderr="ResourceNotFoundException: microvm not found")})
    slot2 = rt2._launch()
    slot2.auth_token = "AGED"
    slot2.token_minted_at = -1e9
    assert rt2.is_alive_for_claim(slot2) is False, "a CONFIRMED dead resource must still drop the slot"


def test_snapstart_claim_does_not_fail_on_parked_token():
    # O2: SnapStart parked slots can't mint (needs RUNNING) and resume() re-mints on wake -> claim must NOT
    # fail them on a mint error (the base override would), which would reap every parked slot before resume.
    rt, fake = _snapstart_rt({
        "lambda-microvms get-microvm": {"state": "suspended"},   # parked -> alive via the base whitelist
        "lambda-microvms create-microvm-auth-token": _cp(rc=254, stderr="not running"),
    }, probe=lambda u, h, t: True)
    slot = AwsWorkerSlot(slot_id="s", resource_id="mv-1")
    slot.auth_token = "STALE"
    assert rt.is_alive_for_claim(slot) is True   # base check (suspended alive), no token touch
    assert sum(1 for k, _ in fake.calls if k == "lambda-microvms create-microvm-auth-token") == 0  # no doomed mint


def test_default_aws_runner_disables_pager(monkeypatch):
    # O3: AWS_PAGER="" must be set (with os.environ spread so creds survive) so noninteractive JSON never
    # routes through a pager -> no spawn/reap hang or non-JSON parse.
    import blastbox.host.runtime.aws_worker as awm
    captured = {}

    def fake_run(argv, **kw):  # noqa: ANN001
        captured["env"] = kw.get("env")
        return _cp(stdout="{}")

    monkeypatch.setattr(awm.subprocess, "run", fake_run)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "sentinel")
    awm._default_aws_runner(["aws", "sts", "get-caller-identity"], 5.0)
    assert captured["env"]["AWS_PAGER"] == ""                    # pager disabled
    assert captured["env"]["AWS_ACCESS_KEY_ID"] == "sentinel"    # creds preserved (os.environ spread)


def test_is_alive_for_claim_bypasses_liveness_cache():
    # a slot cached-alive by a background tick but terminated by AWS since must read DEAD at claim time,
    # so the pool drops it instead of handing a dead worker to a user job.
    state = {"v": "running"}
    rt, _ = _lambda_rt({"lambda-microvms run-microvm": {"microvmId": "mv-1"},
                        "lambda-microvms get-microvm": lambda argv: _cp(stdout=json.dumps({"state": state["v"]}))})
    slot = rt._launch()
    assert rt.is_alive(slot) is True             # cached: running
    state["v"] = "terminated"
    assert rt.is_alive(slot) is True             # STILL cached True (constant clock, within the 5s TTL)
    assert rt.is_alive_for_claim(slot) is False  # fresh describe -> dead


def test_lambda_health_describe_is_cached_across_warming_ticks():
    # while the microVM is still coming up (url unresolved), the ~10Hz readiness poll must throttle the
    # get-microvm describe to _liveness_cache_s -- otherwise every tick hits the AWS control plane.
    rt, fake = _lambda_rt(
        {"lambda-microvms run-microvm": {"microvmId": "mv-1"},
         "lambda-microvms get-microvm": {"state": "pending"}},   # never resolves -> url stays None
    )
    slot = rt._launch()
    for _ in range(10):
        assert rt.is_ready(slot) is False        # not running yet
    describes = sum(1 for k, _ in fake.calls if k == "lambda-microvms get-microvm")
    assert describes == 1        # cached across ticks (constant clock, within the 5s TTL)
    cfg = Ec2Config(region="us-east-1", image_id="ami-0")
    fake = FakeAws({**_IDENT, "ec2 describe-instances": _cp(rc=254, stderr="AccessDenied")})
    rt = DisposableEc2Runtime(cfg, aws_runner=fake)
    assert rt.available() is False


def test_select_requires_available_raises():
    fake = FakeAws({"sts get-caller-identity": {}})
    with pytest.raises(AwsUnavailable):
        select_lambda_microvm_runtime(
            cfg=LambdaMicroVmConfig(region="us-east-1", image_identifier="img", allow_default_egress=True),
            require_available=True, aws_runner=fake,
        )


# --------------------------------------------------------------------------- config from_env

def test_lambda_config_from_env():
    env = {
        "BLASTBOX_AWS_REGION": "us-west-2",
        "BLASTBOX_AWS_PROFILE": "detonate",
        "BLASTBOX_LAMBDA_IMAGE": "arn:img",
        "BLASTBOX_LAMBDA_EGRESS_CONNECTORS": "conn-1,conn-2",
        "BLASTBOX_LAMBDA_INGRESS_CONNECTORS": "ing-1",
        "BLASTBOX_LAMBDA_AUTH_TTL_MIN": "20",
    }
    cfg = LambdaMicroVmConfig.from_env(env.get)
    assert cfg.region == "us-west-2"
    assert cfg.profile == "detonate"
    assert cfg.image_identifier == "arn:img"
    assert cfg.egress_connector_ids == ("conn-1", "conn-2")
    assert cfg.ingress_connector_ids == ("ing-1",)
    assert cfg.auth_token_ttl_min == 20
    assert cfg.aws_argv("lambda-microvms", "list-microvms")[:6] == [
        "aws", "lambda-microvms", "list-microvms", "--region", "us-west-2", "--output",
    ]


def test_ec2_self_terminate_bool_spellings():
    # G4: non-canonical falsy spellings must disable the backstop (were treated as ENABLED before the
    # strip/lower fix); default (unset) + truthy spellings stay ON.
    for val in ("False", "FALSE", "NO", "No", "off", "Off", " false ", "0", "no"):
        cfg = Ec2Config.from_env({"BLASTBOX_EC2_SELF_TERMINATE": val, "BLASTBOX_EC2_AMI": "ami-x"}.get)
        assert cfg.self_terminate is False, val
    for val in ("1", "true", "yes", "on", ""):   # "" -> _env default "1"; unset also defaults ON
        cfg = Ec2Config.from_env({"BLASTBOX_EC2_SELF_TERMINATE": val, "BLASTBOX_EC2_AMI": "ami-x"}.get)
        assert cfg.self_terminate is True, val
    assert Ec2Config.from_env({"BLASTBOX_EC2_AMI": "ami-x"}.get).self_terminate is True   # unset -> ON


def test_snapstart_auto_resume_off_disables():
    # H4: "off"/"Off"/"OFF" must disable AWS platform auto-resume (parity with self_terminate); default ON.
    for val in ("off", " Off ", "OFF"):
        cfg = LambdaSnapStartConfig.from_env({"BLASTBOX_LAMBDA_SNAPSTART_AUTO_RESUME": val,
                                              "BLASTBOX_LAMBDA_IMAGE": "arn:img"}.get)
        assert cfg.auto_resume is False, val
    assert LambdaSnapStartConfig.from_env({"BLASTBOX_LAMBDA_IMAGE": "arn:img"}.get).auto_resume is True


def test_ec2_public_ip_requests_associate_flag():
    # #1: public-endpoint mode must request a public IP (a nondefault subnet defaults auto-assign off, so
    # without --associate-public-ip-address the instance gets no public address and the slot churns).
    fake = FakeAws({**_IDENT, "ec2 run-instances": {"Instances": [{"InstanceId": "i-1"}]}})
    rt = DisposableEc2Runtime(
        Ec2Config(region="us-east-1", image_id="ami-x", use_public_ip=True, allow_plaintext_public=True),
        aws_runner=fake, http_probe=lambda u, h, t: True, clock=lambda: 1.0)
    rt.spawn()
    assert "--associate-public-ip-address" in next(a for k, a in fake.calls if k == "ec2 run-instances")
    fake2 = FakeAws({**_IDENT, "ec2 run-instances": {"Instances": [{"InstanceId": "i-2"}]}})
    rt2 = DisposableEc2Runtime(Ec2Config(region="us-east-1", image_id="ami-x"),   # private-IP default
                               aws_runner=fake2, http_probe=lambda u, h, t: True, clock=lambda: 1.0)
    rt2.spawn()
    assert "--associate-public-ip-address" not in next(a for k, a in fake2.calls if k == "ec2 run-instances")


def test_ec2_public_ip_without_tls_fails_closed():
    # J3 (security): a public IP with no dispatcher TLS would send X-aws-proxy-auth + samples in cleartext
    # over the public endpoint -> fail closed at construction, unless the operator explicitly opts in.
    import ssl
    fake = FakeAws({**_IDENT})
    with pytest.raises(AwsUnavailable, match="cleartext"):
        DisposableEc2Runtime(Ec2Config(region="us-east-1", image_id="ami-x", use_public_ip=True),
                             aws_runner=fake)
    with pytest.raises(AwsUnavailable, match="cleartext"):   # hibernate tier too (shared __init__)
        Ec2HibernateRuntime(Ec2HibernateConfig(region="us-east-1", image_id="ami-x", use_public_ip=True),
                            aws_runner=fake)
    # explicit opt-out accepts plaintext:
    DisposableEc2Runtime(Ec2Config(region="us-east-1", image_id="ami-x", use_public_ip=True,
                                   allow_plaintext_public=True), aws_runner=fake)
    # a dispatcher TLS context also satisfies it (probes + /detonate go https):
    DisposableEc2Runtime(Ec2Config(region="us-east-1", image_id="ami-x", use_public_ip=True),
                         aws_runner=fake, ssl_context=ssl.create_default_context())
    # the default private-IP path never trips the guard:
    DisposableEc2Runtime(Ec2Config(region="us-east-1", image_id="ami-x"), aws_runner=fake)


def test_inject_tls_installs_mtls_probe_for_explicit_context():
    # K1: an explicit ssl_context must also get a MATCHING mTLS probe, else _health_ok probes the https
    # worker with the non-mTLS default probe (no client cert) and it never readies.
    import ssl
    from blastbox.host.runtime.aws_worker import _inject_tls
    ctx = ssl.create_default_context()
    kw = _inject_tls({}.get, {"ssl_context": ctx})
    assert kw["ssl_context"] is ctx and callable(kw.get("http_probe"))   # TLS-aware probe installed

    def sentinel(u, h, t):
        return True

    kw2 = _inject_tls({}.get, {"ssl_context": ctx, "http_probe": sentinel})
    assert kw2["http_probe"] is sentinel                                 # explicit probe preserved
    assert "http_probe" not in _inject_tls({}.get, {"ssl_context": None})  # None stays http (no probe)


def test_ec2_public_ip_bool_spellings():
    # sweep: BLASTBOX_EC2_PUBLIC_IP / _ALLOW_PLAINTEXT_PUBLIC accept the same 1/true/yes/on set (were bare ==)
    for val in ("true", "YES", "On", " 1 "):
        assert Ec2Config.from_env({"BLASTBOX_EC2_PUBLIC_IP": val, "BLASTBOX_EC2_AMI": "ami-x"}.get).use_public_ip
    for val in ("0", "false", "off", ""):
        assert not Ec2Config.from_env({"BLASTBOX_EC2_PUBLIC_IP": val, "BLASTBOX_EC2_AMI": "ami-x"}.get).use_public_ip


def test_ec2_config_from_env_defaults_arm():
    cfg = Ec2Config.from_env({"BLASTBOX_EC2_AMI": "ami-x"}.get)
    assert cfg.image_id == "ami-x"
    assert cfg.instance_type == "m7g.large"   # ARM64 default
    assert cfg.region == "us-east-1"


def test_lambda_config_clamps_to_aws_bounds():
    # AWS rejects max-duration > 28800s and auth-token TTL > 60min; the config clamps at construction
    # so an over-large operator value can't 400 every run-microvm / create-auth-token call.
    hi = LambdaMicroVmConfig(region="us-east-1", image_identifier="arn:img",
                             max_duration_s=999999, auth_token_ttl_min=120)
    assert hi.max_duration_s == 28800 and hi.auth_token_ttl_min == 60
    lo = LambdaMicroVmConfig(region="us-east-1", image_identifier="arn:img",
                             max_duration_s=0, auth_token_ttl_min=0)
    assert lo.max_duration_s == 1 and lo.auth_token_ttl_min == 1
    # SnapStart chains the same clamp via super().__post_init__()
    snap = LambdaSnapStartConfig(region="us-east-1", image_identifier="arn:img", max_duration_s=999999)
    assert snap.max_duration_s == 28800


# --------------------------------------------------------------------------- pool_config registration

def test_build_warm_pool_recognizes_aws_runtimes(monkeypatch):
    from blastbox.host import pool_config

    ec2, _ = _ec2_rt({})
    monkeypatch.setattr(
        "blastbox.host.runtime.aws_worker.select_disposable_ec2_runtime",
        lambda **kw: ec2,
    )
    monkeypatch.setenv("BLASTBOX_POOL_RUNTIME", "aws-ec2")
    monkeypatch.setenv("BLASTBOX_POOL_WARM_SIZE", "1")
    cfg = pool_config.PoolConfig.from_env()
    pool = pool_config.build_warm_pool(cfg)
    assert pool is not None


def test_snapstart_runtime_satisfies_slotruntime_protocol():
    rt, _ = _snapstart_rt({})
    assert isinstance(rt, SlotRuntime)
    assert callable(getattr(rt, "resume", None))   # the warm-claim seam the dispatcher detects


def test_pool_config_registers_snapstart(monkeypatch):
    from blastbox.host import pool_config
    ss, _ = _snapstart_rt({})
    monkeypatch.setattr("blastbox.host.runtime.aws_worker.select_lambda_snapstart_runtime",
                        lambda **kw: ss)
    got = pool_config.select_runtime_by_name("aws-lambda-snapstart", require_available=False)
    assert got is ss and got.dispatch_style == "network"


def test_ec2_select_injects_dispatch_tls_context(tmp_path):
    from blastbox.host.pki import ensure_ca
    from blastbox.host.runtime.aws_worker import select_disposable_ec2_runtime
    ensure_ca(tmp_path)  # writes ca.crt
    env = {"BLASTBOX_DISPATCH_TLS_CA": str(tmp_path / "ca.crt"), "BLASTBOX_EC2_AMI": "ami-x"}
    rt = select_disposable_ec2_runtime(get_env=env.get, require_available=False)
    assert rt.ssl_context is not None   # self-hosted EC2 agent -> worker mTLS applies


def test_lambda_select_does_not_pin_worker_ca(tmp_path):
    # Lambda talks to AWS's public https endpoint + JWE -> must NOT get the private worker CA
    from blastbox.host.pki import ensure_ca
    ensure_ca(tmp_path)
    env = {"BLASTBOX_DISPATCH_TLS_CA": str(tmp_path / "ca.crt"), "BLASTBOX_LAMBDA_IMAGE": "img-x",
           "BLASTBOX_LAMBDA_ALLOW_DEFAULT_EGRESS": "1"}
    rt = select_lambda_microvm_runtime(get_env=env.get, require_available=False)
    assert rt.ssl_context is None


def test_lambda_select_no_tls_context():
    rt = select_lambda_microvm_runtime(
        get_env={"BLASTBOX_LAMBDA_IMAGE": "img-x", "BLASTBOX_LAMBDA_ALLOW_DEFAULT_EGRESS": "1"}.get,
        require_available=False)
    assert rt.ssl_context is None


def test_lambda_cli_arg_shapes_match_live_api():
    # locked in from the live spike: connectors are (list) tokens (NOT comma-joined), and the auth
    # token needs --microvm-identifier + --expiration-in-minutes + --allowed-ports.
    cfg = LambdaMicroVmConfig(region="us-east-1", image_identifier="arn:img",
                              egress_connector_ids=("e-1", "e-2"), ingress_connector_ids=("i-1",),
                              auth_token_ttl_min=25, agent_port=8765)
    fake = FakeAws({**_IDENT,
                    "lambda-microvms run-microvm": {"microvmId": "mv-1"},
                    "lambda-microvms create-microvm-auth-token": {"token": "jwe"}})
    rt = LambdaMicroVmRuntime(cfg, aws_runner=fake, http_probe=lambda u, h, t: True, clock=lambda: 1.0)
    slot = rt.spawn()
    run_argv = next(a for k, a in fake.calls if k == "lambda-microvms run-microvm")
    i = run_argv.index("--egress-network-connectors")
    assert run_argv[i + 1:i + 3] == ["e-1", "e-2"]          # separate tokens, not "e-1,e-2"
    assert "e-1,e-2" not in run_argv
    assert "--ingress-network-connectors" in run_argv and "i-1" in run_argv
    rt._mint_token(slot)
    tok = next(a for k, a in fake.calls if k == "lambda-microvms create-microvm-auth-token")
    assert "--microvm-identifier" in tok
    assert tok[tok.index("--expiration-in-minutes") + 1] == "25"
    assert tok[tok.index("--allowed-ports") + 1] == "port=8765"   # tagged-union list shorthand


def test_lambda_endpoint_resolves_to_https():
    # live: get-microvm returns `endpoint` (bare host) + create-microvm-auth-token returns `authToken`
    rt, _ = _lambda_rt({
        "lambda-microvms run-microvm": {"microvmId": "mv-1"},
        "lambda-microvms get-microvm": {"state": "running", "endpoint": "abc.lambda-microvm.us-east-1.on.aws"},
        "lambda-microvms create-microvm-auth-token": {"authToken": "jwe.x"},
    })
    slot = rt.spawn()
    assert rt.is_ready(slot) is True
    assert slot.url == "https://abc.lambda-microvm.us-east-1.on.aws"
    assert slot.auth_token == "jwe.x"


def test_aws_runtimes_declare_network_dispatch_style():
    lam, _ = _lambda_rt({})
    ec2, _ = _ec2_rt({})
    assert lam.dispatch_style == "network" and ec2.dispatch_style == "network"


def test_ec2_forwards_agent_token():
    cfg = Ec2Config(region="us-east-1", image_id="ami-x", agent_token="tok123")
    seen: list = []
    fake = FakeAws({**_IDENT,
                    "ec2 run-instances": {"Instances": [{"InstanceId": "i-1"}]},
                    "ec2 describe-instances": {"Reservations": [{"Instances": [
                        {"InstanceId": "i-1", "State": {"Name": "running"}, "PrivateIpAddress": "10.0.0.5"}]}]}})
    rt = DisposableEc2Runtime(cfg, aws_runner=fake,
                              http_probe=lambda u, h, t: (seen.append(h) or True), clock=lambda: 1.0)
    slot = rt.spawn()
    assert slot.auth_token == "tok123"                     # forwarded to the /detonate transport
    assert rt.is_ready(slot) is True
    assert seen[-1].get("X-aws-proxy-auth") == "tok123"    # and sent in the readiness probe


# --------------------------------------------------------------------------- EC2 hibernate (warm) tier

def _hibernate_rt(*, state, healthy, clock=lambda: 100.0, **cfgkw):  # noqa: ANN001
    """state=[str] and healthy=[bool] are 1-elem lists the test mutates to drive the state machine."""
    cfg = Ec2HibernateConfig(region="us-east-1", image_id="ami-x", instance_type="t4g.nano",
                             resume_poll_s=0.0, **cfgkw)

    def describe(argv):  # noqa: ANN001 -- callable response reads the CURRENT state each call
        return _cp(stdout=json.dumps({"Reservations": [{"Instances": [
            {"InstanceId": "i-1", "State": {"Name": state[0]}, "PrivateIpAddress": "10.0.0.5"}]}]}))

    fake = FakeAws({
        **_IDENT,
        "ec2 run-instances": {"Instances": [{"InstanceId": "i-1"}]},
        "ec2 describe-instances": describe,
        "ec2 stop-instances": {},
        "ec2 start-instances": {},
    })
    rt = Ec2HibernateRuntime(cfg, aws_runner=fake, http_probe=lambda u, h, t: healthy[0], clock=clock)
    return rt, fake


def test_ec2_hibernate_launch_adds_hibernation_and_encrypted_ebs():
    rt, fake = _hibernate_rt(state=["running"], healthy=[False])
    rt._launch()
    argv = next(a for k, a in fake.calls if k == "ec2 run-instances")
    assert "--hibernation-options" in argv and "Configured=true" in argv
    joined = " ".join(argv)
    assert '"Encrypted": true' in joined or '"Encrypted":true' in joined   # encrypted root volume


def test_ec2_hibernate_state_machine_parks_a_warmed_slot():
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    state, healthy = ["running"], [False]
    rt, fake = _hibernate_rt(state=state, healthy=healthy)
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")
    assert rt.is_ready(slot) is False                       # running but agent not up
    healthy[0] = True
    assert rt.is_ready(slot) is False                       # agent up -> issues stop --hibernate
    assert any(k == "ec2 stop-instances" and "--hibernate" in a for k, a in fake.calls)
    n_hib = sum(1 for k, a in fake.calls if k == "ec2 stop-instances")
    state[0] = "stopped"
    assert rt.is_ready(slot) is True                        # hibernated -> parked -> claimable
    rt.is_ready(slot)                                       # parked stays ready, no more hibernate calls
    assert sum(1 for k, a in fake.calls if k == "ec2 stop-instances") == n_hib   # issued exactly once


def test_ec2_hibernate_tolerates_not_ready_and_throttles():
    # stop --hibernate can fail "not ready to hibernate yet" for ~1-2min after boot (ec2-hibinit-agent
    # lays down the reserve). is_ready must STAY warming + retry (throttled), never falsely advance.
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    state, healthy, ticks, hib_ok = ["running"], [True], [1000.0], [False]
    rt, fake = _hibernate_rt(state=state, healthy=healthy, clock=lambda: ticks[0])

    def stop(argv):  # noqa: ANN001
        if not hib_ok[0]:
            return _cp(rc=254, stderr="An error occurred (UnsupportedOperation): not ready to hibernate yet")
        return _cp(stdout="{}")

    fake.responses["ec2 stop-instances"] = stop
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")
    assert rt.is_ready(slot) is False                                   # attempts hibernate, not-ready -> warming
    assert sum(1 for k, a in fake.calls if k == "ec2 stop-instances") == 1
    assert rt.is_ready(slot) is False                                   # immediate retry THROTTLED
    assert sum(1 for k, a in fake.calls if k == "ec2 stop-instances") == 1   # no new attempt
    ticks[0] += 10.0
    hib_ok[0] = True
    assert rt.is_ready(slot) is False                                   # past cooldown -> retries -> succeeds
    assert sum(1 for k, a in fake.calls if k == "ec2 stop-instances") == 2
    state[0] = "stopped"
    assert rt.is_ready(slot) is True                                    # now parked


def test_ec2_hibernate_running_whitelist():
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")
    for st in ("pending", "running", "stopping", "stopped"):
        rt, _ = _hibernate_rt(state=[st], healthy=[False])
        assert rt._running(slot) is True, st                # parked (stopped) counts alive
    for st in ("shutting-down", "terminated", ""):
        rt, _ = _hibernate_rt(state=[st], healthy=[False])
        assert rt._running(slot) is False, st               # dead/unknown -> reaped


def test_ec2_hibernate_resume_starts_and_health_gates():
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    state, healthy = ["stopped"], [True]                    # already reachable-after-start in this fake
    rt, fake = _hibernate_rt(state=state, healthy=healthy)
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")
    rt.resume(slot)
    assert any(k == "ec2 start-instances" for k, a in fake.calls)   # woke the hibernated instance
    assert slot.ip == "10.0.0.5"                            # private IP resolved


def test_ec2_hibernate_resume_raises_on_terminated():
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    rt, _ = _hibernate_rt(state=["terminated"], healthy=[False])
    with pytest.raises(AwsWorkerError, match="cannot resume"):
        rt.resume(AwsWorkerSlot(slot_id="s", resource_id="i-1"))


def test_ec2_hibernate_resume_times_out():
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    ticks = [0.0]

    def clock():
        ticks[0] += 1.0
        return ticks[0]

    rt, _ = _hibernate_rt(state=["stopped"], healthy=[False], clock=clock, resume_timeout_s=5.0)
    with pytest.raises(AwsWorkerError, match="not ready"):
        rt.resume(AwsWorkerSlot(slot_id="s", resource_id="i-1"))


def test_ec2_hibernate_config_defaults_self_terminate_on():
    # the crash backstop is now DEFAULT-ON for the hibernate tier (uptime-based, so it can't fire on
    # resume), on BOTH the direct-construct and from_env paths; explicitly disable-able.
    assert Ec2HibernateConfig(region="us-east-1", image_id="a").self_terminate is True
    cfg = Ec2HibernateConfig.from_env({"BLASTBOX_EC2_AMI": "ami-x"}.get)
    assert cfg.self_terminate is True
    off = Ec2HibernateConfig.from_env({"BLASTBOX_EC2_AMI": "ami-x", "BLASTBOX_EC2_SELF_TERMINATE": "0"}.get)
    assert off.self_terminate is False
    assert cfg.root_volume_gb == 30 and cfg.root_device_name == "/dev/xvda"
    assert cfg.ready_timeout_s == 600.0 and cfg.resume_timeout_s == 180.0   # covers boot+warm+hibernate; < worker budget


def test_ec2_hibernate_backstop_is_uptime_based():
    # a wall-clock `shutdown -h +minutes` would fire on RESUME after the clock jumped; the hibernate tier
    # must arm a MONOTONIC uptime timer (systemd-run --on-active) instead, so a parked slot isn't killed.
    captured = {}

    def _run(argv):   # user-data is a 0600 file:// -> read it during the call
        val = argv[argv.index("--user-data") + 1]
        with open(val[len("file://"):]) as fh:
            captured["ud"] = fh.read()
        return _cp(stdout=json.dumps({"Instances": [{"InstanceId": "i-1"}]}))

    fake = FakeAws({**_IDENT, "ec2 run-instances": _run})
    rt = Ec2HibernateRuntime(Ec2HibernateConfig(region="us-east-1", image_id="ami-x", max_duration_s=3600),
                             aws_runner=fake, http_probe=lambda u, h, t: True, clock=lambda: 1.0)
    rt._launch()
    assert "systemd-run --on-active=3600s /sbin/shutdown -h now" in captured["ud"]   # uptime timer
    assert "shutdown -h +" not in captured["ud"]                                      # NOT wall-clock


def test_ec2_hibernate_preflight_rejects_incapable_type():
    # fail LOUD at pool build on a hibernation-incapable type instead of churning launch->stuck->reap.
    rt, fake = _hibernate_rt(state=["running"], healthy=[False])
    fake.responses["ec2 describe-instance-types"] = {"InstanceTypes": [{"HibernationSupported": False,
                                                                        "MemoryInfo": {"SizeInMiB": 2048}}]}
    fake.responses["ec2 describe-instances"] = {"Reservations": []}   # available()'s probe
    assert rt.available() is False   # _service_available raises -> available() fail-closed


def test_ec2_hibernate_preflight_rejects_undersized_root_volume():
    rt, fake = _hibernate_rt(state=["running"], healthy=[False], root_volume_gb=1)   # 1GB < 2GB RAM
    fake.responses["ec2 describe-instance-types"] = {"InstanceTypes": [{"HibernationSupported": True,
                                                                        "MemoryInfo": {"SizeInMiB": 2048}}]}
    fake.responses["ec2 describe-instances"] = {"Reservations": []}
    assert rt.available() is False   # root volume can't hold RAM -> refused


def test_ec2_hibernate_redrives_when_hibernate_does_not_take():
    # stop --hibernate accepted, but the instance lands back 'running' (async hibernate failure) -> the
    # hibernating phase must re-drive from 'warming' (re-issue stop), not sit stuck until warming_timeout.
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    state, healthy, ticks = ["running"], [True], [1000.0]
    rt, fake = _hibernate_rt(state=state, healthy=healthy, clock=lambda: ticks[0])
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")
    rt.is_ready(slot)                       # warming -> stop --hibernate -> hibernating
    assert rt._phase["s"] == "hibernating"
    # instance came back running (hibernate didn't take) -> is_ready re-drives to warming
    ticks[0] += 10.0
    assert rt.is_ready(slot) is False
    assert rt._phase["s"] == "warming"      # recovered instead of stuck


def test_ec2_hibernate_resume_refreshes_public_ip_uncached():
    # a resumed instance gets a NEW public IP; resume must re-describe uncached (not the stale cached IP).
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    ip = {"v": "1.1.1.1"}

    def describe(argv):  # noqa: ANN001
        return _cp(stdout=json.dumps({"Reservations": [{"Instances": [
            {"InstanceId": "i-1", "State": {"Name": "running"}, "PublicIpAddress": ip["v"]}]}]}))

    cfg = Ec2HibernateConfig(region="us-east-1", image_id="ami-x", use_public_ip=True, resume_poll_s=0.0,
                             allow_plaintext_public=True)   # this test exercises IP refresh, not the TLS guard
    fake = FakeAws({**_IDENT, "ec2 describe-instances": describe, "ec2 start-instances": {},
                   "ec2 stop-instances": {}})
    rt = Ec2HibernateRuntime(cfg, aws_runner=fake, http_probe=lambda u, h, t: "2.2.2.2" in u, clock=lambda: 100.0)
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")
    slot.ip = "1.1.1.1"          # stale pre-hibernate public IP
    ip["v"] = "2.2.2.2"          # AWS assigned a new one on start
    rt.resume(slot)             # must pick up 2.2.2.2 (probe only passes on the new IP)
    assert slot.ip == "2.2.2.2"


def test_ec2_hibernate_select_and_registration():
    from blastbox.host import pool_config
    rt = select_ec2_hibernate_runtime(get_env={"BLASTBOX_EC2_AMI": "ami-x"}.get)
    assert rt.kind == "aws-ec2-hibernate" and rt.dispatch_style == "network"
    hib, _ = _hibernate_rt(state=["running"], healthy=[False])
    import unittest.mock as m
    with m.patch("blastbox.host.runtime.aws_worker.select_ec2_hibernate_runtime", lambda **kw: hib):
        got = pool_config.select_runtime_by_name("aws-ec2-hibernate", require_available=False)
    assert got is hib


def test_ec2_self_terminate_ttl_injected():
    import base64

    from blastbox.host.runtime.aws_worker import _userdata_with_self_terminate
    wrapped = _userdata_with_self_terminate("#!/bin/bash\necho hi\n", 600)
    assert "shutdown -h +10" in wrapped and "echo hi" in wrapped   # 600s -> 10min; operator part kept
    # CEILING, not floor: a non-minute budget must never schedule the shutdown BEFORE max_duration_s.
    assert "shutdown -h +2" in _userdata_with_self_terminate(None, 119)   # 119s -> 2min (not 1)
    assert "shutdown -h +1" in _userdata_with_self_terminate(None, 60)    # exact minute stays 1
    # A misconfigured <=0 duration must still ARM a backstop (never emit an invalid negative timer that
    # silently fails to fire) -- both branches clamp to a positive minimum.
    assert "systemd-run --on-active=1s" in _userdata_with_self_terminate(None, -5, uptime=True)
    assert "systemd-run --on-active=1s" in _userdata_with_self_terminate(None, 0, uptime=True)
    assert "shutdown -h +1" in _userdata_with_self_terminate(None, -5)

    ud = base64.b64encode(b"#!/bin/bash\nstart-agent\n").decode()
    cfg = Ec2Config(region="us-east-1", image_id="ami-x", user_data_b64=ud, max_duration_s=1800)
    captured = {}

    def _run(argv):   # user-data is passed as a 0600 file:// (out of argv) -> read it DURING the call
        val = argv[argv.index("--user-data") + 1]
        assert val.startswith("file://")                       # secret is NOT a raw argv element
        path = val[len("file://"):]
        assert (os.stat(path).st_mode & 0o777) == 0o600        # created 0600 (O_EXCL)
        with open(path) as fh:
            captured["ud"] = fh.read()
        return _cp(stdout=json.dumps({"Instances": [{"InstanceId": "i-1"}]}))

    fake = FakeAws({**_IDENT, "ec2 run-instances": _run})
    rt = DisposableEc2Runtime(cfg, aws_runner=fake, http_probe=lambda u, h, t: True, clock=lambda: 1.0)
    rt.spawn()
    argv = next(a for k, a in fake.calls if k == "ec2 run-instances")
    assert not any("start-agent" in str(a) for a in argv)      # the bootstrap secret never hits argv (/proc)
    assert "shutdown -h +30" in captured["ud"] and "start-agent" in captured["ud"]  # ...but is in the file
    ud_path = argv[argv.index("--user-data") + 1][len("file://"):]
    assert not os.path.exists(ud_path)                          # temp file unlinked after the call


def test_userdata_preserves_cloudinit_part_types():
    # L3: a single-part cloud-init payload keeps its own format (docstring promise) -- #cloud-boothook /
    # #include / #part-handler must NOT be wrapped as x-shellscript (cloud-init would mis-run them and the
    # worker agent never starts). #!shebang + #cloud-config stay as they were.
    from email import message_from_string

    from blastbox.host.runtime.aws_worker import _userdata_with_self_terminate
    cases = [
        ("#cloud-boothook\nfoo\n", "text/cloud-boothook"),
        ("#include\nhttp://x/y\n", "text/x-include-url"),
        ("#include-once\nhttp://x/y\n", "text/x-include-once-url"),
        ("#part-handler\ndef list_types():\n    pass\n", "text/part-handler"),
        ("#!/bin/bash\necho hi\n", "text/x-shellscript"),          # shebang default unchanged
        ("#cloud-config\nruncmd:\n  - x\n", "text/cloud-config"),  # cloud-config unchanged
    ]
    for raw, expected in cases:
        parts = message_from_string(_userdata_with_self_terminate(raw, 600)).get_payload()
        assert parts[0].get_content_type() == expected, raw          # operator part keeps its type
        assert parts[1].get_content_type() == "text/x-shellscript"   # TTL part stays a shell script
        assert "shutdown -h +10" in parts[1].get_payload()


def test_ec2_self_terminate_preserves_multipart_userdata():
    # if the operator user-data is ALREADY MIME multipart cloud-init, the TTL is APPENDED as a part,
    # not nested (which would make cloud-init treat the whole document as one opaque script).
    from email import message_from_string

    from blastbox.host.runtime.aws_worker import _userdata_with_self_terminate
    multipart = (
        "Content-Type: multipart/mixed; boundary=\"BOUND\"\n"
        "MIME-Version: 1.0\n\n"
        "--BOUND\n"
        "Content-Type: text/cloud-config\n\n"
        "#cloud-config\nruncmd:\n  - echo original\n\n"
        "--BOUND--\n"
    )
    wrapped = _userdata_with_self_terminate(multipart, 600)
    msg = message_from_string(wrapped)
    payloads = [p.get_payload() for p in msg.get_payload()] if msg.is_multipart() else []
    assert msg.is_multipart()
    assert any("echo original" in p for p in payloads)          # operator part preserved as its own part
    assert any("shutdown -h +10" in p for p in payloads)        # TTL appended alongside, not nesting it


def test_ec2_self_terminate_can_be_disabled():
    cfg = Ec2Config(region="us-east-1", image_id="ami-x", max_duration_s=1800, self_terminate=False)
    fake = FakeAws({**_IDENT, "ec2 run-instances": {"Instances": [{"InstanceId": "i-1"}]}})
    rt = DisposableEc2Runtime(cfg, aws_runner=fake, http_probe=lambda u, h, t: True, clock=lambda: 1.0)
    rt.spawn()
    argv = next(a for k, a in fake.calls if k == "ec2 run-instances")
    assert "--user-data" not in argv   # opted out -> no injected TTL, no user-data


# ---- aws-ec2-hibernate orphan sweep ------------------------------------------------------


def _gmt_epoch(s):  # noqa: ANN001  "YYYY-MM-DD HH:MM:SS" GMT -> epoch seconds
    import datetime as _dt
    return _dt.datetime.strptime(s, "%Y-%m-%d %H:%M:%S").replace(tzinfo=_dt.timezone.utc).timestamp()


def _sweep_rt(orphan_max_age_s=3600.0):  # noqa: ANN001
    cfg = Ec2HibernateConfig(region="us-east-1", image_id="ami-x", orphan_max_age_s=orphan_max_age_s)
    fake = FakeAws({**_IDENT,
                    "ec2 describe-instances": {"Reservations": []},
                    "ec2 terminate-instances": {}})
    rt = Ec2HibernateRuntime(cfg, aws_runner=fake, clock=lambda: 100.0)
    return rt, fake


def _stopped_inst(iid, run_tag, when="2026-07-11 00:00:00"):  # noqa: ANN001
    return {"InstanceId": iid, "State": {"Name": "stopped"},
            "StateTransitionReason": f"User initiated ({when} GMT)",
            "Tags": [{"Key": "blastbox-tier", "Value": "aws-ec2-hibernate"},
                     {"Key": "blastbox-run", "Value": run_tag}]}


def _set_instances(fake, instances):  # noqa: ANN001
    fake.responses["ec2 describe-instances"] = {"Reservations": [{"Instances": instances}]}


def test_orphan_sweep_terminates_leaked_stopped_slot():
    rt, fake = _sweep_rt(orphan_max_age_s=3600.0)
    _set_instances(fake, [_stopped_inst("i-old", "some-dead-run")])
    killed = rt.sweep_orphans(now=_gmt_epoch("2026-07-11 00:00:00") + 7200)  # 2h old > 1h max
    assert killed == ["i-old"]
    assert any(k == "ec2 terminate-instances" and "i-old" in a for k, a in fake.calls)


def test_orphan_sweep_skips_our_own_live_parked_slot():
    rt, fake = _sweep_rt(orphan_max_age_s=3600.0)
    _set_instances(fake, [_stopped_inst("i-mine", rt._run_id)])  # carries OUR run id
    killed = rt.sweep_orphans(now=_gmt_epoch("2026-07-11 00:00:00") + 7200)
    assert killed == []
    assert not any(k == "ec2 terminate-instances" for k, _ in fake.calls)


def test_orphan_sweep_skips_too_young():
    rt, fake = _sweep_rt(orphan_max_age_s=3600.0)
    _set_instances(fake, [_stopped_inst("i-young", "some-dead-run")])
    killed = rt.sweep_orphans(now=_gmt_epoch("2026-07-11 00:00:00") + 60)  # 60s < 1h max
    assert killed == []


def test_orphan_sweep_skips_unparseable_stopped_time():
    # Fail-safe: a missing/unparseable StateTransitionReason must be treated as "too young" and
    # SKIPPED -- we must NOT fall back to LaunchTime (creation time), which would over-age a
    # recently-stopped but long-lived slot and terminate it prematurely.
    rt, fake = _sweep_rt(orphan_max_age_s=3600.0)
    _set_instances(fake, [{
        "InstanceId": "i-weird", "State": {"Name": "stopped"},
        "StateTransitionReason": "User initiated",          # no "(YYYY-MM-DD HH:MM:SS GMT)"
        "LaunchTime": "2020-01-01T00:00:00Z",                # ancient — must NOT be used
        "Tags": [{"Key": "blastbox-tier", "Value": "aws-ec2-hibernate"},
                 {"Key": "blastbox-run", "Value": "some-dead-run"}],
    }])
    killed = rt.sweep_orphans(now=_gmt_epoch("2026-07-11 00:00:00") + 7200)
    assert killed == []
    assert not any(k == "ec2 terminate-instances" for k, _ in fake.calls)


def test_orphan_sweep_disabled_when_max_age_zero():
    rt, fake = _sweep_rt(orphan_max_age_s=0.0)
    _set_instances(fake, [_stopped_inst("i-old", "some-dead-run")])
    assert rt.sweep_orphans(now=_gmt_epoch("2026-07-11 00:00:00") + 99999) == []
    assert "ec2 describe-instances" not in fake.ops()  # no calls at all when disabled


def test_orphan_sweep_nan_max_age_is_disabled():
    # float("nan") passes `max_age <= 0` as False AND `age < max_age` as False, which would
    # terminate EVERY stopped slot. A NaN age must be treated as disabled (no describe/terminate).
    rt, fake = _sweep_rt(orphan_max_age_s=float("nan"))
    _set_instances(fake, [_stopped_inst("i-old", "some-dead-run")])
    assert rt.sweep_orphans(now=_gmt_epoch("2026-07-11 00:00:00") + 99999) == []
    assert "ec2 describe-instances" not in fake.ops()


def test_orphan_sweep_swallows_terminate_error_and_continues():
    rt, fake = _sweep_rt(orphan_max_age_s=3600.0)
    _set_instances(fake, [_stopped_inst("i-a", "dead"), _stopped_inst("i-b", "dead")])

    def term(argv):
        return _cp(rc=254, stderr="boom") if "i-a" in argv else _cp(stdout="{}")

    fake.responses["ec2 terminate-instances"] = term
    killed = rt.sweep_orphans(now=_gmt_epoch("2026-07-11 00:00:00") + 7200)
    assert killed == ["i-b"]   # i-a failed but the sweep kept going


def test_orphan_sweep_filters_by_tier_and_stopped_state():
    rt, fake = _sweep_rt(orphan_max_age_s=3600.0)
    rt.sweep_orphans(now=1.0)
    argv = next(a for k, a in fake.calls if k == "ec2 describe-instances")
    assert "Name=tag:blastbox-tier,Values=aws-ec2-hibernate" in argv
    assert "Name=instance-state-name,Values=stopping,stopped" in argv


def test_orphan_sweep_dry_run_lists_without_terminating():
    rt, fake = _sweep_rt(orphan_max_age_s=3600.0)
    _set_instances(fake, [_stopped_inst("i-old", "dead")])
    killed = rt.sweep_orphans(now=_gmt_epoch("2026-07-11 00:00:00") + 7200, dry_run=True)
    assert killed == ["i-old"]
    assert not any(k == "ec2 terminate-instances" for k, _ in fake.calls)


def test_orphan_max_age_from_env():
    cfg = Ec2HibernateConfig.from_env({"BLASTBOX_EC2_ORPHAN_MAX_AGE_S": "3600"}.get)
    assert cfg.orphan_max_age_s == 3600.0
    assert Ec2HibernateConfig.from_env({}.get).orphan_max_age_s == 0.0  # default off


def test_launch_tags_include_tier_and_run_fence():
    cfg = Ec2Config(region="us-east-1", image_id="ami-x")
    fake = FakeAws({**_IDENT,
                    "ec2 run-instances": {"Instances": [{"InstanceId": "i-1"}]},
                    "ec2 describe-instances": {"Reservations": [{"Instances": [
                        {"InstanceId": "i-1", "State": {"Name": "running"}, "PrivateIpAddress": "10.0.0.5"}]}]}})
    rt = DisposableEc2Runtime(cfg, aws_runner=fake, http_probe=lambda u, h, t: True, clock=lambda: 1.0)
    rt.spawn()
    argv = next(a for k, a in fake.calls if k == "ec2 run-instances")
    tagspec = argv[argv.index("--tag-specifications") + 1]
    assert "Key=blastbox-tier,Value=aws-ec2" in tagspec
    assert f"Key=blastbox-run,Value={rt._run_id}" in tagspec


def test_claim_probe_uses_a_short_cli_budget_background_calls_do_not():
    # issue #77: the claim-time hand-out probe is on job-dispatch latency and holds the dispatcher's
    # warm-gate reservation (#72), so it must NOT wait out cli_timeout_s (120s) during a
    # control-plane brownout. It runs under claim_probe_timeout_s; every other call (background
    # health tick, terminate) keeps the full budget — a slow terminate isn't a latency problem.
    rt, _fake = _lambda_rt({"lambda-microvms run-microvm": {"microvmId": "mv-1"},
                            "lambda-microvms get-microvm": {"state": "running"}})
    slot = rt._launch()

    seen: list[float] = []
    real = rt._run_aws

    def _spy(argv, timeout):        # noqa: ANN001
        seen.append(timeout)
        return real(argv, timeout)

    rt._run_aws = _spy              # type: ignore[method-assign]

    seen.clear()
    rt.is_alive_for_claim(slot)
    assert seen, "claim probe issued no aws call"
    # each call gets what remains of the WHOLE-probe deadline (<= the budget, > 0)
    assert all(0 < t <= rt.cfg.claim_probe_timeout_s for t in seen), (
        f"claim probe used {seen}, want <= {rt.cfg.claim_probe_timeout_s}s")
    assert rt.cfg.claim_probe_timeout_s < rt.cfg.cli_timeout_s

    seen.clear()
    rt._desc_cache.pop(slot.slot_id, None)      # force a fresh background describe
    rt._live_cache.pop(slot.slot_id, None)
    rt.is_alive(slot)
    assert seen, "background liveness issued no aws call"
    # background is bounded too (issue #77 — it runs on the single tick thread), but by the
    # GENEROUS health budget, never the tight claim budget.
    assert all(0 < t <= rt.cfg.health_probe_timeout_s for t in seen), seen
    assert all(t > rt.cfg.claim_probe_timeout_s for t in seen), (
        f"background call inherited the CLAIM budget: {seen}")


def test_claim_probe_budget_is_thread_local_not_shared():
    # issue #77 (review): the design's headline safety property — a claim probe must NOT shorten
    # the budget of concurrent calls on OTHER threads — had zero coverage: swapping
    # threading.local() for a shared namespace left the suite green. With a shared attribute a
    # `terminate-instances` issued by the tick thread WHILE a probe is in flight would silently drop
    # from cli_timeout_s to the probe budget, raise, and LEAK a live worker.
    import threading

    in_probe = threading.Event()
    release = threading.Event()
    rt, _fake = _lambda_rt({"lambda-microvms run-microvm": {"microvmId": "mv-1"},
                            "lambda-microvms get-microvm": {"state": "running"}})
    slot = rt._launch()

    seen: list[tuple[str, float]] = []
    real = rt._run_aws

    def _spy(argv, timeout):        # noqa: ANN001
        seen.append((argv[2], timeout))
        if argv[2] == "get-microvm":          # inside the claim probe
            in_probe.set()
            release.wait(10)                  # hold the probe OPEN
        return real(argv, timeout)

    rt._run_aws = _spy              # type: ignore[method-assign]

    probe = threading.Thread(target=lambda: rt.is_alive_for_claim(slot), daemon=True)
    probe.start()
    assert in_probe.wait(5), "probe never started"
    try:
        # concurrent call on ANOTHER thread, while the probe holds its budget open
        rt._desc_cache.pop(slot.slot_id, None)
        rt._live_cache.pop(slot.slot_id, None)
        other: list[float] = []
        t = threading.Thread(target=lambda: (rt.is_alive(slot), other.extend(
            [to for op, to in seen if op == "get-microvm"][-1:])), daemon=True)
        t.start()
        t.join(5)
        concurrent = [to for op, to in seen[1:]]
        assert concurrent, "the concurrent call issued no aws call"
        assert all(to > rt.cfg.claim_probe_timeout_s for to in concurrent), (
            f"a concurrent call inherited the CLAIM probe budget: {concurrent}")
    finally:
        release.set()
        probe.join(5)


def test_claim_probe_budget_is_restored_not_cleared():
    # issue #77 (review): the scope must SAVE/RESTORE. A hard reset to None let a nested probe wipe
    # an outer scope's budget — which is exactly how the JWE re-mint escaped the bound and ran at
    # the full cli_timeout_s on the claim path.
    rt, _fake = _lambda_rt({"lambda-microvms run-microvm": {"microvmId": "mv-1"},
                            "lambda-microvms get-microvm": {"state": "running"}})
    with rt._claim_probe_budget():
        outer = rt._tls.probe_deadline
        assert outer is not None
        with rt._claim_probe_budget():
            assert rt._tls.probe_deadline is not None
        assert rt._tls.probe_deadline == outer, "nested scope clobbered the outer deadline"
    assert getattr(rt._tls, "probe_deadline", None) is None


def test_aws_config_positional_binding_is_stable():
    # issue #77 (review): claim_probe_timeout_s was inserted MID-dataclass, so a positional caller's
    # later fields silently rebound (the same trap PoolSpec.queued hit). Declared last now — lock it.
    cfg = AwsWorkerConfig("us-east-1", "prof", 9999, "/hz", 11.0, 12.0, 13.0, 14.0)
    assert cfg.region == "us-east-1" and cfg.profile == "prof"
    assert cfg.agent_port == 9999 and cfg.agent_health_path == "/hz"
    assert (cfg.ready_timeout_s, cfg.probe_timeout_s) == (11.0, 12.0)
    assert (cfg.cli_timeout_s, cfg.max_duration_s) == (13.0, 14.0)
    assert cfg.claim_probe_timeout_s == 5.0          # trailing field keeps its default


def test_claim_probe_timeout_reports_unknown_not_dead():
    # issue #77 (review, HIGH): a claim probe that TIMES OUT must report UNKNOWN, never False.
    # False would make the pool defer the slot for disposal — destroying a possibly-healthy microVM
    # because the control plane was slow, which is far worse than a missed claim.
    import subprocess

    def _timeout_runner(argv, timeout):     # noqa: ANN001
        raise subprocess.TimeoutExpired(cmd=argv, timeout=timeout)

    rt, _fake = _lambda_rt({"lambda-microvms run-microvm": {"microvmId": "mv-1"},
                            "lambda-microvms get-microvm": {"state": "running"}})
    slot = rt._launch()
    rt._run_aws = _timeout_runner           # type: ignore[method-assign]
    assert rt.is_alive_for_claim(slot) is None, "a probe timeout must be UNKNOWN, not dead"

    # An OSError is the HOST failing to start `aws` (missing binary, EMFILE, ENOMEM) -- it is not a
    # verdict about the worker at all, and it hits every slot and thread at once, so reading it as
    # death wipes the tier. This assertion used to demand exactly that (issue #77 marla-loop).
    def _boom(argv, timeout):               # noqa: ANN001
        raise OSError("no such binary")
    rt._run_aws = _boom                     # type: ignore[method-assign]
    assert rt.is_alive_for_claim(slot) is None, "a host-side exec failure is UNKNOWN, not death"

    # ...while a CONFIRMED answer from AWS is still a definite False.
    def _gone(argv, timeout):               # noqa: ANN001
        return _cp(rc=254, stderr="An error occurred (ResourceNotFoundException): no such microvm")
    rt._run_aws = _gone                     # type: ignore[method-assign]
    assert rt.is_alive_for_claim(slot) is False


def test_probe_timeout_is_an_aws_worker_error_subclass():
    # issue #77 (self-review): AwsProbeTimeout is raised from inside _aws, which sits under ~16
    # `except AwsWorkerError` handlers across this module. As a bare RuntimeError it would have
    # ESCAPED all of them — a brownout would surface as an unhandled crash (or, via the pool's
    # `except Exception`, as "dead" -> destroying a healthy worker). Subclassing keeps every
    # existing handler working while is_alive_for_claim catches the specific type first.
    assert issubclass(AwsProbeTimeout, AwsWorkerError)


def test_claim_mint_timeout_reports_unknown_not_unusable():
    # issue #77 (self-review): the JWE re-mint runs INSIDE the claim budget, and its handler
    # returned False ("un-refreshable token -> unusable slot"). A TIMEOUT there is a control-plane
    # brownout, not an unusable worker, so it must report UNKNOWN — otherwise the pool defers a
    # perfectly healthy microVM for disposal.
    import subprocess

    rt, _fake = _lambda_rt({"lambda-microvms run-microvm": {"microvmId": "mv-1"},
                            "lambda-microvms get-microvm": {"state": "running", "endpoint": "h.x"},
                            "lambda-microvms create-microvm-auth-token": {"authToken": "jwe"}})
    slot = rt._launch()
    slot.auth_token = "old"
    slot.token_minted_at = -1e9                 # force a re-mint at hand-out

    real = rt._run_aws

    def _timeout_the_mint(argv, timeout):       # noqa: ANN001
        if "create-microvm-auth-token" in argv:
            raise subprocess.TimeoutExpired(cmd=argv, timeout=timeout)
        return real(argv, timeout)

    rt._run_aws = _timeout_the_mint             # type: ignore[method-assign]
    assert rt.is_alive_for_claim(slot) is None, "a mint timeout must be UNKNOWN, not unusable"


def test_claim_probe_budget_is_shared_across_the_whole_probe():
    # issue #77 (review): the budget must bound the probe AS A WHOLE, not each call. A describe at
    # 4.9s followed by a token mint at 4.9s would otherwise take ~9.8s while holding the warm-gate
    # reservation, blowing a claim(timeout_s=2) contract by ~5x. Uses an ADVANCING clock — the
    # module's default fixture freezes time, which would hide exactly this.
    now = {"t": 1000.0}
    cfg = LambdaMicroVmConfig(region="us-east-1", image_identifier="arn:img",
                              allow_default_egress=True)
    fake = FakeAws({**_IDENT,
                    "lambda-microvms run-microvm": {"microvmId": "mv-1"},
                    "lambda-microvms get-microvm": {"state": "running", "endpoint": "h.x"},
                    "lambda-microvms create-microvm-auth-token": {"authToken": "jwe"}})
    rt = LambdaMicroVmRuntime(cfg, aws_runner=fake, http_probe=lambda u, h, t: True,
                              clock=lambda: now["t"])
    slot = rt._launch()
    slot.auth_token = "old"
    slot.token_minted_at = -1e9                  # force the re-mint inside the same probe

    budgets: list[float] = []
    real = rt._run_aws

    def _spy(argv, timeout):                     # noqa: ANN001
        budgets.append(timeout)
        now["t"] += 3.0                          # each call burns 3s of the probe's deadline
        return real(argv, timeout)

    rt._run_aws = _spy                           # type: ignore[method-assign]
    rt.is_alive_for_claim(slot)

    assert len(budgets) >= 2, f"expected describe + mint, got {budgets}"
    assert budgets[1] < budgets[0], (
        f"second call got a fresh budget instead of the remainder: {budgets}")
    assert sum(3.0 for _ in budgets) <= rt.cfg.claim_probe_timeout_s + 3.0, budgets


def test_subclass_config_positional_binding_survives_the_new_base_field():
    # issue #77 (review): dataclass inheritance appends SUBCLASS fields AFTER the base's, so adding
    # claim_probe_timeout_s to the BASE — even "last" — still inserted it BEFORE image_identifier &
    # friends, silently rebinding positional subclass calls. kw_only takes it out of positional
    # ordering entirely. (This is the same trap PoolSpec.queued hit, one inheritance level up.)
    cfg = LambdaMicroVmConfig("us-east-1", "prof", 8765, "/hz", 300.0, 5.0, 120.0, 3600.0, "arn:img")
    assert cfg.image_identifier == "arn:img", "the new base field rebound a subclass field"
    assert cfg.max_duration_s == 3600.0
    assert cfg.claim_probe_timeout_s == 5.0


def test_transient_control_plane_answer_is_unknown_not_dead():
    # issue #77 sweep: bounding the call by TIME missed the most likely brownout of all — a throttle
    # ANSWERS. The aws CLI exits 255 (never TimeoutExpired) for ThrottlingException /
    # RequestLimitExceeded / 503 / "Could not connect to the endpoint", so those landed in
    # `alive = False` and the health tick terminated the whole tier.
    import subprocess

    for stderr in ("An error occurred (ThrottlingException) ... Rate exceeded",
                   "An error occurred (RequestLimitExceeded)",
                   "Could not connect to the endpoint URL: https://ec2.us-east-1.amazonaws.com/",
                   "An error occurred (ServiceUnavailable) ... 503"):
        runner = lambda argv, timeout, _e=stderr: subprocess.CompletedProcess(  # noqa: E731
            list(argv), 255, "", _e)
        rt = LambdaMicroVmRuntime(
            LambdaMicroVmConfig(region="us-east-1", image_identifier="arn:x",
                                allow_default_egress=True),
            aws_runner=runner)
        slot = AwsWorkerSlot(slot_id="s1", resource_id="mv-1")
        assert rt.is_alive_for_claim(slot) is None, f"{stderr!r} read as DEAD at claim"
        # UNKNOWN, not True (issue #77 marla-loop): the pool still KEEPS the slot -- that is the
        # #77 guarantee and it is unchanged -- but reporting honestly is what lets the pool bound
        # how long "we can't tell" may keep a slot alive. Masking it as True made that impossible.
        assert rt.is_alive(slot) is None, f"{stderr!r} read as a definitive verdict on the health tick"
        assert rt.is_alive(slot) is not False, f"{stderr!r} read as DEAD on the health tick"
        # The cache may hold the UNKNOWN verdict -- that is what throttles re-probing to once per
        # _liveness_cache_s instead of once per ~0.1s tick (measured: 20 aws invocations where 1 was
        # expected, for the whole brownout, on every slot). What it must NEVER hold is a DEFINITIVE
        # verdict manufactured from a transient failure; that is the poisoning this guards.
        assert all(v is None for _ts, v in rt._live_cache.values()), (
            f"{stderr!r} poisoned the liveness cache with a definitive verdict: {rt._live_cache}")

    # ...while a DEFINITIVE negative is still definitive
    gone = lambda argv, timeout: subprocess.CompletedProcess(  # noqa: E731
        list(argv), 255, "", "An error occurred (ResourceNotFoundException): microvm not found")
    rt2 = LambdaMicroVmRuntime(
        LambdaMicroVmConfig(region="us-east-1", image_identifier="arn:x", allow_default_egress=True),
        aws_runner=gone)
    assert rt2.is_alive_for_claim(AwsWorkerSlot(slot_id="s2", resource_id="mv-2")) is False


def test_every_tier_clamps_non_positive_probe_budgets():
    # issue #77 (codex): the clamp had landed on LambdaMicroVmConfig, and that class's own
    # __post_init__ never chained to the base — so EC2 never got it and the lambda tiers only got
    # it by accident. A 0 makes the probe deadline already-expired: every claim reports UNKNOWN,
    # no AWS slot is ever claimable, and the tier stays green in metrics. Check ALL tiers.
    for cls, kw in ((LambdaMicroVmConfig, {"image_identifier": "i"}),
                    (LambdaSnapStartConfig, {"image_identifier": "i"}),
                    (Ec2Config, {"image_id": "ami-0"})):
        cfg = cls(region="us-east-1", claim_probe_timeout_s=0, health_probe_timeout_s=-5, **kw)
        assert cfg.claim_probe_timeout_s > 0, f"{cls.__name__} would brick: claim budget 0"
        assert cfg.health_probe_timeout_s > 0, f"{cls.__name__} health budget non-positive"


# ------------------------------------------------- issue #77 round 2: escalated-review regressions
# Every test below FAILS against the code as first written; each pins one finding from the
# gpt-5.6-sol/ultra pass on PR #78. The theme is the same invariant, at sites the delta review
# could not see: "the control plane didn't answer" must never be read as "this worker is dead".


def _timeout(argv):  # noqa: ANN001
    raise subprocess.TimeoutExpired(cmd="aws", timeout=120)


class RecordingAws(FakeAws):
    """FakeAws that also records the per-call timeout the runtime asked for."""

    def __init__(self, responses: dict) -> None:
        super().__init__(responses)
        self.timeouts: list[tuple[str, float]] = []

    def __call__(self, argv, timeout):  # noqa: ANN001
        self.timeouts.append((f"{list(argv)[1]} {list(argv)[2]}", timeout))
        return super().__call__(argv, timeout)

    def timeout_for(self, key: str) -> float:
        return next(t for k, t in self.timeouts if k == key)


def test_f1_cli_timeout_outside_a_probe_budget_is_unknown_not_dead():
    """A resume-time timeout has NO probe budget in scope, so it used to raise a plain
    AwsWorkerError whose message ("timed out after 120s") matched no transient marker --
    so _resume_on_claim dirty-released and TERMINATED a healthy PARKED SnapStart worker."""
    from blastbox.host.runtime.vm_dispatch import _is_unknown_not_dead

    rt, _ = _snapstart_rt({"lambda-microvms get-microvm": _timeout})
    with pytest.raises(AwsWorkerError) as ei:
        rt._aws("lambda-microvms", "get-microvm", "--microvm-identifier", "mv-1")
    assert _is_unknown_not_dead(ei.value), (
        "a CLI timeout is 'the control plane did not answer' -- UNKNOWN, never confirmed death")


def test_f1_transient_rc_outside_a_probe_budget_is_unknown_not_dead():
    """Same for a throttle that exits non-zero outside a probe (resume() has no budget of its own)."""
    from blastbox.host.runtime.vm_dispatch import _is_unknown_not_dead

    rt, _ = _snapstart_rt({"lambda-microvms get-microvm": _cp(rc=255, stderr="ThrottlingException: Rate exceeded")})
    with pytest.raises(AwsWorkerError) as ei:
        rt._aws("lambda-microvms", "get-microvm", "--microvm-identifier", "mv-1")
    assert _is_unknown_not_dead(ei.value)


def test_f1_a_confirmed_dead_verdict_is_still_dead():
    """The widening must NOT soften a real terminal answer -- otherwise dead slots leak forever."""
    from blastbox.host.runtime.vm_dispatch import _is_unknown_not_dead

    rt, _ = _snapstart_rt({"lambda-microvms get-microvm": _cp(rc=254, stderr="ResourceNotFoundException: no such microvm")})
    with pytest.raises(AwsWorkerError) as ei:
        rt._aws("lambda-microvms", "get-microvm", "--microvm-identifier", "mv-1")
    assert not _is_unknown_not_dead(ei.value)


@pytest.mark.parametrize("stderr", [
    "An error occurred (InternalServerException) when calling the GetMicrovm operation",
    "InternalServerException: Internal server error",
    "An error occurred (500) when calling: Internal Server Error",
])
def test_f2_internal_server_exception_is_transient(stderr):
    """AWS 5xx must never read as a dead worker. Round 2 fixed this by ADDING spellings to a
    denylist; round 4 inverted the default so no spelling is required at all."""
    from blastbox.host.runtime.aws_worker import _is_confirmed_dead_aws_error
    assert not _is_confirmed_dead_aws_error(stderr)


def test_f2_resource_not_found_is_not_transient():
    """Guard: a definitive "no such resource" must STILL cost the slot, or husks leak forever."""
    from blastbox.host.runtime.aws_worker import _is_confirmed_dead_aws_error
    assert _is_confirmed_dead_aws_error("ResourceNotFoundException: Function not found")


def test_f4_health_path_token_mint_honours_the_health_budget():
    """LambdaMicroVmRuntime.is_alive minted the JWE AFTER super().is_alive() had exited the
    health-probe scope, so the mint ran at cli_timeout_s (120s) instead of health_probe_timeout_s.
    One unresponsive mint then stalled the single pool tick thread for 2 minutes PER SLOT."""
    cfg = LambdaMicroVmConfig(region="us-east-1", image_identifier="arn:aws:lambda:us-east-1:aws:microvm-image:x",
                              allow_default_egress=True, health_probe_timeout_s=3.0, cli_timeout_s=120.0)
    fake = RecordingAws({**_IDENT,
                         "lambda-microvms get-microvm": {"state": "RUNNING"},
                         "lambda-microvms create-microvm-auth-token": {"authToken": "jwe-new"}})
    rt = LambdaMicroVmRuntime(cfg, aws_runner=fake, http_probe=lambda u, h, t: True, clock=lambda: 100.0)
    slot = AwsWorkerSlot(slot_id="s1", state=SlotState.IDLE, resource_id="mv-1",
                         url="http://10.0.0.1:8080", auth_token="jwe-old")
    slot.token_minted_at = -1000.0   # far past half-TTL -> forces a re-mint
    rt.is_alive(slot)
    minted = fake.timeout_for("lambda-microvms create-microvm-auth-token")
    assert minted <= cfg.health_probe_timeout_s, (
        f"mint ran at {minted}s, outside the {cfg.health_probe_timeout_s}s health budget")


def test_f5_claim_probe_never_outruns_the_callers_claim_deadline():
    """claim(timeout_s=0.5) with claim_probe_timeout_s=5 blocked ~5s -- a 10x contract violation
    that also held the dispatcher's warm-gate reservation for the overrun."""
    cfg = LambdaSnapStartConfig(region="us-east-1", image_identifier="arn:img", allow_default_egress=True,
                                resume_poll_s=0.0, claim_probe_timeout_s=5.0, cli_timeout_s=120.0)
    fake = RecordingAws({**_IDENT, "lambda-microvms get-microvm": {"Microvm": {"State": "RUNNING"}}})
    rt = LambdaSnapStartRuntime(cfg, aws_runner=fake, http_probe=lambda u, h, t: True, clock=lambda: 100.0)
    slot = AwsWorkerSlot(slot_id="s1", state=SlotState.IDLE, resource_id="mv-1", url="http://10.0.0.1:8080")
    rt.is_alive_for_claim(slot, budget_s=0.5)
    used = fake.timeout_for("lambda-microvms get-microvm")
    assert used <= 0.5, f"probe asked for {used}s against a 0.5s claim budget"


def test_f5_claim_probe_budget_still_applies_without_a_caller_deadline():
    """The pool may not pass one (no claim timeout); the runtime's own bound must still hold."""
    cfg = LambdaSnapStartConfig(region="us-east-1", image_identifier="arn:img", allow_default_egress=True,
                                resume_poll_s=0.0, claim_probe_timeout_s=4.0, cli_timeout_s=120.0)
    fake = RecordingAws({**_IDENT, "lambda-microvms get-microvm": {"Microvm": {"State": "RUNNING"}}})
    rt = LambdaSnapStartRuntime(cfg, aws_runner=fake, http_probe=lambda u, h, t: True, clock=lambda: 100.0)
    slot = AwsWorkerSlot(slot_id="s1", state=SlotState.IDLE, resource_id="mv-1", url="http://10.0.0.1:8080")
    rt.is_alive_for_claim(slot)
    assert fake.timeout_for("lambda-microvms get-microvm") <= 4.0


# ------------------------- issue #77 round 3: the escalated review of the round-2 fixes ----------

def test_f8_a_resume_that_exhausts_its_deadline_on_timeouts_is_still_unknown():
    """Round 2 fixed the RAISE site but not the RE-RAISE: resume() swallows each AwsProbeTimeout
    into last_exc and finally raises a NEW plain AwsWorkerError that merely INTERPOLATES it. The
    type is lost and "timed out" matches no marker, so a brownout that outlasts resume_timeout_s
    still terminated a healthy parked worker -- the exact bug, one level up the stack."""
    from blastbox.host.runtime.vm_dispatch import _is_unknown_not_dead

    tick = [100.0]
    # EVERY control-plane call times out -- the real brownout shape. The loop keeps the last such
    # error in last_exc and finally interpolates it into a fresh, plain AwsWorkerError.
    rt, _ = _snapstart_rt({"lambda-microvms get-microvm": _timeout,
                           "lambda-microvms create-microvm-auth-token": _timeout,
                           "lambda-microvms resume-microvm": _timeout},
                          probe=lambda u, h, t: False,
                          clock=lambda: tick.__setitem__(0, tick[0] + 0.05) or tick[0],
                          resume_timeout_s=5.0)
    slot = AwsWorkerSlot(slot_id="p1", resource_id="mv-1", state=SlotState.ASSIGNED,
                         url="http://10.0.0.1:8080")
    with pytest.raises(AwsWorkerError) as ei:
        rt.resume(slot)
    assert _is_unknown_not_dead(ei.value), (
        "a resume that only ever saw timeouts is UNKNOWN, not a confirmed dead worker")
    # Pin BOTH mechanisms independently: the raised TYPE, and (via _is_unknown_not_dead above) the
    # chained cause. Either alone would keep the classification correct, so without this assertion
    # a regression in the type is invisible -- redundancy that no test can see is redundancy that rots.
    from blastbox.host.runtime.aws_worker import AwsUnknownState
    assert isinstance(ei.value, AwsUnknownState), (
        f"resume flattened its own verdict to {type(ei.value).__name__}")
    assert isinstance(ei.value.__cause__, AwsUnknownState), "the originating cause was not chained"


def test_f8_a_resume_that_fails_on_a_healthy_control_plane_is_still_a_real_failure():
    """Guard: if the control plane answered fine and the AGENT simply never came up, that IS
    evidence the slot is unusable -- it must stay a hard failure so the slot is retired."""
    from blastbox.host.runtime.vm_dispatch import _is_unknown_not_dead

    tick = [100.0]
    # The control plane answers everything; only the AGENT never comes up.
    rt, _ = _snapstart_rt({"lambda-microvms get-microvm": {"state": "RUNNING"},
                           "lambda-microvms create-microvm-auth-token": {"authToken": "jwe"},
                           "lambda-microvms resume-microvm": {}},
                          probe=lambda u, h, t: False,
                          clock=lambda: tick.__setitem__(0, tick[0] + 0.05) or tick[0],
                          resume_timeout_s=60.0)
    slot = AwsWorkerSlot(slot_id="p1", resource_id="mv-1", state=SlotState.ASSIGNED,
                         url="http://10.0.0.1:8080")
    with pytest.raises(AwsWorkerError) as ei:
        rt.resume(slot)
    assert not _is_unknown_not_dead(ei.value)


@pytest.mark.parametrize("stderr", [
    "An error occurred (InvalidInstanceID.NotFound) when calling DescribeInstances: i-0503deadbeef1",
    "ResourceNotFoundException: microvm mv-500ab does not exist",
])
def test_f9_a_definitive_error_carrying_503_digits_is_not_transient(stderr):
    """The marker list kept a BARE "503" directly under a comment explaining that bare digits match
    instance ids and must be anchored. A definitive NotFound for an id containing those digits was
    therefore read as a brownout: the slot is never reaped, keeps counting against the warm target,
    and the tier never refills -- the same 'dead read as unknown' failure as the libvirt one."""
    from blastbox.host.runtime.aws_worker import _is_confirmed_dead_aws_error
    assert _is_confirmed_dead_aws_error(stderr), "a definitive NotFound must be read as dead"


def test_f9_a_real_503_is_still_transient():
    from blastbox.host.runtime.aws_worker import _is_confirmed_dead_aws_error
    assert not _is_confirmed_dead_aws_error("An error occurred (503) when calling the GetMicrovm operation")
    assert not _is_confirmed_dead_aws_error("ServiceUnavailable: please retry")


# ------------------------------- issue #77 round 4: the inverted classifier + its fallout --------

@pytest.mark.parametrize("stderr", [
    "An error occurred (TooManyRequestsException) when calling the InvokeMicrovm operation",
    "An error occurred (RequestTimeout): Request timed out",
    "An error occurred (SlowDown) when calling the GetMicrovm operation",
    "An error occurred (502) when calling the GetMicrovm operation",
    "An error occurred (504) when calling the GetMicrovm operation",
    "An error occurred (RequestTimeoutException) when calling",
    "An error occurred (SomethingAwsHasNotInventedYet) when calling",
])
def test_f15_retryable_and_unrecognised_aws_errors_are_never_death(stderr):
    """TooManyRequestsException is LAMBDA'S OWN THROTTLE NAME -- the likeliest brownout signal on
    the primary tier -- and the denylist read it as death. Four rounds each added the strings the
    previous round missed, which is why the default is now inverted: anything not positively
    confirmed dead is UNKNOWN, including errors AWS has not invented yet."""
    from blastbox.host.runtime.aws_worker import _is_confirmed_dead_aws_error
    assert not _is_confirmed_dead_aws_error(stderr)


@pytest.mark.parametrize("stderr", [
    "An error occurred (ResourceNotFoundException) when calling GetMicrovm",
    "An error occurred (InvalidInstanceID.NotFound) when calling DescribeInstances",
    "An error occurred (InvalidInstanceID.Malformed) when calling DescribeInstances",
])
def test_f15_confirmed_dead_answers_still_cost_the_slot(stderr):
    """The inversion must not strand husks: a positive "no such resource" is still death, else a
    dead slot keeps counting against the warm target and the tier never refills."""
    from blastbox.host.runtime.aws_worker import _is_confirmed_dead_aws_error
    assert _is_confirmed_dead_aws_error(stderr)


def test_f15_an_unrecognised_cli_failure_raises_unknown_not_error():
    """End-to-end through _aws: the default path must produce AwsUnknownState."""
    from blastbox.host.runtime.aws_worker import AwsUnknownState
    rt, _ = _snapstart_rt({"lambda-microvms get-microvm":
                           _cp(rc=255, stderr="An error occurred (TooManyRequestsException)")})
    with pytest.raises(AwsUnknownState):
        rt._aws("lambda-microvms", "get-microvm", "--microvm-identifier", "mv-1")


def test_f14_a_throttled_token_mint_does_not_kill_the_worker():
    """_health_ok caught AwsUnknownState as a generic error and returned False, so resume()'s loop
    never recorded it: last_exc stayed None and the final raise was a plain AwsWorkerError -> read
    as death -> a healthy resumed microVM terminated over a throttled mint."""
    from blastbox.host.runtime.vm_dispatch import _is_unknown_not_dead

    tick = [100.0]
    rt, _ = _snapstart_rt({"lambda-microvms get-microvm": {"state": "RUNNING", "endpoint": "vm.example"},
                           "lambda-microvms resume-microvm": {},
                           "lambda-microvms create-microvm-auth-token":
                               _cp(rc=255, stderr="An error occurred (TooManyRequestsException)")},
                          probe=lambda u, h, t: True,
                          clock=lambda: tick.__setitem__(0, tick[0] + 0.05) or tick[0],
                          resume_timeout_s=5.0)
    slot = AwsWorkerSlot(slot_id="p1", resource_id="mv-1", state=SlotState.ASSIGNED,
                         url="http://10.0.0.1:8080")
    with pytest.raises(AwsWorkerError) as ei:
        rt.resume(slot)
    assert _is_unknown_not_dead(ei.value), "a throttled mint is not evidence the worker is dead"


def test_f19_a_recovered_control_plane_clears_a_stale_unknown():
    """The final classification keyed off last_exc, which a LATER success never cleared. One early
    timeout could therefore mark a full-window AGENT failure as UNKNOWN, so an unusable slot went
    back to IDLE instead of being retired -- still counted, and eligible for more jobs."""
    from blastbox.host.runtime.vm_dispatch import _is_unknown_not_dead

    calls = {"n": 0}

    def flaky_describe(argv):  # noqa: ANN001
        calls["n"] += 1
        if calls["n"] == 1:
            raise subprocess.TimeoutExpired(cmd="aws", timeout=120)   # one early blip ...
        return _cp(stdout=json.dumps({"state": "RUNNING", "endpoint": "vm.example"}))  # ... then fine

    tick = [100.0]
    rt, _ = _snapstart_rt({"lambda-microvms get-microvm": flaky_describe,
                           "lambda-microvms resume-microvm": {},
                           "lambda-microvms create-microvm-auth-token": {"authToken": "jwe"}},
                          probe=lambda u, h, t: False,          # agent never comes up
                          clock=lambda: tick.__setitem__(0, tick[0] + 0.05) or tick[0],
                          resume_timeout_s=60.0)
    slot = AwsWorkerSlot(slot_id="p1", resource_id="mv-1", state=SlotState.ASSIGNED,
                         url="http://10.0.0.1:8080")
    with pytest.raises(AwsWorkerError) as ei:
        rt.resume(slot)
    assert not _is_unknown_not_dead(ei.value), (
        "the control plane recovered and the agent still never answered -- that is a real failure")


def test_f21_resume_honours_a_shorter_claim_budget():
    """resume_timeout_s is the runtime's own ceiling; when the dispatcher's remaining claim window
    is shorter, one unreachable slot would otherwise burn the whole window and the healthy slots
    behind it would never be tried."""
    tick = [100.0]
    rt, _ = _snapstart_rt({"lambda-microvms get-microvm": {"state": "RUNNING", "endpoint": "vm.example"},
                           "lambda-microvms resume-microvm": {},
                           "lambda-microvms create-microvm-auth-token": {"authToken": "jwe"}},
                          probe=lambda u, h, t: False,
                          clock=lambda: tick.__setitem__(0, tick[0] + 0.01) or tick[0],
                          resume_timeout_s=100.0)
    slot = AwsWorkerSlot(slot_id="p1", resource_id="mv-1", state=SlotState.ASSIGNED)
    start = tick[0]
    with pytest.raises(AwsWorkerError):
        rt.resume(slot, budget_s=0.5)
    spent = tick[0] - start
    assert spent < 50.0, f"resume ignored the 0.5s claim budget and ran for {spent} clock-seconds"


def test_the_two_claim_describes_share_one_deadline():
    """`is_alive_for_claim(budget_s=B)` must not cost 2xB.

    The hibernate override does its own uncached describe and then delegates to the base, which
    describes again. _claim_probe_budget only mins against an OUTER LIVE scope, so two SIBLING
    scopes each compute a fresh clock()+bound and the call can hold the dispatcher's warm-gate
    reservation for twice its contract. (My first fix wrapped only the super() call in a scope,
    which changed nothing -- the sibling-scope problem was the whole bug.)

    MUTATION: split the body back into two sibling `with self._claim_probe_budget(...)` scopes ->
    the second describe gets a full fresh budget and the elapsed doubles.
    """
    now = [1000.0]
    granted: list = []
    real_state = ["running"]

    rt, fake = _hibernate_rt(state=real_state, healthy=[True], clock=lambda: now[0],
                             claim_probe_timeout_s=5.0)

    orig_aws = rt._aws

    def timed_aws(svc, op, *args, timeout_s=None, **kw):
        # burn almost the whole granted budget on every control-plane call
        deadline = getattr(rt._tls, "probe_deadline", None)
        left = (deadline - now[0]) if deadline is not None else 999.0
        granted.append(round(left, 3))
        now[0] += max(0.0, left - 0.1)
        return orig_aws(svc, op, *args, timeout_s=timeout_s, **kw)

    rt._aws = timed_aws
    start = now[0]
    rt.is_alive_for_claim(AwsWorkerSlot(slot_id="h9", resource_id="i-1", state=SlotState.IDLE,
                                        url="http://10.0.0.5:8080"), budget_s=5.0)
    elapsed = now[0] - start

    assert elapsed <= 5.0 + 0.5, (
        f"is_alive_for_claim(budget_s=5.0) consumed {elapsed:.1f}s across {len(granted)} "
        f"control-plane calls granted {granted}; the claim reservation is held for twice its "
        f"contract"
    )


def test_a_hibernate_accepted_this_tick_makes_the_slot_unclaimable_immediately():
    """The exclusive maintenance window ends one instruction after `stop --hibernate` is accepted.

    maintain_idle issues the stop, records phase="hibernating", and returns USABLE -- so the pool
    republishes the slot as IDLE and wakes claimants. The only thing standing between that
    claimant and a job on an instance that is about to hibernate is is_alive_for_claim's fresh
    describe reading "stopping"; and DescribeInstances is eventually consistent, so for a short
    window it still answers "running". The claim then succeeds, the job POSTs, and the accepted
    hibernation completes mid-detonation.

    The runtime already KNOWS a stop was accepted. Using its own bookkeeping to CORROBORATE the
    describe closes the window, and it is safe in the direction that matters: it can only ever
    make the probe more conservative (skip a claim), never authorise one. A phase corrupted by a
    lost response therefore costs at most a skipped claim, which the park give-up timeout escapes.

    MUTATION: drop the _phase check from is_alive_for_claim -> the stale "running" describe wins
    and this returns True.
    """
    # eventual consistency: the stop was accepted, the describe has not caught up yet
    rt, _ = _hibernate_rt(state=["running"], healthy=[True])
    slot = AwsWorkerSlot(slot_id="h1", resource_id="i-1", state=SlotState.IDLE,
                         url="http://10.0.0.5:8080")
    rt._phase[slot.slot_id] = "hibernating"      # a stop-instances --hibernate was ACCEPTED

    assert rt.is_alive_for_claim(slot, budget_s=5.0) is None, (
        "a slot with a hibernate already in flight was reported claimable because the describe "
        "had not caught up; the job would run on an instance that is about to suspend"
    )


def test_f14_health_ok_propagates_an_unknown_mint_rather_than_returning_false():
    """The contract, pinned directly. resume() reads only what ESCAPES _health_ok, so collapsing an
    unconfirmed mint failure into a bare False loses the verdict on that pass. (The mint back-off
    re-raises it on later passes, which is why an end-to-end resume test alone cannot detect this:
    a single-pass resume would still be misclassified.)

    CHANGED 2026-08-20: the last assertion used to be ``is_ready(slot) is False``, "exactly as
    before". That was pinning the defect. The microVM here is RUNNING and only the TOKEN MINT is
    throttled, so the control plane has told us nothing about the worker -- and a False restarts
    the warming timeout aging, which terminates the tier's whole healthy WARMING population during
    a partial brownout. That is issue #79's exact failure mode, inside the branch that fixes #79.
    The sibling tier already answers None here (Ec2HibernateRuntime.is_ready: "A throttled
    describe tells us NOTHING"). UNKNOWN is the correct answer and the test name already said so.
    """
    from blastbox.host.runtime.aws_worker import AwsUnknownState

    rt, _ = _snapstart_rt({"lambda-microvms get-microvm": {"state": "RUNNING", "endpoint": "vm.example"},
                           "lambda-microvms create-microvm-auth-token":
                               _cp(rc=255, stderr="An error occurred (TooManyRequestsException)")},
                          probe=lambda u, h, t: True)
    slot = AwsWorkerSlot(slot_id="p1", resource_id="mv-1", state=SlotState.ASSIGNED,
                         url="http://10.0.0.1:8080")
    with pytest.raises(AwsUnknownState):
        rt._health_ok(slot)          # first call: nothing suppressed yet, so this is the raise site
    assert rt.is_ready(slot) is None, (
        "a RUNNING microVM whose token mint is merely throttled must stay UNKNOWN: a definitive "
        "False here spends the warming budget on the control plane's silence (issue #79)"
    )


def test_f23_a_resume_that_never_got_to_try_is_unknown_not_failure():
    """WarmPool's scan grace can return a slot just after the dispatcher's deadline, so round 4's
    budget plumbing could hand resume() a 0s budget. The loop then ran ZERO iterations and raised
    a plain error with last_exc=None -- and the pool terminated a healthy parked worker that was
    never probed even once. "We ran out of time to ask" is the purest form of UNKNOWN there is."""
    from blastbox.host.runtime.aws_worker import AwsUnknownState
    from blastbox.host.runtime.vm_dispatch import _is_unknown_not_dead

    rt, _ = _snapstart_rt({"lambda-microvms get-microvm": {"state": "SUSPENDED", "endpoint": "vm.x"},
                           "lambda-microvms resume-microvm": {},
                           "lambda-microvms create-microvm-auth-token": {"authToken": "jwe"}},
                          probe=lambda u, h, t: True, resume_timeout_s=30.0)
    slot = AwsWorkerSlot(slot_id="p1", resource_id="mv-1", state=SlotState.ASSIGNED,
                         url="http://10.0.0.1:8080")
    with pytest.raises(AwsUnknownState) as ei:
        rt.resume(slot, budget_s=0.0)
    assert _is_unknown_not_dead(ei.value), "a slot we never got to probe must never be destroyed"


def test_f24_a_running_microvm_with_a_dead_agent_is_a_confirmed_failure():
    """ResumeMicrovm wants a SUSPENDED target and answers ConflictException for a RUNNING one, which
    the inverted classifier calls UNKNOWN. When the state query has just CONFIRMED the microVM is
    up, that conflict says nothing new -- and letting it become the verdict masked a dead agent as a
    brownout forever: handed back every claim, never replaced, jobs requeued indefinitely."""
    from blastbox.host.runtime.vm_dispatch import _is_unknown_not_dead

    tick = [100.0]
    rt, _ = _snapstart_rt({"lambda-microvms get-microvm": {"state": "RUNNING", "endpoint": "vm.x"},
                           "lambda-microvms create-microvm-auth-token": {"authToken": "jwe"},
                           "lambda-microvms resume-microvm":
                               _cp(rc=255, stderr="An error occurred (ConflictException): not SUSPENDED")},
                          probe=lambda u, h, t: False,          # the agent is dead
                          clock=lambda: tick.__setitem__(0, tick[0] + 0.05) or tick[0],
                          resume_timeout_s=60.0)
    slot = AwsWorkerSlot(slot_id="p1", resource_id="mv-1", state=SlotState.ASSIGNED,
                         url="http://10.0.0.1:8080")
    with pytest.raises(AwsWorkerError) as ei:
        rt.resume(slot)
    assert not _is_unknown_not_dead(ei.value), (
        "a CONFIRMED-running microVM whose agent never answers must be retired and replaced")


def test_f24_a_suspended_slot_conflict_is_still_unknown():
    """Guard: the same conflict against a slot that is NOT confirmed up stays UNKNOWN -- otherwise
    this reintroduces exactly the class of bug the inversion removed."""
    from blastbox.host.runtime.vm_dispatch import _is_unknown_not_dead

    tick = [100.0]
    rt, _ = _snapstart_rt({"lambda-microvms get-microvm": {"state": "SUSPENDED", "endpoint": "vm.x"},
                           "lambda-microvms create-microvm-auth-token": {"authToken": "jwe"},
                           "lambda-microvms resume-microvm":
                               _cp(rc=255, stderr="An error occurred (ThrottlingException): slow down")},
                          probe=lambda u, h, t: False,
                          clock=lambda: tick.__setitem__(0, tick[0] + 0.05) or tick[0],
                          resume_timeout_s=5.0)
    slot = AwsWorkerSlot(slot_id="p1", resource_id="mv-1", state=SlotState.ASSIGNED,
                         url="http://10.0.0.1:8080")
    with pytest.raises(AwsWorkerError) as ei:
        rt.resume(slot)
    assert _is_unknown_not_dead(ei.value)


def test_credential_errors_are_never_confirmed_worker_death():
    """A bare "does not exist" lived in the confirmed-dead allowlist for one round and matched
    AWS's InvalidAccessKeyId text -- so rotating an access key marked the ENTIRE fleet dead, and
    terminate failed under the same credentials, quarantining every slot as DRAINING. Allowlist
    entries must be AWS ERROR CODES, never English prose."""
    from blastbox.host.runtime.aws_worker import _is_confirmed_dead_aws_error as dead

    assert not dead("An error occurred (InvalidAccessKeyId) when calling DescribeInstances: "
                    "The AWS Access Key Id you provided does not exist in our records.")
    assert not dead("An error occurred (AuthFailure): AWS was not able to validate the credentials")
    assert not dead("An error occurred (UnauthorizedOperation) when calling DescribeInstances")
    # ...while the real codes still are:
    assert dead("An error occurred (ResourceNotFoundException) when calling GetMicrovm")
    assert dead("An error occurred (InvalidInstanceID.NotFound) when calling DescribeInstances")


def test_a_truncated_positive_claim_budget_is_unknown_not_failure():
    """Only an exactly-zero budget raised UNKNOWN. With 10ms of a 2s window left, a perfectly
    healthy warming microVM cannot answer -- and calling that a confirmed failure destroys it."""
    from blastbox.host.runtime.aws_worker import AwsUnknownState
    from blastbox.host.runtime.vm_dispatch import _is_unknown_not_dead

    tick = [100.0]
    rt, _ = _snapstart_rt({"lambda-microvms get-microvm": {"state": "RUNNING", "endpoint": "vm.x"},
                           "lambda-microvms resume-microvm": {},
                           "lambda-microvms create-microvm-auth-token": {"authToken": "jwe"}},
                          probe=lambda u, h, t: False,          # agent not up YET
                          # a tiny per-call step so every aws call COMPLETES well inside the
                          # budget: the window simply runs out, nothing times out. That isolates
                          # the verdict rule from the inner-call bound.
                          clock=lambda: tick.__setitem__(0, tick[0] + 0.0005) or tick[0],
                          resume_timeout_s=60.0)
    slot = AwsWorkerSlot(slot_id="p1", resource_id="mv-1", state=SlotState.ASSIGNED,
                         url="http://10.0.0.1:8080")
    with pytest.raises(AwsUnknownState) as ei:
        rt.resume(slot, budget_s=0.2)      # positive, but a fraction of the real resume budget
    assert _is_unknown_not_dead(ei.value), "a window we truncated ourselves is not a worker verdict"


# ------------- marla loop 2 (run-42): the "shortened" heuristic was always true -----------------

def _resume_rt(probe_ok, tick_step=0.05, **cfgkw):
    tick = [100.0]
    return _snapstart_rt({"lambda-microvms get-microvm": {"state": "RUNNING", "endpoint": "vm.x"},
                          "lambda-microvms resume-microvm": {},
                          "lambda-microvms create-microvm-auth-token": {"authToken": "jwe"}},
                         probe=lambda u, h, t: probe_ok,
                         clock=lambda: tick.__setitem__(0, tick[0] + tick_step) or tick[0],
                         **cfgkw)[0]


def test_a_near_full_budget_still_yields_a_REAL_verdict():
    """`shortened = budget < resume_timeout_s` was true for ANY shortening -- and the dispatcher
    always passes the claim window's remainder, so any time consumed by claim() made it true. In
    production it was therefore ALWAYS true, so the verdict was unconditionally UNKNOWN and the
    dead-agent fix became unreachable: a microVM whose agent had crashed was handed back on every
    claim, never retired, and jobs requeued forever. What matters is whether the worker got a FAIR
    chance to answer, not whether the budget was trimmed at all."""
    from blastbox.host.runtime.vm_dispatch import _is_unknown_not_dead

    rt = _resume_rt(False, resume_timeout_s=60.0)
    slot = AwsWorkerSlot(slot_id="p1", resource_id="mv-1", state=SlotState.ASSIGNED,
                         url="http://10.0.0.1:8080")
    with pytest.raises(AwsWorkerError) as ei:
        rt.resume(slot, budget_s=59.0)      # trimmed by 1s -- a full, fair chance
    assert not _is_unknown_not_dead(ei.value), (
        "a near-full window that a CONFIRMED-running microVM never answered is a real failure")


def test_a_genuinely_tiny_budget_is_still_unknown():
    """The other half: with a fraction of a second left, a healthy warming microVM cannot answer,
    so that expiry is not evidence about the worker (issue #77 round 6)."""
    from blastbox.host.runtime.aws_worker import AwsUnknownState

    rt = _resume_rt(False, tick_step=0.0005, resume_timeout_s=60.0)
    slot = AwsWorkerSlot(slot_id="p1", resource_id="mv-1", state=SlotState.ASSIGNED,
                         url="http://10.0.0.1:8080")
    with pytest.raises(AwsUnknownState):
        rt.resume(slot, budget_s=0.2)


def test_a_fair_budget_still_bounds_the_calls_inside_resume():
    """Two INDEPENDENT questions were fused into one flag: (a) how long may a call block, and
    (b) does an expiry mean the worker is bad. Tying the call bound to the fairness flag meant that
    in the COMMON case (a near-full window, unfair=False) the inner aws calls ran at cli_timeout_s
    -- so a single describe could block 120s inside a 59s claim window, the round-6 finding
    reintroduced. The bound must ALWAYS apply; only the VERDICT depends on fairness."""
    cfg = LambdaSnapStartConfig(region="us-east-1", image_identifier="arn:x", allow_default_egress=True,
                                resume_poll_s=0.0, resume_timeout_s=60.0, cli_timeout_s=120.0)
    fake = RecordingAws({**_IDENT,
                         "lambda-microvms get-microvm": {"state": "RUNNING", "endpoint": "vm.x"},
                         "lambda-microvms resume-microvm": {},
                         "lambda-microvms create-microvm-auth-token": {"authToken": "jwe"}})
    tick = [100.0]
    rt = LambdaSnapStartRuntime(cfg, aws_runner=fake, http_probe=lambda u, h, t: False,
                                clock=lambda: tick.__setitem__(0, tick[0] + 0.05) or tick[0])
    slot = AwsWorkerSlot(slot_id="p1", resource_id="mv-1", state=SlotState.ASSIGNED,
                         url="http://10.0.0.1:8080")
    with pytest.raises(AwsWorkerError):
        rt.resume(slot, budget_s=10.0)          # fair (>= floor), so the verdict is real...
    over = [(k, t) for k, t in fake.timeouts if t > 10.0]
    assert not over, f"calls exceeded the 10s claim budget and ran at cli_timeout_s: {over[:3]}"


def test_a_trailing_budget_expiry_does_not_erase_a_confirmed_verdict():
    """Bounding the calls means the LAST one can expire as UNKNOWN. That must not overwrite what we
    already observed: the control plane CONFIRMED the microVM running and its agent never answered
    across a fair window -- that is a real, replaceable failure."""
    from blastbox.host.runtime.vm_dispatch import _is_unknown_not_dead

    rt = _resume_rt(False, resume_timeout_s=60.0)
    slot = AwsWorkerSlot(slot_id="p1", resource_id="mv-1", state=SlotState.ASSIGNED,
                         url="http://10.0.0.1:8080")
    with pytest.raises(AwsWorkerError) as ei:
        rt.resume(slot, budget_s=30.0)
    assert not _is_unknown_not_dead(ei.value), (
        "a confirmed-running microVM whose agent never answered a fair window must be retired")


def test_a_probe_we_could_not_issue_never_convicts_the_worker():
    """Local fd exhaustion makes the health probe return None -- we never got to ask the agent
    anything. The control plane still says RUNNING and the mint still works, so every other signal
    looks like the dead-agent case; convicting here would evict the whole fleet on a host hiccup,
    one level below the probe fix itself (issue #77 marla-loop 3)."""
    from blastbox.host.runtime.aws_worker import AwsUnknownState

    tick = [100.0]
    rt, _ = _snapstart_rt({"lambda-microvms get-microvm": {"state": "RUNNING", "endpoint": "vm.x"},
                           "lambda-microvms resume-microvm": {},
                           "lambda-microvms create-microvm-auth-token": {"authToken": "jwe"}},
                          probe=lambda u, h, t: None,      # could not even ask
                          clock=lambda: tick.__setitem__(0, tick[0] + 0.05) or tick[0],
                          resume_timeout_s=60.0)
    slot = AwsWorkerSlot(slot_id="p1", resource_id="mv-1", state=SlotState.ASSIGNED,
                         url="http://10.0.0.1:8080")
    with pytest.raises(AwsUnknownState):
        rt.resume(slot)

    # ...while a probe that ANSWERS no, against a confirmed-running VM, is still a real failure.
    tick2 = [100.0]
    rt2, _ = _snapstart_rt({"lambda-microvms get-microvm": {"state": "RUNNING", "endpoint": "vm.x"},
                            "lambda-microvms resume-microvm": {},
                            "lambda-microvms create-microvm-auth-token": {"authToken": "jwe"}},
                           probe=lambda u, h, t: False,
                           clock=lambda: tick2.__setitem__(0, tick2[0] + 0.05) or tick2[0],
                           resume_timeout_s=60.0)
    slot2 = AwsWorkerSlot(slot_id="p2", resource_id="mv-2", state=SlotState.ASSIGNED,
                          url="http://10.0.0.1:8080")
    with pytest.raises(AwsWorkerError) as ei:
        rt2.resume(slot2)
    assert not isinstance(ei.value, AwsUnknownState)


# ------------- marla loop 3 (run-43): the two findings that survived dedup --------------------

def test_the_http_probe_honours_the_remaining_resume_budget():
    """_call_budget bounds the aws SUBPROCESS calls via a thread-local deadline, but the agent
    health probe was handed a flat probe_timeout_s and sailed straight past it. With a nearly
    exhausted window the probe could still block for its full timeout, overrunning the claim."""
    seen: list[float] = []

    def _probe(url, headers, timeout):  # noqa: ANN001
        seen.append(timeout)
        return False

    tick = [100.0]
    rt, _ = _snapstart_rt({"lambda-microvms get-microvm": {"state": "RUNNING", "endpoint": "vm.x"},
                           "lambda-microvms resume-microvm": {},
                           "lambda-microvms create-microvm-auth-token": {"authToken": "jwe"}},
                          probe=_probe,
                          clock=lambda: tick.__setitem__(0, tick[0] + 0.05) or tick[0],
                          resume_timeout_s=60.0)
    slot = AwsWorkerSlot(slot_id="p1", resource_id="mv-1", state=SlotState.ASSIGNED,
                         url="http://10.0.0.1:8080")
    with pytest.raises(AwsWorkerError):
        rt.resume(slot, budget_s=1.0)
    assert seen, "the probe never ran"
    over = [t for t in seen if t > 1.0]
    assert not over, f"probe was given {over[:3]}s against a 1.0s remaining window"


def test_hibernate_resume_does_not_grant_a_second_full_budget():
    """The prelude (describe + start-instances + describe) opened its own budget scope, which CLOSED
    before the loop opened another -- so a resume could consume up to TWICE the window it was
    given. One deadline must cover the whole call."""
    from blastbox.host.runtime.aws_worker import Ec2HibernateConfig, Ec2HibernateRuntime

    # Only WORK advances the clock -- reading it is free. A clock that ticked on every read made
    # the budget be consumed by the act of checking it, which is not what this test is about.
    tick = [100.0]

    def clock():
        return tick[0]

    def runner(argv, timeout):   # noqa: ANN001
        argv = list(argv)
        op = f"{argv[1]} {argv[2]}"
        tick[0] += 0.25          # each aws call costs a quarter second
        if op == "sts get-caller-identity":
            return _cp(stdout=json.dumps({"Account": "1", "Arn": "arn:aws:iam::1:user/x"}))
        if op == "ec2 describe-instances":
            return _cp(stdout=json.dumps({"Reservations": [{"Instances": [
                {"InstanceId": "i-1", "State": {"Name": "stopped"}, "PrivateIpAddress": "10.0.0.5"}]}]}))
        return _cp(stdout="{}")

    def probe(url, headers, timeout):   # noqa: ANN001
        tick[0] += 0.25          # ...and so does each agent probe
        return False

    rt = Ec2HibernateRuntime(Ec2HibernateConfig(region="us-east-1", image_id="ami-0abc",
                                                resume_timeout_s=180.0, resume_poll_s=0.0),
                             aws_runner=runner, http_probe=probe, clock=clock)
    slot = AwsWorkerSlot(slot_id="h1", resource_id="i-1", state=SlotState.ASSIGNED, ip="10.0.0.5")
    start = tick[0]
    with pytest.raises(AwsWorkerError):
        rt.resume(slot, budget_s=4.0)
    spent = tick[0] - start
    assert spent <= 4.0 * 1.15, (
        f"resume consumed {spent:.1f} clock-seconds against a 4.0s budget — the prelude and the "
        f"loop each got their own full window")


def test_hibernate_rejects_a_zero_claim_budget_before_touching_the_instance():
    """The entry guard is on what the CALLER gave us. With no window at all we have not probed the
    worker even once, so an expiry is not evidence about it -- and start-instances must not fire
    either, or a slot handed back as UNKNOWN is left running (issue #77 round 5 / marla-loop 3)."""
    from blastbox.host.runtime.aws_worker import (
        AwsUnknownState,
        Ec2HibernateConfig,
        Ec2HibernateRuntime,
    )

    ops: list[str] = []

    def runner(argv, timeout):  # noqa: ANN001
        argv = list(argv)
        ops.append(f"{argv[1]} {argv[2]}")
        return _cp(stdout=json.dumps({"Reservations": [{"Instances": [
            {"InstanceId": "i-1", "State": {"Name": "stopped"}, "PrivateIpAddress": "10.0.0.5"}]}]}))

    rt = Ec2HibernateRuntime(Ec2HibernateConfig(region="us-east-1", image_id="ami-0abc"),
                             aws_runner=runner, http_probe=lambda u, h, to: False,
                             clock=lambda: 100.0)
    slot = AwsWorkerSlot(slot_id="h1", resource_id="i-1", state=SlotState.ASSIGNED, ip="10.0.0.5")
    with pytest.raises(AwsUnknownState) as ei:
        rt.resume(slot, budget_s=0.0)
    assert "ec2 start-instances" not in ops, f"the instance was started with no budget to wake it: {ops}"
    assert ops == [], f"a doomed call was issued with no budget: {ops}"
    # The _call_budget(0) scope would also produce an UNKNOWN here, so the guard's real contribution
    # is the DIAGNOSTIC: an operator reading "claim probe budget exhausted" would hunt a slow control
    # plane, when in fact the dispatcher simply had no window left to give. Pin the message, or the
    # guard is untested redundancy that will rot.
    assert "no claim budget left" in str(ei.value), (
        f"lost the explicit no-budget diagnostic: {ei.value}")


def test_an_exhausted_window_skips_the_probe_instead_of_issuing_a_zero_timeout():
    """Clamping the probe to the remaining window can yield ZERO. A zero socket timeout is not
    "fail fast" -- it puts the socket in NON-BLOCKING mode, so connect raises BlockingIOError
    (EINPROGRESS) immediately. That is not one of the local-exhaustion errnos, so it was classified
    as "the box answered no" and became evidence against a worker we never actually asked
    (issue #77 marla-loop 4). Below a meaningful floor we must decline to probe and report UNKNOWN."""
    asked: list[float] = []

    def _probe(url, headers, timeout):  # noqa: ANN001
        asked.append(timeout)
        return False

    # The EC2 path probes DIRECTLY -- no token mint in front of it to trip the budget first -- so
    # this is where a zero timeout actually reaches urllib.
    rt, _ = _ec2_rt({"ec2 describe-instances": {"Reservations": [{"Instances": [
        {"InstanceId": "i-1", "State": {"Name": "running"}, "PrivateIpAddress": "10.0.0.5"}]}]}},
        probe=_probe)
    slot = AwsWorkerSlot(slot_id="p1", resource_id="i-1", state=SlotState.ASSIGNED, ip="10.0.0.5")
    # pin the thread-local budget to "already exhausted"
    rt._tls.probe_deadline = rt._clock()
    try:
        assert rt._health_ok(slot) is None, "an unaskable probe must report UNKNOWN, not not-healthy"
        assert not [t for t in asked if t <= 0.0], (
            f"a zero/negative timeout was handed to the probe: {asked}")
    finally:
        rt._tls.probe_deadline = None


def test_local_exhaustion_is_unknown_through_the_SHAPE_urllib_ACTUALLY_RAISES():
    """The previous guard for this passed against a BARE OSError(EMFILE) -- a shape the real opener
    never produces. urllib's do_open does `raise URLError(err)`: __cause__ stays None, __context__
    holds the original, and URLError (an OSError subclass that never calls OSError.__init__) has
    .errno None. A __cause__-only lookup was therefore UNREACHABLE in production, and real fd
    exhaustion reaped whole fleets while this test stayed green (issue #77 marla-loop 4)."""
    import errno as _errno
    import urllib.error

    from blastbox.host.runtime.aws_worker import _is_local_resource_error

    real_shape = urllib.error.URLError(OSError(_errno.EMFILE, "Too many open files"))
    assert real_shape.__cause__ is None and getattr(real_shape, "errno", None) is None
    assert _is_local_resource_error(real_shape), (
        "the branch is unreachable through the shape urllib actually raises")

    # ...and a refusal wrapped the same way is still a real verdict about the box.
    refused = urllib.error.URLError(ConnectionRefusedError(_errno.ECONNREFUSED, "refused"))
    assert not _is_local_resource_error(refused)


def test_a_small_configured_probe_timeout_does_not_brick_the_tier():
    """_probe_timeout() declines below _MIN_PROBE_S, so a probe_timeout_s configured beneath that
    floor would decline unconditionally and no slot would ever ready -- the same brick
    __post_init__ already guards claim/health_probe_timeout_s against."""
    from blastbox.host.runtime.aws_worker import _MIN_PROBE_S
    cfg = LambdaSnapStartConfig(region="us-east-1", image_identifier="arn:x",
                                allow_default_egress=True, probe_timeout_s=0.01)
    assert cfg.probe_timeout_s >= _MIN_PROBE_S, "a sub-floor probe timeout bricks the tier"


def test_a_healthy_slow_agent_survives_a_SQUEEZED_probe():
    """The measured cliff: a healthy agent needing ~300ms against probe_timeout_s=5.0. Squeezing the
    probe into 0.26s makes it answer 'no', and that was recorded as evidence and the instance
    terminated. Picking a floor only moved the cliff (0.24 declined and SPARED the slot; clamping it
    to 0.25 made it REAP the slot instead). The rule is about provenance: a negative answer from a
    probe we cut short is not evidence about the worker (issue #77 marla-loop 4)."""
    from blastbox.host.runtime.aws_worker import AwsUnknownState

    # probe_timeout_s deliberately != the old magic 5.0 floor, so this test can tell the derived
    # rule apart from the constant it replaced.
    AGENT_NEEDS = 8.0

    def _slow_agent(url, headers, timeout):  # noqa: ANN001
        return timeout >= AGENT_NEEDS        # answers only if given enough time

    tick = [100.0]
    rt, _ = _snapstart_rt({"lambda-microvms get-microvm": {"state": "RUNNING", "endpoint": "vm.x"},
                           "lambda-microvms resume-microvm": {},
                           "lambda-microvms create-microvm-auth-token": {"authToken": "jwe"}},
                          probe=_slow_agent,
                          clock=lambda: tick.__setitem__(0, tick[0] + 0.01) or tick[0],
                          resume_timeout_s=60.0, probe_timeout_s=10.0)
    slot = AwsWorkerSlot(slot_id="p1", resource_id="mv-1", state=SlotState.ASSIGNED,
                         url="http://10.0.0.1:8080")
    # A window that cannot afford one FULL probe (7 < probe_timeout_s=10). The old fixed 5.0s floor
    # called this "fair" and convicted the agent; the derived rule knows we squeezed it.
    with pytest.raises(AwsUnknownState):
        rt.resume(slot, budget_s=7.0)


@pytest.mark.parametrize(("name", "code", "is_local"), [
    ("EADDRNOTAVAIL", errno.EADDRNOTAVAIL, True),   # ephemeral ports exhausted -- purely OUR side,
    ("ENETUNREACH", errno.ENETUNREACH, True),       # and both hit every worker on the same tick
    ("EINPROGRESS", errno.EINPROGRESS, True),
    ("EAGAIN", errno.EAGAIN, True),
    ("EMFILE", errno.EMFILE, True),
    ("ETIMEDOUT", errno.ETIMEDOUT, False),          # ...these ARE answers about the worker
    ("ECONNREFUSED", errno.ECONNREFUSED, False),
    ("ECONNRESET", errno.ECONNRESET, False),
    ("EHOSTUNREACH", errno.EHOSTUNREACH, False),
])
def test_local_errnos_are_separated_from_real_verdicts(name, code, is_local):
    """Which side of "did the box answer?" each errno falls on. The local ones are fleet-wide by
    nature -- ephemeral-port exhaustion and a missing route hit every worker at once -- so
    misfiling one of them is a whole-tier eviction, not a single bad slot (issue #77 marla-loop 4)."""
    import urllib.error

    from blastbox.host.runtime.aws_worker import _is_local_resource_error
    wrapped = urllib.error.URLError(OSError(code, name))   # the shape urllib actually raises
    assert _is_local_resource_error(wrapped) is is_local, f"{name} is on the wrong side"


def test_dns_failures_are_unknown_not_a_worker_verdict():
    """socket.gaierror is how a resolver failure arrives, wrapped in URLError.reason. Its codes are
    a SEPARATE namespace from errno -- EAI_AGAIN is typically NEGATIVE and is not errno.EAGAIN -- so
    an errno allowlist never matched it and a resolver blip convicted every hostname-based worker at
    once. A name we could not resolve tells us nothing about the worker's health (upstream P1)."""
    import socket
    import urllib.error

    from blastbox.host.runtime.aws_worker import _is_local_resource_error

    # TEMPORARY resolver failure -> we could not ask.
    wrapped = urllib.error.URLError(socket.gaierror(socket.EAI_AGAIN, "[EAI_AGAIN] Temporary failure"))
    assert _is_local_resource_error(wrapped), "a temporary resolver failure is not a worker verdict"

    # ...but a DEFINITIVE NXDOMAIN is a real reachability answer about an existing worker. Treating
    # every gaierror as unknown (my over-correction) left such a slot IDLE and reported healthy for
    # the whole 300s grace while every claim skipped it, when capacity used to be replaced at once.
    nxdomain = urllib.error.URLError(socket.gaierror(socket.EAI_NONAME, "[EAI_NONAME] Name unknown"))
    assert not _is_local_resource_error(nxdomain), "NXDOMAIN must stay a real verdict"

    # a refusal is still the box answering
    assert not _is_local_resource_error(
        urllib.error.URLError(ConnectionRefusedError(errno.ECONNREFUSED, "refused")))


def test_an_unparseable_aws_response_is_unknown_not_death():
    """A truncated pipe, a CLI upgraded mid-flight, a proxy error page -- we could not PARSE the
    answer, which is not the worker telling us it is gone. Whatever caused it applies to every call
    on this host at once, so reading it as death is another fleet-wide eviction (upstream P2)."""
    from blastbox.host.runtime.aws_worker import AwsUnknownState

    rt, _ = _snapstart_rt({"lambda-microvms get-microvm": _cp(stdout="<html>502 Bad Gateway</html>")})
    with pytest.raises(AwsUnknownState):
        rt._aws("lambda-microvms", "get-microvm", "--microvm-identifier", "mv-1")


def test_a_window_of_only_UNKNOWN_probes_never_convicts():
    """Every HTTP probe returns None (local exhaustion the whole time) while AWS keeps confirming
    the instance RUNNING. saw_agent_silent therefore stays False, last_exc stays None -- and the
    classifier's FALLBACK was AwsWorkerError, so a worker we never once got to ask was convicted
    and terminated. Conviction must require positive evidence; everything else is UNKNOWN, which
    the pool's unknown-escalation already bounds (escalated codex, loop 4)."""
    from blastbox.host.runtime.aws_worker import AwsUnknownState

    # ONLY the probe advances the clock, so no aws call ever hits its budget and last_exc stays
    # None -- otherwise a trailing budget expiry supplies the UNKNOWN and the fallback under test is
    # never reached (this test passed for that reason before the clock was isolated).
    tick = [100.0]

    def _unaskable(url, headers, timeout):  # noqa: ANN001
        tick[0] += 1.0
        return None

    rt, _ = _snapstart_rt({"lambda-microvms get-microvm": {"state": "RUNNING", "endpoint": "vm.x"},
                           "lambda-microvms resume-microvm": {},
                           "lambda-microvms create-microvm-auth-token": {"authToken": "jwe"}},
                          probe=_unaskable, clock=lambda: tick[0], resume_timeout_s=5.0)
    slot = AwsWorkerSlot(slot_id="p1", resource_id="mv-1", state=SlotState.ASSIGNED,
                         url="http://10.0.0.1:8080")
    with pytest.raises(AwsUnknownState):
        rt.resume(slot)


def test_an_unknown_verdict_is_cached_at_COMPLETION_not_at_start():
    """If the health call itself stalls longer than _liveness_cache_s before ending UNKNOWN, a
    timestamp captured BEFORE the call is already expired by the time it is written -- so the next
    tick re-probes immediately and the sole tick thread burns the full health budget per idle slot
    for the whole outage, instead of honouring the cache (upstream P2)."""
    tick = [100.0]

    def _stalling_runner(argv, timeout):  # noqa: ANN001
        tick[0] += 30.0                    # the call itself takes far longer than the cache TTL
        raise subprocess.TimeoutExpired(cmd=list(argv), timeout=timeout)

    cfg = LambdaSnapStartConfig(region="us-east-1", image_identifier="arn:x",
                                allow_default_egress=True, resume_poll_s=0.0)
    rt = LambdaSnapStartRuntime(cfg, aws_runner=_stalling_runner, http_probe=lambda u, h, t: True,
                                clock=lambda: tick[0])
    slot = AwsWorkerSlot(slot_id="s1", resource_id="mv-1", state=SlotState.IDLE,
                         url="http://10.0.0.1:8080")
    started = tick[0]
    assert rt.is_alive(slot) is None
    stamped, verdict = rt._live_cache["s1"]
    assert verdict is None
    assert stamped > started, (
        f"UNKNOWN cached with a pre-call timestamp ({stamped} <= {started}); the entry is born "
        f"expired and the next tick re-probes immediately")
    assert stamped >= tick[0] - 1e-6


def test_a_confirmed_dead_microvm_is_retired_not_handed_back():
    """The strongest evidence of all is AWS saying the resource is GONE. Simplifying the classifier
    to "agent silent on a fair window" swallowed that into UNKNOWN, so a husk AWS had explicitly
    confirmed dead was unclaimed and retried forever instead of retired and replaced (upstream P2)."""
    from blastbox.host.runtime.aws_worker import AwsUnknownState

    tick = [100.0]
    rt, _ = _snapstart_rt({"lambda-microvms get-microvm":
                               _cp(rc=254, stderr="An error occurred (ResourceNotFoundException)"),
                           "lambda-microvms resume-microvm": {},
                           "lambda-microvms create-microvm-auth-token": {"authToken": "jwe"}},
                          probe=lambda u, h, t: False,
                          clock=lambda: tick.__setitem__(0, tick[0] + 0.05) or tick[0],
                          resume_timeout_s=60.0)
    slot = AwsWorkerSlot(slot_id="p1", resource_id="mv-1", state=SlotState.ASSIGNED,
                         url="http://10.0.0.1:8080")
    with pytest.raises(AwsWorkerError) as ei:
        rt.resume(slot)
    assert not isinstance(ei.value, AwsUnknownState), (
        "a microVM AWS confirmed GONE was handed back as unknown instead of retired")


def test_a_squeezed_probe_cannot_record_the_agent_as_silent():
    """Fairness was decided before the forced token mint and describes consumed part of the window,
    so a window fair at the top could still squeeze the probe below probe_timeout_s -- and a healthy
    agent 'timing out' purely from that truncation was recorded as silent and its slot terminated.
    Only a FULL-duration probe may convict (upstream P2)."""
    from blastbox.host.runtime.aws_worker import AwsUnknownState

    # The probe must NOT consume the window itself, or it starves the describe that sets saw_up and
    # the test passes for that reason instead of the one under test.
    AGENT_NEEDS = 4.8
    tick = [100.0]

    def _slow_agent(url, headers, timeout):  # noqa: ANN001
        return timeout >= AGENT_NEEDS

    rt, _ = _snapstart_rt({"lambda-microvms get-microvm": {"state": "RUNNING", "endpoint": "vm.x"},
                           "lambda-microvms resume-microvm": {},
                           "lambda-microvms create-microvm-auth-token": {"authToken": "jwe"}},
                          probe=_slow_agent,
                          clock=lambda: tick.__setitem__(0, tick[0] + 0.05) or tick[0],
                          resume_timeout_s=60.0, probe_timeout_s=5.0)
    slot = AwsWorkerSlot(slot_id="p1", resource_id="mv-1", state=SlotState.ASSIGNED,
                         url="http://10.0.0.1:8080")
    # ~4.5s left: the control plane still answers (saw_up becomes True), but every agent probe is
    # squeezed below its configured 5s, so none of them may convict.
    with pytest.raises(AwsUnknownState):
        rt.resume(slot, budget_s=4.5)


def test_early_silence_while_parked_cannot_convict_a_later_running_instance():
    """The two evidence flags were CUMULATIVE across the whole resume, so they could be satisfied by
    different phases. A hibernate resume that begins from `stopped` legitimately fails its first
    full-duration probes; if the instance only reaches `running` near the deadline, that early
    silence paired with the late running-observation raised a hard error and terminated a healthy
    instance which was never given a full probe after it started (upstream P2)."""
    from blastbox.host.runtime.aws_worker import (
        AwsUnknownState,
        Ec2HibernateConfig,
        Ec2HibernateRuntime,
    )

    tick = [100.0]
    state = {"name": "stopped"}
    probes: list[bool] = []

    def clock():
        return tick[0]

    def runner(argv, timeout):  # noqa: ANN001
        argv = list(argv)
        op = f"{argv[1]} {argv[2]}"
        tick[0] += 1.0
        if op == "sts get-caller-identity":
            return _cp(stdout=json.dumps({"Account": "1", "Arn": "arn:aws:iam::1:user/x"}))
        if op == "ec2 describe-instances":
            # it only comes up near the very end of the window
            if tick[0] > 126.0:      # up only in the last few seconds of the 30s window
                state["name"] = "running"
            return _cp(stdout=json.dumps({"Reservations": [{"Instances": [
                {"InstanceId": "i-1", "State": {"Name": state["name"]},
                 "PrivateIpAddress": "10.0.0.5"}]}]}))
        return _cp(stdout="{}")

    def probe(url, headers, timeout):  # noqa: ANN001
        probes.append(state["name"] == "running")
        return False              # never answers -- but it was parked for almost all of them

    rt = Ec2HibernateRuntime(Ec2HibernateConfig(region="us-east-1", image_id="ami-0abc",
                                                # a 5s probe cannot fit in the <4s that remains
                                                # once it finally comes up, so every probe after
                                                # that point is squeezed -> UNKNOWN, not silence
                                                resume_timeout_s=30.0, resume_poll_s=0.0,
                                                probe_timeout_s=5.0),
                             aws_runner=runner, http_probe=probe, clock=clock)
    slot = AwsWorkerSlot(slot_id="h1", resource_id="i-1", state=SlotState.ASSIGNED, ip="10.0.0.5")
    with pytest.raises(AwsUnknownState):
        rt.resume(slot)
    assert probes, "the agent was never probed at all"


def test_a_confirmed_dead_verdict_survives_a_later_budget_timeout():
    """`confirmed_dead` was derived from last_exc, which holds only the LATEST pass's error -- so a
    trailing budget exhaustion masked an earlier ResourceNotFoundException and the husk was handed
    back as UNKNOWN. AWS answering that the resource is gone does not stop being true because a
    later call ran out of time (upstream P2)."""
    from blastbox.host.runtime.aws_worker import AwsUnknownState

    calls = {"n": 0}

    def flaky(argv):  # noqa: ANN001
        calls["n"] += 1
        if calls["n"] <= 2:      # AWS confirms it is GONE early on...
            return _cp(rc=254, stderr="An error occurred (ResourceNotFoundException)")
        raise subprocess.TimeoutExpired(cmd="aws", timeout=120)   # ...then everything times out

    tick = [100.0]
    rt, _ = _snapstart_rt({"lambda-microvms get-microvm": flaky,
                           "lambda-microvms resume-microvm": flaky,
                           "lambda-microvms create-microvm-auth-token": {"authToken": "jwe"}},
                          probe=lambda u, h, t: False,
                          clock=lambda: tick.__setitem__(0, tick[0] + 0.05) or tick[0],
                          resume_timeout_s=60.0)
    slot = AwsWorkerSlot(slot_id="p1", resource_id="mv-1", state=SlotState.ASSIGNED,
                         url="http://10.0.0.1:8080")
    with pytest.raises(AwsWorkerError) as ei:
        rt.resume(slot)
    assert not isinstance(ei.value, AwsUnknownState), (
        "a trailing timeout masked AWS's confirmed-dead answer and the husk was handed back")


def test_snapstart_resume_does_not_grant_a_second_full_budget():
    """The EC2 path was given one hard deadline across prelude and loop; the Lambda path was left
    resetting it, so _resolve_url could consume most of a shortened budget and the loop would then
    open a FRESH window with the original value -- nearly twice the dispatcher's remaining claim
    window, delaying attempts on healthy slots behind it (upstream P2)."""
    tick = [100.0]

    def clock():
        return tick[0]                      # only WORK advances time

    def runner(argv, timeout):  # noqa: ANN001
        tick[0] += 0.25
        argv = list(argv)
        if f"{argv[1]} {argv[2]}" == "sts get-caller-identity":
            return _cp(stdout=json.dumps({"Account": "1", "Arn": "arn:aws:iam::1:user/x"}))
        return _cp(stdout=json.dumps({"state": "SUSPENDED", "endpoint": "vm.x"}))

    def probe(url, headers, timeout):  # noqa: ANN001
        tick[0] += 0.25
        return False

    cfg = LambdaSnapStartConfig(region="us-east-1", image_identifier="arn:x",
                                allow_default_egress=True, resume_poll_s=0.0,
                                resume_timeout_s=180.0)
    rt = LambdaSnapStartRuntime(cfg, aws_runner=runner, http_probe=probe, clock=clock)
    slot = AwsWorkerSlot(slot_id="p1", resource_id="mv-1", state=SlotState.ASSIGNED)
    # A SMALL budget, so the one-describe prelude is a meaningful fraction of it: with 4s the
    # prelude is ~6% and a second full window hides inside any sane tolerance.
    start = tick[0]
    with pytest.raises(AwsWorkerError):
        rt.resume(slot, budget_s=1.0)
    spent = tick[0] - start
    assert spent <= 1.0 * 1.1, (
        f"resume consumed {spent:.2f} clock-seconds against a 1.0s budget — the prelude and the "
        f"loop each got their own window")


def test_a_slot_that_suspends_between_passes_is_not_convicted():
    """Correlating the probe against `state_says_up` used the PREVIOUS pass's observation. A Lambda
    that auto-suspends between iterations fails its next probe perfectly normally -- and that was
    banked as silence-while-up before the same pass's describe reported "suspended". The flag is
    sticky, so the healthy slot was convicted anyway. Silence must be corroborated by the state
    query that FOLLOWS it in the same pass (upstream P2)."""
    from blastbox.host.runtime.aws_worker import AwsUnknownState

    # Pass 1: we cannot ASK (probe unknown) but the describe confirms RUNNING -> state is "up".
    # Between passes the platform auto-suspends. Pass 2: the probe fails -- entirely normal for a
    # suspended VM -- and the OLD code banked that against pass 1's stale "up" before this pass's
    # describe reported SUSPENDED.
    states = iter(["RUNNING"] + ["SUSPENDED"] * 60)
    probe_answers = iter([None] + [False] * 60)
    tick = [100.0]

    def describe(argv):  # noqa: ANN001
        return _cp(stdout=json.dumps({"state": next(states, "SUSPENDED"), "endpoint": "vm.x"}))

    rt, _ = _snapstart_rt({"lambda-microvms get-microvm": describe,
                           "lambda-microvms resume-microvm": {},
                           "lambda-microvms create-microvm-auth-token": {"authToken": "jwe"}},
                          probe=lambda u, h, t: next(probe_answers, False),
                          clock=lambda: tick.__setitem__(0, tick[0] + 0.05) or tick[0],
                          resume_timeout_s=60.0)
    slot = AwsWorkerSlot(slot_id="p1", resource_id="mv-1", state=SlotState.ASSIGNED,
                         url="http://10.0.0.1:8080")
    with pytest.raises(AwsUnknownState):
        rt.resume(slot)


def test_an_unaddressable_instance_is_unknown_not_silent():
    """With use_public_ip a just-started instance has no address yet, so NO probe is issued.
    Reporting False recorded it as agent silence the moment the state query said "running", and a
    shortened window then terminated a healthy instance that simply was not addressable (P2)."""
    from blastbox.host.runtime.aws_worker import Ec2HibernateConfig, Ec2HibernateRuntime

    def runner(argv, timeout):  # noqa: ANN001
        argv = list(argv)
        if f"{argv[1]} {argv[2]}" == "sts get-caller-identity":
            return _cp(stdout=json.dumps({"Account": "1", "Arn": "arn:aws:iam::1:user/x"}))
        return _cp(stdout=json.dumps({"Reservations": [{"Instances": [
            {"InstanceId": "i-1", "State": {"Name": "running"}}]}]}))   # NO PublicIpAddress yet

    rt = Ec2HibernateRuntime(Ec2HibernateConfig(region="us-east-1", image_id="ami-0abc",
                                                use_public_ip=True,
                                                allow_plaintext_public=True),
                             aws_runner=runner, http_probe=lambda u, h, t: False,
                             clock=lambda: 100.0)
    slot = AwsWorkerSlot(slot_id="h1", resource_id="i-1", state=SlotState.ASSIGNED)
    assert rt._agent_healthy(slot) is None, "no address yet was reported as the agent being silent"


def test_a_mint_unknown_reaches_the_pool_from_the_HEALTH_path_too():
    """The claim hook reports a throttled mint as UNKNOWN so the slot is skipped non-destructively.
    The health path swallowed the same error and said alive=True, so the pool never started its
    unknown clock while _spawn_to_deficit kept counting the unclaimable slot -- a warm_size=1 tier
    requeued jobs indefinitely once the token aged (P2)."""
    cfg = LambdaMicroVmConfig(region="us-east-1", image_identifier="arn:aws:lambda:us-east-1:aws:x",
                              allow_default_egress=True)
    fake = FakeAws({**_IDENT,
                    "lambda-microvms get-microvm": {"state": "RUNNING"},
                    "lambda-microvms create-microvm-auth-token":
                        _cp(rc=255, stderr="An error occurred (ThrottlingException): Rate exceeded")})
    rt = LambdaMicroVmRuntime(cfg, aws_runner=fake, http_probe=lambda u, h, t: True,
                              clock=lambda: 100.0)
    slot = AwsWorkerSlot(slot_id="s1", state=SlotState.IDLE, resource_id="mv-1",
                         url="http://10.0.0.1:8080", auth_token="aged")
    slot.token_minted_at = -1e9        # far past half-TTL -> forces a re-mint, which is throttled
    assert rt.is_alive(slot) is None, "a throttled mint was reported as a healthy slot"


def test_hibernate_can_still_convict_a_dead_agent():
    """Guards a REGRESSION I shipped: a `starved` guard meant to protect slow thaws was a tautology
    (budget = min(resume_timeout_s, budget_s) - prelude, so it was true for EVERY budget including
    None), and it cleared silence unconditionally -- the hibernate tier could not convict a dead
    agent at all. It survived a revert that removed only the snapstart copy, which is exactly the
    fix-one-tier-skip-the-sibling shape this branch keeps producing."""
    from blastbox.host.runtime.aws_worker import (
        AwsUnknownState,
        Ec2HibernateConfig,
        Ec2HibernateRuntime,
    )

    tick = [100.0]

    def runner(argv, timeout):  # noqa: ANN001
        tick[0] += 0.5
        argv = list(argv)
        if f"{argv[1]} {argv[2]}" == "sts get-caller-identity":
            return _cp(stdout=json.dumps({"Account": "1", "Arn": "arn:aws:iam::1:user/x"}))
        return _cp(stdout=json.dumps({"Reservations": [{"Instances": [
            {"InstanceId": "i-1", "State": {"Name": "running"},
             "PrivateIpAddress": "10.0.0.5"}]}]}))

    def probe(url, headers, timeout):  # noqa: ANN001
        tick[0] += 1.0
        return False                    # the instance is up; its agent is genuinely dead

    rt = Ec2HibernateRuntime(Ec2HibernateConfig(region="us-east-1", image_id="ami-0abc",
                                                resume_timeout_s=20.0, resume_poll_s=0.0,
                                                probe_timeout_s=1.0),
                             aws_runner=runner, http_probe=probe, clock=lambda: tick[0])
    slot = AwsWorkerSlot(slot_id="h1", resource_id="i-1", state=SlotState.ASSIGNED, ip="10.0.0.5")
    with pytest.raises(AwsWorkerError) as ei:
        rt.resume(slot)
    assert not isinstance(ei.value, AwsUnknownState), (
        "a RUNNING instance whose agent never answers a full-duration probe must be retired")


def test_snapstart_unresolved_endpoint_is_unknown_with_zero_probes():
    """The sibling of the EC2 no-IP fix, on the DEFAULT warm tier. _health_ok returned a bare False
    when the endpoint had not surfaced -- no probe issued at all -- and same-pass corroboration
    promoted that to a conviction, terminating a healthy RUNNING microVM with ZERO agent probes
    ever sent."""
    from blastbox.host.runtime.aws_worker import AwsUnknownState

    probes = [0]
    tick = [100.0]

    def probe(url, headers, timeout):  # noqa: ANN001
        probes[0] += 1
        return False

    rt, _ = _snapstart_rt({"lambda-microvms get-microvm": {"state": "RUNNING"},   # no endpoint yet
                           "lambda-microvms resume-microvm": {},
                           "lambda-microvms create-microvm-auth-token": {"authToken": "jwe"}},
                          probe=probe,
                          clock=lambda: tick.__setitem__(0, tick[0] + 0.05) or tick[0],
                          resume_timeout_s=5.0)
    slot = AwsWorkerSlot(slot_id="p1", resource_id="mv-1", state=SlotState.ASSIGNED)
    with pytest.raises(AwsUnknownState):
        rt.resume(slot)
    assert probes[0] == 0, f"convicted after issuing {probes[0]} probes — it issued none"


def test_a_confirmed_dead_mint_error_is_not_swallowed_into_a_backoff():
    """A mint failing with ResourceNotFoundException is AWS saying the microVM is GONE. Swallowing
    it into the backoff meant the resume loop never saw it, saw_confirmed_dead stayed False, and a
    later throttle produced UNKNOWN -- so the dispatcher unclaimed a microVM AWS had already said
    does not exist, and retried it forever (upstream P2)."""
    from blastbox.host.runtime.aws_worker import AwsUnknownState

    # The state call is THROTTLED, so nothing corroborates silence and the only route to a hard
    # verdict is the confirmed-dead mint itself. Without that route the classifier says UNKNOWN.
    tick = [100.0]
    rt, _ = _snapstart_rt({"lambda-microvms get-microvm":
                               _cp(rc=255, stderr="An error occurred (ThrottlingException)"),
                           "lambda-microvms resume-microvm":
                               _cp(rc=255, stderr="An error occurred (ThrottlingException)"),
                           "lambda-microvms create-microvm-auth-token":
                               _cp(rc=254, stderr="An error occurred (ResourceNotFoundException)")},
                          probe=lambda u, h, t: False,
                          clock=lambda: tick.__setitem__(0, tick[0] + 0.05) or tick[0],
                          resume_timeout_s=60.0)
    slot = AwsWorkerSlot(slot_id="p1", resource_id="mv-1", state=SlotState.ASSIGNED,
                         url="http://10.0.0.1:8080")
    with pytest.raises(AwsWorkerError) as ei:
        rt.resume(slot)
    assert not isinstance(ei.value, AwsUnknownState), (
        "a microVM AWS confirmed GONE was handed back as unknown because the confirmed-dead mint "
        "error was swallowed into a backoff and the later throttles decided the verdict")


def test_is_ready_reports_unknown_when_the_control_plane_throttles():
    """issue #79: a throttled describe is NOT "the instance didn't boot".

    is_ready() folded every AwsWorkerError into False, and the pool evicts any WARMING slot older
    than warming_timeout_s -- so a brownout outlasting that budget terminated the tier's entire
    WARMING population, instances that were booting perfectly well.
    """
    def throttled(argv):  # noqa: ANN001
        raise AwsProbeTimeout("Throttling: Rate exceeded")

    fake = FakeAws({**_IDENT, "ec2 run-instances": {"Instances": [{"InstanceId": "i-1"}]},
                    "ec2 describe-instances": throttled})
    cfg = Ec2HibernateConfig(region="us-east-1", image_id="ami-x", resume_poll_s=0.0)
    rt = Ec2HibernateRuntime(cfg, aws_runner=fake, http_probe=lambda u, h, t: True,
                             clock=lambda: 100.0)
    slot = rt.spawn()
    assert rt.is_ready(slot) is None, "a throttled describe must be UNKNOWN, not not-ready"


def test_is_ready_still_reports_a_definitive_not_ready():
    """The exemption must not swallow real answers: an instance that is genuinely still booting
    reports False, so the warming timeout keeps working for actual failures.
    """
    rt, _ = _hibernate_rt(state=["pending"], healthy=[False])
    slot = rt.spawn()
    assert rt.is_ready(slot) is False


def test_a_throttle_leaves_the_hibernate_phase_untouched():
    """The phase machine must resume where it was once AWS answers again, rather than being
    re-driven from the start by a brownout."""
    state = ["running"]
    calls = {"n": 0}

    def describe(argv):  # noqa: ANN001
        calls["n"] += 1
        if calls["n"] == 2:
            raise AwsProbeTimeout("Throttling: Rate exceeded")
        return _cp(stdout=json.dumps({"Reservations": [{"Instances": [
            {"InstanceId": "i-1", "State": {"Name": state[0]}, "PrivateIpAddress": "10.0.0.5"}]}]}))

    fake = FakeAws({**_IDENT, "ec2 run-instances": {"Instances": [{"InstanceId": "i-1"}]},
                    "ec2 describe-instances": describe, "ec2 stop-instances": {}})
    cfg = Ec2HibernateConfig(region="us-east-1", image_id="ami-x", resume_poll_s=0.0)
    rt = Ec2HibernateRuntime(cfg, aws_runner=fake, http_probe=lambda u, h, t: True,
                             clock=lambda: 100.0)
    slot = rt.spawn()
    rt.is_ready(slot)                      # call 1: running + healthy -> parks, phase advances
    phase_before = rt._phase.get(slot.slot_id)
    assert rt.is_ready(slot) is None       # call 2: throttled -> UNKNOWN
    assert rt._phase.get(slot.slot_id) == phase_before, "a brownout must not rewind the phase"


def test_snapstart_is_ready_is_unknown_when_the_instance_is_unobservable():
    """SnapStart is the DEFAULT warm tier, so the base-class is_ready is the one that matters most.

    A brownout that hides the microVM entirely must read UNKNOWN, not "didn't boot" -- otherwise
    warming_timeout_s terminates the tier's whole WARMING population (issue #79).
    """
    def throttled(argv):  # noqa: ANN001
        raise AwsProbeTimeout("Throttling: Rate exceeded")

    rt, _ = _snapstart_rt({"lambda-microvms get-microvm": throttled})
    slot = AwsWorkerSlot(slot_id="s", resource_id="mv-1")
    assert rt.is_ready(slot) is None


def test_snapstart_is_ready_is_not_ready_when_the_state_is_still_readable():
    """The mirror case, and the reason the exemption is narrow: minting a token needs a RUNNING
    microVM, so a `pending` slot fails the mint with an unconfirmed error. The describe answered,
    though -- we DID observe the worker -- so this is a definitive not-ready-yet, and the warming
    timeout must keep running against it. Reading it as UNKNOWN would exempt an instance that
    never boots from the very timeout that replaces it.
    """
    rt, _ = _snapstart_rt({
        "lambda-microvms get-microvm": {"state": "pending", "endpoint": "vm.example"},
        "lambda-microvms create-microvm-auth-token": _cp(rc=254, stderr="microvm not running"),
    })
    slot = AwsWorkerSlot(slot_id="s", resource_id="mv-1")
    assert rt.is_ready(slot) is False


def test_snapstart_is_ready_preserves_a_health_ok_unknown():
    """_health_ok is itself tri-state: it returns None when NO probe was issued (the endpoint has
    not surfaced yet). Flattening that to False convicts a running microVM with zero agent probes
    ever sent -- the shape the liveness path already fixed; readiness must not undo it.
    """
    rt, _ = _snapstart_rt({"lambda-microvms get-microvm": {"state": "running"}})  # no endpoint
    slot = AwsWorkerSlot(slot_id="s", resource_id="mv-1")
    assert rt._health_ok(slot) is None, "sanity: this is the _health_ok UNKNOWN case"
    assert rt.is_ready(slot) is None


def test_available_raises_rather_than_reporting_an_unentitled_tier():
    """issue #79: availability is probed ONCE at construction and a False drops the tier for the
    whole process lifetime. A throttled sts get-caller-identity must therefore NOT return False --
    "throttled" is not "unentitled", and only the latter is a verdict.
    """
    def throttled(argv):  # noqa: ANN001
        raise AwsProbeTimeout("Throttling: Rate exceeded")

    rt, _ = _snapstart_rt({"sts get-caller-identity": throttled})
    with pytest.raises(AwsUnknownState):
        rt.available()


def test_available_still_reports_false_for_a_real_verdict():
    """Missing credentials IS a verdict, and must stay one -- otherwise a genuinely misconfigured
    tier is retried forever instead of being dropped with a clear message."""
    rt, _ = _snapstart_rt({"sts get-caller-identity": {}})   # answered, but no Account
    assert rt.available() is False


def test_available_reports_false_when_the_probe_fails_definitively():
    """A CONFIRMED failure (bad credentials, no entitlement) must still return False rather than
    propagate: that is the verdict the cascade drops a tier on. Only the undecided case escapes.
    """
    def denied(argv):  # noqa: ANN001
        raise AwsWorkerError("AccessDenied: not authorized to perform sts:GetCallerIdentity")

    rt, _ = _snapstart_rt({"sts get-caller-identity": denied})
    assert rt.available() is False


def test_a_throttled_call_raises_the_retryable_type():
    """The classifier must SPLIT rate limiting from other unconfirmed failures, or availability
    cannot tell "come back later" from "you may not use this"."""
    def throttled(argv):  # noqa: ANN001
        return _cp(rc=254, stderr="An error occurred (ThrottlingException): Rate exceeded")

    rt, _ = _snapstart_rt({"sts get-caller-identity": throttled})
    with pytest.raises(AwsThrottled):
        rt.available()


def test_an_access_denied_is_a_verdict_not_a_retry():
    """AccessDenied stays a plain AwsUnknownState -- still never evidence a worker died, but a
    definitive answer that this tier is unusable, so available() reports False rather than raising.
    """
    def denied(argv):  # noqa: ANN001
        return _cp(rc=254, stderr="An error occurred (AccessDenied) when calling GetCallerIdentity")

    rt, _ = _snapstart_rt({"sts get-caller-identity": denied})
    assert rt.available() is False


# ---------------------------------------------- #80: warm-slot reconciliation state machine

def test_a_half_succeeded_resume_is_re_parked(tmp_path=None):
    """THE motivating case (issue #80). resume() half-succeeds: start-instances is accepted and a
    later describe browns out, so the claim is handed back non-destructively with the instance
    RUNNING while the pool believes it is parked. Nothing re-hibernated it: the pool counted a
    parked warm slot while EC2 billed a running one until the uptime backstop fired.
    """
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    state, healthy, ticks = ["running"], [True], [1000.0]
    rt, fake = _hibernate_rt(state=state, healthy=healthy, clock=lambda: ticks[0])
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")
    rt._phase["s"] = "parked"      # what the pool believes

    assert rt.maintain_idle(slot) is True
    assert rt._phase["s"] == "warming", "the mismatch must be noticed from the OBSERVED state"

    ticks[0] += 10.0
    rt.maintain_idle(slot)         # next window: warmed + healthy -> re-issue the hibernate
    stops = [a for k, a in fake.calls if k == "ec2 stop-instances"]
    assert stops, "a running-but-recorded-parked instance was never re-hibernated"
    assert any("--hibernate" in a for a in stops)


def test_a_stopping_instance_is_not_claimable():
    """issue #80, finding 1: if EC2 accepts stop --hibernate but the response is LOST, the instance
    is 'stopping' -- which EC2 counts as alive and whose agent still answers. A claimant would
    resume it successfully and the pending hibernation would then complete DURING the job.

    The previous attempt guarded this with the phase bookkeeping, which is exactly the state a lost
    response corrupts, so it guarded nothing. Note the phase here says 'parked' -- i.e. wrong.
    """
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    state, healthy, ticks = ["stopping"], [True], [1000.0]
    rt, _ = _hibernate_rt(state=state, healthy=healthy, clock=lambda: ticks[0])
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")
    rt._phase["s"] = "parked"

    assert rt.is_alive_for_claim(slot) is None, (
        "a stopping instance must be skipped -- and skipped as UNKNOWN, never destroyed"
    )


def test_a_hibernation_stuck_in_stopping_is_eventually_given_up_on():
    """issue #80, finding 2: AWS documents instances getting stuck in 'stopping'. With no timeout
    escape the slot is unclaimable forever AND blocks its own replacement, so a warm_size=1 tier
    stays dead until someone intervenes.
    """
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    state, healthy, ticks = ["stopping"], [True], [1000.0]
    rt, _ = _hibernate_rt(state=state, healthy=healthy, clock=lambda: ticks[0],
                          hibernate_timeout_s=300.0)
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")
    # OUR hibernation, not an operator's. An accepted stop stamps _hib_started (and _phase) at
    # issue time, and a no-verdict one stamps _park_attempted, so a real `stopping` we care about
    # is never evidence-free. Without one of those markers this is an instance somebody ELSE
    # stopped, which is deliberately not adopted and so has no give-up clock to expire.
    rt._hib_started[slot.slot_id] = 1000.0

    assert rt.maintain_idle(slot) is True          # in flight, still plausible
    ticks[0] += 301.0
    assert rt.maintain_idle(slot) is False, "a stuck hibernation must be given up on, not held forever"


def test_an_instance_that_keeps_waking_up_still_reaches_the_give_up():
    """The escape must measure the whole EPISODE, not one attempt. A slot that keeps accepting the
    stop and landing back at 'running' re-drives each time; resetting the clock on each re-drive
    would cycle running -> stop -> running forever and never escape.
    """
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    state, healthy, ticks = ["running"], [True], [1000.0]
    rt, _ = _hibernate_rt(state=state, healthy=healthy, clock=lambda: ticks[0],
                          hibernate_timeout_s=300.0)
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")

    for _ in range(12):            # 12 cycles x 30s = 360s > 300s, each one re-driving
        rt.maintain_idle(slot)
        ticks[0] += 30.0
    assert rt.maintain_idle(slot) is False, (
        "re-driving reset the give-up clock, so the slot cycles forever"
    )


def test_reaching_stopped_clears_the_give_up_clock():
    """The mirror: a slot that DOES park must not carry a stale episode clock into its next park,
    or its second hibernation would be given up on early."""
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    state, healthy, ticks = ["running"], [True], [1000.0]
    rt, _ = _hibernate_rt(state=state, healthy=healthy, clock=lambda: ticks[0],
                          hibernate_timeout_s=300.0)
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")
    rt.maintain_idle(slot)                     # starts the episode
    assert "s" in rt._park_since
    state[0] = "stopped"
    ticks[0] += 10.0
    assert rt.maintain_idle(slot) is True
    assert rt._phase["s"] == "parked"
    assert "s" not in rt._park_since, "a completed park must clear its episode clock"


def test_maintain_idle_changes_nothing_when_the_control_plane_is_silent():
    """Reconciliation must be driven by an OBSERVATION. Acting on a guess is how the bookkeeping
    got corrupted in the first place."""
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot

    def throttled(argv):  # noqa: ANN001
        raise AwsProbeTimeout("Throttling: Rate exceeded")

    fake = FakeAws({**_IDENT, "ec2 run-instances": {"Instances": [{"InstanceId": "i-1"}]},
                    "ec2 describe-instances": throttled, "ec2 stop-instances": {}})
    cfg = Ec2HibernateConfig(region="us-east-1", image_id="ami-x", resume_poll_s=0.0)
    rt = Ec2HibernateRuntime(cfg, aws_runner=fake, http_probe=lambda u, h, t: True,
                             clock=lambda: 1000.0)
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")
    rt._phase["s"] = "parked"

    assert rt.maintain_idle(slot) is True, "a brownout must not retire a healthy parked slot"
    assert rt._phase["s"] == "parked", "and must not rewrite the bookkeeping on a guess"
    assert not [a for k, a in fake.calls if k == "ec2 stop-instances"]


# Red tests for findings A / B / C -- append to tests/host/runtime/test_aws_worker.py.
# Verified: all three FAIL on d1c83c0 and PASS with findings-ABC.patch applied.
# (test_aws_worker.py already imports _cp, FakeAws, _IDENT, _snapstart_rt, _hibernate_rt.)


def test_a_definitive_park_refusal_is_not_frozen_like_a_brownout():
    """The mirror of the freeze. AWS ANSWERING "AccessDenied" to stop-instances is a VERDICT.

    It arrives as a bare AwsUnknownState, and the freeze originally caught AwsUnknownState -- so a
    permanent refusal froze the give-up clock forever: _park_since never started, the slot was
    republished every pass, and the instance ran and billed indefinitely with liveness happily
    reporting it alive. Only silence (AwsNoVerdict) may freeze; a refusal must age the clock and
    be retired at give-up like any other slot that will not park.

    MUTATION: widen the freeze back to `except AwsUnknownState` -> maintain_idle never returns
    False and this fails.
    """
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    state, healthy, ticks = ["running"], [True], [1000.0]
    rt, fake = _hibernate_rt(state=state, healthy=healthy, clock=lambda: ticks[0],
                             hibernate_timeout_s=120.0)
    fake.responses["ec2 stop-instances"] = lambda argv: _cp(
        rc=254, stderr="An error occurred (AccessDenied) when calling the StopInstances operation")

    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")
    verdicts = []
    for _ in range(10):                       # 10 x 30s = 300s, well past hibernate_timeout_s
        verdicts.append(rt.maintain_idle(slot))
        ticks[0] += 30.0

    assert False in verdicts, (
        "a permanently REFUSED park never reached give-up: the clock was frozen as though the "
        "control plane had gone silent, so the instance runs and bills forever"
    )


def test_the_second_no_verdict_door_in_maintenance_freezes_too():
    """maintain_idle has TWO places a no-verdict can escape, and only the first froze.

    The opening `_state()` describe is handled; everything _park_step itself asks is not -- notably
    _agent_healthy, which issues its own describe when slot.ip is unset (a public-IP slot returned
    after a partial resume) and raises once the SHARED maintenance budget is spent by the first
    call. That path returned the slot as usable without freezing, so _park_since aged through every
    inconclusive pass until give-up retired a healthy, running instance.

    MUTATION: remove the AwsNoVerdict handler -> the outer (AwsWorkerError, OSError) branch catches
    it, nothing freezes, and this fails.
    """
    from blastbox.host.runtime.aws_worker import AwsNoVerdict, AwsWorkerSlot
    rt, _ = _hibernate_rt(state=["running"], healthy=[True], hibernate_timeout_s=300.0)
    slot = AwsWorkerSlot(slot_id="d2", resource_id="i-1")
    rt._park_since[slot.slot_id] = 1000.0

    def no_verdict(_slot):
        raise AwsNoVerdict("ec2 describe-instances: probe budget exhausted")

    rt._agent_healthy = no_verdict          # the SECOND describe, inside _park_step

    assert rt.maintain_idle(slot) is True, "a no-verdict must not report the slot unusable"
    assert slot.slot_id in rt._park_unknown_since, (
        "the second no-verdict door did not freeze the give-up clock; _park_since ages through "
        "every inconclusive pass until a healthy running instance is retired"
    )


def test_the_maintenance_door_freezes_the_park_clock_too():
    """is_ready and maintain_idle drive the SAME state machine against the SAME control plane.

    The freeze was applied to one of them. An IDLE slot's park clock therefore aged straight
    through a describe brownout on the maintenance path, and the first answered pass retired it --
    measured on one 400s outage: is_ready path park_expired=False, maintain_idle path
    park_expired=True, slot retired.

    MUTATION: remove the _freeze_park call from maintain_idle's handler -> the clock ages and the
    slot is given up on.
    """
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    ticks = [1000.0]
    rt, fake = _hibernate_rt(state=["running"], healthy=[True], clock=lambda: ticks[0],
                             hibernate_timeout_s=120.0)
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")
    rt.maintain_idle(slot)                       # starts the episode
    assert slot.slot_id in rt._park_since

    fake.responses["ec2 describe-instances"] = lambda argv: _cp(
        rc=254, stderr="An error occurred (RequestLimitExceeded) when calling DescribeInstances")
    for _ in range(8):                           # 240s of brownout, driven ONLY through maintain_idle
        rt.maintain_idle(slot)
        ticks[0] += 30.0

    assert slot.slot_id in rt._park_unknown_since, (
        "the maintenance door never opened a no-verdict episode, so the give-up clock aged through "
        "an outage in which nothing was learned about the slot"
    )


def test_a_describe_brownout_does_not_age_the_park_clock():
    """The freeze has to cover BOTH doors. _park_step is never reached when the describe itself is
    unanswered, so the independent hibernation timer kept running through a describe brownout: an
    outage covering the remainder of hibernate_timeout_s -- comfortably inside the default UNKNOWN
    grace -- meant the first recovered `running` observation went straight to _park_expired and
    retired a healthy slot before even retrying the park.

    MUTATION: drop the _park_unknown_since stamp from is_ready's AwsUnknownState handler -> the
    clock ages through the outage and the slot is given up on.
    """
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    state, healthy, ticks = ["running"], [True], [1000.0]
    rt, fake = _hibernate_rt(state=state, healthy=healthy, clock=lambda: ticks[0],
                             hibernate_timeout_s=120.0)
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")

    rt.maintain_idle(slot)                    # starts the park episode
    assert slot.slot_id in rt._park_since, "sanity: the park clock must have started"

    fake.responses["ec2 describe-instances"] = lambda argv: _cp(
        rc=254, stderr="An error occurred (RequestLimitExceeded) when calling DescribeInstances")
    # 90s of brownout. Deliberately INSIDE the freeze's bound (one hibernate_timeout_s of frozen
    # time): the freeze absorbs a brownout, it does not absorb an outage. An earlier version ran
    # 240s here and started failing the moment the bound was added -- correctly, because 120s
    # elapsed plus 120s frozen is the whole allowance. The unbounded case is pinned separately by
    # test_an_indefinite_freeze_still_expires.
    for _ in range(3):
        rt.is_ready(slot)
        ticks[0] += 30.0

    fake.responses["ec2 describe-instances"] = lambda argv: _cp(stdout=json.dumps(
        {"Reservations": [{"Instances": [
            {"InstanceId": "i-1", "State": {"Name": "running"}, "PrivateIpAddress": "10.0.0.5"}]}]}))
    # TWO passes on purpose. A slot recorded `hibernating` but observed `running` takes the
    # "re-driving to warm" branch, which returns BEFORE _park_expired -- so a single call cannot
    # discriminate here at all, and the first version of this test passed with the fix reverted.
    verdicts = []
    for _ in range(2):
        verdicts.append(rt.maintain_idle(slot))
        ticks[0] += 30.0
    assert False not in verdicts, (
        f"the slot was retired on recovery ({verdicts}): the park clock aged through a DESCRIBE "
        f"outage in which we learned nothing about it"
    )


def test_a_slow_stop_call_is_not_re_issued_the_instant_it_returns():
    """Found by sweeping for the shape, not by a review: the FOURTH site on this branch where a
    rate-limit stamp was taken BEFORE the slow call it throttles.

    _hib_attempt gates `stop-instances --hibernate` at _liveness_cache_s (5s), but that call is
    bounded by the health-probe budget (30s), or cli_timeout_s (120s) unbudgeted. Stamping only on
    entry leaves the mark six to twenty-four times older than the interval by the time the call
    returns, so the next pass re-issues it immediately and the pool's sole tick thread does nothing
    but stop-instances for the duration of a control-plane stall.

    MUTATION: drop the finally re-stamp -> every pass issues another stop and this fails.
    """
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    ticks = [1000.0]
    calls: list = []
    rt, fake = _hibernate_rt(state=["running"], healthy=[True], clock=lambda: ticks[0])

    def slow_stop(argv):
        calls.append(ticks[0])
        ticks[0] += 30.0            # a stalled stop-instances at the health-probe bound
        return _cp()

    fake.responses["ec2 stop-instances"] = slow_stop
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")

    for _ in range(5):
        rt._try_park(slot)
        ticks[0] += 0.1             # the pool's tick interval

    assert len(calls) == 1, (
        f"{len(calls)} stop-instances calls in {ticks[0] - 1000.0:.0f}s against a 5s throttle: a "
        f"call that outruns its own interval is eligible the moment it returns"
    )


def test_recovery_observing_stopping_credits_the_brownout_like_every_other_closer():
    """The two closers of the freeze disagreed, and the disagreement was inverted.

    The answered-stop closer credited the outage back to the give-up clock; the `stopping` closer
    popped the freeze bare, charging the whole brownout to the episode. `stopping` is the HEALTHY
    observation -- the hibernate is in flight and progressing -- so recovery on `running` was
    forgiven while recovery on `stopping` retired the slot. The failing state pardoned, the
    succeeding one convicted. One _thaw_park is the fix.

    MUTATION: replace the _thaw_park call in the `stopping` branch with a bare pop -> the episode
    is charged the full outage and this gives up.
    """
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    ticks = [1000.0]
    rt, fake = _hibernate_rt(state=["running"], healthy=[True], clock=lambda: ticks[0],
                             hibernate_timeout_s=300.0)
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")

    rt.maintain_idle(slot)                       # accepted stop -> _park_since starts
    assert slot.slot_id in rt._park_since

    fake.responses["ec2 describe-instances"] = lambda argv: _cp(
        rc=254, stderr="An error occurred (RequestLimitExceeded) when calling DescribeInstances")
    for _ in range(14):                          # 420s > hibernate_timeout_s, all unanswered
        rt.is_ready(slot)
        ticks[0] += 30.0

    # AWS answers again, and what it says is `stopping`: the hibernate WAS accepted.
    fake.responses["ec2 describe-instances"] = lambda argv: _cp(stdout=json.dumps(
        {"Reservations": [{"Instances": [
            {"InstanceId": "i-1", "State": {"Name": "stopping"}, "PrivateIpAddress": "10.0.0.5"}]}]}))
    assert rt.maintain_idle(slot) is not False, (
        "a slot whose hibernate was PROGRESSING was retired on recovery: the brownout was charged "
        "to the give-up clock because this closer did not credit it"
    )


def test_a_definitive_agent_answer_closes_the_freeze():
    """"Only SILENCE freezes" has to run in BOTH directions.

    The agent-probe writer opens an episode on `_agent_healthy() is None` and had no closer, so a
    slot that went unknown ONCE and was thereafter definitively unhealthy kept _park_expired pinned
    to that first timestamp: give-up was unreachable and maintenance republished a running, billing
    instance. The bound caps the damage; it is not a substitute for closing on an answer.

    MUTATION: remove the _thaw_park from the `not healthy` branch -> the episode stays open.
    """
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    ticks = [1000.0]
    healthy: list = [None]
    rt, _ = _hibernate_rt(state=["running"], healthy=[True], clock=lambda: ticks[0],
                          hibernate_timeout_s=300.0)
    rt._agent_healthy = lambda slot: healthy[0]
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")

    rt._park_since[slot.slot_id] = 1000.0
    rt.maintain_idle(slot)                       # UNKNOWN agent -> freeze opens
    assert slot.slot_id in rt._park_unknown_since, "sanity: the episode must open"

    healthy[0] = False                           # now a DEFINITIVE answer: not warm yet
    ticks[0] += 30.0
    rt.maintain_idle(slot)

    assert slot.slot_id not in rt._park_unknown_since, (
        "a definitive agent answer left the freeze open; the give-up clock stays pinned to the "
        "first UNKNOWN and a running, billing instance is republished forever"
    )


def test_a_stopped_instance_that_never_tried_to_hibernate_is_not_a_parked_slot():
    """`stopped` was adopted as parked+ready unconditionally.

    A failed boot, or an operator stopping the instance by hand, reaches `stopped` with no warmed
    process ever captured. Adopting it advertises capacity that cannot serve, and a claim spends
    the whole resume budget starting an instance whose agent was never up.

    MUTATION: drop the `attempted` guard -> the slot is reported ready.
    """
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    rt, _ = _hibernate_rt(state=["stopped"], healthy=[True])
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")
    assert slot.slot_id not in rt._park_since and slot.slot_id not in rt._hib_started

    phase, ready = rt._park_step(slot, "stopped", 1000.0)
    assert ready is not True, (
        f"a stopped instance with no hibernation ever attempted was reported ready (phase={phase})"
    )


def test_a_partially_resumed_slot_restarts_the_give_up_clock():
    """A slot that reached `parked` had _park_since POPPED.

    Coming back RUNNING after a half-succeeded resume therefore left no clock at all, and if the
    resumed agent stays unhealthy _park_step returns before _try_park is ever reached -- so nothing
    starts one later either, and maintenance republishes a running, billing instance indefinitely.

    MUTATION: remove the _park_since.setdefault from the re-drive branch -> no clock is started.
    """
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    rt, _ = _hibernate_rt(state=["running"], healthy=[True])
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")
    rt._phase[slot.slot_id] = "parked"           # we believed it was hibernated
    assert slot.slot_id not in rt._park_since, "parked slots have no give-up clock"

    rt._park_step(slot, "running", 1000.0)       # ...but it is awake and billing

    assert slot.slot_id in rt._park_since, (
        "the re-drive started no give-up clock, so an instance whose agent never recovers is "
        "republished forever with nothing able to retire it"
    )


def test_the_settle_window_survives_a_slow_stop():
    """The settle window is measured from _hib_started, which was stamped PRE-call.

    stop-instances is bounded at 30s (budgeted) or 120s (not), against a 5s window -- so the
    duration of the stop itself consumed the whole window and the guard was a no-op for exactly
    the THROTTLED case it exists for. Measured on the boundary: a 1s stop held the guard, 6s and
    30s did not. Sixth instance of stamp-before-call on this branch, three lines below the sibling
    that does it right.

    MUTATION: stamp _hib_started from the pre-call `now` -> a slow stop reopens the claim gate.
    """
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    ticks = [1000.0]
    rt, fake = _hibernate_rt(state=["running"], healthy=[True], clock=lambda: ticks[0])

    def slow_stop(argv):
        ticks[0] += 30.0                  # a throttled-but-accepted stop
        return _cp()

    fake.responses["ec2 stop-instances"] = slow_stop
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1", state=SlotState.IDLE,
                         url="http://10.0.0.5:8080")

    rt._try_park(slot)                    # accepted, 30s later
    assert rt._phase.get(slot.slot_id) == "hibernating"
    ticks[0] += 0.2                       # the very next poll: describe is still stale `running`
    rt._park_step(slot, "running", ticks[0])

    assert rt._phase.get(slot.slot_id) == "hibernating", (
        "a stale `running` re-drove an ACCEPTED hibernate because the settle window had already "
        "been spent by the stop call itself; the claim gate is now open"
    )


def test_the_boot_warm_up_is_not_credited_to_the_park_clock():
    """A freeze opened because the AGENT was unprobeable is not evidence of parking.

    `_agent_healthy` returns None whenever the address has not resolved -- every poll of a
    just-booted instance -- so removing the "only credit if a clock exists" guard banked the whole
    boot window and then subtracted it from a clock that starts afterwards. That buys up to a
    second hibernate_timeout_s of suppression an operator cannot configure away.

    MUTATION: credit unconditionally in _thaw_park -> the boot window is banked and this fails.
    """
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    ticks = [1000.0]
    rt, _ = _hibernate_rt(state=["running"], healthy=[True], clock=lambda: ticks[0],
                          hibernate_timeout_s=300.0)
    slot = AwsWorkerSlot(slot_id="b1", resource_id="i-1")

    rt._freeze_park(slot.slot_id, ticks[0])       # agent unprobeable at boot (NOT a park attempt)
    ticks[0] += 120.0
    rt._thaw_park(slot.slot_id, ticks[0])         # the agent finally answers
    rt._park_since[slot.slot_id] = ticks[0]       # ...and only NOW does parking begin

    assert rt._park_credit.get(slot.slot_id, 0.0) == 0.0, (
        f"{rt._park_credit.get(slot.slot_id)}s of BOOT time was banked against a give-up clock "
        f"that did not exist during it"
    )
    # ...so the escape fires on schedule, at park_since + hibernate_timeout_s, rather than being
    # pushed out by the whole boot window.
    assert rt._park_expired(slot.slot_id, ticks[0] + 301.0), (
        "the give-up escape was delayed past its budget by credit banked before the clock existed; "
        "the instance runs and bills for roughly twice hibernate_timeout_s"
    )


def test_a_lost_response_hibernate_is_still_recognised_as_parked():
    """In the lost-response case the ONLY park evidence is the open episode.

    A definitive-unhealthy agent probe thaws it -- the guest is shutting down, so the health socket
    refuses, which is a real False, not a None -- and nothing replaced the evidence. The `stopped`
    that followed was then refused as "no hibernation ever attempted": a genuinely parked slot
    discarded, and with no _park_since the give-up escape could never fire either.

    MUTATION: drop the _park_attempted bookkeeping -> the slot is refused.
    """
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    rt, _ = _hibernate_rt(state=["stopped"], healthy=[True])
    slot = AwsWorkerSlot(slot_id="h2", resource_id="i-1")

    rt._freeze_park(slot.slot_id, 1000.0, park_attempted=True)   # stop issued, no verdict
    rt._thaw_park(slot.slot_id, 1010.0)                          # agent answers a definitive False

    phase, ready = rt._park_step(slot, "stopped", 1020.0)
    assert ready is True and phase == "parked", (
        f"a slot whose hibernate WAS accepted was refused (phase={phase}, ready={ready}); the "
        f"thaw destroyed the only evidence the attempt ever happened"
    )


def test_a_lost_response_park_attempt_starts_the_give_up_clock():
    """...and the evidence has to become a CLOCK, not just an adoption flag.

    A stop we issued and never got a verdict on deliberately does not start _park_since -- silence
    is not evidence. But the ANSWER that closes the episode is, and if the clock never starts, a
    lost-response hibernate that then fails to complete can never reach give-up: the instance runs
    and bills with nothing able to retire it.

    MUTATION: drop the `_park_attempted and not in _park_since` branch in _thaw_park -> no clock.
    """
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    rt, _ = _hibernate_rt(state=["running"], healthy=[True])
    slot = AwsWorkerSlot(slot_id="h3", resource_id="i-1")

    rt._freeze_park(slot.slot_id, 1000.0, park_attempted=True)
    assert slot.slot_id not in rt._park_since, "silence alone must not start the clock"
    rt._thaw_park(slot.slot_id, 1010.0)

    assert slot.slot_id in rt._park_since, (
        "the answer that closed a lost-response episode started no give-up clock; a hibernate that "
        "never completes can never be retired"
    )


def test_a_write_racing_a_reap_cannot_resurrect_a_departed_slot():
    """Disposal runs on the pool's dedicated reaper threads; the park machine runs on the tick
    thread. A write that started before the reap can therefore land after it.

    Slot ids are per-spawn UUIDs, so anything re-created that way is never removed again -- the
    per-slot dicts grow for the process lifetime on a disposable tier. Bounded FIFO tombstones
    suppress the late write instead.

    MUTATION: drop the _slot_is_gone guards -> the freeze re-creates an entry for a reaped slot.
    """
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    rt, fake = _hibernate_rt(state=["stopped"], healthy=[True])
    fake.responses["ec2 terminate-instances"] = {}   # the reap must SUCCEED for a tombstone
    slot = AwsWorkerSlot(slot_id="ghost", resource_id="i-1")
    rt._park_since[slot.slot_id] = 1000.0

    rt.reap(slot)                                  # reaper thread disposes of it
    assert slot.slot_id not in rt._park_since, "sanity: reap clears the per-slot state"

    rt._freeze_park(slot.slot_id, 2000.0)          # a tick-thread write already in flight
    # Checked HERE as well as at the end: _thaw_park pops what _freeze_park created, so asserting
    # only after both runs lets a broken freeze hide behind a working thaw -- which is exactly how
    # the first version of this test survived its own mutant.
    assert slot.slot_id not in rt._park_unknown_since, (
        "_freeze_park re-created an episode for a slot that has already been reaped")

    rt._thaw_park(slot.slot_id, 2100.0)

    # And the other interleaving, which the freeze guard cannot cover: the thaw had ALREADY read
    # the open episode when the reap landed, so it arrives holding a real `stalled` value and would
    # bank credit for a slot that is gone. Simulated by putting the entry back, since reproducing
    # the true interleaving needs two threads.
    rt._park_unknown_since[slot.slot_id] = 2000.0
    rt._thaw_park(slot.slot_id, 2200.0)

    # And _park_step itself -- the DOMINANT writer of the entries reap clears. Guarding only the
    # two credit helpers left the main path unprotected, which the direct freeze/thaw calls above
    # cannot detect.
    # 'stopping' on purpose: that branch writes _phase, _hib_started and _park_since DIRECTLY,
    # without passing through _try_park -- whose own tombstone guard would otherwise cover for a
    # missing one in _park_step and hide the gap.
    rt._park_step(slot, "stopping", 2300.0)
    step_leaked = [n for n, d in (("_phase", rt._phase), ("_hib_started", rt._hib_started),
                                  ("_park_since", rt._park_since))
                   if slot.slot_id in d]
    assert not step_leaked, (
        f"_park_step re-created {step_leaked} for a reaped slot; it writes _phase, _hib_started "
        f"and _park_since, none of which the credit-helper guards cover"
    )

    leaked = [name for name, d in (("_park_unknown_since", rt._park_unknown_since),
                                   ("_park_credit", rt._park_credit))
              if slot.slot_id in d]
    assert not leaked, (
        f"a write that raced the reap re-created {leaked} for a slot that no longer exists; the "
        f"id is a per-spawn UUID, so nothing will ever remove it again"
    )


def test_a_no_verdict_stop_is_unknown_to_the_pool_too():
    """The tri-state has to be honoured on the way OUT, not just on the way in.

    _park_step froze ITS clock on an unanswered stop and then handed the pool `ready=False` -- a
    definitive verdict we do not have. _promote_warming ends the slot's warming-unknown episode on
    any definitive answer, so the pool's warming timeout resumed aging and evicted the tier's
    WARMING population over a stop API that never answered. Freezing our clock while lying to the
    pool just moves the same drain one layer up.

    MUTATION: return False instead of None from the AwsNoVerdict branch -> is_ready reports a
    definitive not-ready and this fails.
    """
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    rt, fake = _hibernate_rt(state=["running"], healthy=[True])
    fake.responses["ec2 stop-instances"] = lambda argv: _cp(
        rc=254, stderr="An error occurred (RequestLimitExceeded) when calling StopInstances")
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")

    assert rt.is_ready(slot) is None, (
        "an unanswered stop was reported to the pool as a DEFINITIVE not-ready; the warming "
        "timeout resumes aging and the tier's WARMING population is evicted over a silent API"
    )


def test_a_stale_running_read_does_not_erase_the_hibernation_claim_guard():
    """DescribeInstances is eventually consistent -- this file depends on that elsewhere.

    So a `running` reading can simply be stale for a window after a stop was ACCEPTED. Re-driving
    on it wiped phase="hibernating", which IS the claim gate: is_alive_for_claim then saw "warming"
    plus another stale `running`, authorised the claim, and the accepted hibernation suspended the
    instance mid-job. That is the original #80 hazard, reopened from the other side.

    MUTATION: drop the settle-window check -> the phase is wiped and the slot becomes claimable.
    """
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    ticks = [1000.0]
    rt, _ = _hibernate_rt(state=["running"], healthy=[True], clock=lambda: ticks[0])
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1", state=SlotState.IDLE,
                         url="http://10.0.0.5:8080")
    rt._phase[slot.slot_id] = "hibernating"      # the stop was accepted...
    rt._hib_started[slot.slot_id] = ticks[0]
    ticks[0] += 1.0                              # ...1s ago; well inside the settle window

    rt._park_step(slot, "running", ticks[0])     # ...and describe still says `running`

    assert rt._phase.get(slot.slot_id) == "hibernating", (
        "a stale `running` read wiped the hibernating phase, removing the claim guard while the "
        "accepted stop was still in flight"
    )
    assert rt.is_alive_for_claim(slot, budget_s=5.0) is None, "the slot must stay unclaimable"


def test_a_failed_terminate_keeps_the_evidence_needed_to_reclaim_the_slot():
    """reap() cleared the park bookkeeping BEFORE terminating.

    That only holds if the terminate succeeds. When it raises -- the correlated-brownout case,
    where the pool keeps the slot and quarantines or restores it -- the runtime has already thrown
    away every trace that this slot was parking. It matters more now that `stopped` is only adopted
    as a parked warm slot when park evidence exists: the slot would come back with all of it gone
    and its own hibernation no longer recognisable, so it would read not-ready forever.

    MUTATION: clear the dicts before super().reap() -> the evidence is gone after a failed
    terminate and this fails.
    """
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    rt, fake = _hibernate_rt(state=["stopped"], healthy=[True])
    fake.responses["ec2 terminate-instances"] = lambda argv: _cp(
        rc=254, stderr="An error occurred (RequestLimitExceeded) when calling TerminateInstances")
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")
    rt._phase[slot.slot_id] = "parked"
    rt._park_since[slot.slot_id] = 1000.0

    with contextlib.suppress(Exception):
        rt.reap(slot)

    assert rt._phase.get(slot.slot_id) == "parked" or slot.slot_id in rt._park_since, (
        "a FAILED terminate still wiped the park evidence; the retained slot can no longer be "
        "recognised as a parked worker and reads not-ready forever"
    )


def test_repeated_brownouts_cannot_reset_the_give_up_clock():
    """The cap has to govern the TOTAL, not just an open episode.

    _park_expired capped a LIVE freeze, so closing one banked its whole interval uncapped. A
    partial brownout -- silence broken by one answered pass -- therefore moved the clock's origin
    forward every cycle and the effective age never grew. Measured before the ledger: 6.9h of wall
    clock with the age pinned at 5s, the slot never retired, the instance billing throughout. That
    is the same failure the cap was added to end, re-entered through the closer.

    MUTATION: bank into _park_since instead of the capped ledger -> the age resets every cycle and
    give-up never fires.
    """
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    ticks = [1000.0]
    rt, _ = _hibernate_rt(state=["running"], healthy=[True], clock=lambda: ticks[0],
                          hibernate_timeout_s=300.0)
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")
    rt._park_since[slot.slot_id] = 1000.0

    # 20 cycles of "500s of silence, then one answered pass". Each answered pass is a DEFINITIVE
    # observation that the slot is still failing to park.
    for _ in range(20):
        rt._freeze_park(slot.slot_id, ticks[0])
        ticks[0] += 500.0
        rt._thaw_park(slot.slot_id, ticks[0])
        ticks[0] += 5.0

    assert rt._park_expired(slot.slot_id, ticks[0]), (
        f"after {ticks[0] - 1000.0:.0f}s of wall clock against a 300s budget the slot still has "
        f"not reached give-up: each closed brownout credited uncapped, so the age resets forever"
    )


def test_crediting_never_puts_the_park_clock_in_the_future():
    """_park_since must stay a FACT: when parking began.

    The `stopping` closer used to credit against a clock it created in the same breath -- the
    lost-response case has no clock, so setdefault(now) then += (now - stalled) landed _park_since
    in the FUTURE by the whole outage. Measured: the give-up escape fired at 7510s instead of 310s,
    and logged "stuck for 310s" while doing it. A future-dated origin also poisons every later
    freeze, since `now - started - credited` goes permanently negative.

    MUTATION: have _thaw_park do `self._park_since[sid] += ...` -> the clock jumps ahead.
    """
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    rt, _ = _hibernate_rt(state=["stopping"], healthy=[True], hibernate_timeout_s=300.0)
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")

    # park_attempted=True: this models a STOP WE ISSUED whose response was lost, which is what
    # the docstring describes and what _try_park's AwsNoVerdict handler actually records. A bare
    # freeze is the observation-only kind (an unreadable describe), which is deliberately NOT
    # parking evidence -- so it would not reach the crediting path this test is about.
    rt._freeze_park(slot.slot_id, 1000.0, park_attempted=True)   # no verdict, and NO _park_since
    assert slot.slot_id not in rt._park_since, "the lost-response case starts with no clock"

    now = 8200.0                                 # 7200s later, AWS finally answers 'stopping'
    rt._park_step(slot, "stopping", now)

    started = rt._park_since.get(slot.slot_id)
    assert started is not None and started <= now, (
        f"_park_since={started} is in the future relative to now={now}; the escape cannot fire "
        f"until wall-clock catches up, and every later freeze computes a negative age"
    )


def test_an_indefinite_freeze_still_expires():
    """The freeze must be BOUNDED, or it is worse than the drain it prevents.

    Unbounded, it was closable only by an event it could itself suppress: the agent-probe writer
    opens on `_agent_healthy() is None`, and that same condition returns before _try_park is ever
    reached, so nothing could close it. Measured before the bound: 6.6 simulated hours, ONE
    stop-instances attempt, the slot never retired and a RUNNING instance billing throughout.
    Ride out a brownout; do not ride out an outage.

    MUTATION: drop the min(now, frozen_at + hibernate_timeout_s) cap -> the clock is frozen at the
    episode start forever and the slot never gives up.
    """
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    ticks = [1000.0]
    rt, _ = _hibernate_rt(state=["running"], healthy=[True], clock=lambda: ticks[0],
                          hibernate_timeout_s=300.0)
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")

    rt._park_since[slot.slot_id] = 1000.0
    rt._freeze_park(slot.slot_id, 1000.0)        # and nothing will ever close it
    ticks[0] += 24 * 3600.0                      # a day of frozen time

    assert rt._park_expired(slot.slot_id, ticks[0]), (
        "the give-up clock was suppressed for a full day; hibernate_timeout_s is unreachable and "
        "the instance bills forever"
    )


def test_an_unresolved_park_attempt_makes_the_slot_unclaimable():
    """A lost `stop-instances` response leaves the phase at "warming" -- only a SUCCESSFUL stop
    advances it -- and EC2 can still describe the instance as `running` for a window afterwards.

    So both existing claim-gate checks pass and the slot is handed to a job that the accepted
    hibernation then suspends underneath it: the original #80 hazard, reopened by the freeze.

    MUTATION: drop the _park_unknown_since check from is_alive_for_claim -> the slot is authorised.
    """
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    rt, _ = _hibernate_rt(state=["running"], healthy=[True])
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1", state=SlotState.IDLE,
                         url="http://10.0.0.5:8080")
    rt._freeze_park(slot.slot_id, 1000.0)        # a stop we never got a verdict on
    assert rt._phase.get(slot.slot_id) != "hibernating", "the lost-response case: phase unchanged"

    assert rt.is_alive_for_claim(slot, budget_s=5.0) is None, (
        "a slot with an unresolved park attempt was reported claimable; if that stop was in fact "
        "accepted, the instance suspends mid-job"
    )


def test_a_server_side_timeout_is_a_non_answer_not_a_refusal():
    """The AwsNoVerdict boundary was drawn on a throttle-marker list that omitted timeouts.

    RequestTimeout fell through to bare AwsUnknownState, so `available()` read it as a DEFINITIVE
    unusable tier and _try_park read it as an ANSWERED refusal that advances the give-up clock --
    both the opposite of what a timeout means. Narrowing the class without widening this list made
    real transients worse.

    MUTATION: drop the timeout markers -> the timeout is classified definitive and this fails.
    """
    from blastbox.host.runtime.aws_worker import AwsNoVerdict, _is_throttle_aws_error
    for stderr in (
        "An error occurred (RequestTimeout) when calling the StopInstances operation",
        "An error occurred (RequestTimeoutException) when calling the GetMicrovm operation",
        "An error occurred (InternalError) when calling the DescribeInstances operation",
        "Could not connect to the endpoint URL: https://ec2.us-east-1.amazonaws.com/",
    ):
        assert _is_throttle_aws_error(stderr), f"classified as a definitive answer: {stderr[:60]}"

    # ...and AccessDenied must STAY definitive; that is the whole point of the boundary.
    assert not _is_throttle_aws_error(
        "An error occurred (AccessDenied) when calling the StopInstances operation")
    assert issubclass(AwsNoVerdict, AwsUnknownState)


def test_a_stop_api_brownout_does_not_drain_the_hibernate_tier():
    """issue #79, park path: `stop-instances --hibernate` being THROTTLED is the control plane
    failing to answer, not this slot failing to park. _try_park caught it as a generic
    AwsWorkerError and reported a definitive not-accepted, so the give-up clock kept aging and
    every healthy warm worker in the tier was retired after hibernate_timeout_s -- during exactly
    the brownout when replacing them is least possible.
    """
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    state, healthy, ticks = ["running"], [True], [1000.0]
    rt, fake = _hibernate_rt(state=state, healthy=healthy, clock=lambda: ticks[0],
                             hibernate_timeout_s=300.0)
    fake.responses["ec2 stop-instances"] = lambda argv: _cp(
        rc=254, stderr="An error occurred (RequestLimitExceeded) when calling StopInstances")

    for _ in range(14):                      # 14 x 30s = 420s > 300s of stop-API brownout
        assert rt.maintain_idle(slot := AwsWorkerSlot(slot_id="s", resource_id="i-1")) is True, (
            "a healthy warm worker was retired over a stop API that never answered"
        )
        ticks[0] += 30.0
    assert slot is not None


def test_b_a_failed_readiness_describe_is_not_repeated():
    """upstream P2: _observed_not_running re-asked the control plane for the state _health_ok had
    just failed to read. Failed describes are not cached, so one warming slot cost TWO full
    cli_timeout_s windows per pass on the pool's single maintenance thread.
    """
    import subprocess as _sp
    n = {"describe": 0}

    def stalled(argv):  # noqa: ANN001
        n["describe"] += 1
        raise _sp.TimeoutExpired(cmd="aws", timeout=120.0)

    rt, _ = _snapstart_rt({"lambda-microvms get-microvm": stalled})
    slot = AwsWorkerSlot(slot_id="s", resource_id="mv-1")
    assert rt.is_ready(slot) is None
    assert n["describe"] == 1, "the readiness path bought the same non-answer twice"


def test_a_slow_failed_describe_memo_outlives_the_call_that_wrote_it():
    """The memo has to be stamped from COMPLETION, or it is born expired.

    A failed describe is the SLOW case -- it usually failed by timing out. Storing the pre-call
    clock against a 5s memo means a 30s failure writes a mark that is already 25s stale when
    control returns, so the very next caller reissues the describe the memo exists to prevent.
    test_b above cannot see this: its stall raises instantly on a fake clock that never advances.

    MUTATION: store the pre-call `now` -> the memo is expired on arrival and the describe runs
    twice.
    """
    import subprocess as _sp
    ticks = [1000.0]
    n = {"describe": 0}

    def slow_fail(argv):  # noqa: ANN001
        n["describe"] += 1
        ticks[0] += 30.0                    # the failure took six times the 5s memo window
        raise _sp.TimeoutExpired(cmd="aws", timeout=30.0)

    rt, _ = _snapstart_rt({"lambda-microvms get-microvm": slow_fail}, clock=lambda: ticks[0])
    slot = AwsWorkerSlot(slot_id="s", resource_id="mv-1")
    assert rt.is_ready(slot) is None
    assert n["describe"] == 1, (
        f"{n['describe']} describes: the failure memo was stamped before a call that outran it, "
        f"so it expired the instant it was written"
    )


def test_c_an_unreadable_availability_answer_is_not_a_verdict():
    """issue #79 round 2: availability is probed ONCE, so a False drops the tier for the whole
    process lifetime (or, for the primary, refuses to start). A truncated/unparseable STS response
    -- or a host that could not even fork the aws process -- is not an answer about entitlement.
    """
    def truncated(argv):  # noqa: ANN001
        return _cp(stdout='{"Account": "1234567890')          # rc=0, unreadable

    def cannot_execute(argv):  # noqa: ANN001
        raise OSError(errno.EMFILE, "Too many open files")

    for responder in (truncated, cannot_execute):
        rt, _ = _snapstart_rt({"sts get-caller-identity": responder})
        with pytest.raises(AwsUnknownState):
            rt.available()

    # ... and the mirror stays intact: AccessDenied IS a verdict about a tier.
    def denied(argv):  # noqa: ANN001
        return _cp(rc=254, stderr="An error occurred (AccessDenied) when calling GetCallerIdentity")

    rt, _ = _snapstart_rt({"sts get-caller-identity": denied})
    assert rt.available() is False


def test_an_unknown_agent_probe_does_not_age_the_park_clock():
    """`_agent_healthy` is tri-state; the park state machine falsy-checked it.

    None means the probe could not be MADE -- e.g. the host cannot open the health socket because
    of correlated local resource exhaustion. That says nothing about the worker, but `if not
    self._agent_healthy(slot)` read it as "not warm yet", so the give-up clock kept running and a
    healthy instance was eventually retired. Same class as every other UNKNOWN collapse on this
    branch, and the same remedy: freeze the clock.

    MUTATION: restore `if not self._agent_healthy(slot)` -> the clock ages and this fails.
    """
    now = [1000.0]
    rt, _ = _hibernate_rt(state=["running"], healthy=[True], clock=lambda: now[0],
                          hibernate_timeout_s=60.0)
    rt._agent_healthy = lambda slot: None          # cannot probe at all
    slot = AwsWorkerSlot(slot_id="hz", resource_id="i-1", state=SlotState.IDLE,
                         url="http://10.0.0.5:8080")

    for _ in range(12):                            # well past hibernate_timeout_s
        rt.maintain_idle(slot)
        now[0] += 10.0

    assert rt.maintain_idle(slot) is not False, (
        "an unprobeable agent aged the park clock to give-up and the slot was retired; the host "
        "not being able to open a socket is not evidence about the worker"
    )


def test_a_refused_hibernation_is_not_parking_evidence():
    """`stopped` is adopted as a parked warm slot only on evidence that WE parked it. The evidence
    set included _park_since -- but _park_since was started for a DEFINITIVE REFUSAL too, because
    the call site collapsed the three-way answer with `_try_park(...) is not None` (False is not
    None). So a slot AWS flatly refused to hibernate, later stopped by an operator or an
    autoscaler, was adopted as parked: the pool advertises capacity that cannot serve, and a claim
    spends the whole resume budget starting an instance whose agent was never captured.

    A refusal still spends the give-up budget -- it IS a verdict -- but it is not evidence of a
    park."""
    state, healthy = ["running"], [True]
    t = [1000.0]
    # ADVANCING clock: the describe is cached per liveness window, so a constant clock would leave
    # the second pass looking at the stale `running` and prove nothing.
    rt, fake = _hibernate_rt(state=state, healthy=healthy, clock=lambda: t[0])
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")

    # AWS definitively REFUSES the hibernation.
    rt._try_park = lambda s: False
    rt.is_ready(slot)
    assert "s" in rt._park_refused, "a definitive refusal must be recorded as such"
    assert "s" in rt._park_since, "...and must still run the give-up clock"

    # Something else stops the instance.
    state[0] = "stopped"
    t[0] += 60.0
    assert rt.is_ready(slot) is not True, (
        "an instance AWS refused to hibernate was adopted as a parked warm slot")
    assert rt._phase.get("s") != "parked"


def test_an_accepted_hibernation_is_still_adopted_when_stopped():
    """Control: the evidence rule must not reject a real park."""
    state, healthy = ["running"], [True]
    t = [1000.0]
    rt, _ = _hibernate_rt(state=state, healthy=healthy, clock=lambda: t[0])
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")

    rt._try_park = lambda s: True                     # AWS ACCEPTS
    rt.is_ready(slot)
    assert "s" not in rt._park_refused

    state[0] = "stopped"
    t[0] += 60.0
    assert rt.is_ready(slot) is True, "a genuinely parked slot must still be adopted"
    assert rt._phase.get("s") == "parked"


def test_a_refusal_followed_by_an_acceptance_clears_the_mark():
    """A tier that refuses while the hibinit agent lays down its reserve, then accepts, is parked
    for real -- the refusal must not disqualify it forever."""
    state, healthy = ["running"], [True]
    t = [1000.0]
    rt, _ = _hibernate_rt(state=state, healthy=healthy, clock=lambda: t[0])
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")

    rt._try_park = lambda s: False
    rt.is_ready(slot)
    assert "s" in rt._park_refused

    t[0] += 60.0
    rt._try_park = lambda s: True
    rt.is_ready(slot)
    assert "s" not in rt._park_refused, "an accepted attempt must clear the refusal mark"

    state[0] = "stopped"
    t[0] += 60.0
    assert rt.is_ready(slot) is True


def test_an_empty_service_probe_is_no_verdict_not_availability():
    """A DOCUMENT query that answers with nothing has not answered. Only sts get-caller-identity
    opted into expect_output, so an empty rc=0 from the service probes parsed to {} and every
    caller read it as a real answer:

      * lambda list-microvms / ec2 describe-instances -> `return True`, so the tier was ADMITTED
        with no service verdict behind it;
      * ec2 describe-instance-types -> `its == []` -> "does not support hibernation", a definitive
        verdict that permanently DROPS the hibernate tier (or blocks pool startup) on what was
        actually a blank answer. That is the transient-read-as-dead class issue #79 removes.

    AwsNoVerdict is an AwsUnknownState, so the cascade defers and re-probes instead."""
    from blastbox.host.runtime.aws_worker import AwsNoVerdict

    # Lambda entitlement probe
    rt, _ = _snapstart_rt({**_IDENT, "lambda-microvms list-microvms": _cp(stdout="   ")})
    with pytest.raises(AwsNoVerdict):
        rt._service_available()

    # ordinary EC2: the describe-instances probe is the FIRST thing the hibernate probe runs
    # (via super()), so a blank there must surface as no-verdict rather than "available".
    rt2, fake2 = _hibernate_rt(state=["running"], healthy=[True])
    fake2.responses["ec2 describe-instances"] = _cp(stdout="")
    with pytest.raises(AwsNoVerdict):
        rt2._service_available()


def test_an_empty_instance_type_probe_does_not_condemn_the_tier():
    """The worst of the three: a blank describe-instance-types was read as 'this instance type
    cannot hibernate', which is a VERDICT and drops the tier for the life of the process."""
    from blastbox.host.runtime.aws_worker import AwsNoVerdict, AwsWorkerError

    rt, fake = _hibernate_rt(state=["running"], healthy=[True])
    fake.responses["ec2 describe-instances"] = {"Reservations": []}
    fake.responses["ec2 describe-instance-types"] = _cp(stdout="")

    with pytest.raises(AwsNoVerdict) as ei:
        rt._service_available()
    assert not (isinstance(ei.value, AwsWorkerError)
                and "does not support hibernation" in str(ei.value)), (
        "a blank answer was condemned as an unsupported instance type")


def test_a_real_unsupported_instance_type_is_still_a_verdict():
    """Control: the definitive error must survive. A tier that genuinely cannot hibernate should
    fail loud at pool build, not be deferred and re-probed forever."""
    from blastbox.host.runtime.aws_worker import AwsNoVerdict, AwsWorkerError

    rt, fake = _hibernate_rt(state=["running"], healthy=[True])
    fake.responses["ec2 describe-instances"] = {"Reservations": []}
    fake.responses["ec2 describe-instance-types"] = {
        "InstanceTypes": [{"HibernationSupported": False, "MemoryInfo": {"SizeInMiB": 512}}]}

    with pytest.raises(AwsWorkerError) as ei:
        rt._service_available()
    assert not isinstance(ei.value, AwsNoVerdict), "a real refusal must stay a verdict"
    assert "does not support hibernation" in str(ei.value)


def test_an_observation_only_freeze_is_not_parking_evidence():
    """_park_unknown_since is opened by OBSERVATION-only freezes too -- an unreadable agent probe
    while the public IP is still unassigned, an unreadable describe -- with park_attempted=False.
    Those say nothing about whether we ever asked EC2 to hibernate, so counting them as evidence
    let an instance stopped by an operator or boot automation be adopted as a parked warm slot
    whose image was never captured."""
    state, healthy = ["running"], [True]
    t = [1000.0]
    rt, fake = _hibernate_rt(state=state, healthy=healthy, clock=lambda: t[0])
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")

    # An observation-only freeze: we could not read the agent, we never asked to hibernate.
    rt._freeze_park("s", t[0])
    assert "s" in rt._park_unknown_since
    assert "s" not in rt._park_attempted, "precondition: no hibernation was attempted"

    state[0] = "stopped"
    t[0] += 60.0
    assert rt.is_ready(slot) is not True, (
        "an observation-only freeze was read as proof we parked the instance")


def test_a_newer_attempt_supersedes_an_older_refusal():
    """A transient 'not ready to hibernate yet' refusal must not outlive the attempt it described.
    If a later stop is ACCEPTED but its response is lost, the stale refusal made the `stopped`
    adoption reject a genuinely hibernated worker -- which then stays non-ready until the pool
    times it out and reaps it."""
    from blastbox.host.runtime.aws_worker import AwsNoVerdict

    state, healthy = ["running"], [True]
    t = [1000.0]
    rt, _ = _hibernate_rt(state=state, healthy=healthy, clock=lambda: t[0])
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")

    rt._try_park = lambda s: False                 # refused
    rt.is_ready(slot)
    assert "s" in rt._park_refused

    def _lost(s):
        raise AwsNoVerdict("stop accepted, response lost")

    t[0] += 60.0
    rt._try_park = _lost                           # a NEWER attempt, unresolved
    rt.is_ready(slot)
    assert "s" not in rt._park_refused, "the stale refusal outlived the attempt it described"

    state[0] = "stopped"
    t[0] += 60.0
    assert rt.is_ready(slot) is True, "a genuinely hibernated worker was rejected"


def test_a_throttled_retry_stays_unknown_while_the_park_is_unresolved():
    """_try_park returns None when _hib_attempt is throttling (~5s), meaning 'not asked' -- not
    'not ready'. Returning a definitive False closed WarmPool's warming-UNKNOWN episode, so
    warming_timeout_s resumed aging: during a sustained stop-API brownout only ONE poll per retry
    interval stayed UNKNOWN and the tier's WARMING slots timed out and were reaped anyway."""
    from blastbox.host.runtime.aws_worker import AwsNoVerdict

    state, healthy = ["running"], [True]
    t = [1000.0]
    rt, _ = _hibernate_rt(state=state, healthy=healthy, clock=lambda: t[0])
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")

    def _no_verdict(s):
        raise AwsNoVerdict("stop API silent")

    rt._try_park = _no_verdict
    assert rt.is_ready(slot) is None               # the failing pass is UNKNOWN
    assert "s" in rt._park_unknown_since

    # The very next poll, inside the retry throttle: "not asked".
    rt._try_park = lambda s: None
    t[0] += 1.0
    assert rt.is_ready(slot) is None, (
        "a throttled retry answered False, closing the pool's UNKNOWN episode")


# --- an empty rc=0 from a STATE query is silence, not a death certificate ------------------

def test_a_blank_describe_is_no_answer_rather_than_a_dead_instance():
    """rc=0 with empty stdout parsed to {}, so State.Name read as "" and _running() -- a plain
    bool -- returned a CONFIRMED False. That reaps a live instance on the strength of silence."""
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    rt, fake = _hibernate_rt(state=["running"], healthy=[True])
    fake.responses["ec2 describe-instances"] = lambda argv: _cp(stdout="")   # rc=0, said nothing
    assert rt.is_alive(AwsWorkerSlot(slot_id="s", resource_id="i-1")) is None


def test_a_blank_get_microvm_is_no_answer_rather_than_a_dead_microvm():
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    rt, fake = _lambda_rt({"lambda-microvms get-microvm": lambda argv: _cp(stdout="")})
    assert rt.is_alive(AwsWorkerSlot(slot_id="s", resource_id="mv-1")) is None


# --- the tri-state has to survive the trip OUT to the pool ---------------------------------

def test_an_unobtainable_agent_probe_leaves_readiness_unknown_not_negative():
    """_agent_healthy() returning None means the probe could not be MADE (no address yet, budget
    already spent) -- host-side and correlated. Reported as a definitive not-ready it ends the
    pool's warming-unknown episode, so warming_timeout_s resumes aging over a probe that never
    happened and the whole WARMING population is evicted while every guest boots fine."""
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    now = [1000.0]
    rt, _ = _hibernate_rt(state=["running"], healthy=[True], clock=lambda: now[0])
    rt._agent_healthy = lambda s: None            # the probe could not be made at all
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")
    rt.is_ready(slot)                             # first observation only opens the episode
    now[0] += 5.0
    assert rt.is_ready(slot) is None


# --- a refusal describes ONE attempt, and cannot reach back past an earlier one -------------

def test_a_later_refusal_does_not_disprove_an_earlier_unresolved_stop():
    """Stop #1's response was lost (unresolved -- it may well have been accepted). Stop #2 was
    refused with IncorrectInstanceState, which is the EXPECTED answer once #1 is taking effect.
    Letting #2's refusal veto adoption rejects a genuinely hibernated worker, image and all."""
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    now = [1000.0]
    rt, _ = _hibernate_rt(state=["stopped"], healthy=[True], clock=lambda: now[0])
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")
    rt._park_attempted.add(slot.slot_id)          # stop #1: issued, no verdict ever returned
    rt._park_refused.add(slot.slot_id)            # stop #2: definitively refused
    assert rt.is_ready(slot) is True
    assert rt._phase.get(slot.slot_id) == "parked"


def test_a_refusal_with_no_unresolved_attempt_still_refuses_adoption():
    """The guard it must NOT weaken: nothing of ours is outstanding, so whatever stopped this
    instance, it was not us succeeding -- there is no captured image and no warm process."""
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    now = [1000.0]
    rt, _ = _hibernate_rt(state=["stopped"], healthy=[True], clock=lambda: now[0])
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")
    rt._phase[slot.slot_id] = "hibernating"       # evidence we drove it...
    rt._park_refused.add(slot.slot_id)            # ...but every attempt was refused
    assert rt.is_ready(slot) is False


# --- stamp-before-call, on the two liveness memos ------------------------------------------

def test_the_liveness_memo_is_stamped_when_the_describe_returns():
    """Stamped from before the call, a 25s describe writes a memo already 25s old against a 5s
    TTL, so the next 0.1s tick re-probes -- per idle slot, on the pool's sole tick thread."""
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    now = [1000.0]
    rt, fake = _hibernate_rt(state=["running"], healthy=[True], clock=lambda: now[0])
    inner = fake.responses["ec2 describe-instances"]

    def slow(argv):                                # degraded but ANSWERING control plane
        now[0] += 25.0
        return inner(argv)

    fake.responses["ec2 describe-instances"] = slow
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")
    rt.is_alive(slot)
    stamp, _ = rt._live_cache["s"]
    assert now[0] - stamp < rt._liveness_cache_s, "the memo was born expired"


def test_an_operator_stop_is_not_adopted_as_our_hibernation():
    """`stopping` means SOMETHING is stopping the instance, not that we asked.

    The branch used to write _phase, _hib_started and _park_since unconditionally -- three of the
    four sources the `stopped` adoption predicate consults -- so an instance stopped by an operator
    or by boot automation manufactured its own evidence and was then published as a parked warm
    slot. There is no captured image behind it: the pool advertises capacity that cannot serve and
    a claim burns the whole resume budget starting an instance whose agent was never up.
    """
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    now = [1000.0]
    state = ["stopping"]
    rt, _ = _hibernate_rt(state=state, healthy=[True], clock=lambda: now[0])
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")

    assert rt.is_ready(slot) is False                  # nothing of ours is outstanding
    assert "s" not in rt._hib_started, "the observation invented hibernation evidence"
    assert "s" not in rt._park_since, "the observation started a park episode we never asked for"

    now[0] += 5.0
    state[0] = "stopped"
    assert rt.is_ready(slot) is False, "adopted an operator-stopped instance as a parked warm slot"
    assert rt._phase.get("s") != "parked"


def test_our_own_stop_is_still_adopted_from_stopping():
    """The guard it must NOT break: the lost-response case. An unanswered stop records
    _park_attempted before `stopping` is ever observed, so it remains adoptable."""
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    now = [1000.0]
    state = ["stopping"]
    rt, _ = _hibernate_rt(state=state, healthy=[True], clock=lambda: now[0])
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")
    rt._park_attempted.add("s")                        # we issued a stop; the response was lost

    assert rt.is_ready(slot) is False                  # still stopping -- not ready yet
    assert rt._phase.get("s") == "hibernating", "our own in-flight hibernation was not adopted"
    now[0] += 5.0
    state[0] = "stopped"
    assert rt.is_ready(slot) is True


def test_a_half_succeeded_resume_does_not_leave_a_stale_parked_phase():
    """resume() used to do no phase bookkeeping, on the reasoning that nothing read _phase. Two
    readers exist now -- the `stopped` adoption predicate and the `stopping` evidence guard -- so a
    resume that ACCEPTED start-instances and then browned out handed the slot back with _phase
    still "parked" while the instance was RUNNING. If anything else stopped it later, that stale
    value read as proof of a hibernation of ours and the never-hibernated image was published as a
    warm slot."""
    from blastbox.host.runtime.aws_worker import AwsUnknownState, AwsWorkerSlot
    now = [1000.0]
    state = ["stopped"]
    rt, _ = _hibernate_rt(state=state, healthy=[False],
                          clock=lambda: now.__setitem__(0, now[0] + 0.5) or now[0],
                          resume_timeout_s=2.0)
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")
    rt._phase["s"] = "parked"                     # legitimately parked before the resume

    state[0] = "running"                          # start-instances took; the agent never answers
    with pytest.raises((AwsUnknownState, Exception)):
        rt.resume(slot)

    assert rt._phase.get("s") != "parked", (
        "the resume woke the instance but left the phase saying parked -- a later stop by anyone "
        "else would be adopted as ours"
    )


def test_a_parked_slot_seen_stopping_is_not_our_hibernation_either():
    """Defence in depth for the phase we now keep honest. A slot we parked is STOPPED; seeing it
    'stopping' means somebody started it and stopped it again, which is not a hibernation of ours
    and carries no image we captured. Only "hibernating" -- written when WE issue the stop -- is
    evidence of a parking in flight."""
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    now = [1000.0]
    rt, _ = _hibernate_rt(state=["stopping"], healthy=[True], clock=lambda: now[0])
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")
    rt._phase["s"] = "parked"

    assert rt.is_ready(slot) is False
    assert "s" not in rt._hib_started, "a parked phase manufactured fresh in-flight parking evidence"
    assert "s" not in rt._park_since


def test_a_stop_that_never_left_the_host_is_not_a_hibernation_attempt():
    """_aws raises AwsNoVerdict when the aws PROCESS could not start -- EMFILE, ENOMEM on fork,
    the binary briefly absent mid-upgrade. _try_park recorded every AwsNoVerdict with
    park_attempted=True, and _park_attempted is later read as proof that a `stopped` instance
    holds a warm image WE captured. A fork that failed issued no stop at all, so an instance
    stopped by an operator was adopted as a parked warm slot with nothing behind it -- the same
    evidence-manufacturing shape as the `stopping` branch, one door over."""
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    now = [1000.0]
    state = ["running"]
    rt, fake = _hibernate_rt(state=state, healthy=[True], clock=lambda: now[0])
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")

    def _cannot_fork(argv):    # noqa: ANN001 -- the host cannot start the process at all
        raise OSError(24, "Too many open files")

    fake.responses["ec2 stop-instances"] = _cannot_fork
    rt._phase["s"] = "hibernating"          # we are trying to park it
    rt.is_ready(slot)
    now[0] += 5.0
    rt.is_ready(slot)

    assert "s" not in rt._park_attempted, (
        "a stop that never left the host was recorded as an attempt, which is later read as "
        "proof of a captured warm image"
    )
    assert "s" in rt._park_unknown_since, "the give-up clock must still freeze -- we learned nothing"


def test_a_stop_that_was_issued_and_went_unanswered_IS_still_an_attempt():
    """The guard it must not weaken: a stop that really was sent and got no answer may well have
    been accepted, and that is the lost-response case the adoption path depends on."""
    from blastbox.host.runtime.aws_worker import AwsProbeTimeout, AwsWorkerSlot
    now = [1000.0]
    rt, fake = _hibernate_rt(state=["running"], healthy=[True], clock=lambda: now[0])
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")

    def _no_answer(argv):      # noqa: ANN001 -- the call went out; nothing came back
        raise AwsProbeTimeout("aws ec2 stop-instances: timed out")

    fake.responses["ec2 stop-instances"] = _no_answer
    rt._phase["s"] = "hibernating"
    rt.is_ready(slot)
    now[0] += 5.0
    rt.is_ready(slot)

    assert "s" in rt._park_attempted, "a genuine unresolved stop must stay recorded as an attempt"


def test_a_missing_cli_stays_UNKNOWN_at_the_probe_layer():
    """Where the verdict must NOT live. This assertion originally read the other way -- it required
    _describe() itself to answer definitively -- and that is what drained a tier: _aws() is shared
    by every slot, and is_ready/is_alive read a definitive error as "this slot is not up". The
    tier-level verdict belongs to available(), which is the only caller asking about the tier;
    see test_a_missing_cli_is_still_a_verdict_about_the_TIER."""
    from blastbox.host.runtime.aws_worker import AwsCliMissing, AwsUnknownState
    from blastbox.host.runtime.cascade import _is_undecided_availability
    rt, fake = _hibernate_rt(state=["running"], healthy=[True])

    def _no_binary(argv):   # noqa: ANN001
        raise FileNotFoundError(2, "No such file or directory: 'aws'")

    fake.responses["ec2 describe-instances"] = _no_binary
    with pytest.raises(AwsCliMissing) as ei:
        rt._describe(AwsWorkerSlot(slot_id="s", resource_id="i-1"))
    assert isinstance(ei.value, AwsUnknownState), (
        "a shared-path error that reads as definitive confirms every slot dead at once"
    )
    assert _is_undecided_availability(ei.value)


def test_a_fork_failure_from_resource_exhaustion_is_still_undecided():
    """The half that must NOT become a verdict: EMFILE/ENOMEM are transient and maximally
    correlated -- every slot and thread hits them at once, so a verdict there wipes the tier."""
    from blastbox.host.runtime.aws_worker import AwsNotExecuted
    from blastbox.host.runtime.cascade import _is_undecided_availability
    rt, fake = _hibernate_rt(state=["running"], healthy=[True])

    def _emfile(argv):      # noqa: ANN001
        raise OSError(24, "Too many open files")

    fake.responses["ec2 describe-instances"] = _emfile
    with pytest.raises(AwsNotExecuted) as ei:
        rt._describe(AwsWorkerSlot(slot_id="s", resource_id="i-1"))
    assert _is_undecided_availability(ei.value), "a fork failure must stay deferrable"


def test_a_missing_cli_does_not_confirm_the_death_of_every_slot():
    """The CLI is shared by every slot, and is_ready/is_alive read a definitive error as "this slot
    is not up". Answering definitively from the shared _aws() path therefore confirmed the whole
    tier dead at once -- and the terminates that followed failed for the same missing binary, so
    every slot was quarantined DRAINING with the tier at zero even after the CLI came back."""
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    rt, fake = _hibernate_rt(state=["running"], healthy=[True])

    def _no_binary(argv):   # noqa: ANN001
        raise FileNotFoundError(2, "No such file or directory: 'aws'")

    for k in list(fake.responses):
        fake.responses[k] = _no_binary
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")
    assert rt.is_alive(slot) is None, "a missing CLI confirmed this worker dead"
    assert rt.is_ready(slot) is None, "a missing CLI confirmed this worker not-ready"


def test_a_missing_cli_is_still_a_verdict_about_the_TIER():
    """The other half: availability is a question about the tier, not a worker. A binary that is
    absent now will be absent next tick, so deferring and re-probing it forever reports nothing."""
    rt, fake = _hibernate_rt(state=["running"], healthy=[True])

    def _no_binary(argv):   # noqa: ANN001
        raise PermissionError(13, "Permission denied: 'aws'")

    for k in list(fake.responses):
        fake.responses[k] = _no_binary
    assert rt.available() is False, "a missing CLI must be a verdict about the tier"


def test_a_fork_failure_still_leaves_tier_availability_undecided():
    """Control: EMFILE/ENOMEM are transient and correlated, so availability must stay UNDECIDED."""
    from blastbox.host.runtime.aws_worker import AwsNoVerdict
    rt, fake = _hibernate_rt(state=["running"], healthy=[True])

    def _emfile(argv):      # noqa: ANN001
        raise OSError(24, "Too many open files")

    for k in list(fake.responses):
        fake.responses[k] = _emfile
    with pytest.raises(AwsNoVerdict):
        rt.available()


def test_a_blank_token_response_is_no_answer_rather_than_a_dead_worker():
    from blastbox.host.runtime.aws_worker import AwsNoVerdict, AwsWorkerSlot
    rt, fake = _lambda_rt({"lambda-microvms create-microvm-auth-token": lambda argv: _cp(stdout="")})
    with pytest.raises(AwsNoVerdict):
        rt._mint_token(AwsWorkerSlot(slot_id="s", resource_id="mv-1"))


def test_a_clock_skew_rejection_is_not_a_hibernation_attempt():
    """RequestTimeTooSkewed is rejected at signature validation, so a stop-instances that gets it
    provably never ran. Recorded as an unresolved ATTEMPT it became evidence that a later `stopped`
    instance held a hibernation image we captured -- and there was no image, because there was no
    stop. Third instance of this shape: the `stopping` branch, a failed fork, and now a request
    AWS refused before performing."""
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    now = [1000.0]
    rt, fake = _hibernate_rt(state=["running"], healthy=[True], clock=lambda: now[0])
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")
    fake.responses["ec2 stop-instances"] = lambda argv: _cp(
        rc=254, stderr="An error occurred (RequestTimeTooSkewed) when calling StopInstances")
    rt._phase["s"] = "hibernating"
    rt.is_ready(slot)
    now[0] += 5.0
    rt.is_ready(slot)

    assert "s" not in rt._park_attempted, (
        "a stop AWS refused before performing was recorded as an unresolved attempt"
    )
    assert "s" in rt._park_unknown_since, "we still learned nothing, so the clock must freeze"


def test_a_clock_skew_rejection_still_leaves_tier_availability_undecided():
    """It must stay RETRYABLE: clock skew is fixed by NTP, not by dropping the tier."""
    from blastbox.host.runtime.aws_worker import AwsNoVerdict
    from blastbox.host.runtime.cascade import _is_undecided_availability
    rt, fake = _hibernate_rt(state=["running"], healthy=[True])
    for k in list(fake.responses):
        fake.responses[k] = lambda argv: _cp(
            rc=254, stderr="An error occurred (RequestTimeTooSkewed) when calling GetCallerIdentity")
    with pytest.raises(AwsNoVerdict) as ei:
        rt.available()
    assert _is_undecided_availability(ei.value), "clock skew must stay deferrable, not drop the tier"


def test_a_refused_stop_for_a_reaped_slot_recreates_no_state():
    """stop-instances is the SLOW call, so a stop()/resize can reap the slot while it is in flight.
    The success path checks the tombstone afterwards; the REFUSAL path returned before reaching that
    check, so _park_step took the answer at face value and recreated _park_since/_park_refused for a
    per-spawn UUID that no longer exists and that nothing will ever collect."""
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    now = [1000.0]
    rt, fake = _hibernate_rt(state=["running"], healthy=[True], clock=lambda: now[0])
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")

    def _refused_then_reaped(argv):   # noqa: ANN001 -- the slot is reaped DURING the call
        rt.reap(slot)                 # installs the tombstone, exactly as a real stop()/resize does
        return _cp(rc=254, stderr="An error occurred (InvalidParameterValue) calling StopInstances")

    fake.responses["ec2 terminate-instances"] = {}      # the reap must SUCCEED to leave a tombstone
    fake.responses["ec2 stop-instances"] = _refused_then_reaped
    assert rt._try_park(slot) is None, "a reaped slot must not report an answered refusal"
    assert "s" not in rt._park_refused
    assert "s" not in rt._park_since


def test_a_half_succeeded_resume_leaves_a_clock_even_though_it_leaves_no_evidence():
    """The regression that clearing the phase introduced.

    "parked" was doing two jobs: EVIDENCE that we hibernated the slot (which the stopped/stopping
    doors consult) and a MARKER that the slot may be mid-resume (which is what starts the give-up
    clock when it comes back running). Popping the phase fixed the first and destroyed the second:
    the phase read "warming", the running branch was skipped, _park_since was never started, and
    _park_step returns before _try_park is ever reached -- so nothing re-hibernates a running,
    billing instance for the life of the process.
    """
    from blastbox.host.runtime.aws_worker import AwsUnknownState, AwsWorkerSlot
    now = [1000.0]
    state = ["stopped"]
    rt, _ = _hibernate_rt(state=state, healthy=[False],
                          clock=lambda: now.__setitem__(0, now[0] + 0.5) or now[0],
                          resume_timeout_s=2.0)
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")
    rt._phase["s"] = "parked"

    state[0] = "running"                       # start-instances took; the agent never answers
    with pytest.raises((AwsUnknownState, Exception)):
        rt.resume(slot)
    assert rt._phase.get("s") == "resuming", "the mid-resume marker was lost"

    rt.is_ready(slot)                          # maintenance observes the running, unclaimed slot
    assert "s" in rt._park_since, (
        "no give-up clock was started for a running instance nothing will re-hibernate; it bills "
        "until demand happens to claim and retire it"
    )


def test_a_resuming_slot_is_not_evidence_of_a_hibernation_we_performed():
    """The property the phase-clearing fix established, which the new marker must not undo: a
    resume moved this slot OUT of parked, so whatever stops it afterwards was not us."""
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    now = [1000.0]
    rt, _ = _hibernate_rt(state=["stopped"], healthy=[True], clock=lambda: now[0])
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")
    rt._phase["s"] = "resuming"

    assert rt.is_ready(slot) is False, "a resuming slot found stopped was adopted as parked"
    assert rt._phase.get("s") != "parked"


def test_an_outage_before_recovery_still_goes_through_the_credit_cap():
    """_park_expired's cap exists so a brownout is ridden out and an OUTAGE is not -- but an
    interval that is never MEASURED is never capped.

    A lost-response stop records the attempt and deliberately leaves _park_since absent. If AWS
    then recovers by reporting `stopping`, anchoring the episode at that recovery excluded the
    entire preceding outage from the budget instead of crediting it and hitting the cap. Measured
    with hibernate_timeout_s=300 and a 3000s outage: give-up fired 3310s after the episode began
    rather than 600s, leaving the slot unclaimable for another full timeout after recovery.
    """
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    now = [1000.0]
    state = ["running"]
    rt, _ = _hibernate_rt(state=state, healthy=[True], clock=lambda: now[0],
                          hibernate_timeout_s=300.0)
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")

    rt._freeze_park("s", now[0], park_attempted=True)     # we issued it; no verdict came back
    assert "s" not in rt._park_since, "the lost-response case starts with no clock"

    now[0] = 4000.0                                       # 3000s of silence...
    state[0] = "stopping"                                 # ...then AWS answers again
    rt.is_ready(slot)

    assert rt._park_since.get("s") == 1000.0, (
        f"episode anchored at {rt._park_since.get('s')} (the recovery) instead of 1000.0 (the "
        f"attempt), so the outage never reaches the credit cap"
    )

    fired = next((t for t in range(1000, 40001, 10)
                  if (now.__setitem__(0, float(t)) or rt._park_expired("s", float(t)))), None)
    assert fired is not None and fired - 1000 <= 700, (
        f"give-up fired {None if fired is None else fired - 1000}s after the episode began; the "
        f"budget is 300s plus at most 300s of credited silence, so the outage bypassed the cap"
    )


def test_an_observation_only_freeze_does_not_anchor_the_park_episode():
    """The half the anchor must not overreach. _park_unknown_since is opened by OBSERVATION-ONLY
    freezes too -- an unreadable describe, an agent socket that would not open -- and those say
    nothing about when we asked EC2 to hibernate. Only _park_attempted marks a stop WE ISSUED.

    Anchoring on any freeze would date the episode from an unrelated earlier observation, so a
    slot that had only just begun parking would reach give-up immediately and be retired.
    """
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    now = [1000.0]
    state = ["running"]
    rt, _ = _hibernate_rt(state=state, healthy=[True], clock=lambda: now[0],
                          hibernate_timeout_s=300.0)
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")

    rt._freeze_park("s", 1000.0)                  # observation-only: NOT a stop we issued
    assert "s" not in rt._park_attempted

    now[0] = 4000.0                               # much later, an accepted stop of ours
    rt._phase["s"] = "hibernating"
    rt._hib_started["s"] = 3900.0
    state[0] = "stopping"
    rt.is_ready(slot)

    assert rt._park_since.get("s") == 4000.0, (
        f"episode anchored at {rt._park_since.get('s')} -- an unrelated observation from 3000s "
        f"earlier -- so a slot that had just begun parking is already past its give-up budget"
    )


def test_the_maintenance_budget_expiring_is_UNKNOWN_not_a_verdict():
    """Deferring on expiry needs no new machinery. The bounded call raises AwsProbeTimeout (an
    AwsUnknownState), which maintain_idle's existing handler already treats as "we could not look,
    change nothing" -- so the slot stays usable and is reconsidered on a later rotation. A False
    here RETIRES it, which would turn a short tick-thread budget into a slot-destroying one."""
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    rt, fake = _hibernate_rt(state=["running"], healthy=[True])

    def _too_slow(argv):    # noqa: ANN001 -- the control plane outruns the pool's tick budget
        raise AwsProbeTimeout("aws ec2 describe-instances: exceeded the maintenance budget")

    fake.responses["ec2 describe-instances"] = _too_slow
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")

    assert rt.maintain_idle(slot, budget_s=0.5) is not False, (
        "a budget expiry was reported as UNUSABLE, so the pool retires a slot it never managed "
        "to look at"
    )


def test_the_pools_budget_actually_bounds_the_aws_calls():
    """Not just accepted -- APPLIED. The budget only means anything if it reaches the subprocess
    timeout, so this captures what _aws hands the runner rather than trusting the signature.

    Without it the pass falls back to health_probe_timeout_s (30s), which is sized for a background
    probe and is far too long to hold the pool's single tick thread.
    """
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    rt, fake = _hibernate_rt(state=["running"], healthy=[True])
    timeouts: list = []
    inner = rt._run_aws

    def _capture(argv, timeout):    # noqa: ANN001
        timeouts.append(timeout)
        return inner(argv, timeout)

    rt._run_aws = _capture          # type: ignore[method-assign]
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")

    rt.maintain_idle(slot, budget_s=2.0)
    assert timeouts, "no aws call was made, so the budget proves nothing"
    assert max(timeouts) <= 2.0, (
        f"aws calls were bounded at {max(timeouts)}s despite a 2.0s pool budget -- the tick thread "
        f"can be held for the runtime's own ceiling instead"
    )


def test_sibling_hibernate_tiers_do_not_sweep_each_others_live_parked_slots():
    """A cascade may hold several aws-ec2-hibernate positions -- "aws-ec2:4,aws-ec2:16" is a
    supported configuration, which is why _tier_identity is f"{name}#{idx}".

    sweep_orphans filters on the SHARED blastbox-tier tag and spares only instances carrying its
    own run id. With a fresh id per runtime CONSTRUCTION, a sibling in the same process read the
    other's live parked slots as foreign and terminated them -- destroying warm capacity that was
    working. Unreachable while the sweep ran only at CLI startup (nothing is parked yet); reachable
    the moment a tier admitted mid-run started sweeping.

    The fence is per PROCESS, which is what the guide describes: "not carrying THIS DISPATCHER
    PROCESS'S blastbox-run id".
    """
    rt_a, fake_a = _sweep_rt(orphan_max_age_s=3600.0)
    rt_b, _ = _sweep_rt(orphan_max_age_s=3600.0)

    assert rt_a._run_id == rt_b._run_id, (
        "sibling tiers in one process carry different ownership fences, so each reads the other's "
        "live parked slots as an orphan"
    )

    # ...and the sweep spares an instance tagged by the sibling.
    killed = rt_a.sweep_orphans(now=_gmt_epoch("2026-07-11 00:00:00") + 7200)
    swept_ours = [i for i in killed if i == "i-ours"]
    assert not swept_ours, f"the sweep terminated this process's own parked slot: {killed}"


def test_a_blank_orphan_inventory_is_a_failed_sweep_not_an_empty_one():
    """An empty inventory and a blank response are the same shape once `{}` is parsed: Reservations
    comes back empty and the sweep reports success having reclaimed nothing.

    Both callers are ONE-SHOT -- dispatcher start, and a tier's admission -- so a single transient
    blank-output incident silently forfeits reclamation until the next process restart, with the
    predecessor's hibernated instances accruing EBS cost throughout. A sweep that could not read
    its inventory has not swept.
    """
    from blastbox.host.runtime.aws_worker import AwsNoVerdict
    rt, fake = _sweep_rt(orphan_max_age_s=3600.0)
    fake.responses["ec2 describe-instances"] = lambda argv: _cp(stdout="")   # rc=0, said nothing

    with pytest.raises(AwsNoVerdict):
        rt.sweep_orphans(now=_gmt_epoch("2026-07-11 00:00:00") + 7200)


def test_a_genuinely_empty_inventory_is_still_a_clean_sweep():
    """The half it must not break: a real answer with no matching instances reclaims nothing and
    is not an error."""
    rt, fake = _sweep_rt(orphan_max_age_s=3600.0)
    fake.responses["ec2 describe-instances"] = {"Reservations": []}
    assert rt.sweep_orphans(now=_gmt_epoch("2026-07-11 00:00:00") + 7200) == []


def test_a_throttled_stop_is_a_rejection_not_an_unresolved_attempt():
    """A throttle is a REJECTION: AWS refused the request rather than performing it, so nothing was
    attempted and nothing was captured. Recorded as an unresolved attempt it became _park_attempted,
    which the `stopped` and `stopping` doors accept as proof the instance holds a hibernation image
    WE captured -- so an instance an operator later stopped normally was published as an unusable
    warm slot.

    Third instance of this shape (failed fork, clock skew, throttle). This one reached the ordinary
    unresolved-attempt arm because AwsThrottled was a SIBLING of AwsNotExecuted, not a subclass.
    """
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    now = [1000.0]
    rt, fake = _hibernate_rt(state=["running"], healthy=[True], clock=lambda: now[0])
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")
    fake.responses["ec2 stop-instances"] = lambda argv: _cp(
        rc=254, stderr="An error occurred (RequestLimitExceeded) when calling StopInstances")
    rt._phase["s"] = "hibernating"
    rt.is_ready(slot)
    now[0] += 5.0
    rt.is_ready(slot)

    assert "s" not in rt._park_attempted, (
        "a throttled stop AWS never performed was recorded as an unresolved attempt"
    )
    assert "s" in rt._park_unknown_since, "we still learned nothing, so the clock must freeze"


def test_a_throttle_still_leaves_tier_availability_undecided():
    """It must stay RETRYABLE -- a throttle is the one non-answer that clearly warrants a retry."""
    from blastbox.host.runtime.aws_worker import AwsNoVerdict
    from blastbox.host.runtime.cascade import _is_undecided_availability
    rt, fake = _hibernate_rt(state=["running"], healthy=[True])
    for k in list(fake.responses):
        fake.responses[k] = lambda argv: _cp(
            rc=254, stderr="An error occurred (ThrottlingException) when calling GetCallerIdentity")
    with pytest.raises(AwsNoVerdict) as ei:
        rt.available()
    assert _is_undecided_availability(ei.value), "a throttle must stay deferrable"


def test_an_ambiguous_failure_still_records_the_lost_response_attempt():
    """The half the previous commit broke, and the more dangerous direction.

    RequestTimeout, InternalError, generic 5xx and connection failures are all RETRYABLE, but none
    of them proves a mutating call was never performed -- a stop-instances AWS ACCEPTED whose reply
    vanished looks exactly like this. Recording no _park_attempted for it means the later
    `stopping`/`stopped` observations are read as somebody else's stop, so a genuinely hibernated
    warm slot is rejected and eventually reaped: warm capacity destroyed, versus the phantom-marker
    cost of the opposite error.
    """
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot
    now = [1000.0]
    rt, fake = _hibernate_rt(state=["running"], healthy=[True], clock=lambda: now[0])
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")
    fake.responses["ec2 stop-instances"] = lambda argv: _cp(
        rc=254, stderr="An error occurred (RequestTimeout) when calling StopInstances")
    rt._phase["s"] = "hibernating"
    rt.is_ready(slot)
    now[0] += 5.0
    rt.is_ready(slot)

    assert "s" in rt._park_attempted, (
        "an ambiguous failure recorded no attempt -- a stop AWS accepted whose reply was lost now "
        "has no evidence, so the hibernated slot is rejected as a foreign stop and reaped"
    )


def test_a_rate_limit_is_both_retryable_and_never_performed():
    """It has to be both, and picking one was wrong in each direction."""
    from blastbox.host.runtime.aws_worker import (AwsNoVerdict, AwsNotExecuted, AwsRateLimited,
                                                  AwsThrottled)
    rt, fake = _hibernate_rt(state=["running"], healthy=[True])
    fake.responses["ec2 describe-instances"] = lambda argv: _cp(
        rc=254, stderr="An error occurred (RequestLimitExceeded) when calling DescribeInstances")
    with pytest.raises(AwsRateLimited) as ei:
        rt._describe(AwsWorkerSlot(slot_id="s", resource_id="i-1"))
    assert isinstance(ei.value, AwsThrottled), "a rate limit must stay the retryable type"
    assert isinstance(ei.value, AwsNotExecuted), "a rate limit was refused, not performed"
    assert isinstance(ei.value, AwsNoVerdict)


def test_a_reap_landing_mid_park_step_cannot_be_outrun_by_the_step():
    """The tombstone made a late write DETECTABLE, not PREVENTABLE.

    Disposal runs on the pool's dedicated reaper thread; the park machine runs on the tick thread.
    Every park writer asked `_slot_is_gone(sid)` and then wrote, with nothing holding the two
    together — so a reap landing in that gap installed the tombstone, cleared every per-slot map,
    and THEN the in-flight step wrote its entries straight back. Slot ids are per-spawn UUIDs, so
    reap() is the only thing that ever collects them: whatever is re-created after it survives for
    the life of the process, and a shutdown/maintenance storm leaks one set per race.

    Ordering the tombstone before the pops inside reap() (an earlier round) closed the half of the
    window where the write STARTED after the tombstone. It could not close this half, where the
    write started before it and could not have observed it at any price. Only a lock spanning the
    check and the write does that, which is what `_park_writes` is.

    Here the reaper thread is released while the tick thread is INSIDE `_park_step`. With the
    chokepoint the reap serializes after the step and its clears win, so nothing is left behind.

    MUTATION: drop the `with self._park_lock` from `_park_writes` and the reap interleaves — the
    step then re-creates `_phase` for a reaped id and this fails.
    """
    import threading

    from blastbox.host.runtime.aws_worker import AwsWorkerSlot

    now = [1000.0]
    rt, fake = _hibernate_rt(state=["stopped"], healthy=[True], clock=lambda: now[0])
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")
    fake.responses["ec2 terminate-instances"] = {}

    # A slot with an ACCEPTED hibernation on record, so `stopped` is adopted as parked and the
    # step is a writer rather than a no-op.
    rt._park_attempted.add("s")
    rt._hib_started["s"] = 900.0
    rt._park_since["s"] = 900.0

    entered = threading.Event()
    reaper_done = threading.Event()
    raced_box: list[bool] = []

    def _reap_on_the_reaper_thread() -> None:
        rt.reap(slot)
        reaper_done.set()

    real_step = rt._park_step_locked

    def _step_with_a_reap_in_flight(*a, **kw):  # noqa: ANN002, ANN003, ANN202
        # Called with _park_lock HELD, i.e. exactly the window the old code left open.
        if not entered.is_set():
            entered.set()
            t = threading.Thread(target=_reap_on_the_reaper_thread, daemon=True)
            t.start()
            # The reaper must not be able to complete while the step holds the lock. If it does,
            # the interleaving under test has occurred.
            reaper_done.wait(timeout=0.25)
            raced_box.append(reaper_done.is_set())
        return real_step(*a, **kw)

    rt._park_step_locked = _step_with_a_reap_in_flight  # type: ignore[method-assign]
    rt._park_step(slot, "stopped", now[0])

    # THE invariant, asserted directly. A reap that completes while the step is mid-flight is the
    # race itself; everything downstream (which entries get resurrected) depends on which branch the
    # step happens to take, so asserting on leftover state alone would pass for the wrong reason --
    # reap() clears the very evidence the `stopped` branch needs, so the step declines to adopt and
    # writes nothing. Whether the reaper could OVERLAP at all is the property the lock provides.
    raced = bool(raced_box and raced_box[0])
    assert not raced, (
        "reap() ran to completion on the reaper thread while the tick thread was inside _park_step: "
        "the liveness check and the writes it authorizes are in different critical sections, so the "
        "step can write entries back after reap() cleared them")

    assert reaper_done.wait(timeout=5.0), "the reaper thread never finished; the lock is not being released"

    assert "s" not in rt._phase, (
        f"_phase still holds {rt._phase.get('s')!r} for a reaped slot: the park step wrote it back "
        f"after reap() cleared it. Ids are per-spawn UUIDs, so nothing will ever collect this again")
    for name in ("_hib_started", "_park_since", "_park_credit", "_park_unknown_since"):
        assert "s" not in getattr(rt, name), f"{name} was re-created for a reaped slot"
    assert "s" not in rt._park_attempted, "_park_attempted was re-created for a reaped slot"


def test_every_park_state_write_goes_through_the_lock():
    """Structural. The defect class this closes has now recurred for five consecutive review rounds
    (claim-probe, admission, `_maintain_idle`, `_run_owed_sweeps`, and this one), always as the same
    shape: state is read, the write that depends on it happens later, and nothing holds the two
    together. Fixing instances has not stopped it, so this fails at WRITE time instead.

    The rule: inside Ec2HibernateRuntime, a write to park bookkeeping is legal only where
    `_park_lock` is provably held — lexically inside `with self._park_writes(...)` / `with
    self._park_lock`, or inside a `*_locked` helper, which by convention documents that its caller
    holds it. The second half of the check enforces that convention: every call to a `*_locked`
    helper must itself sit inside one of those `with` blocks, so the suffix cannot become a lie.

    Same shape as the `_queue_deferred_reap_unlocked` chokepoint test: a seventh writer added
    without the lock fails here rather than in production, months later, as a leak.
    """
    import ast
    from pathlib import Path

    from blastbox.host.runtime import aws_worker as _aw

    GUARDED = {"_phase", "_park_since", "_hib_started", "_park_attempted", "_park_refused",
               "_park_credit", "_park_unknown_since", "_hib_attempt", "_reaped_ids"}
    MUTATORS = {"pop", "discard", "setdefault", "clear", "popitem", "add", "update"}

    src = Path(_aw.__file__).read_text()
    tree = ast.parse(src)
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Ec2HibernateRuntime")

    parent: dict = {}
    for node in ast.walk(cls):
        for child in ast.iter_child_nodes(node):
            parent[child] = node

    def _locked_context(node) -> bool:  # noqa: ANN001
        """True if `node` is lexically inside a with-block that takes _park_lock."""
        cur = node
        while cur in parent:
            cur = parent[cur]
            if isinstance(cur, ast.With):
                for item in cur.items:
                    call = item.context_expr
                    if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) \
                            and call.func.attr == "_park_writes":
                        return True
                    if isinstance(call, ast.Attribute) and call.attr == "_park_lock":
                        return True
            if isinstance(cur, ast.FunctionDef) and cur.name.endswith("_locked"):
                return True
        return False

    def _fn_of(node) -> str:  # noqa: ANN001
        cur = node
        while cur in parent:
            cur = parent[cur]
            if isinstance(cur, ast.FunctionDef):
                return cur.name
        return "<class body>"

    # ALIASES. `for d in (self._phase, self._park_since): d.pop(sid, None)` is not a hypothetical
    # idiom -- it is the one aws_worker.py already uses for park bookkeeping, in BOTH reap() and
    # _forget_slot_locked(). A guard that only matches `self.<map>.pop(...)` is therefore blind to
    # the exact shape the next writer is most likely to copy from the file, and would report clean.
    # So bind loop targets iterating a tuple of guarded maps, and treat writes through them as
    # writes to the maps themselves.
    aliases: dict = {}
    for node in ast.walk(cls):
        if isinstance(node, ast.For) and isinstance(node.target, ast.Name) \
                and isinstance(node.iter, (ast.Tuple, ast.List)):
            named = [e.attr for e in node.iter.elts
                     if isinstance(e, ast.Attribute) and e.attr in GUARDED]
            if named:
                for inner in ast.walk(node):
                    aliases[id(inner)] = (node.target.id, named)

    unguarded = []
    for node in ast.walk(cls):
        target = None
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute) \
                and node.value.attr in GUARDED and isinstance(node.ctx, (ast.Store, ast.Del)):
            target = node.value.attr
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr in MUTATORS:
            base = node.func.value
            if isinstance(base, ast.Attribute) and base.attr in GUARDED:
                target = base.attr
            elif isinstance(base, ast.Name) and id(node) in aliases:
                alias_name, named = aliases[id(node)]
                if base.id == alias_name:
                    target = "/".join(named) + f" (via alias `{alias_name}`)"
        if target and not _locked_context(node):
            unguarded.append(f"{_fn_of(node)}() writes self.{target} at line {node.lineno}")

    assert not unguarded, (
        "park bookkeeping written without _park_lock held — a reap on the reaper thread can clear "
        "these maps between the liveness check and the write, permanently re-creating state for a "
        "per-spawn UUID that nothing collects again:\n  " + "\n  ".join(unguarded))

    # ...and the `_locked` suffix must not be able to become a lie.
    bad_calls = []
    for node in ast.walk(cls):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr.endswith("_locked") and not _locked_context(node):
            bad_calls.append(f"{_fn_of(node)}() calls {node.func.attr}() at line {node.lineno}")
    assert not bad_calls, (
        "a *_locked helper is called from outside the lock, so its name no longer documents "
        "anything:\n  " + "\n  ".join(bad_calls))


def test_the_health_probe_ceiling_is_configurable_and_cannot_be_set_to_nothing():
    """It is a BASE AwsWorkerConfig field, so it is `BLASTBOX_AWS_*` and every AWS tier inherits it.

    The guide advertised this ceiling as tunable while the field was a fixed 30s default that no
    reader ever touched. It matters during exactly the failure it is documented for: each IDLE
    health probe occupies the pool's SINGLE tick thread, so during a control-plane brownout an
    operator who cannot shorten it cannot stop the stall either.

    The clamp also has to reject NaN, not just `<= 0`. NaN fails every comparison, so `nan <= 0` is
    False and it sailed straight through the guard written to prevent this: `clock() + nan` is nan,
    every comparison against the deadline is False, and the probe then neither expires nor bounds
    anything -- a silent brick reached through the one input the clamp did not test.

    MUTATION: drop the from_env wiring -> 45 is ignored. Drop the isfinite() term -> nan survives.
    """
    from blastbox.host.runtime.aws_worker import Ec2Config, Ec2HibernateConfig

    for cfg_cls in (Ec2Config, Ec2HibernateConfig):
        env = {"BLASTBOX_EC2_AMI": "ami-x", "BLASTBOX_AWS_HEALTH_PROBE_TIMEOUT_S": "45"}
        assert cfg_cls.from_env(env.get).health_probe_timeout_s == 45.0, (
            f"{cfg_cls.__name__} ignores BLASTBOX_AWS_HEALTH_PROBE_TIMEOUT_S; the guide documents it "
            f"as the probe ceiling, so an operator shortening it during a brownout changes nothing")

        for bad in ("nan", "inf", "0", "-5"):
            env = {"BLASTBOX_EC2_AMI": "ami-x", "BLASTBOX_AWS_HEALTH_PROBE_TIMEOUT_S": bad}
            got = cfg_cls.from_env(env.get).health_probe_timeout_s
            assert got == 30.0, (
                f"{cfg_cls.__name__} accepted health_probe_timeout_s={bad!r} -> {got!r}; an "
                f"unbounded or never-expiring probe is the tick-thread stall this bound exists to "
                f"prevent, so a meaningless value must fall back to the default")


def test_the_agent_probe_never_runs_while_the_park_lock_is_held():
    """A correctness lock must not become an availability bug.

    `_agent_healthy()` is network I/O twice over: `_resolve_ip()` can issue an UNCACHED describe,
    and the health check is an HTTP round trip. Taking `_park_lock` across the whole park step put
    both inside the critical section, so `reap()` on the reaper thread blocked on disposal for as
    long as a control-plane brownout lasted -- the exact tick-thread stall this branch exists to
    remove, transplanted onto the reaper thread. The fix for a race must not serialize disposal
    behind a network call.

    So the step hands the probe back: on reaching that branch unprobed it returns `_PROBE_PENDING`,
    the wrapper drops the lock, probes, and RE-ENTERS through `_park_writes` -- re-entry rather than
    carrying the old liveness answer forward, because the slot can be reaped during the probe and
    that answer is stale the moment the lock is released.

    Checked from ANOTHER thread on purpose: `_park_lock` is reentrant, so a same-thread acquire
    would succeed even while held and prove nothing.

    MUTATION: call `self._agent_healthy(slot)` inline in `_park_step_locked` instead of returning
    `_PROBE_PENDING` -> the probing thread holds the lock and this fails.
    """
    import threading

    from blastbox.host.runtime.aws_worker import AwsWorkerSlot

    now = [1000.0]
    rt, fake = _hibernate_rt(state=["running"], healthy=[True], clock=lambda: now[0])
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")
    # phase stays "warming": the `running` branch returns early for hibernating/parked/resuming,
    # and the probe only happens on the still-warming path.
    rt._park_since["s"] = 900.0          # a live clock, well inside hibernate_timeout_s (300s)

    lock_free_during_probe: list[bool] = []
    real_probe = rt._agent_healthy

    def _probe_and_check_the_lock(*a, **kw):  # noqa: ANN002, ANN003, ANN202
        got = []

        def _try_from_another_thread() -> None:
            # RLock is reentrant, so this MUST be a different thread to mean anything.
            acquired = rt._park_lock.acquire(timeout=0.25)
            got.append(acquired)
            if acquired:
                rt._park_lock.release()

        t = threading.Thread(target=_try_from_another_thread)
        t.start()
        t.join(timeout=5.0)
        lock_free_during_probe.append(bool(got and got[0]))
        return real_probe(*a, **kw)

    rt._agent_healthy = _probe_and_check_the_lock  # type: ignore[method-assign]
    rt._park_step(slot, "running", now[0])

    assert lock_free_during_probe, (
        "the agent probe never ran, so this test proved nothing about the lock; the park step no "
        "longer reaches its probe branch and the test needs rewriting against one that does")
    assert all(lock_free_during_probe), (
        "_park_lock was HELD while the agent probe ran: _resolve_ip() can issue an uncached describe "
        "and the health check is an HTTP round trip, so reap() on the reaper thread blocks on "
        "disposal for the length of a control-plane brownout")


def test_no_locked_method_can_reach_a_blocking_call_even_transitively():
    """The audit that missed this checked DIRECT calls only.

    Hoisting `_agent_healthy` out of the lock looked like it fixed the "no I/O under _park_lock"
    problem, and a direct-call audit agreed. It was wrong one level down: `_park_step_locked` still
    reached `_try_park` -> `self._aws("ec2", "stop-instances", ...)`, an AWS mutation bounded only
    by the CLI budget. So the reaper thread could still block on disposal for the length of a
    control-plane brownout -- the exact stall the hoist was supposed to remove, hidden behind one
    more call frame.

    A depth-1 check cannot express the invariant. The invariant is TRANSITIVE: nothing reachable
    from a `*_locked` method may block, because everything reachable runs with `_park_lock` held and
    `reap()` -- on the pool's dedicated reaper thread -- waits behind it.

    MUTATION: call `self._agent_healthy(slot)` or `self._try_park(slot)` from any `*_locked` method
    and this fails, naming the path.
    """
    import ast
    from pathlib import Path

    from blastbox.host.runtime import aws_worker as _aw

    BLOCKING = {"_aws", "_describe", "_describe_cached", "_resolve_ip", "_http_probe",
                "_agent_healthy", "_try_park"}

    tree = ast.parse(Path(_aw.__file__).read_text())
    parent: dict = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent[child] = node

    def _holds_lock(node) -> bool:  # noqa: ANN001
        cur = node
        while cur in parent:
            cur = parent[cur]
            if isinstance(cur, ast.With):
                for item in cur.items:
                    ce = item.context_expr
                    if isinstance(ce, ast.Call) and isinstance(ce.func, ast.Attribute) \
                            and ce.func.attr == "_park_writes":
                        return True
                    if isinstance(ce, ast.Attribute) and ce.attr == "_park_lock":
                        return True
        return False

    calls: dict = {}
    locked: list[str] = []
    # ENTRY POINTS are both halves of the convention: a `*_locked` method, and any `with
    # _park_writes(...)` block anywhere -- including inside an otherwise-unlocked function. Scanning
    # only `*_locked` names is what let the first version of this test pass while the wrapper made
    # an AWS call from inside its own `with` block.
    inline: set = set()
    for cls in [n for n in tree.body if isinstance(n, ast.ClassDef)]:
        for fn in cls.body:
            if not isinstance(fn, ast.FunctionDef):
                continue
            calls.setdefault(fn.name, set()).update(
                n.func.attr for n in ast.walk(fn)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and isinstance(n.func.value, ast.Name) and n.func.value.id == "self")
            if fn.name.endswith("_locked"):
                locked.append(fn.name)
            for n in ast.walk(fn):
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) \
                        and isinstance(n.func.value, ast.Name) and n.func.value.id == "self" \
                        and _holds_lock(n):
                    inline.add(n.func.attr)

    assert locked, "sanity: the lock convention uses a _locked suffix; none were found"

    def paths_to_blocking(start: str) -> list[str]:
        found, seen = [], set()

        def walk(name: str, trail: list[str]) -> None:
            for callee in sorted(calls.get(name, ())):
                if callee in seen:
                    continue
                seen.add(callee)
                if callee in BLOCKING:
                    found.append(" -> ".join(trail + [callee]))
                else:
                    walk(callee, trail + [callee])

        walk(start, [start])
        return found

    offenders = {}
    for m in sorted(set(locked) | inline):
        if m in BLOCKING:
            offenders[m] = [f"{m} (called directly while the lock is held)"]
        elif (p := paths_to_blocking(m)):
            offenders[m] = p
    assert not offenders, (
        "a method that runs with _park_lock held can reach a blocking call, so reap() on the "
        "reaper thread blocks behind it for the length of a control-plane brownout:\n  "
        + "\n  ".join(f"{m}: {' | '.join(p)}" for m, p in offenders.items()))


def test_a_describe_landing_after_reap_leaves_no_cache_entry_behind():
    """The tombstone guards the PARK maps. It says nothing about the describe caches.

    Moving the probe and the stop outside the lock is what makes disposal responsive, but it also
    means `_describe_cached` can be in flight when `reap()` completes: it publishes
    `_desc_cache[sid]` on success and `_desc_fail_at[sid]` on failure, and both are cleared by reap.
    A write landing afterwards re-creates an entry for a per-spawn UUID that nothing collects again,
    so the leak is permanent and grows once per race.

    Re-entry already re-checks liveness, but detecting the tombstone is not the same as undoing what
    the unlocked call published -- so re-entry finding the slot gone now does a final synchronized
    sweep of exactly those caches.

    MUTATION: drop the `_forget_slot_locked` call from the not-live paths and the entry survives.
    """
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot

    now = [1000.0]
    rt, fake = _hibernate_rt(state=["running"], healthy=[True], clock=lambda: now[0])
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")
    fake.responses["ec2 terminate-instances"] = {}
    rt._park_since["s"] = 900.0

    def _probe_then_reap(*a, **kw):  # noqa: ANN002, ANN003, ANN202
        # ORDER MATTERS. The reaper completes FIRST, and the in-flight describe publishes its cache
        # entry afterwards -- that is the race. Writing before the reap would just be cleared by it,
        # and the test would pass without the fix (it did, first time round).
        rt.reap(slot)
        rt._desc_cache["s"] = (now[0], {"InstanceId": "i-1", "State": {"Name": "running"}})
        rt._desc_fail_at["s"] = now[0]
        return True

    rt._agent_healthy = _probe_then_reap  # type: ignore[method-assign]
    rt._park_step(slot, "running", now[0])

    assert "s" not in rt._desc_cache, (
        f"_desc_cache still holds an entry for a reaped slot ({rt._desc_cache.get('s')!r}); ids are "
        f"per-spawn UUIDs, so reap() was its only collector and this entry is now permanent")
    assert "s" not in rt._desc_fail_at, "_desc_fail_at leaked an entry for a reaped slot"


def test_the_hibernate_tier_rejects_a_timeout_that_cannot_mean_a_duration():
    """Third round of this class, on the tier that had none of the hardening.

    `Ec2HibernateConfig` defined no `__post_init__`, so its four float knobs took anything `float()`
    accepted -- while the BASE config validates the probe budgets, `orphan_max_age_s` is explicitly
    NaN-hardened, and every pool knob is checked at its reader. This branch is what made
    `hibernate_timeout_s` load-bearing TWICE in `_park_expired`: as the credit cap
    `min(credit + live, hibernate_timeout_s)` and as the threshold.

    NaN wins both comparisons: `min(x, nan)` is x and `x > nan` is False, so the give-up escape can
    NEVER fire -- the escape whose own comment says that without it the slot is unclaimable forever
    AND blocks its own replacement, so a warm_size=1 tier stays dead until someone intervenes.
    A NEGATIVE value inverts it: `min(0, -1)` is -1, so `age > -1` holds at age 0 and every slot in
    the tier is retired on its first observation.

    MUTATION: delete Ec2HibernateConfig.__post_init__ -> nan/inf/-1 survive and both asserts fail.
    """
    from blastbox.host.runtime.aws_worker import Ec2HibernateConfig

    for bad in ("nan", "inf", "-inf", "-1", "0"):
        cfg = Ec2HibernateConfig.from_env(
            {"BLASTBOX_EC2_AMI": "ami-x", "BLASTBOX_EC2_HIBERNATE_TIMEOUT_S": bad}.get)
        assert cfg.hibernate_timeout_s == 300.0, (
            f"hibernate_timeout_s={bad!r} was accepted as {cfg.hibernate_timeout_s!r}")
    # a real value still wins
    assert Ec2HibernateConfig.from_env(
        {"BLASTBOX_EC2_AMI": "ami-x", "BLASTBOX_EC2_HIBERNATE_TIMEOUT_S": "45"}.get
    ).hibernate_timeout_s == 45.0
    # ...and chaining to the base must not have been lost by defining __post_init__ here
    assert Ec2HibernateConfig.from_env(
        {"BLASTBOX_EC2_AMI": "ami-x", "BLASTBOX_AWS_HEALTH_PROBE_TIMEOUT_S": "nan"}.get
    ).health_probe_timeout_s == 30.0, "subclass __post_init__ silently replaced the base's clamp"

    # BEHAVIOUR: the give-up escape still fires for a genuinely stuck slot.
    now = [1000.0]
    rt, _ = _hibernate_rt(state=["stopping"], healthy=[True], clock=lambda: now[0],
                          hibernate_timeout_s=float("nan"))
    rt._park_since["s"] = 0.0
    assert rt._park_expired("s", now[0]) is True, (
        "a slot stuck for 1000s never expires, so it is unclaimable forever and blocks its own "
        "replacement -- the exact failure the give-up escape exists to end")


def test_a_failing_describe_that_loses_to_the_reaper_leaves_no_desc_fail_at_entry():
    """`_desc_fail_at` is popped by super().reap() -- which runs BEFORE the tombstone.

    So the pop is not inside the critical section that makes it stick. A `_describe_cached` FAILURE
    still in flight lands `_desc_fail_at[sid] = clock()` after the slot's only cleanup, and slot ids
    are per-spawn UUIDs, so the entry is permanent -- one leaked per race.

    `_forget_slot_locked` does sweep it, but is only reachable from `_park_step` re-entry, and this
    path never gets there: `is_ready()` describes BEFORE `_park_step`, so a describe failure
    short-circuits straight out to the exception handler.

    MUTATION: drop `_desc_fail_at` from reap()'s locked tuple -> the entry survives.
    """
    from blastbox.host.runtime.aws_worker import AwsProbeTimeout, AwsWorkerSlot

    now = [1000.0]
    rt, fake = _hibernate_rt(state=["running"], healthy=[True], clock=lambda: now[0])
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")
    fake.responses["ec2 terminate-instances"] = {}

    def _reaper_wins_then_the_describe_fails(*a, **kw):  # noqa: ANN002, ANN003, ANN202
        rt.reap(slot)                                    # disposal completes first...
        raise AwsProbeTimeout("describe-instances: timed out")   # ...then our call fails

    rt._describe = _reaper_wins_then_the_describe_fails  # type: ignore[method-assign]
    rt.is_ready(slot)

    assert "s" not in rt._desc_fail_at, (
        f"_desc_fail_at leaked {rt._desc_fail_at.get('s')!r} for a slot already tombstoned "
        f"({list(rt._reaped_ids)}); nothing collects a per-spawn UUID after reap()")


def test_the_park_clock_is_anchored_when_the_calls_finished_not_when_the_pass_started():
    """`is_ready` samples `now` once and opens no budget scope; the pass then blocks twice.

    The wrapper releases `_park_lock` for the agent probe AND for stop-instances, each able to burn
    the full `cli_timeout_s` (120s) -- and unlike `maintain_idle`, `is_ready` wraps the pass in no
    `_call_budget`. Settling against the pre-call `now` therefore charges the LATENCY of those calls
    to the operator's `hibernate_timeout_s` budget: a 240s pass anchors `_park_since` 240s in the
    past, so 80% of a 300s window is spent before the first attempt is even counted. Under the
    correlated throttling this branch exists to survive, every slot hits it together and the tier
    churns instances instead of parking them.

    The file already states this rule three lines away in `_record_park_accepted_locked` ("self.
    _clock(), NOT the pre-call `now` ... stamping the pre-call value let the duration of the stop
    itself consume the whole window"). It was applied to `_hib_started` and not to its siblings.

    MUTATION: drop the fresh `now = self._clock()` from `_settle_park_locked` -> _park_since is
    anchored at the start of the pass again and this fails.
    """
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot

    clock = [1000.0]
    rt, fake = _hibernate_rt(state=["running"], healthy=[True], clock=lambda: clock[0])
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")

    def _slow_refused_stop(argv):  # noqa: ANN001 -- the probe + stop burn 240s of real time
        clock[0] += 240.0
        return _cp(rc=254,
                   stderr="An error occurred (UnsupportedOperation): not ready to hibernate yet")

    fake.responses["ec2 stop-instances"] = _slow_refused_stop
    rt._park_step(slot, "running", clock[0])

    started = rt._park_since.get("s")
    assert started is not None, "sanity: a refused attempt should still open the give-up clock"
    lag = clock[0] - started
    assert lag < 1.0, (
        f"the park episode was anchored {lag:.0f}s in the past, so that much of the "
        f"{rt.cfg.hibernate_timeout_s:.0f}s parking budget is consumed by call latency rather than "
        f"by parking attempts")


def test_a_liveness_probe_that_loses_to_the_reaper_leaves_no_live_cache_entry():
    """`_live_cache` was the last per-slot map whose publication was not tombstone-aware.

    The base `reap()` pops it BEFORE issuing the slow terminate, and it is written from two threads
    that can both be mid-describe at that moment: the pool tick thread (`is_alive`, via
    `_health_check`) and dispatcher claim threads (`is_alive_for_claim`). A write landing after
    disposal re-creates an entry for a per-spawn UUID -- and on a disposable-warm tier that mints a
    slot per job, that is once per race, forever.

    MUTATION: remove the `_slot_is_gone` guard from the `is_alive` publication -> the entry survives.
    """
    from blastbox.host.runtime.aws_worker import AwsWorkerSlot

    now = [1000.0]
    rt, fake = _hibernate_rt(state=["running"], healthy=[True], clock=lambda: now[0])
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")
    fake.responses["ec2 terminate-instances"] = {}

    def _reaper_wins_mid_probe(*a, **kw):  # noqa: ANN002, ANN003, ANN202
        rt.reap(slot)                       # disposal completes while we are "in the describe"
        return {"InstanceId": "i-1", "State": {"Name": "running"}}

    rt._describe = _reaper_wins_mid_probe  # type: ignore[method-assign]
    rt.is_alive(slot)

    assert "s" not in rt._live_cache, (
        f"_live_cache leaked {rt._live_cache.get('s')!r} for a slot already tombstoned "
        f"({list(rt._reaped_ids)}); the base reap popped it before the terminate, so nothing "
        f"collects it now")


def test_every_float_knob_on_every_aws_tier_rejects_a_non_duration():
    """Enumerated from the FIELD LIST, which is the point.

    This defect class was reported on four consecutive review rounds -- the pool knobs, the
    dispatcher thaw budget, the shared health-probe ceiling, the hibernate budget, and finally
    LambdaSnapStartConfig.resume_timeout_s, the one tier nobody had reached. Every round fixed the
    reported field and left its siblings, because each guard enumerated NAMES. A NaN resume budget
    makes `min(cfg.resume_timeout_s, budget_s)` NaN, the deadline comparisons never enter the
    polling loop, and every claimed warm slot comes back UNKNOWN -- the tier requeues jobs forever
    while reporting green.

    So this test enumerates fields too. A new float knob, or a whole new AWS tier, is covered the
    day it is declared rather than the round after someone reports it.

    MUTATION: add a float field with a default to any AwsWorkerConfig subclass and skip it in the
    base clamp -> this fails, naming the field.
    """
    import dataclasses
    import inspect
    import math

    from blastbox.host.runtime import aws_worker as _aw

    exempt = _aw._DURATION_EXEMPT
    allow_zero = _aw._DURATION_ALLOW_ZERO

    tiers = [obj for obj in vars(_aw).values()
             if inspect.isclass(obj) and dataclasses.is_dataclass(obj)
             and issubclass(obj, _aw.AwsWorkerConfig)]
    assert len(tiers) >= 4, f"sanity: expected every AWS tier config, found {len(tiers)}"

    bad_values = (float("nan"), float("inf"), float("-inf"), -1.0)
    offenders = []
    for cls in tiers:
        required = {f.name: ("ami-x" if "image_id" in f.name else "x")
                    for f in dataclasses.fields(cls)
                    if f.default is dataclasses.MISSING
                    and f.default_factory is dataclasses.MISSING}  # type: ignore[misc]
        for field in dataclasses.fields(cls):
            if field.name in exempt or not isinstance(field.default, float):
                continue
            for bad in bad_values:
                if bad == -1.0 and field.name in allow_zero:
                    pass          # still illegal: allow_zero permits 0, never negative
                got = getattr(cls(**{**required, field.name: bad}), field.name)
                if not math.isfinite(got) or got < 0 or (got == 0 and field.name not in allow_zero):
                    offenders.append(f"{cls.__name__}.{field.name} kept {bad!r} as {got!r}")
            # ...and a legal value must still survive the clamp
            kept = getattr(cls(**{**required, field.name: 7.0}), field.name)
            if kept != 7.0 and field.name != "probe_timeout_s":   # probe has a documented floor
                offenders.append(f"{cls.__name__}.{field.name} clobbered a legal 7.0 -> {kept!r}")

    assert not offenders, (
        "AWS config knobs accepted a value that cannot mean a duration; a NaN budget makes every "
        "deadline comparison False, so the tier neither times out nor succeeds:\n  "
        + "\n  ".join(offenders))


def test_cache_publication_holds_the_lock_it_checks_the_tombstone_under():
    """`_slot_is_gone()` is only meaningful while `_park_lock` is held -- its own docstring says so.

    The previous round guarded the describe/liveness cache publications with a bare
    `_slot_is_gone()` call, which is a check-then-act with no lock: the reaper can install the
    tombstone and clear the caches between the check and the assignment. That narrowed the window
    rather than closing it, and the liveness and claim paths never reach `_park_step`'s re-entry
    sweep to undo the damage. Same defect class as the one this whole chokepoint exists for --
    reported again, one layer down.

    All five publications now go through `_park_writes()`, which on this tier takes the lock and on
    every other tier is a free no-op yielding True.

    MUTATION: publish outside the chokepoint (bare `_slot_is_gone()`) -> the reaper interleaves.
    """
    import threading

    from blastbox.host.runtime.aws_worker import AwsWorkerSlot

    now = [1000.0]
    rt, fake = _hibernate_rt(state=["running"], healthy=[True], clock=lambda: now[0])
    slot = AwsWorkerSlot(slot_id="s", resource_id="i-1")
    fake.responses["ec2 terminate-instances"] = {}

    import contextlib

    done = threading.Event()
    released = threading.Event()
    real_gone = rt._slot_is_gone
    real_writes = rt._park_writes

    def _release_the_reaper() -> None:
        """Let the reaper run AT the liveness decision, then give it a moment to finish.

        Under the chokepoint this happens with _park_lock held, so the reaper cannot get in until
        the publication is done. Without it -- a bare `_slot_is_gone()` check -- nothing holds it
        back and the write lands after the slot's only cleanup. The describe itself stays OUTSIDE
        the lock either way; holding a lock across I/O is a separate bug this must not reintroduce.
        """
        if released.is_set():
            return
        released.set()
        threading.Thread(target=lambda: (rt.reap(slot), done.set()), daemon=True).start()
        done.wait(timeout=0.25)

    # THE WINDOW IS BETWEEN THE CHECK AND THE ASSIGNMENT, and `self._clock()` is evaluated exactly
    # there -- `_live_cache[sid] = (self._clock(), alive)`. Releasing the reaper at the CHECK
    # instead proves nothing: the reaper finishes, the check then observes the tombstone, and even
    # the unguarded shape correctly declines to write. (That version of this test passed against a
    # deliberately unguarded build.) Hooking the clock reproduces the real interleaving: under the
    # chokepoint the lock is held here so the reaper blocks; unguarded, it runs to completion and
    # the write lands after the tombstone sweep, where nothing will ever collect it.
    armed = {"go": False}
    real_clock = rt._clock

    def _hooked_clock():  # noqa: ANN202
        if armed["go"]:
            _release_the_reaper()
        return real_clock()

    def _hooked_gone(sid):  # noqa: ANN001, ANN202 -- the UNGUARDED shape calls this
        armed["go"] = True
        return real_gone(sid)

    @contextlib.contextmanager
    def _hooked_writes(sid):  # noqa: ANN001, ANN202 -- the CHOKEPOINT shape calls this
        with real_writes(sid) as live:
            armed["go"] = True
            yield live

    # Hook every shape, so this drives whichever implementation is present rather than passing
    # vacuously when the hook it happens to patch is the one not in use.
    rt._slot_is_gone = _hooked_gone          # type: ignore[method-assign]
    rt._park_writes = _hooked_writes         # type: ignore[method-assign]
    rt._clock = _hooked_clock                # type: ignore[method-assign]
    rt.is_alive(slot)
    assert released.is_set(), "no publication hook fired; the test drove nothing"
    assert done.wait(timeout=5.0), "the reaper never finished; the lock is not being released"

    assert "s" not in rt._live_cache and "s" not in rt._desc_cache, (
        f"a cache entry survived for a reaped slot (live={rt._live_cache.get('s')!r}, "
        f"desc={rt._desc_cache.get('s')!r}); ids are per-spawn UUIDs, so this is permanent")
