"""Unit tests for the AWS disposable-worker runtime family (no real AWS).

The AWS CLI and the HTTP health probe are injected as fakes, so spawn/is_ready/is_alive/reap are
exercised end-to-end against canned responses. Also checks SlotRuntime protocol conformance, the
fail-closed availability probe, config from_env, and pool_config registration.
"""

from __future__ import annotations

import errno
import json
import os
import subprocess

import pytest

from blastbox.host.pool import SlotRuntime, SlotState
from blastbox.host.runtime.aws_worker import (
    AwsProbeTimeout,
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
                          resume_timeout_s=5.0)
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
                          resume_timeout_s=5.0)
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


def test_f14_health_ok_propagates_an_unknown_mint_rather_than_returning_false():
    """The contract, pinned directly. resume() reads only what ESCAPES _health_ok, so collapsing an
    unconfirmed mint failure into a bare False loses the verdict on that pass. (The mint back-off
    re-raises it on later passes, which is why an end-to-end resume test alone cannot detect this:
    a single-pass resume would still be misclassified.) is_ready() catches it and returns False,
    exactly as before."""
    from blastbox.host.runtime.aws_worker import AwsUnknownState

    rt, _ = _snapstart_rt({"lambda-microvms get-microvm": {"state": "RUNNING", "endpoint": "vm.example"},
                           "lambda-microvms create-microvm-auth-token":
                               _cp(rc=255, stderr="An error occurred (TooManyRequestsException)")},
                          probe=lambda u, h, t: True)
    slot = AwsWorkerSlot(slot_id="p1", resource_id="mv-1", state=SlotState.ASSIGNED,
                         url="http://10.0.0.1:8080")
    with pytest.raises(AwsUnknownState):
        rt._health_ok(slot)          # first call: nothing suppressed yet, so this is the raise site
    assert rt.is_ready(slot) is False, "is_ready must still absorb it and report not-ready"


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
                          resume_timeout_s=5.0)
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
                          resume_timeout_s=5.0)
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
                           resume_timeout_s=5.0)
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

    for code, label in ((socket.EAI_AGAIN, "EAI_AGAIN"), (socket.EAI_NONAME, "EAI_NONAME")):
        wrapped = urllib.error.URLError(socket.gaierror(code, f"[{label}] Name resolution failure"))
        assert _is_local_resource_error(wrapped), f"{label} read as a verdict about the worker"

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
