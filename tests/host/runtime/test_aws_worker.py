"""Unit tests for the AWS disposable-worker runtime family (no real AWS).

The AWS CLI and the HTTP health probe are injected as fakes, so spawn/is_ready/is_alive/reap are
exercised end-to-end against canned responses. Also checks SlotRuntime protocol conformance, the
fail-closed availability probe, config from_env, and pool_config registration.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from blastbox.host.pool import SlotRuntime, SlotState
from blastbox.host.runtime.aws_worker import (
    AwsUnavailable,
    AwsWorkerError,
    AwsWorkerSlot,
    DisposableEc2Runtime,
    Ec2Config,
    LambdaMicroVmConfig,
    LambdaMicroVmRuntime,
    LambdaSnapStartConfig,
    LambdaSnapStartRuntime,
    select_lambda_microvm_runtime,
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


def test_ec2_config_from_env_defaults_arm():
    cfg = Ec2Config.from_env({"BLASTBOX_EC2_AMI": "ami-x"}.get)
    assert cfg.image_id == "ami-x"
    assert cfg.instance_type == "m7g.large"   # ARM64 default
    assert cfg.region == "us-east-1"


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


def test_ec2_self_terminate_ttl_injected():
    import base64

    from blastbox.host.runtime.aws_worker import _userdata_with_self_terminate
    wrapped = _userdata_with_self_terminate("#!/bin/bash\necho hi\n", 600)
    assert "shutdown -h +10" in wrapped and "echo hi" in wrapped   # 600s -> 10min; operator part kept

    ud = base64.b64encode(b"#!/bin/bash\nstart-agent\n").decode()
    cfg = Ec2Config(region="us-east-1", image_id="ami-x", user_data_b64=ud, max_duration_s=1800)
    fake = FakeAws({**_IDENT, "ec2 run-instances": {"Instances": [{"InstanceId": "i-1"}]}})
    rt = DisposableEc2Runtime(cfg, aws_runner=fake, http_probe=lambda u, h, t: True, clock=lambda: 1.0)
    rt.spawn()
    argv = next(a for k, a in fake.calls if k == "ec2 run-instances")
    ud_arg = argv[argv.index("--user-data") + 1]
    assert "shutdown -h +30" in ud_arg and "start-agent" in ud_arg   # crashed dispatcher can't leak it


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
