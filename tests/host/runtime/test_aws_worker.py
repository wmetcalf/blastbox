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
    DisposableEc2Runtime,
    Ec2Config,
    LambdaMicroVmConfig,
    LambdaMicroVmRuntime,
    select_lambda_microvm_runtime,
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
    cfg = LambdaMicroVmConfig(region="us-east-1", image_identifier="arn:aws:lambda:us-east-1:aws:microvm-image:al2023-1")
    fake = FakeAws({**_IDENT, **responses})
    return LambdaMicroVmRuntime(cfg, aws_runner=fake, http_probe=probe, clock=lambda: 100.0, **kw), fake


def _ec2_rt(responses, probe=lambda url, hdrs, to: True, **kw):  # noqa: ANN001
    cfg = Ec2Config(region="us-east-1", image_id="ami-0abc")
    fake = FakeAws({**_IDENT, **responses})
    return DisposableEc2Runtime(cfg, aws_runner=fake, http_probe=probe, clock=lambda: 100.0, **kw), fake


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
    cfg = LambdaMicroVmConfig(region="us-east-1", image_identifier="img")
    fake = FakeAws({"sts get-caller-identity": {}})   # no Account
    rt = LambdaMicroVmRuntime(cfg, aws_runner=fake)
    assert rt.available() is False


def test_available_false_when_service_denied():
    cfg = Ec2Config(region="us-east-1", image_id="ami-0")
    fake = FakeAws({**_IDENT, "ec2 describe-instances": _cp(rc=254, stderr="AccessDenied")})
    rt = DisposableEc2Runtime(cfg, aws_runner=fake)
    assert rt.available() is False


def test_select_requires_available_raises():
    fake = FakeAws({"sts get-caller-identity": {}})
    with pytest.raises(AwsUnavailable):
        select_lambda_microvm_runtime(
            cfg=LambdaMicroVmConfig(region="us-east-1", image_identifier="img"),
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
    env = {"BLASTBOX_DISPATCH_TLS_CA": str(tmp_path / "ca.crt"), "BLASTBOX_LAMBDA_IMAGE": "img-x"}
    rt = select_lambda_microvm_runtime(get_env=env.get, require_available=False)
    assert rt.ssl_context is None


def test_lambda_select_no_tls_context():
    rt = select_lambda_microvm_runtime(get_env={"BLASTBOX_LAMBDA_IMAGE": "img-x"}.get, require_available=False)
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
