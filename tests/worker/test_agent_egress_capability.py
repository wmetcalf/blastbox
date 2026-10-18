"""The agent ADVERTISES whether it can provide egress, and REFUSES a job that needs it when it
cannot -- instead of running it with the network silently denied.

Before this, a macOS worker handed an egress job logged "net_egress requested ...; network stays
DENIED" from inside seatbelt/appsandbox and returned a plausible `ok`: the job's answer described
a run that never reached the network. Platform is simulated (``ha.host_platform``) both ways,
so this runs identically on Linux CI and a Mac.
"""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from blastbox.contract import Detection, Record
from blastbox.limits import Limits
from blastbox.worker import http_agent as ha
from blastbox.worker.engine import DetonationResult
from blastbox.worker.sandbox.base import note_confined_run


class _Engine:
    name = "egress-probe"
    formats = frozenset({"*"})
    sandboxed_parsing = True

    def __init__(self) -> None:
        self.ran: list[bool] = []

    def detonate(self, input: Path, outdir: Path, limits: Limits) -> DetonationResult:
        self.ran.append(limits.net_egress)
        note_confined_run()
        return DetonationResult(
            payload=Record(fields={"n": 1}), artifacts=[],
            detected=Detection(label="bin", mime="application/octet-stream", confidence=1.0,
                               source="test"))


@pytest.fixture
def platform(monkeypatch):
    monkeypatch.delenv("BLASTBOX_WORKER_AGENT_EGRESS", raising=False)
    monkeypatch.delenv("BLASTBOX_NET_EGRESS", raising=False)
    monkeypatch.setattr(ha, "_HARD_EXIT", lambda code: None)

    def set_(name: str) -> None:
        monkeypatch.setattr(ha, "host_platform", lambda: name)

    return set_


def _serve(engine, **kw):
    httpd = ha.serve(engine, bind="127.0.0.1", port=0, **kw)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.server_address[1]


def _healthz(port: int) -> dict:
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=10) as r:
        return json.loads(r.read())


def _post(port: int, params: dict | None = None) -> tuple[int, dict]:
    headers = {"X-Blastbox-Params": json.dumps(params)} if params else {}
    req = urllib.request.Request(f"http://127.0.0.1:{port}/detonate?name=x", data=b"x",
                                 method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, {}
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def _stop(httpd) -> None:
    httpd.shutdown()
    httpd.server_close()


def test_a_mac_advertises_no_egress_and_refuses_an_egress_job_before_it_runs(platform):
    platform("darwin")
    eng = _Engine()
    httpd, port = _serve(eng)
    try:
        assert _healthz(port)["egress"] is False
        code, body = _post(port, {"BLASTBOX_NET_EGRESS": "1"})
        assert code == 422 and body["error"] == "egress_unavailable"
        assert eng.ran == []                          # the engine never saw the input
        code, _ = _post(port)                          # a sealed job is served as before
        assert code == 200 and eng.ran == [False]
    finally:
        _stop(httpd)


def test_a_mac_cannot_be_told_it_has_egress(platform, monkeypatch):
    platform("darwin")
    monkeypatch.setenv("BLASTBOX_WORKER_AGENT_EGRESS", "1")
    with pytest.raises(SystemExit, match="cannot provide egress"):
        ha._egress_capable()
    with pytest.raises(SystemExit):
        ha.serve(_Engine(), bind="127.0.0.1", port=0, egress_capable=True)


def test_linux_keeps_its_behaviour_by_default(platform):
    platform("linux")
    eng = _Engine()
    httpd, port = _serve(eng)
    try:
        assert _healthz(port)["egress"] is True
        code, _ = _post(port, {"BLASTBOX_NET_EGRESS": "1"})
        assert code == 200 and eng.ran == [True]
    finally:
        _stop(httpd)


def test_a_linux_worker_can_declare_it_has_no_exit(platform, monkeypatch):
    platform("linux")
    monkeypatch.setenv("BLASTBOX_WORKER_AGENT_EGRESS", "0")
    eng = _Engine()
    httpd, port = _serve(eng)
    try:
        assert _healthz(port)["egress"] is False
        assert _post(port, {"BLASTBOX_NET_EGRESS": "true"})[0] == 422
        assert eng.ran == []
    finally:
        _stop(httpd)


def test_the_agents_own_env_counts_too(platform, monkeypatch):
    """Limits.from_env reads the agent's environment under the forwarded params: an agent
    whose image sets BLASTBOX_NET_EGRESS=1 is asking for egress on every job."""
    platform("darwin")
    monkeypatch.setenv("BLASTBOX_NET_EGRESS", "1")
    eng = _Engine()
    httpd, port = _serve(eng)
    try:
        assert _post(port)[0] == 422 and eng.ran == []
        assert _post(port, {"BLASTBOX_NET_EGRESS": "0"})[0] == 200   # forwarded param wins
    finally:
        _stop(httpd)


def test_a_typo_in_the_capability_flag_stops_startup(platform, monkeypatch):
    platform("linux")
    monkeypatch.setenv("BLASTBOX_WORKER_AGENT_EGRESS", "maybe")
    with pytest.raises(SystemExit):
        ha._egress_capable()


def test_the_dispatcher_turns_the_refusal_into_a_clear_job_error(platform, tmp_path):
    """End to end against the real agent: the transport recognises the 422 and the validate
    path fails the job with the placement reason, releasing the slot CLEAN (nothing ran)."""
    from types import SimpleNamespace

    from blastbox.host.runtime.remote_http import (
        EGRESS_PLACEMENT_ERROR,
        WorkerLacksEgress,
        detonate_remote,
        make_remote_validate,
    )

    platform("darwin")
    eng = _Engine()
    httpd, port = _serve(eng)
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"x")
    try:
        with pytest.raises(WorkerLacksEgress):
            detonate_remote(f"http://127.0.0.1:{port}", inp, tmp_path / "o",
                            params={"BLASTBOX_NET_EGRESS": "1"})
        released = []
        slot = SimpleNamespace(url=f"http://127.0.0.1:{port}", ip=None, auth_token=None,
                               agent_port=port)
        validate = make_remote_validate(
            lambda: slot,
            lambda s, dirty=False, fault=None: released.append((dirty, fault)),
            output_dir_for=lambda p: tmp_path / "o2",
            params_for=lambda p: {"BLASTBOX_NET_EGRESS": "1"})
        meta, ok = validate(inp)
        assert ok is False and meta == {"error": EGRESS_PLACEMENT_ERROR}
        assert released == [(False, "job")]
        assert eng.ran == []
    finally:
        _stop(httpd)
