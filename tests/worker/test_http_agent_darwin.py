"""The worker agent on macOS, where there is no outer isolation boundary.

On Linux the agent runs inside runsc/Firecracker, so an engine that parses in-process is still
contained. On a Mac nothing is: the agent refuses engines that don't declare sandboxed parsing,
refuses an `ok` result that no confined run produced, and gates /healthz on warmup.
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


@pytest.fixture(autouse=True)
def _darwin(monkeypatch):
    monkeypatch.setattr(ha, "host_platform", lambda: "darwin")
    monkeypatch.delenv("BLASTBOX_WORKER_AGENT_ALLOW_UNSANDBOXED_ENGINE", raising=False)


class _Engine:
    name = "test-mac"
    formats = frozenset({"*"})
    sandboxed_parsing = True

    def __init__(self, confine: bool = True, status: str = "ok"):
        self.confine, self.status = confine, status

    def detonate(self, input: Path, outdir: Path, limits: Limits) -> DetonationResult:
        if self.confine:
            note_confined_run()          # what seatbelt/appsandbox .run() record
        return DetonationResult(
            payload=Record(fields={"n": 1}), artifacts=[],
            detected=Detection(label="bin", mime="application/octet-stream", confidence=1.0,
                               source="test"),
            status=self.status)  # type: ignore[arg-type]


def _agent(engine, **kw):
    httpd = ha.serve(engine, bind="127.0.0.1", port=0, **kw)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.server_address[1]


def _detonate(port: int) -> int:
    req = urllib.request.Request(f"http://127.0.0.1:{port}/detonate?name=x", data=b"x", method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def _stop(httpd):
    httpd.shutdown()
    httpd.server_close()


def test_an_engine_that_does_not_declare_sandboxed_parsing_is_refused():
    class Plain(_Engine):
        sandboxed_parsing = False
    with pytest.raises(SystemExit, match="sandboxed_parsing"):
        ha.serve(Plain(), bind="127.0.0.1", port=0)


def test_the_escape_hatch_is_explicit(monkeypatch):
    class Plain(_Engine):
        sandboxed_parsing = False
    monkeypatch.setenv("BLASTBOX_WORKER_AGENT_ALLOW_UNSANDBOXED_ENGINE", "1")
    httpd, port = _agent(Plain(confine=False))
    try:
        assert _detonate(port) == 200
    finally:
        _stop(httpd)


def test_ok_from_a_confined_run_is_served():
    httpd, port = _agent(_Engine(confine=True))
    try:
        assert _detonate(port) == 200
    finally:
        _stop(httpd)


def test_ok_without_any_confined_run_is_refused():
    # The engine declared sandboxing but parsed in-process this time: the result is not served.
    httpd, port = _agent(_Engine(confine=False))
    try:
        assert _detonate(port) == 500
    finally:
        _stop(httpd)


def test_a_rejection_needs_no_confined_run():
    # Refusing bad input before spawning anything is fine; only an `ok` needs the proof.
    httpd, port = _agent(_Engine(confine=False, status="rejected"))
    try:
        assert _detonate(port) == 200
    finally:
        _stop(httpd)


def test_failed_warmup_makes_healthz_not_ready():
    httpd, port = _agent(_Engine(), warmup_error="self-test failed")
    try:
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=10)
        assert exc.value.code == 503
        assert json.loads(exc.value.read())["warmup"] == "failed"
    finally:
        _stop(httpd)
