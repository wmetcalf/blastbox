"""The worker agent on macOS, where there is no outer isolation boundary.

On Linux the agent runs inside runsc/Firecracker, so an engine that parses in-process is still
contained. On a Mac nothing is: the agent refuses engines that don't declare sandboxed parsing,
refuses an `ok` result that no confined run produced, and gates /healthz on warmup.
"""
from __future__ import annotations

import json
import concurrent.futures
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from blastbox.contract import Detection, Record
from blastbox.limits import Limits
from blastbox.worker import http_agent as ha
from blastbox.worker.engine import DetonationResult
from blastbox.worker.sandbox.base import confined_runs, not_counted, note_confined_run


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


def test_a_required_warmup_that_the_engine_lacks_is_not_ready():
    # _Engine has no warmup(): when the self-test gate is on, that is "not ready", not "passed".
    assert ha._warmup(_Engine(), require_warmup=True) == "engine has no warmup self-test"
    assert ha._warmup(_Engine(), require_warmup=False) is None


def test_a_required_warmup_must_complete_a_confined_run():
    class InProcess(_Engine):
        def warmup(self):
            pass                         # "passed", but parsed in-process: nothing confined

    class Confined(_Engine):
        def warmup(self):
            note_confined_run()
    err = ha._warmup(InProcess(), require_warmup=True, require_confined=True)
    assert err is not None and "confined" in err
    assert ha._warmup(Confined(), require_warmup=True, require_confined=True) is None
    # not required to be confined (Linux, or the logged escape hatch), or warmup not required
    assert ha._warmup(InProcess(), require_warmup=True, require_confined=False) is None
    assert ha._warmup(InProcess(), require_warmup=False, require_confined=True) is None


def test_a_retried_warmup_that_never_confines_stays_unready():
    import time

    class InProcess(_Engine):
        calls = 0

        def warmup(self):
            type(self).calls += 1
    eng = InProcess()
    err = ha._warmup(eng, require_warmup=True, require_confined=True)
    httpd, port = _agent(eng, warmup_error=err)
    stop = threading.Event()
    try:
        ha.retry_warmup(eng, httpd.RequestHandlerClass, first_s=0.02, max_s=0.02, stop=stop)
        deadline = time.monotonic() + 5
        while InProcess.calls < 4 and time.monotonic() < deadline:
            time.sleep(0.02)
        assert InProcess.calls >= 4
        assert httpd.RequestHandlerClass.warmup_error is not None
    finally:
        stop.set()
        _stop(httpd)


def test_warmup_errors_gate_only_when_required():
    class Boom(_Engine):
        def warmup(self):
            raise RuntimeError("self-test decoded nothing")
    assert "decoded nothing" in ha._warmup(Boom(), require_warmup=True)
    assert ha._warmup(Boom(), require_warmup=False) is None


class _Detecting(_Engine):
    def __init__(self, **kw):
        super().__init__(**kw)
        self.detect_calls = 0

    def detect(self, input_path: Path):
        self.detect_calls += 1
        return None


def test_optional_detect_is_not_run_in_the_agent_on_macos():
    eng = _Detecting()
    httpd, port = _agent(eng)
    try:
        assert _detonate(port) == 200
        assert eng.detect_calls == 0
    finally:
        _stop(httpd)


def test_an_engine_may_declare_its_detect_sandboxed():
    class Declared(_Detecting):
        sandboxed_detect = True
    eng = Declared()
    httpd, port = _agent(eng)
    try:
        assert _detonate(port) == 200
        assert eng.detect_calls == 1
    finally:
        _stop(httpd)


def test_a_sandboxed_detect_is_not_credit_for_an_in_process_detonate():
    # detect() goes through the sandbox (a confined run) but detonate() then parses in-process
    # and returns ok: the detector's run must not satisfy the result gate
    class DetectsSandboxedParsesInProcess(_Detecting):
        sandboxed_detect = True

        def detect(self, input_path: Path):
            super().detect(input_path)
            note_confined_run()          # what a sandboxed detector's backend run records
            return None
    eng = DetectsSandboxedParsesInProcess(confine=False)
    httpd, port = _agent(eng)
    try:
        assert _detonate(port) == 500
        assert eng.detect_calls == 1
    finally:
        _stop(httpd)


def test_a_confined_detonate_after_a_sandboxed_detect_still_passes():
    class Declared(_Detecting):
        sandboxed_detect = True

        def detect(self, input_path: Path):
            super().detect(input_path)
            note_confined_run()
            return None
    httpd, port = _agent(Declared(confine=True))
    try:
        assert _detonate(port) == 200
    finally:
        _stop(httpd)


def test_detect_still_runs_off_macos(monkeypatch):
    monkeypatch.setattr(ha, "host_platform", lambda: "linux")
    eng = _Detecting()
    httpd, port = _agent(eng)
    try:
        assert _detonate(port) == 200
        assert eng.detect_calls == 1
    finally:
        _stop(httpd)


def test_a_selector_probe_during_a_job_is_not_confinement_credit(monkeypatch):
    # An engine that calls select_sandbox() inside detonate() and then parses in-process: the
    # selector's /usr/bin/true smoketest must not count as its confined run.
    from blastbox.worker.sandbox import detect
    from blastbox.worker.sandbox.base import SandboxResult, confined_runs

    class _Counting:
        name = "probe"
        secure = True
        insecurity_reasons: list[str] = []

        def run(self, request):
            note_confined_run()         # what seatbelt/appsandbox do for a real launch
            return SandboxResult(exit_code=0, stdout=b"", stderr=b"")

    before = confined_runs()
    assert detect._smoketest(_Counting()) == (True, None)
    assert confined_runs() == before

    class SelectsThenParsesInProcess(_Engine):
        def detonate(self, input, outdir, limits):
            detect._smoketest(_Counting())
            return super().detonate(input, outdir, limits)
    httpd, port = _agent(SelectsThenParsesInProcess(confine=False))
    try:
        assert _detonate(port) == 500
    finally:
        _stop(httpd)


def test_a_failed_required_warmup_is_retried_until_it_passes():
    import time

    class Flaky(_Engine):
        def __init__(self):
            super().__init__()
            self.calls = 0

        def warmup(self):
            self.calls += 1
            if self.calls < 3:
                raise RuntimeError("ANE busy")
            note_confined_run()
    eng = Flaky()
    err = ha._warmup(eng, require_warmup=True, require_confined=True)
    httpd, port = _agent(eng, warmup_error=err)
    stop = threading.Event()
    try:
        url = f"http://127.0.0.1:{port}/healthz"
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(url, timeout=10)
        assert exc.value.code == 503
        ha.retry_warmup(eng, httpd.RequestHandlerClass, first_s=0.05, max_s=0.1, stop=stop)
        deadline = time.monotonic() + 10
        while httpd.RequestHandlerClass.warmup_error is not None and time.monotonic() < deadline:
            time.sleep(0.02)
        assert eng.calls == 3
        with urllib.request.urlopen(url, timeout=10) as r:
            assert r.status == 200
    finally:
        stop.set()
        _stop(httpd)


@pytest.mark.parametrize("name", ["BLASTBOX_WORKER_AGENT_REQUIRE_WARMUP",
                                  "BLASTBOX_WORKER_AGENT_ALLOW_UNSANDBOXED_ENGINE"])
def test_security_flags_are_parsed_strictly(monkeypatch, name):
    for raw, want in (("1", True), ("YES", True), ("true", True), ("0", False), ("No", False),
                      ("FALSE", False)):
        monkeypatch.setenv(name, raw)
        assert ha._env_flag(name, default=not want) is want
    for raw in ("", "  "):
        monkeypatch.setenv(name, raw)
        assert ha._env_flag(name, default=True) is True
    for raw in ("on", "enabled", "flase", "2"):
        monkeypatch.setenv(name, raw)
        with pytest.raises(SystemExit, match=name):
            ha._env_flag(name, default=False)


def test_a_mistyped_escape_hatch_stops_startup(monkeypatch):
    class Plain(_Engine):
        sandboxed_parsing = False
    monkeypatch.setenv("BLASTBOX_WORKER_AGENT_ALLOW_UNSANDBOXED_ENGINE", "ture")
    with pytest.raises(SystemExit, match="ALLOW_UNSANDBOXED_ENGINE"):
        ha.serve(Plain(), bind="127.0.0.1", port=0)


def test_a_detectors_sandbox_run_on_another_thread_is_not_credit_either():
    # the detector makes its sandbox call on a thread it starts (no context is inherited):
    # still not credit for a detonate() that then parses in-process
    class ThreadedDetector(_Detecting):
        sandboxed_detect = True

        def detect(self, input_path: Path):
            super().detect(input_path)
            t = threading.Thread(target=note_confined_run)
            t.start()
            t.join()
            with concurrent.futures.ThreadPoolExecutor(1) as ex:
                ex.submit(note_confined_run).result()
            return None
    eng = ThreadedDetector(confine=False)
    httpd, port = _agent(eng)
    try:
        assert _detonate(port) == 500
        assert eng.detect_calls == 1
    finally:
        _stop(httpd)


def test_not_counted_covers_threads_started_inside_it():
    before = confined_runs()
    with not_counted():
        t = threading.Thread(target=note_confined_run)
        t.start()
        t.join()
        with concurrent.futures.ThreadPoolExecutor(2) as ex:
            list(ex.map(lambda _: note_confined_run(), range(3)))
        with not_counted():          # nests
            note_confined_run()
        note_confined_run()
    assert confined_runs() == before
    note_confined_run()
    assert confined_runs() == before + 1
