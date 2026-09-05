"""The timeout cleanup must not report a failed enumeration as a clean host.

`runsc list` is run with check=False, so a non-zero exit yields empty stdout --
which read as "no containers" and printed `nothing to clean up` while live
sandboxes may have remained. Same class as reporting an unchecked delete as a
success.

Driven through a stub `runsc` so it runs anywhere, no gVisor needed.
"""
from __future__ import annotations

import importlib.util
import stat
from pathlib import Path

import pytest


_MODULE = (
    Path(__file__).resolve().parents[2]
    / "integration" / "test_gvisor_snapshot_roundtrip.py"
)


def _load():
    spec = importlib.util.spec_from_file_location("_gv_roundtrip", _MODULE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _stub_runsc(tmp_path: Path, *, list_rc: int, list_out: str, delete_rc: int = 0) -> Path:
    """A `runsc` that answers `list` and `delete` however the test needs."""
    payload = tmp_path / "list.json"
    payload.write_text(list_out)
    script = tmp_path / "runsc-stub"
    script.write_text(
        "#!/bin/sh\n"
        "verb=\n"
        'for a in "$@"; do\n'
        "  case \"$a\" in list|kill|delete) verb=\"$a\"; break;; esac\n"
        "done\n"
        "case \"$verb\" in\n"
        f"  list) cat {payload}; exit {list_rc};;\n"
        f"  delete) exit {delete_rc};;\n"
        "  *) exit 0;;\n"
        "esac\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script


class _Cfg:
    def __init__(self, runsc_bin: str, root: Path) -> None:
        self.runsc_bin = runsc_bin
        self.root = root


def test_a_failed_listing_is_not_an_empty_host(tmp_path):
    mod = _load()
    stub = _stub_runsc(tmp_path, list_rc=1, list_out="")
    deleted, unconfirmed = mod._force_delete_all(_Cfg(str(stub), tmp_path / "root"))
    assert deleted == []
    assert unconfirmed, "a failed enumeration must be reported as unconfirmed"
    assert "listing failed" in unconfirmed[0]


def test_an_empty_host_is_reported_as_clean(tmp_path):
    """`runsc list` prints literal null when nothing is registered."""
    mod = _load()
    stub = _stub_runsc(tmp_path, list_rc=0, list_out="null")
    assert mod._force_delete_all(_Cfg(str(stub), tmp_path / "root")) == ([], [])


def test_a_delete_that_fails_is_unconfirmed(tmp_path):
    mod = _load()
    stub = _stub_runsc(
        tmp_path, list_rc=0, list_out='[{"id": "slot-abc"}]', delete_rc=1
    )
    deleted, unconfirmed = mod._force_delete_all(_Cfg(str(stub), tmp_path / "root"))
    assert deleted == [], "a failed delete must not be reported as removed"
    assert unconfirmed == ["slot-abc"]


def test_a_delete_that_succeeds_is_reported(tmp_path):
    mod = _load()
    stub = _stub_runsc(tmp_path, list_rc=0, list_out='[{"id": "slot-abc"}]')
    deleted, unconfirmed = mod._force_delete_all(_Cfg(str(stub), tmp_path / "root"))
    assert deleted == ["slot-abc"] and unconfirmed == []


def test_a_listing_that_is_not_an_array_is_unconfirmed(tmp_path):
    """runsc exiting 0 with an object, not a list, is not a clean host either.

    Treating an unexpected shape as "no containers" is the same failure as
    treating a failed listing that way: the cleanup reports success without
    having enumerated anything.
    """
    mod = _load()
    stub = _stub_runsc(tmp_path, list_rc=0, list_out='{"error": "unexpected"}')
    deleted, unconfirmed = mod._force_delete_all(_Cfg(str(stub), tmp_path / "root"))
    assert deleted == []
    assert unconfirmed, "an unrecognised listing shape must be reported"


def test_a_listing_that_cannot_run_is_unconfirmed(tmp_path):
    """A timeout or a missing binary is not an empty host either."""
    mod = _load()
    deleted, unconfirmed = mod._force_delete_all(
        _Cfg(str(tmp_path / "no-such-runsc"), tmp_path / "root")
    )
    assert deleted == []
    assert unconfirmed and "errored" in unconfirmed[0]


@pytest.mark.parametrize("body", ["{}", "false", "0", '""'])
def test_falsy_but_non_null_listings_are_unconfirmed(tmp_path, body):
    """`json.loads(...) or []` accepted every one of these as a clean host."""
    mod = _load()
    stub = _stub_runsc(tmp_path, list_rc=0, list_out=body)
    deleted, unconfirmed = mod._force_delete_all(_Cfg(str(stub), tmp_path / "root"))
    assert deleted == [], body
    assert unconfirmed, f"{body} is not an empty host"


def test_a_later_sweep_clears_an_earlier_unconfirmed_id(tmp_path):
    """A transient delete failure must not be reported as possibly-live forever."""
    mod = _load()
    calls = {"n": 0}

    def fake_force_delete(cfg, **kw):
        # sweep 1: delete fails. sweep 2: it succeeds. sweep 3: host is clean --
        # which is what a real host does once the container is gone.
        calls["n"] += 1
        if calls["n"] == 1:
            return [], ["slot-abc"]
        if calls["n"] == 2:
            return ["slot-abc"], []
        return [], []

    original = mod._force_delete_all
    mod._force_delete_all = fake_force_delete
    try:
        alive = iter([True, False, False])
        deleted, unconfirmed, was_live = mod._sweep_until_clean(
            _Cfg("runsc", tmp_path / "root"), lambda: next(alive, False), settle_s=0
        )
    finally:
        mod._force_delete_all = original

    assert deleted == ["slot-abc"]
    assert unconfirmed == [], "a later successful delete must clear the earlier doubt"
    assert was_live is True, "the producer was live during the first sweep"


def test_a_producer_live_only_during_the_sweep_is_still_reported(tmp_path):
    """It can register a container after the last listing and then exit.

    Checking `is_alive()` only afterwards reads False and the host looks clean
    though nothing swept what was just created.
    """
    mod = _load()
    original = mod._force_delete_all
    mod._force_delete_all = lambda cfg, **kw: ([], [])
    try:
        alive = iter([True, False])
        _, _, was_live = mod._sweep_until_clean(
            _Cfg("runsc", tmp_path / "root"), lambda: next(alive, False), settle_s=0
        )
    finally:
        mod._force_delete_all = original
    assert was_live is True


def test_a_container_seen_twice_is_reported_once(tmp_path):
    """`runsc delete` can return 0 while the id is still listed on the next pass.

    Counting it twice makes the failure message name two sandboxes where there
    was one, which is exactly the kind of inaccuracy this cleanup exists to
    avoid.
    """
    mod = _load()
    seen = {"n": 0}

    def fake_force_delete(cfg, **kw):
        seen["n"] += 1
        return (["slot-abc"], []) if seen["n"] <= 2 else ([], [])

    original = mod._force_delete_all
    mod._force_delete_all = fake_force_delete
    try:
        deleted, unconfirmed, _ = mod._sweep_until_clean(
            _Cfg("runsc", tmp_path / "root"), lambda: False, settle_s=0
        )
    finally:
        mod._force_delete_all = original
    assert deleted == ["slot-abc"], f"one container, reported once; got {deleted}"
    assert unconfirmed == []
