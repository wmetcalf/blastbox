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
