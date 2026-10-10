"""Backend selection is platform-aware and never substitutes across platforms."""
from __future__ import annotations

import pytest

from blastbox.errors import SandboxUnavailable
from blastbox.worker.sandbox import detect
from blastbox.worker.sandbox.base import SandboxResult

pytestmark = pytest.mark.host_platform


class _Fake:
    def __init__(self, name):
        self.name = name
        self.secure = True
        self.insecurity_reasons: list[str] = []

    def run(self, request):
        return SandboxResult(exit_code=0, stdout=b"", stderr=b"")


@pytest.fixture
def on(monkeypatch):
    def _set(platform: str):
        monkeypatch.setattr(detect, "host_platform", lambda: platform)
        monkeypatch.setattr(detect, "_in_container", lambda: False)
        monkeypatch.delenv("BLASTBOX_SANDBOX", raising=False)
        monkeypatch.delenv("BLASTBOX_WARN_ON_INSECURE", raising=False)
    return _set


def test_darwin_auto_order_is_seatbelt_then_appsandbox(on, monkeypatch):
    on("darwin")
    tried = []

    def make(name, **kw):
        tried.append(name)
        if name == "seatbelt":
            raise SandboxUnavailable("pretend sandbox-exec vanished")
        return _Fake(name)

    monkeypatch.setattr(detect, "_make_backend", make)
    assert detect.select_sandbox().name == "appsandbox"
    assert tried == ["seatbelt", "appsandbox"]


def test_darwin_never_auto_selects_linux_or_container(on, monkeypatch):
    on("darwin")
    tried = []

    def make(name, **kw):
        tried.append(name)
        raise SandboxUnavailable("no")

    monkeypatch.setattr(detect, "_make_backend", make)
    with pytest.raises(SandboxUnavailable):
        detect.select_sandbox()
    assert set(tried) == {"seatbelt", "appsandbox"}


@pytest.mark.parametrize("name", ["nono", "bwrap", "nsjail"])
def test_forcing_a_linux_backend_on_darwin_is_refused(on, name):
    on("darwin")
    with pytest.raises(SandboxUnavailable, match="linux backend"):
        detect.select_sandbox(backend=name)


@pytest.mark.parametrize("name", ["seatbelt", "appsandbox"])
def test_forcing_a_darwin_backend_on_linux_is_refused(on, name):
    on("linux")
    with pytest.raises(SandboxUnavailable, match="darwin backend"):
        detect.select_sandbox(backend=name)


def test_linux_auto_order_unchanged(on):
    on("linux")
    assert detect._all_backends() == ("nsjail", "bwrap", "nono", "container")


def test_nono_backend_refuses_on_darwin():
    from blastbox.worker.sandbox.nono import NonoSandbox
    with pytest.raises(SandboxUnavailable, match="seatbelt"):
        NonoSandbox(platform="darwin")
