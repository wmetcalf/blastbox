"""The warm-base readiness budget must be reachable from the environment.

`SnapshotManager(ready_timeout_s=120.0)` is the budget a warm base gets to signal READY.
Neither production factory passed one, and no variable reached it -- so it was a hard-coded
120 s for both tiers. Meanwhile the integration test documents `BLASTBOX_SNAPSHOT_BUILD_S`
and the failure says "set BLASTBOX_SNAPSHOT_BUILD_S to allow longer", which governs a
DIFFERENT phase: raising it could not help a base that simply needed more than 120 s
(issue #147). A cold OCR/soffice warm-up on a loaded node is exactly that case.

The same shape was already fixed once in the FC live tests, per their own docstring: "Held at
30 s while the round-trip allowed 45, this failed the whole class first on a slow fleet
rootfs -- a guest that came up at 35 s never reached the test that would have accepted it."

These drive the REAL factories, because "a caller forgot to pass it" is precisely the defect.
"""

from __future__ import annotations

import pytest

from blastbox.host.runtime.env_knobs import positive_float_env

READY_ENV = "BLASTBOX_SNAPSHOT_READY_S"


class TestTheKnobItself:
    def test_a_finite_positive_value_is_honoured(self):
        assert positive_float_env({READY_ENV: "300"}, READY_ENV, 120.0) == 300.0

    @pytest.mark.parametrize("raw", ["inf", "-inf", "nan", "0", "-5", "abc", ""])
    def test_a_value_that_cannot_be_honoured_falls_back(self, raw):
        """inf never expires and nan compares false against everything, so both would
        silently restore the unbounded wait; 0 and negatives expire instantly."""
        assert positive_float_env({READY_ENV: raw}, READY_ENV, 120.0) == 120.0

    def test_an_absent_knob_uses_the_default(self):
        assert positive_float_env({}, READY_ENV, 120.0) == 120.0


def _gvisor_cr_available() -> bool:
    """The product's own answer, never a re-implementation of it."""
    try:
        from blastbox.host.runtime.gvisor_snapshot import GvisorSnapshotBackend
        from blastbox.host.runtime.gvisor_snapshot_runtime import _gvisor_config_from_env
    except Exception:  # noqa: BLE001
        return False
    try:
        return GvisorSnapshotBackend(_gvisor_config_from_env({})).available()
    except Exception:  # noqa: BLE001
        return False


def _fc_available() -> bool:
    try:
        from blastbox.host.runtime.firecracker import firecracker_available
    except Exception:  # noqa: BLE001
        return False
    return bool(firecracker_available())


class TestBothFactoriesPassItOn:
    """A knob nothing passes on is exactly the bug this fixes, so assert the wiring per tier.

    These drive the REAL factories, so the tier has to be available -- the factory returns
    None before constructing a manager otherwise. Gated on the product's OWN probe, and run on
    the fleet nodes where those are true (toolz2/toolz3); they skip on a dev box.

    The two factories BIND `SnapshotManager` differently, and that decides where a patch has
    to go:

      gVisor  imports it INSIDE the function -> patch the source module (fc_snapshot)
      FC      imports it at MODULE level     -> patch fc_snapshot_runtime's own name

    Patching only one silently patches nothing for the other, and the test then "passes"
    without ever reaching the assertion it exists for -- which is exactly what happened on the
    first run against toolz3. Each test patches the name its factory will actually resolve,
    and `_recorder` refuses to run if it patched nothing.
    """

    @staticmethod
    def _recorder(monkeypatch, *modules):
        """Record what each factory hands SnapshotManager, patching every binding given."""
        seen: list[dict] = []

        class _Mgr:
            def __init__(self, base_dir, backend, **kw):
                seen.append(kw)

            def __getattr__(self, name):
                return lambda *a, **k: None

        patched = 0
        for mod in modules:
            if hasattr(mod, "SnapshotManager"):
                monkeypatch.setattr(mod, "SnapshotManager", _Mgr)
                patched += 1
        assert patched, "no SnapshotManager binding was patched; the test would prove nothing"
        return seen

    @pytest.mark.skipif(not _gvisor_cr_available(),
                        reason="needs runsc with checkpoint/restore (run on toolz2/toolz3)")
    def test_the_gvisor_factory_passes_the_budget(self, monkeypatch, tmp_path):
        from blastbox.host.runtime import gvisor_snapshot_runtime as gr

        from blastbox.host.runtime import fc_snapshot

        seen = self._recorder(monkeypatch, fc_snapshot, gr)   # gVisor resolves it lazily
        monkeypatch.setenv(READY_ENV, "450")
        monkeypatch.setenv("BLASTBOX_GVISOR_ROOTFS", str(tmp_path))
        # Away from /var/lib/blastbox: this test is about the kwargs the factory passes, and
        # must not need write access to the fleet's real state dir to find out.
        monkeypatch.setenv("BLASTBOX_GVISOR_ROOT", str(tmp_path / "root"))
        monkeypatch.setattr(gr, "GvisorSnapshotSlotRuntime", lambda *a, **k: object())

        gr.select_gvisor_snapshot_runtime(require_available=False)

        assert seen, "the factory never constructed a SnapshotManager"
        assert seen[0].get("ready_timeout_s") == 450.0, (
            f"the gVisor factory dropped the readiness budget: {seen[0]}"
        )

    @pytest.mark.skipif(not _fc_available(),
                        reason="needs firecracker + /dev/kvm (run on toolz2/toolz3)")
    def test_the_fc_factory_passes_the_budget(self, monkeypatch, tmp_path):
        from blastbox.host.runtime import fc_snapshot_runtime as fr

        seen = self._recorder(monkeypatch, fr)   # FC bound it at import time
        monkeypatch.setenv(READY_ENV, "615")
        monkeypatch.setattr(fr, "SnapshotSlotRuntime", lambda *a, **k: object(), raising=False)

        fr.select_snapshot_runtime(require_available=False)

        assert seen, "the factory never constructed a SnapshotManager"
        assert seen[0].get("ready_timeout_s") == 615.0, (
            f"the FC factory dropped the readiness budget: {seen[0]}"
        )
