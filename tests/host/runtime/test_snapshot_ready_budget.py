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


class TestBothFactoriesPassItOn:
    """A knob nothing passes on is exactly the bug this fixes, so assert the wiring per tier.

    These drive the REAL factories and run EVERYWHERE. They were first written gated on the
    product's availability probe, which meant they skipped on every CI host and dev box -- so
    deleting either factory's `ready_timeout_s` argument left the suite green, which is the
    one thing a regression test for "a caller forgot to pass it" must never allow (codex,
    #151). Nothing here launches a sandbox, so the availability GATE is faked while the code
    under test -- the construction call -- is entirely real. That is the opposite of a probe
    that re-implements what it gates: the fake stands in for the host, not for the product.

    The two factories BIND `SnapshotManager` differently, and that decides where a patch has
    to go:

      gVisor  imports it INSIDE the function -> patch the source module (fc_snapshot)
      FC      imports it at MODULE level     -> patch fc_snapshot_runtime's own name

    Patching only one silently patches nothing for the other, and the test then "passes"
    without ever reaching its assertion -- which is exactly what happened on the first run
    against toolz3. `_recorder` refuses to run if it patched nothing.
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

    def test_the_gvisor_factory_passes_the_budget(self, monkeypatch, tmp_path):
        from blastbox.host.runtime import gvisor_snapshot_runtime as gr
        from blastbox.host.runtime import fc_snapshot

        seen = self._recorder(monkeypatch, fc_snapshot, gr)   # gVisor resolves it lazily
        monkeypatch.setenv(READY_ENV, "450")
        monkeypatch.setenv("BLASTBOX_GVISOR_ROOTFS", str(tmp_path))
        # Away from /var/lib/blastbox: this is about the kwargs the factory passes, and must
        # not need write access to the fleet's real state dir to find out.
        monkeypatch.setenv("BLASTBOX_GVISOR_ROOT", str(tmp_path / "root"))

        class _Backend:
            def __init__(self, cfg, **kw):
                pass

            def available(self):
                return True       # stands in for the HOST, not for the product

        # Source module again: the gVisor factory imports the backend inside the function.
        from blastbox.host.runtime import gvisor_snapshot as gs

        monkeypatch.setattr(gs, "GvisorSnapshotBackend", _Backend)
        monkeypatch.setattr(gr, "GvisorSnapshotBackend", _Backend, raising=False)
        monkeypatch.setattr(gr, "GvisorSnapshotSlotRuntime", lambda *a, **k: object(),
                            raising=False)

        gr.select_gvisor_snapshot_runtime(require_available=False)

        assert seen, "the factory never constructed a SnapshotManager"
        assert seen[0].get("ready_timeout_s") == 450.0, (
            f"the gVisor factory dropped the readiness budget: {seen[0]}"
        )

    def test_the_fc_factory_passes_the_budget(self, monkeypatch, tmp_path):
        from blastbox.host.runtime import fc_snapshot_runtime as fr

        seen = self._recorder(monkeypatch, fr)   # FC bound it at import time
        monkeypatch.setenv(READY_ENV, "615")
        # Stand-in HOST assets so FCConfig.from_env resolves; the factory bails before the
        # construction otherwise. Their contents are never read -- only the construction call
        # is under test.
        for name, var in (("vmlinux", "BLASTBOX_FC_KERNEL"), ("rootfs.ext4", "BLASTBOX_FC_ROOTFS"),
                          ("firecracker", "BLASTBOX_FC_BIN")):
            f = tmp_path / name
            f.write_bytes(b"")
            f.chmod(0o755)
            monkeypatch.setenv(var, str(f))
        monkeypatch.setenv("BLASTBOX_FC_JOBS_DIR", str(tmp_path / "jobs"))
        # At its SOURCE module: the factory imports this name inside the function, exactly
        # like SnapshotManager -- patching fr's namespace patches nothing and the REAL probe
        # runs (it rejected the empty stand-in binary as "version unknown").
        from blastbox.host.runtime import firecracker as fc_mod

        monkeypatch.setattr(fc_mod, "firecracker_available", lambda cfg=None: True)
        monkeypatch.setattr(fr, "SnapshotSlotRuntime", lambda *a, **k: object(), raising=False)

        fr.select_snapshot_runtime(require_available=True)

        assert seen, "the factory never constructed a SnapshotManager"
        assert seen[0].get("ready_timeout_s") == 615.0, (
            f"the FC factory dropped the readiness budget: {seen[0]}"
        )
