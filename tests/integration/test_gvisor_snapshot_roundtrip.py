"""Gated end-to-end integration test: gVisor C/R warm-tier round-trip.

Proven manually on toolz2 (runsc 20250301.0 or later); this test documents that
proof as a runnable gate. It is NOT expected to execute on a dev host without runsc.

Design spec: docs/specs/2026-06-05-gvisor-cr-snapshot-design.md

Required environment variables to run (all have defaults where sensible):

    BLASTBOX_GVISOR_ROOTFS      Path to an exported OCI rootfs dir for the warm
                                 container (clippyshot or Tika worker image rootfs).
                                 REQUIRED — test is skipped if unset or non-existent.

    BLASTBOX_GVISOR_RUNSC       Path to the runsc binary (default: "runsc").
    BLASTBOX_GVISOR_WARM_ARGV   JSON-encoded argv for the warm entrypoint inside the
                                 container (default: ["worker", "warm"]).
    BLASTBOX_GVISOR_LD_PRELOAD  Optional path to an LD_PRELOAD .so to inject
                                 (default: unset).
    BLASTBOX_SNAPSHOT_SETTLE_S  Post-restore settle window in seconds before the
                                 slot is considered ready (default: "1.0").

Example invocation on toolz2:
    BLASTBOX_GVISOR_ROOTFS=/var/lib/blastbox/gvisor-rootfs \\
    BLASTBOX_GVISOR_RUNSC=/usr/local/bin/runsc \\
    pytest tests/integration/test_gvisor_snapshot_roundtrip.py -v
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Host capability helpers (evaluated at collection time so skipif works)
# ---------------------------------------------------------------------------


def _runsc_cr_available() -> bool:
    """Return True iff the configured runsc binary advertises checkpoint/restore.

    Honors ``BLASTBOX_GVISOR_RUNSC`` (the same override the test uses to build the
    GvisorConfig): an absolute path is probed as-is, a bare name is resolved on PATH —
    so setting an absolute path no longer spuriously skips the test."""
    runsc = os.environ.get("BLASTBOX_GVISOR_RUNSC", "runsc").strip() or "runsc"
    if os.sep in runsc:
        if not Path(runsc).is_file():
            return False
    elif not shutil.which(runsc):
        return False
    try:
        result = subprocess.run(
            [runsc, "help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout + result.stderr
        return "checkpoint" in output and "restore" in output
    except Exception:  # noqa: BLE001
        return False


def _force_delete_all(cfg, *, timeout_s: float = 20.0) -> tuple[list[str], list[str]]:
    """Force-delete containers under ``cfg.root``. Returns (deleted, unconfirmed).

    Only this test's OWN root -- `cfg.root` is under tmp_path and unique per
    run -- so it can never touch the fleet's containers, which live under the
    dispatcher's own root.

    Needed because failing on a timeout only stops WAITING for the build: the
    thread keeps running, its child `runsc` keeps going, and a stalled build can
    leave a sandbox on the host and keep writing under tmp_path after the test
    has gone.

    A container counts as deleted only when `runsc delete` actually SUCCEEDS.
    Appending every id regardless of exit status is how a cleanup that silently
    failed would still report "force-deleted 3 containers" while three sandboxes
    kept running -- the swallow-everything mistake `_best_effort_delete` was
    fixed for upstream.
    """
    import json as _json
    import subprocess as _sp

    base = [cfg.runsc_bin, "-root", str(cfg.root)]
    try:
        listed = _sp.run([*base, "list", "-format=json"], capture_output=True,
                         text=True, timeout=timeout_s, check=False)
        # `runsc list -format=json` prints literal `null` when nothing is
        # registered, which parses to None -- iterating that raised TypeError
        # and turned the cleanup into a second failure. Measured on toolz3.
        containers = _json.loads(listed.stdout or "[]") or []
        if not isinstance(containers, list):
            return [], []
    except Exception:  # noqa: BLE001 - cleanup is best effort by definition
        return [], []
    deleted: list[str] = []
    unconfirmed: list[str] = []
    for entry in containers:
        cid = entry.get("id") if isinstance(entry, dict) else None
        if not cid:
            continue
        try:
            _sp.run([*base, "kill", cid, "KILL"], capture_output=True,
                    timeout=timeout_s, check=False)
            gone = _sp.run([*base, "delete", "-force", cid], capture_output=True,
                           timeout=timeout_s, check=False)
        except Exception:  # noqa: BLE001
            unconfirmed.append(cid)
            continue
        (deleted if gone.returncode == 0 else unconfirmed).append(cid)
    return deleted, unconfirmed


def _warm_rootfs() -> str | None:
    """Return the BLASTBOX_GVISOR_ROOTFS path if set and the directory exists."""
    val = os.environ.get("BLASTBOX_GVISOR_ROOTFS", "").strip()
    if not val:
        return None
    if Path(val).is_dir():
        return val
    return None


def _fixture_doc() -> Path | None:
    """Return a path to any small fixture file under tests/fixtures, or None."""
    here = Path(__file__).parent.parent  # tests/
    candidates = list(here.glob("fixtures/**/*.docx")) + list(here.glob("fixtures/**/*.txt"))
    if candidates:
        return candidates[0]
    # fallback: any non-Python file in the fixtures tree
    all_files = [p for p in here.glob("fixtures/**/*") if p.is_file() and p.suffix not in (".py", ".pyc")]
    return all_files[0] if all_files else None


# ---------------------------------------------------------------------------
# pytest module-level marker
# ---------------------------------------------------------------------------

pytestmark = pytest.mark.integration

# ---------------------------------------------------------------------------
# E2E round-trip
# ---------------------------------------------------------------------------

_RUNSC_SKIP_REASON = (
    "needs runsc binary with checkpoint/restore support "
    "(run on a runsc-C/R host such as toolz2 with BLASTBOX_GVISOR_ROOTFS set)"
)


@pytest.mark.skipif(not _runsc_cr_available(), reason=_RUNSC_SKIP_REASON)
def test_gvisor_snapshot_roundtrip(tmp_path: Path) -> None:
    """Full warm-tier round-trip through gVisor C/R.

    spawn() → wait ready → stage input → signal_go → wait_for_done → assert outputs.
    """
    rootfs = _warm_rootfs()
    if rootfs is None:
        pytest.skip(
            "BLASTBOX_GVISOR_ROOTFS is not set or does not point to an existing directory; "
            "set it to an exported clippyshot/Tika OCI rootfs dir to run this test"
        )

    fixture = _fixture_doc()
    if fixture is None:
        pytest.skip(
            "no fixture document found under tests/fixtures/; "
            "populate tests/fixtures/ with at least one .docx or .txt file"
        )

    import dataclasses

    from blastbox.host.runtime.fc_snapshot import SnapshotManager
    from blastbox.host.runtime.gvisor_snapshot import GvisorSnapshotBackend
    from blastbox.host.runtime.gvisor_snapshot_runtime import (
        GvisorSnapshotSlotRuntime,
        _gvisor_config_from_env,
    )
    from blastbox.worker.warm import HostWarmControl, WarmJobSpec

    settle_s = float(os.environ.get("BLASTBOX_SNAPSHOT_SETTLE_S", "1.0"))

    # Build the config through the REAL env-driven path so EVERY BLASTBOX_GVISOR_* knob
    # (warm_argv, ld_preload, extra_env, rlimits, ...) is exercised end-to-end. A hand-rolled
    # mirror silently drops new knobs — it did exactly that: BLASTBOX_GVISOR_EXTRA_ENV (needed to
    # hand the clippyshot worker CLIPPYSHOT_SANDBOX=container + CLIPPYSHOT_WARN_ON_INSECURE=1 for
    # the runsc inner-sandbox, which gVisor's virtualized /proc/self/status hides) was missed.
    # Override only image_rootfs (the exported test rootfs) + root (BLASTBOX_GVISOR_ROOT defaults
    # to a shared /var/lib path) for per-test isolation.
    cfg = dataclasses.replace(
        _gvisor_config_from_env(os.environ),
        image_rootfs=Path(rootfs),
        root=tmp_path / "root",
    )
    backend = GvisorSnapshotBackend(cfg)
    mgr = SnapshotManager(tmp_path / "snap", backend)
    rt = GvisorSnapshotSlotRuntime(mgr, settle_s=settle_s)

    # BUILD the warm snapshot first. `spawn()` deliberately refuses to build
    # inline -- a synchronous build there blocks the pool's only maintenance
    # thread for a full boot plus readiness timeout (upstream PR #82) -- so the
    # pool kicks `ensure_build_started()` on tick and spawns once it is built.
    # Without this the test could never pass on a host that has no snapshot yet,
    # which is every host: it died in `spawn()` with
    # `SnapshotBuildInvalidated: warm snapshot is not built`. That went unnoticed
    # because the test is gated behind BLASTBOX_GVISOR_ROOTFS and had never run.
    #
    # Built synchronously here on purpose: this is a test thread, not the
    # maintenance thread the guard protects, and a blocking build gives a clear
    # failure instead of a timeout if the base cannot boot at all.
    # BOUNDED while it runs, not measured afterwards. The backend's subprocess
    # calls have no timeout of their own, so a `runsc run` or checkpoint that
    # stalls on a broken host never returns and an elapsed-time assertion after
    # the call is never reached. A DAEMON thread makes the join timeout the
    # bound that actually holds: a non-daemon one (or a ThreadPoolExecutor,
    # which joins its workers at interpreter exit) would hang pytest instead.
    build_s = float(os.environ.get("BLASTBOX_SNAPSHOT_BUILD_S", "180"))
    outcome: list[tuple[str, object]] = []

    def _build() -> None:
        try:
            outcome.append(("ok", mgr.build()))
        except BaseException as exc:  # noqa: BLE001 - reported by the caller below
            outcome.append(("error", exc))

    builder = threading.Thread(target=_build, daemon=True, name="warm-snapshot-build")
    builder.start()
    builder.join(timeout=build_s)
    if builder.is_alive():
        # Do not just stop waiting: tear down whatever the stalled build left
        # under THIS test's private root, or a sandbox outlives the run and
        # keeps writing into tmp_path after it is gone.
        deleted, unconfirmed = _force_delete_all(cfg)
        detail = f"force-deleted {deleted}" if deleted else "nothing to clean up"
        if unconfirmed:
            # Loudly: these may still be running, and on a fleet node that is
            # the next run's problem.
            detail += f"; COULD NOT confirm deletion of {unconfirmed} -- may still be live"
        pytest.fail(
            f"warm snapshot build did not finish within {build_s}s "
            f"(set BLASTBOX_SNAPSHOT_BUILD_S to allow longer); {detail}"
        )
    kind, payload = outcome[0]
    if kind == "error":
        pytest.fail(f"warm snapshot build failed: {payload}")

    slot = rt.spawn()
    slot_reaped = False
    try:
        # Wait up to 30 s for the restored container to be ready.
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            if rt.is_ready(slot):
                break
            time.sleep(0.25)
        assert rt.is_ready(slot), "gVisor restored container was not ready within 30 s"

        # Stage the fixture document into the slot's input dir.
        staged = rt.stage_warm_input(slot, fixture)
        assert staged.exists(), f"stage_warm_input did not copy fixture to {staged}"

        # Signal go and wait for done.
        ctrl: HostWarmControl = rt.host_warm_control(slot)  # type: ignore[assignment]
        ctrl.signal_go(WarmJobSpec(input_path=staged, output_dir=slot.output_dir))
        status = ctrl.wait_for_done(timeout_s=60.0)

        assert status == "ok", f"warm worker exited with status={status!r} (expected 'ok')"

        # At least one output file must be present.
        output_files = list(slot.output_dir.iterdir())
        assert output_files, (
            f"slot.output_dir ({slot.output_dir}) is empty after a successful warm job"
        )

        # The lifecycle status above ("ok" from signal_done) only proves the worker
        # COMPLETED — not that the conversion succeeded. Validate the envelope status in
        # metadata.json so a failed conversion (status="engine_error") that still wrote a
        # metadata.json can't pass this test green.
        meta_path = slot.output_dir / "metadata.json"
        assert meta_path.exists(), f"metadata.json missing from {slot.output_dir}"
        envelope = json.loads(meta_path.read_text())
        assert envelope.get("status") == "ok", (
            f"conversion envelope status={envelope.get('status')!r} (expected 'ok')"
        )

    finally:
        rt.reap(slot)
        slot_reaped = True

    assert slot_reaped  # reap() must not raise
