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
    BLASTBOX_SNAPSHOT_BUILD_S   Seconds to allow for the warm snapshot BUILD
                                (default 180). The only supported way to give a
                                slower checkpoint host more room; without it the
                                failure arrives three minutes in.
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

    EVERY path that did not actually enumerate the host reports unconfirmed. A
    failed listing, a listing that errored or timed out, one that is not JSON,
    and one whose shape is not a container array are all indistinguishable from
    "no containers" to a caller that only looks at the list -- and reporting
    `nothing to clean up` while sandboxes are live is the same lie as reporting
    an unchecked delete as a success. Only JSON `null`, which is what runsc
    prints for an empty host, means empty.
    """
    import json as _json
    import subprocess as _sp

    base = [cfg.runsc_bin, "-root", str(cfg.root)]
    try:
        listed = _sp.run([*base, "list", "-format=json"], capture_output=True,
                         text=True, timeout=timeout_s, check=False)
    except Exception as exc:  # noqa: BLE001 - timeout, missing binary, ...
        return [], [f"<listing errored: {type(exc).__name__}>"]
    if listed.returncode != 0:
        return [], [f"<listing failed: rc={listed.returncode}>"]
    raw = (listed.stdout or "").strip()
    if not raw:
        # Exit 0 with NO document is not an empty host -- it is a listing that
        # told us nothing. `null` is what an empty host prints.
        return [], ["<listing produced no output>"]
    try:
        parsed = _json.loads(raw)
    except Exception as exc:  # noqa: BLE001
        return [], [f"<listing was not JSON: {type(exc).__name__}>"]
    if parsed is None:
        containers: list = []          # runsc prints `null` for an empty host
    elif isinstance(parsed, list):
        containers = parsed
    else:
        # `{}`, `false`, `0`, `""` are falsy but are NOT an empty host; an
        # `or []` fallback would have accepted every one of them as clean.
        return [], ["<listing was not a container array>"]

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


def _sweep_until_clean(
    cfg, is_live, *, attempts: int = 3, settle_s: float = 1.0
) -> tuple[list[str], list[str], bool]:
    """Clean up after a producer that cannot be cancelled.

    Returns (deleted, unconfirmed, confirmed_clean).

    ``confirmed_clean`` is the only claim worth making: a sweep found the
    producer already stopped AND enumerated the host successfully AND there was
    nothing there. Anything short of that -- the producer still running, a
    listing that failed, a delete that could not be confirmed -- leaves the host
    dirty as far as this test can tell.

    Accumulating "was it ever live" instead was wrong in both directions: a
    producer live during an early sweep but stopped before a later CLEAN one had
    the host reported dirty though it was confirmed empty, while a producer that
    registered a container after the last listing and then exited read clean
    because liveness was only checked at the end.

    An id unconfirmed on one pass and deleted on a later one is reconciled, and
    an id seen by two sweeps is reported once.
    """
    deleted: list[str] = []
    unconfirmed: list[str] = []
    confirmed_clean = False
    for _ in range(attempts):
        live_now = bool(is_live())
        found, unsure = _force_delete_all(cfg)
        deleted.extend(f for f in found if f not in deleted)
        unconfirmed = [u for u in unconfirmed if u not in found]
        unconfirmed.extend(u for u in unsure if u not in deleted and u not in unconfirmed)
        if not live_now and not found and not unsure:
            # Nothing running to create more, and an enumeration that actually
            # answered. Only here can the host be called clean -- and a sweep
            # whose listing or delete failed must NOT break, or a transient
            # failure burns the remaining attempts.
            # A successful enumeration finding NOTHING supersedes earlier
            # doubt: a listing that failed two sweeps ago, and a delete that
            # could not be confirmed, are both answered by an empty host.
            # Without this a single transient failure taints the report forever.
            confirmed_clean = True
            unconfirmed = []
            break
        time.sleep(settle_s)
    return deleted, unconfirmed, confirmed_clean


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

    from blastbox.host.runtime.env_knobs import positive_float_env
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
    # THE KNOB THIS TEST MOTIVATED. Constructing the manager bare kept the hard-coded
    # 120s readiness budget, so BLASTBOX_SNAPSHOT_READY_S had no effect on the one
    # scenario it exists for -- a base that is slow but healthy (codex, #151).
    mgr = SnapshotManager(
        tmp_path / "snap", backend,
        ready_timeout_s=positive_float_env(os.environ, "BLASTBOX_SNAPSHOT_READY_S", 120.0),
    )
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
        # Sweep more than once, and record whether the producer was live DURING
        # a sweep -- see `_sweep_until_clean`.
        deleted, unconfirmed, confirmed_clean = _sweep_until_clean(
            cfg, builder.is_alive
        )
        detail = f"force-deleted {deleted}" if deleted else "found nothing to delete"
        if unconfirmed:
            detail += f"; COULD NOT confirm {unconfirmed} -- may still be live"
        if not confirmed_clean:
            detail += (
                "; the host was NOT confirmed clean -- the build thread cannot be "
                "cancelled and may have registered a container after the last "
                "listing, so treat this host as dirty"
            )
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
