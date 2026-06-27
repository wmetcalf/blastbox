"""Validation-gated golden rotation + retention for libvirt VM-worker engines.

A VM-worker engine boots its workers off a "golden" qcow2 (see ``libvirt_vm``). That golden has
time-sensitive state (trust stores, caches, agents) that needs periodic re-baking, and a bad bake
must never silently ship. This is the generic, engine-agnostic half of that lifecycle:

  validate_golden()  boot a throwaway worker off a candidate qcow2, run an engine CHECK, reap —
                     the gate (e.g. "a known-good sample still validates correctly").
  rotate()           back up the live golden (keep the last N), then promote a candidate into place.
  promote_if_valid() the fail-safe: rotate ONLY if the candidate passes the gate; else keep current.

The engine supplies what's engine-specific — how to build a runtime for a given qcow2
(``runtime_factory``) and what "healthy" means (``check``) — plus how it builds the candidate (its
own bake/provision steps). This module owns the boot-gate-reap + backup-promote-prune orchestration,
so any libvirt-golden engine gets fail-safe rotation with rollback backups for free.
"""
from __future__ import annotations

import logging
import subprocess
from collections.abc import Callable
from pathlib import Path

logger = logging.getLogger(__name__)


def validate_golden(qcow2: str, *, runtime_factory: Callable[[str], object],
                    check: Callable[[object], bool], timeout_s: float = 240.0) -> bool:
    """Boot a throwaway worker off ``qcow2`` and return ``check(slot)`` — the gate. False if the
    worker won't boot/become ready or the check raises/fails (a broken/regressed golden is rejected).

    ``runtime_factory(qcow2)`` returns a LibvirtVmRuntime booting off that qcow2 (typically
    ``VmWorkerSpec(image=VmImageSpec(golden=qcow2)).runtime()``). ``check(slot)`` is the engine's
    health assertion against the ready worker (e.g. validate a benign sample == Valid)."""
    try:
        # The factory call is INSIDE the gate's try: a malformed candidate path/config that makes
        # runtime_factory() itself raise is a failed gate (→ promote_if_valid returns False + runs
        # on_reject), not an uncaught crash. Fail closed consistently.
        rt = runtime_factory(qcow2)
        slot = rt.spawn_ready(timeout_s=timeout_s)  # type: ignore[attr-defined]
    except Exception as exc:  # noqa: BLE001 — any boot/factory failure = gate fail
        logger.error("golden gate: candidate %s did not boot a healthy worker: %s", qcow2, exc)
        return False
    try:
        ok = bool(check(slot))
        logger.info("golden gate: candidate %s -> %s", qcow2, "PASS" if ok else "FAIL")
        return ok
    except Exception:  # noqa: BLE001 — a raising check is a fail, not a crash
        logger.warning("golden gate: check raised for %s", qcow2, exc_info=True)
        return False
    finally:
        rt.reap(slot)  # type: ignore[attr-defined]


def rotate(candidate: str, *, live_disk: str, backup_dir: str, keep_n: int = 5,
           live_shm: str | None = None, ts: str, sudo: bool = True,
           runner: Callable = subprocess.run) -> None:
    """Back up the current live golden (keep the last ``keep_n``), then promote ``candidate`` into
    place. ``live_disk`` is the persistent golden; ``live_shm`` an optional RAM-backed mirror that
    workers actually boot from. ``ts`` (a timestamp string) names the backup — passed in so the op
    is deterministic/testable. All writes go through ``sudo`` (libvirt image dirs are root-owned)."""
    pfx = ["sudo"] if sudo else []

    def _checked(argv: list[str], what: str) -> None:
        # A failed cp/mv (missing candidate, no perms, disk full) must ABORT the rotation, not press
        # on — else promote_if_valid() reports success while the live golden is stale, or a partial
        # `.new` from a half-finished cp gets mv'd over the live disk. Raise so the caller sees it.
        cp = runner([*pfx, *argv], capture_output=True, text=True)
        if getattr(cp, "returncode", 0) != 0:
            raise RuntimeError(f"golden rotate: {what} failed ({' '.join(argv)}): "
                               f"{getattr(cp, 'stderr', '') or ''}".strip())

    runner([*pfx, "mkdir", "-p", backup_dir], capture_output=True, text=True)
    runner([*pfx, "chmod", "755", backup_dir], capture_output=True, text=True)
    # Existence check via the SAME privileged runner: libvirt image dirs are often root-only, so an
    # unprivileged Path.exists() would report False and silently SKIP the backup, overwriting the live
    # golden with no rollback copy. `test -e` under sudo sees what the cp/mv below actually see.
    if runner([*pfx, "test", "-e", live_disk], capture_output=True, text=True).returncode == 0:
        bak = f"{backup_dir}/golden-base.{ts}.qcow2"
        logger.info("backing up current golden -> %s", bak)
        _checked(["cp", "--reflink=auto", live_disk, bak], "backup")
    logger.info("promoting candidate -> %s%s", live_disk, f" (+ {live_shm})" if live_shm else "")
    dests = [live_disk] + ([live_shm] if live_shm else [])
    # STAGE every target first (cp to <dest>.new). If staging the RAM mirror fails we haven't yet
    # moved anything over the live disk, so a failure here leaves both at the old version (all-or-
    # nothing) instead of advancing the disk golden while the boot mirror stays stale.
    for dest in dests:
        _checked(["cp", "--reflink=auto", candidate, dest + ".new"], "stage candidate")
    # Only once ALL targets are staged, SWAP them into place (rename is ~atomic; the gap between the
    # two renames is a single syscall apart, far tighter than a full cp between them).
    for dest in dests:
        _checked(["mv", dest + ".new", dest], "promote")
    runner([*pfx, "chmod", "644", live_disk, *([live_shm] if live_shm else [])], capture_output=True, text=True)
    prune_backups(backup_dir, keep_n, sudo=sudo, runner=runner)


def prune_backups(backup_dir: str, keep_n: int, *, sudo: bool = True,
                  runner: Callable = subprocess.run) -> None:
    """Delete all but the newest ``keep_n`` ``golden-base.*.qcow2`` backups (lexical sort == temporal
    for the ``%Y%m%d-%H%M%S`` names). ``keep_n <= 0`` keeps everything."""
    if keep_n <= 0:
        return
    baks = sorted(Path(backup_dir).glob("golden-base.*.qcow2"))
    pfx = ["sudo"] if sudo else []
    for b in baks[:-keep_n]:
        logger.info("pruning old golden backup %s", b.name)
        runner([*pfx, "rm", "-f", str(b)], capture_output=True, text=True)


def promote_if_valid(candidate: str, *, runtime_factory: Callable[[str], object],
                     check: Callable[[object], bool], live_disk: str, backup_dir: str, ts: str,
                     keep_n: int = 5, live_shm: str | None = None, sudo: bool = True,
                     timeout_s: float = 240.0, runner: Callable = subprocess.run,
                     on_reject: Callable[[str], None] | None = None) -> bool:
    """The fail-safe: gate ``candidate`` (``validate_golden``); rotate it into place ONLY if it
    passes, else keep the current golden and call ``on_reject`` (e.g. delete the candidate + alert).
    Returns whether the candidate was promoted."""
    if not validate_golden(candidate, runtime_factory=runtime_factory, check=check, timeout_s=timeout_s):
        logger.error("golden REJECTED: candidate %s failed the gate; keeping current golden", candidate)
        if on_reject is not None:
            on_reject(candidate)
        return False
    rotate(candidate, live_disk=live_disk, backup_dir=backup_dir, keep_n=keep_n,
           live_shm=live_shm, ts=ts, sudo=sudo, runner=runner)
    logger.info("golden PROMOTED: %s -> %s (%d backups kept)", candidate, live_disk, keep_n)
    return True
