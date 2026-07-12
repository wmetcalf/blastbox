# blastbox networking — Phase 1 (policy/personality core) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the per-job network-**personality** policy layer — declare personalities,
default one per engine, allow a gated per-job override, and resolve the effective personality
fail-closed — with **no networking applied yet** (that is Plan 2).

**Architecture:** A new pure-Python module `netpolicy.py` (a `Personality` dataclass, an env
registry parser, and a `resolve_net_policy` function) plus four small config-plumbing
additions that mirror the existing `target_tier` / `ALLOW_TIER_ROUTING` pattern exactly:
`EngineSpec.net_policy` (per-engine default), `Job.net_policy` (per-job request), the SQL
column, and the ingress gate. Everything is unit-testable in isolation.

**Tech Stack:** Python 3.12, dataclasses, pytest. No new runtime deps. Repo:
`/home/coz/Downloads/blastbox`, venv at `.venv` (`.venv/bin/pytest`).

> **Spec:** `docs/superpowers/specs/2026-06-16-blastbox-networking-design.md` (§5.3 registry,
> §6 policy model). This plan implements §6 + the registry/resolver half of §5.3.

> **Branch:** before Task 1, create a feature branch off the current work:
> `git checkout -b feat/netpolicy-phase1` (the executing skill may instead use a worktree).

---

## File structure

| file | responsibility | this plan |
|---|---|---|
| `src/blastbox/host/netpolicy.py` | `Personality`, exit-driver validation, registry parse, resolver | **create** |
| `tests/host/test_netpolicy.py` | unit tests for the module | **create** |
| `src/blastbox/host/dispatch.py` | `EngineSpec` dataclass | modify (add 1 field) |
| `src/blastbox/host/cli.py` | `_parse_engine_specs` env→EngineSpec | modify (parse 1 knob) |
| `src/blastbox/host/jobs/base.py` | `Job` dataclass + `from_dict` | modify (add 1 field) |
| `src/blastbox/host/jobs/sql_store.py` | columns list + CREATE TABLE | modify (add 1 column) |
| `src/blastbox/host/ingress/app.py` | submit handler | modify (gated form field) |
| `tests/host/test_cli.py`, `tests/host/jobs/test_base.py`, `tests/host/ingress/test_app.py` | extend existing | modify |

---

### Task 1: `Personality` dataclass + exit-driver validation + the `none` builtin

**Files:**
- Create: `src/blastbox/host/netpolicy.py`
- Test: `tests/host/test_netpolicy.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/host/test_netpolicy.py
from blastbox.host.netpolicy import (
    NONE,
    VALID_EXIT_DRIVERS,
    Personality,
)


def test_none_builtin_is_no_egress():
    assert NONE.name == "none"
    assert NONE.exit_driver == "none"
    assert NONE.inspect is False


def test_valid_exit_drivers_set():
    # the personalities the design names (spec §3/§5.3)
    assert VALID_EXIT_DRIVERS == (
        "none", "drop", "direct", "inetsim", "socks", "wireguard", "openvpn",
    )


def test_personality_carries_opaque_config():
    p = Personality(name="p", exit_driver="socks", inspect=True, config={"endpoint": "h:1"})
    assert p.config["endpoint"] == "h:1"
    assert p.inspect is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/host/test_netpolicy.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'blastbox.host.netpolicy'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/blastbox/host/netpolicy.py
"""Network-personality policy core — declare, default, gate, resolve.

A *personality* is a named egress chain (spec §5.3). This module is PURE policy/config:
it parses operator-declared personalities, holds the per-engine default + per-job request,
and resolves the effective personality FAIL-CLOSED. It applies no networking — Plan 2 reads
the resolved Personality and wires the worker's network.
"""
from __future__ import annotations

import sys
from collections.abc import Mapping
from dataclasses import dataclass, field

# Exit drivers the design names (spec §3 two-tier, §5.3). `none` (default) and `drop` need no
# sidecar; `direct`/`inetsim` are ship-cheap; `socks` (tor/BrightData) + `wireguard`/`openvpn`
# (BYO creds) come with config. Plan 1 only VALIDATES these; Plan 2 implements each.
VALID_EXIT_DRIVERS = (
    "none", "drop", "direct", "inetsim", "socks", "wireguard", "openvpn",
)


@dataclass
class Personality:
    """A named egress personality. ``config`` is opaque exit-specific data (socks endpoint,
    wireguard conf ref, dns, …) consumed by Plan 2 — Plan 1 keeps it verbatim."""

    name: str
    exit_driver: str
    inspect: bool = False
    config: dict[str, str] = field(default_factory=dict)


# The always-present safe default: no egress. Resolution falls back here fail-closed.
NONE = Personality(name="none", exit_driver="none")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/host/test_netpolicy.py -q`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add src/blastbox/host/netpolicy.py tests/host/test_netpolicy.py
git commit -m "feat(netpolicy): Personality dataclass + exit-driver set + none builtin"
```

---

### Task 2: `parse_personalities` — operator registry from env

**Files:**
- Modify: `src/blastbox/host/netpolicy.py`
- Test: `tests/host/test_netpolicy.py`

Operator declares each personality with `BLASTBOX_NETPOLICY_<NAME>='exit=<driver>[,inspect=true][,k=v...]'`.
`none` is always present. Malformed/unknown-driver declarations are warned-and-skipped (fail-closed — they never become available).

- [ ] **Step 1: Write the failing test**

```python
# add to tests/host/test_netpolicy.py
from blastbox.host.netpolicy import parse_personalities


def test_registry_always_has_none():
    reg = parse_personalities({})
    assert reg["none"].exit_driver == "none"


def test_parse_declares_personality_lowercased_name():
    reg = parse_personalities({"BLASTBOX_NETPOLICY_FAKENET": "exit=inetsim"})
    assert "fakenet" in reg
    assert reg["fakenet"].exit_driver == "inetsim"


def test_parse_inspect_flag_and_config():
    reg = parse_personalities(
        {"BLASTBOX_NETPOLICY_PIA": "exit=wireguard,inspect=true,conf=/run/pia.conf"}
    )
    p = reg["pia"]
    assert p.exit_driver == "wireguard"
    assert p.inspect is True
    assert p.config == {"conf": "/run/pia.conf"}


def test_parse_unknown_driver_skipped_failclosed(capsys):
    reg = parse_personalities({"BLASTBOX_NETPOLICY_BAD": "exit=teleport"})
    assert "bad" not in reg
    assert "teleport" in capsys.readouterr().err


def test_parse_missing_exit_skipped(capsys):
    reg = parse_personalities({"BLASTBOX_NETPOLICY_NOEXIT": "inspect=true"})
    assert "noexit" not in reg
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/host/test_netpolicy.py -q`
Expected: FAIL — `ImportError: cannot import name 'parse_personalities'`

- [ ] **Step 3: Write minimal implementation**

```python
# append to src/blastbox/host/netpolicy.py

_NETPOLICY_PREFIX = "BLASTBOX_NETPOLICY_"


def _parse_decl(name: str, raw: str) -> Personality | None:
    """Parse one ``exit=...,k=v,...`` declaration into a Personality, or None (warn) if
    malformed. Comma-separated KEY=VALUE (so values can't contain a comma — fine here)."""
    kv: dict[str, str] = {}
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        if "=" not in item:
            print(f"warning: ignoring malformed netpolicy {name!r} entry {item!r} "
                  "(expected KEY=VALUE)", file=sys.stderr)
            return None
        k, _, v = item.partition("=")
        kv[k.strip().lower()] = v.strip()

    exit_driver = kv.pop("exit", "")
    if exit_driver not in VALID_EXIT_DRIVERS:
        print(f"warning: ignoring netpolicy {name!r}: exit={exit_driver!r} not one of "
              f"{', '.join(VALID_EXIT_DRIVERS)}", file=sys.stderr)
        return None
    inspect = kv.pop("inspect", "").lower() in ("1", "true", "yes", "on")
    return Personality(name=name, exit_driver=exit_driver, inspect=inspect, config=kv)


def parse_personalities(env: Mapping[str, str]) -> dict[str, Personality]:
    """Build the personality registry from ``BLASTBOX_NETPOLICY_<NAME>`` env vars.

    ``none`` is always present (the fail-closed default). A declaration with an unknown
    exit-driver or missing ``exit`` is warned-and-skipped, so it never becomes selectable."""
    registry: dict[str, Personality] = {"none": NONE}
    for env_key, raw in env.items():
        if not env_key.startswith(_NETPOLICY_PREFIX):
            continue
        name = env_key[len(_NETPOLICY_PREFIX):].lower()
        if not name:
            continue
        p = _parse_decl(name, raw or "")
        if p is not None:
            registry[name] = p
    return registry
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/host/test_netpolicy.py -q`
Expected: PASS (8 passed)

- [ ] **Step 5: Commit**

```bash
git add src/blastbox/host/netpolicy.py tests/host/test_netpolicy.py
git commit -m "feat(netpolicy): parse BLASTBOX_NETPOLICY_<NAME> registry (fail-closed)"
```

---

### Task 3: `resolve_net_policy` — effective personality, fail-closed

**Files:**
- Modify: `src/blastbox/host/netpolicy.py`
- Test: `tests/host/test_netpolicy.py`

Resolution order (spec §6): per-job override (only if the gate is on **and** the name is in
the registry) → per-engine default → `none`.

- [ ] **Step 1: Write the failing test**

```python
# add to tests/host/test_netpolicy.py
from blastbox.host.netpolicy import resolve_net_policy


def _reg():
    return parse_personalities(
        {"BLASTBOX_NETPOLICY_FAKENET": "exit=inetsim",
         "BLASTBOX_NETPOLICY_DIRECT": "exit=direct"}
    )


def test_resolve_defaults_to_none_when_engine_default_unset():
    p = resolve_net_policy(job_net_policy=None, engine_default="none",
                           registry=_reg(), allow_override=False)
    assert p.name == "none"


def test_resolve_uses_engine_default():
    p = resolve_net_policy(job_net_policy=None, engine_default="fakenet",
                           registry=_reg(), allow_override=False)
    assert p.name == "fakenet"


def test_resolve_engine_default_unknown_failscloses_to_none():
    p = resolve_net_policy(job_net_policy=None, engine_default="bogus",
                           registry=_reg(), allow_override=False)
    assert p.name == "none"


def test_resolve_job_override_ignored_when_gate_off():
    p = resolve_net_policy(job_net_policy="direct", engine_default="fakenet",
                           registry=_reg(), allow_override=False)
    assert p.name == "fakenet"  # override ignored → engine default


def test_resolve_job_override_honored_when_gate_on_and_declared():
    p = resolve_net_policy(job_net_policy="direct", engine_default="fakenet",
                           registry=_reg(), allow_override=True)
    assert p.name == "direct"


def test_resolve_job_override_undeclared_failscloses_to_default():
    p = resolve_net_policy(job_net_policy="nope", engine_default="fakenet",
                           registry=_reg(), allow_override=True)
    assert p.name == "fakenet"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/host/test_netpolicy.py -q`
Expected: FAIL — `ImportError: cannot import name 'resolve_net_policy'`

- [ ] **Step 3: Write minimal implementation**

```python
# append to src/blastbox/host/netpolicy.py

def resolve_net_policy(
    *,
    job_net_policy: str | None,
    engine_default: str,
    registry: Mapping[str, Personality],
    allow_override: bool,
) -> Personality:
    """Resolve the effective personality (spec §6), FAIL-CLOSED to ``none``.

    Order: per-job override (only when ``allow_override`` AND the name is declared) →
    per-engine default (when declared) → ``none``. An unknown name at any step collapses to
    ``none`` rather than erroring, so a misconfig never grants unintended egress."""
    if allow_override and job_net_policy and job_net_policy in registry:
        return registry[job_net_policy]
    if engine_default in registry:
        return registry[engine_default]
    return registry.get("none", NONE)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/host/test_netpolicy.py -q`
Expected: PASS (14 passed)

- [ ] **Step 5: Commit**

```bash
git add src/blastbox/host/netpolicy.py tests/host/test_netpolicy.py
git commit -m "feat(netpolicy): resolve_net_policy (override-gated, fail-closed to none)"
```

---

### Task 4: `EngineSpec.net_policy` (per-engine default) + cli parse

**Files:**
- Modify: `src/blastbox/host/dispatch.py` (the `EngineSpec` dataclass, ends ~line 169 at `default_params`)
- Modify: `src/blastbox/host/cli.py` (`_parse_engine_specs`, the `EngineSpec(...)` build ~line 145)
- Test: `tests/host/test_cli.py`

- [ ] **Step 1: Write the failing test**

```python
# add to tests/host/test_cli.py
from blastbox.host.cli import _parse_engine_specs


def test_engine_net_policy_default_is_none():
    engines = _parse_engine_specs("redtusk=img:tag")
    assert engines["redtusk"].net_policy == "none"


def test_engine_net_policy_from_env(monkeypatch):
    monkeypatch.setenv("BLASTBOX_ENGINE_REDTUSK_NETPOLICY", "fakenet")
    engines = _parse_engine_specs("redtusk=img:tag")
    assert engines["redtusk"].net_policy == "fakenet"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/host/test_cli.py -k net_policy -q`
Expected: FAIL — `AttributeError: 'EngineSpec' object has no attribute 'net_policy'`

- [ ] **Step 3a: Add the field to `EngineSpec`** (`src/blastbox/host/dispatch.py`)

Find the end of the `EngineSpec` dataclass (the `default_params` field with its
`field(default_factory=dict)`). Immediately after it, add:

```python
    # Per-engine DEFAULT network personality (BLASTBOX_ENGINE_<NAME>_NETPOLICY). Ships "none"
    # (no egress). Resolved per job against the operator's personality registry, fail-closed
    # (see netpolicy.resolve_net_policy). Runtime-configurable like default_params: flip the
    # env + restart the dispatcher, no rebuild. Plan 1 only carries it; Plan 2 applies it.
    net_policy: str = "none"
```

- [ ] **Step 3b: Parse the knob in `_parse_engine_specs`** (`src/blastbox/host/cli.py`)

In the block that already computes `default_params` (just before `engines[name] = EngineSpec(...)`), add:

```python
            # Optional per-engine DEFAULT network personality (BLASTBOX_ENGINE_<NAME>_NETPOLICY).
            # A name from the operator's BLASTBOX_NETPOLICY_<NAME> registry; "none" (default)
            # = no egress. Validated/resolved fail-closed at dispatch (netpolicy.resolve).
            net_policy = (
                os.environ.get(f"BLASTBOX_ENGINE_{env_name}_NETPOLICY") or "none"
            ).strip().lower()
```

Then add `net_policy=net_policy,` to the `EngineSpec(...)` call:

```python
            engines[name] = EngineSpec(
                name=name, image=image, worker_argv=[],
                allowed_param_keys=allowed, reserved_param_keys=reserved,
                default_params=default_params, net_policy=net_policy,
            )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/host/test_cli.py -k net_policy -q`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add src/blastbox/host/dispatch.py src/blastbox/host/cli.py tests/host/test_cli.py
git commit -m "feat(netpolicy): EngineSpec.net_policy default + BLASTBOX_ENGINE_<NAME>_NETPOLICY"
```

---

### Task 5: `Job.net_policy` (per-job request) + `from_dict`

**Files:**
- Modify: `src/blastbox/host/jobs/base.py` (the `Job` dataclass `target_tier` field ~line 55, and `from_dict` ~line 117)
- Test: `tests/host/jobs/test_base.py`

- [ ] **Step 1: Write the failing test**

```python
# add to tests/host/jobs/test_base.py
from blastbox.host.jobs.base import Job


def test_job_net_policy_defaults_none():
    j = Job.new(engine="redtusk", filename="x.doc")
    assert j.net_policy is None


def test_job_net_policy_roundtrips_through_dict():
    j = Job.new(engine="redtusk", filename="x.doc")
    j.net_policy = "fakenet"
    assert Job.from_dict(j.to_dict()).net_policy == "fakenet"
```

> If `Job` has no `to_dict` (it builds dicts elsewhere), replace the second test body with:
> `d = {**j.__dict__}; assert Job.from_dict(d).net_policy == "fakenet"` — confirm by reading
> `Job` for a `to_dict`/`asdict` first.

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/host/jobs/test_base.py -k net_policy -q`
Expected: FAIL — `AttributeError: 'Job' object has no attribute 'net_policy'`

- [ ] **Step 3a: Add the field** — immediately after the `target_tier: str | None = None` line in `Job`:

```python
    # OPERATOR/CLIENT routing hint: the requested network personality name (a key in the
    # operator's BLASTBOX_NETPOLICY_<NAME> registry). None = use the engine default. Only
    # honored at submit when BLASTBOX_ALLOW_NETPOLICY_OVERRIDE is on; resolved fail-closed at
    # dispatch. Mirrors target_tier.
    net_policy: str | None = None
```

- [ ] **Step 3b: Wire `from_dict`** — in `Job.from_dict`, next to `target_tier=d.get("target_tier"),` add:

```python
            net_policy=d.get("net_policy"),
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/host/jobs/test_base.py -k net_policy -q`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add src/blastbox/host/jobs/base.py tests/host/jobs/test_base.py
git commit -m "feat(netpolicy): Job.net_policy request field + from_dict"
```

---

### Task 6: `net_policy` SQL column (persist the request)

**Files:**
- Modify: `src/blastbox/host/jobs/sql_store.py` (the `_COLUMNS`/persisted-columns list ~line 37; the `CREATE TABLE` ~line 136; the row-read projection ~line 191)
- Test: `tests/host/jobs/test_sql_store.py`

- [ ] **Step 1: Write the failing test**

```python
# add to tests/host/jobs/test_sql_store.py
def test_net_policy_persists(tmp_path):
    from blastbox.host.jobs.base import Job
    from blastbox.host.jobs.sql_store import SqlJobStore

    store = SqlJobStore(f"sqlite:///{tmp_path / 'j.db'}")
    job = Job.new(engine="redtusk", filename="x.doc")
    job.net_policy = "fakenet"
    store.create(job)
    assert store.get(job.job_id).net_policy == "fakenet"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/host/jobs/test_sql_store.py -k net_policy -q`
Expected: FAIL — the read-back `net_policy` is `None` (column not persisted) → AssertionError.

- [ ] **Step 3: Add the column in all three places** (mirror `target_tier` exactly):
  1. In the persisted-columns tuple/list (where `"target_tier",` appears ~line 37), add `"net_policy",`.
  2. In the `CREATE TABLE` DDL (where `target_tier TEXT,` appears ~line 136), add `net_policy TEXT,`.
  3. In the row-read column projection (the tuple at ~line 191 listing `"worker_tier", "target_tier"`), add `"net_policy"`.

> Read each site first and place `net_policy` directly adjacent to `target_tier` so ordering
> stays consistent between the INSERT column list and the SELECT projection.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/host/jobs/test_sql_store.py -k net_policy -q`
Expected: PASS (1 passed)

- [ ] **Step 5: Commit**

```bash
git add src/blastbox/host/jobs/sql_store.py tests/host/jobs/test_sql_store.py
git commit -m "feat(netpolicy): persist Job.net_policy column (SqlJobStore)"
```

---

### Task 7: ingress gate — `net_policy` form field honored only when allowed

**Files:**
- Modify: `src/blastbox/host/ingress/app.py` (the submit handler; the `target_tier` Form param ~line 478 and its gating block ~line 531-546)
- Test: `tests/host/ingress/test_app.py`

Mirror `target_tier` / `BLASTBOX_ALLOW_TIER_ROUTING`: accept the form field, but only set
`job.net_policy` when `BLASTBOX_ALLOW_NETPOLICY_OVERRIDE` is truthy; otherwise ignore + log.

- [ ] **Step 1: Write the failing test**

```python
# add to tests/host/ingress/test_app.py  (uses the existing _make_client helper)
def test_net_policy_ignored_when_override_disabled(tmp_path, monkeypatch):
    monkeypatch.delenv("BLASTBOX_ALLOW_NETPOLICY_OVERRIDE", raising=False)
    client, store = _make_client(tmp_path)
    resp = client.post(
        "/v1/jobs",
        data={"engine": "clippyshot", "net_policy": "fakenet"},
        files={"file": ("x.docx", b"data", "application/octet-stream")},
    )
    assert resp.status_code in (200, 202)
    jid = resp.json()["job_id"]
    assert store.get(jid).net_policy is None  # ignored


def test_net_policy_set_when_override_enabled(tmp_path, monkeypatch):
    monkeypatch.setenv("BLASTBOX_ALLOW_NETPOLICY_OVERRIDE", "1")
    client, store = _make_client(tmp_path)
    resp = client.post(
        "/v1/jobs",
        data={"engine": "clippyshot", "net_policy": "fakenet"},
        files={"file": ("x.docx", b"data", "application/octet-stream")},
    )
    assert resp.status_code in (200, 202)
    assert store.get(resp.json()["job_id"]).net_policy == "fakenet"
```

> Confirm the submit route path + the existing field names (`engine`, file part) by reading
> the handler and an existing submit test first; align the `data=`/`files=` keys to them.

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/host/ingress/test_app.py -k net_policy -q`
Expected: FAIL — `net_policy` is `None` even with the override enabled (handler ignores the field).

- [ ] **Step 3a: Add the Form param** — next to `target_tier: str | None = Form(default=None),` in the submit handler signature:

```python
        net_policy: str | None = Form(default=None),
```

- [ ] **Step 3b: Add the gating block** — directly after the existing `target_tier` gating block (the `if tt_raw:` ... `_log.info("target_tier_ignored_routing_disabled", ...)`), add:

```python
        # Per-job network personality: ignored unless the operator sets
        # BLASTBOX_ALLOW_NETPOLICY_OVERRIDE. Off (default) → silently ignored, mirroring
        # target_tier. The NAME is validated against the registry at dispatch (fail-closed),
        # so ingress only needs the gate here.
        np_raw = (net_policy or "").strip()
        if np_raw:
            if os.environ.get("BLASTBOX_ALLOW_NETPOLICY_OVERRIDE", "").strip().lower() in (
                "1", "true", "yes", "on",
            ):
                job.net_policy = np_raw.lower()
            else:
                _log.info("net_policy_ignored_override_disabled", requested=np_raw[:64])
```

> Place this AFTER `job` is constructed (same place `job.target_tier` is set). If the handler
> sets `job.target_tier` before persisting, set `job.net_policy` in the same spot.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/host/ingress/test_app.py -k net_policy -q`
Expected: PASS (2 passed)

- [ ] **Step 5: Run the full affected suites + commit**

```bash
.venv/bin/pytest tests/host/test_netpolicy.py tests/host/test_cli.py \
  tests/host/jobs/test_base.py tests/host/jobs/test_sql_store.py \
  tests/host/ingress/test_app.py -q
```
Expected: all PASS.

```bash
git add src/blastbox/host/ingress/app.py tests/host/ingress/test_app.py
git commit -m "feat(netpolicy): gated per-job net_policy override at ingress"
```

---

## Self-review

**Spec coverage (§6 + §5.3 registry/resolver):**
- §6 operator declares personalities → Task 2 (`parse_personalities`, `BLASTBOX_NETPOLICY_<NAME>`). ✓
- §6 per-engine default (`BLASTBOX_ENGINE_<NAME>_NETPOLICY`, ships `none`, runtime-flip) → Task 4. ✓
- §6 gated per-job override (`BLASTBOX_ALLOW_NETPOLICY_OVERRIDE`, default off) → Tasks 5 (field) + 7 (gate). ✓
- §6 resolution order + fail-closed → Task 3. ✓
- §5.3 registry (`Personality`, exit drivers) → Tasks 1-2. ✓
- Persistence of the request → Task 6. ✓
- **Out of scope (Plan 2+):** attachment adapter, `blastbox-netd`, sidecars, capture/decrypt,
  the dispatcher calling `resolve_net_policy` and APPLYING the network. Plan 1 stops at "the
  effective Personality is declarable, defaultable, gateable, persisted, and resolvable."

**Placeholder scan:** none — every step has full code/commands. The three `>` notes (Job
`to_dict` shape, submit route field names, gating placement) are *read-first* confirmations of
existing code, not deferred work; the code to write is fully given.

**Type consistency:** `Personality(name, exit_driver, inspect, config)` used identically in
Tasks 1-3; `resolve_net_policy(job_net_policy=, engine_default=, registry=, allow_override=)`
keyword-only, matching its tests; `net_policy` is `str` on `EngineSpec` (default `"none"`) and
`str | None` on `Job` (request, default `None`) — intentional (a default always exists; a
request may be absent), and the resolver takes `job_net_policy: str | None` + `engine_default:
str`, consistent.

---

## Next plans (not this one)
- **Plan 2 — apply on runc (docker-native):** dispatcher calls `resolve_net_policy`; map
  `none→--network=none`, `direct→bb-net0 bridge`, `fakenet→bb-fakenet bridge + inetsim sidecar`,
  `drop→blackhole`; per-job tcpdump capture + seal. (Spec §5.1 runc, §7 capture, §10 flow.)
- **Plan 3** — SOCKS tier (passt/tun2socks: tor/socks). **Plan 4** — all-IP (`blastbox-netd` +
  wg/veth). **Plan 5** — inspect + GoGoRoboCap decrypt. **Plan 6** — gVisor (SOCKS) + FC (TAP).
