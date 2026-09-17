"""THE ENFORCEMENT MATRIX — every path that can run a job, executed, for every gate state.

WHY THIS FILE EXISTS. Two review rounds found that the node-grants gate could be made
COMPLETELY INERT while the whole suite stayed green, because every test written for it
asserted on `inspect.getsource()` substrings. Twice. The gate was also missing from the
warm path and from `VmJobDispatcher` entirely — a static reading said "the check is
there", and the check was there, in one of the three places a job can execute.

So this file does not read source. Every test below RUNS a dispatcher against a real
in-memory store and asserts on what happened to the job and on whether anything was
executed. The companion `test_the_matrix_catches_an_inert_gate` proves the matrix has
teeth by disabling the gate and requiring these tests to go red.

THE INVARIANT, stated once: a node whose certificate does not grant a job must not
execute it, by ANY path, and must RELEASE it rather than destroy it — it cannot see the
fleet and has no standing to assert that no peer can run it.
"""
from __future__ import annotations

import subprocess

import pytest

from blastbox.host import pki
from blastbox.host.jobs.memory import InMemoryJobStore
from blastbox.host.jobs.base import JobStatus

from tests.host.test_dispatch import (  # the harness the real-path tests already use
    _ENGINE_NAME,
    _INPUT_SHA,
    _make_dispatcher,
    _make_job,
    _setup_job_dirs,
)

WG = "A" * 43 + "="


# --------------------------------------------------------------------------- fixtures

def _arm(tmp_path, monkeypatch, *, engines=(), tiers=(), credentials=False, rogue=False):
    """Give this node a certificate. `rogue=True` signs it with a DIFFERENT CA, which is
    what an expired/revoked/foreign identity looks like to the verifier."""
    pki_dir = tmp_path / "pki"
    ca = pki.ensure_ca(pki_dir)
    signer = pki.ensure_ca(tmp_path / "rogue") if rogue else ca
    issued = signer.issue_node("toolz3", wg_pubkey=WG,
                               grants=pki.NodeGrants(engines=tuple(engines),
                                                     tiers=tuple(tiers),
                                                     credentials=credentials))
    crt, _ = issued.write(tmp_path, "node-toolz3")
    monkeypatch.setenv("BLASTBOX_PKI_DIR", str(pki_dir))
    monkeypatch.setenv("BLASTBOX_NODE_CERT", str(crt))
    return crt


def _disarm(monkeypatch):
    monkeypatch.delenv("BLASTBOX_NODE_CERT", raising=False)
    monkeypatch.delenv("BLASTBOX_NODE_GRANTS_GATE", raising=False)


def _queued(store, tmp_path, *, net_policy=None):
    job = _make_job(engine=_ENGINE_NAME)
    job.input_sha256 = _INPUT_SHA
    if net_policy is not None:
        job.net_policy = net_policy
    store.create(job)
    return job, _setup_job_dirs(tmp_path, job)


# --------------------------------------------------------------------- 1. the COLD path

@pytest.mark.parametrize("grants,expect_run", [
    (dict(engines=(_ENGINE_NAME,)), True),                 # granted
    (dict(engines=("some-other-engine",)), False),         # engine not granted
    (dict(engines=()), False),                             # granted nothing
])
def test_cold_path_runs_only_what_is_granted(tmp_path, monkeypatch, grants, expect_run):
    store = InMemoryJobStore()
    job, _ = _queued(store, tmp_path)
    _arm(tmp_path, monkeypatch, **grants)

    calls: list = []
    _make_dispatcher(store, job_root=tmp_path,
                     subprocess_runner=lambda a, **k: calls.append(a)
                     or subprocess.CompletedProcess(a, 0, "", "")).dispatch_once()

    assert bool(calls) is expect_run, (
        f"granted={grants}: expected run={expect_run}, got {bool(calls)}")
    if not expect_run:
        assert store.get(job.job_id).status == JobStatus.QUEUED, "released, never failed"


def test_cold_path_refuses_a_certificate_that_does_not_verify(tmp_path, monkeypatch):
    """Revocation is "stop renewing", so a foreign/expired identity must run NOTHING —
    not fall back to unrestricted, which is what "no certificate" means."""
    store = InMemoryJobStore()
    job, _ = _queued(store, tmp_path)
    _arm(tmp_path, monkeypatch, engines=(_ENGINE_NAME,), rogue=True)

    calls: list = []
    _make_dispatcher(store, job_root=tmp_path,
                     subprocess_runner=lambda a, **k: calls.append(a)
                     or subprocess.CompletedProcess(a, 0, "", "")).dispatch_once()

    assert calls == [], "a node with an unverifiable certificate detonated a sample"
    assert store.get(job.job_id).status == JobStatus.QUEUED


def test_cold_path_is_unrestricted_with_no_certificate(tmp_path, monkeypatch):
    """Enforcement is OPT-IN. Without this, a gate that refused everything would satisfy
    every refusal test above while bricking every existing deployment."""
    store = InMemoryJobStore()
    _queued(store, tmp_path)
    _disarm(monkeypatch)

    calls: list = []
    _make_dispatcher(store, job_root=tmp_path,
                     subprocess_runner=lambda a, **k: calls.append(a)
                     or subprocess.CompletedProcess(a, 0, "", "")).dispatch_once()
    assert calls, "an ungated node refused work it should have run"


def test_the_released_job_keeps_its_input_for_the_peer(tmp_path, monkeypatch):
    """A release whose cleanup deletes the sample turns "released, never failed" into
    its opposite: the peer cannot re-materialise it and fails the job."""
    store = InMemoryJobStore()
    job, input_path = _queued(store, tmp_path)
    _arm(tmp_path, monkeypatch, engines=("some-other-engine",))

    _make_dispatcher(store, job_root=tmp_path,
                     subprocess_runner=lambda a, **k: subprocess.CompletedProcess(a, 0, "", "")
                     ).dispatch_once()

    assert store.get(job.job_id).status == JobStatus.QUEUED
    assert input_path.exists(), "the released job's input was deleted"


# --------------------------------------------------------------------- 2. the WARM path
# The gate was ABSENT here for the whole first implementation: `_dispatch_warm` is called
# as the ALTERNATIVE to `_dispatch_inner`, where the check lived, so every job that
# landed on an idle warm slot ran ungated. On a warm-only sidecar there is no cold path
# at all, so the control was 100% unreachable for that deployment.

def _warm_dispatcher(store, tmp_path, monkeypatch, claimed, *, warm_only=False):
    from tests.host.test_dispatch_warm import (
        FakeWarmPool, _make_dispatcher_with_pool, _make_slot,
    )

    slot = _make_slot(tmp_path)
    pool = FakeWarmPool(slot)

    # Record the moment a warm slot is actually CLAIMED for this job. Nothing downstream
    # of that point can un-run a detonation, so it is the honest "did it execute" mark.
    real_claim = pool.claim

    def watched(*, timeout_s):
        got = real_claim(timeout_s=timeout_s)
        if got is not None:
            claimed.append(got)
        return got

    pool.claim = watched          # type: ignore[method-assign]
    return _make_dispatcher_with_pool(
        store, job_root=tmp_path, pool=pool, worker_timeout_s=5, warm_only=warm_only)


@pytest.mark.parametrize("warm_only", [False, True])
def test_warm_path_does_not_run_an_ungranted_job(tmp_path, monkeypatch, warm_only):
    store = InMemoryJobStore()
    job, _ = _queued(store, tmp_path)
    _arm(tmp_path, monkeypatch, engines=("some-other-engine",))

    claimed: list = []
    _warm_dispatcher(store, tmp_path, monkeypatch, claimed, warm_only=warm_only).dispatch_once()

    assert claimed == [], (
        f"warm_only={warm_only}: an ungranted job reached a warm slot. The gate must "
        "sit ABOVE the warm/cold branch, not inside the cold path."
    )
    assert store.get(job.job_id).status == JobStatus.QUEUED


@pytest.mark.parametrize("warm_only", [False, True])
def test_warm_path_still_runs_a_granted_job(tmp_path, monkeypatch, warm_only):
    """Or the test above would pass against a gate that refuses everything."""
    store = InMemoryJobStore()
    _queued(store, tmp_path)
    _arm(tmp_path, monkeypatch, engines=(_ENGINE_NAME,))

    claimed: list = []
    _warm_dispatcher(store, tmp_path, monkeypatch, claimed, warm_only=warm_only).dispatch_once()
    assert claimed, f"warm_only={warm_only}: a granted job was refused a warm slot"


def test_warm_path_refuses_an_unverifiable_certificate(tmp_path, monkeypatch):
    store = InMemoryJobStore()
    _queued(store, tmp_path)
    _arm(tmp_path, monkeypatch, engines=(_ENGINE_NAME,), rogue=True)

    claimed: list = []
    _warm_dispatcher(store, tmp_path, monkeypatch, claimed).dispatch_once()
    assert claimed == [], "an unverifiable certificate reached a warm slot"


def test_the_warm_reservation_is_not_leaked_by_a_refusal(tmp_path, monkeypatch):
    """This method is the sole owner of releasing the warm-slot gate reservation. A
    refusal that returns without releasing leaks one per visit, and once the leak reaches
    the idle-slot count a warm-only sidecar stops claiming ANY job — granted or not — and
    never recovers, not even after the certificate is renewed."""
    store = InMemoryJobStore()
    _arm(tmp_path, monkeypatch, engines=("some-other-engine",))
    claimed: list = []
    d = _warm_dispatcher(store, tmp_path, monkeypatch, claimed, warm_only=True)

    for _ in range(6):            # more visits than there are idle slots
        job, _p = _queued(store, tmp_path)
        d.dispatch_once()
        # drive the same job round again, which is what the cooldown branch handles
        d.dispatch_once()

    assert getattr(d, "_warm_slot_reservations", 0) == 0, (
        f"leaked {d._warm_slot_reservations} warm-slot reservation(s); the gate would "
        "wedge a warm-only sidecar permanently"
    )


# ----------------------------------------------------------------------- 3. the VM path
# `VmJobDispatcher` had NO grants check of any kind in the first implementation. cli.py
# routes every network-style pool (aws, static, cascade) here and RETURNS before
# `Dispatcher` is ever constructed — so the remote workers the federation design exists
# to constrain were precisely the ones running ungoverned, and an operator setting
# BLASTBOX_NODE_CERT on such a node would see no refusals and conclude it worked.

def _vm(store, tmp_path, validated, *, fixed_net_policy=None):
    from blastbox.host.runtime.vm_dispatch import VmJobDispatcher

    def validate(path):
        validated.append(path)
        return ({"verdict": {"status": "clean"}}, True)

    return VmJobDispatcher(store, str(tmp_path), validate, worker_tier="libvirt-vm",
                           fixed_net_policy=fixed_net_policy)


def _vm_job(store, tmp_path, engine="authenticode", net_policy=None):
    from blastbox.host.jobs.base import Job

    job = Job.new(engine=engine, filename="evil.dll")
    if net_policy is not None:
        # The VM dispatcher separately fails a job whose effective policy differs from
        # the pool's provisioned egress. The POSITIVE cases must satisfy that check, or
        # they would "pass" for a reason that has nothing to do with the grants gate.
        job.net_policy = net_policy
    root = tmp_path / job.job_id
    (root / "input").mkdir(parents=True)
    (root / "input" / "evil.dll").write_bytes(b"MZ")
    job.result_dir = str(root)
    store.create(job)
    return job


def test_vm_path_does_not_validate_an_ungranted_engine(tmp_path, monkeypatch):
    store = InMemoryJobStore()
    job = _vm_job(store, tmp_path)
    _arm(tmp_path, monkeypatch, engines=("some-other-engine",))

    validated: list = []
    _vm(store, tmp_path, validated)._process(store.claim_next())

    assert validated == [], "the VM dispatcher ran an ungranted engine"
    assert store.get(job.job_id).status == JobStatus.QUEUED, "released, never failed"


def test_vm_path_still_runs_a_granted_engine(tmp_path, monkeypatch):
    store = InMemoryJobStore()
    job = _vm_job(store, tmp_path)
    _arm(tmp_path, monkeypatch, engines=("authenticode",))

    validated: list = []
    _vm(store, tmp_path, validated)._process(store.claim_next())
    assert validated, "a granted engine was refused by the VM dispatcher"
    assert store.get(job.job_id).status == JobStatus.DONE


def test_vm_path_refuses_an_unverifiable_certificate(tmp_path, monkeypatch):
    store = InMemoryJobStore()
    _vm_job(store, tmp_path)
    _arm(tmp_path, monkeypatch, engines=("authenticode",), rogue=True)

    validated: list = []
    _vm(store, tmp_path, validated)._process(store.claim_next())
    assert validated == [], "an unverifiable certificate ran work on the VM path"


def test_vm_path_is_unrestricted_with_no_certificate(tmp_path, monkeypatch):
    store = InMemoryJobStore()
    _vm_job(store, tmp_path)
    _disarm(monkeypatch)

    validated: list = []
    _vm(store, tmp_path, validated)._process(store.claim_next())
    assert validated, "an ungated VM dispatcher refused work it should have run"


def test_vm_path_enforces_the_TIER_not_only_the_engine(tmp_path, monkeypatch):
    """The tier arm collapsed silently: `resolve_net_policy` never raises, so every
    personality resolved to the ungoverned "none" and only the engine name was ever
    checked. A pool whose fixed_net_policy names a personality declared in another
    unit's environment ran with real egress while the gate recorded it as sealed."""
    store = InMemoryJobStore()
    job = _vm_job(store, tmp_path)
    # Granted the ENGINE but no tiers at all, on a pool provisioned with a real egress.
    _arm(tmp_path, monkeypatch, engines=("authenticode",), tiers=())

    validated: list = []
    _vm(store, tmp_path, validated, fixed_net_policy="openvpn-nl")._process(store.claim_next())

    assert validated == [], (
        "the VM dispatcher ran an egress-provisioned job for a certificate granting no "
        "tier — the tier arm of the gate is inert"
    )
    assert store.get(job.job_id).status == JobStatus.QUEUED


def test_vm_path_leaves_the_released_job_runnable_by_a_peer(tmp_path, monkeypatch):
    """The refusal must not purge: the neighbouring net_policy branch purges because it
    is TERMINAL, and copying that shape onto a RELEASE destroys the peer's input."""
    store = InMemoryJobStore()
    job = _vm_job(store, tmp_path)
    _arm(tmp_path, monkeypatch, engines=("some-other-engine",))

    _vm(store, tmp_path, [])._process(store.claim_next())

    final = store.get(job.job_id)
    assert final.status == JobStatus.QUEUED
    assert (tmp_path / job.job_id / "input" / "evil.dll").exists(), (
        "the released job's input was purged; the peer cannot run it"
    )


# ------------------------------------------------------- 4. the CREDENTIALS arm
# Found missing by scripts/ci/prove-grants-enforcement.sh: the whole matrix above passed
# with `if require_credentials and not grants.credentials:` disabled. The grant that
# decides whether a node may HOLD a provider secret had no executing coverage at all —
# which is how the same arm shipped twice already covering only openvpn/wireguard in
# local mode, letting a credentials=False node run a credentialed SOCKS sidecar.

def _local_mode(tmp_path, monkeypatch):
    """Make this node look like a local-mode egress node, which is what makes an
    openvpn/wireguard tier mean it HOLDS a provider profile."""
    from blastbox.host import egress_apply as ea

    env = tmp_path / "egress.env"
    env.write_text("BLASTBOX_EGRESS_MODE=local\n")
    monkeypatch.setattr(ea, "ENV_FILE", env)


@pytest.mark.parametrize("driver", ["socks", "httpproxy"])
def test_a_credentialed_sidecar_tier_needs_the_credentials_grant_in_any_mode(
        tmp_path, monkeypatch, driver):
    """socks and httpproxy run against a local sidecar in BOTH egress modes, and their
    URLs are exactly the credentials this project refuses to put on a command line. The
    first version required the grant only for openvpn/wireguard in local mode."""
    from blastbox.host import egress_apply as ea

    env = tmp_path / "egress.env"
    env.write_text("BLASTBOX_EGRESS_MODE=global\n")      # NOT local — still credentialed
    monkeypatch.setattr(ea, "ENV_FILE", env)
    monkeypatch.setenv(f"BLASTBOX_NETPOLICY_{driver.upper()}", f"exit={driver}")

    store = InMemoryJobStore()
    job = _vm_job(store, tmp_path)
    _arm(tmp_path, monkeypatch, engines=("authenticode",), tiers=(driver,),
         credentials=False)

    validated: list = []
    _vm(store, tmp_path, validated, fixed_net_policy=driver)._process(store.claim_next())

    assert validated == [], (
        f"a certificate granting credentials=False ran a {driver} tier, whose sidecar "
        "carries a provider secret"
    )
    assert store.get(job.job_id).status == JobStatus.QUEUED


def test_a_vpn_tier_needs_the_credentials_grant_in_LOCAL_mode(tmp_path, monkeypatch):
    _local_mode(tmp_path, monkeypatch)
    monkeypatch.setenv("BLASTBOX_NETPOLICY_OPENVPN", "exit=openvpn")

    store = InMemoryJobStore()
    job = _vm_job(store, tmp_path)
    _arm(tmp_path, monkeypatch, engines=("authenticode",), tiers=("openvpn",),
         credentials=False)

    validated: list = []
    _vm(store, tmp_path, validated, fixed_net_policy="openvpn")._process(store.claim_next())

    assert validated == [], "a local-mode node ran openvpn without the credentials grant"
    assert store.get(job.job_id).status == JobStatus.QUEUED


def test_the_same_vpn_tier_runs_in_GLOBAL_mode_without_the_grant(tmp_path, monkeypatch):
    """The other direction, and it matters as much: in global mode the node forwards over
    the overlay to a host that holds the profile and holds nothing itself. Demanding the
    grant there would idle every correctly-issued worker node — a fix that over-corrects
    into a fleet-wide outage."""
    from blastbox.host import egress_apply as ea

    env = tmp_path / "egress.env"
    env.write_text("BLASTBOX_EGRESS_MODE=global\n")
    monkeypatch.setattr(ea, "ENV_FILE", env)
    monkeypatch.setenv("BLASTBOX_NETPOLICY_OPENVPN", "exit=openvpn")

    store = InMemoryJobStore()
    job = _vm_job(store, tmp_path, net_policy="openvpn")
    _arm(tmp_path, monkeypatch, engines=("authenticode",), tiers=("openvpn",),
         credentials=False)

    validated: list = []
    _vm(store, tmp_path, validated, fixed_net_policy="openvpn")._process(store.claim_next())

    assert validated, "a global-mode worker was idled by a credentials grant it should not need"
    assert store.get(job.job_id).status == JobStatus.DONE


def test_granting_credentials_lets_the_credentialed_tier_run(tmp_path, monkeypatch):
    """So the refusals above cannot be satisfied by a gate that blocks these tiers
    unconditionally."""
    _local_mode(tmp_path, monkeypatch)
    monkeypatch.setenv("BLASTBOX_NETPOLICY_OPENVPN", "exit=openvpn")

    store = InMemoryJobStore()
    _vm_job(store, tmp_path, net_policy="openvpn")
    _arm(tmp_path, monkeypatch, engines=("authenticode",), tiers=("openvpn",),
         credentials=True)

    validated: list = []
    _vm(store, tmp_path, validated, fixed_net_policy="openvpn")._process(store.claim_next())
    assert validated, "credentials=True was granted and the tier was still refused"
