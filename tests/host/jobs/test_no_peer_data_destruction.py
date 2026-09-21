"""A credential-less node must never delete a peer's files (#178).

THE DEFECT THIS PINS was reproduced against real code: `HttpJobStore.get()` returned None for
"not yours", `dispatch`'s ownership gates read None as "the row is gone, nobody needs these
bytes", and a peer's staged malware sample and its ENTIRE job tree were deleted mid-detonation.

The gates were already written to fail safe — "if we cannot PROVE we still own the tree we
leave it alone. A leaked dir is recoverable; a job whose input vanished under it is not" — they
just were never given a truthful answer. The store now raises instead of lying, so the safe
path runs.
"""
from __future__ import annotations

import tempfile
import time
from pathlib import Path

import pytest

from blastbox.host import pki
from blastbox.host.dispatch import Dispatcher, EngineSpec
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.http_store import ClaimNotHeld, HttpJobStore
from blastbox.limits import Limits

JID = "11111111-2222-4333-8444-555555555555"
WG = "A" * 42 + "B="


def _refuses_everything(method, path, *, json=None, params=None, headers=None):
    """A control plane that will not confirm this node's claim — i.e. a peer reclaimed it."""
    if path == "/v1/nodes/challenge":
        return 200, {"challenge": "c" * 43, "scope": "claim-next"}
    if path == "/v1/nodes/session":
        return 200, {"token": "t", "expires_in": 600, "node_id": "n1"}
    return 403, {"detail": "not authorised to claim this work"}


@pytest.fixture
def node(tmp_path):
    p = tmp_path / "pki"
    ca = pki.ensure_ca(p)
    ca.issue_node("n1", wg_pubkey=WG, grants=pki.NodeGrants(
        engines=("boxjs",), credentials=True)).write(p, "node-n1")
    store = HttpJobStore("https://cp", cert_path=p / "node-n1.crt",
                         transport=_refuses_everything)
    store._claims[JID] = ("stale-claim", "receipt")   # we HELD it; a peer took it since
    return store


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "jobs"
    (root / JID / "input").mkdir(parents=True)
    (root / JID / "output").mkdir()
    sample = root / JID / "input" / "sample.js"
    sample.write_text("the peer's untrusted input")
    return root, sample


def _dispatcher(store, root):
    return Dispatcher(
        job_store=store,
        engines={"boxjs": EngineSpec(name="boxjs", image="i", worker_argv=["x"])},
        limits=Limits.from_env(), job_root=root)


def _stale_job():
    return Job(job_id=JID, engine="boxjs", filename="sample.js", status=JobStatus.RUNNING,
               created_at=time.time(), claim_id="stale-claim")


def test_a_lost_claim_does_not_delete_the_peers_staged_input(node, tree):
    root, sample = tree
    _dispatcher(node, root)._delete_input_if_owned(_stale_job(), sample)
    assert sample.exists(), "deleted a peer's staged malware sample mid-detonation"


def test_a_lost_claim_does_not_purge_the_peers_job_tree(node, tree):
    root, _sample = tree
    _dispatcher(node, root)._purge_job_dir_if_owned(_stale_job())
    assert (root / JID).exists(), "deleted a peer's entire job tree mid-detonation"


def test_the_store_raises_rather_than_reporting_the_job_absent(node):
    """The root cause, asserted directly: None would mean "no such row" to every caller."""
    with pytest.raises(ClaimNotHeld):
        node.get(JID)


def test_metrics_do_not_mask_the_real_outcome_when_ownership_cannot_be_confirmed(node):
    """`_record_outcome` runs from the same terminal `finally` and must never raise, or it
    would surface instead of the DONE/FAILED the job actually produced."""
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / JID).mkdir()
        _dispatcher(node, root)._record_outcome(_stale_job(), path="cold", started=0.0)
