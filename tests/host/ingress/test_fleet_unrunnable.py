"""Work that NO enrolled certificate can run is excluded fleet-wide (#178, round nine).

Every earlier fix to refusal-wall starvation tuned the per-node refusal memo -- a skip cap, an
exclusion, a size cap, a TTL -- and each review found the next edge of it, because a memo that
must forget something eventually forgets the head of the wall. The class ends here: a job no node
in the fleet is granted is judged ONCE (per certificate set), excluded for every node, and never
walked again until the certificate set changes. A job some OTHER enrolled node can run is left
alone, so its peer still gets it.
"""
from __future__ import annotations

import base64
import time

from fastapi import FastAPI
from fastapi.testclient import TestClient

from blastbox.host import node_auth, pki
from blastbox.host.ingress import node_claim as nc
from blastbox.host.ingress.node_claim import SESSION_HEADER, register_node_claim_routes
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore

WG = "A" * 42 + "B="
ENV = {"BLASTBOX_NETPOLICY_PROX": "exit=socks",
       "BLASTBOX_ENGINE_CLAMAV_NETPOLICY": "prox",       # needs the socks tier + credentials
       "BLASTBOX_ENGINE_BOXJS_NETPOLICY": "none"}


class Fleet:
    def __init__(self, tmp_path, monkeypatch, nodes: dict):
        monkeypatch.delenv(node_auth.SECRET_FILE_ENV, raising=False)
        for k, v in ENV.items():
            monkeypatch.setenv(k, v)
        self.d = tmp_path / "pki"
        self.ca = pki.ensure_ca(self.d)
        for name, grants in nodes.items():
            self.enrol(name, grants)
        self.store = InMemoryJobStore()
        app = FastAPI()
        assert register_node_claim_routes(app, job_store=self.store, pki_dir=self.d)
        self.c = TestClient(app)

    def enrol(self, name, grants):
        self.ca.issue_node(name, wg_pubkey=WG, grants=grants).write(self.d, f"node-{name}")

    def headers(self, name):
        ch = self.c.get("/v1/nodes/challenge").json()["challenge"]
        sig = base64.b64encode(node_auth.sign_claim(
            (self.d / f"node-{name}.key").read_bytes(), ch, node_auth.SCOPE_CLAIM_NEXT,
            name)).decode()
        tok = self.c.post("/v1/nodes/session", json={
            "cert_pem": (self.d / f"node-{name}.crt").read_text(), "challenge": ch,
            "signature": sig}).json()["token"]
        return {SESSION_HEADER: tok}

    def wall(self, n, engine="clamav"):
        now = time.time()
        for i in range(n):
            self.store.create(Job(job_id=f"wall{i:05d}", engine=engine, filename="f",
                                  status=JobStatus.QUEUED,
                                  created_at=now - nc.MAX_TOTAL_DEFERRAL_S - 100_000 + i))


NO_SOCKS = pki.NodeGrants(engines=("clamav", "boxjs"), tiers=(), credentials=False)
HAS_SOCKS = pki.NodeGrants(engines=("clamav",), tiers=("socks",), credentials=True)


def _poll_until(f, name, want, polls):
    h = f.headers(name)
    for _ in range(polls):
        r = f.c.post("/v1/nodes/claim", json={}, headers=h)
        if r.status_code == 200:
            got = r.json()["job"]["job_id"]
            if got == want:
                return True
    return False


def test_a_job_no_node_can_run_is_walked_once_not_per_node(tmp_path, monkeypatch):
    """Two nodes, neither granted socks. Once the first has judged the wall, the second must not
    re-walk it: the store should never even offer those jobs again."""
    f = Fleet(tmp_path, monkeypatch, {"a": NO_SOCKS, "b": NO_SOCKS})
    f.wall(40)
    h = f.headers("a")
    for _ in range(10):                                    # node a judges the whole wall
        f.c.post("/v1/nodes/claim", json={}, headers=h)
    offered = []
    real = f.store.claim_next

    def watching(**k):
        job = real(**k)
        if job is not None:
            offered.append(job.job_id)
        return job

    monkeypatch.setattr(f.store, "claim_next", watching)
    f.c.post("/v1/nodes/claim", json={}, headers=f.headers("b"))
    walled = [j for j in offered if j.startswith("wall")]
    assert not walled, (
        f"node b was offered {len(walled)} jobs no node in the fleet can run; the wall is still "
        "walked per node instead of excluded fleet-wide")


def test_a_job_some_other_node_can_run_is_NOT_excluded(tmp_path, monkeypatch):
    """The safety property. Node a cannot run the wall but node c CAN; c must still be handed it.
    Excluding by 'this node was refused' alone would starve the one node that is entitled."""
    f = Fleet(tmp_path, monkeypatch, {"a": NO_SOCKS, "c": HAS_SOCKS})
    f.wall(5)
    h = f.headers("a")
    for _ in range(3):
        f.c.post("/v1/nodes/claim", json={}, headers=h)    # a is refused all five
    for i in range(5):
        f.store.update(f"wall{i:05d}", claimable_after=None)
    assert _poll_until(f, "c", "wall00000", 5), (
        "a job an enrolled node IS granted was hidden from it because a different node was refused")


def test_enrolling_a_node_that_can_run_it_releases_the_exclusion(tmp_path, monkeypatch):
    """The exclusion is tied to the certificate set: enrol a node that holds the missing grant and
    the work must reach it straight away, not after some memo expires."""
    f = Fleet(tmp_path, monkeypatch, {"a": NO_SOCKS})
    f.wall(3)
    h = f.headers("a")
    for _ in range(3):
        f.c.post("/v1/nodes/claim", json={}, headers=h)
    for i in range(3):
        f.store.update(f"wall{i:05d}", claimable_after=None)
    f.enrol("late", HAS_SOCKS)
    assert _poll_until(f, "late", "wall00000", 3), (
        "a newly-enrolled node that can run the work never got it: the fleet-wide exclusion "
        "outlived the certificate set it was computed from")


def test_a_wall_deeper_than_the_per_node_memo_is_crossed(tmp_path, monkeypatch):
    """The class itself. Shrink the per-node memo to 64 so it must forget; with only that memo a
    300-deep wall of fleet-unrunnable work is never crossed, because the head of the wall keeps
    coming back. The fleet exclusion does not forget."""
    monkeypatch.setattr(nc._RefusalMemo.__init__, "__defaults__", (3600.0, 64))
    f = Fleet(tmp_path, monkeypatch, {"a": NO_SOCKS})
    f.wall(300)
    f.store.create(Job(job_id="behind", engine="boxjs", filename="f", status=JobStatus.QUEUED,
                       created_at=time.time()))
    assert _poll_until(f, "a", "behind", 300 // nc._MAX_CLAIM_PROBES + 30), (
        "a wall deeper than the per-node memo starved the work behind it")


def test_the_operator_is_told_why_the_work_sits(tmp_path, monkeypatch, caplog):
    """Queued-forever with nothing in the log was half the problem. Say it once per job."""
    import logging

    f = Fleet(tmp_path, monkeypatch, {"a": NO_SOCKS})
    f.wall(2)
    with caplog.at_level(logging.WARNING):
        h = f.headers("a")
        for _ in range(4):
            f.c.post("/v1/nodes/claim", json={}, headers=h)
    said = [r for r in caplog.records if "no enrolled node" in r.message]
    assert len(said) == 2, f"expected one line per unrunnable job, got {len(said)}"
