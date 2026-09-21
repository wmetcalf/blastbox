"""`serve` must refuse a control-plane URL at BUILD time, structurally (#178).

A serving process built on HttpJobStore boots, answers 200 on /v1/healthz -- so a load balancer
takes it into rotation -- and then 500s on every submission because create/list/delete raise. The
first guard keyed on a BLASTBOX_ROLE variable that nothing in the serve path ever set, so it never
fired: review found it dead. This one keys on the store's type, which cannot be forgotten.
"""
from __future__ import annotations

import pytest

from blastbox.host import pki
from blastbox.host.ingress.app import build_app
from blastbox.host.jobs.http_store import HttpJobStore


def test_build_app_refuses_a_control_plane_store(tmp_path, monkeypatch):
    d = tmp_path / "pki"
    pki.ensure_ca(d)
    cert = d / "node-x.crt"
    cert.write_text("x")
    store = HttpJobStore("https://control-plane.example", cert_path=cert)
    with pytest.raises(ValueError, match="SERVES the queue"):
        build_app(job_store=store, job_root=tmp_path / "jobs")


def test_build_app_refuses_it_from_the_environment_too(tmp_path, monkeypatch):
    """The real path: nothing injected, just the env an operator would copy from the node."""
    d = tmp_path / "pki"
    pki.ensure_ca(d)
    (d / "node-x.crt").write_text("x")
    monkeypatch.setenv("BLASTBOX_DATABASE_URL", "https://control-plane.example")
    monkeypatch.setenv("BLASTBOX_NODE_CERT", str(d / "node-x.crt"))
    monkeypatch.setenv("BLASTBOX_PKI_DIR", str(d))
    with pytest.raises(ValueError, match="SERVES the queue"):
        build_app(job_root=tmp_path / "jobs")
