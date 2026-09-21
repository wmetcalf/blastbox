"""The control plane is selected by SCHEME, not by a second variable (#178)."""
from __future__ import annotations

import pytest

from blastbox.host.jobs.factory import build_job_store_from_env
from blastbox.host.jobs.http_store import HttpJobStore


def test_an_https_url_builds_a_control_plane_store(tmp_path):
    cert = tmp_path / "node-alpha.crt"
    cert.write_text("not read at construction")
    store = build_job_store_from_env({
        "BLASTBOX_DATABASE_URL": "https://control-plane.example:8443",
        "BLASTBOX_NODE_CERT": str(cert),
    })
    assert isinstance(store, HttpJobStore)


def test_it_refuses_to_build_without_a_node_identity(tmp_path):
    """A control-plane store with no certificate could never authenticate. Saying so at
    construction beats failing on the first claim, which looks like an empty queue."""
    with pytest.raises(ValueError, match="BLASTBOX_NODE_CERT"):
        build_job_store_from_env({
            "BLASTBOX_DATABASE_URL": "https://control-plane.example:8443",
        })


def test_plain_http_warns_that_the_link_is_clear(tmp_path, caplog):
    cert = tmp_path / "node-alpha.crt"
    cert.write_text("x")
    with caplog.at_level("WARNING"):
        build_job_store_from_env({
            "BLASTBOX_DATABASE_URL": "http://control-plane.example:8080",
            "BLASTBOX_NODE_CERT": str(cert),
        })
    assert any("clear" in r.message or "unencrypted" in r.message
               for r in caplog.records), caplog.text


def test_a_database_url_still_builds_a_database_store(tmp_path):
    """The scheme dispatch must not have changed what every existing deployment gets."""
    store = build_job_store_from_env({
        "BLASTBOX_DATABASE_URL": f"sqlite:///{tmp_path / 'jobs.db'}",
    })
    assert not isinstance(store, HttpJobStore)


def test_the_factory_itself_does_not_judge_the_role(tmp_path):
    """The role guard lives in build_app, keyed on the store's TYPE. An earlier version keyed on
    BLASTBOX_ROLE here -- which nothing ever set, so it never fired. The factory just builds."""
    cert = tmp_path / "node-alpha.crt"
    cert.write_text("x")
    store = build_job_store_from_env({
        "BLASTBOX_DATABASE_URL": "https://control-plane.example:8443",
        "BLASTBOX_NODE_CERT": str(cert),
        "BLASTBOX_ROLE": "serve",          # ignored: no such contract any more
    })
    assert isinstance(store, HttpJobStore)
