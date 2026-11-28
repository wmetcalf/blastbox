"""fleet_grants must never block on a FIFO planted in the PKI dir."""
from __future__ import annotations

import os
import threading

from blastbox.host import pki
from blastbox.host.placement import fleet_grants
from tests.host.test_node_renew import GRANTS, make_csr


def test_fleet_grants_skips_a_fifo_instead_of_blocking(tmp_path):
    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    (d / "node-n1.crt").write_bytes(ca.sign_node_csr(make_csr("n1")[0], node_id="n1",
                                                     grants=GRANTS))
    os.mkfifo(d / "aaa.crt")
    out: dict = {}
    t = threading.Thread(target=lambda: out.update(fleet_grants(d)), daemon=True)
    t.start()
    t.join(5)
    assert not t.is_alive(), "fleet_grants blocked on a FIFO"
    assert set(out) == {"n1"}


def test_fleet_grants_still_follows_a_symlinked_cert(tmp_path):
    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    store = tmp_path / "store.crt"
    store.write_bytes(ca.sign_node_csr(make_csr("n1")[0], node_id="n1", grants=GRANTS))
    (d / "node-n1.crt").symlink_to(store)
    assert set(fleet_grants(d)) == {"n1"}


def test_a_large_narrower_cert_still_narrows(tmp_path):
    """No size cap: a regular cert file of any size is read whole, as before, so a padded
    narrower cert cannot drop out of the intersection and widen the node."""
    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    broad = pki.NodeGrants(engines=("a", "b"), tiers=(), credentials=False)
    narrow = pki.NodeGrants(engines=("a",), tiers=(), credentials=False)
    (d / "node-n1.crt").write_bytes(ca.sign_node_csr(make_csr("n1")[0], node_id="n1",
                                                     grants=broad))
    with open(d / "n1-new.crt", "wb") as fh:
        fh.write(ca.sign_node_csr(make_csr("n1")[0], node_id="n1", grants=narrow))
        fh.write(b"\n" * (2 << 20))                   # padded past any read cap
    assert fleet_grants(d)["n1"].engines == ("a",)


def test_a_short_reading_filesystem_still_reads_the_whole_cert(tmp_path, monkeypatch):
    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    (d / "node-n1.crt").write_bytes(ca.sign_node_csr(make_csr("n1")[0], node_id="n1",
                                                     grants=GRANTS))
    real = os.read
    monkeypatch.setattr(os, "read", lambda fd, n: real(fd, min(n, 64)))   # NFS-ish
    assert set(fleet_grants(d)) == {"n1"}
