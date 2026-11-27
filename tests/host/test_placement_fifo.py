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
