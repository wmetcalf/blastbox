"""Authenticating a node AT THE HAND-OVER POINT (#178).

The property under test throughout: the server decides whether this caller may run this
job BEFORE the caller receives the input, and it decides from the caller's certificate
plus a proof of key possession -- never from anything the caller asserts about itself.

Why not mTLS: `issue_node` stamps a CRITICAL private EKU (``OID_NODE_AUTH``) and
deliberately never ``clientAuth``, because `tls.py` verifies the CA chain only -- so a
node cert carrying ``clientAuth`` would be accepted by every worker AS THE DISPATCHER'S.
OpenSSL's client-purpose check rejects a node cert outright
(``SSLV3_ALERT_UNSUPPORTED_CERTIFICATE``), which is the pki module working as designed.
So possession is proved one layer up, and the EKU is checked here -- exactly what
``OID_NODE_AUTH``'s own comment says the control plane should do.
"""
from __future__ import annotations

import pytest

from blastbox.host import pki
from blastbox.host.node_auth import (
    CHALLENGE_TTL_S,
    ClaimRefused,
    admit,
    challenge_for,
    sign_claim,
)

WG = "A" * 42 + "B="
SECRET = b"a server secret, shared by every ingress worker"


@pytest.fixture
def fleet(tmp_path):
    """A CA, and two nodes granted different engines."""
    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    ca.issue_node("alpha", wg_pubkey=WG, grants=pki.NodeGrants(
        engines=("clamav",), tiers=("socks",))).write(d, "node-alpha")
    ca.issue_node("beta", wg_pubkey=WG, grants=pki.NodeGrants(
        engines=("boxjs",))).write(d, "node-beta")
    return d, ca, pki.load_trust_anchor(d)


def _claim(fleet, who, *, scope="job-1", engine="clamav", sign_as=None,
           challenge=None, secret=SECRET, now=None, **kw):
    """Present *who*'s certificate, signed by *sign_as* (default: the same node)."""
    d, _ca, anchor = fleet
    ch = challenge if challenge is not None else challenge_for(scope, secret=SECRET, now=now)
    signer = sign_as or who
    sig = sign_claim((d / f"node-{signer}.key").read_bytes(), ch, scope, who)
    return admit(anchor, (d / f"node-{who}.crt").read_bytes(), challenge=ch,
                 scope=scope, signature=sig, secret=secret, engine=engine, now=now, **kw)


def test_a_granted_node_is_admitted(fleet):
    assert _claim(fleet, "alpha", engine="clamav").node_id == "alpha"


def test_an_ungranted_engine_is_refused_before_the_input_moves(fleet):
    with pytest.raises(ClaimRefused) as e:
        _claim(fleet, "alpha", engine="boxjs")
    assert "boxjs" in str(e.value) and "clamav" in str(e.value), "say what IS granted"


def test_each_node_is_admitted_for_its_own_grant_only(fleet):
    assert _claim(fleet, "beta", engine="boxjs").node_id == "beta"
    with pytest.raises(ClaimRefused):
        _claim(fleet, "beta", engine="clamav")


def test_presenting_a_peers_certificate_without_its_key_is_refused(fleet):
    """THE #178 PROPERTY. A node that can read another node's .crt -- they sit in the same
    pki dir on the exit host -- must not inherit its grants. Only the key proves identity."""
    with pytest.raises(ClaimRefused) as e:
        _claim(fleet, "alpha", engine="clamav", sign_as="beta")
    assert "possession" in str(e.value).lower() or "signature" in str(e.value).lower()


def test_a_signature_is_bound_to_its_challenge(fleet):
    d, _ca, anchor = fleet
    good = challenge_for("job-1", secret=SECRET)
    sig = sign_claim((d / "node-alpha.key").read_bytes(), good, "job-1", "alpha")
    other = challenge_for("job-1", secret=SECRET, now=1.0)
    with pytest.raises(ClaimRefused):
        admit(anchor, (d / "node-alpha.crt").read_bytes(), challenge=other, scope="job-1",
              signature=sig, secret=SECRET, engine="clamav")


def test_a_signature_harvested_for_one_job_cannot_claim_another(fleet):
    """One admitted claim must not be a reusable ticket for every job the node is granted.

    WHERE THIS IS ENFORCED: the challenge MAC covers the job id, so presenting job-1's
    challenge for job-2 fails as unrecognised -- which is why removing scope from
    `signing_payload` does NOT fail this test (measured). The payload's job id is
    redundant defence in depth for a future challenge that is not job-scoped;
    `test_the_signed_payload_binds_all_three` is what defends it."""
    d, _ca, anchor = fleet
    ch = challenge_for("job-1", secret=SECRET)
    sig = sign_claim((d / "node-alpha.key").read_bytes(), ch, "job-1", "alpha")
    with pytest.raises(ClaimRefused):
        admit(anchor, (d / "node-alpha.crt").read_bytes(), challenge=ch, scope="job-2",
              signature=sig, secret=SECRET, engine="clamav")


def test_the_signed_payload_binds_all_three(fleet):
    """challenge, job and node all inside the signature, and each one changes it."""
    from blastbox.host.node_auth import signing_payload

    base = signing_payload("chal", "job-1", "alpha")
    assert base != signing_payload("other", "job-1", "alpha"), "challenge not bound"
    assert base != signing_payload("chal", "job-2", "alpha"), "job not bound"
    assert base != signing_payload("chal", "job-1", "beta"), "node not bound"
    # Field separation: "a" + "bc" must not collide with "ab" + "c".
    assert signing_payload("a", "bc", "n") != signing_payload("ab", "c", "n")


def test_a_challenge_for_one_job_does_not_open_another(fleet):
    with pytest.raises(ClaimRefused) as e:
        _claim(fleet, "alpha", scope="job-2",
               challenge=challenge_for("job-1", secret=SECRET))
    assert "challenge" in str(e.value).lower()


def test_an_expired_challenge_is_refused(fleet):
    ch = challenge_for("job-1", secret=SECRET, now=1000.0)
    with pytest.raises(ClaimRefused) as e:
        _claim(fleet, "alpha", challenge=ch, now=1000.0 + CHALLENGE_TTL_S + 1)
    assert "expire" in str(e.value).lower()


def test_a_challenge_this_server_did_not_issue_is_refused(fleet):
    """Forged, or minted by a different deployment. The MAC is the whole check."""
    forged = challenge_for("job-1", secret=b"not this server's secret")
    with pytest.raises(ClaimRefused) as e:
        _claim(fleet, "alpha", challenge=forged)
    assert "challenge" in str(e.value).lower()


def test_a_dispatcher_client_certificate_cannot_claim_as_a_node(fleet):
    """A dispatcher CLIENT cert is CA-signed and unexpired. It is not a node."""
    d, ca, anchor = fleet
    client = ca.issue_client("dispatcher")
    client.write(d, "dispatcher")
    ch = challenge_for("job-1", secret=SECRET)
    sig = sign_claim((d / "dispatcher.key").read_bytes(), ch, "job-1", "dispatcher")
    with pytest.raises(ClaimRefused):
        admit(anchor, client.cert_pem, challenge=ch, scope="job-1", signature=sig,
              secret=SECRET, engine="clamav")


def test_a_node_shaped_cert_carrying_clientauth_is_refused(fleet):
    """A cert that satisfies everything EXCEPT the node EKU is still refused.

    This is the escalation shape OID_NODE_AUTH exists to prevent: the node-info extension
    present (so it looks like a node) but stamped ``clientAuth`` (so it is ALSO usable as
    a TLS client cert, and `tls.py` verifies the CA chain only -- every worker would
    accept it as the dispatcher's). Nothing in the CA's public surface mints one today,
    so it is built with the CA key directly.

    WHERE IT IS ENFORCED: inside `pki.node_identity`, which requires OID_NODE_AUTH before
    reading the grants. `admit` deliberately does NOT re-check it -- a copy of that check
    was written into `admit` first and mutation testing proved it dead code (deleting it
    failed nothing), so it was removed rather than left to rot as a second authority."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    from blastbox.host.pki import OID_NODE_INFO, _node_info_bytes, load_ca

    d, _ca, anchor = fleet
    ca = load_ca(d)
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "impostor")]))
        .issuer_name(x509.load_pem_x509_certificate(ca.cert_pem).subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        # clientAuth, NOT the private node EKU: the escalation shape.
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                       critical=True)
        .add_extension(x509.UnrecognizedExtension(
            OID_NODE_INFO,
            _node_info_bytes("impostor", WG, pki.NodeGrants(engines=("clamav",)))),
            critical=False)
        .sign(serialization.load_pem_private_key(ca.key_pem, password=None),
              hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    # Signed by the real CA, unexpired, carries node-info: only the EKU is wrong.
    with pytest.raises(ValueError, match="node extended key usage"):
        pki.node_identity(anchor, cert_pem)
    ch = challenge_for("job-1", secret=SECRET)
    sig = sign_claim(key_pem, ch, "job-1", "impostor")
    with pytest.raises(ClaimRefused) as e:
        admit(anchor, cert_pem, challenge=ch, scope="job-1", signature=sig,
              secret=SECRET, engine="clamav")
    assert "node" in str(e.value).lower()


def test_a_foreign_cas_node_certificate_is_refused(fleet, tmp_path):
    _d, _ca, anchor = fleet
    rogue_dir = tmp_path / "rogue"
    rogue = pki.ensure_ca(rogue_dir)
    rogue.issue_node("alpha", wg_pubkey=WG, grants=pki.NodeGrants(
        engines=("clamav", "boxjs"))).write(rogue_dir, "node-alpha")
    ch = challenge_for("job-1", secret=SECRET)
    sig = sign_claim((rogue_dir / "node-alpha.key").read_bytes(), ch, "job-1", "alpha")
    with pytest.raises(ClaimRefused) as e:
        admit(anchor, (rogue_dir / "node-alpha.crt").read_bytes(), challenge=ch,
              scope="job-1", signature=sig, secret=SECRET, engine="clamav")
    assert "sign" in str(e.value).lower() or "ca" in str(e.value).lower()


def test_the_node_id_comes_from_the_certificate_not_the_request(fleet):
    """There is no request-supplied node id to disagree with the certificate: the payload
    is rebuilt from the VERIFIED identity, so claiming to be someone else cannot verify."""
    d, _ca, anchor = fleet
    ch = challenge_for("job-1", secret=SECRET)
    # beta signs a payload naming ALPHA, and presents beta's own (valid) certificate.
    sig = sign_claim((d / "node-beta.key").read_bytes(), ch, "job-1", "alpha")
    with pytest.raises(ClaimRefused):
        admit(anchor, (d / "node-beta.crt").read_bytes(), challenge=ch, scope="job-1",
              signature=sig, secret=SECRET, engine="boxjs")


def test_a_tier_grant_is_enforced_too(fleet):
    assert _claim(fleet, "alpha", engine="clamav", tier="socks").node_id == "alpha"
    with pytest.raises(ClaimRefused) as e:
        _claim(fleet, "alpha", engine="clamav", tier="wireguard")
    assert "wireguard" in str(e.value)


def test_credentials_are_enforced_too(fleet):
    with pytest.raises(ClaimRefused) as e:
        _claim(fleet, "alpha", engine="clamav", require_credentials=True)
    assert "credential" in str(e.value).lower()


def test_a_malformed_signature_is_a_refusal_not_a_crash(fleet):
    d, _ca, anchor = fleet
    ch = challenge_for("job-1", secret=SECRET)
    with pytest.raises(ClaimRefused):
        admit(anchor, (d / "node-alpha.crt").read_bytes(), challenge=ch, scope="job-1",
              signature=b"not a signature", secret=SECRET, engine="clamav")


def test_a_malformed_certificate_is_a_refusal_not_a_crash(fleet):
    _d, _ca, anchor = fleet
    ch = challenge_for("job-1", secret=SECRET)
    with pytest.raises(ClaimRefused):
        admit(anchor, b"-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n",
              challenge=ch, scope="job-1", signature=b"x", secret=SECRET, engine="clamav")


def test_a_malformed_challenge_is_a_refusal_not_a_crash(fleet):
    for bad in ("", "no-separator", "abc:def", "1:", ":abc", "1e9:zz"):
        with pytest.raises(ClaimRefused):
            _claim(fleet, "alpha", challenge=bad)


class TestTheChallengeSecretIsSharedNotPerProcess:
    """Ingress forks (``workers>1``). A per-process secret would mint challenges that every
    other worker rejects as forged -- a load-dependent intermittent failure."""

    def test_it_is_created_on_first_use(self, tmp_path):
        from blastbox.host.node_auth import SECRET_FILE, challenge_secret

        s = challenge_secret(tmp_path)
        assert len(s) >= 32
        assert (tmp_path / SECRET_FILE).exists()

    def test_it_is_stable_across_calls(self, tmp_path):
        from blastbox.host.node_auth import challenge_secret

        assert challenge_secret(tmp_path) == challenge_secret(tmp_path)

    def test_two_directories_get_different_secrets(self, tmp_path):
        from blastbox.host.node_auth import challenge_secret

        a, b = tmp_path / "a", tmp_path / "b"
        a.mkdir()
        b.mkdir()
        assert challenge_secret(a) != challenge_secret(b)

    def test_it_is_not_world_readable(self, tmp_path):
        import stat

        from blastbox.host.node_auth import SECRET_FILE, challenge_secret

        challenge_secret(tmp_path)
        mode = (tmp_path / SECRET_FILE).stat().st_mode
        assert not mode & stat.S_IRGRP and not mode & stat.S_IROTH, oct(mode)

    def test_concurrent_first_use_agrees_on_one_secret(self, tmp_path):
        """The shape claim_blob_target exists to defend: both see no file, both generate.
        Exactly one may win, and the loser must adopt the winner's bytes -- not its own."""
        import threading

        from blastbox.host.node_auth import challenge_secret

        out, barrier = [], threading.Barrier(8)

        def go():
            barrier.wait()
            out.append(challenge_secret(tmp_path))

        threads = [threading.Thread(target=go) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(out) == 8
        assert len(set(out)) == 1, "workers disagreed about the challenge secret"

    def test_a_loser_never_observes_a_half_written_secret(self, monkeypatch, tmp_path):
        """DETERMINISTIC version of the test above, and the one that actually defends this.

        The plain barrier race catches the defect only ~3 runs in 10 (measured), which is
        the weak-test class this repo has been bitten by before: `fix-pool-deferred-reap`
        recorded a single-reaper test that caught its regression ~10% of runs. So the
        interleaving is FORCED rather than hoped for -- the key generation is made slow, so
        every loser is guaranteed to read while the winner is still mid-write.

        Against the correct implementation (write a private temp file, then link it into
        place) a slow write changes nothing: the real path never exists incomplete. Against
        the obvious-but-wrong shape -- O_EXCL on the real path, then write -- the losers
        read an EMPTY published file and raise "interrupted first write". Mutation-checked
        at 10/10 runs, where the hopeful version managed 3/10."""
        import secrets as _secrets
        import threading
        import time as _time

        from blastbox.host.node_auth import challenge_secret

        real = _secrets.token_bytes

        def slow_token_bytes(n):
            _time.sleep(0.25)           # wide enough that no loser can miss the window
            return real(n)

        monkeypatch.setattr(_secrets, "token_bytes", slow_token_bytes)

        out, errors, barrier = [], [], threading.Barrier(8)

        def go():
            barrier.wait()
            try:
                out.append(challenge_secret(tmp_path))
            except Exception as exc:    # noqa: BLE001 - the failure IS the assertion
                errors.append(exc)

        threads = [threading.Thread(target=go) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors, f"a loser saw an incomplete secret: {errors!r}"
        assert len(set(out)) == 1, "workers disagreed about the challenge secret"

    def test_a_truncated_secret_raises_rather_than_being_padded(self, tmp_path):
        """An interrupted first write. Regenerating would invalidate challenges the other
        workers already minted; padding would serve whatever the partial write chose."""
        import pytest as _pytest

        from blastbox.host.node_auth import SECRET_FILE, challenge_secret

        (tmp_path / SECRET_FILE).write_bytes(b"\x01\x02\x03")
        with _pytest.raises(RuntimeError, match="interrupted first write"):
            challenge_secret(tmp_path)

    def test_a_challenge_minted_under_one_secret_fails_under_another(self, tmp_path, fleet):
        """Proves the secret is actually what binds a challenge to this deployment."""
        import pytest as _pytest

        from blastbox.host.node_auth import (
            SCOPE_CLAIM_NEXT,
            ClaimRefused,
            admit,
            challenge_for,
            challenge_secret,
            sign_claim,
        )

        d, _ca, anchor = fleet
        a, b = tmp_path / "a", tmp_path / "b"
        a.mkdir()
        b.mkdir()
        ch = challenge_for(SCOPE_CLAIM_NEXT, secret=challenge_secret(a))
        sig = sign_claim((d / "node-alpha.key").read_bytes(), ch, SCOPE_CLAIM_NEXT, "alpha")
        with _pytest.raises(ClaimRefused):
            admit(anchor, (d / "node-alpha.crt").read_bytes(), challenge=ch,
                  scope=SCOPE_CLAIM_NEXT, signature=sig, secret=challenge_secret(b),
                  engine="clamav")


def test_a_node_cert_with_a_non_ec_key_is_refused_not_crashed(fleet):
    """The CA issues P-256 only, so any other key type did not come from `issue_node`.

    Verifying it would mean guessing which signature scheme the CALLER meant, and a scheme
    the caller chooses is not a check -- so this refuses rather than dispatching on it. It
    also must not surface as an AttributeError from inside `cryptography`, which a caller
    could use to distinguish "wrong key type" from "not granted"."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    from blastbox.host.pki import (
        OID_NODE_AUTH,
        OID_NODE_INFO,
        _node_info_bytes,
        load_ca,
    )

    d, _ca, anchor = fleet
    ca = load_ca(d)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rsanode")]))
        .issuer_name(x509.load_pem_x509_certificate(ca.cert_pem).subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([OID_NODE_AUTH]), critical=True)
        .add_extension(x509.UnrecognizedExtension(
            OID_NODE_INFO,
            _node_info_bytes("rsanode", WG, pki.NodeGrants(engines=("clamav",)))),
            critical=False)
        .sign(serialization.load_pem_private_key(ca.key_pem, password=None),
              hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    # It satisfies node_identity -- CA-signed, unexpired, node EKU, node-info present.
    assert pki.node_identity(anchor, cert_pem).node_id == "rsanode"
    ch = challenge_for("claim-next", secret=SECRET)
    with pytest.raises(ClaimRefused, match="elliptic-curve"):
        admit(anchor, cert_pem, challenge=ch, scope="claim-next",
              signature=b"whatever", secret=SECRET, engine="clamav")


class TestSessionTokens:
    """A token so the challenge-response is not paid per request. It names the node and
    NOTHING else -- the grants are re-resolved per request from the server's own
    certificate store, because a token carrying grants outlives the certificate it came
    from and quietly defeats "revocation is stop renewing"."""

    SECRET = b"the server's challenge key, 32 bytes at least ok"

    def test_a_token_round_trips_to_its_node_id(self):
        from blastbox.host.node_auth import issue_session, verify_session

        t = issue_session("alpha", secret=self.SECRET)
        assert verify_session(t, secret=self.SECRET) == "alpha"

    def test_a_token_from_another_server_is_refused(self):
        from blastbox.host.node_auth import ClaimRefused, issue_session, verify_session

        t = issue_session("alpha", secret=b"a different deployment's secret!!")
        with pytest.raises(ClaimRefused, match="not issued by this server"):
            verify_session(t, secret=self.SECRET)

    def test_an_expired_token_is_refused(self):
        from blastbox.host.node_auth import (
            SESSION_TTL_S,
            ClaimRefused,
            issue_session,
            verify_session,
        )

        t = issue_session("alpha", secret=self.SECRET, now=1000.0)
        with pytest.raises(ClaimRefused, match="expired"):
            verify_session(t, secret=self.SECRET, now=1000.0 + SESSION_TTL_S + 1)

    def test_the_node_id_cannot_be_edited(self):
        """The whole point: a node must not be able to rename itself into a peer's grants."""
        from blastbox.host.node_auth import ClaimRefused, issue_session, verify_session

        t = issue_session("alpha", secret=self.SECRET)
        _alpha, _, rest = t.partition(":")
        with pytest.raises(ClaimRefused):
            verify_session("beta:" + rest, secret=self.SECRET)

    def test_the_expiry_cannot_be_extended(self):
        from blastbox.host.node_auth import ClaimRefused, issue_session, verify_session

        t = issue_session("alpha", secret=self.SECRET, now=1000.0)
        node_id, _, rest = t.partition(":")
        _exp, _, mac = rest.partition(":")
        with pytest.raises(ClaimRefused):
            verify_session(f"{node_id}:{1e12!r}:{mac}", secret=self.SECRET)

    def test_a_token_does_not_carry_grants(self):
        """If the token ever starts carrying them, this test should fail and the design note
        in `issue_session` should be re-read before changing it."""
        from blastbox.host.node_auth import issue_session

        t = issue_session("alpha", secret=self.SECRET)
        for leak in ("clamav", "boxjs", "engine", "tier", "credential"):
            assert leak not in t

    @pytest.mark.parametrize("bad", ["", "nocolons", "a:b", "alpha::", ":1.0:mac",
                                     "alpha:notafloat:mac"])
    def test_a_malformed_token_is_a_refusal_not_a_crash(self, bad):
        from blastbox.host.node_auth import ClaimRefused, verify_session

        with pytest.raises(ClaimRefused):
            verify_session(bad, secret=self.SECRET)


class TestMultiHostIngress:
    """Challenges and session tokens are MACs under one key, so two ingress hosts with their
    own PKI directories mint credentials the other rejects. Behind a load balancer that is a
    handshake failing most of the time, presenting as a node problem."""

    def test_two_hosts_with_separate_keys_do_not_interoperate(self, tmp_path):
        """The failure this knob exists to prevent, pinned so it cannot be forgotten."""
        from blastbox.host.node_auth import (
            SCOPE_CLAIM_NEXT,
            ClaimRefused,
            challenge_for,
            challenge_secret,
            issue_session,
            verify_session,
        )

        a, b = tmp_path / "hostA", tmp_path / "hostB"
        a.mkdir()
        b.mkdir()
        tok = issue_session("alpha", secret=challenge_secret(a))
        with pytest.raises(ClaimRefused):
            verify_session(tok, secret=challenge_secret(b))
        assert challenge_for(SCOPE_CLAIM_NEXT, secret=challenge_secret(a)) != \
            challenge_for(SCOPE_CLAIM_NEXT, secret=challenge_secret(b))

    def test_pointing_both_hosts_at_one_key_makes_them_agree(self, tmp_path, monkeypatch):
        from blastbox.host.node_auth import (
            SECRET_FILE_ENV,
            challenge_secret,
            issue_session,
            verify_session,
        )

        a, b = tmp_path / "hostA", tmp_path / "hostB"
        a.mkdir()
        b.mkdir()
        monkeypatch.setenv(SECRET_FILE_ENV, str(tmp_path / "shared.key"))
        tok = issue_session("alpha", secret=challenge_secret(a))
        assert verify_session(tok, secret=challenge_secret(b)) == "alpha"

    def test_the_override_is_a_path_not_a_secret(self):
        """A secret on a command line or in a unit file is what this project refuses
        elsewhere; the variable must name a FILE."""
        from blastbox.host import node_auth

        assert node_auth.SECRET_FILE_ENV.endswith("_FILE")
