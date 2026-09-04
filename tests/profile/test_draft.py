"""Deterministic tests for PolicyDraft union, analysis, and emitters."""

from blastbox.profile import NetDraft, PolicyDraft


def _draft(**kw):
    d = PolicyDraft()
    for k, v in kw.items():
        setattr(d, k, v)
    return d


def test_union_accumulates():
    a = _draft(syscalls={"openat", "mmap"}, read_paths={"/usr/lib/a"})
    b = _draft(syscalls={"mmap", "futex"}, write_paths={"/tmp/x"})
    b.net = NetDraft(unix=True)
    a |= b
    assert a.syscalls == {"openat", "mmap", "futex"}
    assert a.read_paths == {"/usr/lib/a"} and a.write_paths == {"/tmp/x"}
    assert a.net.unix is True


def test_denylist_violations():
    d = _draft(syscalls={"openat", "mmap", "read", "write"})
    assert d.denylist_violations({"ptrace", "bpf"}) == set()  # safe
    assert d.denylist_violations({"mmap", "ptrace"}) == {"mmap"}  # violation


def test_grant_roots_collapses():
    d = _draft(read_paths={"/usr/lib/x/y", "/usr/share/z"}, write_paths={"/tmp/a/b"})
    assert d.grant_roots(depth=2) == ["/tmp/a", "/usr/lib", "/usr/share"]


def test_emitters_shape():
    d = _draft(syscalls={"openat", "mmap"}, read_paths={"/usr/lib/a"})
    kafel = d.to_kafel("soffice")
    assert "POLICY soffice" in kafel and "openat" in kafel and "DEFAULT KILL" in kafel
    oci = d.to_oci_seccomp()
    assert oci["defaultAction"] == "SCMP_ACT_ERRNO"
    assert sorted(oci["syscalls"][0]["names"]) == ["mmap", "openat"]
    nono = d.to_nono_profile("soffice")
    assert nono["network"]["block"] is True  # no inet -> block safe
    assert "/usr/lib" in nono["filesystem"]["read"]


def test_nono_profile_unblocks_when_egress_seen():
    d = PolicyDraft()
    d.net.inet.add(("1.2.3.4", 443))
    assert d.to_nono_profile()["network"]["block"] is False


def test_nono_profile_conforms_to_schema_fields():
    """meta/network only carry keys nono's schema accepts (no free-form _comment)."""
    p = PolicyDraft().to_nono_profile("eng")
    assert set(p["meta"]) <= {"name", "version", "description", "author"}
    assert set(p["network"]) <= {"block", "network_profile", "allow_domain"}
    assert "_comment" not in str(p)  # the bug nono's validator rejected
