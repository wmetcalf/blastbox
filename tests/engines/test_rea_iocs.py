from blastbox.engines.rea.iocs import extract_iocs

INPUT = [
    ("ghidra:0x401000", "GET http://evil.example/a.php?x=1"),
    ("ghidra:0x402000", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
    ("s", "10.1.2.3 and 1.2.3.4"),
    ("s", "Global\\MyMutex_123"),
    ("s", "C:\\Users\\Public\\x.exe"),
    ("s", "a@b.example"),
    ("s", "version 1.2.3.4.5"),
]


def _by(iocs):  # type: ignore[no-untyped-def]
    return {(i.type, i.value): i.source for i in iocs}


def test_extracts_each_type() -> None:
    m = _by(extract_iocs(INPUT))
    assert m[("url", "http://evil.example/a.php?x=1")] == "ghidra:0x401000"
    assert m[("domain", "evil.example")] == "ghidra:0x401000"
    assert ("registry", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run") in m
    assert ("ipv4", "10.1.2.3") in m and ("ipv4", "1.2.3.4") in m
    assert ("mutex", "Global\\MyMutex_123") in m
    assert ("path", "C:\\Users\\Public\\x.exe") in m
    assert ("email", "a@b.example") in m


def test_no_ipv4_from_five_octets() -> None:
    assert not any(t == "ipv4" and v.startswith("1.2.3.4.") for t, v in _by(extract_iocs(INPUT)))
    assert ("ipv4", "2.3.4.5") not in _by(extract_iocs(INPUT))
    assert ("ipv4", "1.2.3.4") in _by(extract_iocs(INPUT))  # from the "10.1.2.3 and 1.2.3.4" line


def test_dedup_keeps_first_source() -> None:
    out = extract_iocs([("a", "http://x.example/"), ("b", "http://x.example/")])
    assert [i.source for i in out if i.type == "url"] == ["a"]


def test_limit_truncates() -> None:
    assert len(extract_iocs(INPUT, limit=3)) == 3


def test_ipv6() -> None:
    assert ("ipv6", "2001:db8::1") in _by(extract_iocs([("s", "connect 2001:db8::1 now")]))


def test_hostile_input_is_linear() -> None:
    import time

    for blob in ("a.a.a." * 170_000, "\\" * 1_000_000, "a." * 500_000, "x@a." * 250_000):
        t0 = time.monotonic()
        extract_iocs([("s", blob)])
        assert time.monotonic() - t0 < 2.0, blob[:8]
