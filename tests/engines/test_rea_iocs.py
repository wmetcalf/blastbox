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


# --------------------------------------------- false positives (version quads, code symbols)
def test_version_quads_are_not_ipv4() -> None:
    noise = [
        ("ghidra:0x1400106c8", "1.0.0.0"),  # PE FileVersion value
        ("ghidra:0x2", "8.0.0.0"),  # .NET assembly version
        ("s", "System.Runtime, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"),
        ("s", "mscorlib, Version=4.0.0.0"),
        ("s", "build v6.3.9600.1"),
        ("s", "AssemblyVersion"), ("s", "2.1.3.4"),  # a version-resource key, then its value
    ]
    assert [i for i in extract_iocs(noise) if i.type == "ipv4"] == []


def test_real_addresses_still_extracted() -> None:
    real = [
        ("ghidra:0x1", "185.220.101.47"),  # standalone C2 config string
        ("s", "connect 45.33.2.17:443"),
        ("s", "srv=91.215.85.0"),  # a .0 host is kept; only N.N.0.0 is version-shaped
        ("s", "dev 10.1.2.3"),  # "dev" is no "v" prefix
        ("s", "185.1.0.0"),  # three-digit first octet: not a version
        ("s", "FileDescription"), ("s", "203.0.113.7"),  # previous string is no version key
    ]
    got = {i.value for i in extract_iocs(real) if i.type == "ipv4"}
    assert got == {"185.220.101.47", "45.33.2.17", "91.215.85.0", "10.1.2.3", "185.1.0.0", "203.0.113.7"}


def test_go_symbols_are_not_domains() -> None:
    noise = [
        ("ghidra:0x1", "runtime.link"),
        ("ghidra:0x2", "godebugs.Info"),
        ("ghidra:0x3", "runtime.work"),
        ("ghidra:0x4", "internal/godebugs.info"),
        ("ghidra:0x5", "sync.top bufio.site reflect.app"),
        ("ghidra:0x6", "vendor/golang.org/x/net/dns/dnsmessage"),  # package path, not a host
        ("ghidra:0x7", "main.Info"),  # pkg.Member shape
    ]
    assert [i for i in extract_iocs(noise) if i.type == "domain"] == []


def test_real_domains_still_extracted() -> None:
    real = [
        ("s", "beacon to cdn-update.info"),
        ("s", "loadout-go-fixture.example.org"),
        ("s", "mail.ru"),  # "mail" is a Go package too, but deliberately not in the symbol list
        ("s", "time.com and github.com/user/repo"),
        ("s", "//evil.link/x"),  # protocol-relative, not a package path
        ("s", "Example.COM"),
        ("s", "GET https://runtime.link/stage2"),  # in a URL the host is always kept
        ("s", "ops@runtime.work"),  # and in an email
    ]
    got = {i.value for i in extract_iocs(real) if i.type == "domain"}
    assert got == {"cdn-update.info", "loadout-go-fixture.example.org", "mail.ru", "time.com", "github.com",
                   "evil.link", "example.com", "runtime.link", "runtime.work"}


def test_utf16le_urls() -> None:
    from blastbox.engines.rea.iocs import utf16le_urls

    url = "https://loadout-dotnet-fixture.example.net/api/v1"
    blob = b"\x00" * 7 + b"\x63" + url.encode("utf-16-le") + b"\x00\x2bG\x00l\x00"
    blob += "ftp://files.example/x".encode("utf-16-le") + b"\x00\x00"
    blob += b"https://ascii.example/"  # narrow strings are Ghidra's job, not this scan
    got = utf16le_urls(blob)
    assert got == [("utf16le:0x8", url), (f"utf16le:{8 + 2 * len(url) + 6:#x}", "ftp://files.example/x")]
    assert len(utf16le_urls("http://a.example/ ".encode("utf-16-le") * 50, limit=3)) == 3
    assert utf16le_urls(b"") == []


# ------------------------------------------------------------- G1: inspect-output false positives


def test_certificate_oids_are_not_ipv4() -> None:
    cert = "inspect:inspect-pe-certificates"
    rows = [(cert, o) for o in ("2.5.4.6", "2.5.4.10", "2.5.4.3", "2.5.4.8", "2.5.4.7", "203.0.113.9")]
    assert not [i for i in extract_iocs(rows) if i.type == "ipv4"]


def test_oid_arcs_are_dropped_from_any_source() -> None:
    rows = [("ghidra:0x1", o) for o in ("2.5.4.3", "1.2.840.113", "1.3.6.1", "2.5.29.17")]
    rows.append(("ghidra:0x2", "C2 203.0.113.7"))
    assert [(i.type, i.value) for i in extract_iocs(rows)] == [("ipv4", "203.0.113.7")]


def test_certificate_inspect_still_yields_urls_and_domains() -> None:
    m = _by(extract_iocs([("inspect:inspect-pe-certificates", "http://crl.evil.example/ca.crl")]))
    assert ("url", "http://crl.evil.example/ca.crl") in m and ("domain", "crl.evil.example") in m


def test_go_module_paths_are_not_domains_but_strings_keep_them() -> None:
    go = "inspect:inspect-go-binary"
    rows = [(go, "github.com/foo/dropper"), (go, "golang.org/x/sys"), (go, "dl.evil.com")]
    assert not [i for i in extract_iocs(rows) if i.type == "domain"]
    m = _by(extract_iocs(rows + [("ghidra:0x500000", "fetch github.com now")]))
    assert m[("domain", "github.com")] == "ghidra:0x500000"


def test_go_binary_urls_are_still_reported() -> None:
    m = _by(extract_iocs([("inspect:inspect-go-binary", "https://evil.example/mod")]))
    assert ("url", "https://evil.example/mod") in m
