"""Deterministic IOC extraction from strings (no model involved)."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Buffer, Iterable
from dataclasses import dataclass
from typing import Literal

IocType = Literal["url", "domain", "ipv4", "ipv6", "email", "registry", "path", "mutex"]

# Bare domains are only reported under well-known TLDs, so "x.exe"/"a.dll" are not domains.
_TLDS = (
    "com|net|org|info|biz|io|ru|cn|top|xyz|site|online|club|tk|ml|ga|cf|gq|cc|co|me|us|uk|de|fr|"
    "nl|br|in|jp|kr|ir|su|ua|pl|it|es|eu|ch|se|no|fi|cz|tv|ws|pw|ink|live|shop|app|dev|cloud|"
    "link|click|work|icu|vip|asia|mobi|onion|example"
)
_OCT = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_URL = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>\\^`{|}]+", re.I)
_IPV4 = re.compile(rf"(?<![\d.])(?:{_OCT}\.){{3}}{_OCT}(?!\d)(?!\.\d)")
_IPV6_CAND = re.compile(r"(?<![\w:.])[0-9A-Fa-f:]{3,45}(?![\w:])")
_EMAIL_LOCAL = re.compile(r"[\w.+-]{1,64}$")
_EMAIL_DOMAIN = re.compile(rf"((?:[A-Za-z0-9-]{{1,63}}\.){{1,8}}(?:{_TLDS}))\b", re.I)
_DOMAIN = re.compile(rf"(?<![\w@.-])((?:[A-Za-z0-9-]{{1,63}}\.){{1,8}}(?:{_TLDS}))\b", re.I)
_REG = re.compile(r"\b(?:HKEY_[A-Z_]+|HK(?:LM|CU|CR|U|CC))\\[^\r\n\"'<>|]*[^\s\"'<>|\\]", re.I)
_PATH = re.compile(r"\b[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n\s]+\\)*[^\\/:*?\"<>|\r\n\s]+")
_MUTEX = re.compile(r"\b(?:Global|Local)\\[\w.{}\-]+")
_URL_HOST = re.compile(r"^[a-z]+://(?:[^/@]*@)?(\[[^\]]+\]|[^/:?#]+)", re.I)

# --- false-positive suppression (conservative: each rule needs a symbol- or version-specific shape)
# Version numbers look like dotted quads: assembly/file versions ("1.0.0.0", "8.0.0.0") and
# "Version=4.0.0.0" in .NET assembly-qualified names.
_VERSION_BEFORE = re.compile(r"\b(?:version|ver|v)\s*[=:]?\s*$", re.I)
_VERSION_AFTER = re.compile(r"^\s*,\s*(?:culture|publickeytoken)\b", re.I)
_VERSION_KEYS = frozenset({
    "fileversion", "productversion", "assemblyversion", "assembly version", "assemblyfileversion",
    "assemblyinformationalversion", "version",
})
# Go runtime/standard-library package names that are never hostnames in practice. Names that
# double as real hosts (mail, time, list, net, http, image, json, go, ...) are left out.
_GO_PKGS = frozenset({
    "runtime", "godebugs", "godebug", "internal", "reflect", "syscall", "strconv", "unicode",
    "bytealg", "goarch", "goos", "abi", "atomic", "unsafe", "cgo", "itoa", "poll", "testlog",
    "sysinfo", "bufio", "slices", "maps", "unique", "weak", "structs", "errors", "fmt", "strings",
    "bytes", "sync", "filepath", "utf8", "utf16", "pprof", "metrics", "coverage", "chacha8rand",
    "stringslite", "routebsd", "singleflight", "goexperiment", "buildcfg", "ioutil", "textproto",
})


@dataclass
class Ioc:
    type: IocType
    value: str
    source: str


def _emails(text: str) -> tuple[list[tuple[str, str]], str]:
    """Find emails by locating '@' first (bounded windows keep this linear on hostile input).

    Returns ((email, domain) pairs, text with the matched emails blanked out).
    """
    found: list[tuple[str, str]] = []
    spans: list[tuple[int, int]] = []
    i = text.find("@")
    while i != -1 and len(found) < 4096:
        lm = _EMAIL_LOCAL.search(text, max(0, i - 64), i)
        dm = _EMAIL_DOMAIN.match(text, i + 1)
        if lm and dm and (lm.start() == 0 or not (text[lm.start() - 1].isalnum() or text[lm.start() - 1] == "_")):
            found.append((text[lm.start() : dm.end()], dm.group(1)))
            spans.append((lm.start(), dm.end()))
        i = text.find("@", i + 1)
    parts, last = [], 0
    for a, b in spans:
        parts += [text[last:a], " "]
        last = b
    parts.append(text[last:])
    return found, "".join(parts)


def _version_quad(text: str, start: int, end: int, prev: str) -> bool:
    """A dotted quad that is a version number, not an address.

    ``N.N.0.0`` with a one- or two-digit major (``1.0.0.0``, ``8.0.0.0``, ``4.5.0.0``) is the
    assembly/file version shape; as a host it would be a /16 network address. Otherwise only an explicit version context counts:
    ``Version=``/``v`` right before it, ``, Culture=``/``, PublicKeyToken=`` right after it, or a
    preceding string that is a version-resource key (``FileVersion`` then ``1.2.3.4``).
    """
    quad = text[start:end]
    if quad.endswith(".0.0") and len(quad.split(".", 1)[0]) <= 2:
        return True
    if _VERSION_BEFORE.search(text, max(0, start - 16), start) or _VERSION_AFTER.match(text[end:end + 32]):
        return True
    return text.strip() == quad and prev.strip().lower() in _VERSION_KEYS


def _symbol_domain(text: str, start: int, end: int) -> bool:
    """A bare "domain" that is a code symbol: Go ``runtime.link``/``godebugs.Info``, a Go
    package path (``internal/godebugs.info``), or a ``pkg.Member`` reference (lowercase package,
    capitalised member). Domains in URLs and email addresses never pass through here."""
    value = text[start:end]
    labels = value.split(".")
    if labels[0].lower() in _GO_PKGS:
        return True
    if start > 0 and text[start - 1] == "/" and not (start > 1 and text[start - 2] == "/"):
        return True
    tld = labels[-1]
    return (len(labels) == 2 and labels[0].islower() and tld[:1].isupper() and tld[1:].islower())


def _ipv6s(text: str) -> list[str]:
    out = []
    for m in _IPV6_CAND.finditer(text):
        c = m.group(0)
        if c.count(":") < 2:
            continue
        try:
            ipaddress.IPv6Address(c)
        except ValueError:
            continue
        out.append(c)
    return out


def extract_iocs(strings: Iterable[tuple[str, str]], *, limit: int = 2048) -> list[Ioc]:
    """``strings`` is ``(source, text)``. Dedup by (type, value), first source wins."""
    seen: set[tuple[str, str]] = set()
    out: list[Ioc] = []

    def add(t: IocType, v: str, src: str) -> bool:
        if (t, v) in seen:
            return True
        seen.add((t, v))
        out.append(Ioc(t, v, src))
        return len(out) < limit

    prev = ""
    for src, text in strings:
        found: list[tuple[IocType, str]] = []
        urls = [u.rstrip(".,;)") for u in (m.group(0) for m in _URL.finditer(text))]
        for u in urls:
            found.append(("url", u))
            hm = _URL_HOST.match(u)
            if hm:
                host = hm.group(1).strip("[]")
                if re.fullmatch(rf"(?:[A-Za-z0-9-]+\.)+(?:{_TLDS})", host, re.I):
                    found.append(("domain", host.lower()))
        rest = _URL.sub(" ", text)
        emails, no_email = _emails(rest)
        found += [("email", e) for e, _d in emails]
        found += [("domain", d.lower()) for _e, d in emails]
        found += [("registry", m.group(0).rstrip()) for m in _REG.finditer(no_email)]
        no_reg = _REG.sub(" ", no_email)
        found += [("mutex", m.group(0)) for m in _MUTEX.finditer(no_reg)]
        found += [("path", m.group(0)) for m in _PATH.finditer(no_reg)]
        no_path = _PATH.sub(" ", no_reg)
        found += [("domain", m.group(1).lower()) for m in _DOMAIN.finditer(no_path)
                  if not _symbol_domain(no_path, m.start(1), m.end(1))]
        found += [("ipv4", m.group(0)) for m in _IPV4.finditer(text)
                  if not _version_quad(text, m.start(), m.end(), prev)]
        found += [("ipv6", v) for v in _ipv6s(text)]
        prev = text
        for t, v in found:
            if not add(t, v, src):
                return out
    return out


_UTF16_URL = re.compile(
    rb"(?:h\x00t\x00t\x00p\x00(?:s\x00)?|f\x00t\x00p\x00):\x00/\x00/\x00(?:[\x21-\x7e]\x00){1,2048}",
    re.I)


def utf16le_urls(data: Buffer, *, limit: int = 1024) -> list[tuple[str, str]]:
    """``(source, url)`` for UTF-16LE URL strings in raw bytes, e.g. a .NET ``#US`` heap.

    Ghidra defines no string for these, so the sweep scans the sample itself. Only the
    ``scheme://`` shape is matched: a general UTF-16 string dump would bring every resource
    string with it. ``source`` is ``utf16le:0x<offset>``.
    """
    out: list[tuple[str, str]] = []
    for m in _UTF16_URL.finditer(data):
        out.append((f"utf16le:{m.start():#x}", m.group(0).decode("utf-16-le")))
        if len(out) >= limit:
            break
    return out
