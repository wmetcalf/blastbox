"""Deterministic IOC extraction from strings (no model involved)."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
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
_EMAIL = re.compile(rf"\b[\w.+-]+@((?:[A-Za-z0-9-]+\.)+(?:{_TLDS}))\b", re.I)
_DOMAIN = re.compile(rf"(?<![\w@.-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{{0,61}}[A-Za-z0-9])?\.)+(?:{_TLDS}))\b", re.I)
_REG = re.compile(r"\b(?:HKEY_[A-Z_]+|HK(?:LM|CU|CR|U|CC))\\[^\r\n\"'<>|]*[^\s\"'<>|\\]", re.I)
_PATH = re.compile(r"\b[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n\s]+\\)*[^\\/:*?\"<>|\r\n\s]+")
_MUTEX = re.compile(r"\b(?:Global|Local)\\[\w.{}\-]+")
_URL_HOST = re.compile(r"^[a-z]+://(?:[^/@]*@)?(\[[^\]]+\]|[^/:?#]+)", re.I)


@dataclass
class Ioc:
    type: IocType
    value: str
    source: str


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
        found += [("email", m.group(0)) for m in _EMAIL.finditer(rest)]
        found += [("domain", m.group(1).lower()) for m in _EMAIL.finditer(rest)]
        no_email = _EMAIL.sub(" ", rest)
        found += [("registry", m.group(0).rstrip()) for m in _REG.finditer(no_email)]
        no_reg = _REG.sub(" ", no_email)
        found += [("mutex", m.group(0)) for m in _MUTEX.finditer(no_reg)]
        found += [("path", m.group(0)) for m in _PATH.finditer(no_reg)]
        no_path = _PATH.sub(" ", no_reg)
        found += [("domain", m.group(1).lower()) for m in _DOMAIN.finditer(no_path)]
        found += [("ipv4", m.group(0)) for m in _IPV4.finditer(text)]
        found += [("ipv6", v) for v in _ipv6s(text)]
        for t, v in found:
            if not add(t, v, src):
                return out
    return out
