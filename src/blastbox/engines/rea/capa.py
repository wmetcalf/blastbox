"""capa (github.com/mandiant/capa) over the sample, run by the sweep after Ghidra.

capa matches its rule set (``-r``, the pinned capa-rules release) against the features
vivisect (PE/ELF) or dnfile (.NET) extracts statically. The sample never runs. The result is a
list of capabilities ("encrypt data using RC4", "create process on Windows") with their ATT&CK
and MBC ids and the functions they matched in. Those are leads for the model, not findings: a
rule match is a pattern over the code, and capa has false positives.

``summarize`` reduces capa's JSON result document (``capa -j``) to that list:

* rules flagged ``lib`` or ``is_subscope_rule`` and rules without a namespace (building
  blocks such as "contain loop") are dropped, as capa's own default rendering drops them;
* every match address is mapped to the function that holds it, via the result's
  ``meta.analysis.layout`` (function -> matched basic blocks). An address outside the layout
  is kept as-is: function-scope matches are function starts already;
* vivisect and Ghidra may load the image at different bases (a PIE ELF: vivisect 0x2000000,
  Ghidra 0x100000), so the caller passes ``rebase``, which moves capa's VA into Ghidra's image;
* .NET matches are metadata tokens, not addresses, and become ``token:0x...`` strings that
  never reach the agent's todo seed.

The document is derived from a hostile sample (string features carry its bytes), so every
count and string is capped, and anything not shaped as expected is skipped.
"""

from __future__ import annotations

import bisect
from collections.abc import Callable
from typing import Any

MAX_RULES = 128
MAX_FUNCTIONS_PER_RULE = 8
MAX_IDS = 8
MAX_TEXT = 160
MAX_MATCHES_SCANNED = 4096

Rebase = Callable[[int], int]


def _text(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return value[:MAX_TEXT]


def _ids(entries: Any) -> list[str]:
    out: list[str] = []
    for e in entries if isinstance(entries, list) else []:
        i = _text(e.get("id")) if isinstance(e, dict) else None
        if i is not None and i not in out:
            out.append(i)
        if len(out) >= MAX_IDS:
            break
    return out


def _addr(node: Any) -> tuple[str, int] | None:
    """(``type``, ``value``) of a capa address object, for the two kinds the sweep uses."""
    if not isinstance(node, dict):
        return None
    t, v = node.get("type"), node.get("value")
    if t == "dn token offset" and isinstance(v, list) and v:  # [token, IL offset]
        t, v = "dn token", v[0]
    if t in ("absolute", "dn token") and isinstance(v, int) and not isinstance(v, bool) and v >= 0:
        return t, v
    return None


class _Layout:
    """Basic block -> function, from ``meta.analysis.layout.functions``."""

    def __init__(self, analysis: Any) -> None:
        pairs: list[tuple[int, int]] = []
        functions = analysis.get("layout", {}).get("functions") if isinstance(analysis, dict) else None
        for f in functions if isinstance(functions, list) else []:
            fa = _addr(f.get("address")) if isinstance(f, dict) else None
            if fa is None or fa[0] != "absolute":
                continue
            pairs.append((fa[1], fa[1]))
            blocks = f.get("matched_basic_blocks")
            for b in blocks if isinstance(blocks, list) else []:
                ba = _addr(b.get("address")) if isinstance(b, dict) else None
                if ba is not None and ba[0] == "absolute":
                    pairs.append((ba[1], fa[1]))
        pairs.sort()
        self._starts = [p[0] for p in pairs]
        self._func = [p[1] for p in pairs]

    def function_of(self, va: int) -> int:
        """The function holding ``va``: that of the nearest block or function start at or below it."""
        i = bisect.bisect_right(self._starts, va) - 1
        return self._func[i] if i >= 0 else va


def summarize(doc: Any, *, rebase: Rebase | None = None) -> list[dict[str, Any]]:
    """capa's JSON result document -> ``[{rule, namespace, attack, mbc, functions}]``.

    ``functions`` holds ``0x``-hex VAs (rebased, Ghidra's image) or ``token:0x...`` for .NET;
    file-scope rules have none. Rules with ATT&CK ids come first, then by namespace and name.
    """
    if not isinstance(doc, dict) or not isinstance(doc.get("rules"), dict):
        return []
    meta = doc.get("meta")
    layout = _Layout(meta.get("analysis") if isinstance(meta, dict) else None)
    out: list[dict[str, Any]] = []
    scanned = 0
    for name, rule in doc["rules"].items():
        if not isinstance(rule, dict) or not isinstance(rule.get("meta"), dict):
            continue
        m = rule["meta"]
        rname, ns = _text(name), _text(m.get("namespace"))
        if rname is None or ns is None or m.get("lib") or m.get("is_subscope_rule"):
            continue
        functions: list[str] = []
        matches = rule.get("matches")
        for match in matches if isinstance(matches, list) else []:
            scanned += 1
            if scanned > MAX_MATCHES_SCANNED or len(functions) >= MAX_FUNCTIONS_PER_RULE:
                break
            a = _addr(match[0]) if isinstance(match, list) and match else None
            if a is None:
                continue
            if a[0] == "dn token":
                label = f"token:{a[1]:#x}"
            else:
                va = layout.function_of(a[1])
                if rebase is not None:
                    va = rebase(va)
                if va < 0:
                    continue
                label = f"{va:#x}"
            if label not in functions:
                functions.append(label)
        out.append({"rule": rname, "namespace": ns, "attack": _ids(m.get("attack")),
                    "mbc": _ids(m.get("mbc")), "functions": functions})
    out.sort(key=lambda r: (not r["attack"], r["namespace"], r["rule"]))
    return out[:MAX_RULES]


def base_address(doc: Any) -> int | None:
    """capa's image base (``meta.analysis.base_address``), when it is an absolute address."""
    meta = doc.get("meta") if isinstance(doc, dict) else None
    analysis = meta.get("analysis") if isinstance(meta, dict) else None
    a = _addr(analysis.get("base_address")) if isinstance(analysis, dict) else None
    return a[1] if a is not None and a[0] == "absolute" else None
