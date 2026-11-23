"""YARA signature matching (YARA-X) for the sweep's signature step, and the image-build rule compile.

THIS FILE RUNS AS A STANDALONE SCRIPT under the yara venv's python (``/opt/yara``, a hash-locked
wheel venv holding only ``yara-x``), as a bounded subprocess (``signatures.scan``: ``ulimit -d``,
``-t`` and ``-f 0``, a wall-clock timeout, a stdout cap). It imports only the standard library and
``yara_x``. Nothing it reads is executed: YARA-X matches bytes against the compiled rules.

    python -I signatures_runner.py compile <rules_dir> <out_file> <min_rules>
    python -I signatures_runner.py scan <rules_file> <max_bytes> <per_target_s> <path>...

``compile`` (image build only) compiles every ``*.yar`` file of ``rules_dir`` (CAPE's rule set) on
its own first, skips each file that does not compile, compiles the rest into one rule set (one
namespace per file, so two files may reuse a rule name) and serializes it to ``out_file``. It
prints ``{"files", "compiled_files", "rules", "skipped": [{"file", "error"}]}`` and exits 1 when
fewer than ``min_rules`` rules compiled.

``scan`` loads the serialized rules and scans each path in order (at most ``max_bytes`` of it,
from the start; YARA-X stops a target after ``per_target_s`` seconds). It writes JSON lines, each
flushed as soon as it is known, so a run killed at its wall clock still leaves the targets it
finished:

    {"rules_total": n}                                           first
    {"i": k, "size": n, "scanned": n, "matches": [{"rule", "namespace", "meta": {...},
      "patterns": [id, ...]}]}                                   one per finished target
    {"i": k, "error": "timeout" | "unreadable" | "scan_failed"}  a target that did not finish
    {"done": true}                                               last
    {"error": <reason>}                                          instead of everything, on setup failure

Every list and string is capped here (``MAX_*``) and again by the parent.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

MAX_RULE_FILES = 4096
MAX_RULE_FILE_BYTES = 4 * 1024 * 1024
MAX_MATCHES = 64  # rules per target
MAX_META = 16
MAX_PATTERNS = 8
MAX_TEXT = 256
MAX_ERROR = 300


def _out(doc: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(doc, ensure_ascii=True) + "\n")
    sys.stdout.flush()


def _short(text: str, n: int = MAX_TEXT) -> str:
    return text if len(text) <= n else text[: n - 3] + "..."


def _meta_value(value: Any) -> str | int | float | bool:
    if isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return _short(str(value))


def compile_rules(src_dir: Path, out_file: Path, min_rules: int) -> int:
    import yara_x  # type: ignore[import-not-found]  # the yara venv only

    files = sorted(p for p in src_dir.iterdir() if p.suffix == ".yar" and p.is_file())[:MAX_RULE_FILES]
    good: list[tuple[str, str, str]] = []
    skipped: list[dict[str, str]] = []
    for path in files:
        if path.stat().st_size > MAX_RULE_FILE_BYTES:
            skipped.append({"file": path.name, "error": "too large"})
            continue
        text = path.read_text("utf-8", "replace")
        namespace = path.stem
        probe = yara_x.Compiler(relaxed_re_syntax=True)
        probe.new_namespace(namespace)
        try:
            probe.add_source(text, origin=path.name)
            probe.build()
        except Exception as exc:  # yara_x.CompileError and anything else the compiler raises
            skipped.append({"file": path.name, "error": _short(" ".join(str(exc).split()), MAX_ERROR)})
            continue
        good.append((namespace, path.name, text))
    compiler = yara_x.Compiler(relaxed_re_syntax=True)
    for namespace, origin, text in good:
        compiler.new_namespace(namespace)
        compiler.add_source(text, origin=origin)
    rules = compiler.build()
    count = sum(1 for _ in rules)
    with open(out_file, "wb") as fh:
        rules.serialize_into(fh)
    _out({"files": len(files), "compiled_files": len(good), "rules": count, "skipped": skipped})
    return 0 if count >= min_rules else 1


def _match(rule: Any) -> dict[str, Any]:
    meta: dict[str, Any] = {}
    for key, value in list(rule.metadata)[:MAX_META]:
        meta[_short(str(key), 64)] = _meta_value(value)
    patterns = [_short(str(p.identifier), 64) for p in rule.patterns if p.matches][:MAX_PATTERNS]
    return {"rule": _short(str(rule.identifier)), "namespace": _short(str(rule.namespace)), "meta": meta,
            "patterns": patterns}


def scan(rules_file: Path, max_bytes: int, per_target_s: int, paths: list[str]) -> int:
    import yara_x  # type: ignore[import-not-found]  # the yara venv only

    try:
        with open(rules_file, "rb") as fh:
            rules = yara_x.Rules.deserialize_from(fh)
    except Exception as exc:
        _out({"error": _short(f"rules: {type(exc).__name__}: {exc}", MAX_ERROR)})
        return 1
    _out({"rules_total": sum(1 for _ in rules)})
    scanner = yara_x.Scanner(rules)
    scanner.set_timeout(max(1, per_target_s))
    for i, raw in enumerate(paths):
        try:
            fd = os.open(raw, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as fh:
                size = os.fstat(fh.fileno()).st_size
                data = fh.read(max_bytes)
        except OSError:
            _out({"i": i, "error": "unreadable"})
            continue
        try:
            result = scanner.scan(data)
        except yara_x.TimeoutError:
            _out({"i": i, "error": "timeout"})
            continue
        except Exception:
            _out({"i": i, "error": "scan_failed"})
            continue
        matches = [_match(r) for r in list(result.matching_rules)[:MAX_MATCHES]]
        _out({"i": i, "size": size, "scanned": len(data), "matches": matches})
    _out({"done": True})
    return 0


def main(argv: list[str]) -> int:
    try:
        if len(argv) == 5 and argv[1] == "compile":
            return compile_rules(Path(argv[2]), Path(argv[3]), int(argv[4]))
        if len(argv) >= 5 and argv[1] == "scan":
            return scan(Path(argv[2]), int(argv[3]), int(argv[4]), argv[5:])
    except ImportError:
        _out({"error": "yara_x is not installed"})
        return 1
    _out({"error": "usage: compile <rules_dir> <out_file> <min_rules> | scan <rules_file> <max_bytes> "
                   "<per_target_s> <path>..."})
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
