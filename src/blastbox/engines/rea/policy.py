"""Which REA MCP tools the model may call, and with which arguments.

``TOOL_ALLOWLIST`` is the 54 read-only analysis tools picked in the spike
(deploy/rea/SPIKE.md, ``_meta.proposed_tool_allowlist`` in tools-snapshot.json). It is a
literal here on purpose: the engine never derives authority from a file or from the server.

``TOOL_ARGS`` is the per-tool argument policy, written from the snapshot's input schemas:

- a ``path`` argument (the 12 static ``inspect_*`` tools) is never taken from the model; it
  is overwritten with the admitted sample path;
- addresses must match ``^(0x)?[0-9a-fA-F]{1,16}$``;
- strings are capped at 256 chars and may not contain ``..``, start with ``/``, or contain
  shell metacharacters or control characters;
- integers are range-checked, enums must match exactly, and unknown arguments are refused.

Object-typed arguments are not accepted (except ``get_evidence_bundle.filters``, which has a
closed schema). Tools whose required arguments are all object-typed (``build_call_path``,
``compare_functions``) stay on the allowlist but are withheld from the model (``WITHHELD``).
A refused call never reaches MCP; the engine reports it to the model as a tool error.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

TOOL_ALLOWLIST: frozenset[str] = frozenset({
    "address_name",
    "address_to_file_offset",
    "analyze_function",
    "batch_decompile",
    "binary_overview",
    "binary_session",
    "build_call_path",
    "comment",
    "compare_functions",
    "find_xrefs_to_name",
    "get_call_graph",
    "get_evidence_bundle",
    "inline_comment",
    "inspect_address_context",
    "inspect_byte_entropy",
    "inspect_elf_notes",
    "inspect_go_binary",
    "inspect_managed_artifact",
    "inspect_managed_members",
    "inspect_managed_native_boundaries",
    "inspect_native_api",
    "inspect_native_data_type",
    "inspect_native_exports",
    "inspect_native_instruction",
    "inspect_native_load_image",
    "inspect_pe_certificates",
    "inspect_pe_imports",
    "inspect_pe_load_config",
    "inspect_pe_resources",
    "inspect_rust_binary",
    "list_documents",
    "list_names",
    "list_procedures",
    "list_segments",
    "list_strings",
    "list_unknowns",
    "procedure_address",
    "procedure_assembly",
    "procedure_callees",
    "procedure_callers",
    "procedure_info",
    "procedure_pseudo_code",
    "procedure_references",
    "read_bytes",
    "read_function_instructions",
    "resolve_containing_procedure",
    "resolve_native_call_targets",
    "search_bytes",
    "search_procedures",
    "search_strings",
    "trace_call_path",
    "trace_feature",
    "trace_native_values",
    "xrefs",
})

ADDRESS_RE = re.compile(r"^(0x)?[0-9a-fA-F]{1,16}$")
MAX_STR = 256
MAX_LIST = 16
_SHELL_META = frozenset(";&|`$<>()\\'\"*?[]{}!~#")
_HEX64 = re.compile(r"^[a-f0-9]{64}$")
_EVIDENCE_ID = re.compile(r"^ev_[a-f0-9]{64}$")
_BIG = 1 << 30


class CallRefused(Exception):
    """The model's tool call violates the policy; it is answered as a tool error."""


# Argument kinds.
PATH = "path"
ADDR = "addr"
STR = "str"
BOOL = "bool"
ADDR_LIST = "addr_list"
STR_LIST = "str_list"
EVIDENCE_FILTERS = "evidence_filters"


def _int(lo: int, hi: int) -> tuple[str, int, int]:
    return ("int", lo, hi)


def _enum(*values: str) -> tuple[str, tuple[str, ...]]:
    return ("enum", values)


_DETAIL = _enum("complete", "summary")
_DOC = STR

ArgSpec = Any  # str | ("int", lo, hi) | ("enum", values)

TOOL_ARGS: dict[str, dict[str, ArgSpec]] = {
    "address_name": {"document": _DOC, "address": ADDR},
    "address_to_file_offset": {"address": ADDR, "document": _DOC},
    "analyze_function": {"procedure": STR, "detail": _DETAIL},
    "batch_decompile": {"addresses": ADDR_LIST},
    "binary_overview": {},
    "binary_session": {"detail": _DETAIL},
    "build_call_path": {},
    "comment": {"document": _DOC, "address": ADDR},
    "compare_functions": {},
    "find_xrefs_to_name": {"name": STR},
    "get_call_graph": {"address": ADDR, "direction": _enum("forward", "backward"), "detail": _DETAIL},
    "get_evidence_bundle": {"detail": _DETAIL, "filters": EVIDENCE_FILTERS},
    "inline_comment": {"document": _DOC, "address": ADDR},
    "inspect_address_context": {"address": ADDR, "document": _DOC},
    "inspect_byte_entropy": {"path": PATH, "block_size": _int(256, 65536), "offset": _int(0, _BIG),
                             "length": _int(0, _BIG), "detail": _DETAIL},
    "inspect_elf_notes": {"path": PATH, "max_file_bytes": _int(64, 536870912), "max_entries": _int(1, 256)},
    "inspect_go_binary": {"path": PATH, "architecture": STR, "detail": STR},
    "inspect_managed_artifact": {"path": PATH, "detail": _DETAIL},
    "inspect_managed_members": {"path": PATH, "detail": _DETAIL, "type_names": STR_LIST},
    "inspect_managed_native_boundaries": {"path": PATH},
    "inspect_native_api": {"procedure": STR},
    "inspect_native_data_type": {"type": STR, "address": ADDR, "document": _DOC},
    "inspect_native_exports": {"path": PATH, "max_file_bytes": _int(1, 536870912), "detail": STR},
    "inspect_native_instruction": {"address": ADDR, "document": _DOC},
    "inspect_native_load_image": {"detail": _DETAIL},
    "inspect_pe_certificates": {"path": PATH, "max_file_bytes": _int(1, 536870912), "max_entries": _int(1, 4096)},
    "inspect_pe_imports": {"path": PATH, "max_file_bytes": _int(1, 536870912), "max_dlls": _int(1, 4096),
                           "max_functions": _int(1, 65536)},
    "inspect_pe_load_config": {"path": PATH, "max_file_bytes": _int(1, 536870912), "max_callbacks": _int(1, 4096)},
    "inspect_pe_resources": {"path": PATH, "max_file_bytes": _int(1, 536870912), "max_entries": _int(1, 65536)},
    "inspect_rust_binary": {"path": PATH, "architecture": STR, "detail": STR},
    "list_documents": {},
    "list_names": {"document": _DOC, "address": ADDR, "detail": _DETAIL},
    "list_procedures": {"document": _DOC, "detail": _DETAIL},
    "list_segments": {"document": _DOC},
    "list_strings": {"document": _DOC, "address": ADDR, "detail": _DETAIL},
    "list_unknowns": {"status": _enum("open", "investigating", "blocked", "contradicted", "resolved"),
                      "severity": _enum("low", "medium", "high", "critical"), "domain": STR,
                      "offset": _int(0, _BIG), "limit": _int(1, 5000)},
    "procedure_address": {"procedure": STR, "document": _DOC, "detail": _DETAIL},
    "procedure_assembly": {"procedure": STR, "document": _DOC},
    "procedure_callees": {"procedure": STR, "document": _DOC, "detail": _DETAIL},
    "procedure_callers": {"procedure": STR, "document": _DOC, "detail": _DETAIL},
    "procedure_info": {"procedure": STR, "document": _DOC},
    "procedure_pseudo_code": {"procedure": STR, "document": _DOC},
    "procedure_references": {"procedure": STR, "direction": _enum("incoming", "outgoing"), "document": _DOC},
    "read_bytes": {"address": ADDR, "length": _int(1, 65536), "document": _DOC},
    "read_function_instructions": {"procedure": STR, "document": _DOC},
    "resolve_containing_procedure": {"address": ADDR, "document": _DOC, "detail": _DETAIL},
    "resolve_native_call_targets": {"address": ADDR, "document": _DOC},
    "search_bytes": {"pattern": STR, "mask": STR, "document": _DOC, "start": ADDR, "end": ADDR,
                     "limit": _int(1, 1000), "cursor": STR},
    "search_procedures": {"pattern": STR, "mode": _enum("literal", "regex"), "case_sensitive": BOOL,
                          "document": _DOC, "detail": _DETAIL},
    "search_strings": {"pattern": STR, "mode": _enum("literal", "regex"), "case_sensitive": BOOL,
                       "document": _DOC, "detail": _DETAIL},
    "trace_call_path": {"start": STR, "goal": STR, "direction": _enum("forward", "backward")},
    "trace_feature": {"query": STR, "case_sensitive": BOOL},
    "trace_native_values": {"procedure": STR, "max_depth": _int(0, 16), "max_functions": _int(1, 64),
                            "max_call_sites": _int(1, 4096), "max_nodes": _int(1, 20000),
                            "max_edges": _int(1, 40000), "offset": _int(0, _BIG), "limit": _int(1, 5000)},
    "xrefs": {"document": _DOC, "address": ADDR},
}

# Required arguments (from the snapshot). ``path`` is filled by the engine.
REQUIRED: dict[str, frozenset[str]] = {
    "address_to_file_offset": frozenset({"address"}),
    "analyze_function": frozenset({"procedure"}),
    "find_xrefs_to_name": frozenset({"name"}),
    "get_call_graph": frozenset({"address"}),
    "inspect_address_context": frozenset({"address"}),
    "inspect_native_api": frozenset({"procedure"}),
    "inspect_native_instruction": frozenset({"address"}),
    "procedure_address": frozenset({"procedure"}),
    "procedure_assembly": frozenset({"procedure"}),
    "procedure_callees": frozenset({"procedure"}),
    "procedure_callers": frozenset({"procedure"}),
    "procedure_info": frozenset({"procedure"}),
    "procedure_pseudo_code": frozenset({"procedure"}),
    "procedure_references": frozenset({"procedure"}),
    "read_bytes": frozenset({"address"}),
    "read_function_instructions": frozenset({"procedure"}),
    "resolve_containing_procedure": frozenset({"address"}),
    "resolve_native_call_targets": frozenset({"address"}),
    "search_bytes": frozenset({"pattern"}),
    "search_procedures": frozenset({"pattern"}),
    "search_strings": frozenset({"pattern"}),
    "trace_call_path": frozenset({"start"}),
    "trace_feature": frozenset({"query"}),
    "trace_native_values": frozenset({"procedure"}),
}

# Allowlisted, but every required argument is an object we do not accept: never offered.
WITHHELD: frozenset[str] = frozenset({"build_call_path", "compare_functions"})

_EVIDENCE_FILTER_KEYS: dict[str, re.Pattern[str] | None] = {
    "evidence_id": _EVIDENCE_ID,
    "operation": None,
    "target_sha256": _HEX64,
    "analysis_profile_digest": _HEX64,
    "procedure_address": None,
}


def safe_name(name: object) -> str:
    """An argument/tool name fit to echo back in a refusal message."""
    if isinstance(name, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name):
        return name
    return "<invalid name>"


def _check_str(arg: str, value: Any) -> str:
    if not isinstance(value, str):
        raise CallRefused(f"argument {arg!r} must be a string")
    if not value or len(value) > MAX_STR:
        raise CallRefused(f"argument {arg!r} must be 1..{MAX_STR} characters")
    if ".." in value or value.startswith("/"):
        raise CallRefused(f"argument {arg!r} looks like a path; paths are not accepted")
    if any(c in _SHELL_META or ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise CallRefused(f"argument {arg!r} contains a forbidden character")
    return value


def _check_addr(arg: str, value: Any) -> str:
    if not isinstance(value, str) or not ADDRESS_RE.fullmatch(value):
        raise CallRefused(f"argument {arg!r} must be a hex address like 0x401000")
    return value


def _check(arg: str, spec: ArgSpec, value: Any) -> Any:
    if spec == ADDR:
        return _check_addr(arg, value)
    if spec == STR:
        return _check_str(arg, value)
    if spec == BOOL:
        if not isinstance(value, bool):
            raise CallRefused(f"argument {arg!r} must be a boolean")
        return value
    if spec in (ADDR_LIST, STR_LIST):
        if not isinstance(value, list) or not 1 <= len(value) <= MAX_LIST:
            raise CallRefused(f"argument {arg!r} must be a list of 1..{MAX_LIST} items")
        item = _check_addr if spec == ADDR_LIST else _check_str
        out = [item(arg, v) for v in value]
        if len(set(out)) != len(out):
            raise CallRefused(f"argument {arg!r} has duplicate items")
        return out
    if spec == EVIDENCE_FILTERS:
        if not isinstance(value, dict) or not value:
            raise CallRefused(f"argument {arg!r} must be a non-empty object")
        clean: dict[str, str] = {}
        for k, v in value.items():
            if k not in _EVIDENCE_FILTER_KEYS:
                raise CallRefused(f"unknown filter {safe_name(k)!r}")
            pat = _EVIDENCE_FILTER_KEYS[k]
            if pat is None:
                clean[k] = _check_str(k, v)
            elif not isinstance(v, str) or not pat.fullmatch(v):
                raise CallRefused(f"filter {k!r} has the wrong format")
            else:
                clean[k] = v
        return clean
    if isinstance(spec, tuple) and spec[0] == "int":
        _kind, lo, hi = spec
        if not isinstance(value, int) or isinstance(value, bool) or not lo <= value <= hi:
            raise CallRefused(f"argument {arg!r} must be an integer in [{lo}, {hi}]")
        return value
    if isinstance(spec, tuple) and spec[0] == "enum":
        if value not in spec[1]:
            raise CallRefused(f"argument {arg!r} must be one of {', '.join(spec[1])}")
        return value
    raise CallRefused(f"argument {arg!r} is not accepted")


def check_call(name: str, arguments: Any, *, sample_path: str) -> dict[str, Any]:
    """Validated arguments for ``name``, with any ``path`` set to ``sample_path``.

    Raises :class:`CallRefused` when the tool or any argument is not allowed.
    """
    if name not in TOOL_ALLOWLIST or name in WITHHELD:
        raise CallRefused(f"tool {safe_name(name)!r} is not available")
    if not isinstance(arguments, dict):
        raise CallRefused("arguments must be a JSON object")
    specs = TOOL_ARGS[name]
    out: dict[str, Any] = {}
    for arg, value in arguments.items():
        if not isinstance(arg, str) or arg not in specs:
            raise CallRefused(f"unknown argument {safe_name(arg)!r}")
        if specs[arg] == PATH:
            continue  # never from the model; set below
        out[arg] = _check(arg, specs[arg], value)
    missing = REQUIRED.get(name, frozenset()) - set(out)
    if missing:
        raise CallRefused(f"missing required argument(s): {', '.join(sorted(missing))}")
    if "path" in specs:
        out["path"] = sample_path
    return out


def _schema(spec: ArgSpec) -> dict[str, Any]:
    if spec == ADDR:
        return {"type": "string", "pattern": ADDRESS_RE.pattern, "description": "hex address, e.g. 0x401000"}
    if spec == STR:
        return {"type": "string", "maxLength": MAX_STR}
    if spec == BOOL:
        return {"type": "boolean"}
    if spec == ADDR_LIST:
        return {"type": "array", "items": _schema(ADDR), "minItems": 1, "maxItems": MAX_LIST}
    if spec == STR_LIST:
        return {"type": "array", "items": _schema(STR), "minItems": 1, "maxItems": MAX_LIST}
    if spec == EVIDENCE_FILTERS:
        return {"type": "object", "additionalProperties": False,
                "properties": {k: {"type": "string"} for k in _EVIDENCE_FILTER_KEYS}}
    if spec[0] == "int":
        return {"type": "integer", "minimum": spec[1], "maximum": spec[2]}
    return {"type": "string", "enum": list(spec[1])}


def model_tool_specs(listed: Mapping[str, str], *, max_description: int = 400) -> list[dict[str, Any]]:
    """OpenAI ``tools`` for every allowlisted, offerable tool the server actually listed.

    ``listed`` maps tool name -> the server's description (pinned REA code, trimmed).
    Parameters come from ``TOOL_ARGS``, never from the server's schema.
    """
    specs = []
    for name in sorted(TOOL_ALLOWLIST - WITHHELD):
        if name not in listed:
            continue
        args = {a: s for a, s in TOOL_ARGS[name].items() if s != PATH}
        desc = " ".join(str(listed[name] or name).split())[:max_description]
        if "path" in TOOL_ARGS[name]:
            desc += " (Always runs on the sample; takes no path argument.)"
        specs.append({"type": "function", "function": {
            "name": name,
            "description": desc,
            "parameters": {"type": "object", "properties": {a: _schema(s) for a, s in args.items()},
                           "required": sorted(REQUIRED.get(name, frozenset()) & set(args)),
                           "additionalProperties": False},
        }})
    return specs
