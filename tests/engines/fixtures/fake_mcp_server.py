"""Fake REA MCP stdio server for the rea-agent engine tests.

Usage: ``python fake_mcp_server.py <log_path> [<responses_json_path>]``.

Speaks newline-delimited JSON-RPC 2.0. Every message received is appended to ``log_path``
as one JSON line (``{"recv": <msg>}``); the first line records the environment the server
was started with (``{"env": {...}, "argv": [...], "cwd": "..."}``).

``responses_json_path`` maps tool name -> response spec:
  ``{"text": "..."}``            -> a normal result with one text content item
  ``{"error": "..."}``           -> an ``isError: true`` result
  ``{"rpc_error": "..."}``       -> a JSON-RPC error response
  ``{"sleep": s, "text": ..}``   -> sleep first (timeouts)
  ``{"huge": n}``                -> a text result of ``n`` bytes (response caps)
Tool names not in the map get ``{"text": "{\\"result\\": \\"ok <name>\\"}"}``.
"""

from __future__ import annotations

import json
import os
import sys
import time

TOOLS = [
    "open_binary",
    "close_binary",
    "binary_overview",
    "list_procedures",
    "procedure_info",
    "procedure_pseudo_code",
    "procedure_callees",
    "read_bytes",
    "search_strings",
    "inspect_pe_imports",
    "inspect_native_exports",
    "build_call_path",
    "annotate_native_function",
    "set_address_name",
    "capture_process",
]


def main() -> None:
    log_path = sys.argv[1]
    responses = {}
    if len(sys.argv) > 2 and sys.argv[2]:
        with open(sys.argv[2]) as f:
            responses = json.load(f)
    log = open(log_path, "a", buffering=1)
    log.write(json.dumps({"env": dict(os.environ), "argv": sys.argv, "cwd": os.getcwd()}) + "\n")
    out = sys.stdout

    def send(msg: dict) -> None:
        out.write(json.dumps(msg) + "\n")
        out.flush()

    for line in sys.stdin:
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        log.write(json.dumps({"recv": msg}) + "\n")
        method = msg.get("method")
        mid = msg.get("id")
        if mid is None:
            continue  # notification
        if method == "initialize":
            send({"jsonrpc": "2.0", "id": mid, "result": {
                "protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake-rea", "version": "0"}}})
        elif method == "tools/list":
            send({"jsonrpc": "2.0", "id": mid, "result": {"tools": [
                {"name": n, "description": f"fake {n}", "inputSchema": {"type": "object"}} for n in TOOLS]}})
        elif method == "tools/call":
            name = msg["params"]["name"]
            spec = responses.get(name, {"text": json.dumps({"result": f"ok {name}"})})
            if "sleep" in spec:
                time.sleep(spec["sleep"])
            if "rpc_error" in spec:
                send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32000, "message": spec["rpc_error"]}})
                continue
            if "huge" in spec:
                text = "A" * int(spec["huge"])
            else:
                text = spec.get("text", spec.get("error", ""))
            result = {"content": [{"type": "text", "text": text}]}
            if "error" in spec:
                result["isError"] = True
            send({"jsonrpc": "2.0", "id": mid, "result": result})
        else:
            send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "no such method"}})


if __name__ == "__main__":
    main()
