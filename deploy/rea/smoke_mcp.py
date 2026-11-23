"""Build-time MCP smoke for the REA cold-worker image. Fails the build on any miss.

Drives ``$REA_BIN --mcp`` (newline-delimited JSON-RPC over stdio) against a saved
analyzeHeadless project and checks, in one session:

1. the tool catalog digest (``server_identity.catalog.digests.tools_sha256`` in the
   ``binary_session`` result) equals the pinned value, so the image runs the REA
   build the engine was designed against;
2. the existing-project reuse path is active (``import_mode`` is
   ``existing-project-private-copy-v1``), not a silent fresh import;
3. provider queries work (``list_procedures``, then ``procedure_pseudo_code main``
   decompiles the fixture's printf string);
4. while Ghidra is up, REA's runtime root (``rea-ghidra-*``) is under ``$TMPDIR`` and
   nothing new appeared under ``/tmp``.

usage: smoke_mcp.py <target> <expected_tools_sha256>
(REA_GHIDRA_PROJECT_PATH / REA_GHIDRA_PROGRAM_NAME / TMPDIR come from the environment.)
"""

import glob
import json
import os
import subprocess
import sys
import threading
import time


def find_key(obj, key):
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        obj = list(obj.values())
    if isinstance(obj, list):
        for v in obj:
            found = find_key(v, key)
            if found is not None:
                return found
    if isinstance(obj, str) and key in obj and obj.lstrip().startswith("{"):
        try:
            return find_key(json.loads(obj), key)
        except ValueError:
            return None
    return None


class Mcp:
    def __init__(self, cmd):
        self.p = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1
        )
        self.msgs = {}
        self.nid = 0
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.p.stdout:
            try:
                m = json.loads(line)
            except ValueError:
                continue
            if "id" in m:
                self.msgs[m["id"]] = m

    def send(self, method, params=None, notify=False):
        m = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            m["params"] = params
        if not notify:
            self.nid += 1
            m["id"] = self.nid
        self.p.stdin.write(json.dumps(m) + "\n")
        self.p.stdin.flush()
        if notify:
            return None
        t0 = time.time()
        while time.time() - t0 < 600:
            if m["id"] in self.msgs:
                r = self.msgs.pop(m["id"])
                if "error" in r:
                    sys.exit(f"FAIL {method}: {r['error']}")
                return r["result"]
            if self.p.poll() is not None:
                sys.exit(f"FAIL {method}: rea exited {self.p.returncode}")
            time.sleep(0.1)
        sys.exit(f"FAIL {method}: timeout")

    def call(self, name, args):
        r = self.send("tools/call", {"name": name, "arguments": args})
        if r.get("isError"):
            sys.exit(f"FAIL {name}: {json.dumps(r)[:2000]}")
        return r


def main():
    target, want_digest = sys.argv[1], sys.argv[2]
    tmpdir = os.environ["TMPDIR"]
    before_tmp = set(glob.glob("/tmp/rea-ghidra-*"))
    t0 = time.time()
    mcp = Mcp([os.environ["REA_BIN"], "--mcp"])
    mcp.send(
        "initialize",
        {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "blastbox-rea-smoke", "version": "0"},
        },
    )
    mcp.send("notifications/initialized", notify=True)
    tools = mcp.send("tools/list", {})["tools"]
    print(f"tools/list: {len(tools)} tools")

    opened = mcp.call("open_binary", {"path": target})
    session = mcp.call("binary_session", {})
    digest = find_key(session, "tools_sha256")
    print(f"tools_sha256: {digest}")
    if digest != want_digest:
        sys.exit(f"FAIL tools_sha256 {digest!r} != pinned {want_digest!r}")

    procs = mcp.call("list_procedures", {"detail": "summary"})
    import_mode = next(
        (m for r in (procs, session, opened) if (m := find_key(r, "import_mode"))), None
    )
    print(f"import_mode: {import_mode}")
    if import_mode != "existing-project-private-copy-v1":
        sys.exit(f"FAIL import_mode {import_mode!r}: saved project was not reused")
    pseudo = json.dumps(mcp.call("procedure_pseudo_code", {"procedure": "main"}))
    if "hello loadout" not in pseudo:
        sys.exit(
            f"FAIL procedure_pseudo_code main lacks the fixture string: {pseudo[:2000]}"
        )
    print("procedure_pseudo_code main: decompiled, fixture string present")

    # Ghidra is running now, so REA's runtime root exists.
    roots = sorted(glob.glob(os.path.join(tmpdir, "rea-ghidra-*")))
    leaked = sorted(set(glob.glob("/tmp/rea-ghidra-*")) - before_tmp)
    print(f"runtime roots under TMPDIR={tmpdir}: {roots}")
    print(f"new runtime roots under /tmp: {leaked}")
    if leaked:
        sys.exit("FAIL REA put its runtime root under /tmp despite TMPDIR")
    if not roots:
        sys.exit("FAIL no rea-ghidra-* runtime root under TMPDIR")
    print(f"runtime root contents: {sorted(os.listdir(roots[0]))}")

    mcp.call("close_binary", {})
    mcp.p.stdin.close()
    try:
        mcp.p.wait(60)
    except subprocess.TimeoutExpired:
        mcp.p.kill()
    print(f"REA MCP smoke OK ({time.time() - t0:.1f}s)")


if __name__ == "__main__":
    main()
