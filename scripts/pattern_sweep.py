"""Find the three defect patterns this branch produced repeatedly, mechanically.

Not a linter -- a targeted search for the exact shapes that have already bitten:

  P1 TRI-STATE COLLAPSE   a function declared `bool | None` whose result is used in a boolean
                          context (`if x`, `if not x`, `bool(x)`, `and`/`or`), which silently
                          turns "I don't know" into "no".
  P2 SIBLING BUDGET SCOPE `with self._*_budget(...)` appearing twice as SIBLINGS in one function.
                          These scopes min only against an OUTER LIVE scope, so siblings each get
                          a full fresh deadline and the function costs 2x its declared bound.
  P3 STAMP-BEFORE-CALL    a rate-limit timestamp assigned from the clock and then NOT re-assigned
                          after the slow call it is supposed to throttle -- so a call that outruns
                          its own interval is eligible again the moment it returns.
"""
import ast
import pathlib
import sys

FILES = [
    "src/blastbox/host/pool.py",
    "src/blastbox/host/runtime/aws_worker.py",
    "src/blastbox/host/runtime/cascade.py",
    "src/blastbox/host/runtime/vm_dispatch.py",
    "src/blastbox/host/dispatch.py",
]
ROOT = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".")


def ann_text(node):
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def tri_state_defs(trees):
    """name -> file:line for every def annotated to return an optional bool."""
    out = {}
    for path, tree in trees.items():
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                a = ann_text(n.returns).replace('"', "").replace("'", "").replace(" ", "")
                if a in ("bool|None", "None|bool", "Optional[bool]"):
                    out[n.name] = f"{path}:{n.lineno}"
    return out


def called_name(node):
    f = node.func
    if isinstance(f, ast.Attribute):
        return f.attr
    if isinstance(f, ast.Name):
        return f.id
    return None


def find_p1(trees, tri):
    hits = []
    for path, tree in trees.items():
        parents = {}
        for n in ast.walk(tree):
            for c in ast.iter_child_nodes(n):
                parents[c] = n
        for n in ast.walk(tree):
            if not isinstance(n, ast.Call):
                continue
            nm = called_name(n)
            if nm not in tri:
                continue
            p = parents.get(n)
            ctx = None
            if isinstance(p, ast.UnaryOp) and isinstance(p.op, ast.Not):
                ctx = "not <call>"
            elif isinstance(p, ast.If) and p.test is n:
                ctx = "if <call>:"
            elif isinstance(p, ast.BoolOp):
                ctx = "and/or"
            elif isinstance(p, ast.Call) and called_name(p) == "bool":
                ctx = "bool(<call>)"
            elif isinstance(p, (ast.While,)) and p.test is n:
                ctx = "while <call>:"
            if ctx:
                hits.append((f"{path}:{n.lineno}", nm, ctx, tri[nm]))
    return hits


def find_p2(trees):
    hits = []
    for path, tree in trees.items():
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            scopes = []

            def walk(node, depth):
                for c in ast.iter_child_nodes(node):
                    if isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        continue
                    if isinstance(c, (ast.With, ast.AsyncWith)):
                        for item in c.items:
                            t = ann_text(item.context_expr)
                            if "_budget(" in t:
                                scopes.append((c.lineno, t, depth))
                        walk(c, depth + 1)
                    else:
                        walk(c, depth)

            walk(fn, 0)
            if len(scopes) >= 2:
                # siblings = same nesting depth
                by_depth = {}
                for ln, t, d in scopes:
                    by_depth.setdefault(d, []).append((ln, t))
                for d, group in by_depth.items():
                    if len(group) >= 2:
                        hits.append((f"{path}:{fn.lineno}", fn.name,
                                     [f"L{ln}" for ln, _ in group]))
    return hits


def find_p3(trees):
    """A `self.X[...] = <clock>` or `self.X = <clock>` with no second assignment to the same
    target later in the same function -- i.e. stamped once, on entry."""
    hits = []
    CLOCKS = ("_clock()", "now", "time.monotonic()")
    for path, tree in trees.items():
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            assigns = {}
            for n in ast.walk(fn):
                if not isinstance(n, ast.Assign) or len(n.targets) != 1:
                    continue
                tgt, val = ann_text(n.targets[0]), ann_text(n.value)
                if not tgt.startswith("self."):
                    continue
                if not any(c in val for c in CLOCKS):
                    continue
                key = tgt.split("[")[0]
                if any(w in key.lower() for w in ("last", "attempt", "since", "at", "stamp")):
                    assigns.setdefault(key, []).append(n.lineno)
            for key, lines in assigns.items():
                if len(lines) == 1:
                    hits.append((f"{path}:{lines[0]}", fn.name, key))
    return hits


trees = {}
for f in FILES:
    p = ROOT / f
    trees[f.split("/")[-1]] = ast.parse(p.read_text())

tri = tri_state_defs(trees)
print(f"tri-state functions found: {len(tri)}")
for k, v in sorted(tri.items()):
    print(f"    {k:<28} {v}")

print("\n=== P1 tri-state collapse (a `bool | None` used as a boolean)")
p1 = find_p1(trees, tri)
print("  none" if not p1 else "")
for loc, nm, ctx, decl in p1:
    print(f"  {loc:<26} {nm}()  used as `{ctx}`   (declared {decl})")

print("\n=== P2 sibling budget scopes in one function")
p2 = find_p2(trees)
print("  none" if not p2 else "")
for loc, nm, lines in p2:
    print(f"  {loc:<26} {nm}()  scopes at {', '.join(lines)}")

print("\n=== P3 rate-limit stamp assigned once (never re-stamped after the call)")
p3 = find_p3(trees)
print("  none" if not p3 else "")
for loc, nm, key in p3:
    print(f"  {loc:<26} {nm}()  {key}")
