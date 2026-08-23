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
    """(class, name) -> file:line for every def annotated to return an optional bool.

    Keyed by the DECLARING CLASS as well as the name. Keying on the bare name made every
    ``.is_alive()`` in the tree look tri-state because CascadingRuntime declares one -- so the
    sweep reported ``threading.Thread.is_alive()`` in pool.py and a process-liveness call in
    vm_dispatch.py as P1 collapses. Every P1 the script has ever emitted was one of those, and a
    checker whose only output is false positives trains you to skim past it.
    """
    out = {}
    for path, tree in trees.items():
        for cls in ast.walk(tree):
            if not isinstance(cls, ast.ClassDef):
                continue
            for n in cls.body:
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    a = ann_text(n.returns).replace('"', "").replace("'", "").replace(" ", "")
                    if a in ("bool|None", "None|bool", "Optional[bool]"):
                        out[(cls.name, n.name)] = f"{path}:{n.lineno}"
    return out


def called_name(node):
    f = node.func
    if isinstance(f, ast.Attribute):
        return f.attr
    if isinstance(f, ast.Name):
        return f.id
    return None


def receiver_of(node):
    """Best-effort static receiver text for `x.method()` / `self._x.method()`."""
    f = node.func
    if not isinstance(f, ast.Attribute):
        return None
    v = f.value
    if isinstance(v, ast.Name):
        return v.id
    if isinstance(v, ast.Attribute):
        return v.attr          # self._thread -> "_thread"
    return None


def bool_uses_of(fn, name):
    """Boolean-context uses of local ``name`` inside ``fn`` (not nested defs)."""
    out = []
    for n in ast.walk(fn):
        if not isinstance(n, ast.Name) or n.id != name or not isinstance(n.ctx, ast.Load):
            continue
        for parent in ast.walk(fn):
            if isinstance(parent, ast.UnaryOp) and isinstance(parent.op, ast.Not) \
                    and parent.operand is n:
                out.append((n.lineno, "not <var>"))
            elif isinstance(parent, ast.If) and parent.test is n:
                out.append((n.lineno, "if <var>:"))
            elif isinstance(parent, ast.BoolOp) and n in parent.values:
                out.append((n.lineno, "and/or"))
    return out


def guards_none(fn, name, before_line=None):
    """Does ``fn`` discriminate the three states of ``name`` BEFORE ``before_line``?

    Any IDENTITY comparison against None, False or True counts. Looking only for `is None` was too
    narrow: `if _ok is False:` separates the definitive negative from the unknown just as well, and
    is what aws_worker's resume loops actually use -- so the first version of this check reported
    both of them as collapses. A checker that flags correct code gets ignored exactly as fast as
    one that misses bugs.
    """
    for n in ast.walk(fn):
        if not isinstance(n, ast.Compare) or not isinstance(n.left, ast.Name):
            continue
        if n.left.id != name:
            continue
        # ORDER MATTERS. Accepting a guard anywhere in the function suppressed
        #     healthy = rt.is_ready(slot)
        #     if not healthy: return          # <- UNKNOWN already collapsed here
        #     if healthy is None: ...         # <- too late to matter
        # i.e. exactly the regression the assignment-following was added to catch. A guard only
        # helps a use it PRECEDES. Line order is an approximation of dominance -- it can still be
        # fooled by a guard in an unrelated earlier branch -- but it is a far better one than
        # "exists somewhere", and it errs toward reporting.
        if before_line is not None and n.lineno >= before_line:
            continue
        if any(isinstance(o, (ast.Is, ast.IsNot)) for o in n.ops) and \
                any(isinstance(c, ast.Constant) and c.value in (None, False, True)
                    for c in n.comparators):
            return True
    return False


def enclosing_funcs(tree):
    return [n for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def find_p1(trees, tri):
    # Only names declared tri-state SOMEWHERE, but reported only when the receiver is plausibly
    # one of those classes: `self` (the declaring class or a subclass) or a name that is not an
    # obvious stdlib object. Anything called on a `thread`/`proc`-ish receiver is skipped.
    by_name = {}
    for (cls, name), loc in tri.items():
        by_name.setdefault(name, []).append((cls, loc))
    # ALLOWLIST, not a denylist. A denylist never converges: the same `is_alive` name is used by
    # threading.Thread, subprocess handles, and locals called `reaper`/`vt`, and each new one has
    # to be discovered from a false positive. Only receivers that could plausibly BE one of these
    # runtimes are worth reporting; anything else is skipped, at the cost of missing a call through
    # an unusually-named variable. A checker that cries wolf is worse than one with a known blind
    # spot, because you stop reading it.
    OURS = ("self", "runtime", "_runtime", "rt", "tier", "engine", "slot_runtime")
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
            if nm not in by_name:
                continue
            recv = (receiver_of(n) or "").lower()
            if recv not in OURS:
                continue        # not one of our runtimes -- Thread.is_alive and friends
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
                decl = ", ".join(f"{c}@{loc}" for c, loc in by_name[nm][:2])
                hits.append((f"{path}:{n.lineno}", f"{recv or '?'}.{nm}", ctx, decl))
            elif isinstance(p, ast.Assign) and len(p.targets) == 1 \
                    and isinstance(p.targets[0], ast.Name):
                # INDIRECT use: `healthy = rt.is_ready(slot)` ... `if not healthy:`. Only the
                # immediate parent was inspected, so this -- the shape every state machine in this
                # codebase actually uses -- was invisible: deleting an `is None` guard recreated a
                # collapse while the sweep still printed `none`. A checker blind to the dominant
                # form of the bug it hunts is worse than none, because its silence reads as proof.
                var = p.targets[0].id
                fn = next((f for f in enclosing_funcs(tree)
                           if f.lineno <= n.lineno <= (f.end_lineno or n.lineno)), None)
                if fn is None:
                    continue
                for lineno, uctx in bool_uses_of(fn, var):
                    # WHICH use decides whether order matters.
                    #   `if x:` tests for SUCCESS and lets both other states fall through, so a
                    #     discriminator anywhere -- including after it -- still governs them. Both
                    #     aws_worker resume loops are this shape: `if _ok: return` then
                    #     `if _ok is False:`. Correct, and demanding a preceding guard flags them.
                    #   `not x` / `and`/`or` CONSUME the None branch on the spot, so only a guard
                    #     that already ran can save them. This is the shape the review cited:
                    #     `if not healthy: return` followed by a now-useless `if healthy is None:`.
                    consumes_none = uctx != "if <var>:"
                    if guards_none(fn, var, before_line=lineno if consumes_none else None):
                        continue
                    decl = ", ".join(f"{c}@{loc}" for c, loc in by_name[nm][:2])
                    hits.append((f"{path}:{lineno}", f"{var} = {recv or '?'}.{nm}",
                                 f"{uctx}, no tri-state guard in {fn.name}()", decl))
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
print(f"tri-state methods found: {len(tri)}")
for (cls, name), v in sorted(tri.items()):
    print(f"    {cls + '.' + name:<40} {v}")

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
