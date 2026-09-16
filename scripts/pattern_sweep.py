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

# Every module that IMPLEMENTS the SlotRuntime protocol belongs here, not just the ones where a
# bug was found once. The list held five files and missed StaticPoolRuntime.is_ready -- a live
# UNKNOWN-to-False collapse on the tier the configuration guide uses in its own canonical example
# -- because static_pool.py was never opened. A checker for a protocol has to scan its implementers.
FILES = [
    "src/blastbox/host/pool.py",
    "src/blastbox/host/runtime/aws_worker.py",
    "src/blastbox/host/runtime/cascade.py",
    "src/blastbox/host/runtime/vm_dispatch.py",
    "src/blastbox/host/dispatch.py",
    "src/blastbox/host/runtime/static_pool.py",
    "src/blastbox/host/runtime/libvirt_vm.py",
    "src/blastbox/host/runtime/gvisor_snapshot_runtime.py",
    "src/blastbox/host/runtime/remote_http.py",
]
ROOT = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".")


def ann_text(node):
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except Exception:
        return ""


#: Methods whose CONTRACT is tri-state (pool.py: "None = UNKNOWN"). A coercion inside one of these
#: breaks the promise its own caller relies on; the same coercion elsewhere is deliberate narrowing.
_TRI_STATE_CONTRACT = frozenset({"is_ready", "is_alive", "is_alive_for_claim"})


def _enclosing_fn(parents, node):
    """The FunctionDef `node` sits in, walking the parent map. There is no `fn` in scope on the
    direct-call path, and reaching for one silently picked up a stale outer binding that made the
    whole check vacuous -- caught only because the validation ran BOTH directions: clean tree still
    clean, AND the reverted collapse still reported."""
    cur = parents.get(node)
    while cur is not None:
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return cur
        cur = parents.get(cur)
    return None


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
        # Walk EVERY def, not just the direct children of a ClassDef. Module-level helpers and
        # nested defs are declarations too, and missing one does not produce a smaller report --
        # it produces `none`, because P1 only looks up names this function returned. A scan that
        # found nothing and a scan that found no bugs printed the identical line.
        owner = {}
        for cls in ast.walk(tree):
            if isinstance(cls, ast.ClassDef):
                for n in ast.walk(cls):
                    owner.setdefault(n, cls.name)
        for n in ast.walk(tree):
            if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            a = ann_text(n.returns).replace('"', "").replace("'", "").replace(" ", "")
            if a in ("bool|None", "None|bool", "Optional[bool]"):
                out[(owner.get(n, "<module>"), n.name)] = f"{path}:{n.lineno}"
    return out


def plain_bool_defs(trees):
    """Same shape, for defs annotated `-> bool`. Used only to flag NAME AMBIGUITY in the report.

    P1 matches on the bare method name, so a correct `-> bool` method sharing a name with a
    tri-state one elsewhere gets reported. Resolving that needs the receiver's real type, which
    this cannot do; saying so on the line is the honest alternative to silently guessing.
    """
    out = set()
    for tree in trees.values():
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                    and ann_text(n.returns).strip().strip("\"'") == "bool":
                out.add(n.name)
    return out


def parent_map(tree):
    parents = {}
    for n in ast.walk(tree):
        for c in ast.iter_child_nodes(n):
            parents[c] = n
    return parents


def bindings_of(fn, name):
    """Every line where ``name`` is (re)bound in ``fn`` -- assignment, annotated, walrus, for, with."""
    return sorted((n.lineno, n.col_offset) for n in ast.walk(fn)
                  if isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Store))


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


def bool_context(p, n, fn):
    """Name the boolean context ``n`` sits in under parent ``p``, or None.

    The module docstring advertised `if x`, `not x`, `bool(x)` and `and`/`or`; the variable form
    -- per this script's own commit message, the shape the codebase actually uses -- implemented
    three of those and none of the others. `while x:`, `x if c else y`, `assert x`, `bool(x)` and
    a `return x` from a `-> bool` function all coerce None to False just as silently, and every
    one of them reported clean.
    """
    if isinstance(p, ast.UnaryOp) and isinstance(p.op, ast.Not):
        return "not <var>"
    if isinstance(p, ast.If) and p.test is n:
        return "if <var>:"
    if isinstance(p, ast.While) and p.test is n:
        return "while <var>:"
    if isinstance(p, ast.IfExp) and p.test is n:
        return "<var> ? a : b"
    if isinstance(p, ast.Assert) and p.test is n:
        return "assert <var>"
    if isinstance(p, ast.Compare) and p.left is n and len(p.ops) == 1 \
            and isinstance(p.ops[0], (ast.Is, ast.IsNot)) \
            and isinstance(p.comparators[0], ast.Constant) and p.comparators[0].value is True:
        # `x is True` / `x is not True` COERCE: None is not True, so the UNKNOWN silently becomes
        # the negative branch -- and this is the idiom the codebase recommends for coercion, so it
        # is where a collapse is most likely to be written deliberately and then outlive its
        # reason. StaticPoolRuntime.is_ready did exactly that: `return self._health_ok(...) is True`
        # against a tri-state contract, invisible to this checker until the context was named.
        # `is None` / `is not None` are deliberately NOT here -- those are the GUARD, not the
        # collapse -- and neither is `is False`, which is an explicit test guards_none already
        # handles.
        return "<var> is True"
    if isinstance(p, ast.BoolOp) and n in p.values:
        return "and/or"
    if isinstance(p, ast.Call) and called_name(p) == "bool" and n in p.args:
        return "bool(<var>)"
    if isinstance(p, ast.comprehension) and any(i is n for i in p.ifs):
        return "comprehension if"
    if isinstance(p, ast.Return) and p.value is n and fn is not None:
        # Returning UNKNOWN is only a collapse if the caller is promised a real bool.
        if ann_text(fn.returns).replace('"', "").replace("'", "").strip() == "bool":
            return "return <var> from -> bool"
    return None


def bool_uses_of(fn, name, parents=None):
    """Boolean-context uses of local ``name`` inside ``fn``.

    Takes a prebuilt parent map: the previous version ran a full ``ast.walk(fn)`` *per matching
    Name* looking for the parent, which is quadratic and, worse, appended a hit for every parent
    that matched rather than the one actual parent.
    """
    if parents is None:
        parents = parent_map(fn)
    out = []
    for n in ast.walk(fn):
        if not isinstance(n, ast.Name) or n.id != name or not isinstance(n.ctx, ast.Load):
            continue
        ctx = bool_context(parents.get(n), n, fn)
        if ctx:
            out.append((n.lineno, ctx, n))
    return out


def block_paths(fn):
    """node -> the chain of (block, index) slots that locate it in ``fn``'s nesting.

    Line order alone let a guard buried in a SIBLING branch vouch for a use outside it:

        if kind == "x":
            if healthy is None: return   # guard -- only on the kind == "x" path
        if not healthy: ...              # None still lands here for every other kind

    which the sweep read as clean. Comparing block paths turns "earlier in the file" into
    "actually on the path to this use". Two reviewers found this independently; the comment
    above admitted the hole rather than closing it, which is not the same thing as knowing
    how wide it was -- a false NEGATIVE here silently weakens every clean run.
    """
    paths = {}

    def visit(st, here):
        # Recurse FIRST. `setdefault` keeps whatever is already there, so descending before
        # claiming lets the DEEPEST block win each node; claiming first made every node in a
        # nested branch look like it lived at the outer statement's depth, which is exactly the
        # confusion this map exists to remove.
        #
        # TRANSPARENT vs CONDITIONAL is the whole distinction. A `with` body is not a branch --
        # control always flows through it -- so a guard inside one governs the code after it, and
        # counting it as a branch reported pool._promote_warming, which handles all three states
        # correctly, purely because its `ready is None` arm sits inside `with self._lock:`. A
        # `try` body IS conditional here: an exception can skip the rest of it, so a guard there
        # may never run, and that direction should err toward reporting.
        if isinstance(st, ast.With | ast.AsyncWith):
            for c in st.body:
                visit(c, here)
        else:
            for field in ("body", "orelse"):
                inner = getattr(st, field, None)
                if isinstance(inner, list):
                    walk(inner, here)
            for h in getattr(st, "handlers", []) or []:
                walk(h.body, here)
        for c in getattr(st, "finalbody", []) or []:
            visit(c, here)
        for case in getattr(st, "cases", []) or []:
            walk(case.body, here)
        for n in ast.walk(st):
            paths.setdefault(n, here)

    def walk(stmts, prefix):
        for i, st in enumerate(stmts):
            visit(st, prefix + ((id(stmts), i),))

    walk(fn.body, ())
    return paths


def dominates(paths, guard_node, use_node, ordered=True):
    """True if the guard's block path is a prefix of the use's -- same block, or an ancestor.

    An `if x is None: return` guard registers at the *test*, which sits in the enclosing block,
    so the common early-return form still passes. A guard nested one level deeper than the use
    does not.
    """
    g, u = paths.get(guard_node), paths.get(use_node)
    if g is None or u is None:
        return False
    if len(g) > len(u):
        return False
    # ``ordered`` mirrors the same split the caller makes on `before_line`. A `not x` use CONSUMES
    # the None branch, so only a guard that already ran helps -- same block AND at/before it. An
    # `if x:` use lets None fall through, so a later sibling guard (`if x: return` then
    # `if x is False:`) still governs it; there the block must match but the index need not.
    return all(a[0] == b[0] and (not ordered or a[1] <= b[1])
               for a, b in zip(g, u[:len(g)]))


def guards_none(fn, name, before=None, use_node=None, paths=None, rebinds=None,
                strict=False):
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
        # Ordering is by (line, COLUMN), not line alone. A one-line ternary puts its guard and
        # its use on the same line -- `return None if alive is None else bool(alive)`, which is
        # correct code -- and a line-only comparison called the guard "too late", reporting
        # pool._probe_alive, the very function whose docstring explains the tri-state contract.
        if before is not None and (n.lineno, n.col_offset) >= before:
            continue
        # ...and preceding is not enough: it must also be ON THE PATH to the use.
        if paths is not None and use_node is not None \
                and not dominates(paths, n, use_node, ordered=before is not None):
            continue
        # ...and it must still be TALKING ABOUT THE SAME VALUE. A guard is evidence about the
        # value it inspected; re-probing overwrites that value with a fresh unknown:
        #     ok = rt.is_ready(s)
        #     if ok is None: return          # guards the FIRST answer
        #     ok = rt.is_ready(s)            # unknown all over again
        #     if not ok: ...                 # collapse -- and the stale guard vouched for it
        if rebinds and before is not None \
                and any((n.lineno, n.col_offset) < rb < before for rb in rebinds):
            continue
        if not (any(isinstance(o, (ast.Is, ast.IsNot)) for o in n.ops) and
                any(isinstance(c, ast.Constant) and c.value in (None, False, True)
                    for c in n.comparators)):
            continue
        # ...and the guard must actually ELIMINATE the unknown path, not merely mention it.
        # Finding the comparison was the whole test, so
        #     if ok is None: log("unknown")        # notes it, changes nothing
        #     if not ok: return                    # None still arrives here
        # was reported CLEAN -- the sweep green-lighting the exact UNKNOWN-to-False collapse it
        # exists to gate. A guard earns its suppression only if, on the path to the use, the
        # None case cannot arrive:
        #   * `x is None` (or `== None`): the branch must EXIT (return/raise/continue/break) or
        #     REBIND x, so control reaching the use has already excluded None;
        #   * `x is not None`: the use must sit INSIDE that branch, where None cannot be.
        if not strict:
            return True
        # STRICT (advisory only): does the guard actually ELIMINATE the unknown path?
        owner = _enclosing_if(fn, n)
        if owner is None:
            # A ternary: `None if x is None else bool(x)`. The use in the arm the guard selects
            # is safe, and that IS the correct idiom -- accept it.
            return True
        if any(isinstance(o, ast.IsNot) for o in n.ops):
            if use_node is not None and _contains(owner.body, use_node):
                return True
            continue
        # `if x is None:` -- the branch must EXIT or REBIND, or the use must be confined to the
        # else arm where None cannot be. The presence of an `else` is NOT elimination on its own:
        #     if ok is None: open_episode()
        #     else:          close_episode()
        #     if not ok:     reap()          <- None still arrives, and this one DESTROYS
        # Both arms reconverge, so a split that handles each case for its own purposes says
        # nothing about the use that follows. Accepting `orelse` wholesale suppressed exactly
        # that shape -- and the test added alongside it asserted the false negative as correct.
        if _branch_settles(owner.body, name):
            return True
        if use_node is not None and owner.orelse and _contains(owner.orelse, use_node):
            return True
    return False


_TERMINATORS = (ast.Return, ast.Raise, ast.Continue, ast.Break)


def _enclosing_if(fn, node):
    """The `if` whose TEST contains `node`, if any."""
    for st in ast.walk(fn):
        if isinstance(st, (ast.If, ast.IfExp)) and any(x is node for x in ast.walk(st.test)):
            return st if isinstance(st, ast.If) else None
    return None


def _contains(stmts, node):
    return any(x is node for st in stmts for x in ast.walk(st))


def _branch_settles(stmts, name):
    """True if this branch exits, or rebinds `name` to something narrower."""
    for st in stmts:
        if isinstance(st, _TERMINATORS):
            return True
        if isinstance(st, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            tgts = st.targets if isinstance(st, ast.Assign) else [st.target]
            if any(isinstance(t, ast.Name) and t.id == name for t in tgts):
                return True
        # an if/else where BOTH arms settle also settles
        if isinstance(st, ast.If) and st.orelse \
                and _branch_settles(st.body, name) and _branch_settles(st.orelse, name):
            return True
    return False


def _enclosing_class(parents, node):
    """The ClassDef name enclosing `node`, or None."""
    cur = node
    while cur in parents:
        cur = parents[cur]
        if isinstance(cur, ast.ClassDef):
            return cur.name
    return None


def receiver_class(fn, var, trees_by_class=None):
    """Best-effort: the CLASS of `var`, from a `var = ClassName(...)` binding in `fn`.

    The tri-state index is keyed by method NAME, which cannot distinguish
    `StaticPoolRuntime.available() -> bool | None` from `AwsDisposableRuntime.available() -> bool`.
    For the shape that actually occurs in the factories -- a local built one line above the check --
    the constructor IS the declaration, so resolving it turns a name match into a receiver match.
    Returns None when the binding is not a plain constructor call (attribute receivers, parameters,
    re-binding), which the caller must treat as "unknown", never as "safe".
    """
    if fn is None or not var:
        return None
    found = None
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == var:
                    fnc = node.value.func
                    nm = fnc.id if isinstance(fnc, ast.Name) else (
                        fnc.attr if isinstance(fnc, ast.Attribute) else None)
                    if nm is None or (found is not None and found != nm):
                        return None      # rebound to something else -> ambiguous, stay unknown
                    found = nm
    return found


def enclosing_funcs(tree):
    return [n for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def bound_name(p, call):
    """The local name ``call`` is bound to under parent ``p``, or None.

    Only `x = call()` counted. Annotating the variable with the very type that makes it dangerous
    -- `ready: bool | None = rt.is_ready(s)` -- turned the check OFF, so writing the code more
    carefully was what hid the bug. Walrus and tuple unpacking were equally invisible.
    """
    if isinstance(p, ast.Assign) and len(p.targets) == 1:
        t = p.targets[0]
        if isinstance(t, ast.Name):
            return t.id
        # `ok, why = rt.is_ready(s), reason` -- match the element position.
        if isinstance(t, ast.Tuple) and isinstance(p.value, ast.Tuple):
            for tgt, val in zip(t.elts, p.value.elts):
                if val is call and isinstance(tgt, ast.Name):
                    return tgt.id
    if isinstance(p, ast.AnnAssign) and isinstance(p.target, ast.Name) and p.value is call:
        return p.target.id
    if isinstance(p, ast.NamedExpr) and isinstance(p.target, ast.Name):
        return p.target.id
    return None


def find_p1(trees, tri, strict=False):
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
    ambiguous = plain_bool_defs(trees) & set(by_name)
    hits = []
    seen = set()
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
            # `ok, why = rt.is_ready(s), reason` puts the RHS Tuple between the call and the
            # assignment, so the binding was invisible one level up.
            if isinstance(p, ast.Tuple) and isinstance(parents.get(p), ast.Assign):
                p = parents.get(p)
            ctx = None
            if isinstance(p, ast.NamedExpr):
                # `if not (ok := rt.is_ready(s)):` -- the walrus binds in STORE context, so there
                # is no Load use for the variable scan to find, and the boolean context belongs to
                # the NamedExpr rather than to a Name. Judge it as a direct use.
                wctx = bool_context(parents.get(p), p, None)
                if wctx:
                    decl = ", ".join(f"{c}@{loc}" for c, loc in by_name[nm][:2])
                    if nm in ambiguous:
                        if not strict:
                            continue          # see the call path below: name-only match, no gate
                        decl += "  [NAME ALSO DECLARED -> bool elsewhere; verify the receiver]"
                    hits.append((f"{path}:{n.lineno}", f"({p.target.id} := {recv or '?'}.{nm})",
                                 wctx.replace("<var>", "<walrus>"), decl))
                    continue
            if isinstance(p, ast.UnaryOp) and isinstance(p.op, ast.Not):
                ctx = "not <call>"
            elif isinstance(p, ast.If) and p.test is n:
                ctx = "if <call>:"
            elif isinstance(p, ast.BoolOp):
                ctx = "and/or"
            elif isinstance(p, ast.Call) and called_name(p) == "bool":
                ctx = "bool(<call>)"
            elif isinstance(p, ast.Compare) and p.left is n and len(p.ops) == 1 \
                    and isinstance(p.ops[0], (ast.Is, ast.IsNot)) \
                    and isinstance(p.comparators[0], ast.Constant) \
                    and p.comparators[0].value is True:
                # `return self._health_ok(...) is True` -- coerced straight out of the function,
                # with no local to guard and no branch to discriminate in. This is the exact shape
                # of the StaticPoolRuntime.is_ready collapse, and the reason it survived: the
                # module was unscanned AND the idiom was unnamed. Both had to be fixed to see it.
                #
                # ...but ONLY inside a method that is itself contracted tri-state. `is True` is also
                # the correct fail-closed idiom when the question is genuinely binary --
                # StaticPoolRuntime.available() is `any(self._health_ok(w) is True ...)`, and an
                # UNKNOWN worker must NOT count toward "this tier is usable". The collapse is a
                # CONTRACT violation, not a bad idiom: it matters exactly when the enclosing method
                # owes its caller the third state. Gating on the idiom alone reported available(),
                # which is the kind of false positive that trains you to skim past this script.
                _owner = _enclosing_fn(parents, n)
                if _owner is None or _owner.name not in _TRI_STATE_CONTRACT:
                    continue
                ctx = "<call> is True"
            elif isinstance(p, (ast.While,)) and p.test is n:
                ctx = "while <call>:"
            # A BARE POSITIVE TEST is the safe shape, and the assigned-variable path above already
            # treats it as one ("if <var>:" is excluded from consumes_none). `if rt.is_ready(s):`
            # with no else means None declines the affirmative action -- which is exactly what "not
            # ready yet" should do, and is why spawn_ready()'s polling loop is correct. Reporting it
            # from the GATE while the identical shape on a local was exempt was an inconsistency,
            # not a finding. It becomes dangerous only with an else that does something
            # destructive, and that is the safe-versus-destructive distinction P1b exists for and
            # states it cannot make -- so these go to the advisory, not the gate.
            if ctx in ("if <call>:", "while <call>:") and not getattr(p, "orelse", None) \
                    and not strict:
                continue
            if ctx:
                decl = ", ".join(f"{c}@{loc}" for c, loc in by_name[nm][:2])
                if nm in ambiguous:
                    # RECEIVER-AMBIGUOUS: the name is declared `-> bool` somewhere too, and this
                    # path matches on the NAME alone. Gating blindly reported all four AWS
                    # `rt.available()` factory checks the moment StaticPoolRuntime.available()
                    # became tri-state -- correct code, on receivers returning a plain bool -- so
                    # the advertised clean-tree gate could not pass.
                    #
                    # But suppressing every ambiguous name is far worse: `available`, `is_alive` and
                    # `is_ready` are ALL ambiguous, i.e. exactly the three the checker exists for,
                    # so blanket suppression silently retires it. (Verified: a deliberately
                    # collapsed `if not self.is_alive(slot)` then went unreported.)
                    #
                    # So RESOLVE the receiver. The factories build the object one line above the
                    # check, so the constructor names the class; if that class declares the method
                    # `-> bool`, this call is not a tri-state use at all. Only an UNRESOLVED
                    # receiver falls back to annotate-don't-gate.
                    # `self.is_alive(...)` is the MOST resolvable receiver, not the least: it is
                    # the enclosing class. Treating it as unknown is what let a deliberately
                    # collapsed `if not self.is_alive(slot)` slip through the first version of this.
                    owner = (_enclosing_class(parents, n) if recv == "self"
                             else receiver_class(_enclosing_fn(parents, n), recv))
                    if owner is not None and (owner, nm) not in tri:
                        continue                      # receiver's own declaration is plain bool
                    if owner is None:
                        if not strict:
                            continue
                        decl += "  [NAME ALSO DECLARED -> bool elsewhere; verify the receiver]"
                hits.append((f"{path}:{n.lineno}", f"{recv or '?'}.{nm}", ctx, decl))
            elif bound_name(p, n) is not None:
                # INDIRECT use: `healthy = rt.is_ready(slot)` ... `if not healthy:`. Only the
                # immediate parent was inspected, so this -- the shape every state machine in this
                # codebase actually uses -- was invisible: deleting an `is None` guard recreated a
                # collapse while the sweep still printed `none`. A checker blind to the dominant
                # form of the bug it hunts is worse than none, because its silence reads as proof.
                var = bound_name(p, n)
                fn = next((f for f in enclosing_funcs(tree)
                           if f.lineno <= n.lineno <= (f.end_lineno or n.lineno)), None)
                if fn is None:
                    continue
                fpaths = block_paths(fn)
                rebinds = bindings_of(fn, var)
                fparents = parent_map(fn)
                for lineno, uctx, unode in bool_uses_of(fn, var, fparents):
                    # The use must come AFTER this tri-state binding. bool_uses_of returns every
                    # use of the NAME, so a `if not ok:` on an unrelated earlier `ok = commit()`
                    # was reported, blamed on a call three lines below it, and printed as
                    # `ok = rt.is_ready()` -- a line that does not exist. Reporting correct code
                    # under a quoted line it does not contain is worse than missing it.
                    if (lineno, unode.col_offset) < (n.lineno, n.col_offset):
                        continue
                    # WHICH use decides whether order matters.
                    #   `if x:` tests for SUCCESS and lets both other states fall through, so a
                    #     discriminator anywhere -- including after it -- still governs them. Both
                    #     aws_worker resume loops are this shape: `if _ok: return` then
                    #     `if _ok is False:`. Correct, and demanding a preceding guard flags them.
                    #   `not x` / `and`/`or` CONSUME the None branch on the spot, so only a guard
                    #     that already ran can save them. This is the shape the review cited:
                    #     `if not healthy: return` followed by a now-useless `if healthy is None:`.
                    # "<var> is True" joins "if <var>:" as ORDER-INDEPENDENT. The discrimination
                    # for this idiom is written INSIDE the branch it opens --
                    #     if verdict is not True:
                    #         if verdict is False: ...   # <- the real discriminator
                    # -- which a preceding-guard rule structurally cannot see. Demanding order here
                    # reported static_pool.spawn(), which discriminates correctly.
                    consumes_none = uctx not in ("if <var>:", "<var> is True")
                    if guards_none(fn, var,
                                   before=(lineno, unode.col_offset) if consumes_none else None,
                                   use_node=unode, paths=fpaths,
                                   rebinds=rebinds if consumes_none else None,
                                   strict=strict):
                        continue
                    decl = ", ".join(f"{c}@{loc}" for c, loc in by_name[nm][:2])
                    if nm in ambiguous:
                        decl += "  [NAME ALSO DECLARED -> bool elsewhere; verify the receiver]"
                    # One line per USE. Two branches assigning the same variable re-ran the whole
                    # use scan and emitted a duplicate for each -- the exact repetitive texture
                    # that teaches you to skim the report.
                    key = (path, lineno, var, uctx)
                    if key in seen:
                        continue
                    seen.add(key)
                    hits.append((f"{path}:{lineno}", f"{var} = {recv or '?'}.{nm}",
                                 f"{uctx}, no tri-state guard in {fn.name}()", decl))
    return hits


def find_p2(trees):
    """Two budget scopes that BOTH run in one function, each getting a fresh full deadline."""
    hits = []
    for path, tree in trees.items():
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            paths = block_paths(fn)
            loops = {id(n) for lp in ast.walk(fn)
                     if isinstance(lp, (ast.For, ast.AsyncFor, ast.While))
                     for st in lp.body for n in ast.walk(st)}
            scopes = []
            for c in ast.walk(fn):
                if not isinstance(c, (ast.With, ast.AsyncWith)):
                    continue
                items = [ann_text(i.context_expr) for i in c.items]
                budgets = [t for t in items if "_budget(" in t]
                if not budgets:
                    continue
                # `with A(), B():` is ONE statement, and Python defines multiple items as
                # NESTING -- B opens inside A, so B mins against a live outer scope, the safe
                # case. Recording each item separately reported that as two siblings costing 2x.
                # Only the OUTERMOST budget item of a with-statement can be a sibling of anything.
                scopes.append((c, budgets[0], len(budgets)))
            for c, txt, _n in scopes:
                if id(c) in loops:
                    # A scope inside a loop body gets a fresh full deadline PER ITERATION, which
                    # is the same defect with an unbounded multiplier -- and it was never reported,
                    # because a single lexical scope can't be its own sibling.
                    hits.append((f"{path}:{fn.lineno}", fn.name,
                                 [f"L{c.lineno} (in a loop -- fresh budget per iteration)"]))
            for i, (a, _t, _n) in enumerate(scopes):
                for b, _t2, _n2 in scopes[i + 1:]:
                    pa, pb = paths.get(a), paths.get(b)
                    if pa is None or pb is None:
                        continue
                    # Nested (one path is a prefix of the other) -> the inner mins against a live
                    # outer scope. Safe, and the reason nesting is the fix for this defect.
                    shared = min(len(pa), len(pb))
                    if pa[:shared] == pb[:shared]:
                        continue
                    # Divergent BLOCK identity means mutually exclusive arms -- an if/else where
                    # only one ever runs. Reported as 2x the bound; it is 1x.
                    if any(x[0] != y[0] for x, y in zip(pa, pb)):
                        continue
                    hits.append((f"{path}:{fn.lineno}", fn.name,
                                 [f"L{a.lineno}", f"L{b.lineno}"]))
    return hits


def is_clock(node):
    """Is this expression a read of the current time?"""
    t = ann_text(node)
    if t in ("now", "_now"):
        return True
    return any(t.endswith(c) for c in
               ("_clock()", "time.monotonic()", "time.time()", "time.perf_counter()",
                "monotonic()", "_now()"))


def name_tokens(attr):
    """`self._last_probe_at` -> {'last','probe','at'} -- TOKENS, not substrings.

    The old test was `"at" in key.lower()`, which matches `self._st-AT-e` and `self._d-AT-a`, and
    the value test was `"now" in val`, which matches `self._k-NOW-n_good`. Three of the fourteen
    hits this check produced were manufactured entirely by those two substring matches.
    """
    return set(attr.lower().replace("self.", "").strip("_").split("_"))


def gate_attrs(fn):
    """Attributes ``fn`` READS inside a comparison -- i.e. ones that gate something here.

    P3 claimed to find "a rate-limit timestamp", but tested only the NAME and the VALUE, so every
    start-time, idle-marker and phase-timer qualified. A throttle is defined by having a GATE
    (`if now - self._x < interval: return`) in the same function as its stamp, so require one.
    """
    out = set()
    for n in ast.walk(fn):
        if not isinstance(n, ast.Compare):
            continue
        for side in [n.left, *n.comparators]:
            for sub in ast.walk(side):
                if isinstance(sub, ast.Attribute) and ann_text(sub).startswith("self."):
                    out.add(ann_text(sub))
    return out


# Logging, event flags and container bookkeeping are not the slow operation a throttle exists to
# space out. Counting them made `self._last_idle_at = now; self._idle_event.set()` -- correct code
# -- read as "stamped before the call".
BOOKKEEPING = ("log", "logger", "debug", "info", "warning", "error", "exception",
               "set", "clear", "append", "add", "discard", "pop", "get", "setdefault",
               "notify", "notify_all", "update", "remove")


def is_bookkeeping(call):
    nm = called_name(call) or ""
    recv = (receiver_of(call) or "").lower()
    return nm in BOOKKEEPING or "log" in recv


def find_p3(trees):
    """A throttle stamp written BEFORE the slow call it throttles, and never re-stamped after it.

    A timestamp written before the call it bounds is already stale when the call returns: a call
    that outruns its own interval is eligible again the moment it finishes.
    """
    hits = []
    STAMPY = {"last", "attempt", "since", "at", "stamp", "next", "prev"}
    for path, tree in trees.items():
        for cls in ast.walk(tree):
            if not isinstance(cls, ast.ClassDef):
                continue
            for fn in ast.walk(cls):
                if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                # The gate must be in THIS function. A throttle is a three-step shape --
                # check the stamp, stamp it, then do the slow thing -- and all three steps live
                # together. Accepting a gate anywhere in the class admitted every start-time and
                # idle-marker in a 3k-line class, which is how this check reached 14 hits with
                # nothing to say.
                gated = gate_attrs(fn)
                if not gated:
                    continue
                # A stamp written inside an `except` handler records WHEN THE FAILURE HAPPENED --
                # an event, at the only moment it can be observed. That is the correct shape, not
                # the bug; `_mint_fail_at` and friends were reported purely for being on one.
                in_handler = {id(n) for h in ast.walk(fn)
                              if isinstance(h, ast.ExceptHandler)
                              for st in h.body for n in ast.walk(st)}
                stamps = {}
                for n in ast.walk(fn):
                    if isinstance(n, ast.Assign) and len(n.targets) == 1:
                        tgt, val = n.targets[0], n.value
                    elif isinstance(n, ast.AnnAssign) and n.value is not None:
                        tgt, val = n.target, n.value
                    else:
                        continue
                    key = ann_text(tgt).split("[")[0]
                    if not key.startswith("self."):
                        continue
                    # The value may be a clock read OR a local already holding one
                    # (`ts = self._clock(); self._last_at = ts`), which the text match missed.
                    if not (is_clock(val) or any(is_clock(v) for v in local_clocks(fn, val))):
                        continue
                    if key not in gated or not (name_tokens(key) & STAMPY):
                        continue
                    if id(n) in in_handler:
                        continue
                    stamps.setdefault(key, []).append(n)
                for key, nodes in stamps.items():
                    last = max(n.lineno for n in nodes)
                    # The defect is a slow call AFTER the final stamp with no re-stamp following
                    # it. Requiring exactly one assignment instead reported correct token-bucket
                    # refills and, worse, went silent whenever a stamp appeared in both arms of an
                    # if/else -- neither of which is the property.
                    after = [c for c in ast.walk(fn)
                             if isinstance(c, ast.Call) and c.lineno > last and not is_clock(c)
                             and not is_bookkeeping(c)]
                    if after:
                        hits.append((f"{path}:{last}", fn.name,
                                     f"{key}  (stamped before {ann_text(after[0].func)}(...))"))
    return hits


def local_clocks(fn, val):
    """If ``val`` is a bare local name, the expressions assigned to it in ``fn``."""
    if not isinstance(val, ast.Name):
        return []
    return [n.value for n in ast.walk(fn)
            if isinstance(n, ast.Assign) and len(n.targets) == 1
            and isinstance(n.targets[0], ast.Name) and n.targets[0].id == val.id]


def main():
    """Run every check and print the report.

    Behind a main() guard because the module-level version ran the ENTIRE sweep -- reading five
    source files and printing three reports -- on `import pattern_sweep`, which is what a test of
    these checks has to do. A checker with no way to test itself is the thing it warns about.
    """
    trees = {}
    missing = []
    for f in FILES:
        fp = ROOT / f
        # Unguarded reads died with a raw traceback on a missing or unparseable file. That at
        # least fails loudly -- but it exits 1 for the same reason a real finding would, so the
        # two are indistinguishable to anything calling this.
        try:
            trees[f.split("/")[-1]] = ast.parse(fp.read_text())
        except (OSError, SyntaxError) as exc:
            missing.append(f"{f}: {type(exc).__name__}: {exc}")
    if missing:
        print("CANNOT SCAN:")
        for m in missing:
            print(f"  {m}")
        print(f"\nRefusing to report on a partial scan ({len(missing)}/{len(FILES)} unreadable).")
        return 2

    tri = tri_state_defs(trees)
    print(f"tri-state methods found: {len(tri)}")
    for (cls, name), v in sorted(tri.items()):
        print(f"    {cls + '.' + name:<40} {v}")
    if not tri:
        # A run that found nothing to look for printed exactly what a clean run prints. P1 can
        # only report uses of names this scan collected, so zero declarations means a guaranteed
        # `none` -- the most reassuring line in the output, produced by having scanned nothing.
        print("\nNO tri-state declarations found. P1 cannot report anything, so its `none` below\n"
              "would be vacuous. Check FILES and the annotation forms in tri_state_defs.")
        return 2

    print("\n=== P1 tri-state collapse (a `bool | None` used as a boolean)")
    p1 = find_p1(trees, tri)
    print("  none" if not p1 else "")
    for loc, nm, ctx, decl in p1:
        print(f"  {loc:<26} {nm}()  used as `{ctx}`   (declared {decl})")

    print("\n=== P2 budget scopes that both run in one function")
    p2 = find_p2(trees)
    print("  none" if not p2 else "")
    for loc, nm, lines in p2:
        print(f"  {loc:<26} {nm}()  scopes at {', '.join(lines)}")

    print("\n=== P3 throttle stamp written before the call it throttles  [ADVISORY]")
    p3 = find_p3(trees)
    print("  none" if not p3 else "")
    for loc, nm, key in p3:
        print(f"  {loc:<26} {nm}()  {key}")
    print("  NOTE: advisory only, and NOT gated on. P3 cannot tell a stamp that RECORDS AN EVENT\n"
          "  (`self._fail_at = now` at the moment of the failure -- correct) from one written\n"
          "  BEFORE the work it throttles (the bug). Distinguishing them needs to know which call\n"
          "  the throttle protects, which is not recoverable from the AST. Read these by hand;\n"
          "  every hit on this tree so far has been correct code.")

    # EXIT NONZERO on a real finding, so this can gate. A constant exit 0 meant no CI step or
    # wrapper could tell "clean" from "findings" from "crashed before scanning" -- while the
    # output was being cited as evidence the branch is correct.
    strict_hits = find_p1(trees, tri, strict=True)
    weak = [h for h in strict_hits if h not in p1]
    print("\n=== P1b guard present but the UNKNOWN path is not eliminated  [ADVISORY]\n")
    if not weak:
        print("  none")
    for loc, nm, ctx, decl in weak:
        print(f"  {loc:26} {nm}  used as `{ctx}`   ({decl})")
    print("  NOTE: advisory only, and NOT gated on. P1 accepts a tri-state comparison as a guard;\n"
          "  this pass additionally demands the guarded branch EXIT, REBIND, or carry an else --\n"
          "  i.e. that None provably cannot reach the use. It cannot tell a None that falls through\n"
          "  to a SAFE path (declining to promote, declining to return early) from one that falls\n"
          "  through to a DESTRUCTIVE one (reap, evict, mark dead), and only the second is a bug.\n"
          "  Gating on it reported four hits on this tree, every one of them correct code. Read\n"
          "  these by hand; what you are looking for is a False that DESTROYS something.")
    return 1 if (p1 or p2) else 0


if __name__ == "__main__":
    sys.exit(main())
