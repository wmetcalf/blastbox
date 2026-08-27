"""The sweep is used as EVIDENCE that the tri-state work is complete, so its blind spots are the
product's blind spots. Two reviewers independently found a false negative -- a guard in a sibling
branch vouching for a use outside it -- that the source comment had acknowledged as a known
approximation without ever measuring how wide it was. These pin both directions: the collapses it
must report, and the correct shapes it must stay quiet about.
"""
import ast
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import pattern_sweep as ps  # noqa: E402

PREAMBLE = '''
class R:
    def is_ready(self, s) -> "bool | None": ...
'''


def sweep(body: str):
    tree = ast.parse(PREAMBLE + "\nclass P:\n" + body)
    trees = {"probe.py": tree}
    return ps.find_p1(trees, ps.tri_state_defs(trees))


COLLAPSES = {
    "guard_in_a_sibling_branch": '''
    def f(self, s):
        rt = R()
        healthy = rt.is_ready(s)
        if s.kind == "x":
            if healthy is None:
                return "unknown"
        if not healthy:
            return "dead"
''',
    "guard_only_in_the_else_arm": '''
    def f(self, s):
        rt = R()
        healthy = rt.is_ready(s)
        if s.kind == "x":
            pass
        else:
            if healthy is None:
                return "unknown"
        if not healthy:
            return "dead"
''',
    "guard_after_the_consuming_use": '''
    def f(self, s):
        rt = R()
        healthy = rt.is_ready(s)
        if not healthy:
            return "dead"
        if healthy is None:
            return "unknown"
''',
    # Binding forms. Only bare `x = call()` was recognised, so ANNOTATING the variable with the
    # very type that makes it dangerous switched the checker off.
    "annotated_assignment": '''
    def f(self, s):
        rt = R()
        ok: "bool | None" = rt.is_ready(s)
        if not ok:
            return "dead"
''',
    "walrus_binding": '''
    def f(self, s):
        rt = R()
        if not (ok := rt.is_ready(s)):
            return "dead"
''',
    "tuple_target": '''
    def f(self, s):
        rt = R()
        ok, why = rt.is_ready(s), "probe"
        if not ok:
            return "dead"
''',
    # Boolean contexts the docstring advertised or implied, none of which were implemented for
    # the variable form -- each coerces None to False exactly as silently as `if not x`.
    "while_loop": '''
    def f(self, s):
        rt = R()
        ok = rt.is_ready(s)
        while ok:
            return "ok"
''',
    "ternary_test": '''
    def f(self, s):
        rt = R()
        ok = rt.is_ready(s)
        return "ok" if ok else "dead"
''',
    "assert_statement": '''
    def f(self, s):
        rt = R()
        ok = rt.is_ready(s)
        assert ok
''',
    "bool_call": '''
    def f(self, s):
        rt = R()
        ok = rt.is_ready(s)
        return bool(ok)
''',
    "guard_in_a_nested_def_that_never_runs": '''
    def f(self, s):
        rt = R()
        ok = rt.is_ready(s)
        def cb():
            if ok is None:
                return "unknown"
        if not ok:
            return "dead"
''',
    "value_reprobed_after_the_guard": '''
    def f(self, s):
        rt = R()
        ok = rt.is_ready(s)
        if ok is None:
            return "unknown"
        ok = rt.is_ready(s)
        if not ok:
            return "dead"
''',
    "guard_inside_a_try_body": '''
    def f(self, s):
        rt = R()
        healthy = rt.is_ready(s)
        try:
            if healthy is None:
                return "unknown"
        except Exception:
            pass
        if not healthy:
            return "dead"
''',
}

CORRECT = {
    "dominating_early_return": '''
    def f(self, s):
        rt = R()
        healthy = rt.is_ready(s)
        if healthy is None:
            return "unknown"
        if not healthy:
            return "dead"
''',
    "guard_inside_a_with_block": '''
    def f(self, s):
        rt = R()
        healthy = rt.is_ready(s)
        with s.lock:
            if healthy is None:
                return "unknown"
        if not healthy:
            return "dead"
''',
    "later_guard_for_a_non_consuming_use": '''
    def f(self, s):
        rt = R()
        healthy = rt.is_ready(s)
        if healthy:
            return "ok"
        if healthy is False:
            return "dead"
        return "unknown"
''',
    "same_line_ternary_guard": '''
    def f(self, s):
        rt = R()
        ok = rt.is_ready(s)
        return None if ok is None else bool(ok)
''',
    "use_of_the_same_name_before_the_tri_state_call": '''
    def f(self, s):
        rt = R()
        ok = self.commit()
        if not ok:
            return "dead"
        ok = rt.is_ready(s)
        if ok is None:
            return "unknown"
        return "ok"
''',
    "guard_and_use_both_in_the_same_branch": '''
    def f(self, s):
        rt = R()
        healthy = rt.is_ready(s)
        if s.kind == "x":
            if healthy is None:
                return "unknown"
            if not healthy:
                return "dead"
''',
}


@pytest.mark.parametrize("name", sorted(COLLAPSES))
def test_a_tri_state_collapse_is_reported(name):
    assert sweep(COLLAPSES[name]), f"{name}: UNKNOWN is consumed as False and the sweep said nothing"


@pytest.mark.parametrize("name", sorted(CORRECT))
def test_correctly_discriminated_code_is_not_reported(name):
    assert not sweep(CORRECT[name]), f"{name}: false positive -- all three states are handled"


def test_the_module_does_not_run_its_report_on_import(capsys):
    """Importing used to read five source files and print three reports."""
    assert capsys.readouterr().out == ""
    assert callable(ps.main)


def test_a_use_is_reported_once_per_use_not_once_per_assignment():
    """Two branches assigning one variable re-ran the whole use scan and duplicated every hit."""
    hits = sweep('''
    def f(self, s):
        rt = R()
        if s.cold:
            ok = rt.is_ready(s)
        else:
            ok = rt.is_ready(s)
        if not ok:
            return "dead"
''')
    assert len(hits) == 1, hits


def test_a_declaration_outside_a_class_body_is_still_found():
    """tri_state_defs walked only ClassDef bodies, so a module-level or nested `bool | None`
    helper yielded `tri-state methods found: 0` -- and P1 then reported `none` for every use of
    it. A scan that found nothing to look for printed the same line as a clean run."""
    tree = ast.parse('''
def is_settled(s) -> "bool | None": ...

class Outer:
    def wrap(self):
        def is_quiesced(s) -> "bool | None": ...
''')
    found = {name for _cls, name in ps.tri_state_defs({"m.py": tree})}
    assert found == {"is_settled", "is_quiesced"}, found


# --- P2: budget scopes ---------------------------------------------------------------------
P2_CASES = {
    # `with A(), B():` is ONE statement, and Python defines multiple items as NESTING, so B mins
    # against a live outer scope -- the safe case, reported as costing 2x the bound.
    "one_with_statement_two_items": ("clean", '''
class C:
    def f(self):
        with self._a_budget(10), self._b_budget(5):
            pass
'''),
    "mutually_exclusive_arms": ("clean", '''
class C:
    def f(self, c):
        if c:
            with self._a_budget(10):
                pass
        else:
            with self._b_budget(5):
                pass
'''),
    "properly_nested_scopes": ("clean", '''
class C:
    def f(self):
        with self._a_budget(10):
            with self._b_budget(5):
                pass
'''),
    "genuine_siblings": ("report", '''
class C:
    def f(self):
        with self._a_budget(10):
            pass
        with self._b_budget(5):
            pass
'''),
    # A single lexical scope cannot be its own sibling, so the unbounded-multiplier case -- a
    # fresh full deadline on every iteration -- was the one shape never reported.
    "scope_inside_a_loop": ("report", '''
class C:
    def f(self, xs):
        for x in xs:
            with self._a_budget(10):
                pass
'''),
}


@pytest.mark.parametrize("name", sorted(P2_CASES))
def test_p2_budget_scopes(name):
    want, src = P2_CASES[name]
    hits = ps.find_p2({"p.py": ast.parse(src)})
    assert bool(hits) == (want == "report"), f"{name}: wanted {want}, got {hits}"


# --- P3: throttle stamps -------------------------------------------------------------------
def test_p3_does_not_fire_on_substring_matches_of_its_own_keywords():
    """`self._st-AT-e`, `self._d-AT-a` and `self._k-NOW-n_good` matched "at"/"now" as SUBSTRINGS."""
    hits = ps.find_p3({"p.py": ast.parse('''
class C:
    def f(self):
        now = self._clock()
        if now - self._gate > 1:
            return
        self._state = self._clock()
        self._data = now
        self._chosen = self._known_good
        self.work()
''')})
    assert not hits, hits


def test_p3_ignores_a_stamp_that_records_a_failure_event():
    """A stamp inside an `except` records WHEN THE FAILURE HAPPENED -- the correct shape."""
    hits = ps.find_p3({"p.py": ast.parse('''
class C:
    def f(self):
        now = self._clock()
        if now - self._fail_at < 5:
            return
        try:
            self.mint()
        except OSError:
            self._fail_at = self._clock()
            self.report()
            raise
''')})
    assert not hits, hits


# --- exit status ---------------------------------------------------------------------------
def test_the_sweep_exits_nonzero_when_it_cannot_scan(tmp_path, monkeypatch, capsys):
    """A constant exit 0 meant nothing could tell "clean" from "findings" from "never ran"."""
    monkeypatch.setattr(ps, "ROOT", tmp_path)
    assert ps.main() == 2
    assert "CANNOT SCAN" in capsys.readouterr().out


def test_a_scan_that_found_no_declarations_refuses_to_report_clean(tmp_path, monkeypatch, capsys):
    """P1 can only report uses of names the declaration scan collected, so zero declarations
    guarantees `none` -- the most reassuring line in the output, produced by scanning nothing."""
    for f in ps.FILES:
        (tmp_path / f).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / f).write_text("x = 1\n")
    monkeypatch.setattr(ps, "ROOT", tmp_path)
    assert ps.main() == 2
    assert "NO tri-state declarations found" in capsys.readouterr().out


# --- P1b: a guard that MENTIONS the unknown without eliminating it -------------------------

_NOTES_BUT_DOES_NOT_GUARD = '''
    def f(self, s):
        rt = R()
        ok = rt.is_ready(s)
        if ok is None:
            self.log("unknown")
        if not ok:
            self.reap(s)
'''

_GUARD_EXITS = '''
    def f(self, s):
        rt = R()
        ok = rt.is_ready(s)
        if ok is None:
            return "unknown"
        if not ok:
            self.reap(s)
'''

_ARMS_RECONVERGE = '''
    def f(self, s):
        rt = R()
        ok = rt.is_ready(s)
        if ok is None:
            self.open_episode(s)
        else:
            self.close_episode(s)
        if not ok:
            self.reap(s)
'''

_USE_CONFINED_TO_THE_ELSE = '''
    def f(self, s):
        rt = R()
        ok = rt.is_ready(s)
        if ok is None:
            self.open_episode(s)
        else:
            if not ok:
                self.reap(s)
'''


def _strict(body: str):
    tree = ast.parse(PREAMBLE + "\nclass P:\n" + body)
    trees = {"probe.py": tree}
    return ps.find_p1(trees, ps.tri_state_defs(trees), strict=True)


def test_the_gate_still_accepts_a_bare_mention_so_it_stays_precise():
    """P1 GATES, so it must not fire on correct code. Demanding elimination there reported four
    hits on this tree, every one correct -- a ternary, an if/else split, and two `if ok:` positives
    where None declining the safe branch is the intended behaviour."""
    assert not sweep(_NOTES_BUT_DOES_NOT_GUARD)


def test_strict_mode_reports_a_guard_that_only_mentions_the_unknown():
    """`if ok is None: log()` changes nothing -- None still reaches `if not ok: reap(s)`, and that
    False DESTROYS something. The gating pass accepts the comparison as a guard; strict mode is
    what makes the hole visible."""
    assert _strict(_NOTES_BUT_DOES_NOT_GUARD), (
        "strict mode green-lit a guard that lets None fall through to a reap"
    )


def test_strict_mode_accepts_a_guard_that_exits():
    assert not _strict(_GUARD_EXITS)


def test_strict_mode_still_reports_arms_that_reconverge_onto_the_use():
    """An `else` is not elimination. Both arms handle their own case and then RECONVERGE, so None
    still arrives at `if not ok: reap(s)` -- and that one destroys something. The first version of
    this advisory accepted any `orelse`, and the test written beside it asserted the false negative
    as correct; the fixture is unchanged, only the expectation was wrong."""
    assert _strict(_ARMS_RECONVERGE), (
        "an if/else whose arms reconverge was suppressed, but None reaches the reap"
    )


def test_strict_mode_accepts_a_use_confined_to_the_else_arm():
    """The genuinely safe split: the use sits INSIDE the else, where None cannot be."""
    assert not _strict(_USE_CONFINED_TO_THE_ELSE)


# --- `is True` is a coercion, and it matters inside a tri-state contract ---------------------

_COERCES_INSIDE_CONTRACT = '''
    def is_ready(self, s):
        rt = R()
        return rt.is_ready(s) is True
'''

_COERCES_OUTSIDE_CONTRACT = '''
    def available(self):
        rt = R()
        return any(rt.is_ready(w) is True for w in self.workers)
'''


def test_is_True_inside_a_tri_state_method_is_reported():
    """`return self._health_ok(...) is True` was a live UNKNOWN-to-False collapse in
    StaticPoolRuntime.is_ready, and it survived because BOTH halves were missing: the module was
    not in FILES, and `is True` was not a named boolean context. Fixing either one alone still
    reported clean -- verified by reverting the fix and re-running with each half in place."""
    assert sweep(_COERCES_INSIDE_CONTRACT)


def test_is_True_outside_the_contract_is_not_reported():
    """The same idiom is CORRECT where the question is genuinely binary: availability is
    fail-closed, so an UNKNOWN worker must not count toward "this tier is usable". The collapse is
    a contract violation, not a bad idiom -- gating on the idiom alone reported `available()`."""
    assert not sweep(_COERCES_OUTSIDE_CONTRACT)
