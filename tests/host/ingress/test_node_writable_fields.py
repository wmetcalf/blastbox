"""The write allowlist must cover what the dispatcher ACTUALLY writes (#178).

I guessed the allowlist and guessed wrong: it omitted `expires_at` and `security_warnings`,
which the real terminal writes carry — so a credential-less node could not mark ANY job DONE
or FAILED. The feature was non-functional and every test passed, because the tests wrote only
the fields I had happened to allow.

So the set is no longer asserted against my judgement. It is DERIVED from dispatch's own
source: every keyword a real `update`/`update_if_status` call passes is a field a node must be
able to write. If someone adds a field to a terminal write and not to the allowlist, this
fails instead of the deployment.
"""
from __future__ import annotations

import ast
import importlib
import inspect

import pytest

from blastbox.host.ingress.node_claim import NODE_WRITABLE_FIELDS

#: Keywords that are part of the CALL, not fields of the Job.
_NOT_FIELDS = frozenset({"expect_claim_id", "expect_status", "job_id", "claimant_tier",
                         "engine", "status_in", "q", "limit", "offset", "order"})


def _written_fields(module) -> set[str]:
    """Keyword arguments of every real update()/update_if_status() call, via the AST.

    NOT a regex. The regex version of this reported `target_tier` as written, because
    dispatch interpolates it into an f-string in an error message -- so the very test written
    to stop me guessing was itself guessing. The AST sees calls, not text.
    """
    found: set[str] = set()
    for node in ast.walk(ast.parse(inspect.getsource(module))):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in ("update", "update_if_status"):
            continue
        found |= {kw.arg for kw in node.keywords if kw.arg}
    return found - _NOT_FIELDS


@pytest.mark.parametrize("modname", [
    "blastbox.host.dispatch",
    "blastbox.host.runtime.vm_dispatch",
])
def test_every_field_a_dispatcher_writes_is_writable_by_a_node(modname):
    """DERIVED, not judged. A node runs the same dispatcher code as a DB-backed one."""
    module = importlib.import_module(modname)
    written = _written_fields(module)
    assert written, f"the scraper found no update() calls in {modname} -- it has drifted"
    missing = sorted(written - set(NODE_WRITABLE_FIELDS))
    assert not missing, (
        f"{modname} writes {missing} on a real transition, but NODE_WRITABLE_FIELDS refuses "
        f"them, so a credential-less node cannot complete a job. Add them, or route that "
        f"write through the control plane deliberately.")


def test_the_allowlist_still_refuses_the_dangerous_fields():
    """Widening it must not become a habit. These are the escalation surface: where this host
    writes a result, what engine a job is, and which node owns it."""
    for never in ("result_dir", "engine", "filename", "job_id", "params", "created_at",
                  "target_tier", "net_policy"):
        assert never not in NODE_WRITABLE_FIELDS, (
            f"{never!r} became node-writable; that is privilege escalation, not a field")
