"""An image must record what it was built FROM, or it cannot be rebuilt."""

from __future__ import annotations

import json
import subprocess

from blastbox.host.stamp import (
    LABEL_BASE_DIGEST,
    LABEL_BASE_NAME,
    LABEL_BLASTBOX,
    LABEL_REVISION,
    UNKNOWN,
    base_digest,
    build_args,
    git_revision,
    read,
)


def _fake(responses: dict[tuple, tuple[int, str]]):
    def run(argv):
        argv = tuple(argv)
        for key, (code, out) in responses.items():
            if argv[: len(key)] == key:
                return subprocess.CompletedProcess(list(argv), code, out, "")
        return subprocess.CompletedProcess(list(argv), 1, "", "no stub")
    return run


def test_a_dirty_tree_is_marked_dirty():
    """A clean sha for a dirty tree names a commit that never built this."""
    # rev-parse and status share the ("git","-C") prefix, so _fake cannot tell
    # them apart; branch on the subcommand instead.
    def run2(argv):
        argv = list(argv)
        if "rev-parse" in argv:
            return subprocess.CompletedProcess(argv, 0, "abc123\n", "")
        return subprocess.CompletedProcess(argv, 0, " M src/x.py\n", "")
    assert git_revision(".", run2) == "abc123-dirty"


def test_a_clean_tree_records_the_bare_sha():
    def run(argv):
        argv = list(argv)
        if "rev-parse" in argv:
            return subprocess.CompletedProcess(argv, 0, "abc123\n", "")
        return subprocess.CompletedProcess(argv, 0, "", "")
    assert git_revision(".", run) == "abc123"


def test_base_is_recorded_by_digest_not_tag():
    """A tag can be re-pointed or deleted; that is what lost the worker base."""
    def run(argv):
        argv = list(argv)
        if "{{json .RepoDigests}}" in argv:
            return subprocess.CompletedProcess(
                argv, 0, json.dumps(["reg/img@sha256:deadbeef"]), "")
        return subprocess.CompletedProcess(argv, 1, "", "")
    assert base_digest("reg/img:tag", run) == "sha256:deadbeef"


def test_a_local_only_base_falls_back_to_the_image_id():
    """Never-pushed bases have no repo digest, but the image ID still pins it."""
    def run(argv):
        argv = list(argv)
        if "{{json .RepoDigests}}" in argv:
            return subprocess.CompletedProcess(argv, 0, "[]", "")
        # Only answer the actual image-ID inspect, so the test notices if the
        # fallback stops making that call.
        assert argv[:2] == ["docker", "inspect"] and "{{.Id}}" in argv, argv
        return subprocess.CompletedProcess(argv, 0, "sha256:localid\n", "")
    assert base_digest("redtusk-worker:bb0127", run) == "sha256:localid"


def test_build_args_carry_all_four_facts():
    def run(argv):
        argv = list(argv)
        if "rev-parse" in argv:
            return subprocess.CompletedProcess(argv, 0, "sha1\n", "")
        if "status" in argv:
            return subprocess.CompletedProcess(argv, 0, "", "")
        if "{{json .RepoDigests}}" in argv:
            return subprocess.CompletedProcess(argv, 0, json.dumps(["x@sha256:bd"]), "")
        return subprocess.CompletedProcess(argv, 1, "", "")
    args = build_args(blastbox_version="0.1.27", repo=".", base="base:tag", runner=run)
    joined = " ".join(args)
    assert f"{LABEL_BLASTBOX}=0.1.27" in joined
    assert f"{LABEL_REVISION}=sha1" in joined
    assert f"{LABEL_BASE_NAME}=base:tag" in joined
    assert f"{LABEL_BASE_DIGEST}=sha256:bd" in joined


def test_reading_an_unstamped_image_is_not_a_silent_pass():
    """The pre-existing fleet images carry nothing; that must be visible."""
    run = _fake({("docker", "inspect"): (0, "null")})
    got = read("legacy:image", run)
    assert got.base_digest == UNKNOWN
    assert not got.reproducible


def test_an_image_without_a_base_digest_is_not_reproducible():
    """Revision alone is not enough: the base is what was lost."""
    labels = {LABEL_BLASTBOX: "0.1.27", LABEL_REVISION: "sha1"}
    run = _fake({("docker", "inspect"): (0, json.dumps(labels))})
    got = read("img", run)
    assert got.revision == "sha1"
    assert not got.reproducible


def test_a_fully_stamped_image_is_reproducible():
    labels = {
        LABEL_BLASTBOX: "0.1.27", LABEL_REVISION: "sha1",
        LABEL_BASE_NAME: "b:t", LABEL_BASE_DIGEST: "sha256:bd",
    }
    run = _fake({("docker", "inspect"): (0, json.dumps(labels))})
    assert read("img", run).reproducible


def test_a_non_git_tree_uses_the_recorded_revision_file(tmp_path):
    """Deployed trees are rsync'd copies, not checkouts.

    Measured on toolz2: stamping a real build reported revision=unknown because
    ~/redtusk-bb is not a git repo. A deploy can record where the tree came from.
    """
    from blastbox.host.stamp import REVISION_FILE

    (tmp_path / REVISION_FILE).write_text("deadbeef\n", encoding="utf-8")

    def run(argv):
        return subprocess.CompletedProcess(list(argv), 128, "", "not a git repository")
    assert git_revision(tmp_path, run) == "deadbeef"


def test_a_real_checkout_wins_over_a_stale_revision_file(tmp_path):
    """The tree's own git state is authoritative when it has one."""
    from blastbox.host.stamp import REVISION_FILE

    (tmp_path / REVISION_FILE).write_text("stale\n", encoding="utf-8")

    def run(argv):
        argv = list(argv)
        if "rev-parse" in argv:
            return subprocess.CompletedProcess(argv, 0, "livesha\n", "")
        return subprocess.CompletedProcess(argv, 0, "", "")
    assert git_revision(tmp_path, run) == "livesha"


def test_no_git_and_no_file_is_unknown_not_a_guess(tmp_path):
    def run(argv):
        return subprocess.CompletedProcess(list(argv), 128, "", "not a git repository")
    assert git_revision(tmp_path, run) == UNKNOWN
