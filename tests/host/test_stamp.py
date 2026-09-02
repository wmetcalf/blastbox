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


def test_a_local_only_base_has_no_repo_digest():
    """An image ID is NOT a repo digest and must not be written as one."""
    def run(argv):
        argv = list(argv)
        if "{{json .RepoDigests}}" in argv:
            return subprocess.CompletedProcess(argv, 0, "[]", "")
        return subprocess.CompletedProcess(argv, 1, "", "")
    assert base_digest("redtusk-worker:bb0127", run) == ""


def test_the_image_id_is_recorded_under_its_own_label():
    from blastbox.host.stamp import LABEL_BASE_IMAGE_ID, base_image_id

    def run(argv):
        argv = list(argv)
        assert argv[:2] == ["docker", "inspect"] and "{{.Id}}" in argv, argv
        return subprocess.CompletedProcess(argv, 0, "sha256:localid\n", "")
    assert base_image_id("img:tag", run) == "sha256:localid"
    assert LABEL_BASE_IMAGE_ID != "org.opencontainers.image.base.digest"


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


def _git(sha: str, dirty: bool = False):
    def run(argv):
        argv = list(argv)
        if "rev-parse" in argv:
            return subprocess.CompletedProcess(argv, 0, sha + "\n", "")
        if "status" in argv:
            return subprocess.CompletedProcess(argv, 0, " M x\n" if dirty else "", "")
        if "{{json .RepoDigests}}" in argv:
            return subprocess.CompletedProcess(argv, 0, json.dumps(["b@sha256:bd"]), "")
        return subprocess.CompletedProcess(argv, 1, "", "")
    return run


def test_a_dirty_build_is_not_reproducible():
    """A `<sha>-dirty` build cannot be rebuilt from that sha.

    The uncommitted changes are recorded nowhere, so claiming reproducibility
    would be a lie with a plausible-looking sha attached.
    """
    from blastbox.host.stamp import Stamp

    assert not Stamp(blastbox="0.1.27",
        revision="abc-dirty", base_name="b:t", base_digest="sha256:bd").reproducible
    assert Stamp(blastbox="0.1.27",
        revision="abc", base_name="b:t", base_digest="sha256:bd").reproducible


def test_base_labels_are_emitted_even_without_a_base():
    """Docker inherits LABELs; an unset base label carries the PARENT's base.

    Without an explicit empty override the child silently claims its
    grandparent as its own base.
    """
    from blastbox.host.stamp import LABEL_BASE_DIGEST as BD
    from blastbox.host.stamp import LABEL_BASE_NAME as BN

    joined = " ".join(build_args(blastbox_version="0.1.27", repo=".", runner=_git("s")))
    assert f"{BN}=" in joined
    assert f"{BD}=" in joined


def test_the_build_is_pinned_to_the_digest_being_stamped():
    """Resolving a digest then building the mutable tag can stamp image A and
    build image B -- especially with --pull. Pin the build to what is recorded."""
    args = build_args(
        blastbox_version="0.1.27", repo=".", base="base:tag", runner=_git("s"))
    joined = " ".join(args)
    assert "--build-arg" in joined
    assert "BASE_IMAGE=base@sha256:bd" in joined


def test_the_pinned_build_arg_name_is_configurable():
    """Consumer Dockerfiles disagree: BASE_IMAGE here, BASE in the gvisor one."""
    args = build_args(
        blastbox_version="0.1.27", repo=".", base="b:t",
        base_arg="BASE", runner=_git("s"))
    assert "BASE=b@sha256:bd" in " ".join(args)


def test_an_unresolvable_base_raises_instead_of_stamping_unknown():
    """`base.digest=unknown` looks recorded and cannot be rebuilt."""
    import pytest as _pytest

    from blastbox.host.stamp import StampError

    def run(argv):
        return subprocess.CompletedProcess(list(argv), 1, "", "No such image")
    with _pytest.raises(StampError):
        base_digest("missing:tag", run)


def test_ambiguous_repo_digests_raise_rather_than_guess():
    """One image can carry digests from several registries."""
    import pytest as _pytest

    from blastbox.host.stamp import StampError

    def run(argv):
        argv = list(argv)
        if "{{json .RepoDigests}}" in argv:
            return subprocess.CompletedProcess(
                argv, 0, json.dumps(["other/x@sha256:a", "third/y@sha256:b"]), "")
        return subprocess.CompletedProcess(argv, 1, "", "")
    with _pytest.raises(StampError):
        base_digest("wanted/z:tag", run)


def test_the_digest_for_the_requested_repository_is_chosen():
    def run(argv):
        argv = list(argv)
        if "{{json .RepoDigests}}" in argv:
            return subprocess.CompletedProcess(
                argv, 0, json.dumps(["other/x@sha256:aaa", "wanted/z@sha256:bbb"]), "")
        return subprocess.CompletedProcess(argv, 1, "", "")
    assert base_digest("wanted/z:tag", run) == "sha256:bbb"


def test_an_uninspectable_image_raises_rather_than_reading_as_unstamped():
    """A mistyped name or stopped daemon must not look like "no stamp"."""
    import pytest as _pytest

    from blastbox.host.stamp import StampError

    def run(argv):
        return subprocess.CompletedProcess(list(argv), 1, "", "No such object")
    with _pytest.raises(StampError):
        read("typo:tag", run)


def test_a_value_needing_quotes_is_refused_not_quoted():
    """Command substitution word-splits WITHOUT removing quotes.

    A quoted value arrives with literal quote characters attached, so emitting
    one would silently corrupt the build. Refusing is the honest answer.
    """
    import pytest as _pytest

    from blastbox.host.stamp import StampError

    with _pytest.raises(StampError):
        build_args(blastbox_version="0.1.27 rc1", repo=".", runner=_git("s"))


def test_a_registry_port_is_not_mistaken_for_a_tag():
    """`host:5000/img` — the colon is a port. A naive rsplit mangles the repo."""
    from blastbox.host.stamp import repo_of

    assert repo_of("host:5000/img:tag") == "host:5000/img"
    assert repo_of("host:5000/img") == "host:5000/img"
    assert repo_of("img:tag") == "img"
    assert repo_of("img@sha256:abc") == "img"
    assert repo_of("ns/img:tag") == "ns/img"


def test_a_missing_git_binary_falls_back_to_the_revision_file(tmp_path):
    """A deployed rsynced tree often has no git at all -- exactly where the
    recorded revision matters most. subprocess raises FileNotFoundError there,
    which is not a non-zero returncode."""
    from blastbox.host.stamp import REVISION_FILE

    (tmp_path / REVISION_FILE).write_text("recorded-sha\n", encoding="utf-8")

    def run(argv):
        raise FileNotFoundError("git")
    assert git_revision(tmp_path, run) == "recorded-sha"


def test_a_base_digest_without_a_name_is_not_reproducible():
    """A bare sha256 does not say which repository to pull it from."""
    from blastbox.host.stamp import Stamp

    assert not Stamp(blastbox="0.1.27", revision="abc", base_digest="sha256:bd").reproducible
    assert Stamp(blastbox="0.1.27", revision="abc",
                 base_digest="sha256:bd", base_name="b:t").reproducible


def test_a_local_only_base_is_reproducible_via_its_image_id():
    from blastbox.host.stamp import Stamp

    assert Stamp(blastbox="0.1.27",
        revision="abc", base_name="b:t", base_image_id="sha256:localid",
    ).reproducible


def test_a_local_only_base_is_stamped_and_pinned_by_image_id():
    """Every image on these hosts is local-only, so this is the common path.

    The ID goes in its own label (not the OCI digest key) and the build is
    pinned to it.
    """
    from blastbox.host.stamp import LABEL_BASE_DIGEST, LABEL_BASE_IMAGE_ID

    def run(argv):
        argv = list(argv)
        if "rev-parse" in argv:
            return subprocess.CompletedProcess(argv, 0, "sha1\n", "")
        if "status" in argv:
            return subprocess.CompletedProcess(argv, 0, "", "")
        if "{{json .RepoDigests}}" in argv:
            return subprocess.CompletedProcess(argv, 0, "[]", "")
        if "{{.Id}}" in argv:
            return subprocess.CompletedProcess(argv, 0, "sha256:localid\n", "")
        return subprocess.CompletedProcess(argv, 1, "", "")

    joined = " ".join(build_args(
        blastbox_version="0.1.27", repo=".", base="redtusk-worker:bb0127", runner=run))
    assert f"{LABEL_BASE_IMAGE_ID}=sha256:localid" in joined
    assert f"{LABEL_BASE_DIGEST}=" in joined            # emitted, but empty
    assert f"{LABEL_BASE_DIGEST}=sha256:localid" not in joined   # never as a digest
    assert "BASE_IMAGE=sha256:localid" in joined        # build pinned to the ID


def test_an_unrunnable_git_status_is_not_reported_clean(tmp_path):
    """rev-parse succeeded, status failed: we cannot claim the tree is clean."""
    def run(argv):
        argv = list(argv)
        if "rev-parse" in argv:
            return subprocess.CompletedProcess(argv, 0, "abc\n", "")
        return subprocess.CompletedProcess(argv, 128, "", "fatal: unreadable index")
    assert git_revision(tmp_path, run) == "abc-dirty"


def test_null_repodigests_do_not_crash():
    """Docker reports a nil RepoDigests field as JSON `null`, not `[]`."""
    def run(argv):
        argv = list(argv)
        if "{{json .RepoDigests}}" in argv:
            return subprocess.CompletedProcess(argv, 0, "null", "")
        return subprocess.CompletedProcess(argv, 1, "", "")
    assert base_digest("local:only", run) == ""


def test_an_unknown_revision_is_refused_before_emitting_flags(tmp_path):
    """`revision=unknown` looks recorded and cannot be rebuilt."""
    import pytest as _pytest

    from blastbox.host.stamp import StampError

    def run(argv):
        return subprocess.CompletedProcess(list(argv), 128, "", "not a git repository")
    with _pytest.raises(StampError):
        build_args(blastbox_version="0.1.27", repo=tmp_path, runner=run)


def test_a_missing_blastbox_version_is_not_reproducible():
    from blastbox.host.stamp import Stamp

    assert not Stamp(
        revision="abc", base_name="b:t", base_digest="sha256:bd").reproducible
