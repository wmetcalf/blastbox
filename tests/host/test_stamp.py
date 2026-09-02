"""An image must record what it was built FROM, or it cannot be rebuilt."""

from __future__ import annotations

import json
import pathlib
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
                argv, 0, json.dumps(["reg/img@sha256:2baf1f40105d9501fe319a8ec463fdf4325a2a5df445adf3f572f626253678c9"]), "")
        return subprocess.CompletedProcess(argv, 1, "", "")
    assert base_digest("reg/img:tag", run) == "sha256:2baf1f40105d9501fe319a8ec463fdf4325a2a5df445adf3f572f626253678c9"


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
        return subprocess.CompletedProcess(argv, 0, "sha256:812c058028763ae1abffeb35d1bdab5473d534a921d930408f71c455f853e4bf\n", "")
    assert base_image_id("img:tag", run) == "sha256:812c058028763ae1abffeb35d1bdab5473d534a921d930408f71c455f853e4bf"
    assert LABEL_BASE_IMAGE_ID != "org.opencontainers.image.base.digest"


def test_build_args_carry_all_four_facts():
    def run(argv):
        argv = list(argv)
        if "rev-parse" in argv:
            return subprocess.CompletedProcess(argv, 0, "5aa1abc\n", "")
        if "status" in argv:
            return subprocess.CompletedProcess(argv, 0, "", "")
        if "{{json .RepoDigests}}" in argv:
            # repo must match the image asked about: base_digest() refuses a
            # digest belonging to another repository.
            return subprocess.CompletedProcess(
                argv, 0,
                json.dumps(["base@sha256:5e657ff6158d3e2a6d23e2a523917a2305acee9423365e268695c4b7b8919f4c"]), "")
        return subprocess.CompletedProcess(argv, 1, "", "")
    args = build_args(blastbox_version="0.1.27", repo=".", base="base:tag", runner=run)
    joined = " ".join(args)
    assert f"{LABEL_BLASTBOX}=0.1.27" in joined
    assert f"{LABEL_REVISION}=5aa1abc" in joined
    assert f"{LABEL_BASE_NAME}=base:tag" in joined
    assert f"{LABEL_BASE_DIGEST}={_BD}" in joined


def test_reading_an_unstamped_image_is_not_a_silent_pass():
    """The pre-existing fleet images carry nothing; that must be visible."""
    run = _fake({("docker", "inspect"): (0, "null")})
    got = read("legacy:image", run)
    assert got.base_digest == UNKNOWN
    assert not got.reproducible


def test_an_image_without_a_base_digest_is_not_reproducible():
    """Revision alone is not enough: the base is what was lost."""
    labels = {LABEL_BLASTBOX: "0.1.27", LABEL_REVISION: "5aa1abc"}
    run = _fake({("docker", "inspect"): (0, json.dumps(labels))})
    got = read("img", run)
    assert got.revision == "5aa1abc"
    assert not got.reproducible


def test_a_fully_stamped_image_is_reproducible():
    labels = {
        LABEL_BLASTBOX: "0.1.27", LABEL_REVISION: "5aa1abc",
        LABEL_BASE_NAME: "b:t", LABEL_BASE_DIGEST: "sha256:5e657ff6158d3e2a6d23e2a523917a2305acee9423365e268695c4b7b8919f4c",
    }
    run = _fake({("docker", "inspect"): (0, json.dumps(labels))})
    assert read("img", run).reproducible


def test_a_non_git_tree_uses_the_recorded_revision_file(tmp_path):
    """Deployed trees are rsync'd copies, not checkouts.

    Measured on toolz2: stamping a real build reported revision=unknown because
    ~/redtusk-bb is not a git repo. A deploy can record where the tree came from.
    """
    from blastbox.host.stamp import REVISION_FILE

    (tmp_path / REVISION_FILE).write_text("d1e2f3a\n", encoding="utf-8")

    def run(argv):
        return subprocess.CompletedProcess(list(argv), 128, "", "not a git repository")
    assert git_revision(tmp_path, run) == "d1e2f3a"


def test_a_real_checkout_wins_over_a_stale_revision_file(tmp_path):
    """The tree's own git state is authoritative when it has one."""
    from blastbox.host.stamp import REVISION_FILE

    (tmp_path / REVISION_FILE).write_text("9999999\n", encoding="utf-8")

    def run(argv):
        argv = list(argv)
        if "rev-parse" in argv:
            return subprocess.CompletedProcess(argv, 0, "1234abc\n", "")
        return subprocess.CompletedProcess(argv, 0, "", "")
    assert git_revision(tmp_path, run) == "1234abc"


def test_no_git_and_no_file_is_unknown_not_a_guess(tmp_path):
    def run(argv):
        return subprocess.CompletedProcess(list(argv), 128, "", "not a git repository")
    assert git_revision(tmp_path, run) == UNKNOWN


def _inspect_ref(argv):
    """The image reference in a `docker inspect [--type image] <ref> ...` argv."""
    rest = argv[2:]
    if rest[:2] == ["--type", "image"]:
        rest = rest[2:]
    return rest[0]


def _git(sha: str, dirty: bool = False):
    """git + docker stand-in. The repo digest it reports MATCHES the image asked
    about, because base_digest() now refuses a digest belonging to another
    repository."""
    def run(argv):
        argv = list(argv)
        if "rev-parse" in argv:
            return subprocess.CompletedProcess(argv, 0, sha + "\n", "")
        if "status" in argv:
            return subprocess.CompletedProcess(argv, 0, " M x\n" if dirty else "", "")
        if "{{json .RepoDigests}}" in argv:
            from blastbox.host.stamp import repo_of
            # `docker inspect --type image <ref>` -- the ref is not argv[2].
            repo = repo_of(_inspect_ref(argv))
            return subprocess.CompletedProcess(
                argv, 0,
                json.dumps([f"{repo}@{_BD}"]), "")
        return subprocess.CompletedProcess(argv, 1, "", "")
    return run


_BD = "sha256:5e657ff6158d3e2a6d23e2a523917a2305acee9423365e268695c4b7b8919f4c"


def test_a_dirty_build_is_not_reproducible():
    """A `<sha>-dirty` build cannot be rebuilt from that sha.

    The uncommitted changes are recorded nowhere, so claiming reproducibility
    would be a lie with a plausible-looking sha attached.
    """
    from blastbox.host.stamp import Stamp

    assert not Stamp(blastbox="0.1.27",
        revision="abc1234-dirty", base_name="b:t", base_digest="sha256:5e657ff6158d3e2a6d23e2a523917a2305acee9423365e268695c4b7b8919f4c").reproducible
    assert Stamp(blastbox="0.1.27",
        revision="abc1234", base_name="b:t", base_digest="sha256:5e657ff6158d3e2a6d23e2a523917a2305acee9423365e268695c4b7b8919f4c").reproducible


def test_base_labels_are_emitted_even_without_a_base():
    """Docker inherits LABELs; an unset base label carries the PARENT's base.

    Without an explicit empty override the child silently claims its
    grandparent as its own base.
    """
    from blastbox.host.stamp import LABEL_BASE_DIGEST as BD
    from blastbox.host.stamp import LABEL_BASE_NAME as BN

    joined = " ".join(build_args(blastbox_version="0.1.27", repo=".", runner=_git("5aa1abc")))
    assert f"{BN}=" in joined
    assert f"{BD}=" in joined


def test_the_build_is_pinned_to_the_digest_being_stamped():
    """Resolving a digest then building the mutable tag can stamp image A and
    build image B -- especially with --pull. Pin the build to what is recorded."""
    args = build_args(
        blastbox_version="0.1.27", repo=".", base="base:tag", runner=_git("5aa1abc"))
    joined = " ".join(args)
    assert "--build-arg" in joined
    assert f"BASE_IMAGE=base@{_BD}" in joined


def test_the_pinned_build_arg_name_is_configurable():
    """Consumer Dockerfiles disagree: BASE_IMAGE here, BASE in the gvisor one."""
    args = build_args(
        blastbox_version="0.1.27", repo=".", base="b:t",
        base_arg="BASE", runner=_git("5aa1abc"))
    assert f"BASE=b@{_BD}" in " ".join(args)


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
                argv, 0, json.dumps(["other/x@sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb", "third/y@sha256:3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d"]), "")
        return subprocess.CompletedProcess(argv, 1, "", "")
    with _pytest.raises(StampError):
        base_digest("wanted/z:tag", run)


def test_the_digest_for_the_requested_repository_is_chosen():
    def run(argv):
        argv = list(argv)
        if "{{json .RepoDigests}}" in argv:
            return subprocess.CompletedProcess(
                argv, 0, json.dumps(["other/x@sha256:9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0", "wanted/z@sha256:3e744b9dc39389baf0c5a0660589b8402f3dbb49b89b3e75f2c9355852a3c677"]), "")
        return subprocess.CompletedProcess(argv, 1, "", "")
    assert base_digest("wanted/z:tag", run) == "sha256:3e744b9dc39389baf0c5a0660589b8402f3dbb49b89b3e75f2c9355852a3c677"


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
        build_args(blastbox_version="0.1.27 rc1", repo=".", runner=_git("5aa1abc"))


def test_a_registry_port_is_not_mistaken_for_a_tag():
    """`host:5000/img` — the colon is a port. A naive rsplit mangles the repo."""
    from blastbox.host.stamp import repo_of

    assert repo_of("host:5000/img:tag") == "host:5000/img"
    assert repo_of("host:5000/img") == "host:5000/img"
    assert repo_of("img:tag") == "img"
    assert repo_of("img@sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == "img"
    assert repo_of("ns/img:tag") == "ns/img"


def test_a_missing_git_binary_falls_back_to_the_revision_file(tmp_path):
    """A deployed rsynced tree often has no git at all -- exactly where the
    recorded revision matters most. subprocess raises FileNotFoundError there,
    which is not a non-zero returncode."""
    from blastbox.host.stamp import REVISION_FILE

    (tmp_path / REVISION_FILE).write_text("a1b2c3d\n", encoding="utf-8")

    def run(argv):
        raise FileNotFoundError("git")
    assert git_revision(tmp_path, run) == "a1b2c3d"


def test_a_base_digest_without_a_name_is_not_reproducible():
    """A bare sha256 does not say which repository to pull it from."""
    from blastbox.host.stamp import Stamp

    assert not Stamp(blastbox="0.1.27", revision="abc1234", base_digest="sha256:5e657ff6158d3e2a6d23e2a523917a2305acee9423365e268695c4b7b8919f4c").reproducible
    assert Stamp(blastbox="0.1.27", revision="abc1234",
                 base_digest="sha256:5e657ff6158d3e2a6d23e2a523917a2305acee9423365e268695c4b7b8919f4c", base_name="b:t").reproducible


def test_a_local_only_base_is_reproducible_via_its_image_id():
    from blastbox.host.stamp import Stamp

    assert Stamp(blastbox="0.1.27",
        revision="abc1234", base_name="b:t", base_image_id="sha256:812c058028763ae1abffeb35d1bdab5473d534a921d930408f71c455f853e4bf",
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
            return subprocess.CompletedProcess(argv, 0, "5aa1abc\n", "")
        if "status" in argv:
            return subprocess.CompletedProcess(argv, 0, "", "")
        if "{{json .RepoDigests}}" in argv:
            return subprocess.CompletedProcess(argv, 0, "[]", "")
        if "{{.Id}}" in argv:
            return subprocess.CompletedProcess(argv, 0, "sha256:812c058028763ae1abffeb35d1bdab5473d534a921d930408f71c455f853e4bf\n", "")
        return subprocess.CompletedProcess(argv, 1, "", "")

    joined = " ".join(build_args(
        blastbox_version="0.1.27", repo=".", base="redtusk-worker:bb0127", runner=run))
    assert f"{LABEL_BASE_IMAGE_ID}=sha256:812c058028763ae1abffeb35d1bdab5473d534a921d930408f71c455f853e4bf" in joined
    assert f"{LABEL_BASE_DIGEST}=" in joined            # emitted, but empty
    assert f"{LABEL_BASE_DIGEST}=sha256:812c058028763ae1abffeb35d1bdab5473d534a921d930408f71c455f853e4bf" not in joined   # never as a digest
    assert "BASE_IMAGE=sha256:812c058028763ae1abffeb35d1bdab5473d534a921d930408f71c455f853e4bf" in joined        # build pinned to the ID


def test_an_unrunnable_git_status_is_not_reported_clean(tmp_path):
    """rev-parse succeeded, status failed: we cannot claim the tree is clean."""
    def run(argv):
        argv = list(argv)
        if "rev-parse" in argv:
            return subprocess.CompletedProcess(argv, 0, "abc1234\n", "")
        return subprocess.CompletedProcess(argv, 128, "", "fatal: unreadable index")
    assert git_revision(tmp_path, run) == "abc1234-dirty"


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
        revision="abc1234", base_name="b:t", base_digest="sha256:5e657ff6158d3e2a6d23e2a523917a2305acee9423365e268695c4b7b8919f4c").reproducible


_D64 = "sha256:" + "a" * 64


def test_a_stamped_image_whose_base_is_gone_is_not_resolvable():
    """This is the original failure, exactly.

    A perfectly stamped image whose base has since been deleted cannot be
    rebuilt, and reporting OK for it would repeat the problem that started
    this work.
    """
    from blastbox.host.stamp import Stamp

    st = Stamp(blastbox="0.1.27", revision="abc1234", base_name="b:t", base_digest=_D64)
    assert st.reproducible                      # it recorded enough
    def gone(argv):
        return subprocess.CompletedProcess(list(argv), 1, "", "No such object")
    assert not st.resolvable(gone)              # but the base is gone

    def present(argv):
        return subprocess.CompletedProcess(list(argv), 0, "sha256:x\n", "")
    assert st.resolvable(present)


def test_untracked_files_count_as_dirty(tmp_path):
    """Untracked files are build inputs -- a COPY picks them up.

    `status.showUntrackedFiles=no` would hide them, so the flag is forced.
    """
    seen = []

    def run(argv):
        argv = list(argv)
        seen.append(argv)
        if "rev-parse" in argv:
            return subprocess.CompletedProcess(argv, 0, "abc1234\n", "")
        return subprocess.CompletedProcess(argv, 0, "?? new_input.py\n", "")
    assert git_revision(tmp_path, run) == "abc1234-dirty"
    assert any("--untracked-files=normal" in a for a in seen), seen


def test_a_malformed_recorded_digest_is_not_reproducible():
    """"Present" is not "valid" -- an image can carry anything in a label."""
    from blastbox.host.stamp import Stamp

    assert not Stamp(
        blastbox="0.1.27", revision="abc1234", base_name="b:t",
        base_digest="not-a-digest").reproducible
    assert not Stamp(
        blastbox="0.1.27", revision="zzz", base_name="b:t",
        base_digest=_D64).reproducible


def test_a_sole_digest_from_another_repository_is_refused():
    """A local alias can carry a digest that belongs to a different repo."""
    import pytest as _pytest

    from blastbox.host.stamp import StampError

    def run(argv):
        argv = list(argv)
        if "{{json .RepoDigests}}" in argv:
            return subprocess.CompletedProcess(
                argv, 0, json.dumps([f"someone-else/img@{_D64}"]), "")
        return subprocess.CompletedProcess(argv, 1, "", "")
    with _pytest.raises(StampError):
        base_digest("wanted/z:tag", run)


def test_a_fully_qualified_hub_reference_matches_the_short_repo_digest():
    """Verified against a real daemon: `docker inspect docker.io/minio/minio:latest`
    returns RepoDigests as `minio/minio@sha256:…`. Without normalising the implicit
    Hub registry, stamping a fully-qualified base raised instead of resolving."""
    def run(argv):
        argv = list(argv)
        if "{{json .RepoDigests}}" in argv:
            return subprocess.CompletedProcess(
                argv, 0, json.dumps([f"minio/minio@{_D64}"]), "")
        return subprocess.CompletedProcess(argv, 1, "", "")
    assert base_digest("docker.io/minio/minio:latest", run) == _D64
    assert base_digest("index.docker.io/minio/minio:latest", run) == _D64
    assert base_digest("minio/minio:latest", run) == _D64


def test_a_genuinely_different_repository_still_raises():
    """Normalising Hub prefixes must not make unrelated repos compare equal."""
    import pytest as _pytest

    from blastbox.host.stamp import StampError

    def run(argv):
        argv = list(argv)
        if "{{json .RepoDigests}}" in argv:
            return subprocess.CompletedProcess(
                argv, 0, json.dumps([f"someone/else@{_D64}"]), "")
        return subprocess.CompletedProcess(argv, 1, "", "")
    with _pytest.raises(StampError):
        base_digest("docker.io/minio/minio:latest", run)


def test_a_stamp_that_disagrees_with_the_image_is_caught():
    """The join the three modules previously lacked.

    `org.blastbox.version` is a self-report written at build time. Nothing
    verified it, and doctor reads only running containers — so a label claiming
    0.1.27 on an image containing 0.1.17 was unrepresentable, and pins, stamp
    and doctor could all exit 0 on a fleet nobody declared.
    """
    from blastbox.host.stamp import LABEL_BLASTBOX, verify_contents

    labels = {LABEL_BLASTBOX: "0.1.27"}

    def run(argv):
        argv = list(argv)
        if argv[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, json.dumps(labels), "")
        if argv[:2] == ["docker", "run"]:
            return subprocess.CompletedProcess(argv, 0, "0.1.17\n", "")
        return subprocess.CompletedProcess(argv, 1, "", "")

    agrees, detail = verify_contents("img", run)
    assert not agrees
    assert "0.1.27" in detail and "0.1.17" in detail


def test_a_stamp_matching_the_image_agrees():
    from blastbox.host.stamp import LABEL_BLASTBOX, verify_contents

    def run(argv):
        argv = list(argv)
        if argv[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(
                argv, 0, json.dumps({LABEL_BLASTBOX: "0.1.27"}), "")
        if argv[:2] == ["docker", "run"]:
            return subprocess.CompletedProcess(argv, 0, "0.1.27\n", "")
        return subprocess.CompletedProcess(argv, 1, "", "")

    agrees, detail = verify_contents("img", run)
    assert agrees and detail == "0.1.27"


def test_images_are_inspected_with_type_image():
    """docker resolves CONTAINER names before image names.

    A container sharing a tag's name (routine under compose) would answer
    instead — returning a container ID and the container's inherited labels as
    if they were the image's.
    """
    from blastbox.host.stamp import base_image_id, read

    seen: list[list[str]] = []

    def run(argv):
        argv = list(argv)
        seen.append(argv)
        if "{{json .Config.Labels}}" in argv:
            return subprocess.CompletedProcess(argv, 0, "{}", "")
        return subprocess.CompletedProcess(argv, 0, "sha256:" + "a" * 64 + "\n", "")

    base_image_id("collide", run)
    read("collide", run)
    for argv in seen:
        assert argv[:4] == ["docker", "inspect", "--type", "image"], argv


def test_a_non_commit_revision_file_is_refused_at_build_time():
    """`release-2026-09-02` looks recorded exactly as much as `unknown` does.

    The read path already validated the shape; the write path did not, so the
    build succeeded and the image read back UNSTAMPED.
    """
    import tempfile

    import pytest as _pytest

    from blastbox.host.stamp import REVISION_FILE, StampError

    d = tempfile.mkdtemp()
    (pathlib.Path(d) / REVISION_FILE).write_text("release-2026-09-02\n", encoding="utf-8")

    def run(argv):
        return subprocess.CompletedProcess(list(argv), 128, "", "not a git repository")

    with _pytest.raises(StampError):
        build_args(blastbox_version="0.1.27", repo=d, runner=run)


def test_unparseable_inspect_output_raises_rather_than_reading_as_unstamped():
    """Every other error path here raises; this one contradicted the docstring."""
    import pytest as _pytest

    from blastbox.host.stamp import StampError

    def run(argv):
        # docker emitting two objects for an ambiguous name
        return subprocess.CompletedProcess(
            list(argv), 0, '{"a":"1"}\n{"a":"1"}\n', "")

    with _pytest.raises(StampError):
        read("ambiguous", run)


def _df(tmp_path, body):
    p = tmp_path / "Dockerfile"
    p.write_text(body)
    return p


def _refused(path, arg="BASE_IMAGE"):
    """Return the refusal message, or fail if the file was accepted."""
    import pytest as _pytest

    from blastbox.host.stamp import StampError, assert_arg_selects_base

    with _pytest.raises(StampError) as e:
        assert_arg_selects_base(path, arg)
    return str(e.value)


def test_an_undeclared_arg_is_refused_and_the_real_args_are_named(tmp_path):
    """docker WARNS and ignores an undeclared --build-arg.

    The build resolves the mutable tag itself while the label claims a pinned
    digest: a stamp wrong in the one way that matters, from a typo in a name.
    """
    msg = _refused(_df(tmp_path, "ARG BASE\nFROM ${BASE}\n"))
    assert "declares no `ARG BASE_IMAGE`" in msg
    assert "BASE" in msg  # tell the caller what IS declared


def test_an_arg_the_base_never_interpolates_is_refused(tmp_path):
    """Declaration is not selection.

    `FROM alpine` + `ARG BASE_IMAGE` accepts the build-arg and ignores it, so
    the image is alpine-based while the label claims the pinned digest. This is
    the exact vector codex raised on #101 against the first version of this
    check, which looked only for the declaration.
    """
    msg = _refused(_df(tmp_path, "FROM alpine\nARG BASE_IMAGE=x\n"))
    assert "does not interpolate it" in msg
    assert "alpine" in msg


def test_an_arg_declared_only_inside_a_stage_is_refused(tmp_path):
    """Only an ARG before the first FROM can parameterize a FROM.

    Declared in-stage, the base stays a constant while the label says pinned.
    """
    msg = _refused(_df(tmp_path, "FROM ${BASE_IMAGE}\nARG BASE_IMAGE\nRUN true\n"))
    assert "BEFORE the first" in msg


def test_a_file_with_no_from_is_refused(tmp_path):
    assert "no FROM" in _refused(_df(tmp_path, "ARG BASE_IMAGE\nRUN true\n"))


def test_a_correctly_parameterized_dockerfile_is_accepted(tmp_path):
    from blastbox.host.stamp import assert_arg_selects_base

    assert_arg_selects_base(_df(tmp_path, "ARG BASE_IMAGE\nFROM ${BASE_IMAGE}\nRUN true\n"), "BASE_IMAGE")


def test_the_instruction_keyword_is_case_insensitive(tmp_path):
    """`arg`/`from` are valid Dockerfile syntax; uppercase is only convention.

    Rejecting them would refuse a file docker builds correctly.
    """
    from blastbox.host.stamp import assert_arg_selects_base

    assert_arg_selects_base(_df(tmp_path, "arg BASE_IMAGE=d\nfrom ${BASE_IMAGE}\n"), "BASE_IMAGE")


def test_the_arg_name_is_case_sensitive(tmp_path):
    """Keywords fold; NAMES do not. `ARG base_image` does not satisfy BASE_IMAGE."""
    assert "declares no" in _refused(_df(tmp_path, "ARG base_image\nfrom ${base_image}\n"))


def test_a_dollar_prefix_of_a_longer_name_does_not_count(tmp_path):
    """`$BASE_IMAGE_TAG` interpolates a DIFFERENT arg than `$BASE_IMAGE`."""
    body = "ARG BASE_IMAGE\nARG BASE_IMAGE_TAG\nFROM $BASE_IMAGE_TAG\n"
    assert "does not interpolate" in _refused(_df(tmp_path, body))


def test_a_bare_dollar_reference_is_accepted(tmp_path):
    from blastbox.host.stamp import assert_arg_selects_base

    assert_arg_selects_base(_df(tmp_path, "ARG BASE_IMAGE\nFROM $BASE_IMAGE\n"), "BASE_IMAGE")


def test_a_default_expansion_is_accepted(tmp_path):
    from blastbox.host.stamp import assert_arg_selects_base

    assert_arg_selects_base(
        _df(tmp_path, "ARG BASE_IMAGE\nFROM ${BASE_IMAGE:-alpine}\n"), "BASE_IMAGE"
    )


def test_a_platform_flag_does_not_hide_the_reference(tmp_path):
    from blastbox.host.stamp import assert_arg_selects_base

    assert_arg_selects_base(
        _df(tmp_path, "ARG BASE_IMAGE\nFROM --platform=linux/amd64 ${BASE_IMAGE}\n"),
        "BASE_IMAGE",
    )


def test_a_continued_from_line_is_read_as_one_instruction(tmp_path):
    """Split across a backslash, a naive line reader sees a FROM with no ref."""
    from blastbox.host.stamp import assert_arg_selects_base

    assert_arg_selects_base(
        _df(tmp_path, "ARG BASE_IMAGE\nFROM \\\n  ${BASE_IMAGE}\n"), "BASE_IMAGE"
    )


def test_a_multistage_final_stage_is_the_one_that_must_be_pinned(tmp_path):
    """The BUILDER may be parameterized while the shipped image is not.

    Only the last stage becomes the image, so pinning the builder pins nothing.
    """
    body = "ARG BASE_IMAGE\nFROM ${BASE_IMAGE} AS builder\nRUN true\nFROM alpine\nCOPY --from=builder /x /x\n"
    assert "does not interpolate" in _refused(_df(tmp_path, body))


def test_a_final_stage_inheriting_a_parameterized_stage_is_accepted(tmp_path):
    """`FROM builder` IS based on whatever builder was built from."""
    from blastbox.host.stamp import assert_arg_selects_base

    body = "ARG BASE_IMAGE\nFROM ${BASE_IMAGE} AS builder\nRUN true\nFROM builder\nRUN true\n"
    assert_arg_selects_base(_df(tmp_path, body), "BASE_IMAGE")


def test_stage_names_resolve_case_insensitively(tmp_path):
    """docker lowercases stage names, so `FROM Builder` is the same stage."""
    from blastbox.host.stamp import assert_arg_selects_base

    body = "ARG BASE_IMAGE\nFROM ${BASE_IMAGE} AS builder\nFROM Builder\n"
    assert_arg_selects_base(_df(tmp_path, body), "BASE_IMAGE")


def test_a_comment_that_looks_like_an_arg_does_not_count(tmp_path):
    """Prose is not a declaration -- the same trap the pin scanner exists for."""
    body = "# ARG BASE_IMAGE is what you would use\nFROM alpine\n"
    assert "declares no" in _refused(_df(tmp_path, body))


def test_a_comment_ending_in_a_backslash_does_not_swallow_the_next_line(tmp_path):
    """Docker strips comments BEFORE joining continuations.

    Treating the backslash as a continuation joins the comment onto the FROM,
    and the file then parses as having no base at all.
    """
    from blastbox.host.stamp import assert_arg_selects_base

    body = "ARG BASE_IMAGE\n# a trailing backslash in prose \\\nFROM ${BASE_IMAGE}\n"
    assert_arg_selects_base(_df(tmp_path, body), "BASE_IMAGE")


def test_an_arg_name_differing_only_in_case_is_not_the_same_arg(tmp_path):
    """docker matches build-arg names exactly; `base_image` != `BASE_IMAGE`."""
    body = "ARG base_image\nFROM ${base_image}\n"
    assert "declares no `ARG BASE_IMAGE`" in _refused(_df(tmp_path, body))
