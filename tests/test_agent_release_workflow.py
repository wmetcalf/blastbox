"""Static checks of the agent release workflow and the PyPI publish guard."""
from __future__ import annotations

import re
from pathlib import Path

import yaml

WF = Path(__file__).resolve().parents[1] / ".github" / "workflows"
RELEASE = WF / "agent-release.yml"
PUBLISH = WF / "publish.yml"


def load(p):
    return yaml.safe_load(p.read_text())


def triggers(doc):
    return doc.get("on", doc.get(True))  # PyYAML parses bare `on` as True


def uses_of(doc):
    for job in doc["jobs"].values():
        for step in job["steps"]:
            if "uses" in step:
                yield step["uses"]


def test_publish_skips_agent_releases():
    doc = load(PUBLISH)
    cond = doc["jobs"]["pypi"].get("if", "")
    assert "agent-v" in cond and "startsWith" in cond
    assert "github.event.release.tag_name" in cond
    assert "!" in cond  # negated: skip when the tag starts with agent-v
    assert "agent-v" in PUBLISH.read_text().split("jobs:")[1].split("steps:")[0]  # commented


def test_release_triggers_only_on_agent_tags():
    t = triggers(load(RELEASE))
    assert set(t) == {"push"}
    assert t["push"] == {"tags": ["agent-v*"]}


def test_release_permissions_minimal():
    doc = load(RELEASE)
    assert doc["permissions"] == {"contents": "read"}
    assert doc["jobs"]["build"].get("permissions", {"contents": "read"}) == {"contents": "read"}
    assert doc["jobs"]["release"]["permissions"] == {"contents": "write", "id-token": "write"}


def test_cosign_pinned_and_main_ancestry_checked():
    text = RELEASE.read_text()
    assert re.search(r'cosign-release: "v[23]\.\d+\.\d+"', text)
    assert "merge-base --is-ancestor" in text and "fetch-depth: 0" in text


def test_actions_pinned_by_sha():
    uses = list(uses_of(load(RELEASE)))
    assert uses
    for u in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", u), u
    # trailing version comment beside each
    for line in RELEASE.read_text().splitlines():
        if "uses:" in line:
            assert re.search(r"# v\d+\.\d+\.\d+$", line), line


def test_go_pinned_exactly():
    doc = load(RELEASE)
    assert re.fullmatch(r"1\.22\.\d+", doc["env"]["GO_VERSION"])


def test_build_flags_and_double_build_compared():
    text = RELEASE.read_text()
    assert 'CGO_ENABLED: "0"' in text
    assert "-trimpath" in text
    assert "-buildid=" in text and "-X main.version=" in text
    assert "cmp " in text and "src-a" in text and "src-b" in text
    assert "go test ./..." in text
    assert "cosign sign-blob --yes --bundle SHA256SUMS.sigstore.json SHA256SUMS" in text
    assert "GH_TOKEN: ${{ github.token }}" in text
    assert "gh release create" in text
    m = load(RELEASE)["jobs"]["build"]["strategy"]["matrix"]
    assert sorted(m["goos"]) == ["darwin", "linux"] and sorted(m["goarch"]) == ["amd64", "arm64"]


def test_cosign_installer_major_supports_cosign_release():
    # cosign-installer v3.x cannot install Cosign v3.x; v4 is required.
    text = RELEASE.read_text()
    m = re.search(r"sigstore/cosign-installer@[0-9a-f]{40} # v(\d+)\.", text)
    c = re.search(r'cosign-release: "v(\d+)\.', text)
    assert m and c
    if int(c.group(1)) >= 3:
        assert int(m.group(1)) >= 4, "cosign-installer v3 cannot install cosign v3"


def test_double_build_uses_separate_go_caches():
    # A shared GOCACHE makes the second build relink cached objects, so cmp proves nothing.
    steps = load(RELEASE)["jobs"]["build"]["steps"]
    step = next(s for s in steps if s.get("name") == "Build twice and compare")
    assert 'GOCACHE="$RUNNER_TEMP/gocache-$d"' in step["run"]


def test_release_verifies_its_own_signature_with_installer_identity():
    text = RELEASE.read_text()
    assert "cosign verify-blob" in text
    assert ("https://github.com/${GITHUB_REPOSITORY}/.github/workflows/agent-release.yml"
            "@${GITHUB_REF}") in text
    assert "--certificate-oidc-issuer https://token.actions.githubusercontent.com" in text


def test_sidecar_assets_are_covered_by_signed_sums():
    steps = load(RELEASE)["jobs"]["release"]["steps"]
    run = next(s for s in steps if s.get("name") == "Checksums, SBOM, conformance digest")["run"]
    # the SHA256SUMS write must come after the sidecars exist and must list them
    sums_cmd = run[run.rindex("sha256sum blastbox-agent"):].split("> SHA256SUMS")[0]
    assert "sbom.txt" in sums_cmd and "conformance-digest.txt" in sums_cmd
    assert run.index("go version -m") < run.rindex("sha256sum blastbox-agent")


def test_releasing_doc_matches_workflow_and_states_trust_anchor():
    doc = (WF.parents[1] / "agent" / "RELEASING.md").read_text()
    assert "<commit on main>" in doc and "master" not in doc
    # the in-workflow main-ancestry check is self-attesting; the doc must say what actually binds it
    assert "ruleset" in doc and "not a trust anchor" in doc
