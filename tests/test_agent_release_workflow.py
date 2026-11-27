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
    assert doc["permissions"] == {"contents": "write", "id-token": "write"}
    for job in doc["jobs"].values():
        assert "permissions" not in job or job["permissions"] == doc["permissions"]


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
