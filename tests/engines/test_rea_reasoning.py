"""The reasoning ledger: the model's reasoning is kept in the pass transcript, never sent back."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from blastbox.engines.rea import agent as ag
from blastbox.engines.rea import prompts
from blastbox.engines.rea.agent import TRANSCRIPT_TEXT, TranscriptWriter, _reasoning, _reasoning_fields
from blastbox.engines.rea.reasoning_policy import capture_allowed

from test_rea_agent import FakeModel, McpRig, _env, _final, make_continuation, run, tc  # noqa: F401 (_env: autouse)

KEPT_MODEL = "deepseek/deepseek-v4.1-flash"


def _resp(content="c", **kw):
    msg = {"role": "assistant", "content": content}
    if "reasoning" in kw:
        msg["reasoning"] = kw["reasoning"]
    if "reasoning_content" in kw:
        msg["reasoning_content"] = kw["reasoning_content"]
    if "details" in kw:
        msg["reasoning_details"] = kw["details"]
    return {"choices": [{"message": msg}]}


def _lines(out: Path) -> list[dict]:
    return [json.loads(x) for x in (out / "transcript.jsonl").read_text().splitlines()]


def test_reasoning_text_is_taken_from_any_spelling():
    assert _reasoning(_resp(reasoning="think")) == "think"
    assert _reasoning(_resp(reasoning_content="think")) == "think"
    assert _reasoning(_resp(details=[{"type": "reasoning.text", "text": "a"},
                                     {"type": "reasoning.summary", "summary": "b"}])) == "a\nb"


def test_encrypted_or_malformed_reasoning_is_nothing():
    assert _reasoning(_resp(details=[{"type": "reasoning.encrypted", "data": "x"}])) is None
    for bad in ([1], {"a": 1}, 7, ""):
        assert _reasoning(_resp(reasoning=bad)) is None
    assert _reasoning(_resp(details="nope")) is None
    assert _reasoning(_resp(details=[7, {"type": "reasoning.text", "text": 3}])) is None
    for junk in (None, [], {"choices": []}, {"choices": [{"message": "x"}]}):
        assert _reasoning(junk) is None


def test_reasoning_fields_are_capped_and_only_when_kept():
    long = "r" * (TRANSCRIPT_TEXT + 10)
    assert _reasoning_fields(_resp(reasoning=long), keep=False) == {}
    assert _reasoning_fields(_resp(), keep=True) == {}
    f = _reasoning_fields(_resp(reasoning=long), keep=True)
    assert len(f["reasoning"]) == TRANSCRIPT_TEXT and f["reasoning_chars"] == TRANSCRIPT_TEXT + 10


def test_only_pinned_models_may_have_reasoning_kept():
    assert capture_allowed(KEPT_MODEL)
    assert not capture_allowed("meta/muse-ember")
    assert not capture_allowed("unknown/model") and not capture_allowed("")


def test_a_pass_keeps_reasoning_on_model_turns_and_never_sends_it_back(tmp_path, monkeypatch):
    monkeypatch.setenv("REA_MODEL_ID", KEPT_MODEL)
    cont = make_continuation(tmp_path)
    model = FakeModel([tc(("binary_overview", {}, "a")), _final()])
    _res, out = run(tmp_path, cont, model, McpRig(tmp_path))
    turns = [e for e in _lines(out) if e["event"] == "model_turn"]
    assert turns[0]["reasoning"] == "thinking..." and turns[0]["reasoning_chars"] == len("thinking...")
    assert "thinking..." not in json.dumps(model.calls[-1]["messages"])
    # The answer with no tool calls is the loop's last model turn; its reasoning is kept too.
    assert turns[-1]["reasoning"] == "secret chain of thought"
    assert "secret chain" not in json.dumps([c["messages"] for c in model.calls])


def test_the_switch_off_keeps_no_reasoning(tmp_path, monkeypatch):
    monkeypatch.setenv("REA_MODEL_ID", KEPT_MODEL)
    monkeypatch.setenv("REA_RETAIN_REASONING", "off")
    cont = make_continuation(tmp_path)
    _res, out = run(tmp_path, cont, FakeModel([tc(("binary_overview", {}, "a")), _final()]), McpRig(tmp_path))
    assert not any("reasoning" in e for e in _lines(out))
    assert [e for e in _lines(out) if e["event"] == "start"][0]["retain_reasoning"] is False


def test_a_model_off_the_table_keeps_no_reasoning(tmp_path):
    cont = make_continuation(tmp_path)  # the harness's model id is not on the table
    _res, out = run(tmp_path, cont, FakeModel([tc(("binary_overview", {}, "a")), _final()]), McpRig(tmp_path))
    assert not any("reasoning" in e for e in _lines(out))


# --- the cap gives reasoning its own room -------------------------------------------------------

def test_reasoning_is_dropped_first_when_it_would_eat_the_reserve(tmp_path):
    tw = TranscriptWriter(tmp_path / "t", cap=10_000, reasoning_reserve=6_000)
    assert tw.write({"event": "model_turn", "reasoning": "x" * 3_000, "reasoning_chars": 3_000})
    assert tw.write({"event": "model_turn", "reasoning": "y" * 3_000, "reasoning_chars": 3_000})
    tw.close()
    lines = [json.loads(x) for x in (tmp_path / "t").read_text().splitlines()]
    assert "reasoning" in lines[0] and "reasoning" not in lines[1]
    assert lines[1]["reasoning_dropped"] is True and lines[1]["reasoning_chars"] == 3_000


def test_without_a_reserve_the_writer_behaves_as_before(tmp_path):
    tw = TranscriptWriter(tmp_path / "t", cap=200)
    assert tw.write({"event": "a"})
    assert not tw.write({"event": "b", "text": "z" * 500})
    tw.close()
    lines = [json.loads(x) for x in (tmp_path / "t").read_text().splitlines()]
    assert [x["event"] for x in lines] == ["a", "truncated"]


def test_start_names_the_build_the_prompts_and_the_switch(tmp_path, monkeypatch):
    monkeypatch.setenv("REA_MODEL_ID", KEPT_MODEL)
    monkeypatch.setenv("REA_COMMIT", "abc")
    monkeypatch.setenv("REA_TOOLS_SHA256", "def")
    cont = make_continuation(tmp_path)
    _res, out = run(tmp_path, cont, FakeModel([tc(("binary_overview", {}, "a")), _final()]), McpRig(tmp_path))
    start = [e for e in _lines(out) if e["event"] == "start"][0]
    assert start["rea_build"] == "abc" and start["tools_sha256"] == "def"
    assert start["prompt_sha256"] == hashlib.sha256(Path(prompts.__file__).read_bytes()).hexdigest()
    assert start["retain_reasoning"] is True


def test_a_reasoning_pass_gets_the_larger_cap():
    assert ag.MAX_TRANSCRIPT_REASONING_BYTES == 16 * 1024 * 1024 > ag.MAX_TRANSCRIPT_BYTES
