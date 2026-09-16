"""Magika engine — the claims that matter are about CONFIDENCE, not about labels."""

from __future__ import annotations

from pathlib import Path

import pytest

from blastbox.engines.magika import MagikaEngine, MagikaUnavailable, identify
from blastbox.limits import Limits


def _run(tmp_path: Path, data: bytes, **kw):
    f = tmp_path / "input.bin"
    f.write_bytes(data)
    return MagikaEngine(**kw).detonate(f, tmp_path, Limits())


def _fake(**over):
    base = {"label": "elf", "mime_type": "application/x-executable-elf", "group": "executable",
            "description": "ELF executable", "is_text": False, "extensions": [],
            "score": 0.99, "model_label": "elf", "overwrite_reason": "none",
            "model": "test_v1"}
    base.update(over)
    return lambda _data: base


def test_the_score_is_the_confidence_not_one(tmp_path):
    """A PREDICTION REPORTED AS A FACT is the whole failure mode of an ML classifier in
    an evidence pipeline. Anything ranking or thresholding on `confidence` has to see the
    model's actual certainty."""
    r = _run(tmp_path, b"x", identify_fn=_fake(score=0.42))
    assert r.detected.confidence == 0.42, r.detected


def test_a_confident_overwrite_is_not_called_a_confidence_problem(tmp_path):
    """THE CASE THAT NAMED THIS WARNING WRONG. Random bytes are overwritten to `unknown`
    with the model CONFIDENT — `randombytes` at 0.9991, reason `overwrite_map`. The first
    version called every overwrite `low_confidence_overwrite`, which told a reader the
    model was unsure precisely when it was certain."""
    r = _run(tmp_path, b"x", identify_fn=_fake(
        label="unknown", model_label="randombytes", score=0.9991,
        overwrite_reason="overwrite_map"))
    codes = [w.code for w in r.warnings]
    assert codes == ["prediction_overwritten"], codes
    msg = r.warnings[0].message
    # The point is that the warning must not ASSERT the model was unsure. It may (and
    # now must) say WHICH label the score describes, which is a different statement and
    # the one that stops a reader pairing 0.9991 with "unknown".
    assert "overwrite_map" in msg, msg
    assert "low_confidence" not in msg and "unsure" not in msg.lower(), msg
    assert "randombytes" in msg and "NOT in the delivered label" in msg, msg
    # ...and the generic confidence field must not claim that number for a label the
    # model never predicted.
    assert r.detected.label == "unknown"
    assert r.detected.confidence == 0.0, (
        "0.9991 is certainty about randombytes; publishing it as confidence in "
        "'unknown' makes a threshold see a near-certain finding about something else"
    )
    assert r.payload.fields["score"] == 0.9991, "the raw score still belongs in the payload"


def test_the_model_prediction_survives_an_overwrite(tmp_path):
    """Magika replaces its own low-confidence prediction with a generic label. Sealing
    only the delivered label hides that a guess existed; sealing only the guess reports
    something the tool declined to stand behind. Both, plus the reason."""
    r = _run(tmp_path, b"x", identify_fn=_fake(
        label="unknown", model_label="psd", score=0.34, overwrite_reason="low_confidence"))
    f = r.payload.fields
    assert f["label"] == "unknown" and f["model_label"] == "psd"
    assert f["overwrite_reason"] == "low_confidence"
    assert any(w.code == "prediction_overwritten" for w in r.warnings), r.warnings


def test_a_confident_answer_raises_no_overwrite_warning(tmp_path):
    """The counterpart, so the warning means something: a warning on every result is
    the same as no warning at all."""
    r = _run(tmp_path, b"x", identify_fn=_fake())
    assert [w.code for w in r.warnings] == []


def test_a_model_that_will_not_load_is_engine_error_never_unknown(tmp_path):
    """`unknown` IS A REAL MAGIKA ANSWER, which is exactly why a failure must not
    produce it. A broken model reporting "could not identify" is indistinguishable from
    a working one reporting the same about random bytes."""
    def _boom(_data):
        raise MagikaUnavailable("no model")

    r = _run(tmp_path, b"x", identify_fn=_boom)
    assert r.status == "engine_error"
    # A DIFFERENT NODE TYPE, not the identification with holes in it. The failure shape
    # has no `label` field to misread, and a consumer discriminating on `_type` cannot
    # take it for an answer — `unknown` is a real Magika result and a failure must not
    # be able to spell one.
    assert r.payload.fields["schema"] == "content_type_unavailable", r.payload.fields
    assert "label" not in r.payload.fields, r.payload.fields
    assert r.detected.confidence == 0.0


def test_a_truncated_read_is_disclosed(tmp_path, monkeypatch):
    """An identification made from part of a file is a weaker claim than one made from
    all of it, and nothing else in the envelope would show the difference."""
    monkeypatch.setenv("BLASTBOX_MAGIKA_MAX_BYTES", "16")
    r = _run(tmp_path, b"y" * 64, identify_fn=_fake())
    assert r.payload.fields["bytes_read"] == 16 and r.payload.fields["file_size"] == 64
    assert any(w.code == "truncated_input" for w in r.warnings), r.warnings


def test_a_whole_file_read_is_not_flagged_as_truncated(tmp_path):
    r = _run(tmp_path, b"y" * 64, identify_fn=_fake())
    assert [w.code for w in r.warnings] == []


# --- against the real model -------------------------------------------------

try:
    identify(b"probe")
    _live = True
except Exception:                                       # pragma: no cover
    _live = False

live = pytest.mark.skipif(not _live, reason="magika model not installed")


@live
def test_real_magika_identifies_an_elf(tmp_path):
    r = _run(tmp_path, Path("/usr/bin/ls").read_bytes())
    assert r.status == "ok"
    assert r.payload.fields["label"] == "elf"
    assert r.detected.confidence > 0.9


@live
def test_real_magika_declines_random_bytes_and_says_what_it_guessed(tmp_path):
    """THE BEHAVIOUR THIS ENGINE EXISTS TO REPORT HONESTLY, against the real model
    rather than a stub: random bytes deliver `unknown`, and the model underneath had a
    guess it was not confident enough to stand behind."""
    r = _run(tmp_path, bytes(range(256)) * 8)
    f = r.payload.fields
    assert f["label"] == "unknown", f
    assert f["overwrite_reason"] != "none", f
    assert f["model_label"] != "unknown", (
        "the raw model prediction was lost — the overwrite is unreportable without it")
    assert r.detected.confidence < 0.9


# --- the contract itself ----------------------------------------------------

def test_the_payload_seals_generically_but_names_its_schema(tmp_path):
    """SEALED AS `Record`, VALIDATED AS A TYPED NODE — and the schema tag survives.

    An engine runs in a container; the dispatcher validating its envelope does not
    import it, so a `register_node_type` tag is unknown host-side and the whole result
    is REJECTED (observed live: "Input tag 'content_type_identification' ... does not
    match any of the expected tags"). So the wire form is the generic floor every host
    can parse, and `schema` records what shape the fields have."""
    from blastbox.contract import parse_node

    r = _run(tmp_path, b"x", identify_fn=_fake())
    node = parse_node(r.payload.model_dump(by_alias=True))
    assert node.type == "record"
    assert node.fields["schema"] == "content_type_identification"
    assert node.fields["label"] == "elf" and node.fields["score"] == 0.99


def test_an_out_of_range_score_is_refused_not_stored():
    """THE FIELD MOST WORTH BOUNDING. A backend returning a percentage instead of a
    fraction would otherwise seal 99.0-confidence evidence, and every consumer
    thresholding on confidence would treat it as certain."""
    import pydantic
    from blastbox.engines.magika import ContentTypeIdentification

    with pytest.raises(pydantic.ValidationError):
        ContentTypeIdentification(
            label="elf", mime_type="application/x-executable-elf", group="executable",
            description="ELF", is_text=False, extensions=[], score=99.0,
            model_label="elf", overwrite_reason="none", model="m",
            bytes_read=1, file_size=1)


def test_a_renamed_field_is_a_parse_error_not_a_silent_none():
    """THE WHOLE REASON THIS IS NOT A `Record`. In a field bag, renaming `model_label`
    breaks every reader silently — they get `None` and carry on. `extra="forbid"` on the
    node turns the same drift into a loud failure at the boundary."""
    import pydantic
    from blastbox.engines.magika import ContentTypeIdentification

    ok = dict(label="elf", mime_type="application/x-executable-elf", group="executable",
              description="ELF", is_text=False, extensions=[], score=1.0,
              model_label="elf", overwrite_reason="none", model="m",
              bytes_read=1, file_size=1)
    ContentTypeIdentification(**ok)                       # control: the shape is valid

    drifted = {**ok, "dl_label": ok.pop("model_label")}   # the rename
    with pytest.raises(pydantic.ValidationError):
        ContentTypeIdentification(**drifted)


def test_the_engine_warms_the_model_before_ready_because_that_is_what_gets_checkpointed():
    """`serve_warm` calls `warmup()` and only then signals READY; the gVisor checkpoint
    is taken AT READY, so whatever is resident then is what every restore inherits.
    Neither engine defined `warmup`, so `_MAGIKA` was None in the checkpoint and each
    restore paid the full model load on its single job — the warm tier delivering cold
    latency, while two Dockerfiles asserted the model was checkpointed loaded."""
    from blastbox.engines import magika as mod
    from blastbox.engines.magika import MagikaEngine

    assert hasattr(MagikaEngine, "warmup")
    loaded = []
    saved = mod._MAGIKA
    mod._MAGIKA = None
    try:
        mod._MAGIKA = None
        orig = mod._magika
        mod._magika = lambda: loaded.append(1)  # type: ignore[assignment]
        MagikaEngine().warmup()
        assert loaded, "warmup() must actually touch the model, not just exist"
    finally:
        mod._magika = orig  # type: ignore[assignment]
        mod._MAGIKA = saved


def test_a_model_that_cannot_load_does_not_kill_the_slot_at_warmup():
    """A reaped slot cannot seal an engine error with a reason in it. The outage must
    surface through detonate(), which produces a typed, sealed, reviewable result."""
    from blastbox.engines import magika as mod
    from blastbox.engines.magika import MagikaEngine, MagikaUnavailable

    orig = mod._magika
    saved = mod._MAGIKA
    try:
        def boom():
            raise MagikaUnavailable("no model here")
        mod._magika = boom  # type: ignore[assignment]
        MagikaEngine().warmup()  # must not raise
    finally:
        mod._magika = orig  # type: ignore[assignment]
        mod._MAGIKA = saved


@pytest.mark.parametrize("raw,expect_default", [
    ("abc", True),        # a typo in a deployment env file failed every job with a traceback
    ("", True),
    ("0", True),          # reads nothing, so Magika identifies the EMPTY STRING confidently
    ("-1", True),
    ("4096", False),
])
def test_the_read_limit_env_var_is_validated(monkeypatch, raw, expect_default):
    from blastbox.engines.magika import DEFAULT_MAX_BYTES, _max_bytes

    monkeypatch.setenv("BLASTBOX_MAGIKA_MAX_BYTES", raw)
    got = _max_bytes()
    assert (got == DEFAULT_MAX_BYTES) is expect_default
    assert got > 0, "a non-positive limit identifies the empty string, not the sample"


def test_a_low_confidence_fallback_does_not_publish_the_rejected_guesss_doubt(tmp_path):
    """The other direction, and it is not harmless either. Measured against magika
    1.0.3, a short text file gives label="txt", model_label="batch", score=0.374 — the
    0.374 is the model's DOUBT ABOUT BATCH, and Magika chose txt precisely because of
    it. Publishing 0.374 as confidence in "txt" makes a threshold discard a label the
    library was more sure of than the one it rejected."""
    r = _run(tmp_path, b"hello\n" * 40, identify_fn=_fake(
        label="txt", model_label="batch", score=0.3735,
        overwrite_reason="low_confidence"))
    assert r.payload.fields["label"] == "txt"
    assert r.payload.fields["score"] == 0.3735, "the raw score stays in the typed payload"
    assert r.detected.confidence == 0.0, (
        "0.0 here means 'no confidence value', as it does everywhere else in this "
        "codebase — not 'zero confidence in txt'"
    )
    assert [w.code for w in r.warnings] == ["prediction_overwritten"]


def test_an_ordinary_identification_still_carries_the_model_score(tmp_path):
    """Withholding the number on EVERY answer would be its own dishonesty: with no
    overwrite the score does describe the delivered label, and a consumer that ranks or
    thresholds on confidence needs it."""
    r = _run(tmp_path, b"x", identify_fn=_fake(
        label="elf", model_label="elf", score=0.9987, overwrite_reason="none"))
    assert r.detected.confidence == 0.9987
    assert r.warnings == []


def test_an_unrecognised_overwrite_sentinel_is_treated_as_an_overwrite(tmp_path):
    """Fail toward saying less. If a future magika spells "no overwrite" a third way,
    reading it as an overwrite costs one withheld number and a spurious warning;
    reading a real overwrite as none is the misreport this distinction exists for."""
    from blastbox.engines.magika import _was_overwritten

    assert not _was_overwritten("none")
    assert not _was_overwritten("OverwriteReason.NONE")
    assert _was_overwritten("overwrite_map")
    assert _was_overwritten("something_new_in_2027")
