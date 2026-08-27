"""Magika content-type identification — a PARSE-ONLY engine.

WHAT IT IS FOR. Magika predicts what a file actually is from its bytes, using a small
neural model rather than a magic-byte table. That makes it a genuine second opinion
against libmagic-style identification: the two disagree on exactly the interesting
files — a script with a misleading extension, a payload wearing a document's header, a
polyglot — and a disagreement is worth more than either answer alone.

IT PREDICTS, SO THE SCORE TRAVELS WITH THE ANSWER. Every other field here is only
meaningful next to it. `elf` at 1.000 and `bmp` at 0.61 are not the same claim, and a
consumer that reads the label and drops the score has turned a probability into a fact.
The label is never emitted without it.

THE MODEL'S ANSWER AND MAGIKA'S ANSWER ARE NOT ALWAYS THE SAME, and both are sealed.
Below a confidence floor Magika OVERWRITES its prediction with a generic one:
random bytes come back `unknown`, while the model underneath actually guessed `psd` at
0.344. Sealing only `unknown` hides that a guess existed; sealing only `psd` reports a
guess the tool itself declined to stand behind. So the envelope carries the delivered
label, the raw model label, and the reason they differ — `overwrite_reason` — and a
reader can see which of the two they are looking at.

WHY WARM. Loading the model costs ~77ms against ~13ms per scan, so a cold slot spends
most of its life starting up. This is a mild version of the ClamAV argument rather than
a dramatic one — the model is small — but the shape is the same: load once, answer many.

WHY SLOT REUSE IS SAFE, in the terms `WarmPool` sets out (`jobs_per_recycle` is an
ENGINE-THREAT DECISION, not a tuning knob): this engine never EXECUTES the sample. It
reads a bounded prefix of the bytes and runs them through a fixed-size model. There is
no interpreter, no unpacker, and no format parser for a malformed file to attack — which
is a materially smaller surface than ClamAV's, let alone a browser's.
"""

from __future__ import annotations

import os
from pathlib import Path

from typing import Literal

from pydantic import Field

from blastbox.contract import Detection, Warning, register_node_type
from blastbox.contract.nodes import _Node
from blastbox.limits import Limits
from blastbox.worker.engine import DetonationResult

#: How much of the sample the model sees. Magika reads a prefix, a suffix and a middle
#: window rather than the whole file, so a ceiling here costs nothing in accuracy for
#: ordinary inputs and stops a multi-gigabyte sample from being read into memory to
#: answer a question that never needed the middle of it.
DEFAULT_MAX_BYTES = 64 * 1024 * 1024


@register_node_type
class ContentTypeIdentification(_Node):
    """A NAMED TYPE, NOT A BAG OF FIELDS.

    The first version of this engine put everything below into `Record.fields` — whose
    own docstring calls it "a typed bag for engine data not worth a named type". That is
    the right home for incidental data and the wrong one for this: `score`,
    `model_label` and `overwrite_reason` are the fields a consumer must read to avoid
    mistaking a prediction for a fact, and in a bag their names are enforced by nothing.
    Rename `model_label` and every reader silently gets `None` instead of a parse error.

    So the payload is a registered node with a discriminator. `_Node` sets
    `extra="forbid"`, `score` is bounded to [0, 1], and `parse_node()` on the far side
    rejects a shape that has drifted rather than handing back a dict that is missing the
    part that mattered.
    """

    type: Literal["content_type_identification"] = Field(
        default="content_type_identification", alias="_type")

    #: What Magika DELIVERED — already subject to its own low-confidence overwrite.
    label: str = Field(min_length=1, max_length=64)
    mime_type: str = Field(max_length=255)
    group: str = Field(max_length=64)
    description: str = Field(max_length=255)
    is_text: bool
    extensions: list[str] = Field(default_factory=list, max_length=16)

    #: The model's certainty in the DELIVERED label. Bounded here, so a future backend
    #: returning a percentage instead of a fraction fails validation rather than
    #: quietly producing 99.0-confidence evidence.
    score: float = Field(ge=0.0, le=1.0)

    #: What the model itself predicted, and why it was not used. Together these are the
    #: only way to tell "the model said unknown" from "the model guessed and Magika
    #: declined the guess" — see the module docstring.
    model_label: str = Field(min_length=1, max_length=64)
    overwrite_reason: str = Field(max_length=64)
    model: str = Field(min_length=1, max_length=64)

    #: How much of the file the answer rests on.
    bytes_read: int = Field(ge=0)
    file_size: int = Field(ge=0)


@register_node_type
class ContentTypeUnavailable(_Node):
    """The failure payload — A DIFFERENT TYPE, not the identification with holes in it.

    Making the error path a distinct node is what stops it from being read as a weak
    identification: there is no `label` field to misread, and a consumer discriminating
    on `_type` cannot accidentally treat it as an answer. `unknown` is a real Magika
    result, so the failure shape must not be able to spell one.
    """

    type: Literal["content_type_unavailable"] = Field(
        default="content_type_unavailable", alias="_type")
    error: str = Field(max_length=1000)


class MagikaUnavailable(RuntimeError):
    """The model could not be loaded. NOT an unidentified file."""


_MAGIKA = None


def _magika():
    """The process-wide model. Held so a warm slot pays the load once.

    NOT loaded at import: an import-time failure happens before the harness can log or
    seal anything, so a broken model would surface as a dead worker rather than as an
    engine error with a reason in it.
    """
    global _MAGIKA
    if _MAGIKA is None:
        try:
            import magika as _m

            _MAGIKA = _m.Magika()
        except Exception as exc:  # pragma: no cover - depends on the install
            raise MagikaUnavailable(f"could not load the Magika model: {exc}") from exc
    return _MAGIKA


def identify(data: bytes) -> dict:
    """Magika's answer, flattened to plain fields — the model's view and the tool's."""
    res = _magika().identify_bytes(data)
    out = res.output
    pred = res.prediction
    return {
        "label": out.label,
        "mime_type": out.mime_type,
        "group": out.group,
        "description": out.description,
        "is_text": bool(out.is_text),
        "extensions": list(out.extensions[:8]),
        "score": round(float(res.score), 4),
        # THE MODEL'S OWN GUESS, which is not always what was delivered. See the module
        # docstring: `unknown` from an overwrite and `unknown` from the model are
        # different states, and only these two fields together tell them apart.
        "model_label": pred.dl.label,
        "overwrite_reason": str(pred.overwrite_reason),
        "model": _magika().get_model_name(),
    }


class MagikaEngine:
    """Identify one sample's content type."""

    name = "magika"
    formats = frozenset({"*"})

    def __init__(self, *, identify_fn=None, name: str | None = None) -> None:
        self._identify = identify_fn or identify
        if name is not None or "BLASTBOX_DETONATE_NAME" in os.environ:
            self.name = name or os.environ["BLASTBOX_DETONATE_NAME"]

    def detonate(self, input: Path, outdir: Path, limits: Limits) -> DetonationResult:
        max_bytes = int(os.environ.get("BLASTBOX_MAGIKA_MAX_BYTES", DEFAULT_MAX_BYTES))
        size = input.stat().st_size
        with input.open("rb") as fh:
            data = fh.read(max_bytes)

        warnings: list[Warning] = []
        if size > max_bytes:
            # Magika reads a prefix anyway, so a truncated read is not the accuracy
            # problem it would be for a scanner — but the reader is told, because an
            # identification made from part of a file is a weaker claim than one made
            # from all of it and nothing else in the envelope would reveal the
            # difference.
            warnings.append(Warning(
                code="truncated_input",
                message=f"identified from the first {max_bytes} of {size} bytes"))

        try:
            got = self._identify(data)
        except MagikaUnavailable as exc:
            # An engine that could not look must not seal a result that reads as
            # "looked, found nothing identifiable" — `unknown` is a real Magika answer
            # and must not be manufactured by a failure. No `label` key at all here.
            return DetonationResult(
                payload=ContentTypeUnavailable(error=str(exc)[:1000]),
                artifacts=[],
                detected=Detection(label="unidentified", mime="application/octet-stream",
                                   confidence=0.0, source=self.name),
                warnings=[Warning(code="magika_unavailable", message=str(exc)[:2000])],
                status="engine_error",
            )

        if got["overwrite_reason"] not in ("none", "OverwriteReason.NONE"):
            # NOT "low confidence" — that was this warning's first name and it was
            # wrong for the commonest case. Random bytes come back with the model
            # CONFIDENT (`randombytes` at 0.9991) and the overwrite reason
            # `overwrite_map`: a deliberate mapping to `unknown`, not a hedge. Naming
            # every overwrite a confidence problem would have told a reader the model
            # was unsure exactly when it was certain. The code states what happened; the
            # reason says why.
            warnings.append(Warning(
                code="prediction_overwritten",
                message=f"Magika delivered {got['label']!r} instead of its model's "
                        f"prediction {got['model_label']!r} (score {got['score']}) "
                        f"— reason: {got['overwrite_reason']}"))

        return DetonationResult(
            payload=ContentTypeIdentification(bytes_read=len(data), file_size=size, **got),
            artifacts=[],
            # THE SCORE IS THE CONFIDENCE. Not 1.0: this engine's answer is a
            # prediction, and a consumer that ranks or thresholds on confidence must see
            # the model's actual certainty rather than the engine's enthusiasm.
            detected=Detection(label=got["label"], mime=got["mime_type"],
                               confidence=got["score"], source=self.name),
            warnings=warnings,
            status="ok",
        )
