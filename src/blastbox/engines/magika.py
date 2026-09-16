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

import logging
import os
from pathlib import Path

from typing import Literal

from pydantic import Field

from blastbox.contract import Detection, Record, Warning, register_node_type
from blastbox.contract.nodes import _Node
from blastbox.limits import Limits
from blastbox.worker.engine import DetonationResult

#: How much of the sample the model sees. Magika reads a prefix, a suffix and a middle
#: window rather than the whole file, so a ceiling here costs nothing in accuracy for
#: ordinary inputs and stops a multi-gigabyte sample from being read into memory to
#: answer a question that never needed the middle of it.
DEFAULT_MAX_BYTES = 64 * 1024 * 1024

_log = logging.getLogger("blastbox.engines.magika")


def _max_bytes() -> int:
    """How much of the sample to read, from the environment, VALIDATED.

    `int(os.environ[...])` raised ValueError out of `detonate` on any non-numeric value
    — a typo in a deployment env file failed every job on that node with a traceback
    rather than a reason. A zero or negative value was worse: it reads nothing and
    Magika then identifies the empty string, producing a confident answer about a file
    nobody looked at. Both fall back to the default, loudly.
    """
    raw = os.environ.get("BLASTBOX_MAGIKA_MAX_BYTES")
    if raw is None:
        return DEFAULT_MAX_BYTES
    try:
        value = int(raw)
    except ValueError:
        _log.warning("BLASTBOX_MAGIKA_MAX_BYTES=%r is not a number; using %d",
                     raw, DEFAULT_MAX_BYTES)
        return DEFAULT_MAX_BYTES
    if value <= 0:
        _log.warning("BLASTBOX_MAGIKA_MAX_BYTES=%d would read nothing at all, which "
                     "identifies the empty string rather than the sample; using %d",
                     value, DEFAULT_MAX_BYTES)
        return DEFAULT_MAX_BYTES
    return value


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



def _sealed(node) -> Record:
    """Validate strictly, then seal GENERICALLY — and this reverses a choice made
    earlier today for a reason worth recording.

    The typed node (`ContentTypeIdentification`) is the right contract: it bounds the fields, forbids
    extras, and turns a rename into a parse error. But `register_node_type` registers
    into the REGISTRY OF THE PROCESS THAT IMPORTS THE ENGINE — and an engine runs in a
    container while the dispatcher validating its envelope does not import it. Observed
    live: the host rejected a perfectly good result with
    `Input tag 'content_type_identification' ... does not match any of the expected tags`.

    So the model still does the checking (constructed and validated above), and what
    goes on the wire is `Record` — the generic floor any host can validate. The field
    names and bounds are still enforced; they are enforced where they can be.
    """
    return Record(fields={"schema": node.type, **node.model_dump(exclude={"type"})})


class MagikaEngine:
    """Identify one sample's content type."""

    name = "magika"
    formats = frozenset({"*"})

    def __init__(self, *, identify_fn=None, name: str | None = None) -> None:
        self._identify = identify_fn or identify
        if name is not None or "BLASTBOX_DETONATE_NAME" in os.environ:
            self.name = name or os.environ["BLASTBOX_DETONATE_NAME"]

    def warmup(self) -> None:
        """Load the model BEFORE the slot signals READY.

        `serve_warm` calls this and only then signals READY, and the gVisor checkpoint is
        taken AT READY — so whatever is resident here is what every restore inherits.
        Without it `_MAGIKA` was still None in the checkpoint, and the warm tier's one
        job per restore paid the full `Magika()` + onnxruntime init that the whole warm
        rationale is built on avoiding. Both Dockerfiles claimed the model was
        "CHECKPOINTED with the model loaded"; nothing implemented it, and
        Dockerfile.magika contradicted its own first line four lines later.

        Deliberately not fatal on its own: a failure here would reap the slot before it
        could seal an engine error with a reason in it. `_magika()` raises
        MagikaUnavailable on the first detonation instead, which is the path the outage
        tests cover. Warming is an optimisation; refusing to answer is the contract.
        """
        try:
            _magika()
        except MagikaUnavailable:
            _log.warning("magika.warmup: model not loadable; the first job will say why")

    def detonate(self, input: Path, outdir: Path, limits: Limits) -> DetonationResult:
        max_bytes = _max_bytes()
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
                payload=_sealed(ContentTypeUnavailable(error=str(exc)[:1000])),
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
            payload=_sealed(ContentTypeIdentification(bytes_read=len(data), file_size=size, **got)),
            artifacts=[],
            # THE SCORE IS THE CONFIDENCE. Not 1.0: this engine's answer is a
            # prediction, and a consumer that ranks or thresholds on confidence must see
            # the model's actual certainty rather than the engine's enthusiasm.
            detected=Detection(label=got["label"], mime=got["mime_type"],
                               confidence=got["score"], source=self.name),
            warnings=warnings,
            status="ok",
        )
