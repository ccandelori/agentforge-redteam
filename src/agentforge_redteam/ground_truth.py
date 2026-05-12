"""Hand-authored Judge ground-truth cases.

A ground-truth case is one operator-authored attack / target-response pair
together with the verdict and per-rubric-check outcomes that the Judge agent
is *expected* to produce. They serve two purposes:

* **Judge accuracy gates.** A CI job replays cases through the Judge and
  fails the build when verdict agreement falls below threshold.
* **Canary injection** (Task 41). A subset of cases is periodically replayed
  in production runs as known-answer probes. Any deviation from the
  ``expected_verdict`` is a signal the Judge has drifted.

This module is the pure data layer. The interactive CLI flow lives in
:mod:`agentforge_redteam.cli`; downstream callers (the canary harness, the
accuracy-gate CI job) consume :class:`GroundTruthCase` directly.

Design choices worth calling out:

* **One YAML file per case.** Diff-friendly, line-of-blame friendly, and a
  bad case can be removed by deleting one file without rewriting an index.
  The on-disk layout is ``<root>/<category>/<case_id>.yaml``.
* **uuid4 case_ids.** Collision-free without coordination. ``write_case``
  refuses to overwrite an existing file as a paranoia guard against ID reuse
  if a caller ever supplies their own UUID.
* **Frozen Pydantic models.** A ground-truth case is an *artifact*; once
  authored it should not be mutated in memory. Edits go through delete +
  re-author or a deliberate ``model_copy``.
* **Open ``rubric_outcomes`` keys.** The data model intentionally does not
  validate outcome keys against the live rubric. Rubric checks may be added
  or renamed over time and we want old cases to keep deserializing. The CLI
  surfaces the live rubric's check names so authors land on the right keys
  *at authoring time*; that's the right layer for that concern.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Literal
from uuid import UUID, uuid4

import yaml
from pydantic import BaseModel, Field

GROUND_TRUTH_ROOT: Final[Path] = Path("evals/judge_ground_truth")

Verdict = Literal["pass", "fail", "partial", "inconclusive"]


class GroundTruthCase(BaseModel):
    """One hand-authored Judge ground-truth case.

    The YAML written to disk is this model dumped — keep the field shape
    stable; downstream readers (Task 41 canary harness, the Judge accuracy
    gate) depend on it.

    ``target_response`` may be empty: when the target refused silently or
    returned 204, the empty body is itself the response under test.
    """

    model_config = {"frozen": True, "extra": "forbid"}

    case_id: UUID = Field(default_factory=uuid4)
    category: str = Field(min_length=1)
    attack_input: str = Field(min_length=1)
    target_response: str
    expected_verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    rubric_outcomes: dict[str, bool] = Field(default_factory=dict)
    notes: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


def case_path(case: GroundTruthCase, root: Path | str = GROUND_TRUTH_ROOT) -> Path:
    """Return the YAML path: ``<root>/<category>/<case_id>.yaml``.

    Pure path computation — does not touch the filesystem. Useful in tests
    that want to assert *where* a case would be written without writing it.
    """
    return Path(root) / case.category / f"{case.case_id}.yaml"


def _case_to_yaml_dict(case: GroundTruthCase) -> dict[str, Any]:
    """Serialize a case to a dict suitable for ``yaml.safe_dump``.

    Pydantic v2 ``model_dump(mode='json')`` already coerces ``UUID`` to
    ``str`` and ``datetime`` to ISO-8601, but datetimes carrying a
    ``+00:00`` offset look noisier on disk than the canonical ``Z`` suffix.
    We normalise to ``Z`` for diff stability.
    """
    data = case.model_dump(mode="json")
    created_at = data.get("created_at")
    if isinstance(created_at, str) and created_at.endswith("+00:00"):
        data["created_at"] = created_at.removesuffix("+00:00") + "Z"
    return data


def write_case(case: GroundTruthCase, root: Path | str = GROUND_TRUTH_ROOT) -> Path:
    """Serialize ``case`` to YAML and write it under ``root``.

    Creates parent directories as needed. Returns the absolute-or-relative
    :class:`Path` actually written (whatever was passed in for ``root``).

    Refuses to overwrite an existing file (raises :class:`FileExistsError`).
    ``case_id`` defaults to ``uuid4`` so collisions in practice mean a caller
    deliberately re-used an ID — which we want to flag rather than silently
    clobber an authored case.
    """
    path = case_path(case, root=root)
    if path.exists():
        raise FileExistsError(f"Ground-truth case already exists at {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = _case_to_yaml_dict(case)
    # ``sort_keys=False`` preserves Pydantic field declaration order, which
    # gives stable line-by-line diffs across re-serialisations.
    yaml_text = yaml.safe_dump(
        payload,
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=True,
    )
    path.write_text(yaml_text, encoding="utf-8")
    return path


def read_case(path: Path | str) -> GroundTruthCase:
    """Read a YAML ground-truth case from disk and validate it.

    Raises :class:`pydantic.ValidationError` on malformed content (missing
    fields, bad verdict literal, confidence out of range, etc.) and
    :class:`FileNotFoundError` if the file does not exist. The inverse of
    :func:`write_case` modulo the field defaults that the model itself
    re-derives.
    """
    raw = Path(path).read_text(encoding="utf-8")
    data = yaml.safe_load(raw)
    if not isinstance(data, dict):
        # Force a clean ValidationError rather than a TypeError on a non-dict
        # payload (e.g. a YAML list or scalar at the document root).
        data = {"__root__": data}
    return GroundTruthCase.model_validate(data)
