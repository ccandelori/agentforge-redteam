"""Canary case selection for Judge drift detection.

A *canary* is a known-answer probe injected into a live red-team session at a
fixed cadence (see :class:`agentforge_redteam.state.CampaignBrief`'s
``is_canary`` flag and Task 37's cadence wiring in the Orchestrator). The
canary harness needs three things:

1. A pool of pre-authored :class:`GroundTruthCase` artefacts to draw from
   (Task 23 seeded these on disk under ``evals/judge_ground_truth/``).
2. A way to pick one case for a target category — uniformly at random, but
   reproducibly when the caller passes a seeded :class:`random.Random`.
3. A way to wrap the picked case in a :class:`CampaignBrief` that satisfies
   the canary invariant (``is_canary=True`` implies a non-``None``
   ``canary_expected_verdict``).

This module is the *selection layer only*. The Orchestrator is responsible for
deciding *when* a canary should fire (cadence) and the Judge is responsible
for raising ``CanaryMismatch`` when its verdict disagrees with the embedded
expected verdict. Both of those concerns live in their own files; we publish a
small typed API and stay out of their way.

Design notes worth calling out:

* **'partial' and 'inconclusive' are excluded from the default verdict
  filter.** Those verdicts are definitionally ambiguous — a canary built on a
  partial case has no crisp pass/fail signal, so a Judge that calls it 'fail'
  is not obviously drifting. Filtering them out keeps the canary metric a
  high-confidence drift detector. Callers can still pass
  ``expected_verdicts=("partial",)`` if they want to assert on those cases,
  e.g. in a Judge-accuracy gate that exercises the full distribution.
* **No global RNG.** Every selection takes an explicit
  :class:`random.Random` so the caller controls determinism. The cadence
  layer in the Orchestrator should pass a session-seeded RNG so canary picks
  are reproducible from session metadata alone.
* **Sub-attack inference is best-effort.** Ground-truth cases predate the
  ``sub_attack`` field on :class:`CampaignBrief`; the YAML schema does not
  carry that label directly. :func:`campaign_for_canary` infers from
  ``rubric_outcomes`` (the first ``True`` key wins), and falls back to the
  literal string ``"unknown"`` when there is no signal. Callers who care
  should pass ``sub_attack_override`` and treat the inference path as a
  convenience for tests.
"""

from __future__ import annotations

import random
from pathlib import Path
from typing import Final

from agentforge_redteam.ground_truth import (
    GROUND_TRUTH_ROOT,
    GroundTruthCase,
    read_case,
)
from agentforge_redteam.state import CampaignBrief

DEFAULT_CANARY_ROOT: Final[Path] = GROUND_TRUTH_ROOT

# Default verdict filter for canary selection. 'partial' and 'inconclusive'
# verdicts are ambiguous by construction and make poor drift signals; callers
# who want them must opt in explicitly.
DEFAULT_EXPECTED_VERDICTS: Final[tuple[str, ...]] = ("pass", "fail")


class NoCanaryAvailable(Exception):
    """Raised when :func:`select_canary_case` finds zero matching cases.

    Common causes: the category does not exist under ``root``, the filter
    ``expected_verdicts`` excludes every case in the category, or the ground
    truth tree is empty (e.g. a stripped test fixture).
    """


def list_canary_cases(
    category: str | None = None,
    *,
    expected_verdicts: tuple[str, ...] = DEFAULT_EXPECTED_VERDICTS,
    root: Path | str = DEFAULT_CANARY_ROOT,
) -> list[GroundTruthCase]:
    """Return every :class:`GroundTruthCase` under ``root`` matching the filter.

    Parameters
    ----------
    category:
        If provided, only return cases whose ``category`` directory matches
        this string. ``None`` (the default) walks every category dir under
        ``root``.
    expected_verdicts:
        Tuple of verdict literals to keep. Defaults to
        :data:`DEFAULT_EXPECTED_VERDICTS` (``pass`` + ``fail``) — see the
        module docstring for the rationale. Pass e.g. ``("partial",)`` to
        widen the filter.
    root:
        On-disk root of the ground-truth tree. Defaults to
        :data:`DEFAULT_CANARY_ROOT` (the production
        ``evals/judge_ground_truth`` directory).

    Returns
    -------
    list[GroundTruthCase]
        Matching cases. Order is filesystem-dependent — callers that need
        determinism should sort by ``case_id`` or seed an RNG.
    """
    root_path = Path(root)
    if not root_path.is_dir():
        return []

    allowed_verdicts = set(expected_verdicts)
    if category is not None:
        category_dirs = [root_path / category]
    else:
        category_dirs = [p for p in sorted(root_path.iterdir()) if p.is_dir()]

    cases: list[GroundTruthCase] = []
    for category_dir in category_dirs:
        if not category_dir.is_dir():
            continue
        for yaml_path in sorted(category_dir.glob("*.yaml")):
            case = read_case(yaml_path)
            if case.expected_verdict in allowed_verdicts:
                cases.append(case)
    return cases


def select_canary_case(
    category: str,
    *,
    rng: random.Random,
    expected_verdicts: tuple[str, ...] = DEFAULT_EXPECTED_VERDICTS,
    root: Path | str = DEFAULT_CANARY_ROOT,
) -> GroundTruthCase:
    """Pick one ground-truth case at random from ``category``.

    Determinism is the caller's responsibility — seed ``rng`` upstream and
    the same seed will pick the same case across runs against the same
    on-disk corpus.

    Raises
    ------
    NoCanaryAvailable
        If zero cases match the (category, expected_verdicts) filter.
    """
    candidates = list_canary_cases(
        category=category,
        expected_verdicts=expected_verdicts,
        root=root,
    )
    if not candidates:
        raise NoCanaryAvailable(
            f"No canary cases for category={category!r} with "
            f"expected_verdicts={expected_verdicts!r} under {root}"
        )
    # Sort by case_id so the choice is reproducible even when filesystem
    # iteration order differs across platforms.
    candidates.sort(key=lambda c: str(c.case_id))
    return rng.choice(candidates)


def _infer_sub_attack(case: GroundTruthCase) -> str:
    """Best-effort inference of a sub_attack label from rubric_outcomes.

    Picks the first key with ``value=True`` (sorted for stability across
    Python dict-iteration orderings on older builds). Falls back to the
    sentinel ``"unknown"`` so the resulting :class:`CampaignBrief` still
    validates — the caller should treat that as a signal to provide an
    explicit override.
    """
    triggered = sorted(name for name, fired in case.rubric_outcomes.items() if fired)
    if triggered:
        return triggered[0]
    return "unknown"


def campaign_for_canary(
    case: GroundTruthCase,
    *,
    budget_cents: int,
    sub_attack_override: str | None = None,
) -> CampaignBrief:
    """Build a canary :class:`CampaignBrief` from a ground-truth case.

    The returned brief has ``is_canary=True`` and
    ``canary_expected_verdict=case.expected_verdict``, satisfying the
    invariant declared in :class:`CampaignBrief`.

    Parameters
    ----------
    case:
        The chosen :class:`GroundTruthCase` (typically from
        :func:`select_canary_case`).
    budget_cents:
        Cost cap to embed in the campaign. The orchestrator owns the
        per-canary budget policy; this function does not second-guess it.
    sub_attack_override:
        Explicit sub_attack label. Strongly preferred — the inference
        fallback exists for tests and for cases where rubric_outcomes happen
        to carry the right signal, but production callers should know which
        sub-attack they are exercising.
    """
    sub_attack = sub_attack_override if sub_attack_override is not None else _infer_sub_attack(case)
    return CampaignBrief(
        category=case.category,
        sub_attack=sub_attack,
        budget_cents=budget_cents,
        is_canary=True,
        canary_expected_verdict=case.expected_verdict,
    )
