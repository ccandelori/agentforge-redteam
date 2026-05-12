"""Deterministic stub node functions for the LangGraph wiring.

These exist purely to validate graph *structure* — node presence, edge routing,
and termination — in tests. Real agent implementations land in tasks 25-28
(Orchestrator, Red Team, Judge, Documentation respectively).

Each stub is a pure function: ``(PlatformState) -> PlatformState``. Stubs never
mutate the input; they return a new state via :meth:`PlatformState.model_copy`.
The only non-determinism is :func:`uuid.uuid4` for new record ids, which the
graph routing logic never compares.
"""

from __future__ import annotations

from uuid import uuid4

from agentforge_redteam.state import (
    AttackRecord,
    CampaignBrief,
    ConfirmedFinding,
    PlatformState,
    VerdictRecord,
)

_HALT_AFTER_CAMPAIGNS = 2
"""Stop after this many completed campaigns; the deterministic exit for tests."""

_STUB_TARGET_SHA = "stub-target-sha"
_STUB_RUBRIC_SHA = "stub-rubric-sha"
_STUB_MODEL_VERSION = "stub-model-v0"


def orchestrator_stub(state: PlatformState) -> PlatformState:
    """Decide the next campaign.

    If ``campaigns_run >= 2`` the orchestrator halts by setting ``halt_reason``;
    otherwise it issues a fresh :class:`CampaignBrief` into ``current_campaign``.
    The campaign-count halt is the test hook — it gives a deterministic exit so
    the graph terminates without running a real Orchestrator.
    """
    if state.campaigns_run >= _HALT_AFTER_CAMPAIGNS:
        return state.model_copy(
            update={"halt_reason": f"stub_halt_after_{_HALT_AFTER_CAMPAIGNS}_campaigns"}
        )

    next_campaign = CampaignBrief(
        category="stub-category",
        sub_attack="stub-sub-attack",
        budget_cents=0,
        is_canary=False,
    )
    return state.model_copy(update={"current_campaign": next_campaign})


def red_team_stub(state: PlatformState) -> PlatformState:
    """Generate one canned :class:`AttackRecord` from ``current_campaign``.

    Requires ``state.current_campaign`` to be set; raises :class:`RuntimeError`
    otherwise so a wiring bug is loud rather than silent.
    """
    if state.current_campaign is None:
        raise RuntimeError("red_team_stub invoked without current_campaign")

    attack = AttackRecord(
        campaign_id=uuid4(),
        payload="stub-payload",
        target_response="stub-response",
        target_sha=_STUB_TARGET_SHA,
        status_code=200,
        latency_ms=0,
    )
    return state.model_copy(update={"attack_records": [*state.attack_records, attack]})


def judge_stub(state: PlatformState) -> PlatformState:
    """Emit a ``pass`` :class:`VerdictRecord` for the most recent attack.

    Requires at least one attack since the last verdict (i.e. more attacks than
    verdicts) — raises :class:`RuntimeError` if violated, again to surface
    wiring bugs loudly.
    """
    if len(state.attack_records) <= len(state.verdict_records):
        raise RuntimeError("judge_stub invoked without a new attack to judge")

    last_attack = state.attack_records[-1]
    verdict = VerdictRecord(
        attack_id=last_attack.attack_id,
        verdict="pass",
        confidence=0.5,
        evidence_refs=[],
        rubric_sha=_STUB_RUBRIC_SHA,
        model_version=_STUB_MODEL_VERSION,
    )
    return state.model_copy(update={"verdict_records": [*state.verdict_records, verdict]})


def documentation_stub(state: PlatformState) -> PlatformState:
    """Append a P3 :class:`ConfirmedFinding` if the last verdict is pass/partial.

    Always increments ``campaigns_run`` by one — one increment per full loop —
    so the orchestrator's halt rule trips deterministically.
    """
    new_findings = state.confirmed_findings
    last_verdict = state.verdict_records[-1] if state.verdict_records else None
    if last_verdict is not None and last_verdict.verdict in ("pass", "partial"):
        finding = ConfirmedFinding(
            severity="P3",
            attack_id=last_verdict.attack_id,
            verdict_id=last_verdict.verdict_id,
        )
        new_findings = [*state.confirmed_findings, finding]

    return state.model_copy(
        update={
            "confirmed_findings": new_findings,
            "campaigns_run": state.campaigns_run + 1,
        }
    )
