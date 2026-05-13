"""Documentation Agent skeleton — convert one confirmed verdict into a finding.

The Documentation Agent is the last hop in the graph. It receives a settled
:class:`~agentforge_redteam.state.VerdictRecord`, sanitises the evidence,
deterministically assigns a :class:`~agentforge_redteam.severity.Severity`,
asks an LLM (injected via :class:`LLMClientLike`) for the prose sections of
the report, renders the markdown via the strict Jinja2 template, and routes
the finding either to GitLab (autofile) or to the human approval queue.

Design constraints (load-bearing — keep stable):

- **Severity is deterministic.** The LLM is asked to *rationalise* the
  already-assigned severity, never to assign it. See
  :func:`agentforge_redteam.severity.assign_severity` — the Doc Agent passes
  through whatever it returns.
- **All external I/O goes through :func:`call_tool`.** Both the LLM call and
  the GitLab call are wrapped, so the ``agent_steps`` table grows two rows
  per autofile finding and one row per queue-routed finding.
- **No top-level imports of Anthropic / GitLab clients.** Clients are
  injected as :class:`Protocol`-typed parameters so tests can substitute
  fakes without monkeypatching.
- **Routing is deterministic.** Severity in ``{P0, P1}`` OR
  ``verdict.confidence < AUTOFILE_CONFIDENCE_THRESHOLD`` -> human queue;
  else autofile. See :func:`_route`.
- **Dedup is exact** on ``(attack_id, verdict_id)``. We raise
  :class:`FindingAlreadyFiled` and let the caller (the graph) decide whether
  to swallow — this keeps the node referentially transparent for the same
  state input + already-filed verdict.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Final, Literal, Protocol

from sqlalchemy import text
from sqlalchemy.engine import Engine

from agentforge_redteam.prompts import load_prompt
from agentforge_redteam.report_template import FindingReportContext, render_finding
from agentforge_redteam.sanitizer import sanitize_evidence
from agentforge_redteam.severity import Severity, assign_severity
from agentforge_redteam.state import (
    AttackRecord,
    ConfirmedFinding,
    PlatformState,
    VerdictRecord,
)
from agentforge_redteam.tools.wrapper import call_tool

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_MODEL: Final[str] = "claude-haiku-4-5-20251001"
"""Doc agent uses Haiku 4.5: report generation is more structure than
reasoning, and Haiku is 3x cheaper than Sonnet ($1/$5 vs $3/$15 per
1M tokens). Per session e2590f4c the doc agent was 2.5¢/finding on
Sonnet; expect ~0.8¢/finding on Haiku."""

AUTOFILE_CONFIDENCE_THRESHOLD: Final[float] = 0.7
"""Verdicts below this confidence go to the human queue regardless of severity."""

_HUMAN_APPROVAL_SEVERITIES: Final[frozenset[str]] = frozenset({"P0", "P1"})
"""Severities that always route to the human approval queue."""

_AGENT_NAME: Final[str] = "documentation"

Routing = Literal["autofile", "human_approval"]


# ---------------------------------------------------------------------------
# Protocols and value objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LLMResponse:
    """LLM response envelope: drafted text plus the cost of producing it."""

    text: str
    cost_cents: int


class LLMClientLike(Protocol):
    """Subset of an Anthropic-shaped client. Tests inject a fake."""

    async def complete(self, *, system: str, user: str, model: str) -> LLMResponse: ...


@dataclass(frozen=True, slots=True)
class GitLabIssueRef:
    """Identifiers returned from a successful ``create_issue`` call."""

    issue_id: int
    url: str


class GitLabClientLike(Protocol):
    """Subset of the GitLab REST API. Tests inject a fake."""

    async def create_issue(self, *, title: str, body: str, labels: list[str]) -> GitLabIssueRef: ...


@dataclass(frozen=True, slots=True)
class FindingFrameworks:
    """Framework tag triple stored alongside every finding.

    The values are stamped into the rendered report's Framework Mapping
    section. Examples: ``owasp_id="LLM01:2025"``, ``mitre_id="ATLAS.T0051"``,
    ``hipaa_section="§164.308(a)(1)(ii)(A)"``.
    """

    owasp_id: str
    mitre_id: str
    hipaa_section: str


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class FindingAlreadyFiled(Exception):
    """Raised when dedup detects an existing finding for (attack_id, verdict_id).

    The Doc Agent never silently no-ops on a duplicate — the caller (the
    LangGraph graph) catches this and decides whether to swallow, retry, or
    halt. Keeps the node referentially transparent.
    """

    def __init__(self, *, attack_id: uuid.UUID, verdict_id: uuid.UUID) -> None:
        self.attack_id = attack_id
        self.verdict_id = verdict_id
        super().__init__(f"finding already filed for attack_id={attack_id} verdict_id={verdict_id}")


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def _route(severity: str, confidence: float) -> Routing:
    """Return ``human_approval`` for high-severity OR low-confidence verdicts.

    The two routing rules are OR'd: a P0 with confidence 0.99 still goes to
    the human queue, and a P3 with confidence 0.4 also goes to the queue.
    """
    if severity in _HUMAN_APPROVAL_SEVERITIES:
        return "human_approval"
    if confidence < AUTOFILE_CONFIDENCE_THRESHOLD:
        return "human_approval"
    return "autofile"


_REQUIRED_LLM_KEYS: Final[tuple[str, ...]] = (
    "title",
    "description",
    "severity_rationale",
    "clinical_impact",
    "observed_behavior",
    "expected_behavior",
    "remediation_suggestions",
    "validation_steps",
    "reproduction_steps",
)


def _strip_markdown_json_fence(text: str) -> str:
    """Strip a leading `````json``-fence wrapper if present.

    Claude Sonnet 4.6 routinely wraps its JSON output in markdown code
    fences even when the prompt asks for raw JSON. We pre-strip the fence
    here so the strict JSON parser below succeeds without us having to
    teach every caller to know about Claude's formatting habit.

    Falls back to slicing from the first ``{`` to the last ``}`` if the
    fence shape doesn't match — handles preambles like "Here's the JSON:".
    """
    s = text.strip()
    if s.startswith("```"):
        nl = s.find("\n")
        if nl > 0:
            s = s[nl + 1 :]
        if s.endswith("```"):
            s = s[:-3]
        s = s.strip()
    first = s.find("{")
    last = s.rfind("}")
    if first >= 0 and last > first:
        return s[first : last + 1]
    return s


def _parse_llm_response_to_sections(text: str) -> dict[str, Any]:
    """Parse the LLM's drafted JSON envelope into the report-template fields.

    For the skeleton we require strict JSON with the keys in
    :data:`_REQUIRED_LLM_KEYS`. Missing keys / malformed JSON raise
    :class:`ValueError` so the audit row carries the parse failure and a
    human reviewer notices immediately.
    """
    try:
        payload = json.loads(_strip_markdown_json_fence(text))
    except json.JSONDecodeError as exc:
        raise ValueError(f"LLM response is not valid JSON: {exc}") from exc

    if not isinstance(payload, dict):
        raise ValueError(f"LLM response must be a JSON object; got {type(payload).__name__}")

    missing = [k for k in _REQUIRED_LLM_KEYS if k not in payload]
    if missing:
        raise ValueError(
            f"LLM response missing required keys: {sorted(missing)}; "
            f"required: {list(_REQUIRED_LLM_KEYS)}"
        )

    # reproduction_steps must be a non-empty list of strings — the report
    # template enforces this at render time but we validate early so the
    # error blames the LLM, not the template.
    steps = payload["reproduction_steps"]
    if not isinstance(steps, list) or not steps or not all(isinstance(s, str) for s in steps):
        raise ValueError("LLM response 'reproduction_steps' must be a non-empty list of strings")

    return payload


def _build_llm_user_prompt(
    verdict: VerdictRecord,
    sanitized_evidence: str,
    frameworks: FindingFrameworks,
) -> str:
    """Assemble the structured user prompt for the Doc Agent's LLM call.

    The prompt tells the LLM the severity is already settled and asks for a
    strict JSON envelope. The exact section names match
    :class:`FindingReportContext` field names so the parser can hand the dict
    straight through.
    """
    return (
        "You are drafting prose sections for a confirmed vulnerability finding.\n"
        "Severity is ALREADY ASSIGNED by a deterministic rubric. Do not re-grade it.\n"
        "Reply with a single JSON object and nothing else. Required keys:\n"
        '  "title" (string, <=120 chars),\n'
        '  "description" (string, 2-4 sentences),\n'
        '  "severity_rationale" (string),\n'
        '  "clinical_impact" (string),\n'
        '  "observed_behavior" (string),\n'
        '  "expected_behavior" (string),\n'
        '  "remediation_suggestions" (string),\n'
        '  "validation_steps" (string),\n'
        '  "reproduction_steps" (non-empty array of strings).\n'
        "\n"
        f"Verdict: {verdict.verdict}\n"
        f"Confidence: {verdict.confidence}\n"
        f"Evidence refs: {verdict.evidence_refs}\n"
        f"Rubric SHA: {verdict.rubric_sha}\n"
        f"Model version: {verdict.model_version}\n"
        "\n"
        f"OWASP: {frameworks.owasp_id}\n"
        f"MITRE: {frameworks.mitre_id}\n"
        f"HIPAA: {frameworks.hipaa_section}\n"
        "\n"
        "Sanitized evidence (only source you may quote):\n"
        f"{sanitized_evidence}\n"
    )


def _find_attack(state: PlatformState, attack_id: uuid.UUID) -> AttackRecord:
    """Return the :class:`AttackRecord` matching ``attack_id`` or raise.

    The state model does not maintain a dict index, so we scan. State sizes
    in a single session are small (low thousands at most), so a linear scan
    is fine and keeps :class:`PlatformState` immutable-friendly.
    """
    for attack in state.attack_records:
        if attack.attack_id == attack_id:
            return attack
    raise RuntimeError(
        f"no AttackRecord found for verdict.attack_id={attack_id}; "
        f"verdict references an attack that is not in state.attack_records"
    )


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------


def _dedup_check(engine: Engine, *, attack_id: uuid.UUID, verdict_id: uuid.UUID) -> bool:
    """Return True if a ``findings`` row already exists for this pair."""
    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT 1 FROM findings "
                "WHERE attack_id = :attack_id AND verdict_id = :verdict_id LIMIT 1"
            ),
            {"attack_id": str(attack_id), "verdict_id": str(verdict_id)},
        ).first()
    return row is not None


def _insert_finding_row(
    engine: Engine,
    *,
    finding_id: uuid.UUID,
    severity: Severity,
    attack_id: uuid.UUID,
    verdict_id: uuid.UUID,
    gitlab_issue_id: int | None,
    sanitized_evidence: str,
) -> None:
    """INSERT a single ``findings`` row. Stays in its own transaction."""
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO findings "
                "(finding_id, severity, attack_id, verdict_id, gitlab_issue_id, sanitized_evidence) "
                "VALUES (:finding_id, :severity, :attack_id, :verdict_id, :gitlab_issue_id, :sanitized_evidence)"
            ),
            {
                "finding_id": str(finding_id),
                "severity": severity,
                "attack_id": str(attack_id),
                "verdict_id": str(verdict_id),
                "gitlab_issue_id": gitlab_issue_id,
                "sanitized_evidence": json.dumps({"text": sanitized_evidence}),
            },
        )


def _insert_approval_queue_row(
    engine: Engine,
    *,
    finding_id: uuid.UUID,
) -> None:
    """INSERT a ``pending`` row in ``human_approval_queue`` for ``finding_id``."""
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO human_approval_queue (queue_id, finding_id, status) "
                "VALUES (:queue_id, :finding_id, 'pending')"
            ),
            {
                "queue_id": str(uuid.uuid4()),
                "finding_id": str(finding_id),
            },
        )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def documentation_node(
    state: PlatformState,
    *,
    engine: Engine,
    llm: LLMClientLike,
    gitlab: GitLabClientLike,
    frameworks: FindingFrameworks,
    rubric_outcomes: dict[str, bool] | None = None,
    target_sha: str = "",
    rubric_sha: str = "",
    model: str = DEFAULT_MODEL,
    langfuse: Any | None = None,
) -> PlatformState:
    """Convert the latest pass/partial verdict into a vulnerability report.

    See module docstring for the contract. Roughly:

    1. Pick the latest verdict; skip when it's ``fail``.
    2. Dedup against the ``findings`` table (raise on hit).
    3. Sanitise the matching ``AttackRecord``'s ``target_response``.
    4. Compute severity deterministically from ``rubric_outcomes`` (default
       empty dict — meaning the verdict-based fallback path in
       :func:`assign_severity` decides).
    5. Audit-wrapped LLM call for the report's prose sections.
    6. Build :class:`FindingReportContext` and render markdown.
    7. Route: ``{P0, P1}`` or confidence < 0.7 -> human queue; else autofile
       via audit-wrapped ``gitlab.create_issue``.
    8. INSERT the ``findings`` row, push :class:`ConfirmedFinding` onto state,
       bump ``cost_so_far`` by the LLM cost.
    """
    # ---- 1. Pick the latest verdict ---------------------------------------
    if not state.verdict_records:
        raise RuntimeError(
            "documentation_node invoked with empty verdict_records; "
            "the graph should not call us until the Judge has settled at least one verdict"
        )

    verdict = state.verdict_records[-1]

    # Skip non-actionable verdicts. ``inconclusive`` is *not* skipped here:
    # the contract is to let ``assign_severity`` raise so a wiring bug
    # (inconclusive verdict reaching the Doc Agent) is loud, not silent.
    if verdict.verdict == "fail":
        return state

    # ---- 2. Dedup ---------------------------------------------------------
    if _dedup_check(engine, attack_id=verdict.attack_id, verdict_id=verdict.verdict_id):
        raise FindingAlreadyFiled(attack_id=verdict.attack_id, verdict_id=verdict.verdict_id)

    # ---- 3. Severity (deterministic, BEFORE the LLM) ---------------------
    outcomes = rubric_outcomes or {}
    severity = assign_severity(verdict, outcomes)

    # ---- 4. Sanitise the evidence ----------------------------------------
    attack = _find_attack(state, verdict.attack_id)
    sanitized = sanitize_evidence(attack.target_response)

    # ---- 5. LLM call for the prose sections ------------------------------
    doc_prompt = load_prompt("doc")
    user_prompt = _build_llm_user_prompt(verdict, sanitized, frameworks)

    llm_call = await call_tool(
        agent=_AGENT_NAME,
        tool_name="llm_complete",
        tool=llm.complete,
        args={"system": doc_prompt.text, "user": user_prompt, "model": model},
        session_id=state.session_id,
        engine=engine,
        langfuse=langfuse,
        cost_estimator=lambda response: int(getattr(response, "cost_cents", 0)),
    )
    llm_response: LLMResponse = llm_call.result
    sections = _parse_llm_response_to_sections(llm_response.text)

    # ---- 6. Build context and render -------------------------------------
    finding_id = uuid.uuid4()
    ctx = FindingReportContext(
        severity=severity,
        title=sections["title"][:120],
        description=sections["description"],
        severity_rationale=sections["severity_rationale"],
        owasp_id=frameworks.owasp_id,
        mitre_id=frameworks.mitre_id,
        hipaa_section=frameworks.hipaa_section,
        clinical_impact=sections["clinical_impact"],
        reproduction_steps=list(sections["reproduction_steps"]),
        observed_behavior=sections["observed_behavior"],
        expected_behavior=sections["expected_behavior"],
        sanitized_evidence=sanitized,
        remediation_suggestions=sections["remediation_suggestions"],
        validation_steps=sections["validation_steps"],
        finding_id=str(finding_id),
        target_sha=target_sha or attack.target_sha,
        rubric_sha=rubric_sha or verdict.rubric_sha,
    )
    rendered = render_finding(ctx)

    # ---- 7. Route ---------------------------------------------------------
    routing = _route(severity, verdict.confidence)
    gitlab_issue_id: int | None
    if routing == "autofile":
        gitlab_call = await call_tool(
            agent=_AGENT_NAME,
            tool_name="gitlab_create_issue",
            tool=gitlab.create_issue,
            args={
                "title": ctx.title,
                "body": rendered,
                "labels": [
                    f"severity::{severity}",
                    f"owasp::{frameworks.owasp_id}",
                    f"mitre::{frameworks.mitre_id}",
                ],
            },
            session_id=state.session_id,
            engine=engine,
            langfuse=langfuse,
        )
        issue_ref: GitLabIssueRef = gitlab_call.result
        gitlab_issue_id = issue_ref.issue_id
    else:
        gitlab_issue_id = None

    # ---- 8. Persist and update state -------------------------------------
    _insert_finding_row(
        engine,
        finding_id=finding_id,
        severity=severity,
        attack_id=verdict.attack_id,
        verdict_id=verdict.verdict_id,
        gitlab_issue_id=gitlab_issue_id,
        sanitized_evidence=sanitized,
    )
    if routing == "human_approval":
        _insert_approval_queue_row(engine, finding_id=finding_id)

    confirmed = ConfirmedFinding(
        finding_id=finding_id,
        severity=severity,
        attack_id=verdict.attack_id,
        verdict_id=verdict.verdict_id,
        gitlab_issue_id=gitlab_issue_id,
    )

    # cost_so_far is in DOLLARS (Decimal); cost_cents is in cents.
    # Bug prior to 2026-05-13: this added Decimal(cents) directly to
    # dollars, inflating state.cost_so_far by 100x on every doc-agent
    # call. Other agents (red_team/judge/orchestrator) all do the
    # ``Decimal(cents) / Decimal(100)`` conversion. See BUG_LEDGER.md.
    delta_dollars = Decimal(llm_call.cost_cents) / Decimal(100)
    new_cost = state.cost_so_far + delta_dollars
    return state.model_copy(
        update={
            "confirmed_findings": [*state.confirmed_findings, confirmed],
            "cost_so_far": new_cost,
        }
    )
