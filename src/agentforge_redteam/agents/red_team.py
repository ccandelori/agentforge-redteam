"""Red Team agent — adversarial payload generation against the in-scope target.

This is the Task 25 *skeleton*: a single-invocation node that runs ONE attack
end-to-end through the platform's safety substrate (allowlist, content filter,
audited tool wrapper, kill switch). A richer mutation strategy and Orchestrator-
level scheduling land in later tasks.

Contract per invocation
-----------------------
1. Require :class:`PlatformState.current_campaign` to be set.
2. Reject the call early if ``target_url`` is not on the YAML allowlist.
3. Choose the payload:
   - If at least one prior :class:`AttackRecord` exists for this campaign
     (matched by the ``campaign_id`` we synthesize deterministically from
     ``(category, sub_attack)``), call the injected LLM client to mutate the
     seed in light of those priors. The LLM call is itself audited.
   - Otherwise (clean first attack), use the seed payload from
     ``attack_library.json`` verbatim and skip the LLM hop entirely.
4. Hand the chosen payload to :func:`content_filter.filter_payload`. A trip
   propagates :class:`PayloadRefused` out of this node — no HTTP, no
   :class:`AttackRecord`. The platform treats it as a configuration error.
5. POST to the target via the injected HTTP client, wrapped in
   :func:`tools.wrapper.call_tool`, so the kill switch is honored and the
   ``agent_steps`` row is written.
6. Build one :class:`AttackRecord`, append it to ``state.attack_records``, and
   update ``state.cost_so_far`` by the cents this invocation cost (LLM + 0
   for the target HTTP call, since the target is not a billed model).
7. Return a fresh :class:`PlatformState` via :meth:`model_copy` — no in-place
   mutation.

Design notes
------------
* **No real clients imported.** The LLM and HTTP clients are
  :class:`Protocol`-typed and injected by the orchestrator. Tests inject
  trivial fakes. The real clients are wired in Task 29.
* **campaign_id is deterministic.** Until :class:`CampaignBrief` grows its
  own ``campaign_id`` field, we hash ``(category, sub_attack)`` through
  :func:`uuid.uuid5` against a fixed namespace. Two invocations for the
  same sub-attack therefore share a campaign id, which is what the prior-
  attempts filter wants. This is documented as a skeleton-only convention.
* **Cost is summed in dollars.** ``state.cost_so_far`` is a Pydantic
  :class:`Decimal`; we convert the wrapper's cent counts via
  ``Decimal(cents) / Decimal(100)`` to avoid float drift in the running
  total.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any, Final, Protocol

import structlog
from sqlalchemy import text
from sqlalchemy.engine import Engine

from agentforge_redteam.allowlist import (
    DEFAULT_TARGETS_PATH,
    validate_target_url,
)
from agentforge_redteam.attack_library import (
    ATTACK_LIBRARY_PATH,
    AttackSeed,
    load_attack_library,
)
from agentforge_redteam.prompts import PROMPTS_DIR, load_prompt
from agentforge_redteam.redteam.content_filter import filter_payload
from agentforge_redteam.state import AttackRecord, PlatformState
from agentforge_redteam.tools.wrapper import call_tool

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT_S: Final[float] = 30.0
DEFAULT_MODEL: Final[str] = "gpt-4o-2024-08-06"

# Deterministic namespace for ``uuid5`` so a (category, sub_attack) tuple maps
# to a stable :class:`UUID` across processes. Documented in the module
# docstring: this is the skeleton's stand-in until ``CampaignBrief`` gains its
# own ``campaign_id`` field.
_CAMPAIGN_ID_NAMESPACE: Final[uuid.UUID] = uuid.UUID("c0a3f0ad-1e2b-4f9d-9e3a-7c0b1f2d3e4f")


# ---------------------------------------------------------------------------
# Injected-client protocols
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LLMResponse:
    """Minimum surface area the Red Team needs from an LLM client.

    ``cost_cents`` is the LLM's reported cost in integer cents. The Red Team
    node converts this to :class:`Decimal` dollars before summing into
    :attr:`PlatformState.cost_so_far`.
    """

    text: str
    cost_cents: int


@dataclass(frozen=True, slots=True)
class TargetResponse:
    """Subset of an HTTP response we need from the target client.

    ``target_sha`` ties the recorded attack to a specific build of the
    target — production wires this from ``/health`` or ``/version``; tests
    supply a canned value.
    """

    status_code: int
    body: str
    target_sha: str


class LLMClientLike(Protocol):
    """Subset of an OpenAI/Anthropic client this node depends on."""

    async def complete(self, *, system: str, user: str, model: str) -> LLMResponse: ...


class HTTPTargetClientLike(Protocol):
    """Subset of an httpx-style HTTP client this node depends on."""

    async def post(self, *, url: str, payload: str, timeout_s: float) -> TargetResponse: ...


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _campaign_id_for(category: str, sub_attack: str) -> uuid.UUID:
    """Deterministic id for the (category, sub_attack) pair.

    See module docstring for rationale. ``uuid5`` is deterministic on
    namespace + name, so two invocations of the same (category, sub_attack)
    in the same process — or in any future process — will share an id and
    the prior-attempts filter will work.
    """
    return uuid.uuid5(_CAMPAIGN_ID_NAMESPACE, f"{category}::{sub_attack}")


def _select_seed(
    category: str,
    sub_attack: str,
    *,
    library_path: Path | str,
) -> AttackSeed:
    """Return the first :class:`AttackSeed` matching the (category, sub_attack)."""
    library = load_attack_library(library_path)
    for seed in library.attacks:
        if seed.category == category and seed.sub_attack == sub_attack:
            return seed
    raise RuntimeError(
        f"no attack_library seed for (category={category!r}, sub_attack={sub_attack!r})"
    )


def _prior_payloads(state: PlatformState, campaign_id: uuid.UUID) -> list[str]:
    """Return the payloads of prior attacks recorded under this campaign id."""
    return [r.payload for r in state.attack_records if r.campaign_id == campaign_id]


def _build_mutation_user_prompt(
    seed: AttackSeed,
    priors: list[str],
) -> str:
    """Render the user-message portion of the mutation prompt.

    The system message comes from ``prompts/redteam.md`` (versioned + hashed
    elsewhere); this function only assembles the per-call context that the
    system prompt's ``{seed_payloads}`` / ``{prior_attempts_summary}``
    placeholders need.
    """
    seed_block = f"seed: {seed.payload}"
    priors_block = "\n".join(f"- {p}" for p in priors)
    return (
        f"category: {seed.category}\n"
        f"sub_attack: {seed.sub_attack}\n"
        f"{seed_block}\n"
        f"prior_attempts:\n{priors_block}\n"
    )


def _parse_mutation_payload(raw_text: str) -> str:
    """Extract the inner ``payload`` string from the Red Team LLM's JSON envelope.

    ``prompts/redteam.md`` asks the LLM to emit
    ``{"payload": "<the adversarial input>", "rationale": ..., "mutation_of_attack_id": ...}``.
    Without this parser we send the entire envelope (``{"payload":...,
    "rationale":..., ...}``) to the target as the attack body, which (a) is
    not the attack the rubric is testing for and (b) trips structured-input
    refusals that mask whether the real attack would have succeeded.

    Tolerant of Claude's habit of wrapping JSON in markdown code fences
    (```json ... ```) and of leading/trailing prose. Raises ``ValueError``
    if no JSON object is recoverable or the ``payload`` field is missing /
    not a string — caller decides the fallback.
    """
    text = raw_text.strip()
    if text.startswith("```"):
        nl = text.find("\n")
        if nl > 0:
            text = text[nl + 1 :]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()
    first = text.find("{")
    last = text.rfind("}")
    if first < 0 or last <= first:
        raise ValueError("no JSON object in mutation response")
    parsed = json.loads(text[first : last + 1])
    payload = parsed.get("payload")
    if not isinstance(payload, str):
        raise ValueError("mutation JSON missing string 'payload' field")
    return payload


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def red_team_node(
    state: PlatformState,
    *,
    engine: Engine,
    llm: LLMClientLike,
    http: HTTPTargetClientLike,
    target_url: str,
    model: str = DEFAULT_MODEL,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    langfuse: Any | None = None,
    attack_library_path: Path | str = ATTACK_LIBRARY_PATH,
    targets_path: Path | str = DEFAULT_TARGETS_PATH,
    prompts_dir: Path = PROMPTS_DIR,
) -> PlatformState:
    """Generate ONE attack against ``state.current_campaign`` and append it.

    See the module docstring for the full contract. In one line: validate
    campaign + URL → pick seed / mutate → content-filter → POST to target via
    the audited wrapper → record the attack → return new state.
    """
    # ---- 1. Require a campaign. -----------------------------------------
    if state.current_campaign is None:
        raise RuntimeError("red_team_node invoked without current_campaign")
    campaign = state.current_campaign

    # ---- 2. Validate the target URL. ------------------------------------
    # Raises TargetNotAllowed if the URL is off-list. The exception propagates
    # so the orchestrator notices the misconfiguration immediately.
    validate_target_url(target_url, targets_path)

    # ---- 3. Choose the payload. -----------------------------------------
    seed = _select_seed(campaign.category, campaign.sub_attack, library_path=attack_library_path)
    campaign_id = _campaign_id_for(campaign.category, campaign.sub_attack)
    priors = _prior_payloads(state, campaign_id)

    llm_cost_cents: int = 0
    if priors:
        # Mutation path: the LLM is called through the audited wrapper so the
        # ``agent_steps`` table records exactly which call produced which
        # payload. The system prompt is the versioned ``redteam.md``.
        loaded = load_prompt("redteam", prompts_dir)
        user_prompt = _build_mutation_user_prompt(seed, priors)
        llm_call = await call_tool(
            agent="red_team",
            tool_name="generate_mutation",
            tool=llm.complete,
            args={"system": loaded.text, "user": user_prompt, "model": model},
            session_id=state.session_id,
            engine=engine,
            langfuse=langfuse,
            # Without this, the audit wrapper records cost_cents=0 for every
            # mutation call — even though LLMResponse.cost_cents is populated
            # by the client. NEXT-SESSION.md Known Debt #5.
            cost_estimator=lambda response: int(getattr(response, "cost_cents", 0)),
        )
        llm_response: LLMResponse = llm_call.result
        try:
            payload = _parse_mutation_payload(llm_response.text)
        except (ValueError, json.JSONDecodeError) as exc:
            logger.warning(
                "red_team.mutation_parse_failed",
                seed_category=seed.category,
                seed_sub_attack=seed.sub_attack,
                error=str(exc),
            )
            payload = seed.payload
        llm_cost_cents = llm_response.cost_cents
    else:
        payload = seed.payload

    # ---- 4. Content filter. ---------------------------------------------
    # Loud-fails on out-of-scope categories. No HTTP and no AttackRecord on
    # refusal — the audit log already shows the LLM call (if any) that
    # produced the offending text.
    filter_payload(payload)

    # ---- 5. Target POST through the audited wrapper. --------------------
    target_call = await call_tool(
        agent="red_team",
        tool_name="call_target",
        tool=http.post,
        args={"url": target_url, "payload": payload, "timeout_s": timeout_s},
        session_id=state.session_id,
        engine=engine,
        langfuse=langfuse,
    )
    target_response: TargetResponse = target_call.result

    # ---- 6. Build the AttackRecord. -------------------------------------
    record = AttackRecord(
        campaign_id=campaign_id,
        payload=payload,
        target_response=target_response.body,
        target_sha=target_response.target_sha,
        status_code=target_response.status_code,
        latency_ms=target_call.latency_ms,
    )

    # ---- 6b. Eagerly persist to the ``attacks`` table. ------------------
    # The web UI reads from SQL tables, not from LangGraph state. We INSERT
    # mid-run (in its own transaction) so the Coverage tab can show the
    # attack within ~100ms of it landing — without waiting for the entire
    # session to finish. The audit-trail invariant for the wrapper still
    # holds (``agent_steps`` written by ``call_tool``); this INSERT is the
    # operator-facing denormalization.
    try:
        with engine.begin() as conn:
            # ``INSERT OR IGNORE``: idempotent under retry, and lets test
            # fixtures that pre-seed attack rows (under the old "agents
            # don't persist" contract) continue to work. uuid4 attack_id
            # collisions are astronomically unlikely in production, so
            # silent-drop is the right semantics: either the row is already
            # there with identical data, or there's a bug we'd catch via
            # agent_steps anyway.
            conn.execute(
                text(
                    "INSERT OR IGNORE INTO attacks "
                    "(attack_id, campaign_id, payload, target_response, "
                    "target_sha, status_code, latency_ms) VALUES "
                    "(:aid, :cid, :pl, :tr, :tsha, :sc, :lat)"
                ),
                {
                    "aid": str(record.attack_id),
                    "cid": str(record.campaign_id),
                    "pl": record.payload,
                    "tr": record.target_response,
                    "tsha": record.target_sha,
                    "sc": record.status_code,
                    "lat": record.latency_ms,
                },
            )
    except Exception:
        # A persistence failure must not crash the agent — the run keeps
        # state in memory and the orchestrator decides whether to halt.
        # The agent_steps audit row already captured the call upstream.
        pass

    # ---- 7. Sum costs in dollars (Decimal). -----------------------------
    # The target call is not a billed model, so its cents contribution is 0.
    delta_cents = llm_cost_cents
    delta_dollars = Decimal(delta_cents) / Decimal(100)

    return state.model_copy(
        update={
            "attack_records": [*state.attack_records, record],
            "cost_so_far": state.cost_so_far + delta_dollars,
        }
    )
