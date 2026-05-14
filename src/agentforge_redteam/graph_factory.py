"""Production graph factory — wires real agents into the LangGraph state machine.

The skeleton graph (:mod:`agentforge_redteam.graph`) wires ``*_stub`` functions
for tests that pin the structural contract. The production graph (this module)
wires the real ``*_node`` async functions with injected LLM / HTTP / GitLab /
Langfuse clients. Both compile to the same LangGraph topology — they differ
only in which functions occupy each node.

Design choices:

* **One factory entry point.** :func:`build_production_graph` returns a
  compiled runnable. Tests use ``build_production_graph(env={})`` with an
  empty env dict to exercise the stub fallbacks; production code wires it
  from ``os.environ.copy()``.

* **Safe fallbacks for every client.** If ``ANTHROPIC_API_KEY`` is missing
  the Judge / Orchestrator / Documentation agents get a stub LLM that
  raises a :class:`RuntimeError` on ``.complete()`` (so the failure is
  loud, not silent). Likewise OpenAI for the Red Team. Missing GitLab
  credentials fall through to :class:`LocalFindingsSink`. Missing
  Langfuse credentials fall through to :class:`NoopLangfuseClient`. The
  graph still compiles cleanly with zero env — the failure surfaces only
  when an agent tries to call a stubbed client.

* **A shared engine per graph build.** All four nodes get the same
  engine reference so the audit log lands in one SQLite file. The
  caller owns the lifecycle (must call ``engine.dispose()``).

* **HTTP target client requires explicit injection or a default.** The
  Red Team needs an :class:`HTTPTargetClientLike` to call the target.
  The factory takes an optional ``http_client`` argument; if ``None``,
  builds an :mod:`httpx`-based client that wraps the target URL from
  ``targets.yaml``. The default httpx client is a thin wrapper, ~20
  lines.

* **Doc Agent's FindingFrameworks is per-campaign.** The mapping
  :data:`_FRAMEWORK_BY_CATEGORY` resolves the right OWASP + MITRE +
  HIPAA triple for the campaign's category at runtime. Future
  categories must extend this map.
"""

from __future__ import annotations

import os
import random
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, cast

import httpx
import structlog
from langgraph.graph import END, START, StateGraph
from sqlalchemy import text
from sqlalchemy.engine import Engine

from agentforge_redteam.agents.documentation import (
    FindingFrameworks,
    documentation_node,
)
from agentforge_redteam.agents.documentation import (
    LLMClientLike as DocLLMClientLike,
)
from agentforge_redteam.agents.documentation import (
    LLMResponse as DocLLMResponse,
)
from agentforge_redteam.agents.judge import (
    LLMClientLike as JudgeLLMClientLike,
)
from agentforge_redteam.agents.judge import (
    LLMResponse as JudgeLLMResponse,
)
from agentforge_redteam.agents.judge import (
    judge_node,
)
from agentforge_redteam.agents.orchestrator import (
    LLMClientLike as OrchLLMClientLike,
)
from agentforge_redteam.agents.orchestrator import (
    LLMResponse as OrchLLMResponse,
)
from agentforge_redteam.agents.orchestrator import (
    orchestrator_node,
)
from agentforge_redteam.agents.red_team import (
    HTTPTargetClientLike,
    TargetResponse,
    red_team_node,
)
from agentforge_redteam.agents.red_team import (
    LLMClientLike as RTLLMClientLike,
)
from agentforge_redteam.agents.red_team import (
    LLMResponse as RTLLMResponse,
)
from agentforge_redteam.allowlist import load_targets
from agentforge_redteam.clients.anthropic_client import create_anthropic_client
from agentforge_redteam.clients.factory import create_documentation_client
from agentforge_redteam.clients.openai_client import create_openai_client
from agentforge_redteam.db import create_platform_engine
from agentforge_redteam.observability.langfuse_client import (
    NoopLangfuseClient,
    create_langfuse_client,
)
from agentforge_redteam.orchestrator_policy import OrchestratorPolicy, load_policy
from agentforge_redteam.regression.runner import (
    RegressionSessionSummary,
    run_regression_session,
)
from agentforge_redteam.state import PlatformState

logger = structlog.get_logger(__name__)

__all__ = [
    "NODE_DOCUMENTATION",
    "NODE_JUDGE",
    "NODE_ORCHESTRATOR",
    "NODE_RED_TEAM",
    "NODE_REGRESSION",
    "HTTPTargetClient",
    "ProductionGraphConfig",
    "build_production_graph",
]


# ---------------------------------------------------------------------------
# Node names — kept identical to graph.py so dashboards and traces line up.
# ---------------------------------------------------------------------------

NODE_ORCHESTRATOR: Final[str] = "orchestrator"
NODE_RED_TEAM: Final[str] = "red_team"
NODE_JUDGE: Final[str] = "judge"
NODE_DOCUMENTATION: Final[str] = "documentation"
NODE_REGRESSION: Final[str] = "regression"

# P0/P1 are the operator-escalation severities; P2/P3 regressions stay in the
# ``regression_runs`` audit table only.
_ESCALATION_SEVERITIES: Final[frozenset[str]] = frozenset({"P0", "P1"})


# ---------------------------------------------------------------------------
# Framework triple lookup
# ---------------------------------------------------------------------------

# Three MVP categories carry hand-curated OWASP + MITRE + HIPAA tags. Future
# categories MUST extend this map; an unknown category falls back to the
# "UNKNOWN" sentinel triple so the doc agent still renders rather than
# crashing on a category that hasn't been mapped yet. The sentinel is
# intentionally loud (greppable) so an operator notices the gap in the
# rendered report.
_FRAMEWORK_BY_CATEGORY: Final[dict[str, FindingFrameworks]] = {
    "prompt-injection-indirect": FindingFrameworks(
        owasp_id="LLM01:2025",
        mitre_id="ATLAS.T0051",
        hipaa_section="§164.308(a)(1)(ii)(A)",
    ),
    "data-exfiltration": FindingFrameworks(
        owasp_id="LLM02:2025",
        mitre_id="ATLAS.T0024",
        hipaa_section="§164.502(b)",
    ),
    "tool-misuse": FindingFrameworks(
        owasp_id="LLM06:2025",
        mitre_id="ATLAS.T0053",
        hipaa_section="§164.312(b)",
    ),
}

_UNKNOWN_FRAMEWORKS: Final[FindingFrameworks] = FindingFrameworks(
    owasp_id="UNKNOWN",
    mitre_id="UNKNOWN",
    hipaa_section="UNKNOWN",
)


# ---------------------------------------------------------------------------
# Stub clients used when env keys are missing
# ---------------------------------------------------------------------------


class _UnconfiguredLLMError(RuntimeError):
    """Raised when a stub LLM client receives a call.

    Surfaces a clear, actionable message that the env key needed to
    configure the real client is missing. Preferred over a silent
    no-op so an agent invocation never accidentally returns an empty
    response and proceeds as if the LLM had spoken.
    """


_ANTHROPIC_MISSING_MSG: Final[str] = (
    "Anthropic client not configured — set ANTHROPIC_API_KEY to enable "
    "Judge / Orchestrator / Documentation"
)


class _StubOpenAILLM:
    """Red Team LLM stand-in. Raises on call to surface a missing key."""

    async def complete(self, *, system: str, user: str, model: str) -> RTLLMResponse:
        raise _UnconfiguredLLMError(
            "OpenAI client not configured — set OPENAI_API_KEY to enable Red Team"
        )


# The Judge / Orchestrator / Documentation Protocols each pin a distinct
# concrete ``LLMResponse`` dataclass on the ``complete`` return type. The
# three are structurally identical (``text: str``, ``cost_cents: int``)
# but mypy treats them nominally, so a Union return value would not
# satisfy any one of them. We therefore declare three thin stub classes
# — one per agent slot — each typed at the exact response shape its
# Protocol expects. All three share the same ``raise`` body via
# :data:`_ANTHROPIC_MISSING_MSG`.


class _StubAnthropicJudgeLLM:
    """Judge LLM stand-in. Raises on call to surface a missing key."""

    async def complete(self, *, system: str, user: str, model: str) -> JudgeLLMResponse:
        raise _UnconfiguredLLMError(_ANTHROPIC_MISSING_MSG)


class _StubAnthropicOrchLLM:
    """Orchestrator LLM stand-in. Raises on call to surface a missing key."""

    async def complete(self, *, system: str, user: str, model: str) -> OrchLLMResponse:
        raise _UnconfiguredLLMError(_ANTHROPIC_MISSING_MSG)


class _StubAnthropicDocLLM:
    """Documentation LLM stand-in. Raises on call to surface a missing key."""

    async def complete(self, *, system: str, user: str, model: str) -> DocLLMResponse:
        raise _UnconfiguredLLMError(_ANTHROPIC_MISSING_MSG)


# ---------------------------------------------------------------------------
# Default HTTP target client (httpx-based)
# ---------------------------------------------------------------------------


class HTTPTargetClient:
    """:mod:`httpx`-based implementation of :class:`HTTPTargetClientLike`.

    Supports two payload modes, picked at construction time:

    * **Generic mode** (default): POSTs JSON ``{"payload": ...}`` and returns
      the raw response body. Used for tests, mock targets, and any target
      whose API contract is "POST a payload, get a response back."
    * **AgentForge Co-Pilot mode**: when ``AGENTFORGE_JWT_SECRET`` is in env,
      the client mints a short-lived HS256 JWT carrying the legacy claim
      shape (issuer ``openemr-agentforge``, ``sub`` / ``patient_id`` /
      ``username`` / ``role``), sends ``{"message": payload}``, and parses
      the SSE response to extract the assistant's final text. This lets us
      attack the deployed sidecar at https://<droplet>:9300/dashboard/turn
      without going through the full OAuth dashboard flow.

    The ``target_sha`` field is read from ``X-Target-SHA`` header when
    present; ``"unknown"`` is the fallback so the recorded
    ``AttackRecord.target_sha`` stays non-empty (Pydantic ``min_length=1``).

    The client opens a fresh :class:`httpx.AsyncClient` per call so
    connection state cannot leak between campaigns. The Red Team node runs
    one POST per invocation, so per-call open is the right cost trade.

    TLS verification defaults to **off**. We are attacking the target, not
    trusting it — a target serving a self-signed or expired cert is a
    normal state of the world for a red-team subject. Operators who want
    strict verification can pass ``verify_tls=True``.
    """

    __slots__ = (
        "_jwt_secret",
        "_patient_id",
        "_role",
        "_timeout_s",
        "_user_id",
        "_username",
        "_verify_tls",
    )

    def __init__(
        self,
        *,
        timeout_s: float = 30.0,
        verify_tls: bool = False,
        jwt_secret: str | None = None,
        patient_id: int = 1,
        user_id: int = 1,
        username: str = "admin",
        role: str = "physician",
    ) -> None:
        self._timeout_s = timeout_s
        self._verify_tls = verify_tls
        self._jwt_secret = jwt_secret
        self._patient_id = patient_id
        self._user_id = user_id
        self._username = username
        self._role = role

    def _mint_agentforge_jwt(self) -> str:
        """Mint a 5-minute HS256 JWT matching the sidecar's legacy claim shape.

        Mirrors ``InternalJwtMinter.mint`` in
        ``sidecar/src/agentforge/dashboard_auth/internal_jwt.py`` byte-for-byte
        — issuer, TTL, claim names, all identical. Drift between the two would
        manifest as 401 from the sidecar.
        """
        import time

        import jwt as _jwt

        assert self._jwt_secret is not None
        iat = int(time.time())
        payload: dict[str, object] = {
            "iss": "openemr-agentforge",
            "iat": iat,
            "exp": iat + 300,
            "sub": str(self._user_id),
            "patient_id": self._patient_id,
            "username": self._username,
            "role": self._role,
            "breakglass_flag": False,
            "breakglass_reason": None,
        }
        return _jwt.encode(payload, self._jwt_secret, algorithm="HS256")

    @staticmethod
    def _parse_sse_text(body: str) -> str:
        """Concatenate ``text`` deltas from an SSE response stream.

        The sidecar emits frames of two shapes:

        * ``data: {"text": "..."}`` — token (or buffered chunk) of the reply.
        * ``data: {"final": true, "stop_reason": ..., "cost_usd": ...}`` — the
          final frame; no ``text`` field.

        Plus a literal ``data: [DONE]`` terminator. We join every ``text``
        we find in document order and return the concatenation. Any frame
        we can't parse as JSON is silently skipped (logged at debug level
        upstream).
        """
        import json as _json

        out: list[str] = []
        for line in body.splitlines():
            if not line.startswith("data:"):
                continue
            payload = line[len("data:") :].strip()
            if payload == "[DONE]" or not payload:
                continue
            try:
                obj = _json.loads(payload)
            except (ValueError, _json.JSONDecodeError):
                continue
            if isinstance(obj, dict) and isinstance(obj.get("text"), str):
                out.append(obj["text"])
        return "".join(out)

    async def post(self, *, url: str, payload: str, timeout_s: float) -> TargetResponse:
        """POST ``payload`` to ``url`` and adapt to a :class:`TargetResponse`.

        Picks AgentForge mode iff ``self._jwt_secret`` is set; otherwise
        falls back to the generic ``{"payload": …}`` shape.
        """
        effective_timeout = timeout_s if timeout_s > 0 else self._timeout_s
        if self._jwt_secret:
            token = self._mint_agentforge_jwt()
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }
            request_body: dict[str, object] = {"message": payload}
        else:
            headers = {"Content-Type": "application/json"}
            request_body = {"payload": payload}

        async with httpx.AsyncClient(timeout=effective_timeout, verify=self._verify_tls) as client:
            resp = await client.post(url, json=request_body, headers=headers)

        # If the response looks like SSE (Content-Type or body starts with
        # ``data:``), distill it into a single assistant-text string so the
        # Judge sees a coherent target_response.
        body = resp.text
        if self._jwt_secret and (
            resp.headers.get("content-type", "").startswith("text/event-stream")
            or body.lstrip().startswith("data:")
        ):
            distilled = self._parse_sse_text(body)
            if distilled:
                body = distilled

        return TargetResponse(
            status_code=resp.status_code,
            body=body,
            target_sha=resp.headers.get("x-target-sha", "unknown"),
        )


# ---------------------------------------------------------------------------
# Routing helpers — duplicated from graph.py so this module is self-contained.
# Skeleton graph.py keeps its own copies because that file is pinned.
# ---------------------------------------------------------------------------


def _should_halt(state: PlatformState) -> str:
    """``halt`` -> END, else ``continue``. Mirrors :func:`graph._should_halt`.

    Kept callable for callers that imported it before the three-way
    :func:`_orchestrator_routes` router landed (e.g. external diagnostic
    scripts). The production graph itself no longer routes on this helper
    — see :func:`_orchestrator_routes`.
    """
    return "halt" if state.halt_reason is not None else "continue"


def _orchestrator_routes(state: PlatformState) -> str:
    """Three-way router off the orchestrator.

    Decision table:

    +---------------------------------+--------------+
    | state.halt_reason               | next         |
    +=================================+==============+
    | ``"regression_due"``            | ``regression`` |
    +---------------------------------+--------------+
    | any other non-None reason       | ``halt``     |
    +---------------------------------+--------------+
    | ``None``                        | ``continue`` |
    +---------------------------------+--------------+

    Rationale: ``regression_due`` is a soft halt that the platform handles
    in-process by dispatching the regression replay loop and looping back
    to the orchestrator for a fresh decision. Every other halt reason
    (``kill_switch_tripped``, ``budget_exhausted``, ``canary_failed``,
    ``no_progress``, ...) is terminal — the run should END so the
    operator can decide what to do next.
    """
    if state.halt_reason == "regression_due":
        return "regression"
    if state.halt_reason is not None:
        return "halt"
    return "continue"


def _verdict_routes(state: PlatformState) -> str:
    """Route pass/partial verdicts to documentation; everything else loops back."""
    last = state.verdict_records[-1] if state.verdict_records else None
    if last is None:
        return "skip_doc"
    return "to_doc" if last.verdict in ("pass", "partial") else "skip_doc"


def _escalate_regressed_to_queue(
    engine: Engine,
    summary: RegressionSessionSummary,
    *,
    session_id: str,
) -> int:
    """Insert one ``human_approval_queue`` row per P0/P1 regression.

    For each :class:`RegressionResult` in ``summary.results`` with
    ``status='regressed'``, JOIN ``findings`` on
    ``regression_runs.finding_id`` to read the severity. If the severity
    is ``P0`` or ``P1``, insert a row into ``human_approval_queue`` with
    ``status='pending'`` (the column default; named explicitly here for
    grep-ability). Returns the count of escalations actually inserted.

    Why P0/P1 only: a regression on a P0/P1 case means a previously-
    confirmed serious vulnerability is reproducing on the new target —
    an operator must look before the next nightly. P2/P3 regressions
    land in ``regression_runs`` (already written by
    :func:`replay_regression_test`) and that audit row is sufficient
    until severity ratcheting promotes them.

    Why the JOIN on ``regression_runs``: a :class:`RegressionResult`
    doesn't carry severity. ``regression_runs.finding_id`` is the
    durable link, written by the harness with the same ``run_id`` the
    result holds. We look up the severity from ``findings`` via that
    finding_id. Using ``run_id`` as the JOIN anchor avoids any
    reliance on the harness's serialized JSON payload format.
    """
    escalated = 0
    with engine.begin() as conn:
        for result in summary.results:
            if result.status != "regressed":
                continue
            row = conn.execute(
                text(
                    "SELECT f.finding_id, f.severity "
                    "FROM regression_runs r "
                    "JOIN findings f ON f.finding_id = r.finding_id "
                    "WHERE r.run_id = :run_id"
                ),
                {"run_id": str(result.run_id)},
            ).first()
            if row is None:
                # Synthetic exception-results never wrote a regression_runs
                # row — see ``runner._exception_to_result``. Skip rather
                # than fabricate an escalation against a missing finding.
                logger.warning(
                    "regression.escalation_skipped_no_run_row",
                    run_id=str(result.run_id),
                    session_id=session_id,
                    notes=result.notes,
                )
                continue
            finding_id, severity = row[0], row[1]
            if severity not in _ESCALATION_SEVERITIES:
                continue
            conn.execute(
                text(
                    "INSERT INTO human_approval_queue "
                    "(queue_id, finding_id, status) "
                    "VALUES (:queue_id, :finding_id, 'pending')"
                ),
                {
                    "queue_id": str(uuid.uuid4()),
                    "finding_id": str(finding_id),
                },
            )
            escalated += 1
    if escalated:
        logger.info(
            "regression.escalated_to_queue",
            session_id=session_id,
            count=escalated,
            new_target_sha=summary.new_target_sha,
        )
    return escalated


# ---------------------------------------------------------------------------
# Public config + factory
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ProductionGraphConfig:
    """Frozen runtime config returned alongside the compiled graph.

    Lets callers (CLI, web-UI worker, smoke tests) inspect which real
    clients were wired in vs which fell through to the stubs / no-ops.
    The booleans use type-name comparison against the known fallback
    classes — see the module docstring for why this is acknowledged as
    brittle.
    """

    has_openai: bool
    has_anthropic: bool
    has_gitlab: bool
    has_langfuse: bool
    target_url: str
    policy: OrchestratorPolicy


def _is_real_gitlab(client: Any) -> bool:
    """Return True iff ``client`` is the real GitLab client, not the local sink.

    We compare on class name rather than ``isinstance`` against the
    concrete GitLab class to avoid pulling the GitLab adapter into the
    import graph for callers that never touch GitLab.
    """
    return type(client).__name__ != "LocalFindingsSink"


def _is_real_langfuse(client: Any) -> bool:
    """Return True iff ``client`` is the real Langfuse client, not the no-op."""
    return not isinstance(client, NoopLangfuseClient)


def build_production_graph(
    env: dict[str, str] | None = None,
    *,
    engine: Engine | None = None,
    rng: random.Random | None = None,
    http_client: HTTPTargetClientLike | None = None,
    target_alias: str = "droplet_prod",
    policy_path: Path | str = Path("orchestrator_policy.yaml"),
    allowed_categories: tuple[str, ...] | None = None,
    cost_cap_cents_override: int | None = None,
) -> tuple[Any, ProductionGraphConfig]:
    """Build and compile the production graph.

    Returns ``(compiled_app, config)``. The compiled app is a LangGraph
    runnable; the config carries the resolved policy + target URL + which
    real clients were wired in.

    Parameters
    ----------
    env:
        Environment mapping the factory reads keys from. Pass ``{}`` in
        tests to force every fallback (stub LLMs, LocalFindingsSink,
        NoopLangfuseClient). Pass ``os.environ.copy()`` in production.
        ``None`` (the default) reads from :data:`os.environ` at call time.
    engine:
        Optional shared SQLAlchemy engine. When ``None`` the factory
        creates one via :func:`create_platform_engine`; either way the
        caller owns the lifecycle and is responsible for
        :meth:`Engine.dispose`.
    rng:
        Optional :class:`random.Random`. When ``None`` a fresh
        unseeded RNG is used.
    http_client:
        Optional :class:`HTTPTargetClientLike` for the Red Team. When
        ``None`` we wrap :mod:`httpx` via :class:`HTTPTargetClient`.
    target_alias:
        Which alias in ``targets.yaml`` to resolve the target URL from.
        Defaults to ``"droplet_prod"``. Raises :class:`ValueError` if the
        alias is not present.
    policy_path:
        Path to the orchestrator policy YAML. Defaults to
        ``./orchestrator_policy.yaml``.
    """
    env_dict = env if env is not None else os.environ.copy()

    # Resolve clients with safe fallbacks. The three factories never raise
    # on missing keys; they each return ``None`` or a no-op sentinel.
    openai_client = create_openai_client(env_dict)
    anthropic_client = create_anthropic_client(env_dict)
    documentation_client = create_documentation_client(env_dict)
    langfuse_client = create_langfuse_client(env_dict)

    # Bind real or stub LLMs to each agent-specific Protocol slot. The
    # stubs are typed as ``Any`` because the three agent Protocols use
    # nominally distinct LLMResponse dataclasses; the stub raises before
    # returning so the actual response type is never observed.
    # The real AnthropicClient declares its return type as
    # ``DocLLMResponse`` (chosen as the canonical alias inside the
    # client module). The three agent Protocols pin their own
    # ``LLMResponse`` dataclasses, all of which are structurally
    # identical to ``DocLLMResponse``. Mypy treats them as nominally
    # distinct types, so the real client doesn't satisfy
    # ``JudgeLLMClientLike`` / ``OrchLLMClientLike`` by name alone. The
    # cast pins the structural compatibility explicitly at the wiring
    # seam — see the canonical alias comment in
    # :mod:`agentforge_redteam.clients.anthropic_client`.
    rt_llm: RTLLMClientLike = openai_client if openai_client is not None else _StubOpenAILLM()
    judge_llm: JudgeLLMClientLike = (
        cast(JudgeLLMClientLike, anthropic_client)
        if anthropic_client is not None
        else _StubAnthropicJudgeLLM()
    )
    orch_llm: OrchLLMClientLike = (
        cast(OrchLLMClientLike, anthropic_client)
        if anthropic_client is not None
        else _StubAnthropicOrchLLM()
    )
    doc_llm: DocLLMClientLike = (
        anthropic_client if anthropic_client is not None else _StubAnthropicDocLLM()
    )

    # Default HTTP target client wires the AgentForge Co-Pilot JWT secret
    # from env when present. The env var lets operators point at the live
    # sidecar (which requires a Bearer JWT) without code changes; when the
    # var is absent the client falls back to the generic {"payload": ...}
    # shape suitable for tests + mock targets.
    if http_client is not None:
        http: HTTPTargetClientLike = http_client
    else:
        jwt_secret_env = (env or os.environ).get("AGENTFORGE_JWT_SECRET", "").strip() or None
        http = HTTPTargetClient(jwt_secret=jwt_secret_env)
    eng: Engine = engine if engine is not None else create_platform_engine()
    rng_instance: random.Random = rng if rng is not None else random.Random()

    # Load policy and target URL up front so misconfiguration raises before
    # we attempt graph compilation.
    policy = load_policy(policy_path)

    # Operator-supplied per-session cap (from API ``cost_cap_cents`` /
    # CLI ``--cost-cap-cents``) takes precedence over the policy YAML's
    # max_session_cost_cents — the operator's intent for THIS session is
    # the authoritative ceiling. The policy value remains a hard upper
    # bound: ``min()`` ensures an operator can't bypass it by passing a
    # huge cap. Without this override, the orchestrator's budget gate
    # silently ignored the operator's cap and only enforced the policy's
    # default ($10), letting an "8¢ session" run far past 8¢.
    if cost_cap_cents_override is not None:
        effective_cap = min(cost_cap_cents_override, policy.max_session_cost_cents)
        policy = policy.model_copy(update={"max_session_cost_cents": effective_cap})

    targets = load_targets()
    if target_alias not in targets:
        raise ValueError(
            f"target alias {target_alias!r} not in targets.yaml; available: {sorted(targets)}"
        )
    target_url = targets[target_alias]

    # ----- Closures over injected dependencies. -----
    # We use plain async closures rather than functools.partial so the
    # node signature stays ``(state) -> PlatformState`` — LangGraph
    # introspects callables for their state parameter, and partials hide
    # that parameter behind a ``__wrapped__`` indirection that confuses
    # some traversals. Closures keep the signature plain and the captured
    # state explicit at the def site.

    async def _orchestrator_closure(state: PlatformState) -> PlatformState:
        return await orchestrator_node(
            state,
            engine=eng,
            llm=orch_llm,
            policy=policy,
            rng=rng_instance,
            langfuse=langfuse_client,
            allowed_categories=allowed_categories,
        )

    async def _red_team_closure(state: PlatformState) -> PlatformState:
        return await red_team_node(
            state,
            engine=eng,
            llm=rt_llm,
            http=http,
            target_url=target_url,
            langfuse=langfuse_client,
        )

    async def _judge_closure(state: PlatformState) -> PlatformState:
        return await judge_node(
            state,
            engine=eng,
            llm=judge_llm,
            langfuse=langfuse_client,
        )

    async def _regression_closure(state: PlatformState) -> PlatformState:
        """Dispatched when the orchestrator halts with ``regression_due``.

        Reads the session's ``target_sha`` from ``run_manifests`` (the
        operator's session runner inserts that row up front before the
        graph starts), invokes :func:`run_regression_session` against
        the new SHA, escalates any P0/P1 regressions onto the
        ``human_approval_queue``, and clears ``halt_reason`` so the
        orchestrator re-evaluates on the next pass. The cleared
        ``halt_reason`` is the load-bearing contract: without it the
        orchestrator's "existing halt wins" rule would route us
        straight back to regression and we'd spin.

        Defensive guard: if invoked with a non-regression
        ``halt_reason`` (which should never happen given the router
        above), return state untouched. Belt-and-braces in case a
        future edit pulls regression_due into another decision path.
        """
        if state.halt_reason != "regression_due":
            return state
        with eng.connect() as conn:
            row = conn.execute(
                text("SELECT target_sha FROM run_manifests WHERE session_id = :sid"),
                {"sid": state.session_id},
            ).first()
        new_sha = row[0] if row else "unknown"
        summary = await run_regression_session(
            new_target_sha=new_sha,
            engine=eng,
            http=http,
            llm_for_judge=judge_llm,
            langfuse=langfuse_client,
        )
        _escalate_regressed_to_queue(eng, summary, session_id=state.session_id)
        # Clear halt_reason so the next orchestrator pass re-evaluates.
        return state.model_copy(update={"halt_reason": None})

    async def _documentation_closure(state: PlatformState) -> PlatformState:
        # Pick frameworks at runtime from the campaign's category so a
        # mid-run category switch (e.g. orchestrator picks tool-misuse
        # after a prompt-injection-indirect campaign) lands on the right
        # triple. ``current_campaign`` must be set — the graph routes us
        # to this node only after the orchestrator picks one.
        if state.current_campaign is None:
            raise RuntimeError("documentation_node invoked without current_campaign")
        frameworks = _FRAMEWORK_BY_CATEGORY.get(
            state.current_campaign.category, _UNKNOWN_FRAMEWORKS
        )
        return await documentation_node(
            state,
            engine=eng,
            llm=doc_llm,
            gitlab=documentation_client,
            frameworks=frameworks,
            langfuse=langfuse_client,
        )

    # ----- Build graph with the same topology as graph.py. -----
    g: Any = StateGraph(PlatformState)
    g.add_node(NODE_ORCHESTRATOR, _orchestrator_closure)
    g.add_node(NODE_RED_TEAM, _red_team_closure)
    g.add_node(NODE_JUDGE, _judge_closure)
    g.add_node(NODE_DOCUMENTATION, _documentation_closure)
    g.add_node(NODE_REGRESSION, _regression_closure)

    g.add_edge(START, NODE_ORCHESTRATOR)
    g.add_conditional_edges(
        NODE_ORCHESTRATOR,
        _orchestrator_routes,
        {
            "halt": END,
            "regression": NODE_REGRESSION,
            "continue": NODE_RED_TEAM,
        },
    )
    g.add_edge(NODE_RED_TEAM, NODE_JUDGE)
    g.add_conditional_edges(
        NODE_JUDGE,
        _verdict_routes,
        {"to_doc": NODE_DOCUMENTATION, "skip_doc": NODE_ORCHESTRATOR},
    )
    g.add_edge(NODE_DOCUMENTATION, NODE_ORCHESTRATOR)
    g.add_edge(NODE_REGRESSION, NODE_ORCHESTRATOR)

    config = ProductionGraphConfig(
        has_openai=openai_client is not None,
        has_anthropic=anthropic_client is not None,
        has_gitlab=_is_real_gitlab(documentation_client),
        has_langfuse=_is_real_langfuse(langfuse_client),
        target_url=target_url,
        policy=policy,
    )
    compiled: Any = g.compile()
    return compiled, config
