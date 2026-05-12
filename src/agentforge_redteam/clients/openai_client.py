"""Real OpenAI Chat Completions client adapter.

This module is the seam between AgentForge Red Team and the ``openai``
Python SDK. The rest of the platform depends only on the
:class:`LLMClientLike` Protocol declared on each agent module — for the
Red Team agent that is
``async def complete(*, system: str, user: str, model: str) -> LLMResponse``
where ``LLMResponse`` is a ``(text: str, cost_cents: int)`` value object.
The :class:`OpenAIClient` defined here structurally satisfies that
Protocol and can be passed wherever an ``LLMClientLike`` is expected.

Design constraints (mirrors :mod:`agentforge_redteam.clients.anthropic_client`):

* **The ``openai`` SDK is imported lazily inside
  :meth:`OpenAIClient.__init__`.** A fresh checkout with no API key
  must still import this module cheaply, and the SDK pulls in a
  non-trivial HTTP/TLS dependency tree. The :class:`OpenAIConfig` value
  object stays pure-Python so callers can introspect / construct it
  without paying the SDK import cost.

* **The factory never raises on a missing key.** Dev, test, and offline
  CI lanes all run without an OpenAI API key. Returning ``None`` lets
  the caller (typically the agent's wiring code) decide whether to swap
  in a stub client or hard-fail.

* **Cost computation is soft.** When the platform's pricing table (in
  :mod:`agentforge_redteam.cost`) is available we delegate cost
  arithmetic to it; otherwise we return ``cost_cents=0`` and let the
  agent's wrapper ``cost_estimator`` fill in. This keeps the adapter
  decoupled from a strict cost-module dependency.

* **Empty ``choices`` tolerance.** The SDK can return zero choices on
  refusals or content-filter trips. We surface ``text=""`` rather than
  indexing into ``[0]`` so the agent's JSON parser produces the loud,
  greppable error rather than an :class:`IndexError` from inside the
  adapter.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Final

import structlog

# Reuse the canonical LLMResponse shape from the Red Team agent so this
# adapter satisfies ``red_team.LLMClientLike`` without indirection.
from agentforge_redteam.agents.red_team import LLMResponse as RTLLMResponse

__all__ = [
    "DEFAULT_TIMEOUT_S",
    "OPENAI_API_KEY_ENV",
    "OPENAI_ORG_ENV",
    "OpenAIClient",
    "OpenAIConfig",
    "RTLLMResponse",
    "create_openai_client",
]

_log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OPENAI_API_KEY_ENV: Final[str] = "OPENAI_API_KEY"
OPENAI_ORG_ENV: Final[str] = "OPENAI_ORG"

DEFAULT_TIMEOUT_S: Final[float] = 60.0
"""Default HTTP timeout for a single Chat Completions API call.

The OpenAI SDK's own default is generous and would let a stuck call
hold a campaign open past the cost cap's window. 60s is enough for a
GPT-4o completion at ~4k output tokens; anything longer is a stall
worth surfacing as a timeout, not a long-poll.
"""


# ---------------------------------------------------------------------------
# Config value object
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class OpenAIConfig:
    """Validated OpenAI credentials, ready to hand to the SDK.

    Construction is via :meth:`from_env` rather than the default
    dataclass init so the "missing key -> None" path is centralised and
    reasoning about partial config doesn't leak into call sites.
    """

    api_key: str
    organization: str | None = None

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> OpenAIConfig | None:
        """Return a config iff :data:`OPENAI_API_KEY_ENV` is set.

        Reads from ``env`` (for testability) or :data:`os.environ` when
        not provided. An empty- or whitespace-only key is treated as
        missing — ``.env`` files with a key declared but left blank
        should not construct a real client.

        The optional :data:`OPENAI_ORG_ENV` value, when present and
        non-empty, is carried through so an organisation header is sent
        with each request.
        """
        source: dict[str, str] = dict(os.environ) if env is None else env
        key = source.get(OPENAI_API_KEY_ENV, "").strip()
        if not key:
            return None
        org_raw = source.get(OPENAI_ORG_ENV, "").strip()
        organization = org_raw or None
        return cls(api_key=key, organization=organization)


# ---------------------------------------------------------------------------
# Real client (wraps the OpenAI SDK)
# ---------------------------------------------------------------------------


class OpenAIClient:
    """OpenAI-backed implementation of the Red Team agent's LLMClientLike Protocol.

    Wraps :class:`openai.AsyncOpenAI` so the rest of the platform depends
    only on the Protocol surface declared on each agent. The SDK is
    imported lazily inside :meth:`__init__` so a module-level
    ``import agentforge_redteam.clients.openai_client`` does not pull in
    the ``openai`` package (which itself depends on ``httpx``, TLS
    roots, etc.) when the platform is running without an API key.
    """

    __slots__ = ("_client",)

    def __init__(
        self,
        *,
        api_key: str,
        organization: str | None = None,
        timeout_s: float = DEFAULT_TIMEOUT_S,
    ) -> None:
        # Lazy import keeps fresh checkouts cheap. The SDK's import-time
        # cost is non-trivial (TLS, HTTP, retry machinery) and we don't
        # want it on the critical path for offline lanes.
        from openai import AsyncOpenAI

        # The OpenAI SDK accepts ``organization`` as an optional kwarg.
        # Only forward it when set — passing ``None`` is also accepted by
        # the current SDK but keeping the keyword absent makes the test
        # assertions clearer and avoids surprising future SDK behavior.
        init_kwargs: dict[str, Any] = {
            "api_key": api_key,
            "timeout": timeout_s,
        }
        if organization is not None:
            init_kwargs["organization"] = organization

        # We hold the client as ``Any`` so this module only depends on
        # the SDK's public construction surface — not on whichever
        # version happens to be pinned.
        self._client: Any = AsyncOpenAI(**init_kwargs)

    async def complete(self, *, system: str, user: str, model: str) -> RTLLMResponse:
        """Call ``client.chat.completions.create`` and adapt to :class:`RTLLMResponse`.

        Behavior notes:

        * The Chat Completions API takes both the system instruction
          and the user turn as messages in the ``messages`` list. We
          synthesize the canonical two-message shape:
          ``[{"role": "system", ...}, {"role": "user", ...}]``.
        * The first choice's ``message.content`` is returned as
          ``text``. If the SDK returns an empty ``choices`` array (rare
          but observable on refusal / policy turns), we return
          ``text=""`` rather than raising :class:`IndexError`.
        * ``cost_cents`` is computed via
          :func:`agentforge_redteam.cost.estimate_cost_cents` when the
          ``cost`` module is importable AND the model has a pricing
          entry; otherwise ``0``. The agent's audit-wrapper
          ``cost_estimator`` is the primary cost source, so a soft
          fallback here keeps the adapter resilient to new model names
          and to early-bootstrap orderings.
        """
        response = await self._client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )

        text = _extract_first_choice_text(response)
        cost_cents = _compute_cost_cents(
            model=model,
            system=system,
            user=user,
            completion_text=text,
        )

        return RTLLMResponse(text=text, cost_cents=cost_cents)


# ---------------------------------------------------------------------------
# Helpers (private — not part of the public surface)
# ---------------------------------------------------------------------------


def _extract_first_choice_text(response: Any) -> str:
    """Return the first choice's ``message.content``, or ``""``.

    The Chat Completions SDK returns a ``ChatCompletion`` whose
    ``choices`` is a list of ``Choice`` objects each with a ``message``.
    For ordinary completions there is exactly one text choice; on
    refusals / content-filter trips the list may be empty.

    We additionally tolerate ``message.content`` being ``None`` (which
    the SDK uses for tool-calling turns where the assistant emits
    ``tool_calls`` instead of free text), returning ``""`` in that case.
    """
    choices = getattr(response, "choices", None)
    if not choices:
        return ""
    first = choices[0]
    message = getattr(first, "message", None)
    if message is None:
        return ""
    content = getattr(message, "content", None)
    if isinstance(content, str):
        return content
    return ""


def _compute_cost_cents(
    *,
    model: str,
    system: str,
    user: str,
    completion_text: str,
) -> int:
    """Best-effort cost computation via :mod:`agentforge_redteam.cost`.

    Returns 0 when:

    * ``agentforge_redteam.cost`` cannot be imported (early-bootstrap,
      ahead of Task 38), OR
    * the model is not in :data:`PRICING_TABLE` (an
      :class:`UnknownModelError` would be raised by the cost module —
      we swallow it here because the call-site ``cost_estimator`` is
      the canonical cost path and will raise the same error there).

    The audit wrapper's ``cost_estimator`` prefers a positive
    ``cost_cents`` from the result, so returning a non-zero value here
    short-circuits the wrapper's chars-per-token estimation. That is
    desirable when we trust the SDK's pricing-table-keyed cost (we do
    — it's the same heuristic the wrapper would use).
    """
    try:
        from agentforge_redteam.cost import (
            UnknownModelError,
            estimate_cost_cents,
        )
    except ImportError:
        return 0

    try:
        return estimate_cost_cents(
            model,
            prompt_text=system + user,
            completion_text=completion_text,
        )
    except UnknownModelError:
        # Unknown model: defer to the wrapper's cost_estimator, which
        # raises the same error at a more useful frame.
        _log.debug(
            "openai_client.unknown_model_for_cost",
            model=model,
        )
        return 0


# ---------------------------------------------------------------------------
# Public factory
# ---------------------------------------------------------------------------


def create_openai_client(
    env: dict[str, str] | None = None,
    *,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> OpenAIClient | None:
    """Return a real :class:`OpenAIClient` if a key is set; else ``None``.

    The agents accept a :class:`Protocol`-typed client; a ``None`` return
    lets the caller swap in a stub for offline / test lanes without this
    module owning that policy. Unlike the Langfuse factory there is no
    "no-op" fallback — an LLM call with no key is a hard error, not a
    silent skip.

    The optional ``env`` parameter makes the factory deterministic in
    tests: pass a dict to control which keys are visible, rather than
    monkeypatching :data:`os.environ`.
    """
    config = OpenAIConfig.from_env(env)
    if config is None:
        return None
    return OpenAIClient(
        api_key=config.api_key,
        organization=config.organization,
        timeout_s=timeout_s,
    )
