"""Real Anthropic Messages API client adapter.

This module is the single seam between AgentForge Red Team and the
``anthropic`` Python SDK. The rest of the platform depends only on the
:class:`LLMClientLike` Protocols defined inside each agent module
(``documentation.LLMClientLike`` and ``judge.LLMClientLike`` are
structurally identical — both expose
``async def complete(*, system: str, user: str, model: str) -> LLMResponse``
where ``LLMResponse`` is a ``(text: str, cost_cents: int)`` value object).
The :class:`AnthropicClient` defined here satisfies both Protocols
structurally and can be passed wherever an ``LLMClientLike`` is expected.

Design constraints (load-bearing — keep stable):

* **The ``anthropic`` SDK is imported lazily inside
  :meth:`AnthropicClient.__init__`.** A fresh checkout with no API key
  must still import this module cheaply, and the SDK pulls in a non-trivial
  HTTP/TLS dependency tree. The :class:`AnthropicConfig` value object stays
  pure-Python so callers can introspect / construct it without paying the
  SDK import cost.

* **The factory never raises on a missing key.** Dev, test, and offline
  CI lanes all run without an Anthropic API key. Returning ``None`` lets
  the caller (typically the agent's wiring code) decide whether to swap
  in a stub client or hard-fail — this module does not own that policy.

* **Cost computation is soft.** When the platform's pricing table (in
  :mod:`agentforge_redteam.cost`) is available we use the call-site cost
  estimator pattern; otherwise we return ``cost_cents=0`` and let the
  agent's wrapper compute cost via :func:`make_cost_estimator`. This
  keeps the client decoupled from a strict cost-module dependency for
  edges (early Task 38 wiring, alternate model names, etc.).

* **Empty content-block tolerance.** The SDK occasionally returns an
  empty ``content`` array (typically on a refusal or a tool-use turn);
  we surface ``text=""`` rather than indexing into ``[0]`` and raising
  an :class:`IndexError` so the agent's JSON parser produces the loud,
  greppable error instead of a cryptic traceback from inside the
  adapter.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Final

import structlog

# Re-export the agents' LLMResponse type. We pick the documentation
# variant as canonical: both ``documentation.LLMResponse`` and
# ``judge.LLMResponse`` are ``@dataclass(frozen=True, slots=True)`` with
# fields ``(text: str, cost_cents: int)`` in that order, so a value
# constructed as :class:`DocLLMResponse` structurally satisfies callers
# typed against the Judge's variant too.
from agentforge_redteam.agents.documentation import LLMResponse as DocLLMResponse

__all__ = [
    "ANTHROPIC_API_KEY_ENV",
    "DEFAULT_TIMEOUT_S",
    "AnthropicClient",
    "AnthropicConfig",
    "DocLLMResponse",
    "create_anthropic_client",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ANTHROPIC_API_KEY_ENV: Final[str] = "ANTHROPIC_API_KEY"
DEFAULT_TIMEOUT_S: Final[float] = 60.0
"""Default HTTP timeout for a single Messages API call.

The Anthropic SDK's own default is generous (10 min) which is far too
long for our orchestrator — a stuck call would hold a campaign open
past the cost cap's window. 60s is enough for a Sonnet 4 completion at
~4k output tokens; anything longer is a stall worth surfacing as a
timeout, not a long-poll.
"""

# Max tokens for a single Messages API call. The SDK requires this
# parameter — there is no "unbounded" sentinel — so we centralise the
# default here. 4096 is enough for the Doc agent's JSON envelope; the
# Judge and Orchestrator agents pass their own values via the model
# kwarg if they need a different budget.
_DEFAULT_MAX_TOKENS: Final[int] = 4096

_logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Config value object
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AnthropicConfig:
    """Validated Anthropic credentials, ready to hand to the SDK.

    Construction is via :meth:`from_env` rather than the default
    dataclass init so the "missing key -> None" path is centralised
    and reasoning about partial config doesn't leak into call sites.
    """

    api_key: str

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> AnthropicConfig | None:
        """Return a config iff :data:`ANTHROPIC_API_KEY_ENV` is set.

        Reads from ``env`` (for testability) or :data:`os.environ` when
        not provided. An empty-string value is treated as missing —
        ``.env`` files with a key declared but left blank should not
        construct a real client.
        """
        source: dict[str, str] = dict(os.environ) if env is None else env
        key = source.get(ANTHROPIC_API_KEY_ENV, "").strip()
        if not key:
            return None
        return cls(api_key=key)


# ---------------------------------------------------------------------------
# Real client (wraps the Anthropic SDK)
# ---------------------------------------------------------------------------


class AnthropicClient:
    """Anthropic-backed implementation of the agents' LLMClientLike Protocol.

    Wraps :class:`anthropic.AsyncAnthropic` so the rest of the platform
    depends only on the Protocol surface declared on each agent. The SDK
    is imported lazily inside :meth:`__init__` so a module-level
    ``import agentforge_redteam.clients`` does not pull in the
    ``anthropic`` package (which itself depends on ``httpx``, TLS roots,
    etc.) when the platform is running without an API key.
    """

    __slots__ = ("_client",)

    def __init__(self, *, api_key: str, timeout_s: float = DEFAULT_TIMEOUT_S) -> None:
        # Lazy import keeps fresh checkouts cheap. The SDK's import-time
        # cost is non-trivial (TLS, HTTP, retry machinery) and we don't
        # want it on the critical path for offline lanes.
        from anthropic import AsyncAnthropic

        # We hold the client as ``Any`` so this module only depends on
        # the SDK's public construction surface — not on whichever
        # version happens to be pinned. The Anthropic SDK has shifted
        # method signatures across 0.x releases; pinning the attribute
        # type to ``Any`` keeps the seam narrow.
        self._client: Any = AsyncAnthropic(
            api_key=api_key,
            timeout=timeout_s,
        )

    async def complete(self, *, system: str, user: str, model: str) -> DocLLMResponse:
        """Call ``client.messages.create`` and adapt to :class:`DocLLMResponse`.

        Behavior notes:

        * The Anthropic Messages API takes ``system`` as a top-level
          parameter (not as a ``role: "system"`` message). We pass it as
          a single text block with ``cache_control={"type":"ephemeral"}``
          so the (large, static) system prompt is cached across calls
          within a 5-minute TTL — Anthropic charges 0.1x the input rate
          for cache reads and 1.25x for the one-time cache write. For
          the Judge (32 calls/session, ~750 system tokens) this cuts
          input cost by ~80% on cached calls and ~55% on Judge total.
          The Doc Agent and Orchestrator share the cache too; the
          marginal cost is one extra parameter object.
        * The ``user`` text goes in as the single user-role message.
        * The first text content block of the response is returned as
          ``text``. If the SDK returns an empty ``content`` array (rare
          but observable on refusal / tool-use turns), we return
          ``text=""`` rather than raising :class:`IndexError`.
        * ``cost_cents`` is computed from ``response.usage`` when the
          SDK exposes it (preferred — accounts for cache hits at
          0.1x rate and cache writes at 1.25x). Falls back to the
          chars-per-token estimator if usage info is missing.
        """
        response = await self._client.messages.create(
            model=model,
            max_tokens=_DEFAULT_MAX_TOKENS,
            system=[
                {
                    "type": "text",
                    "text": system,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=[{"role": "user", "content": user}],
        )

        text = _extract_first_text_block(response)
        usage = getattr(response, "usage", None)
        cost_cents = _compute_cost_cents(
            model=model,
            system=system,
            user=user,
            completion_text=text,
            usage=usage,
        )

        # Surface the cache breakdown so an operator (or
        # docs/EVIDENCE post-mortem) can see at a glance whether
        # caching is engaging. Without this, the only proof would be
        # the difference between two integer-cent cost columns —
        # which rounding hides at MVP scale.
        if usage is not None:
            _logger.info(
                "anthropic.usage",
                model=model,
                input_tokens=int(getattr(usage, "input_tokens", 0) or 0),
                cache_creation_input_tokens=int(
                    getattr(usage, "cache_creation_input_tokens", 0) or 0
                ),
                cache_read_input_tokens=int(getattr(usage, "cache_read_input_tokens", 0) or 0),
                output_tokens=int(getattr(usage, "output_tokens", 0) or 0),
                cost_cents=cost_cents,
            )

        return DocLLMResponse(text=text, cost_cents=cost_cents)


# ---------------------------------------------------------------------------
# Helpers (private — not part of the public surface)
# ---------------------------------------------------------------------------


def _extract_first_text_block(response: Any) -> str:
    """Return the first text content block's ``.text``, or ``""``.

    The Anthropic SDK returns a ``Message`` whose ``content`` is a list
    of content blocks. For ordinary completions there is exactly one
    text block; for tool-use or refusal turns there may be zero or more
    of other types. We pick the first block whose ``type`` is
    ``"text"`` (or whichever first block exposes a ``.text`` attribute,
    since some SDK versions don't stamp ``type`` on every block).
    """
    content = getattr(response, "content", None)
    if not content:
        return ""
    for block in content:
        block_type = getattr(block, "type", None)
        if block_type is None or block_type == "text":
            text = getattr(block, "text", None)
            if isinstance(text, str):
                return text
    return ""


def _compute_cost_cents(
    *,
    model: str,
    system: str,
    user: str,
    completion_text: str,
    usage: Any = None,
) -> int:
    """Cost computation. Uses ``response.usage`` when available, else
    falls back to chars-per-token estimation.

    When the SDK returns a usable ``usage`` object we account for prompt
    caching explicitly: cache-write tokens are billed at 1.25x the
    input rate, cache-read tokens at 0.1x, regular input at 1x, and
    output at the standard output rate. Returning 0 means either the
    cost module is unimportable or the model name is unknown in
    :data:`PRICING_TABLE`.
    """
    try:
        from decimal import ROUND_CEILING, Decimal

        from agentforge_redteam.cost import (
            PRICING_TABLE,
            UnknownModelError,
            estimate_cost_cents,
        )
    except ImportError:
        return 0

    if usage is not None and model in PRICING_TABLE:
        pricing = PRICING_TABLE[model]
        # Read whichever fields the SDK exposes. Anthropic's recent SDKs
        # publish ``input_tokens`` (uncached input),
        # ``cache_creation_input_tokens``, ``cache_read_input_tokens``,
        # and ``output_tokens``. Older SDKs may omit the cache fields —
        # they default to 0, so this path stays correct.
        raw_input = int(getattr(usage, "input_tokens", 0) or 0)
        cache_write = int(getattr(usage, "cache_creation_input_tokens", 0) or 0)
        cache_read = int(getattr(usage, "cache_read_input_tokens", 0) or 0)
        output = int(getattr(usage, "output_tokens", 0) or 0)
        if raw_input + cache_write + cache_read + output > 0:
            one_million = Decimal("1000000")
            # Anthropic's published cache pricing multipliers
            cache_write_multiplier = Decimal("1.25")
            cache_read_multiplier = Decimal("0.10")
            input_cost = (
                (Decimal(raw_input) / one_million) * pricing.prompt_per_1m
                + (Decimal(cache_write) / one_million)
                * pricing.prompt_per_1m
                * cache_write_multiplier
                + (Decimal(cache_read) / one_million)
                * pricing.prompt_per_1m
                * cache_read_multiplier
            )
            output_cost = (Decimal(output) / one_million) * pricing.completion_per_1m
            cents = ((input_cost + output_cost) * Decimal("100")).quantize(
                Decimal("1"), rounding=ROUND_CEILING
            )
            return int(cents)

    # Fallback: chars-per-token estimation. Conservative side
    # (over-reports vs the real bill when caching is active and usage
    # is unavailable). This branch fires for tests using SDK mocks that
    # don't populate ``usage``.
    try:
        return estimate_cost_cents(
            model,
            prompt_text=system + user,
            completion_text=completion_text,
        )
    except UnknownModelError:
        return 0


# ---------------------------------------------------------------------------
# Public factory
# ---------------------------------------------------------------------------


def create_anthropic_client(
    env: dict[str, str] | None = None,
    *,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> AnthropicClient | None:
    """Return a real :class:`AnthropicClient` if a key is set; else ``None``.

    The agents accept a :class:`Protocol`-typed client; a ``None`` return
    lets the caller swap in a stub for offline / test lanes without this
    module owning that policy. Unlike the Langfuse factory there is no
    "no-op" fallback — an LLM call with no key is a hard error, not a
    silent skip.

    The optional ``env`` parameter makes the factory deterministic in
    tests: pass a dict to control which keys are visible, rather than
    monkeypatching :data:`os.environ`.
    """
    config = AnthropicConfig.from_env(env)
    if config is None:
        return None
    return AnthropicClient(api_key=config.api_key, timeout_s=timeout_s)
