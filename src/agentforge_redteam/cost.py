"""Cost-estimation primitive for the audited tool wrapper.

The :func:`make_cost_estimator` factory produces a callable that drops into
:func:`agentforge_redteam.tools.wrapper.call_tool`'s ``cost_estimator``
parameter. The factory pre-binds ``model`` and ``prompt_text`` so that the
caller-site reads cleanly::

    await call_tool(
        ...,
        cost_estimator=make_cost_estimator(model="gpt-4o", prompt_text=system + user),
    )

When the underlying LLM SDK exposes accurate usage data on its response
object (i.e. ``LLMResponse.cost_cents > 0``), the estimator prefers that.
Otherwise it falls through to text-based estimation using the model's entry
in :data:`PRICING_TABLE`.

Design choices worth flagging:

* **Decimal arithmetic.** All math goes through :class:`decimal.Decimal` so
  per-call cents never drift on summed float error. The platform's budget
  cap is a hard halt condition; a 0.001 cent leak per call adds up.
* **Round up at the cent boundary.** We quantize with
  :data:`decimal.ROUND_CEILING`. The cost cap is a budget gate; rounding up
  is the conservative direction (we'd rather halt slightly early than blow
  past the cap by a half-cent each call).
* **No tiktoken dependency.** For the platform's scale (<= 100k tokens per
  session) a 4-chars-per-token heuristic is within ~15% of the real BPE
  count, well inside the precision the cost gate needs. The dep is opt-in
  via the function signature — :func:`estimate_tokens` is the single
  source of truth and is swappable.
* **Loud-fail on unknown model.** A typo'd model name silently zeroing out
  cost accounting would be much worse than an exception at startup.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from decimal import ROUND_CEILING, Decimal
from typing import Any, Final


@dataclass(frozen=True, slots=True)
class ModelPricing:
    """USD cost per 1M tokens for one model. Pricing as of 2026-05-11."""

    prompt_per_1m: Decimal
    """Price in USD per 1,000,000 input (prompt) tokens."""

    completion_per_1m: Decimal
    """Price in USD per 1,000,000 output (completion) tokens."""


# Authoritative pricing table. Use Decimal to avoid float drift on per-call
# cents. Sources: each provider's pricing page. Values are USD per 1M tokens.
PRICING_TABLE: Final[dict[str, ModelPricing]] = {
    # OpenAI
    "gpt-4o-2024-08-06": ModelPricing(Decimal("2.50"), Decimal("10.00")),
    "gpt-4o": ModelPricing(Decimal("2.50"), Decimal("10.00")),
    "gpt-4o-mini": ModelPricing(Decimal("0.15"), Decimal("0.60")),
    # Anthropic
    "claude-sonnet-4-20250514": ModelPricing(Decimal("3.00"), Decimal("15.00")),
    "claude-haiku-4-5-20251001": ModelPricing(Decimal("1.00"), Decimal("5.00")),
    # OpenRouter fallback — use a conservative price (the real one varies)
    "openrouter/auto": ModelPricing(Decimal("3.00"), Decimal("15.00")),
}


class UnknownModelError(KeyError):
    """Raised by :func:`estimate_cost_cents` / :func:`make_cost_estimator`
    when the supplied model name is not present in :data:`PRICING_TABLE`.

    Inherits from :class:`KeyError` so existing ``except KeyError`` branches
    keep working, but the dedicated subclass makes the failure greppable in
    logs and lets callers narrow their handling. Loud-failing here is
    deliberate — a typo'd model would otherwise silently zero out the cost
    accounting and disable the session-level budget cap.
    """


# Single source of truth for the chars-per-token assumption. Make it swappable
# without touching the cost arithmetic.
_CHARS_PER_TOKEN: Final[int] = 4


def estimate_tokens(text: str) -> int:
    """Approximate token count via a chars-per-token heuristic.

    The PRD references tiktoken; we deliberately avoid the dep. For cost
    accounting at this platform's scale (<= 100k tokens / session) the
    4-chars-per-token approximation is within ~15% of the real BPE count,
    well inside the precision the cost cap needs. If tighter accounting is
    ever required, swap this function for a real tokenizer behind the same
    signature — the rest of the module is agnostic.
    """
    if not text:
        return 0
    # Ceiling division: even a single character costs at least one token.
    return (len(text) + _CHARS_PER_TOKEN - 1) // _CHARS_PER_TOKEN


def _lookup_pricing(model: str) -> ModelPricing:
    """Resolve ``model`` against :data:`PRICING_TABLE` or raise."""
    try:
        return PRICING_TABLE[model]
    except KeyError as exc:
        raise UnknownModelError(
            f"No pricing entry for model {model!r}. Add it to PRICING_TABLE."
        ) from exc


def estimate_cost_cents(model: str, *, prompt_text: str, completion_text: str) -> int:
    """Return integer cents for one ``(prompt, completion)`` pair.

    The computation, in USD::

        cost_usd = (prompt_tokens     / 1_000_000) * pricing.prompt_per_1m
                 + (completion_tokens / 1_000_000) * pricing.completion_per_1m

    Then converted to integer cents via :data:`decimal.ROUND_CEILING` so the
    cost cap stays conservative — a half-cent always rounds up, not down.

    Raises :class:`UnknownModelError` (a :class:`KeyError` subclass) if
    ``model`` is not present in :data:`PRICING_TABLE`.
    """
    pricing = _lookup_pricing(model)

    prompt_tokens = Decimal(estimate_tokens(prompt_text))
    completion_tokens = Decimal(estimate_tokens(completion_text))
    one_million = Decimal("1000000")

    cost_usd = (prompt_tokens / one_million) * pricing.prompt_per_1m + (
        completion_tokens / one_million
    ) * pricing.completion_per_1m

    # Convert USD -> cents and round UP to the nearest integer cent.
    cents = (cost_usd * Decimal("100")).quantize(Decimal("1"), rounding=ROUND_CEILING)
    return int(cents)


def make_cost_estimator(model: str, *, prompt_text: str) -> Callable[[Any], int]:
    """Produce a callable suitable for :func:`call_tool`'s ``cost_estimator``.

    The returned callable accepts the tool's return value (typically one of
    the agents' ``LLMResponse`` dataclasses, which expose ``.text`` and
    ``.cost_cents``) and returns integer cents using ``model``'s entry in
    :data:`PRICING_TABLE`.

    Behavior:

    * If the result exposes ``.cost_cents`` and that value is ``> 0``, prefer
      it. The provider SDK's own usage data (when present) is more accurate
      than our chars-per-token heuristic.
    * Otherwise, if the result exposes ``.text``, compute via
      :func:`estimate_cost_cents` using ``prompt_text`` (closed over) as the
      prompt side and ``result.text`` as the completion side.
    * Otherwise, return ``0``. A tool that produces neither attribute is not
      an LLM call and has no token-priced cost.

    This factory raises :class:`UnknownModelError` eagerly (at factory time,
    not call time) so misconfiguration surfaces at agent start-up rather
    than partway through a campaign.
    """
    # Eagerly validate the model so misconfiguration fails loudly at the
    # call-site that wired the agent, not inside the wrapper's try block.
    _lookup_pricing(model)

    def _estimator(result: Any) -> int:
        sdk_cost = getattr(result, "cost_cents", None)
        if isinstance(sdk_cost, int) and sdk_cost > 0:
            return sdk_cost

        completion_text = getattr(result, "text", None)
        if not isinstance(completion_text, str):
            return 0

        return estimate_cost_cents(model, prompt_text=prompt_text, completion_text=completion_text)

    return _estimator
