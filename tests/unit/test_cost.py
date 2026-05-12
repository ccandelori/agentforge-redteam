"""Unit tests for :mod:`agentforge_redteam.cost`.

The cost module is the single source of truth for converting (prompt,
completion, model) tuples into integer cents for the platform's session
budget gate. Tests are written vertical-slice TDD: each name reads like a
spec line auditable against the PRD's cost-cap requirement.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

import pytest

from agentforge_redteam.cost import (
    PRICING_TABLE,
    UnknownModelError,
    estimate_cost_cents,
    estimate_tokens,
    make_cost_estimator,
)


@dataclass
class _FakeResp:
    """Stand-in for the agents' LLMResponse dataclasses.

    Mirrors the two attributes the estimator cares about — ``text`` and
    ``cost_cents`` — without depending on any agent module.
    """

    text: str = ""
    cost_cents: int = 0


# --- estimate_tokens: heuristic ceiling-divides chars by 4 -------------------


def test_estimate_tokens_empty_string_is_zero() -> None:
    assert estimate_tokens("") == 0


def test_estimate_tokens_single_char_rounds_up_to_one_token() -> None:
    assert estimate_tokens("a") == 1


def test_estimate_tokens_four_chars_is_one_token() -> None:
    assert estimate_tokens("abcd") == 1


def test_estimate_tokens_five_chars_ceils_to_two_tokens() -> None:
    assert estimate_tokens("abcde") == 2


def test_estimate_tokens_four_thousand_chars_is_one_thousand_tokens() -> None:
    assert estimate_tokens("a" * 4000) == 1000


# --- estimate_cost_cents: known-good math -----------------------------------


def test_estimate_cost_cents_small_input_is_small_positive_int() -> None:
    # 2 chars prompt / 2 chars completion -> 1 token each.
    # gpt-4o: (1/1_000_000)*$2.50 + (1/1_000_000)*$10.00 = $0.0000125
    # In cents: 0.00125 -> ROUND_CEILING -> 1 cent.
    cents = estimate_cost_cents("gpt-4o", prompt_text="hi", completion_text="hi")
    assert isinstance(cents, int)
    assert cents == 1


def test_estimate_cost_cents_empty_strings_returns_zero() -> None:
    assert estimate_cost_cents("gpt-4o", prompt_text="", completion_text="") == 0


def test_estimate_cost_cents_rounds_up_via_round_ceiling() -> None:
    # gpt-4o-mini @ $0.15/1M prompt + $0.60/1M completion. With 1 token each:
    # cost_usd = 1/1M*0.15 + 1/1M*0.60 = 7.5e-7 dollars = 7.5e-5 cents.
    # ROUND_CEILING must lift this to 1 cent, not floor it to 0.
    cents = estimate_cost_cents("gpt-4o-mini", prompt_text="hi", completion_text="hi")
    assert cents == 1


def test_estimate_cost_cents_scales_linearly_with_prompt_size() -> None:
    # Use a big enough payload that rounding noise is dominated by the
    # actual scaling — 40k chars = 10k tokens.
    base = estimate_cost_cents(
        "gpt-4o",
        prompt_text="a" * 40_000,
        completion_text="b" * 40_000,
    )
    doubled = estimate_cost_cents(
        "gpt-4o",
        prompt_text="a" * 80_000,
        completion_text="b" * 80_000,
    )
    # Allow a 1-cent tolerance for ROUND_CEILING boundary effects.
    assert abs(doubled - 2 * base) <= 1
    assert doubled > base


def test_estimate_cost_cents_unknown_model_raises_unknown_model_error() -> None:
    with pytest.raises(UnknownModelError):
        estimate_cost_cents("not-a-real-model", prompt_text="hi", completion_text="hi")


def test_unknown_model_error_is_catchable_as_keyerror() -> None:
    # Existing ``except KeyError`` handlers must keep working.
    with pytest.raises(KeyError):
        estimate_cost_cents("still-not-real", prompt_text="hi", completion_text="hi")


# --- make_cost_estimator: closure factory -----------------------------------


def test_make_cost_estimator_returns_callable_that_prices_text_responses() -> None:
    estimator = make_cost_estimator("gpt-4o", prompt_text="hello world")
    cents = estimator(_FakeResp(text="response text from model"))
    assert isinstance(cents, int)
    assert cents > 0


def test_make_cost_estimator_prefers_sdk_cost_cents_when_nonzero() -> None:
    estimator = make_cost_estimator("gpt-4o", prompt_text="hello world")
    # A response with a large body but a tiny SDK-reported cost should return
    # the SDK value, not the text-based estimate.
    cents = estimator(_FakeResp(text="x" * 10_000, cost_cents=42))
    assert cents == 42


def test_make_cost_estimator_falls_through_to_text_estimate_when_cost_zero() -> None:
    estimator = make_cost_estimator("gpt-4o", prompt_text="hello world")
    cents = estimator(_FakeResp(text="x" * 10_000, cost_cents=0))
    # With 10k chars of completion the text estimate must be positive.
    assert cents > 0


def test_make_cost_estimator_returns_zero_when_result_has_no_text() -> None:
    estimator = make_cost_estimator("gpt-4o", prompt_text="hello world")

    @dataclass
    class _Bare:
        """A tool result that's neither an LLMResponse nor cost-bearing."""

        value: int = 1

    assert estimator(_Bare()) == 0


def test_make_cost_estimator_rejects_unknown_model_eagerly() -> None:
    # Validation happens at factory time, not call time, so misconfiguration
    # surfaces at agent wiring rather than mid-campaign.
    with pytest.raises(UnknownModelError):
        make_cost_estimator("not-a-real-model", prompt_text="hi")


# --- Pricing table presence checks ------------------------------------------


@pytest.mark.parametrize(
    "model",
    [
        "gpt-4o-2024-08-06",
        "claude-sonnet-4-20250514",
        "claude-haiku-4-5-20251001",
        "openrouter/auto",
    ],
)
def test_pricing_table_has_entry_for_production_model(model: str) -> None:
    """All four production-config models must be priced."""
    assert model in PRICING_TABLE
    pricing = PRICING_TABLE[model]
    assert pricing.prompt_per_1m > Decimal("0")
    assert pricing.completion_per_1m > Decimal("0")
