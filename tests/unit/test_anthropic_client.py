"""Tests for the Anthropic client factory + real-SDK adapter.

These tests are hermetic: the ``anthropic`` SDK is replaced in
``sys.modules`` with a tiny fake whenever a test instantiates the real
:class:`AnthropicClient`, so no network call ever fires. The factory's
"no key" branch needs no stubbing — it returns ``None`` without ever
reaching the SDK.
"""

from __future__ import annotations

import sys
import types
from typing import Any, ClassVar

import pytest

from agentforge_redteam.agents.documentation import LLMResponse as DocLLMResponse
from agentforge_redteam.clients.anthropic_client import (
    ANTHROPIC_API_KEY_ENV,
    DEFAULT_TIMEOUT_S,
    AnthropicClient,
    AnthropicConfig,
    create_anthropic_client,
)

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _FakeBlock:
    """Stand-in for one Anthropic content block."""

    def __init__(self, text: str, block_type: str = "text") -> None:
        self.text = text
        self.type = block_type


class _FakeUsage:
    def __init__(self, input_tokens: int, output_tokens: int) -> None:
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens


class _FakeMessage:
    """Stand-in for an Anthropic ``Message`` object."""

    def __init__(
        self,
        *,
        content: list[_FakeBlock] | None = None,
        input_tokens: int = 10,
        output_tokens: int = 20,
    ) -> None:
        self.content: list[_FakeBlock] = (
            content if content is not None else [_FakeBlock(text="fake response")]
        )
        self.usage = _FakeUsage(input_tokens=input_tokens, output_tokens=output_tokens)


class _FakeMessages:
    """Stand-in for ``client.messages``."""

    def __init__(self, parent: _FakeAsyncAnthropic) -> None:
        self._parent = parent

    async def create(self, **kwargs: Any) -> _FakeMessage:
        self._parent.create_calls.append(kwargs)
        return self._parent.next_response


class _FakeAsyncAnthropic:
    """Stand-in for ``anthropic.AsyncAnthropic``."""

    last_constructed: ClassVar[_FakeAsyncAnthropic | None] = None

    def __init__(self, **kwargs: Any) -> None:
        self.init_kwargs = kwargs
        self.create_calls: list[dict[str, Any]] = []
        self.next_response: _FakeMessage = _FakeMessage()
        self.messages = _FakeMessages(self)
        _FakeAsyncAnthropic.last_constructed = self


@pytest.fixture
def fake_anthropic_module(monkeypatch: pytest.MonkeyPatch) -> type[_FakeAsyncAnthropic]:
    """Install a fake ``anthropic`` module in :data:`sys.modules`."""
    fake_mod = types.ModuleType("anthropic")
    fake_mod.AsyncAnthropic = _FakeAsyncAnthropic  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "anthropic", fake_mod)
    _FakeAsyncAnthropic.last_constructed = None
    return _FakeAsyncAnthropic


# ---------------------------------------------------------------------------
# AnthropicConfig.from_env
# ---------------------------------------------------------------------------


def test_from_env_returns_config_when_key_set() -> None:
    cfg = AnthropicConfig.from_env({ANTHROPIC_API_KEY_ENV: "sk-test-1"})
    assert cfg is not None
    assert cfg.api_key == "sk-test-1"


def test_from_env_returns_none_when_empty() -> None:
    assert AnthropicConfig.from_env({}) is None


def test_from_env_treats_empty_string_key_as_missing() -> None:
    assert AnthropicConfig.from_env({ANTHROPIC_API_KEY_ENV: ""}) is None
    assert AnthropicConfig.from_env({ANTHROPIC_API_KEY_ENV: "   "}) is None


def test_from_env_falls_back_to_os_environ_when_env_is_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(ANTHROPIC_API_KEY_ENV, "sk-from-os")
    cfg = AnthropicConfig.from_env(None)
    assert cfg is not None
    assert cfg.api_key == "sk-from-os"


# ---------------------------------------------------------------------------
# create_anthropic_client — None branch
# ---------------------------------------------------------------------------


def test_create_returns_none_when_env_empty() -> None:
    assert create_anthropic_client(env={}) is None


def test_create_returns_none_when_key_empty_string() -> None:
    assert create_anthropic_client(env={ANTHROPIC_API_KEY_ENV: ""}) is None


# ---------------------------------------------------------------------------
# create_anthropic_client — Real branch (under fake SDK)
# ---------------------------------------------------------------------------


def test_create_returns_real_client_when_key_present(
    fake_anthropic_module: type[_FakeAsyncAnthropic],
) -> None:
    client = create_anthropic_client(env={ANTHROPIC_API_KEY_ENV: "sk-test"})
    assert isinstance(client, AnthropicClient)
    last = fake_anthropic_module.last_constructed
    assert last is not None
    assert last.init_kwargs["api_key"] == "sk-test"
    # Default timeout forwarded.
    assert last.init_kwargs["timeout"] == DEFAULT_TIMEOUT_S


def test_create_forwards_custom_timeout(
    fake_anthropic_module: type[_FakeAsyncAnthropic],
) -> None:
    create_anthropic_client(env={ANTHROPIC_API_KEY_ENV: "sk-test"}, timeout_s=5.0)
    last = fake_anthropic_module.last_constructed
    assert last is not None
    assert last.init_kwargs["timeout"] == 5.0


def test_anthropic_client_honors_timeout_s_parameter(
    fake_anthropic_module: type[_FakeAsyncAnthropic],
) -> None:
    AnthropicClient(api_key="sk-test", timeout_s=12.5)
    last = fake_anthropic_module.last_constructed
    assert last is not None
    assert last.init_kwargs["timeout"] == 12.5


# ---------------------------------------------------------------------------
# AnthropicClient.complete — request shape
# ---------------------------------------------------------------------------


async def test_complete_calls_sdk_with_system_user_and_model(
    fake_anthropic_module: type[_FakeAsyncAnthropic],
) -> None:
    client = AnthropicClient(api_key="sk-test")
    last = fake_anthropic_module.last_constructed
    assert last is not None

    await client.complete(
        system="you are an auditor",
        user="grade this output",
        model="claude-sonnet-4-20250514",
    )

    assert len(last.create_calls) == 1
    call = last.create_calls[0]
    assert call["model"] == "claude-sonnet-4-20250514"
    assert call["system"] == "you are an auditor"
    assert call["messages"] == [{"role": "user", "content": "grade this output"}]
    # Always provides a max_tokens (SDK requires it).
    assert isinstance(call["max_tokens"], int)
    assert call["max_tokens"] > 0


# ---------------------------------------------------------------------------
# AnthropicClient.complete — response shape
# ---------------------------------------------------------------------------


async def test_complete_returns_doc_llm_response_with_first_text_block(
    fake_anthropic_module: type[_FakeAsyncAnthropic],
) -> None:
    client = AnthropicClient(api_key="sk-test")
    last = fake_anthropic_module.last_constructed
    assert last is not None
    last.next_response = _FakeMessage(
        content=[_FakeBlock(text="hello world"), _FakeBlock(text="ignored")]
    )

    result = await client.complete(system="s", user="u", model="claude-sonnet-4-20250514")
    assert isinstance(result, DocLLMResponse)
    assert result.text == "hello world"


async def test_complete_returns_empty_text_when_content_is_empty(
    fake_anthropic_module: type[_FakeAsyncAnthropic],
) -> None:
    client = AnthropicClient(api_key="sk-test")
    last = fake_anthropic_module.last_constructed
    assert last is not None
    last.next_response = _FakeMessage(content=[])

    result = await client.complete(system="s", user="u", model="claude-sonnet-4-20250514")
    assert result.text == ""
    # cost_cents is still an int — the dataclass enforces that — but for
    # an empty completion against a known model it should be the cost
    # of the prompt-side tokens only (>= 0).
    assert isinstance(result.cost_cents, int)
    assert result.cost_cents >= 0


async def test_complete_skips_non_text_blocks(
    fake_anthropic_module: type[_FakeAsyncAnthropic],
) -> None:
    client = AnthropicClient(api_key="sk-test")
    last = fake_anthropic_module.last_constructed
    assert last is not None
    # First block is tool_use (no .text); second is text — we should
    # fall through to the text block.
    tool_block = _FakeBlock(text="should-not-leak", block_type="tool_use")
    # Strip the .text attr to simulate a block type that doesn't carry
    # text content at all.
    del tool_block.text
    last.next_response = _FakeMessage(
        content=[tool_block, _FakeBlock(text="real reply", block_type="text")]
    )

    result = await client.complete(system="s", user="u", model="claude-sonnet-4-20250514")
    assert result.text == "real reply"


# ---------------------------------------------------------------------------
# Cost computation
# ---------------------------------------------------------------------------


async def test_complete_computes_cost_via_cost_module_when_present(
    fake_anthropic_module: type[_FakeAsyncAnthropic],
) -> None:
    # claude-sonnet-4-20250514 is in PRICING_TABLE, so we should see a
    # positive cost_cents value computed by the cost module.
    client = AnthropicClient(api_key="sk-test")
    last = fake_anthropic_module.last_constructed
    assert last is not None
    last.next_response = _FakeMessage(content=[_FakeBlock(text="some response")])

    result = await client.complete(
        system="a" * 1000,
        user="b" * 1000,
        model="claude-sonnet-4-20250514",
    )
    # Independent compute using the same function — ensures the adapter
    # is delegating cost arithmetic to the cost module rather than
    # implementing its own.
    from agentforge_redteam.cost import estimate_cost_cents

    expected = estimate_cost_cents(
        "claude-sonnet-4-20250514",
        prompt_text="a" * 1000 + "b" * 1000,
        completion_text="some response",
    )
    assert result.cost_cents == expected
    assert result.cost_cents > 0


async def test_complete_returns_zero_cost_for_unknown_model(
    fake_anthropic_module: type[_FakeAsyncAnthropic],
) -> None:
    # An unknown model triggers UnknownModelError inside the cost
    # module; the adapter swallows it and returns 0. The wrapper's
    # cost_estimator at the call site will raise the same error in a
    # more useful frame.
    client = AnthropicClient(api_key="sk-test")
    result = await client.complete(
        system="s",
        user="u",
        model="never-shipped-model-xyz",
    )
    assert result.cost_cents == 0


# ---------------------------------------------------------------------------
# Lazy import contract
# ---------------------------------------------------------------------------


def test_module_does_not_import_anthropic_at_top_level() -> None:
    # Importing the clients module must not trigger the ``anthropic``
    # package import. We assert on attribute absence on the module
    # rather than on sys.modules so this test stays robust even when
    # another test in the same session has already imported anthropic
    # (e.g. via the fake-module fixture).
    import agentforge_redteam.clients.anthropic_client as mod

    assert not hasattr(mod, "AsyncAnthropic")
