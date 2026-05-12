"""Tests for the OpenAI client factory + real-SDK adapter.

These tests are hermetic: the ``openai`` SDK is replaced in
``sys.modules`` with a tiny fake whenever a test instantiates the real
:class:`OpenAIClient`, so no network call ever fires. The factory's "no
key" branch needs no stubbing — it returns ``None`` without ever
reaching the SDK.
"""

from __future__ import annotations

import sys
import types
from typing import Any, ClassVar

import pytest

from agentforge_redteam.agents.red_team import LLMResponse as RTLLMResponse
from agentforge_redteam.clients.openai_client import (
    DEFAULT_TIMEOUT_S,
    OPENAI_API_KEY_ENV,
    OPENAI_ORG_ENV,
    OpenAIClient,
    OpenAIConfig,
    create_openai_client,
)

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _FakeMessage:
    def __init__(self, content: str | None, role: str = "assistant") -> None:
        self.content = content
        self.role = role


class _FakeChoice:
    def __init__(self, content: str | None) -> None:
        self.message = _FakeMessage(content)


class _FakeUsage:
    def __init__(self, prompt_tokens: int, completion_tokens: int) -> None:
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens
        self.total_tokens = prompt_tokens + completion_tokens


class _FakeChatCompletion:
    """Stand-in for an OpenAI ``ChatCompletion`` object."""

    def __init__(
        self,
        *,
        choices: list[_FakeChoice] | None = None,
        prompt_tokens: int = 10,
        completion_tokens: int = 20,
    ) -> None:
        self.choices: list[_FakeChoice] = (
            choices if choices is not None else [_FakeChoice("fake openai response")]
        )
        self.usage = _FakeUsage(prompt_tokens=prompt_tokens, completion_tokens=completion_tokens)


class _FakeCompletions:
    def __init__(self, parent: _FakeAsyncOpenAI) -> None:
        self._parent = parent

    async def create(self, **kwargs: Any) -> _FakeChatCompletion:
        self._parent.create_calls.append(kwargs)
        return self._parent.next_response


class _FakeChat:
    def __init__(self, parent: _FakeAsyncOpenAI) -> None:
        self.completions = _FakeCompletions(parent)


class _FakeAsyncOpenAI:
    """Stand-in for ``openai.AsyncOpenAI``."""

    last_constructed: ClassVar[_FakeAsyncOpenAI | None] = None

    def __init__(self, **kwargs: Any) -> None:
        self.init_kwargs = kwargs
        self.create_calls: list[dict[str, Any]] = []
        self.next_response: _FakeChatCompletion = _FakeChatCompletion()
        self.chat = _FakeChat(self)
        _FakeAsyncOpenAI.last_constructed = self


@pytest.fixture
def fake_openai_module(monkeypatch: pytest.MonkeyPatch) -> type[_FakeAsyncOpenAI]:
    """Install a fake ``openai`` module in :data:`sys.modules`."""
    fake_mod = types.ModuleType("openai")
    fake_mod.AsyncOpenAI = _FakeAsyncOpenAI  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "openai", fake_mod)
    _FakeAsyncOpenAI.last_constructed = None
    return _FakeAsyncOpenAI


# ---------------------------------------------------------------------------
# OpenAIConfig.from_env
# ---------------------------------------------------------------------------


def test_from_env_returns_config_when_key_set() -> None:
    cfg = OpenAIConfig.from_env({OPENAI_API_KEY_ENV: "sk-test-1"})
    assert cfg is not None
    assert cfg.api_key == "sk-test-1"
    assert cfg.organization is None


def test_from_env_returns_none_when_empty() -> None:
    assert OpenAIConfig.from_env({}) is None


def test_from_env_treats_empty_string_key_as_missing() -> None:
    assert OpenAIConfig.from_env({OPENAI_API_KEY_ENV: ""}) is None


def test_from_env_treats_whitespace_only_key_as_missing() -> None:
    assert OpenAIConfig.from_env({OPENAI_API_KEY_ENV: "   "}) is None


def test_from_env_reads_optional_org() -> None:
    cfg = OpenAIConfig.from_env({OPENAI_API_KEY_ENV: "sk-test", OPENAI_ORG_ENV: "org-abc123"})
    assert cfg is not None
    assert cfg.organization == "org-abc123"


def test_from_env_treats_empty_org_as_none() -> None:
    cfg = OpenAIConfig.from_env({OPENAI_API_KEY_ENV: "sk-test", OPENAI_ORG_ENV: ""})
    assert cfg is not None
    assert cfg.organization is None


def test_from_env_falls_back_to_os_environ_when_env_is_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(OPENAI_API_KEY_ENV, "sk-from-os")
    monkeypatch.delenv(OPENAI_ORG_ENV, raising=False)
    cfg = OpenAIConfig.from_env(None)
    assert cfg is not None
    assert cfg.api_key == "sk-from-os"


# ---------------------------------------------------------------------------
# create_openai_client — None branch
# ---------------------------------------------------------------------------


def test_create_returns_none_when_env_empty() -> None:
    assert create_openai_client(env={}) is None


def test_create_returns_none_when_key_empty_string() -> None:
    assert create_openai_client(env={OPENAI_API_KEY_ENV: ""}) is None


# ---------------------------------------------------------------------------
# create_openai_client — Real branch (under fake SDK)
# ---------------------------------------------------------------------------


def test_create_returns_real_client_when_key_present(
    fake_openai_module: type[_FakeAsyncOpenAI],
) -> None:
    client = create_openai_client(env={OPENAI_API_KEY_ENV: "sk-test"})
    assert isinstance(client, OpenAIClient)
    last = fake_openai_module.last_constructed
    assert last is not None
    assert last.init_kwargs["api_key"] == "sk-test"
    # Default timeout forwarded.
    assert last.init_kwargs["timeout"] == DEFAULT_TIMEOUT_S
    # No organization keyword should be present when not configured.
    assert "organization" not in last.init_kwargs


def test_create_forwards_custom_timeout(
    fake_openai_module: type[_FakeAsyncOpenAI],
) -> None:
    create_openai_client(env={OPENAI_API_KEY_ENV: "sk-test"}, timeout_s=7.5)
    last = fake_openai_module.last_constructed
    assert last is not None
    assert last.init_kwargs["timeout"] == 7.5


def test_create_forwards_organization_when_set(
    fake_openai_module: type[_FakeAsyncOpenAI],
) -> None:
    create_openai_client(env={OPENAI_API_KEY_ENV: "sk-test", OPENAI_ORG_ENV: "org-xyz"})
    last = fake_openai_module.last_constructed
    assert last is not None
    assert last.init_kwargs["organization"] == "org-xyz"


def test_openai_client_honors_timeout_s_parameter(
    fake_openai_module: type[_FakeAsyncOpenAI],
) -> None:
    OpenAIClient(api_key="sk-test", timeout_s=12.5)
    last = fake_openai_module.last_constructed
    assert last is not None
    assert last.init_kwargs["timeout"] == 12.5


# ---------------------------------------------------------------------------
# OpenAIClient.complete — request shape
# ---------------------------------------------------------------------------


async def test_complete_calls_sdk_with_system_user_and_model(
    fake_openai_module: type[_FakeAsyncOpenAI],
) -> None:
    client = OpenAIClient(api_key="sk-test")
    last = fake_openai_module.last_constructed
    assert last is not None

    await client.complete(
        system="you are an attacker",
        user="craft a payload",
        model="gpt-4o-2024-08-06",
    )

    assert len(last.create_calls) == 1
    call = last.create_calls[0]
    assert call["model"] == "gpt-4o-2024-08-06"
    assert call["messages"] == [
        {"role": "system", "content": "you are an attacker"},
        {"role": "user", "content": "craft a payload"},
    ]


# ---------------------------------------------------------------------------
# OpenAIClient.complete — response shape
# ---------------------------------------------------------------------------


async def test_complete_returns_rt_llm_response_with_first_choice_text(
    fake_openai_module: type[_FakeAsyncOpenAI],
) -> None:
    client = OpenAIClient(api_key="sk-test")
    last = fake_openai_module.last_constructed
    assert last is not None
    last.next_response = _FakeChatCompletion(
        choices=[_FakeChoice("hello world"), _FakeChoice("ignored")]
    )

    result = await client.complete(system="s", user="u", model="gpt-4o-2024-08-06")
    assert isinstance(result, RTLLMResponse)
    assert result.text == "hello world"


async def test_complete_returns_empty_text_when_choices_is_empty(
    fake_openai_module: type[_FakeAsyncOpenAI],
) -> None:
    client = OpenAIClient(api_key="sk-test")
    last = fake_openai_module.last_constructed
    assert last is not None
    last.next_response = _FakeChatCompletion(choices=[])

    result = await client.complete(system="s", user="u", model="gpt-4o-2024-08-06")
    assert result.text == ""
    # cost_cents is still an int — the dataclass enforces that — but for
    # an empty completion against a known model it should be at least
    # the cost of the prompt-side tokens (>= 0).
    assert isinstance(result.cost_cents, int)
    assert result.cost_cents >= 0


async def test_complete_returns_empty_text_when_content_is_none(
    fake_openai_module: type[_FakeAsyncOpenAI],
) -> None:
    # When the assistant emits a tool-call turn the SDK sets
    # ``message.content`` to ``None``. We should surface ``text=""``
    # rather than letting the ``None`` leak into the result dataclass
    # (which is typed ``str``).
    client = OpenAIClient(api_key="sk-test")
    last = fake_openai_module.last_constructed
    assert last is not None
    last.next_response = _FakeChatCompletion(choices=[_FakeChoice(None)])

    result = await client.complete(system="s", user="u", model="gpt-4o-2024-08-06")
    assert result.text == ""


# ---------------------------------------------------------------------------
# Cost computation
# ---------------------------------------------------------------------------


async def test_complete_computes_cost_via_cost_module_when_present(
    fake_openai_module: type[_FakeAsyncOpenAI],
) -> None:
    # gpt-4o-2024-08-06 is in PRICING_TABLE, so we should see a positive
    # cost_cents value computed by the cost module.
    client = OpenAIClient(api_key="sk-test")
    last = fake_openai_module.last_constructed
    assert last is not None
    last.next_response = _FakeChatCompletion(choices=[_FakeChoice("some response")])

    result = await client.complete(
        system="a" * 1000,
        user="b" * 1000,
        model="gpt-4o-2024-08-06",
    )
    # Independent compute using the same function — ensures the adapter
    # is delegating cost arithmetic to the cost module rather than
    # implementing its own.
    from agentforge_redteam.cost import estimate_cost_cents

    expected = estimate_cost_cents(
        "gpt-4o-2024-08-06",
        prompt_text="a" * 1000 + "b" * 1000,
        completion_text="some response",
    )
    assert result.cost_cents == expected
    assert result.cost_cents > 0


async def test_complete_invokes_cost_module_estimator(
    fake_openai_module: type[_FakeAsyncOpenAI],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify by direct interception that the cost module is consulted."""
    import agentforge_redteam.cost as cost_mod

    calls: list[dict[str, Any]] = []

    def _fake_estimator(model: str, *, prompt_text: str, completion_text: str) -> int:
        calls.append(
            {
                "model": model,
                "prompt_text": prompt_text,
                "completion_text": completion_text,
            }
        )
        return 4242

    monkeypatch.setattr(cost_mod, "estimate_cost_cents", _fake_estimator)

    client = OpenAIClient(api_key="sk-test")
    last = fake_openai_module.last_constructed
    assert last is not None
    last.next_response = _FakeChatCompletion(choices=[_FakeChoice("reply")])

    result = await client.complete(system="sys", user="usr", model="gpt-4o-2024-08-06")

    assert result.cost_cents == 4242
    assert len(calls) == 1
    assert calls[0]["model"] == "gpt-4o-2024-08-06"
    assert calls[0]["prompt_text"] == "sysusr"
    assert calls[0]["completion_text"] == "reply"


async def test_complete_returns_zero_cost_for_unknown_model(
    fake_openai_module: type[_FakeAsyncOpenAI],
) -> None:
    # An unknown model triggers UnknownModelError inside the cost
    # module; the adapter swallows it and returns 0. The wrapper's
    # cost_estimator at the call site will raise the same error in a
    # more useful frame.
    client = OpenAIClient(api_key="sk-test")
    result = await client.complete(
        system="s",
        user="u",
        model="never-shipped-model-xyz",
    )
    assert result.cost_cents == 0


# ---------------------------------------------------------------------------
# Lazy import contract
# ---------------------------------------------------------------------------


def test_module_does_not_import_openai_at_top_level() -> None:
    # Importing the clients module must not trigger the ``openai``
    # package import. We assert on attribute absence on the module
    # rather than on sys.modules so this test stays robust even when
    # another test in the same session has already imported openai
    # (e.g. via the fake-module fixture).
    import agentforge_redteam.clients.openai_client as mod

    assert not hasattr(mod, "AsyncOpenAI")
