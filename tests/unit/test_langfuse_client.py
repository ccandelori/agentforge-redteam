"""Tests for the Langfuse client factory + no-op fallback.

These tests are hermetic: the ``langfuse`` SDK is replaced in
``sys.modules`` with a tiny fake whenever a test instantiates the real
:class:`LangfuseClient`, so no network call ever fires. The Noop client
needs no stubbing — it is the pure-Python fallback exercised in the
"no keys" lane.
"""

from __future__ import annotations

import sys
import types
from typing import Any, ClassVar

import pytest

from agentforge_redteam.observability.langfuse_client import (
    DEFAULT_HOST,
    LANGFUSE_HOST_ENV,
    LANGFUSE_PUBLIC_KEY_ENV,
    LANGFUSE_SECRET_KEY_ENV,
    LangfuseClient,
    LangfuseClientLike,
    LangfuseConfig,
    NoopLangfuseClient,
    create_langfuse_client,
)
from agentforge_redteam.observability.session import SessionContext, langfuse_session

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _FakeSpan:
    """Stand-in for a real Langfuse span — captures update/end calls."""

    def __init__(self, **kwargs: Any) -> None:
        self.init_kwargs = kwargs
        self.updates: list[dict[str, Any]] = []
        self.ended: bool = False

    def update(
        self,
        *,
        output: Any = None,
        level: str | None = None,
        status_message: str | None = None,
    ) -> None:
        self.updates.append({"output": output, "level": level, "status_message": status_message})

    def end(self) -> None:
        self.ended = True


class _FakeLangfuseSDK:
    """Stand-in for ``langfuse.Langfuse`` — records construction kwargs."""

    # Class-level holder so tests can pull the most recently constructed
    # fake without threading it through the fixture's return value. The
    # ``ClassVar`` annotation is the canonical "this is not a per-instance
    # field" marker dataclass-style tooling looks for.
    last_constructed: ClassVar[Any] = None

    def __init__(
        self,
        *,
        public_key: str,
        secret_key: str,
        host: str,
    ) -> None:
        self.public_key = public_key
        self.secret_key = secret_key
        self.host = host
        self.span_calls: list[dict[str, Any]] = []
        self.flush_count: int = 0
        _FakeLangfuseSDK.last_constructed = self

    def span(self, **kwargs: Any) -> _FakeSpan:
        self.span_calls.append(kwargs)
        return _FakeSpan(**kwargs)

    def flush(self) -> None:
        self.flush_count += 1


@pytest.fixture
def fake_langfuse_module(monkeypatch: pytest.MonkeyPatch) -> _FakeLangfuseSDK:
    """Install a fake ``langfuse`` module in :data:`sys.modules`.

    The fake exposes only ``Langfuse``; the lazy import inside
    :class:`LangfuseClient` will pick it up instead of the real
    package. Yields the fake class so the test can inspect what was
    constructed (the test gets ``_FakeLangfuseSDK.last_constructed``
    via the class attribute, but receiving the type also lets tests
    construct fresh fakes if they want).
    """
    fake_mod = types.ModuleType("langfuse")
    fake_mod.Langfuse = _FakeLangfuseSDK  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "langfuse", fake_mod)
    _FakeLangfuseSDK.last_constructed = None
    return _FakeLangfuseSDK


# ---------------------------------------------------------------------------
# LangfuseConfig.from_env
# ---------------------------------------------------------------------------


def test_from_env_returns_config_when_both_keys_set() -> None:
    cfg = LangfuseConfig.from_env(
        {
            LANGFUSE_PUBLIC_KEY_ENV: "pk-test-1",
            LANGFUSE_SECRET_KEY_ENV: "sk-test-1",
        }
    )
    assert cfg is not None
    assert cfg.public_key == "pk-test-1"
    assert cfg.secret_key == "sk-test-1"


def test_from_env_returns_none_when_empty() -> None:
    assert LangfuseConfig.from_env({}) is None


def test_from_env_returns_none_when_only_public_key_set() -> None:
    cfg = LangfuseConfig.from_env({LANGFUSE_PUBLIC_KEY_ENV: "pk"})
    assert cfg is None


def test_from_env_returns_none_when_only_secret_key_set() -> None:
    cfg = LangfuseConfig.from_env({LANGFUSE_SECRET_KEY_ENV: "sk"})
    assert cfg is None


def test_from_env_treats_empty_string_keys_as_missing() -> None:
    cfg = LangfuseConfig.from_env(
        {
            LANGFUSE_PUBLIC_KEY_ENV: "",
            LANGFUSE_SECRET_KEY_ENV: "sk",
        }
    )
    assert cfg is None


def test_from_env_uses_default_host_when_not_set() -> None:
    cfg = LangfuseConfig.from_env(
        {
            LANGFUSE_PUBLIC_KEY_ENV: "pk",
            LANGFUSE_SECRET_KEY_ENV: "sk",
        }
    )
    assert cfg is not None
    assert cfg.host == DEFAULT_HOST


def test_from_env_respects_custom_host_value() -> None:
    cfg = LangfuseConfig.from_env(
        {
            LANGFUSE_PUBLIC_KEY_ENV: "pk",
            LANGFUSE_SECRET_KEY_ENV: "sk",
            LANGFUSE_HOST_ENV: "https://self-hosted.example",
        }
    )
    assert cfg is not None
    assert cfg.host == "https://self-hosted.example"


def test_from_env_falls_back_to_os_environ_when_env_is_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(LANGFUSE_PUBLIC_KEY_ENV, "pk-os")
    monkeypatch.setenv(LANGFUSE_SECRET_KEY_ENV, "sk-os")
    monkeypatch.delenv(LANGFUSE_HOST_ENV, raising=False)
    cfg = LangfuseConfig.from_env(None)
    assert cfg is not None
    assert cfg.public_key == "pk-os"
    assert cfg.secret_key == "sk-os"
    assert cfg.host == DEFAULT_HOST


# ---------------------------------------------------------------------------
# create_langfuse_client — Noop branch
# ---------------------------------------------------------------------------


def test_create_returns_noop_client_when_env_empty() -> None:
    client = create_langfuse_client(env={})
    assert isinstance(client, NoopLangfuseClient)


def test_noop_client_satisfies_protocol_structurally() -> None:
    # mypy already checks this at the type level; runtime smoke test
    # ensures the Protocol surface (.span returning .update/.end) is
    # exercised end-to-end without errors.
    client: LangfuseClientLike = NoopLangfuseClient()
    span = client.span(name="x", trace_id="t", input={"a": 1}, metadata={"k": "v"})
    # No assertions on side effects — the contract is "doesn't raise".
    span.update(output={"result": 1})
    span.update(level="ERROR", status_message="boom")
    span.end()


def test_noop_client_flush_is_noop() -> None:
    client = NoopLangfuseClient()
    # Method exists and returns None without raising.
    assert client.flush() is None


# ---------------------------------------------------------------------------
# create_langfuse_client — Real branch (under fake SDK)
# ---------------------------------------------------------------------------


def test_create_returns_real_client_when_keys_present(
    fake_langfuse_module: type[_FakeLangfuseSDK],
) -> None:
    client = create_langfuse_client(
        env={
            LANGFUSE_PUBLIC_KEY_ENV: "pk-test-1",
            LANGFUSE_SECRET_KEY_ENV: "sk-test-1",
        }
    )
    assert isinstance(client, LangfuseClient)
    # The factory should have constructed the underlying SDK exactly
    # once, with the keys forwarded and the default host filled in.
    assert fake_langfuse_module.last_constructed is not None
    assert fake_langfuse_module.last_constructed.public_key == "pk-test-1"
    assert fake_langfuse_module.last_constructed.secret_key == "sk-test-1"
    assert fake_langfuse_module.last_constructed.host == DEFAULT_HOST
    # The returned object exposes a flush method.
    assert callable(client.flush)


def test_real_client_construction_forwards_kwargs(
    fake_langfuse_module: type[_FakeLangfuseSDK],
) -> None:
    LangfuseClient(public_key="pk", secret_key="sk", host="https://x.example")
    last = fake_langfuse_module.last_constructed
    assert last is not None
    assert last.public_key == "pk"
    assert last.secret_key == "sk"
    assert last.host == "https://x.example"


def test_real_client_span_delegates_to_sdk(
    fake_langfuse_module: type[_FakeLangfuseSDK],
) -> None:
    client = LangfuseClient(public_key="pk", secret_key="sk")
    span = client.span(name="step-42", trace_id="t-42", input={"a": 1}, metadata=None)
    last = fake_langfuse_module.last_constructed
    assert last is not None
    assert last.span_calls == [
        {"name": "step-42", "trace_id": "t-42", "input": {"a": 1}, "metadata": None}
    ]
    # The returned object structurally satisfies LangfuseSpanLike.
    span.update(output={"ok": True})
    span.end()
    assert isinstance(span, _FakeSpan)
    assert span.ended is True


def test_real_client_flush_calls_sdk_flush(
    fake_langfuse_module: type[_FakeLangfuseSDK],
) -> None:
    client = LangfuseClient(public_key="pk", secret_key="sk")
    last = fake_langfuse_module.last_constructed
    assert last is not None
    assert last.flush_count == 0
    client.flush()
    assert last.flush_count == 1


# ---------------------------------------------------------------------------
# Lazy import contract
# ---------------------------------------------------------------------------


def test_langfuse_client_module_does_not_import_langfuse_at_top_level() -> None:
    # Importing the observability module must not trigger the
    # ``langfuse`` package import. We assert on attribute absence in
    # the module rather than on sys.modules so this test stays robust
    # even when another test in the same session has already imported
    # langfuse (e.g. via the fake-module fixture).
    import agentforge_redteam.observability.langfuse_client as mod

    assert not hasattr(mod, "Langfuse")


# ---------------------------------------------------------------------------
# Session context manager
# ---------------------------------------------------------------------------


def test_langfuse_session_enters_and_exits_without_raising() -> None:
    client = NoopLangfuseClient()
    sess = SessionContext(session_id="s-1")
    entered = False
    with langfuse_session(client, session=sess):
        entered = True
    assert entered


def test_langfuse_session_calls_flush_on_exit(
    fake_langfuse_module: type[_FakeLangfuseSDK],
) -> None:
    client = LangfuseClient(public_key="pk", secret_key="sk")
    last = fake_langfuse_module.last_constructed
    assert last is not None
    with langfuse_session(client, session=SessionContext(session_id="s-2")):
        pass
    assert last.flush_count == 1


def test_langfuse_session_swallows_flush_exceptions() -> None:
    class _FlushRaisingClient:
        def span(
            self,
            *,
            name: str,
            trace_id: str | None = None,
            input: Any = None,
            metadata: dict[str, Any] | None = None,
        ) -> Any:
            return _FakeSpan()

        def flush(self) -> None:
            raise RuntimeError("langfuse outage")

    client = _FlushRaisingClient()
    # A Langfuse outage at session end must NOT bubble out — that
    # would crash the orchestrator after the audit log is already
    # written.
    with langfuse_session(client, session=SessionContext(session_id="s-3")):
        pass


def test_langfuse_session_swallows_flush_exceptions_when_block_raises() -> None:
    class _FlushRaisingClient:
        def span(
            self,
            *,
            name: str,
            trace_id: str | None = None,
            input: Any = None,
            metadata: dict[str, Any] | None = None,
        ) -> Any:
            return _FakeSpan()

        def flush(self) -> None:
            raise RuntimeError("outage")

    client = _FlushRaisingClient()
    with (
        pytest.raises(ValueError, match="inner"),
        langfuse_session(client, session=SessionContext(session_id="s-4")),
    ):
        raise ValueError("inner")


def test_langfuse_session_tolerates_client_without_flush_attr() -> None:
    class _ClientNoFlush:
        def span(
            self,
            *,
            name: str,
            trace_id: str | None = None,
            input: Any = None,
            metadata: dict[str, Any] | None = None,
        ) -> Any:
            return _FakeSpan()

    client = _ClientNoFlush()
    # Some test doubles may omit ``flush``; the session helper must
    # not blow up via AttributeError in that case.
    with langfuse_session(client, session=SessionContext(session_id="s-5")):
        pass


def test_session_context_carries_optional_user_id_and_metadata() -> None:
    sess = SessionContext(
        session_id="s-6",
        user_id="cameron",
        metadata={"campaign": "c-1"},
    )
    assert sess.user_id == "cameron"
    assert sess.metadata == {"campaign": "c-1"}
