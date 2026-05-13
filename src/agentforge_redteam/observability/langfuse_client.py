"""Langfuse client factory + no-op fallback.

This module is the single seam between AgentForge Red Team and the
``langfuse`` SDK. The rest of the platform depends only on the
:class:`LangfuseClientLike` and :class:`LangfuseSpanLike` Protocols
defined in :mod:`agentforge_redteam.tools.wrapper`; this module either
returns a real :class:`LangfuseClient` (when both keys are present) or
a :class:`NoopLangfuseClient` (when they are missing).

Design constraints (load-bearing — keep stable):

* **The Protocols are NOT redefined here.** They live in
  :mod:`agentforge_redteam.tools.wrapper` so type-checkers see one
  canonical type across the codebase. We re-export them via ``from ...
  import`` so callers can ``from agentforge_redteam.observability import
  LangfuseClientLike`` without reaching into the audit-wrapper module.

* **The ``langfuse`` package is imported lazily inside
  :meth:`LangfuseClient.__init__`.** A fresh checkout with no Langfuse
  keys must still import this module cheaply (and without the side
  effect of pulling in the entire OpenTelemetry tree that ``langfuse``
  brings in). The Noop client never touches the SDK.

* **The factory never raises on missing keys.** Dev, test, and offline
  CI lanes all run without Langfuse credentials. Returning a Noop
  client lets every agent's ``langfuse=...`` parameter be filled with
  a real object that satisfies the Protocol, instead of forcing every
  call site to guard against ``None``.

* **No PHI / payload logging from this module.** We log only the
  construction-time decisions ("real client constructed",
  "no-op client returned because keys missing") — never the trace
  contents themselves; those are the SDK's responsibility.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Final

import structlog

# Re-export the protocol the agents already depend on so callers see one
# canonical type. The Protocols live in the audit-wrapper module because
# that is where the dependency is load-bearing; this module is just a
# convenient re-export point.
from agentforge_redteam.tools.wrapper import LangfuseClientLike, LangfuseSpanLike

__all__ = [
    "DEFAULT_HOST",
    "LANGFUSE_HOST_ENV",
    "LANGFUSE_PUBLIC_KEY_ENV",
    "LANGFUSE_SECRET_KEY_ENV",
    "LangfuseClient",
    "LangfuseClientLike",
    "LangfuseConfig",
    "LangfuseSpanLike",
    "NoopLangfuseClient",
    "create_langfuse_client",
]

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LANGFUSE_PUBLIC_KEY_ENV: Final[str] = "LANGFUSE_PUBLIC_KEY"
LANGFUSE_SECRET_KEY_ENV: Final[str] = "LANGFUSE_SECRET_KEY"
LANGFUSE_HOST_ENV: Final[str] = "LANGFUSE_HOST"
DEFAULT_HOST: Final[str] = "https://cloud.langfuse.com"


# ---------------------------------------------------------------------------
# Config value object
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LangfuseConfig:
    """Validated Langfuse credentials, ready to hand to the SDK.

    Construction is via :meth:`from_env` rather than the default
    dataclass init so the "missing keys -> None" path is centralised
    and reasoning about partial config doesn't leak into call sites.
    """

    public_key: str
    secret_key: str
    host: str = DEFAULT_HOST

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> LangfuseConfig | None:
        """Return a config iff both public and secret keys are set.

        Reads from ``env`` (for testability) or :data:`os.environ` when
        not provided. Either key being missing/empty yields ``None``
        — callers should treat ``None`` as "fall back to a no-op
        client", not as an error. The host defaults to
        :data:`DEFAULT_HOST` (Langfuse Cloud) when ``LANGFUSE_HOST`` is
        absent.
        """
        source: dict[str, str] = dict(os.environ) if env is None else env
        public = source.get(LANGFUSE_PUBLIC_KEY_ENV, "").strip()
        secret = source.get(LANGFUSE_SECRET_KEY_ENV, "").strip()
        if not public or not secret:
            return None
        host = source.get(LANGFUSE_HOST_ENV, "").strip() or DEFAULT_HOST
        return cls(public_key=public, secret_key=secret, host=host)


# ---------------------------------------------------------------------------
# No-op client (fallback when keys are missing)
# ---------------------------------------------------------------------------


class _NoopSpan:
    """No-op span — silently swallows update/end calls.

    Implements :class:`LangfuseSpanLike` structurally so the audit
    wrapper's span-handling branch in
    :func:`agentforge_redteam.tools.wrapper.call_tool` runs identically
    whether or not a real Langfuse client is wired in. Keeping the
    code path identical means we don't grow a separate, lightly-tested
    "no observability" path that drifts from the observed one.
    """

    __slots__ = ()

    def update(
        self,
        *,
        output: Any = None,
        level: str | None = None,
        status_message: str | None = None,
    ) -> None:
        return None

    def end(self) -> None:
        return None


class NoopLangfuseClient:
    """LangfuseClientLike-compatible no-op client.

    Used when:

    * Either of ``LANGFUSE_PUBLIC_KEY`` / ``LANGFUSE_SECRET_KEY`` is
      unset — typical for local dev and CI lanes that don't proxy to
      Langfuse Cloud.
    * Tests want to exercise the wrapper's span branch without
      asserting on trace state.

    The class is intentionally not a singleton — instances are cheap,
    and the factory returns a fresh one per call so callers can hold
    distinct objects when they want (e.g. one per session).
    """

    __slots__ = ()

    def span(
        self,
        *,
        name: str,
        trace_id: str | None = None,
        input: Any = None,
        metadata: dict[str, Any] | None = None,
    ) -> LangfuseSpanLike:
        return _NoopSpan()

    def flush(self) -> None:
        """No-op flush — exists so the session helper's best-effort
        ``getattr(client, "flush", None)`` path runs the same shape of
        code as it does with a real client."""
        return None


# ---------------------------------------------------------------------------
# Real client (wraps the Langfuse SDK)
# ---------------------------------------------------------------------------


class LangfuseClient:
    """Real Langfuse-backed client.

    Wraps :class:`langfuse.Langfuse` so the rest of the platform
    depends on the :class:`LangfuseClientLike` Protocol, not the SDK
    directly. The SDK is imported lazily inside :meth:`__init__` so a
    module-level ``import agentforge_redteam.observability`` does not
    pull in OpenTelemetry, gRPC, or any other Langfuse transitive
    dependency when the platform is running without keys.
    """

    __slots__ = ("_client",)

    def __init__(
        self,
        *,
        public_key: str,
        secret_key: str,
        host: str = DEFAULT_HOST,
    ) -> None:
        # Lazy import keeps fresh checkouts cheap and keeps the
        # langfuse OpenTelemetry import cost off the critical path
        # when keys are missing.
        from langfuse import Langfuse

        # We type the held client as ``Any`` so this module only depends
        # on the Protocol surface declared on :class:`LangfuseClientLike`
        # — not on whichever SDK version happens to be pinned. The
        # ``langfuse`` SDK's public surface has shifted across 2.x / 3.x
        # / 4.x; pinning the attribute type to ``Any`` keeps the seam
        # narrow.
        self._client: Any = Langfuse(
            public_key=public_key,
            secret_key=secret_key,
            host=host,
        )

    def span(
        self,
        *,
        name: str,
        trace_id: str | None = None,
        input: Any = None,
        metadata: dict[str, Any] | None = None,
    ) -> LangfuseSpanLike:
        """Open a new Langfuse span and return its handle.

        Langfuse 4.x dropped the top-level ``.span()`` shortcut in favour
        of OTel-shaped ``start_observation(as_type="span", ...)`` plus a
        ``TraceContext`` for trace grouping. The wrapper's contract is
        unchanged (still takes name / trace_id / input / metadata) — we
        just translate the trace_id seed into a W3C-format trace id via
        ``create_trace_id`` so two spans sharing a step_id land in the
        same Langfuse trace, then pass it via ``trace_context``.

        ``TraceContext`` is a TypedDict at the SDK seam, so we build it
        as a plain ``dict`` to avoid importing ``langfuse.types`` at
        module level (keeps the lazy-import discipline intact and keeps
        the test seam shallow — a stubbed ``langfuse`` module doesn't
        need to ship a ``.types`` submodule).
        """
        trace_context: dict[str, str] | None = None
        if trace_id is not None:
            normalized = self._client.create_trace_id(seed=trace_id)
            trace_context = {"trace_id": normalized}

        span: LangfuseSpanLike = self._client.start_observation(
            name=name,
            as_type="span",
            input=input,
            metadata=metadata,
            trace_context=trace_context,
        )
        return span

    def flush(self) -> None:
        """Block until queued events are uploaded.

        Should be called before process exit so the final batch of
        spans doesn't get dropped. The session context manager in
        :mod:`agentforge_redteam.observability.session` calls this
        on exit best-effort.
        """
        self._client.flush()


# ---------------------------------------------------------------------------
# Public factory
# ---------------------------------------------------------------------------


def create_langfuse_client(
    env: dict[str, str] | None = None,
) -> LangfuseClientLike:
    """Return a real Langfuse client if keys are set; otherwise a no-op.

    This function NEVER raises on missing keys. The agents must work
    in dev/test without Langfuse credentials, so the factory's contract
    is "give me a Protocol-shaped object I can pass through to
    :func:`agentforge_redteam.tools.wrapper.call_tool` unconditionally".

    The optional ``env`` parameter makes the factory deterministic in
    tests — pass a dict to control which keys are visible, rather than
    monkeypatching ``os.environ``.
    """
    config = LangfuseConfig.from_env(env)
    if config is None:
        logger.info(
            "langfuse.client.noop",
            reason="missing_keys",
        )
        return NoopLangfuseClient()

    client = LangfuseClient(
        public_key=config.public_key,
        secret_key=config.secret_key,
        host=config.host,
    )
    logger.info(
        "langfuse.client.real",
        host=config.host,
    )
    return client
