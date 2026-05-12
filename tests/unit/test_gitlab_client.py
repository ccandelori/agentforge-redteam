"""Tests for the GitLab client factory + httpx-backed adapter.

These tests are hermetic: ``httpx.AsyncClient`` is monkeypatched at the
module level whenever a test invokes :meth:`GitLabClient.create_issue`,
so no real network call ever fires. The factory's "no config" branch
needs no stubbing — it returns ``None`` before any HTTP machinery is
constructed.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from agentforge_redteam.agents.documentation import GitLabIssueRef
from agentforge_redteam.clients.gitlab_client import (
    DEFAULT_GITLAB_URL,
    GITLAB_PROJECT_ID_ENV,
    GITLAB_TOKEN_ENV,
    GITLAB_URL_ENV,
    GitLabAPIError,
    GitLabClient,
    GitLabConfig,
    create_gitlab_client,
)

# ---------------------------------------------------------------------------
# httpx fake plumbing
# ---------------------------------------------------------------------------


class _FakeResponse:
    """Stand-in for ``httpx.Response``."""

    def __init__(
        self,
        *,
        status_code: int = 201,
        json_body: Any = None,
        text: str | None = None,
    ) -> None:
        self.status_code = status_code
        self._json_body = (
            json_body
            if json_body is not None
            else {
                "iid": 42,
                "web_url": "https://gitlab.example/group/proj/-/issues/42",
            }
        )
        # Mirror httpx.Response.text: if explicit text was passed use it,
        # otherwise serialise the JSON body for assertions on error
        # messages.
        if text is not None:
            self.text = text
        else:
            import json as _json

            self.text = _json.dumps(self._json_body)

    def json(self) -> Any:
        return self._json_body


class _Captured:
    """Container for whatever the fake httpx.AsyncClient saw."""

    def __init__(self) -> None:
        self.init_kwargs: dict[str, Any] | None = None
        self.post_url: str | None = None
        self.post_kwargs: dict[str, Any] | None = None
        self.next_response: _FakeResponse = _FakeResponse()
        self.raise_on_post: Exception | None = None


def _install_fake_httpx(
    monkeypatch: pytest.MonkeyPatch,
    *,
    captured: _Captured | None = None,
) -> _Captured:
    """Install a fake ``httpx.AsyncClient`` that records calls."""
    state = captured if captured is not None else _Captured()

    class _FakeAsyncClient:
        def __init__(self, **kwargs: Any) -> None:
            state.init_kwargs = kwargs

        async def __aenter__(self) -> _FakeAsyncClient:
            return self

        async def __aexit__(self, *exc_info: Any) -> bool:
            return False

        async def post(self, url: str, **kwargs: Any) -> _FakeResponse:
            state.post_url = url
            state.post_kwargs = kwargs
            if state.raise_on_post is not None:
                raise state.raise_on_post
            return state.next_response

    monkeypatch.setattr(httpx, "AsyncClient", _FakeAsyncClient)
    return state


# ---------------------------------------------------------------------------
# GitLabConfig.from_env
# ---------------------------------------------------------------------------


def test_from_env_returns_config_when_both_set() -> None:
    cfg = GitLabConfig.from_env(
        {
            GITLAB_TOKEN_ENV: "glpat-xyz",
            GITLAB_PROJECT_ID_ENV: "123",
        }
    )
    assert cfg is not None
    assert cfg.token == "glpat-xyz"
    assert cfg.project_id == "123"
    assert cfg.base_url == DEFAULT_GITLAB_URL


def test_from_env_returns_none_when_empty() -> None:
    assert GitLabConfig.from_env({}) is None


def test_from_env_returns_none_when_only_token_set() -> None:
    assert GitLabConfig.from_env({GITLAB_TOKEN_ENV: "glpat-x"}) is None


def test_from_env_returns_none_when_only_project_id_set() -> None:
    assert GitLabConfig.from_env({GITLAB_PROJECT_ID_ENV: "123"}) is None


def test_from_env_treats_empty_strings_as_missing() -> None:
    assert (
        GitLabConfig.from_env(
            {
                GITLAB_TOKEN_ENV: "",
                GITLAB_PROJECT_ID_ENV: "123",
            }
        )
        is None
    )
    assert (
        GitLabConfig.from_env(
            {
                GITLAB_TOKEN_ENV: "glpat-x",
                GITLAB_PROJECT_ID_ENV: "",
            }
        )
        is None
    )


def test_from_env_respects_custom_base_url() -> None:
    cfg = GitLabConfig.from_env(
        {
            GITLAB_TOKEN_ENV: "glpat-x",
            GITLAB_PROJECT_ID_ENV: "123",
            GITLAB_URL_ENV: "https://gitlab.self-hosted.example",
        }
    )
    assert cfg is not None
    assert cfg.base_url == "https://gitlab.self-hosted.example"


def test_from_env_falls_back_to_os_environ_when_env_is_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(GITLAB_TOKEN_ENV, "glpat-os")
    monkeypatch.setenv(GITLAB_PROJECT_ID_ENV, "999")
    monkeypatch.delenv(GITLAB_URL_ENV, raising=False)
    cfg = GitLabConfig.from_env(None)
    assert cfg is not None
    assert cfg.token == "glpat-os"
    assert cfg.project_id == "999"
    assert cfg.base_url == DEFAULT_GITLAB_URL


# ---------------------------------------------------------------------------
# create_gitlab_client — None branch
# ---------------------------------------------------------------------------


def test_create_returns_none_when_env_empty() -> None:
    assert create_gitlab_client(env={}) is None


def test_create_returns_none_when_only_token_set() -> None:
    assert create_gitlab_client(env={GITLAB_TOKEN_ENV: "glpat-x"}) is None


# ---------------------------------------------------------------------------
# create_gitlab_client — Real branch
# ---------------------------------------------------------------------------


def test_create_returns_real_client_when_config_present() -> None:
    client = create_gitlab_client(
        env={
            GITLAB_TOKEN_ENV: "glpat-x",
            GITLAB_PROJECT_ID_ENV: "42",
        }
    )
    assert isinstance(client, GitLabClient)


# ---------------------------------------------------------------------------
# GitLabClient.create_issue — request shape
# ---------------------------------------------------------------------------


async def test_create_issue_posts_to_correct_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _install_fake_httpx(monkeypatch)
    client = GitLabClient(
        token="glpat-x",
        project_id="123",
        base_url="https://gitlab.example",
    )
    await client.create_issue(title="t", body="b", labels=["severity::P2"])

    assert state.post_url == "https://gitlab.example/api/v4/projects/123/issues"


async def test_create_issue_strips_trailing_slash_in_base_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _install_fake_httpx(monkeypatch)
    client = GitLabClient(
        token="glpat-x",
        project_id="123",
        base_url="https://gitlab.example/",
    )
    await client.create_issue(title="t", body="b", labels=[])
    assert state.post_url == "https://gitlab.example/api/v4/projects/123/issues"


async def test_create_issue_sends_private_token_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _install_fake_httpx(monkeypatch)
    client = GitLabClient(token="glpat-secret", project_id="1")
    await client.create_issue(title="t", body="b", labels=[])

    assert state.post_kwargs is not None
    headers = state.post_kwargs["headers"]
    assert headers["PRIVATE-TOKEN"] == "glpat-secret"


async def test_create_issue_joins_labels_with_commas(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _install_fake_httpx(monkeypatch)
    client = GitLabClient(token="glpat-x", project_id="1")
    await client.create_issue(
        title="t", body="b", labels=["severity::P2", "owasp::LLM01:2025", "mitre::ATLAS.T0051"]
    )
    assert state.post_kwargs is not None
    payload = state.post_kwargs["data"]
    assert payload["labels"] == "severity::P2,owasp::LLM01:2025,mitre::ATLAS.T0051"


async def test_create_issue_sends_title_and_description(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _install_fake_httpx(monkeypatch)
    client = GitLabClient(token="glpat-x", project_id="1")
    await client.create_issue(title="my title", body="my body", labels=[])

    assert state.post_kwargs is not None
    payload = state.post_kwargs["data"]
    assert payload["title"] == "my title"
    assert payload["description"] == "my body"


async def test_create_issue_forwards_timeout_to_httpx(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _install_fake_httpx(monkeypatch)
    client = GitLabClient(token="glpat-x", project_id="1", timeout_s=7.5)
    await client.create_issue(title="t", body="b", labels=[])

    assert state.init_kwargs is not None
    assert state.init_kwargs["timeout"] == 7.5


# ---------------------------------------------------------------------------
# GitLabClient.create_issue — response handling
# ---------------------------------------------------------------------------


async def test_create_issue_returns_issue_ref_from_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _install_fake_httpx(monkeypatch)
    state.next_response = _FakeResponse(
        status_code=201,
        json_body={
            "iid": 42,
            "web_url": "https://gitlab.example/group/proj/-/issues/42",
        },
    )
    client = GitLabClient(token="glpat-x", project_id="1")
    ref = await client.create_issue(title="t", body="b", labels=[])

    assert isinstance(ref, GitLabIssueRef)
    assert ref.issue_id == 42
    assert ref.url == "https://gitlab.example/group/proj/-/issues/42"


async def test_create_issue_raises_on_non_2xx_with_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _install_fake_httpx(monkeypatch)
    state.next_response = _FakeResponse(
        status_code=401,
        json_body={"message": "401 Unauthorized"},
        text='{"message": "401 Unauthorized"}',
    )
    client = GitLabClient(token="glpat-bad", project_id="1")

    with pytest.raises(GitLabAPIError) as exc_info:
        await client.create_issue(title="t", body="b", labels=[])

    err = exc_info.value
    assert err.status_code == 401
    assert "401 Unauthorized" in err.body
    assert "401" in str(err)


async def test_create_issue_propagates_network_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _install_fake_httpx(monkeypatch)
    state.raise_on_post = httpx.ConnectError("connection refused")
    client = GitLabClient(token="glpat-x", project_id="1")

    with pytest.raises(httpx.ConnectError, match="connection refused"):
        await client.create_issue(title="t", body="b", labels=[])


async def test_create_issue_raises_when_response_is_not_an_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _install_fake_httpx(monkeypatch)
    state.next_response = _FakeResponse(
        status_code=201,
        json_body=["not", "an", "object"],
        text='["not", "an", "object"]',
    )
    client = GitLabClient(token="glpat-x", project_id="1")
    with pytest.raises(GitLabAPIError, match="expected JSON object"):
        await client.create_issue(title="t", body="b", labels=[])


async def test_create_issue_raises_when_iid_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _install_fake_httpx(monkeypatch)
    state.next_response = _FakeResponse(
        status_code=201,
        json_body={"web_url": "https://x/issues/1"},  # no iid
        text='{"web_url": "https://x/issues/1"}',
    )
    client = GitLabClient(token="glpat-x", project_id="1")
    with pytest.raises(GitLabAPIError, match="missing or malformed"):
        await client.create_issue(title="t", body="b", labels=[])


async def test_create_issue_raises_when_web_url_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _install_fake_httpx(monkeypatch)
    state.next_response = _FakeResponse(
        status_code=201,
        json_body={"iid": 42},  # no web_url
        text='{"iid": 42}',
    )
    client = GitLabClient(token="glpat-x", project_id="1")
    with pytest.raises(GitLabAPIError, match="missing or malformed"):
        await client.create_issue(title="t", body="b", labels=[])
