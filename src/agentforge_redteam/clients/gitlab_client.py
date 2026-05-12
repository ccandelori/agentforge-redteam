"""Real GitLab Issues API client adapter.

This module is the single seam between AgentForge Red Team and the
GitLab REST API. The Documentation agent depends only on the
:class:`agentforge_redteam.agents.documentation.GitLabClientLike`
Protocol — its single method is::

    async def create_issue(*, title: str, body: str, labels: list[str]) -> GitLabIssueRef

We implement that Protocol against :class:`httpx.AsyncClient` (already a
hard dep — see :mod:`pyproject`). We deliberately do **not** add
``python-gitlab`` as a dependency: a single POST endpoint is not worth
the import-time cost or the dependency surface, and the project's
broader posture is to keep its external integration list minimal.

Design constraints (load-bearing — keep stable):

* **The factory never raises on missing config.** Dev, test, and
  offline CI lanes all run without a GitLab token. Returning ``None``
  lets the caller (typically the agent's wiring code) decide whether
  to swap in a stub or hard-fail; this module does not own that
  policy.

* **Errors include the GitLab response body.** A non-2xx response
  raises :class:`GitLabAPIError` with the response body embedded.
  GitLab's 4xx responses (rate limit, label permission, invalid
  project ID, expired token) all carry actionable error JSON; losing
  it to a generic ``HTTPError`` would force every operator to re-run
  the call with curl to diagnose. The error type stays a thin subclass
  of :class:`RuntimeError` so callers don't need to import the
  module just to ``except`` it.

* **PRIVATE-TOKEN, not Bearer.** GitLab supports both auth schemes but
  Personal Access Tokens (``glpat-...``) and Project Access Tokens are
  documented against the ``PRIVATE-TOKEN`` header. Using the documented
  header avoids subtle scope failures when the same token is used
  against self-hosted GitLab instances that have OAuth disabled.

* **Comma-separated labels.** The Issues API accepts the ``labels``
  parameter as either a comma-separated string or a JSON array
  depending on the GitLab version; the comma-separated form works on
  every version since 11.x, so we standardise on that.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Final

import httpx

from agentforge_redteam.agents.documentation import GitLabIssueRef

__all__ = [
    "DEFAULT_GITLAB_URL",
    "DEFAULT_TIMEOUT_S",
    "GITLAB_PROJECT_ID_ENV",
    "GITLAB_TOKEN_ENV",
    "GITLAB_URL_ENV",
    "GitLabAPIError",
    "GitLabClient",
    "GitLabConfig",
    "GitLabIssueRef",
    "create_gitlab_client",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GITLAB_TOKEN_ENV: Final[str] = "GITLAB_TOKEN"
GITLAB_PROJECT_ID_ENV: Final[str] = "GITLAB_PROJECT_ID"
GITLAB_URL_ENV: Final[str] = "GITLAB_URL"
DEFAULT_GITLAB_URL: Final[str] = "https://gitlab.com"
DEFAULT_TIMEOUT_S: Final[float] = 30.0


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class GitLabAPIError(RuntimeError):
    """Raised on any non-2xx response from the GitLab API.

    The exception message embeds the response status code and body
    text so the operator-facing log is sufficient to diagnose the
    failure without re-running the call. Inherits from
    :class:`RuntimeError` so callers that only need to log-and-skip
    don't need to import this module.
    """

    def __init__(self, *, status_code: int, body: str, url: str) -> None:
        self.status_code = status_code
        self.body = body
        self.url = url
        super().__init__(f"GitLab API error {status_code} from {url}: {body}")


# ---------------------------------------------------------------------------
# Config value object
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GitLabConfig:
    """Validated GitLab credentials, ready to hand to the client.

    ``project_id`` is stored as a ``str`` rather than an ``int`` so we
    can drop it straight into a URL path without parsing — GitLab also
    accepts URL-encoded path identifiers ("group%2Fproject") in this
    slot, which would not fit into an ``int``.
    """

    token: str
    project_id: str
    base_url: str = DEFAULT_GITLAB_URL

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> GitLabConfig | None:
        """Return a config iff BOTH token and project_id are set.

        Reads from ``env`` (for testability) or :data:`os.environ` when
        not provided. Either field being missing/empty yields ``None``
        — callers treat ``None`` as "fall back to stub or hard-fail",
        not as a typed error. The base URL defaults to
        :data:`DEFAULT_GITLAB_URL` (gitlab.com) when ``GITLAB_URL`` is
        absent.
        """
        source: dict[str, str] = dict(os.environ) if env is None else env
        token = source.get(GITLAB_TOKEN_ENV, "").strip()
        project_id = source.get(GITLAB_PROJECT_ID_ENV, "").strip()
        if not token or not project_id:
            return None
        base_url = source.get(GITLAB_URL_ENV, "").strip() or DEFAULT_GITLAB_URL
        return cls(token=token, project_id=project_id, base_url=base_url)


# ---------------------------------------------------------------------------
# Real client (httpx-backed)
# ---------------------------------------------------------------------------


class GitLabClient:
    """GitLab-backed implementation of :class:`GitLabClientLike`.

    Uses :class:`httpx.AsyncClient` for a single POST to
    ``/api/v4/projects/{id}/issues``. ``httpx`` is already a hard dep
    of the platform (HTTP transport for the kill-switch heartbeat and
    other agents), so we import it at module top — no lazy import
    needed.
    """

    __slots__ = ("_base_url", "_project_id", "_timeout_s", "_token")

    def __init__(
        self,
        *,
        token: str,
        project_id: str,
        base_url: str = DEFAULT_GITLAB_URL,
        timeout_s: float = DEFAULT_TIMEOUT_S,
    ) -> None:
        self._token = token
        self._project_id = project_id
        # Strip a trailing slash so we can construct paths by simple
        # concatenation regardless of how the operator wrote the URL.
        self._base_url = base_url.rstrip("/")
        self._timeout_s = timeout_s

    async def create_issue(self, *, title: str, body: str, labels: list[str]) -> GitLabIssueRef:
        """POST to the Issues API and return the created issue's ref.

        Construction details:

        * Endpoint: ``{base_url}/api/v4/projects/{project_id}/issues``
        * Header: ``PRIVATE-TOKEN: {token}``
        * Form params: ``title``, ``description=body``,
          ``labels`` as a comma-separated string.

        The response is expected to be ``201 Created`` carrying a JSON
        object with ``iid`` (project-scoped issue number) and
        ``web_url``. We surface those two fields as
        :class:`GitLabIssueRef`; any non-2xx response is converted to a
        :class:`GitLabAPIError` carrying the status code and body for
        diagnosis.
        """
        url = f"{self._base_url}/api/v4/projects/{self._project_id}/issues"
        payload = {
            "title": title,
            "description": body,
            "labels": ",".join(labels),
        }
        headers = {"PRIVATE-TOKEN": self._token}

        async with httpx.AsyncClient(timeout=self._timeout_s) as client:
            response = await client.post(url, data=payload, headers=headers)

        # Status guard: anything outside 2xx is an error worth surfacing
        # with the body attached. We don't use ``raise_for_status``
        # because its message drops the response body, which is exactly
        # what we need to diagnose GitLab 4xx returns.
        if not 200 <= response.status_code < 300:
            raise GitLabAPIError(
                status_code=response.status_code,
                body=response.text,
                url=url,
            )

        data: Any = response.json()
        if not isinstance(data, dict):
            raise GitLabAPIError(
                status_code=response.status_code,
                body=f"expected JSON object, got {type(data).__name__}: {response.text}",
                url=url,
            )

        iid = data.get("iid")
        web_url = data.get("web_url")
        if not isinstance(iid, int) or not isinstance(web_url, str):
            raise GitLabAPIError(
                status_code=response.status_code,
                body=(f"missing or malformed iid/web_url in response: {response.text}"),
                url=url,
            )

        return GitLabIssueRef(issue_id=iid, url=web_url)


# ---------------------------------------------------------------------------
# Public factory
# ---------------------------------------------------------------------------


def create_gitlab_client(
    env: dict[str, str] | None = None,
    *,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> GitLabClient | None:
    """Return a real :class:`GitLabClient` if config is set; else ``None``.

    The Documentation agent accepts a Protocol-typed client; a ``None``
    return lets the caller swap in a stub for offline / test lanes
    without this module owning that policy. There is no "no-op"
    fallback — a real run that ends with autofile routing requires a
    real client.

    The optional ``env`` parameter makes the factory deterministic in
    tests.
    """
    config = GitLabConfig.from_env(env)
    if config is None:
        return None
    return GitLabClient(
        token=config.token,
        project_id=config.project_id,
        base_url=config.base_url,
        timeout_s=timeout_s,
    )
