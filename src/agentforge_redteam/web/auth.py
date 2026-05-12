"""BasicAuth dependency for the operator UI.

The web UI is reachable by anyone who can hit the listening port. Every JSON
endpoint guards itself with :func:`require_operator`, which checks the
``Authorization: Basic ...`` header against the credentials wired into the
process via two environment variables:

* ``WEB_UI_USER`` — defaults to ``"operator"`` so dev/CI lanes do not need to
  set it.
* ``WEB_UI_PASSWORD`` — when set, BasicAuth is enforced and a missing /
  wrong credential yields ``401`` with a ``WWW-Authenticate`` challenge so
  curl / browser clients prompt for credentials. When **unset**, BasicAuth
  is DISABLED and the dependency returns the default user. This is a
  deliberate dev-mode escape hatch; the deploy task (Task 48) asserts that
  ``WEB_UI_PASSWORD`` is set in any production-shaped environment.

Comparisons go through :func:`secrets.compare_digest` to keep timing
side channels closed. Both username and password are compared, because
leaking the username via a fast-fail short-circuit would be just as bad
as leaking the password.
"""

from __future__ import annotations

import os
import secrets
from typing import Annotated, Final

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

__all__ = [
    "DEFAULT_USER",
    "WEB_UI_PASSWORD_ENV",
    "WEB_UI_USER_ENV",
    "require_operator",
]

WEB_UI_USER_ENV: Final[str] = "WEB_UI_USER"
WEB_UI_PASSWORD_ENV: Final[str] = "WEB_UI_PASSWORD"
DEFAULT_USER: Final[str] = "operator"

# ``auto_error=False`` so we can produce our own 401 with the right
# ``WWW-Authenticate`` challenge — FastAPI's default treats *missing*
# credentials as 403, which is wrong for BasicAuth where the response is
# meant to invite re-authentication.
basic_auth = HTTPBasic(auto_error=False)


def require_operator(
    credentials: Annotated[HTTPBasicCredentials | None, Depends(basic_auth)],
) -> str:
    """Verify BasicAuth credentials against env vars.

    If ``WEB_UI_PASSWORD`` is not set, authentication is DISABLED and the
    dependency returns :data:`DEFAULT_USER` — useful for local dev.
    Production deployments MUST set ``WEB_UI_PASSWORD``; the deploy task
    asserts this.

    Returns the authenticated username. Raises :class:`HTTPException` 401
    with a ``WWW-Authenticate: Basic`` header on missing or bad creds.
    """
    expected_password = os.environ.get(WEB_UI_PASSWORD_ENV, "")
    if not expected_password:
        # Dev mode: no password configured, accept anonymous callers.
        return DEFAULT_USER

    expected_user = os.environ.get(WEB_UI_USER_ENV, DEFAULT_USER)

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    # Encode both sides for compare_digest, which requires equal-length byte
    # strings. We always compare both fields so a wrong username and wrong
    # password take the same amount of time to fail.
    user_ok = secrets.compare_digest(
        credentials.username.encode("utf-8"),
        expected_user.encode("utf-8"),
    )
    password_ok = secrets.compare_digest(
        credentials.password.encode("utf-8"),
        expected_password.encode("utf-8"),
    )
    if not (user_ok and password_ok):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username
