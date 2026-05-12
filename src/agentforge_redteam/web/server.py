"""Tiny uvicorn launcher for the operator UI.

A follow-up CLI task wires ``agentforge-redteam web`` to call
:func:`run` so an operator can boot the UI without remembering the
uvicorn flag set. We read ``WEB_UI_HOST`` / ``WEB_UI_PORT`` so the deploy
task can override these without code changes.
"""

from __future__ import annotations

import os

import uvicorn

from agentforge_redteam.web.app import app

__all__ = ["run"]


def run() -> None:
    """Run uvicorn with sensible defaults.

    ``WEB_UI_HOST`` defaults to ``127.0.0.1`` — the loopback interface —
    so a fresh install does not accidentally expose the API on a public
    NIC. The deploy task overrides this to ``0.0.0.0`` once it has
    confirmed the surrounding network rules.
    """
    host = os.environ.get("WEB_UI_HOST", "127.0.0.1")
    port = int(os.environ.get("WEB_UI_PORT", "8080"))
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":  # pragma: no cover - manual launch
    run()
