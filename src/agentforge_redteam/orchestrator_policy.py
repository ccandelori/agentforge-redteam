"""Loader for ``orchestrator_policy.yaml`` with content-addressed hashing.

The Orchestrator agent reads its engagement policy from a YAML file at
runtime. The policy controls:

* the target runs-per-sub_attack-per-week (drives the coverage-gap signal),
* the epsilon for the epsilon-greedy explorer,
* per-severity weights applied to the historical findings vector,
* the per-session and per-campaign budget caps,
* canary cadence.

Every load returns a :class:`OrchestratorPolicy` whose ``sha`` field is the
SHA-256 of the YAML file's on-disk bytes. The hash is stamped into
``run_manifests.policy_sha`` so a verdict is verifiably anchored to the exact
policy that produced its parent campaign — auditability over convenience.

The module is stdlib + pydantic + pyyaml only. We deliberately avoid
importing any other ``agentforge_redteam`` module so the policy can be loaded
from hot paths (the orchestrator node, the manifest builder) without import
cycles.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Final

import yaml
from pydantic import BaseModel, Field

DEFAULT_POLICY_PATH: Final[Path] = Path("orchestrator_policy.yaml")


class OrchestratorPolicy(BaseModel):
    """The validated, frozen view of ``orchestrator_policy.yaml``.

    ``sha`` is attached by the loader and is the SHA-256 of the on-disk
    bytes. Callers MUST NOT mutate fields after construction — Pydantic's
    ``frozen=True`` enforces this — because the SHA would silently disagree
    with the in-memory content otherwise, defeating the manifest binding.
    """

    model_config = {"frozen": True, "extra": "forbid"}

    version: int = Field(ge=1)
    target_runs_per_sub_attack_per_week: int = Field(gt=0)
    epsilon: float = Field(ge=0.0, le=1.0)
    severity_weights: dict[str, float] = Field(min_length=1)
    max_session_cost_cents: int = Field(gt=0)
    default_campaign_budget_cents: int = Field(gt=0)
    canary_every_n_campaigns: int = Field(gt=0)

    # ------------------------------------------------------------------
    # Optional Task 37 extensions. Every field here MUST default so the
    # existing repo ``orchestrator_policy.yaml`` still validates without
    # change.
    # ------------------------------------------------------------------

    # Per-category override for ``target_runs_per_sub_attack_per_week``.
    # Keyed by category (e.g. ``prompt-injection-indirect``). When a
    # category appears here the orchestrator uses this value as the target
    # for every sub_attack under that category; otherwise it falls back to
    # ``target_runs_per_sub_attack_per_week``.
    target_runs_per_category: dict[str, int] | None = None

    # Number of consecutive ``fail`` verdicts (most-recent window) that
    # triggers a ``no_progress`` halt. Five is a deliberately small default:
    # if the last five attempts in a session all failed, we are burning
    # budget on a category that's saturated — better to halt and let the
    # operator inspect than to keep grinding.
    no_progress_threshold: int = Field(default=5, gt=0)

    # Alias for ``max_session_cost_cents`` that matches the PRD wording.
    # The orchestrator uses ``max_session_cost_cents`` internally; this
    # field is here so a policy YAML may carry the PRD-named key without a
    # validation error. ``None`` means "no alias provided".
    cost_cap_default_cents: int | None = Field(default=None, gt=0)

    # Set by loader, not in YAML — hash of the file's bytes.
    sha: str = Field(min_length=64, max_length=64)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_policy(path: Path | str = DEFAULT_POLICY_PATH) -> OrchestratorPolicy:
    """Read ``path``, validate, and attach the file-bytes SHA.

    A missing or unreadable file propagates :class:`FileNotFoundError` /
    :class:`OSError`. Schema violations propagate
    :class:`pydantic.ValidationError`. We do not silently substitute a
    default policy — a broken policy must surface loudly before any
    campaign runs.
    """
    p = Path(path)
    raw = p.read_bytes()
    sha = _sha256_hex(raw)

    # ``yaml.safe_load`` only — never ``yaml.load``. The policy file is in
    # the repo but the loader runs after a deploy could have shipped a
    # tampered copy; we never let YAML instantiate arbitrary Python
    # objects.
    data = yaml.safe_load(raw)
    if not isinstance(data, dict):
        # Force a clean ValidationError rather than a TypeError from
        # model_validate on a non-dict.
        data = {"__root__": data}
    data["sha"] = sha
    return OrchestratorPolicy.model_validate(data)
