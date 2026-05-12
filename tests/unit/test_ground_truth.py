"""Tests for :mod:`agentforge_redteam.ground_truth` and the ``ground-truth`` CLI.

The data-layer tests exercise the Pydantic model and the YAML round-trip
directly. The CLI tests drive :class:`typer.testing.CliRunner` with scripted
stdin to walk the interactive ``new`` flow end-to-end, asserting against the
written YAML file on disk.

The CLI tests use ``--root`` and ``--rubrics-dir`` options rather than
``monkeypatch``\\ ing ``GROUND_TRUTH_ROOT`` because:

* Typer parses options *before* the command body, so we get the override at
  the right boundary.
* It keeps the test fixture stateless — no env-var bleed, no module-attr
  bleed, just CLI args.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError
from typer.testing import CliRunner

from agentforge_redteam.cli import app
from agentforge_redteam.ground_truth import (
    GroundTruthCase,
    case_path,
    read_case,
    write_case,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
REAL_RUBRICS_DIR = REPO_ROOT / "rubrics"
EXAMPLE_CATEGORY = "prompt-injection-indirect"

# Per the example rubric this is the count and ordering of checks the CLI
# will prompt for. Keep these in lock-step with the rubric file.
EXAMPLE_CHECK_NAMES = (
    "marker_token_reproduced",
    "citation_to_nonexistent_source",
    "system_prompt_revealed",
    "agent_took_unauthorized_action",
    "response_contains_other_patient_phi",
)

runner = CliRunner()


# ---------------------------------------------------------------------------
# Data-layer tests
# ---------------------------------------------------------------------------


def test_groundtruthcase_rejects_confidence_above_one() -> None:
    with pytest.raises(ValidationError):
        GroundTruthCase(
            category="x",
            attack_input="a",
            target_response="",
            expected_verdict="pass",
            confidence=1.5,
        )


def test_groundtruthcase_rejects_unknown_verdict() -> None:
    with pytest.raises(ValidationError):
        GroundTruthCase(
            category="x",
            attack_input="a",
            target_response="",
            expected_verdict="maybe",  # type: ignore[arg-type]
            confidence=0.5,
        )


def test_groundtruthcase_accepts_minimal_valid_case() -> None:
    case = GroundTruthCase(
        category="x",
        attack_input="a",
        target_response="",
        expected_verdict="pass",
        confidence=0.5,
    )
    assert case.category == "x"
    assert case.rubric_outcomes == {}
    assert case.notes == ""


def test_case_path_layout(tmp_path: Path) -> None:
    case = GroundTruthCase(
        category="alpha",
        attack_input="a",
        target_response="",
        expected_verdict="pass",
        confidence=0.5,
    )
    expected = tmp_path / "alpha" / f"{case.case_id}.yaml"
    assert case_path(case, root=tmp_path) == expected


def test_write_case_creates_parent_dirs_and_writes_yaml(tmp_path: Path) -> None:
    case = GroundTruthCase(
        category="alpha",
        attack_input="prompt",
        target_response="resp",
        expected_verdict="fail",
        confidence=0.9,
        rubric_outcomes={"check_a": True},
        notes="why this case",
    )
    path = write_case(case, root=tmp_path)
    assert path.exists()
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert payload["category"] == "alpha"
    assert payload["expected_verdict"] == "fail"
    assert payload["confidence"] == 0.9
    assert payload["rubric_outcomes"] == {"check_a": True}
    assert payload["case_id"] == str(case.case_id)
    # created_at must be stable ISO with a 'Z' suffix for diff-friendliness.
    assert payload["created_at"].endswith("Z")


def test_write_case_refuses_to_overwrite(tmp_path: Path) -> None:
    case = GroundTruthCase(
        category="alpha",
        attack_input="a",
        target_response="",
        expected_verdict="pass",
        confidence=0.5,
    )
    write_case(case, root=tmp_path)
    with pytest.raises(FileExistsError):
        write_case(case, root=tmp_path)


def test_read_case_round_trips(tmp_path: Path) -> None:
    case = GroundTruthCase(
        category="alpha",
        attack_input="prompt",
        target_response="resp",
        expected_verdict="partial",
        confidence=0.42,
        rubric_outcomes={"a": True, "b": False},
        notes="round-trip",
    )
    path = write_case(case, root=tmp_path)
    loaded = read_case(path)
    assert loaded == case


def test_read_case_rejects_malformed_yaml(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("category: x\n", encoding="utf-8")  # missing required fields
    with pytest.raises(ValidationError):
        read_case(bad)


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------


def _new_input(
    *,
    category: str = EXAMPLE_CATEGORY,
    attack: str = "attack line 1\nattack line 2",
    response: str = "response line 1",
    verdict: str = "pass",
    confidence: str = "0.9",
    outcomes: tuple[str, ...] = ("y", "n", "n", "n", "n"),
    notes: str = "operator notes",
    verdict_retries: tuple[str, ...] = (),
    confidence_retries: tuple[str, ...] = (),
) -> str:
    """Build a scripted-stdin payload for ``ground-truth new``.

    The flow expects, in order:
      1. category (one line)
      2. attack_input (one line per content line + a blank line)
      3. target_response (one line per content line + a blank line)
      4. zero or more invalid verdicts (each retried) then a valid verdict
      5. zero or more invalid confidences then a valid confidence
      6. one y/N per rubric check (5 for the example rubric)
      7. notes (one line)
    """
    parts: list[str] = [category]
    parts.extend(attack.split("\n"))
    parts.append("")  # end attack
    parts.extend(response.split("\n"))
    parts.append("")  # end response
    parts.extend(verdict_retries)
    parts.append(verdict)
    parts.extend(confidence_retries)
    parts.append(confidence)
    parts.extend(outcomes)
    parts.append(notes)
    # Trailing newline so the final prompt gets its line terminator.
    return "\n".join(parts) + "\n"


def _written_case_path(root: Path, category: str = EXAMPLE_CATEGORY) -> Path:
    """Return the single YAML file written under ``root / category``."""
    category_dir = root / category
    cases = sorted(category_dir.glob("*.yaml"))
    assert len(cases) == 1, f"Expected exactly one case file, found {cases}"
    return cases[0]


def test_cli_new_writes_yaml_under_root(tmp_path: Path) -> None:
    root = tmp_path / "evals" / "judge_ground_truth"
    result = runner.invoke(
        app,
        [
            "ground-truth",
            "new",
            "--root",
            str(root),
            "--rubrics-dir",
            str(REAL_RUBRICS_DIR),
        ],
        input=_new_input(),
    )
    assert result.exit_code == 0, result.output

    path = _written_case_path(root)
    case = read_case(path)
    assert case.category == EXAMPLE_CATEGORY
    assert case.attack_input == "attack line 1\nattack line 2"
    assert case.target_response == "response line 1"
    assert case.expected_verdict == "pass"
    assert case.confidence == pytest.approx(0.9)
    assert case.rubric_outcomes == {
        "marker_token_reproduced": True,
        "citation_to_nonexistent_source": False,
        "system_prompt_revealed": False,
        "agent_took_unauthorized_action": False,
        "response_contains_other_patient_phi": False,
    }
    assert case.notes == "operator notes"


def test_cli_new_reprompts_on_invalid_verdict(tmp_path: Path) -> None:
    root = tmp_path / "evals" / "judge_ground_truth"
    result = runner.invoke(
        app,
        [
            "ground-truth",
            "new",
            "--root",
            str(root),
            "--rubrics-dir",
            str(REAL_RUBRICS_DIR),
        ],
        input=_new_input(verdict="fail", verdict_retries=("maybe",)),
    )
    assert result.exit_code == 0, result.output
    assert "Invalid" in result.output
    case = read_case(_written_case_path(root))
    assert case.expected_verdict == "fail"


def test_cli_new_reprompts_on_invalid_confidence(tmp_path: Path) -> None:
    root = tmp_path / "evals" / "judge_ground_truth"
    result = runner.invoke(
        app,
        [
            "ground-truth",
            "new",
            "--root",
            str(root),
            "--rubrics-dir",
            str(REAL_RUBRICS_DIR),
        ],
        input=_new_input(
            confidence="0.5",
            confidence_retries=("1.5", "not a number"),
        ),
    )
    assert result.exit_code == 0, result.output
    output_lower = result.output.lower()
    assert "out of range" in output_lower or "invalid" in output_lower
    case = read_case(_written_case_path(root))
    assert case.confidence == pytest.approx(0.5)


def test_cli_new_errors_when_no_rubrics(tmp_path: Path) -> None:
    """Empty rubrics directory: ``new`` must exit non-zero with a hint."""
    empty_rubrics = tmp_path / "rubrics_empty"
    empty_rubrics.mkdir()
    result = runner.invoke(
        app,
        [
            "ground-truth",
            "new",
            "--root",
            str(tmp_path / "evals"),
            "--rubrics-dir",
            str(empty_rubrics),
        ],
        input="",
    )
    assert result.exit_code == 1
    assert "No rubrics" in result.output


def test_cli_list_empty_dir(tmp_path: Path) -> None:
    root = tmp_path / "evals" / "judge_ground_truth"
    result = runner.invoke(app, ["ground-truth", "list", "--root", str(root)])
    assert result.exit_code == 0, result.output
    assert "no cases yet" in result.output


def test_cli_list_shows_summary_after_new(tmp_path: Path) -> None:
    root = tmp_path / "evals" / "judge_ground_truth"
    new_result = runner.invoke(
        app,
        [
            "ground-truth",
            "new",
            "--root",
            str(root),
            "--rubrics-dir",
            str(REAL_RUBRICS_DIR),
        ],
        input=_new_input(),
    )
    assert new_result.exit_code == 0, new_result.output

    case = read_case(_written_case_path(root))
    list_result = runner.invoke(app, ["ground-truth", "list", "--root", str(root)])
    assert list_result.exit_code == 0, list_result.output
    out = list_result.output
    assert str(case.case_id)[:8] in out
    assert EXAMPLE_CATEGORY in out
    assert "pass" in out
    assert "conf=0.90" in out


def test_cli_list_filters_by_category(tmp_path: Path) -> None:
    root = tmp_path / "evals" / "judge_ground_truth"
    new_result = runner.invoke(
        app,
        [
            "ground-truth",
            "new",
            "--root",
            str(root),
            "--rubrics-dir",
            str(REAL_RUBRICS_DIR),
        ],
        input=_new_input(),
    )
    assert new_result.exit_code == 0, new_result.output

    # Same category: case is listed.
    hit = runner.invoke(
        app,
        ["ground-truth", "list", "--root", str(root), "--category", EXAMPLE_CATEGORY],
    )
    assert hit.exit_code == 0
    assert EXAMPLE_CATEGORY in hit.output
    assert "no cases yet" not in hit.output

    # Different (non-existent) category: empty output.
    miss = runner.invoke(
        app,
        ["ground-truth", "list", "--root", str(root), "--category", "no-such-cat"],
    )
    assert miss.exit_code == 0
    assert "no cases yet" in miss.output
