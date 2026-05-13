"""Unit tests for :mod:`agentforge_redteam.rubrics.loader`.

The happy-path tests use the committed fixture at
``tests/fixtures/rubrics/example.yaml`` so production ``rubrics/`` stays
authoritative for real category files (authored in tasks 19/20/21).
Negative paths build throwaway rubric directories in ``tmp_path``.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from pydantic import ValidationError

from agentforge_redteam.rubrics.loader import (
    Rubric,
    RubricCheck,
    RubricNotFoundError,
    VerdictSchemaShape,
    load_all_rubrics,
    load_rubric,
    rubric_set_sha,
)

REAL_RUBRIC_PATH = Path("tests/fixtures/rubrics/example.yaml")
FIXTURE_RUBRICS_DIR = REAL_RUBRIC_PATH.parent
EXPECTED_SUB_ATTACKS = [
    "marker_token_reproduction",
    "citation_fabrication",
    "unauthorized_action",
]
EXPECTED_CHECK_NAMES = [
    "marker_token_present",
    "instruction_followed_against_policy",
    "phi_leaked_other_patient",
]
EXPECTED_SEVERITY_MAP = {
    "patient_harm_possible": "P0",
    "unauthorized_action_taken": "P1",
    "phi_disclosed_cross_patient": "P1",
    "partial_injection_success": "P2",
}


def _copy_real_rubric_into(tmp_path: Path) -> Path:
    """Mirror the committed example rubric into a tmp rubrics dir."""
    rubrics_dir = tmp_path / "rubrics"
    rubrics_dir.mkdir()
    shutil.copy(REAL_RUBRIC_PATH, rubrics_dir / "example.yaml")
    return rubrics_dir


def test_load_rubric_returns_version_one_zero_zero() -> None:
    rubric = load_rubric("prompt-injection-indirect", rubrics_dir=FIXTURE_RUBRICS_DIR)
    assert isinstance(rubric, Rubric)
    assert rubric.version == "1.0.0"


def test_load_rubric_returns_expected_sub_attacks_in_order() -> None:
    rubric = load_rubric("prompt-injection-indirect", rubrics_dir=FIXTURE_RUBRICS_DIR)
    assert rubric.sub_attacks == EXPECTED_SUB_ATTACKS


def test_load_rubric_returns_three_checks_with_expected_names() -> None:
    rubric = load_rubric("prompt-injection-indirect", rubrics_dir=FIXTURE_RUBRICS_DIR)
    assert len(rubric.checks) == 3
    assert [c.name for c in rubric.checks] == EXPECTED_CHECK_NAMES


def test_load_rubric_severity_map_contains_all_four_canonical_outcomes() -> None:
    rubric = load_rubric("prompt-injection-indirect", rubrics_dir=FIXTURE_RUBRICS_DIR)
    assert dict(rubric.severity_map) == EXPECTED_SEVERITY_MAP


def test_load_rubric_sha_is_64_char_lowercase_hex() -> None:
    rubric = load_rubric("prompt-injection-indirect", rubrics_dir=FIXTURE_RUBRICS_DIR)
    assert len(rubric.sha) == 64
    assert all(c in "0123456789abcdef" for c in rubric.sha)


def test_load_rubric_is_deterministic_across_repeat_calls() -> None:
    first = load_rubric("prompt-injection-indirect", rubrics_dir=FIXTURE_RUBRICS_DIR)
    second = load_rubric("prompt-injection-indirect", rubrics_dir=FIXTURE_RUBRICS_DIR)
    assert first.sha == second.sha


def test_editing_rubric_file_changes_sha(tmp_path: Path) -> None:
    rubrics_dir = _copy_real_rubric_into(tmp_path)
    original = load_rubric("prompt-injection-indirect", rubrics_dir=rubrics_dir)

    # Single-character whitespace tweak — must still parse, must change SHA.
    target = rubrics_dir / "example.yaml"
    target.write_text(target.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    edited = load_rubric("prompt-injection-indirect", rubrics_dir=rubrics_dir)
    assert edited.sha != original.sha


def test_load_rubric_missing_category_raises_rubric_not_found() -> None:
    with pytest.raises(RubricNotFoundError) as excinfo:
        load_rubric("not-a-real-category", rubrics_dir=FIXTURE_RUBRICS_DIR)
    # Must remain a FileNotFoundError subclass so existing handlers still work.
    assert isinstance(excinfo.value, FileNotFoundError)


def test_load_all_rubrics_returns_at_least_one_entry_keyed_by_category() -> None:
    all_rubrics = load_all_rubrics(rubrics_dir=FIXTURE_RUBRICS_DIR)
    assert len(all_rubrics) >= 1
    assert "prompt-injection-indirect" in all_rubrics
    assert all_rubrics["prompt-injection-indirect"].version == "1.0.0"


def test_load_all_rubrics_ignores_non_yaml_files(tmp_path: Path) -> None:
    rubrics_dir = _copy_real_rubric_into(tmp_path)
    (rubrics_dir / "notes.md").write_text("not a rubric", encoding="utf-8")
    (rubrics_dir / "SCHEMA.md").write_text("not a rubric", encoding="utf-8")

    result = load_all_rubrics(rubrics_dir=rubrics_dir)
    assert set(result.keys()) == {"prompt-injection-indirect"}


def test_rubric_set_sha_is_64_char_lowercase_hex() -> None:
    sha = rubric_set_sha(rubrics_dir=FIXTURE_RUBRICS_DIR)
    assert len(sha) == 64
    assert all(c in "0123456789abcdef" for c in sha)


def test_rubric_set_sha_is_deterministic() -> None:
    assert rubric_set_sha(rubrics_dir=FIXTURE_RUBRICS_DIR) == rubric_set_sha(
        rubrics_dir=FIXTURE_RUBRICS_DIR
    )


def test_rubric_set_sha_changes_when_any_rubric_changes(tmp_path: Path) -> None:
    rubrics_dir = _copy_real_rubric_into(tmp_path)
    # Add a second rubric so we know the set hash is genuinely a set property.
    second_yaml = (rubrics_dir / "example.yaml").read_text(encoding="utf-8")
    second_yaml = second_yaml.replace(
        "category: prompt-injection-indirect",
        "category: tool-misuse",
    )
    (rubrics_dir / "tool-misuse.yaml").write_text(second_yaml, encoding="utf-8")

    before = rubric_set_sha(rubrics_dir=rubrics_dir)

    # Touch only the first rubric.
    first = rubrics_dir / "example.yaml"
    first.write_text(first.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    after = rubric_set_sha(rubrics_dir=rubrics_dir)
    assert before != after


def test_rubric_rejects_empty_sub_attacks() -> None:
    with pytest.raises(ValidationError):
        Rubric(
            version="1.0.0",
            category="prompt-injection-indirect",
            sub_attacks=[],
            verdict_schema=VerdictSchemaShape(
                verdict=["pass"],
                confidence="float",
                evidence_refs="list[str]",
                notes="str",
            ),
            checks=[
                RubricCheck(
                    name="c",
                    type="deterministic",
                    criteria="x",
                    severity_contribution="partial_injection_success",
                )
            ],
            severity_map={"partial_injection_success": "P2"},
            sha="a" * 64,
            raw_text="<test fixture>",
        )


def test_rubric_rejects_empty_version_string() -> None:
    with pytest.raises(ValidationError):
        Rubric(
            version="",
            category="prompt-injection-indirect",
            sub_attacks=["x"],
            verdict_schema=VerdictSchemaShape(
                verdict=["pass"],
                confidence="float",
                evidence_refs="list[str]",
                notes="str",
            ),
            checks=[
                RubricCheck(
                    name="c",
                    type="deterministic",
                    criteria="x",
                    severity_contribution="partial_injection_success",
                )
            ],
            severity_map={"partial_injection_success": "P2"},
            sha="a" * 64,
            raw_text="<test fixture>",
        )


def test_rubric_check_rejects_unknown_type_literal() -> None:
    with pytest.raises(ValidationError):
        RubricCheck(
            name="c",
            type="unknown",  # type: ignore[arg-type]
            criteria="x",
            severity_contribution="partial_injection_success",
        )


def test_rubric_rejects_extra_top_level_field(tmp_path: Path) -> None:
    rubrics_dir = _copy_real_rubric_into(tmp_path)
    target = rubrics_dir / "example.yaml"
    target.write_text(
        target.read_text(encoding="utf-8") + "\nrogue_field: 1\n",
        encoding="utf-8",
    )
    with pytest.raises(ValidationError):
        load_rubric("prompt-injection-indirect", rubrics_dir=rubrics_dir)


def test_rubric_rejects_severity_value_outside_p0_p3(tmp_path: Path) -> None:
    rubrics_dir = _copy_real_rubric_into(tmp_path)
    target = rubrics_dir / "example.yaml"
    text = target.read_text(encoding="utf-8")
    # Promote partial_injection_success from P2 to the bogus P4.
    text = text.replace("partial_injection_success: P2", "partial_injection_success: P4")
    target.write_text(text, encoding="utf-8")
    with pytest.raises(ValidationError):
        load_rubric("prompt-injection-indirect", rubrics_dir=rubrics_dir)
