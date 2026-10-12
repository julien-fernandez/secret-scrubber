"""Tests du garde-fou de sélection de règles : jamais de scan à blanc silencieux."""
from __future__ import annotations

from pathlib import Path

import pytest

from secret_scrubber.cli import RuleSelectionError, build_parser, main, run


def _args(root: Path, *extra: str):
    return build_parser().parse_args(
        ["scan", "--root", str(root), "--report", "none", *extra]
    )


def test_unknown_rule_name_raises(tmp_path: Path) -> None:
    with pytest.raises(RuleSelectionError) as exc:
        run(_args(tmp_path, "--rules", "github"))

    assert "github" in str(exc.value)
    assert "github-token" in str(exc.value)


def test_unknown_excluded_rule_name_raises(tmp_path: Path) -> None:
    with pytest.raises(RuleSelectionError):
        run(_args(tmp_path, "--exclude-rules", "gitub-token"))


def test_literal_scope_without_literal_raises(tmp_path: Path) -> None:
    with pytest.raises(RuleSelectionError):
        run(_args(tmp_path, "--scope", "literal"))


def test_known_rule_name_is_accepted(tmp_path: Path) -> None:
    stats = run(_args(tmp_path, "--rules", "github-token"))

    assert stats.findings == 0


def test_main_returns_2_on_empty_selection(tmp_path: Path, capsys) -> None:
    code = main(["scan", "--root", str(tmp_path), "--report", "none", "--rules", "github"])

    assert code == 2
    assert "ERREUR" in capsys.readouterr().err
