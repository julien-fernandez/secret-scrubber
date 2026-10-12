"""Le rapport compte des VALEURS, pas des occurrences : une clé recopiée est un problème."""
from __future__ import annotations

from secret_scrubber.cli import RunStats, build_parser, main
from secret_scrubber.detect import build_rules, digest, find_in_text

KEY_A = "sk-proj-Ab3xK9mQ7wL2pR5tY8vN1cD4fG6hJ0sZ"
KEY_B = "sk-proj-Zz9yX8wV7uT6sR5qP4oN3mL2kJ1hG0fE"


def _digests(text: str) -> set[str]:
    rules = [r for r in build_rules([]) if r.rule_id == "openai-api-key"]
    return {f.digest for f in find_in_text(text, rules)}


def test_same_value_twice_is_one_digest():
    assert len(_digests(f"a={KEY_A}\nb={KEY_A}\n")) == 1


def test_two_values_are_two_digests():
    assert len(_digests(f"a={KEY_A}\nb={KEY_B}\n")) == 2


def test_digest_never_carries_the_value():
    d = digest(KEY_A)
    assert KEY_A not in d
    assert KEY_A[:8] not in d
    assert len(d) == 8


def test_stats_separate_occurrences_from_values():
    stats = RunStats()
    stats.note_value("openai-api-key", "aaaaaaaa", "f1.md")
    stats.note_value("openai-api-key", "aaaaaaaa", "f2.md")
    stats.note_value("openai-api-key", "bbbbbbbb", "f1.md")
    assert stats.distinct_values == 2
    assert len(stats.digests_by_rule["openai-api-key"]) == 2
    assert stats.files_by_digest["aaaaaaaa"] == {"f1.md", "f2.md"}


def test_report_counts_values_not_occurrences(tmp_path, capsys):
    doc = tmp_path / "notes.md"
    doc.write_text(f"un {KEY_A}\ndeux {KEY_A}\ntrois {KEY_A}\n", encoding="utf-8")
    assert main(["scan", "--root", str(tmp_path), "--report", "text"]) == 0
    out = capsys.readouterr().out
    assert "1 valeur(s) distincte(s)" in out
    assert "3 occurrence(s)" in out
    assert KEY_A not in out


def test_parser_still_accepts_git_tracked():
    assert build_parser().parse_args(["scan", "--git-tracked"]).git_tracked is True
