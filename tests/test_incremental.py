"""Tests du mode incrémental --since-last-scrub (offset par-fichier)."""
from __future__ import annotations

from pathlib import Path

from secret_scrubber.cli import build_parser, read_state, run

AWS = "AKIAIOSFODNN7EXAMPLE"  # clé d'exemple AWS (matche aws-access-key)


def _args(root: Path, wm: Path):
    return build_parser().parse_args(
        [
            "apply",
            "--scope",
            "safe",
            "--since-last-scrub",
            "--watermark-file",
            str(wm),
            "--root",
            str(root),
            "--report",
            "none",
        ]
    )


def test_incremental_scans_only_appended_lines(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    wm = tmp_path / "wm.json"
    f = root / "session.jsonl"
    f.write_text('{"t":"a"}\n{"t":"b"}\n{"t":"c"}\n', encoding="utf-8")

    # Passe 1 : fichier propre → 3 lignes scannées, état persisté.
    s1 = run(_args(root, wm))
    assert s1.scanned == 1
    assert s1.tail_lines == 3
    assert s1.findings == 0
    assert str(f) in read_state(wm)

    # Append d'une ligne AVEC secret.
    with f.open("a", encoding="utf-8") as fh:
        fh.write(f'{{"t":"ma cle {AWS} fin"}}\n')

    # Passe 2 : SEULE la ligne ajoutée est (re)scannée, le secret est attrapé.
    s2 = run(_args(root, wm))
    assert s2.tail_lines == 1, "doit ne scanner que la queue, pas les 4 lignes"
    assert s2.findings == 1
    body = f.read_text(encoding="utf-8")
    assert AWS not in body, "secret de la queue masqué"
    assert '{"t":"a"}' in body, "début intact (non re-traité)"

    # Passe 3 : rien changé → skip sans lecture.
    s3 = run(_args(root, wm))
    assert s3.scanned == 0
    assert s3.skipped_unchanged == 1


def test_shrink_triggers_full_rescan(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    wm = tmp_path / "wm.json"
    f = root / "s.jsonl"
    f.write_text('{"t":"x"}\n{"t":"y"}\n{"t":"z"}\n', encoding="utf-8")
    run(_args(root, wm))

    # Réécriture plus courte contenant un secret dès le début → rescan complet.
    f.write_text(f'{{"t":"{AWS}"}}\n', encoding="utf-8")
    s = run(_args(root, wm))
    assert s.findings == 1
    assert AWS not in f.read_text(encoding="utf-8")
