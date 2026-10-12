"""Le corpus `--git-tracked` doit être exact, et échouer bruyamment plutôt que vide."""
from __future__ import annotations

import subprocess

import pytest

from secret_scrubber.cli import (
    GitTrackedError,
    build_parser,
    git_tracked_files,
    iter_target_files,
    main,
)


def _init_repo(root):
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "t@t"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "t"], check=True)


def _commit_all(root):
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "init"], check=True)


def test_returns_tracked_only(tmp_path):
    _init_repo(tmp_path)
    (tmp_path / "kept.md").write_text("suivi", encoding="utf-8")
    (tmp_path / ".gitignore").write_text("ignored.md\n", encoding="utf-8")
    (tmp_path / "ignored.md").write_text("ignoré", encoding="utf-8")
    _commit_all(tmp_path)

    names = {p.name for p in git_tracked_files(tmp_path)}
    assert "kept.md" in names
    assert "ignored.md" not in names


def test_covers_extensions_the_tree_walk_skips(tmp_path):
    """Un secret dans un .py doit être vu : le filtre d'extension ne vaut que hors git."""
    _init_repo(tmp_path)
    (tmp_path / "app.py").write_text("KEY = 'x'", encoding="utf-8")
    _commit_all(tmp_path)

    tracked = git_tracked_files(tmp_path)
    assert {p.name for p in iter_target_files(tmp_path, [], None, tracked)} == {"app.py"}
    assert "app.py" not in {p.name for p in iter_target_files(tmp_path, [], None, None)}


def test_raises_outside_a_repo(tmp_path):
    (tmp_path / "orphan.md").write_text("pas de dépôt", encoding="utf-8")
    with pytest.raises(GitTrackedError):
        git_tracked_files(tmp_path)


def test_raises_on_empty_corpus(tmp_path):
    """Un dépôt sans fichier suivi rendrait findings=0 sans avoir rien lu."""
    _init_repo(tmp_path)
    with pytest.raises(GitTrackedError):
        git_tracked_files(tmp_path)


def test_cli_exits_2_instead_of_reporting_ras(tmp_path, capsys):
    args = build_parser().parse_args(
        ["scan", "--root", str(tmp_path), "--git-tracked", "--report", "text"]
    )
    assert main(
        ["scan", "--root", str(tmp_path), "--git-tracked", "--report", "text"]
    ) == 2
    assert args.git_tracked is True
    assert "RAS" not in capsys.readouterr().out
