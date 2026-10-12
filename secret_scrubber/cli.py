"""Interface en ligne de commande : `secret-scrubber scan|apply`."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from .detect import Finding, build_rules, find_in_text, known_rule_ids
from .redact import atomic_write, redact_content
from .wcm import read_credential

SCANNED_EXTENSIONS = (".jsonl", ".json", ".txt", ".md", ".log")
NOISY_RULES = ("env-secret", "database-url")  # forts taux de faux positifs
DEFAULT_WATERMARK = Path.home() / ".secret-scrubber" / "last-scrub.json"


def read_state(path: Path) -> dict[str, dict]:
    """État par-fichier du dernier apply réussi : {abs_path: {lines, mtime, size}}.

    `lines` = nombre de lignes déjà scannées. Un transcript JSONL est append-only
    → au prochain passage on ne scanne QUE les lignes ajoutées (offset), pas tout
    le fichier. Renvoie {} si absent/illisible ou format legacy (v1 timestamp)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        files = data.get("files")
        return files if isinstance(files, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def write_state(path: Path, files: dict[str, dict]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"version": 2, "files": files}), encoding="utf-8")
    except OSError as exc:
        print(f"[scrub] watermark non écrit ({exc})", file=sys.stderr)


@dataclass
class RunStats:
    scanned: int = 0
    hit_files: int = 0
    findings: int = 0
    locked: int = 0
    skipped_unchanged: int = 0  # fichiers inchangés depuis le dernier scrub (stat seule)
    tail_lines: int = 0  # lignes réellement (re)scannées (offset incrémental)
    per_rule: dict[str, int] = field(default_factory=dict)
    touched: list[str] = field(default_factory=list)
    files_by_digest: dict[str, set[str]] = field(default_factory=dict)
    digests_by_rule: dict[str, set[str]] = field(default_factory=dict)

    def note_value(self, rule_id: str, value_digest: str, path: str) -> None:
        """Rattache une occurrence à sa VALEUR — une clé recopiée n'est qu'un problème."""
        self.files_by_digest.setdefault(value_digest, set()).add(path)
        self.digests_by_rule.setdefault(rule_id, set()).add(value_digest)

    @property
    def distinct_values(self) -> int:
        return len(self.files_by_digest)


class GitTrackedError(Exception):
    """Corpus git indisponible : scanner tout, ou rien, rendrait un verdict trompeur."""


def git_tracked_files(root: Path) -> set[Path]:
    """Fichiers suivis par git sous `root` — le corpus committé ou committable.

    Échoue bruyamment plutôt que de rendre un corpus vide : un `findings=0` obtenu
    sans avoir rien lu est indiscernable d'un vrai « rien à masquer »."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=False
        )
    except OSError as exc:
        raise GitTrackedError(f"git inutilisable sur {root} ({exc})") from exc
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace").strip()
        raise GitTrackedError(
            f"`git ls-files` a échoué sur {root} : {detail or f'code {proc.returncode}'}"
        )
    names = [n for n in proc.stdout.decode("utf-8", "replace").split("\0") if n]
    if not names:
        raise GitTrackedError(
            f"aucun fichier suivi par git sous {root} — un findings=0 ne prouverait rien"
        )
    return {(root / name) for name in names}


def iter_target_files(
    root: Path,
    exclude_globs: list[str],
    min_mtime: float | None = None,
    tracked: Iterable[Path] | None = None,
) -> Iterator[Path]:
    """Fichiers à examiner. `tracked` fourni → ce corpus exact, sans parcours d'arbre.

    Le filtre d'extension ne s'applique qu'au parcours d'arbre : un corpus git est déjà
    trié, et un secret y vit aussi bien dans un `.py` ou un `.yml` que dans un `.md`.
    Les binaires sont écartés plus loin, à la lecture."""
    candidates = sorted(tracked) if tracked is not None else root.rglob("*")
    for path in candidates:
        if not path.is_file() or path.is_symlink():
            continue
        if tracked is None and path.suffix.lower() not in SCANNED_EXTENSIONS:
            continue
        if any(path.match(glob) for glob in exclude_globs):
            continue
        if min_mtime is not None:
            try:
                if path.stat().st_mtime < min_mtime:
                    continue
            except OSError:
                continue
        yield path


def _resolve_literals(args: argparse.Namespace) -> list[str]:
    literals: list[str] = []
    literals.extend(v for v in (args.literal or []) if v.strip())
    # `--literal-env` est répétable (comme `--literal`). Il ne l'était pas : argparse
    # gardait alors la DERNIÈRE occurrence en écrasant les précédentes, sans rien dire —
    # une commande passant N variables n'en scrubbait qu'une et rapportait « RAS » pour
    # les autres, ce qui se lit comme « rien à masquer » alors que les secrets sont là.
    # (Constaté 2026-08-03 en purgeant 19 cookies Google d'un coup.)
    env_names = args.literal_env or ["OLLAMA_SCRUB_LITERAL"]
    if isinstance(env_names, str):
        env_names = [env_names]
    for name in env_names:
        env_value = os.environ.get(name, "")
        literals.extend(line for line in env_value.splitlines() if line.strip())
    for name in args.wcm_literal or []:
        secret = read_credential(name)
        if secret:
            literals.append(secret)
        else:
            print(f"[scrub] credential WCM introuvable : {name}", file=sys.stderr)
    return literals


class RuleSelectionError(Exception):
    """Sélection de règles vide ou nom inconnu : scanner à blanc rendrait un faux RAS."""


def _reject_unknown(names: set[str], flag: str) -> None:
    unknown = sorted(names - known_rule_ids())
    if unknown:
        raise RuleSelectionError(
            f"{flag} : nom(s) de règle inconnu(s) : {', '.join(unknown)}. "
            f"Règles connues : {', '.join(sorted(known_rule_ids()))}"
        )


def _select_rules(args: argparse.Namespace, literals: list[str]):
    rules = build_rules(literals)
    keep: set[str] | None = None
    drop: set[str] = set()
    if args.scope == "literal":
        keep = {"literal"}
    elif args.scope == "safe":
        drop |= set(NOISY_RULES)
    if args.rules:
        keep = {r.strip() for r in args.rules.split(",")}
        _reject_unknown(keep, "--rules")
    if args.exclude_rules:
        excluded = {r.strip() for r in args.exclude_rules.split(",")}
        _reject_unknown(excluded, "--exclude-rules")
        drop |= excluded
    if keep is not None:
        rules = [r for r in rules if r.rule_id in keep]
    if drop:
        rules = [r for r in rules if r.rule_id not in drop]
    if not rules:
        raise RuleSelectionError(
            "sélection de règles vide — aucun fichier ne sera examiné, et un "
            "findings=0 ne prouverait rien. Vérifier --scope / --rules / "
            "--exclude-rules, et qu'un littéral a bien été fourni si --scope literal."
        )
    return rules


def run(args: argparse.Namespace) -> RunStats:
    literals = _resolve_literals(args)
    rules = _select_rules(args, literals)
    run_start = time.time()
    min_mtime = run_start - args.max_age_hours * 3600 if args.max_age_hours else None

    incremental = args.since_last_scrub
    state = read_state(args.watermark_file) if incremental else {}
    new_state: dict[str, dict] = {}

    stats = RunStats()
    age = f" | âge≤{args.max_age_hours}h" if args.max_age_hours else ""
    wm = ""
    if incremental:
        wm = f" | incrémental (offset/fichier, {len(state)} connus)" if state else " | incrémental (1re passe)"
    print(
        f"[scrub] mode={args.mode} | racines={[str(r) for r in args.root]} | "
        f"règles={len(rules)} (dont {len(literals)} littérale(s)){age}{wm}",
        file=sys.stderr,
    )
    for root in args.root:
        root = root.expanduser()
        if not root.exists():
            print(f"[scrub] racine absente, ignorée : {root}", file=sys.stderr)
            continue
        tracked = git_tracked_files(root) if args.git_tracked else None
        for path in iter_target_files(root, args.exclude_glob, min_mtime, tracked):
            key = str(path)
            prev = state.get(key) if incremental else None
            try:
                st = path.stat()
            except OSError:
                continue

            # Fichier strictement inchangé depuis le dernier scrub → skip sans lecture.
            if prev and prev.get("size") == st.st_size and prev.get("mtime") == st.st_mtime:
                stats.skipped_unchanged += 1
                new_state[key] = prev
                continue

            try:
                content = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue

            lines = content.splitlines(keepends=True)
            # Offset incrémental : un transcript est append-only → ne scanner que
            # les lignes AJOUTÉES depuis le dernier passage. Si le fichier a rétréci
            # (réécrit/rotaté), re-scanner tout (start=0).
            start = 0
            if prev and st.st_size >= prev.get("size", 0):
                start = min(int(prev.get("lines", 0)), len(lines))
            tail = "".join(lines[start:]) if start else content
            stats.scanned += 1
            stats.tail_lines += len(lines) - start
            # État « intégralement scanné jusqu'à maintenant » (persisté en mode apply).
            scanned_state = {"lines": len(lines), "mtime": st.st_mtime, "size": st.st_size}

            # Pré-filtre rapide : regex sur le texte brut de la QUEUE seulement. Un
            # secret dans une valeur JSON apparaît aussi en texte brut → pas de faux
            # négatif, et on évite de re-scanner le début déjà traité.
            if not find_in_text(tail, rules):
                if incremental and args.mode == "apply":
                    new_state[key] = scanned_state
                continue
            # Secret dans la queue → rédaction sur le contenu COMPLET (idempotent :
            # le début déjà scrubbé porte [MASKARA_REDACTED] et n'est pas re-matché).
            new_content, findings = redact_content(path, content, rules)
            if not findings:
                if incremental and args.mode == "apply":
                    new_state[key] = scanned_state
                continue
            stats.hit_files += 1
            stats.findings += len(findings)
            stats.touched.append(key)
            for finding in findings:
                stats.per_rule[finding.rule_id] = stats.per_rule.get(finding.rule_id, 0) + 1
                stats.note_value(finding.rule_id, finding.digest, key)
            if args.verbose:
                _print_findings(path, findings)
            if args.mode == "apply":
                try:
                    atomic_write(path, new_content)
                    if incremental:
                        try:
                            st2 = path.stat()
                            new_state[key] = {
                                "lines": len(new_content.splitlines(keepends=True)),
                                "mtime": st2.st_mtime,
                                "size": st2.st_size,
                            }
                        except OSError:
                            pass
                except OSError as exc:  # fichier verrouillé (session active) : skip
                    stats.locked += 1
                    # NE PAS avancer l'état → le fichier sera re-scanné au prochain run.
                    print(f"[scrub] VERROUILLÉ, ignoré : {path} ({exc})", file=sys.stderr)

    if incremental and args.mode == "apply":
        write_state(args.watermark_file, new_state)
    return stats


def _print_findings(path: Path, findings: list[Finding]) -> None:
    for finding in findings:
        print(f"  {path}  [{finding.rule_id}]  {finding.preview}")


def _json_report(args: argparse.Namespace, stats: RunStats) -> dict:
    """Machine-readable report: which files, which rules, never a secret value.

    A caller that has to grep the human report re-implements the parsing badly
    and reads "0 finding" out of an error message. Values stay out: the digest
    identifies a value across files without disclosing it.
    """
    files: dict[str, list[str]] = {}
    for value_digest, names in stats.files_by_digest.items():
        for name in names:
            files.setdefault(str(name), []).append(value_digest)
    return {
        "mode": args.mode,
        "scope": args.scope,
        "scanned": stats.scanned,
        "hit_files": stats.hit_files,
        "findings": stats.findings,
        "locked": stats.locked,
        "distinct_values": stats.distinct_values,
        "per_rule": {
            rule_id: {"occurrences": count,
                      "values": len(stats.digests_by_rule.get(rule_id, ()))}
            for rule_id, count in stats.per_rule.items()
        },
        "files": {name: sorted(set(digests)) for name, digests in sorted(files.items())},
    }


def _emit_report(args: argparse.Namespace, stats: RunStats) -> None:
    incr = ""
    if args.since_last_scrub:
        incr = f" | inchangés={stats.skipped_unchanged} | lignes(re)scannées={stats.tail_lines}"
    summary = (
        f"[scrub] fichiers scannés={stats.scanned} | fichiers touchés={stats.hit_files} | "
        f"findings={stats.findings} | verrouillés={stats.locked}{incr}"
    )
    print(summary, file=sys.stderr)
    for rule_id, count in sorted(stats.per_rule.items(), key=lambda kv: -kv[1]):
        values = len(stats.digests_by_rule.get(rule_id, ()))
        print(f"  {rule_id}: {count} occurrence(s), {values} valeur(s)", file=sys.stderr)
    spread = sorted(
        ((d, files) for d, files in stats.files_by_digest.items() if len(files) > 1),
        key=lambda kv: -len(kv[1]),
    )
    if spread and args.verbose:
        print("[scrub] valeurs recopiées dans plusieurs fichiers :", file=sys.stderr)
        for value_digest, files in spread:
            print(f"  #{value_digest} — {len(files)} fichier(s)", file=sys.stderr)
            for name in sorted(files):
                print(f"      {name}", file=sys.stderr)

    if args.report == "none":
        return
    if args.report == "json":
        print(json.dumps(_json_report(args, stats), ensure_ascii=False, indent=2))
        return
    if stats.findings == 0:
        # Ligne concise : un consommateur comme idle-queue délivre toujours la
        # sortie (placeholder sinon) ; on émet un statut propre plutôt que vide.
        print(f"✅ Secret Scrubber — RAS ({stats.scanned} fichiers scannés, scope {args.scope})")
        return

    verb = "masquée(s)" if args.mode == "apply" else "détectée(s)"
    lines = [
        f"🔑 Secret Scrubber — {stats.distinct_values} valeur(s) distincte(s) {verb}, "
        f"{stats.findings} occurrence(s) dans {stats.hit_files} fichier(s)"
    ]
    for rule_id, count in sorted(stats.per_rule.items(), key=lambda kv: -kv[1]):
        values = len(stats.digests_by_rule.get(rule_id, ()))
        lines.append(f"  • {rule_id}: {values} valeur(s), {count} occurrence(s)")
    if stats.locked:
        lines.append(f"  ⚠️ {stats.locked} fichier(s) verrouillé(s), ignoré(s)")
    if args.mode == "scan":
        lines.append("  (dry-run — relancer en 'apply' pour nettoyer)")
    print("\n".join(lines))  # stdout → délivré par idle-queue (Telegram)


TRANSCRIPT_ROOTS = (
    Path.home() / ".claude" / "projects",
    Path.home() / ".pi" / "agent" / "sessions",
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secret-scrubber", description=__doc__)
    parser.add_argument("mode", choices=["scan", "apply"], help="scan = dry-run ; apply = réécriture")
    parser.add_argument("--root", action="append", type=Path,
                        help=f"racine(s) (défaut : {', '.join(str(p) for p in TRANSCRIPT_ROOTS)})")
    parser.add_argument("--scope", choices=["all", "safe", "literal"], default="safe",
                        help="all=toutes les règles ; safe=sans env-secret/database-url (défaut) ; literal=secrets connus seuls")
    parser.add_argument("--rules", help="rule_id à GARDER (csv) — surcharge --scope")
    parser.add_argument("--exclude-rules", help="rule_id à EXCLURE (csv)")
    parser.add_argument("--literal", action="append",
                        help="secret littéral ad-hoc à masquer (répétable, ≥6 chars). "
                             "⚠️ visible dans la liste des process (ps/tasklist) — pour un "
                             "secret sensible, préférer --literal-env (invisible dans ps)")
    parser.add_argument("--literal-env", action="append",
                        default=None,
                        help="var d'env contenant des secrets littéraux (un par ligne ; "
                             "répétable). Défaut : OLLAMA_SCRUB_LITERAL")
    parser.add_argument("--wcm-literal", action="append",
                        help="nom de credential WCM à charger comme secret littéral (répétable)")
    parser.add_argument("--exclude-glob", action="append", default=[],
                        help="glob de fichiers à ignorer (répétable)")
    parser.add_argument("--git-tracked", action="store_true",
                        help="n'examiner que les fichiers suivis par git sous chaque racine "
                             "— le corpus committé ou committable, seul périmètre qui compte "
                             "pour un dépôt. Toutes les extensions sont couvertes (pas seulement "
                             f"{', '.join(SCANNED_EXTENSIONS)}), et logs/caches ignorés par git "
                             "sont écartés sans parcours d'arbre. Échoue si git est inutilisable "
                             "ou si le corpus est vide, plutôt que de rendre un faux RAS.")
    parser.add_argument("--max-age-hours", type=float, default=None,
                        help="ne scanner que les fichiers modifiés depuis N heures (scan incrémental)")
    parser.add_argument("--since-last-scrub", action="store_true",
                        help="ne scanner que les fichiers modifiés depuis le dernier apply réussi "
                             "(watermark persisté). Combinable avec --max-age-hours (plancher le plus "
                             "restrictif). Le watermark n'est avancé qu'en mode apply.")
    parser.add_argument("--watermark-file", type=Path, default=DEFAULT_WATERMARK,
                        help=f"fichier de watermark pour --since-last-scrub (défaut : {DEFAULT_WATERMARK})")
    parser.add_argument("--report", choices=["telegram", "text", "json", "none"], default="telegram",
                        help="format du rapport stdout (défaut telegram, silencieux si 0 finding)")
    parser.add_argument("--verbose", action="store_true", help="lister chaque finding sur stderr")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.root:
        args.root = [p for p in TRANSCRIPT_ROOTS if p.is_dir()] or [TRANSCRIPT_ROOTS[0]]
    try:
        stats = run(args)
    except (RuleSelectionError, GitTrackedError) as exc:
        print(f"[scrub] ERREUR — {exc}", file=sys.stderr)
        return 2
    _emit_report(args, stats)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
