"""Rédaction des secrets : texte brut, JSON et JSONL value-aware + écriture atomique.

Réf. amont : internal/redact/redact.go et structured.go (mrgoonie/maskara, MIT).
Pour les .jsonl/.json, on ne rédige que les *valeurs* string (jamais les clés),
ligne par ligne, et on ne re-sérialise que les lignes effectivement modifiées.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from .detect import REDACTION_MARKER, Finding, Rule, find_in_text


def redact_text(content: str, rules: list[Rule]) -> tuple[str, list[Finding]]:
    findings = find_in_text(content, rules)
    if not findings:
        return content, []
    # Appliquer de la fin vers le début pour préserver les offsets.
    out = content
    for finding in sorted(findings, key=lambda f: f.start, reverse=True):
        token = f"[{REDACTION_MARKER}:{finding.rule_id}]"
        out = out[: finding.start] + token + out[finding.end :]
    return out, findings


def _redact_json_value(value: object, rules: list[Rule], findings: list[Finding]) -> object:
    if isinstance(value, str):
        new, found = redact_text(value, rules)
        findings.extend(found)
        return new
    if isinstance(value, list):
        return [_redact_json_value(item, rules, findings) for item in value]
    if isinstance(value, dict):
        return {key: _redact_json_value(item, rules, findings) for key, item in value.items()}
    return value


def redact_jsonl(content: str, rules: list[Rule]) -> tuple[str, list[Finding]]:
    """Réécrit ligne par ligne ; ne re-sérialise que les lignes modifiées."""
    findings: list[Finding] = []
    out_lines: list[str] = []
    for raw in content.splitlines(keepends=True):
        stripped = raw.rstrip("\n").rstrip("\r")
        ending = raw[len(stripped) :]
        if not stripped.strip():
            out_lines.append(raw)
            continue
        try:
            value = json.loads(stripped)
        except json.JSONDecodeError:
            new, found = redact_text(stripped, rules)  # fallback texte brut
            findings.extend(found)
            out_lines.append(new + ending)
            continue
        line_findings: list[Finding] = []
        new_value = _redact_json_value(value, rules, line_findings)
        if line_findings:
            findings.extend(line_findings)
            out_lines.append(json.dumps(new_value, ensure_ascii=False) + ending)
        else:
            out_lines.append(raw)
    return "".join(out_lines), findings


def redact_content(path: Path, content: str, rules: list[Rule]) -> tuple[str, list[Finding]]:
    ext = path.suffix.lower()
    if ext == ".jsonl":
        return redact_jsonl(content, rules)
    if ext == ".json":
        try:
            value = json.loads(content)
        except json.JSONDecodeError:
            return redact_text(content, rules)
        findings: list[Finding] = []
        new_value = _redact_json_value(value, rules, findings)
        if not findings:
            return content, []
        tail = "\n" if content.endswith("\n") else ""
        return json.dumps(new_value, ensure_ascii=False) + tail, findings
    return redact_text(content, rules)


def atomic_write(path: Path, content: str) -> None:
    """Écriture atomique : fichier temp dans le même dossier puis os.replace.

    Pas de .bak persistant — un backup ferait survivre le secret en clair.
    """
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".scrub.tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise
