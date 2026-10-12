"""Tests des règles de détection et de la rédaction."""
from __future__ import annotations

from pathlib import Path

from secret_scrubber.detect import build_rules, find_in_text, mask
from secret_scrubber.redact import redact_content, redact_jsonl


def test_openai_key_detected() -> None:
    rules = build_rules()
    findings = find_in_text("token = sk-proj-ABCDEFGHIJKLMNOPQRSTUVWX", rules)
    assert any(f.rule_id == "openai-api-key" for f in findings)


def test_telegram_token_after_json_escaped_newline() -> None:
    """Un token collé après un `\\n` échappé en JSON (`...API:\\n123…`) n'a pas de frontière de mot."""
    rules = build_rules()
    fake = "1234567890:AA" + "Bc" * 17
    findings = find_in_text(r'"access the HTTP API:\\n' + fake + r'\\nKeep your', rules)
    assert any(f.rule_id == "telegram-bot-token" for f in findings)


def test_prefixed_key_after_json_escaped_newline() -> None:
    """Même frontière pour toute règle en `\\b` : une clé collée en début de ligne d'un message."""
    rules = build_rules()
    findings = find_in_text(r'"voici:\\nsk-proj-ABCDEFGHIJKLMNOPQRSTUVWX"', rules)
    assert any(f.rule_id == "openai-api-key" for f in findings)


def test_word_glued_prefix_still_ignored() -> None:
    """La frontière reste une frontière : `xsk-proj-…` collé à un mot n'est pas une clé."""
    rules = build_rules()
    findings = find_in_text("maskxsk-proj-ABCDEFGHIJKLMNOPQRSTUVWX", rules)
    assert not any(f.rule_id == "openai-api-key" for f in findings)


def test_cartesia_key_detected() -> None:
    rules = build_rules()
    findings = find_in_text("CARTESIA=sk_car_nJS1aBcDeFgHiJkLmNoP done", rules)
    assert any(f.rule_id == "cartesia-api-key" for f in findings)


def test_groq_key_detected() -> None:
    rules = build_rules()
    fake = "gsk_" + "A1b2C3d4E5" * 5
    findings = find_in_text(f"GROQ_API_KEY={fake} suite", rules)
    assert any(f.rule_id == "groq-api-key" for f in findings)


# Forme de la clé Inworld (valeur synthétique) (base64 key:secret, ~76 chars, terminée par ==).
INWORLD_KEY = "a0tCbGhOMTVMaEYzdXRqcEw5eEEzaHlVZnZJT0VtYXY6ZEdtVXUwWDdNRDhuMUNOa1Y3SmJJaA=="


def test_inworld_key_pasted_label() -> None:
    # Format collé par l'utilisateur : « inworld : <base64> ».
    rules = build_rules()
    out, findings = redact_jsonl(f'{{"text":"inworld : {INWORLD_KEY}"}}\n', rules)
    assert any(f.rule_id == "inworld-api-key" for f in findings)
    assert INWORLD_KEY not in out
    assert "inworld" in out  # le label reste, seule la clé est masquée


def test_inworld_key_env_assignment() -> None:
    # Format env : INWORLD_API_KEY=<base64> (le \b raterait l'ancienne règle env-secret).
    rules = build_rules()
    out, findings = redact_jsonl(f'{{"cmd":"INWORLD_API_KEY={INWORLD_KEY}"}}\n', rules)
    assert any(f.rule_id == "inworld-api-key" for f in findings)
    assert INWORLD_KEY not in out


def test_inworld_covered_in_safe_scope() -> None:
    # La règle inworld n'est PAS noisy → active en scope safe (drop env-secret/database-url).
    from secret_scrubber.detect import _RULESPECS

    noisy = {"env-secret", "database-url"}
    assert any(rid == "inworld-api-key" and rid not in noisy for rid, _, _ in _RULESPECS)


def test_basic_auth_credential_detected() -> None:
    rules = build_rules()
    findings = find_in_text(f"Authorization: Basic {INWORLD_KEY}", rules)
    assert any(f.rule_id in ("http-basic-credential", "inworld-api-key") for f in findings)


def test_inworld_label_no_false_positive_in_prose() -> None:
    rules = build_rules()
    findings = find_in_text("Inworld is the best TTS provider for laughter.", rules)
    assert not any(f.rule_id == "inworld-api-key" for f in findings)


# Formes du cookie apiV2Auth d'un service tiers (valeurs synthétiques).
HF_JWT = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJodHRwczovL2V4YW1wbGUuY29t.ISsWgGiVVmCY7loKCKZNkKgnOR8-"
)
HF_AUTH0_REFRESH = "v1.UZQmgipMzDHZwMn6_11mDW2gmNuuUjWZGZelezy7meoSkHKPpoRADrpodBxiosR_PRf5-b9JrndwqvSJagPUlw5"


def test_auth0_refresh_token_detected() -> None:
    rules = build_rules()
    findings = find_in_text(f"refresh_token: {HF_AUTH0_REFRESH}", rules)
    assert any(f.rule_id == "auth0-refresh-token" for f in findings)


def test_jwt_detected_when_url_encoded() -> None:
    # Régression idle-queue#166 : dans le cookie URL-encodé le JWT est précédé de
    # `%22` (finit par `2`) → l'ancien `\beyJ` ratait. Doit matcher JWT + refresh.
    rules = build_rules()
    blob = f'{{"cmd":"apiV2Auth={{%22access_token%22:%22{HF_JWT}%22%2C%22refresh_token%22:%22{HF_AUTH0_REFRESH}%22}}"}}\n'
    out, findings = redact_jsonl(blob, rules)
    assert any(f.rule_id == "jwt" for f in findings)
    assert any(f.rule_id == "auth0-refresh-token" for f in findings)
    assert HF_JWT not in out
    assert HF_AUTH0_REFRESH not in out


def test_auth0_refresh_no_false_positive_on_version() -> None:
    # `v1.` isolé ou suivi d'une chaîne courte (numéro de version) ne doit pas matcher.
    rules = build_rules()
    findings = find_in_text("Migré vers schema v1.2.3 puis v1.4 hier.", rules)
    assert not any(f.rule_id == "auth0-refresh-token" for f in findings)


def test_env_var_secret_detected() -> None:
    # Forme dominante de l'écosystème : NAME_PASSWORD=valeur. `\bpassword\b`
    # rate (`_` est un word-char), d'où cette règle dédiée (incident gmail-manager-2).
    rules = build_rules()
    out, findings = redact_jsonl(
        '{"cmd":"export APP_IMAP_EXAMPLE_PASSWORD=Qv7Lm*Rt2ZpXK48W"}\n', rules
    )
    assert any(f.rule_id == "env-var-secret" for f in findings)
    assert "Qv7Lm*Rt2ZpXK48W" not in out
    assert "APP_IMAP_EXAMPLE_PASSWORD" in out  # le nom de var reste lisible


def test_env_var_secret_covered_in_safe_scope() -> None:
    # Haut signal (NAME_PASSWORD=…) → doit être active en scope safe.
    from secret_scrubber.detect import HIGH_SIGNAL_RULES

    assert "env-var-secret" in HIGH_SIGNAL_RULES


def test_env_var_secret_ignores_command_substitution() -> None:
    # NE doit PAS masquer une substitution de commande (pas un secret littéral) :
    # `$(cat …)` s'arrête au 1er espace (<8 chars capturés).
    rules = [r for r in build_rules() if r.rule_id == "env-var-secret"]
    findings = find_in_text('CALDAV_INFOMANIAK_PASSWORD="$(cat x)"', rules)
    assert not findings


def test_env_var_secret_ignores_short_value() -> None:
    rules = [r for r in build_rules() if r.rule_id == "env-var-secret"]
    assert not find_in_text("X_TOKEN=short", rules)


def test_env_var_secret_ignores_placeholders_and_code() -> None:
    # secret-scrubber#10 : le NAME matche mais la VALUE est un non-secret → 0 finding.
    rules = [r for r in build_rules() if r.rule_id == "env-var-secret"]
    for text in (
        "OPENAI_API_KEY=your_key_here",
        "MY_SECRET=votre_cle_secrete",
        "SLACK_TOKEN=<beaker_token>",
        "DB_PASSWORD=os.getenv('DB_PWD')",
        "VAULT_TOKEN=${VAULT_ADDR}",
        "CONFIG_SECRET=E:\\Dropbox\\JULIEN\\Projets",
        "SOME_API_KEY=changeme",
        "X_TOKEN=example",
        "MY_TOKEN=$savedToken",           # réf. variable shell/PowerShell
        "MY_TOKEN=$__secretValue",
        "AFFINE_TOKEN=~/affine.env",       # chemin home
        "X_SECRET=(masqué)",               # annotation FR
        "X_TOKEN=<AFFINE_TOKEN",           # placeholder chevron partiel
        "X_TOKEN=.env.example:#foo",       # ligne de doc/.env
        "X_TOKEN=.+|OPENAI_BASE_URL=.+",   # pattern regex
        "X_SECRET=XAI_MODEL=grok-beta",    # chaîne de config NAME=VALUE
        "X_SECRET=(masqué)",               # annotation entre parenthèses
        "X_TOKEN=logging(",                # fragment de code
        "X_SECRET=OPENAI_BASE_URL",        # nom de var capturé comme valeur
        "X_SECRET=ANTHROPIC_MODEL=",       # idem avec = final
    ):
        assert not find_in_text(text, rules), f"faux positif non filtré : {text}"


def test_env_var_secret_keeps_real_value_after_filter() -> None:
    # Un vrai secret (casse mixte + symboles) passe le validateur.
    rules = [r for r in build_rules() if r.rule_id == "env-var-secret"]
    findings = find_in_text("APP_IMAP_EXAMPLE_PASSWORD=Qv7Lm*Rt2ZpXK48W", rules)
    assert any(f.rule_id == "env-var-secret" for f in findings)


def test_literal_takes_priority() -> None:
    rules = build_rules(literals=["b3d3secretkeyvalue123456"])
    findings = find_in_text("OLLAMA=b3d3secretkeyvalue123456 done", rules)
    assert findings
    assert findings[0].rule_id == "literal"


def test_short_literal_ignored() -> None:
    # Un littéral trivial (<6 chars) ne doit jamais devenir une règle.
    rules = build_rules(literals=["abc"])
    assert all(r.rule_id != "literal" for r in rules)


def test_cli_literal_flag_masks_bare_secret(tmp_path: Path) -> None:
    # `--literal` masque un secret collé nu (sans contexte NAME=…), ex. un
    # mot de passe d'appareil dans `printf %s …` (cas gmail-manager-2).
    from secret_scrubber.cli import main

    target = tmp_path / "t.jsonl"
    target.write_text('{"cmd":"printf %s Qv7Lm*Rt2ZpXK48W | ssh box"}\n', encoding="utf-8")
    rc = main(["apply", "--root", str(tmp_path), "--scope", "safe",
               "--literal", "Qv7Lm*Rt2ZpXK48W", "--report", "none"])
    out = target.read_text(encoding="utf-8")
    assert rc == 0
    assert "Qv7Lm*Rt2ZpXK48W" not in out
    assert "MASKARA_REDACTED" in out


def test_mask_preview() -> None:
    assert mask("1234567890abcdef") == "1234...cdef"
    assert mask("short") == "***"


def test_redact_jsonl_only_touches_values() -> None:
    line = '{"text":"key sk-proj-ABCDEFGHIJKLMNOPQRSTUVWX","api_key_field":"name"}\n'
    rules = build_rules()
    out, findings = redact_jsonl(line, rules)
    assert findings
    assert "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWX" not in out
    assert "MASKARA_REDACTED" in out
    # La clé du dict ("api_key_field") ne doit jamais être réécrite.
    assert "api_key_field" in out


def test_idempotent() -> None:
    rules = build_rules()
    line = '{"v":"sk-proj-ABCDEFGHIJKLMNOPQRSTUVWX"}\n'
    once, _ = redact_jsonl(line, rules)
    twice, findings = redact_jsonl(once, rules)
    assert once == twice
    assert findings == []


def test_no_findings_returns_original() -> None:
    rules = build_rules()
    content = '{"hello":"world"}\n'
    out, findings = redact_content(Path("x.jsonl"), content, rules)
    assert out == content
    assert findings == []


# JWE NextAuth (algorithme `dir`) : 5 segments, le 2e VIDE — d'où le `..`.
# Valeur synthétique : structure réelle, charge inventée.
NEXTAUTH_JWE = (
    "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0.."
    "QWxpY2VJbml0VmVjdA.Q2lwaGVydGV4dEZha2VQYXlsb2FkRm9yVGVzdHM.VGFnRmFrZVZhbHVl"
)


def test_jwe_with_empty_key_segment_detected() -> None:
    # Régression session 2026-07-22 : un cookie `__Secure-next-auth.session-token`
    # (Perplexity) a traversé un transcript sans être masqué. La règle `jwt` exige
    # 3 segments NON vides ; ce JWE en a 5 dont un vide → elle ne pouvait pas le voir.
    rules = build_rules()
    findings = find_in_text(f'"__Secure-next-auth.session-token": "{NEXTAUTH_JWE}"', rules)
    assert any(f.rule_id == "jwe" for f in findings), "JWE non détecté"


def test_jwe_fully_masked_not_truncated_by_jwt_rule() -> None:
    # `jwt` matcherait les 3 premiers segments d'un JWE et laisserait le ciphertext
    # ET le tag EN CLAIR. `jwe` doit primer : placée avant dans _RULESPECS, et
    # _dedupe_overlaps garde le premier trouvé à position égale.
    rules = build_rules()
    out, findings = redact_jsonl(f'{{"cookie":"{NEXTAUTH_JWE}"}}\n', rules)
    assert NEXTAUTH_JWE not in out
    assert "VGFnRmFrZVZhbHVl" not in out, "le tag a survécu — masquage tronqué"
    assert any(f.rule_id == "jwe" for f in findings)


def test_jwe_rule_does_not_break_plain_jwt() -> None:
    # Non-régression : un JWT à 3 segments reste capté par la règle `jwt`.
    rules = build_rules()
    findings = find_in_text(f"Authorization: Bearer {HF_JWT}", rules)
    assert any(f.rule_id == "jwt" for f in findings)


# --- dsn-password : DSN libpq en `key=value` (secret-scrubber, 2026-09-03) ---------------
# Cas fondateur : un mot de passe PostgreSQL affiché en clair dans un transcript, alors que
# le scan `safe` répondait RAS — `database-url` ne voit que la forme URL et `env-var-secret`
# exige un NOM en MAJUSCULES. La fuite n'a été trouvée que par recherche indépendante.
DSN = "host=127.0.0.1 port=5432 user=svc_demo dbname=svc_demo password=Fk3Np8Vd2Lr6Tc9W"


def test_dsn_password_detected_in_safe_scope() -> None:
    rules = build_rules()
    findings = find_in_text(f"DROPBOX_PG_DSN={DSN}", rules)
    assert any(f.rule_id == "dsn-password" for f in findings)


def test_dsn_password_is_high_signal() -> None:
    from secret_scrubber.detect import HIGH_SIGNAL_RULES

    assert "dsn-password" in HIGH_SIGNAL_RULES


def test_dsn_password_masks_only_the_value() -> None:
    rules = build_rules()
    out, _ = redact_content(Path("t.txt"), f"DROPBOX_PG_DSN={DSN}", rules)
    assert "Fk3Np8Vd2Lr6Tc9W" not in out
    assert "host=127.0.0.1" in out
    assert "dbname=svc_demo" in out


def test_dsn_password_ignores_isolated_password_assignment() -> None:
    """Sans marqueur DSN devant, `password=` seul ne doit pas declencher la regle."""
    rules = build_rules()
    findings = find_in_text("password=hunter2000000", rules)
    assert not any(f.rule_id == "dsn-password" for f in findings)


def test_dsn_password_ignores_documentation_placeholder() -> None:
    rules = build_rules()
    findings = find_in_text("host=localhost dbname=app password=your_password_here", rules)
    assert not any(f.rule_id == "dsn-password" for f in findings)


def test_dsn_password_ignores_fstring_placeholder() -> None:
    """Un f-string de script (`password={password}
`) n'est pas un secret."""
    rules = build_rules()
    findings = find_in_text('f"... dbname={DB} password={password}\n"', rules)
    assert not any(f.rule_id == "dsn-password" for f in findings)



def test_env_var_secret_never_crosses_a_newline() -> None:
    """`if GITHUB_TOKEN:` puis la ligne suivante n'est pas une assignation (secret-scrubber#17)."""
    rules = build_rules()
    code = '    if GITHUB_TOKEN:\n        headers["Authorization"] = f"token {GITHUB_TOKEN}"\n'
    findings = find_in_text(code, rules)
    assert not any(f.rule_id == "env-var-secret" for f in findings)


def test_env_secret_never_crosses_a_newline() -> None:
    """Même garde pour la règle minuscule : un `token:` en fin de ligne n'ouvre rien."""
    rules = build_rules()
    findings = find_in_text('    if token:\n        headers["A"] = 1\n', rules)
    assert not any(f.rule_id == "env-secret" for f in findings)


def test_ellipsis_prefix_is_a_placeholder() -> None:
    """`sk_car_…` / `sk-or-v1-...` = préfixe de marque + ellipse → placeholder de doc."""
    rules = build_rules()
    for text in ("CARTESIA_API_KEY=sk_car_…", 'OPENROUTER_API_KEY = "sk-or-v1-..."'):
        findings = find_in_text(text, rules)
        assert not any(f.rule_id.startswith("env-") for f in findings), text


def test_truncated_real_key_is_still_masked() -> None:
    """Un fragment tronqué qui porte de l'entropie reste un secret : on le masque."""
    rules = build_rules()
    findings = find_in_text("CARTESIA_API_KEY=sk_car_Qx81LmZt4w…", rules)
    assert any(f.rule_id == "env-var-secret" for f in findings)
