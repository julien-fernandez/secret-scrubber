"""Détection de secrets — règles regex portées de mrgoonie/maskara.

Réf. amont : internal/detect/detect.go (MIT). Les expressions sont reprises
telles quelles ; group=1 signifie « ne masquer que le groupe capturant, pas tout
le match » (cas de la règle générique env-secret où le préfixe `api_key=` doit
rester lisible).
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass

REDACTION_MARKER = "MASKARA_REDACTED"

# --- Validateur de valeur pour les règles NAME=VALUE (env-var-secret / env-secret) ---
# Le NAME (`*_TOKEN`, `*_SECRET`, `api_key=`…) est fort signal, mais la VALUE capturée
# est souvent un non-secret : placeholder de doc, bout de code, ou chemin de fichier.
# secret-scrubber#10 (2026-07-14) : 426 faux positifs `env-var-secret` sur un corpus,
# quasi tous `your_key_here`, `os.getenv(`, `E:\…\Projets`, `<beaker>`. On garde le regex
# de nom et on rejette ces valeurs côté Python (plus lisible qu'un regex géant).

# Wrappée dans des chevrons/accolades : `<your-key>`, `{{VALUE}}`.
_ANGLE_BRACE_RE = re.compile(r"^[<{].*[>}]$")
# Placeholders de documentation : your_key_here, votre_cle, xxxx, ..., changeme, example…
_PLACEHOLDER_VALUE_RE = re.compile(
    r"""(?ix)
    ^\s*(?:
        (?:your|my|the|some|put|insert|enter|paste|replace|add|set)[-_].*
      | (?:votre|vos|ton|ta|mon|ma)[-_].*
      | .*(?:_here|-here|placeholder|example|sample|dummy|change[-_]?me|yourkey|
             api[-_]?key|apikey|access[-_]?key|client[-_]?secret)\s*$
      | x{3,}
      | \.{2,}
      | none | null | true | false | changeme | todo | tbd | example | test
    )\s*$
    """,
)
# Bouts de code : os.getenv(…), process.env.X, ${VAR}, %VAR%, $savedToken (réf. shell/PS).
_CODEISH_RE = re.compile(
    r"(?i)(?:^os\.|process\.env|os\.environ|getenv|system\.getenv"
    r"|^\$\{|^\{\{|^%[a-z0-9_]+%$|^\$[a-z_][a-z0-9_]*$)"
)
# Chemins de fichiers : C:\…, /home/…, …\Users\…, …/Dropbox/…, ~/affine.env.
_PATHISH_RE = re.compile(r"(?i)(?:^[a-z]:[\\/]|^~[\\/]|[\\/](?:users|home|dropbox|documents)[\\/])")
# snake_case tout en minuscules sans chiffre : your_key_here, votre_cle, my_secret_token —
# une vraie clé/token/mot de passe n'est presque jamais de cette forme.
_SNAKE_WORDS_RE = re.compile(r"^[a-z]+(?:_[a-z]+)+$")
# Valeur coupée par une ellipse (`sk_car_…`, `sk-or-v1-...`). Ce qui précède l'ellipse
# décide : un simple préfixe de marque est un placeholder de doc, un fragment qui porte
# de l'entropie reste un secret tronqué qu'on masque (secret-scrubber#17).
_ELLIPSIS_TAIL_RE = re.compile(r"(?:\.{3,}|…)\s*$")
_PREFIX_ONLY_RE = re.compile(r"^[A-Za-z]{1,10}(?:[-_][A-Za-z0-9]{1,4})*$")
# Chaîne de config (NAME=VALUE chaîné, ex. `XAI_MODEL=grok`) : `=` entre deux word-chars.
# Le padding base64 (`==` en fin) n'est jamais suivi d'un word-char → non matché.
_INNER_EQUALS_RE = re.compile(r"[A-Za-z0-9_]=[A-Za-z0-9_]")
# Nom de variable d'env capturé comme valeur : XAI_MODEL, OPENAI_BASE_URL(=). Tout en
# MAJUSCULES avec `_` (≥2 segments) → jamais une vraie clé (qui est hex/base64 mixte).
_UPPER_SNAKE_RE = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+=?$")


def _is_probable_secret_value(value: str) -> bool:
    """True si la VALUE capturée ressemble à un vrai secret (pas un placeholder/code/chemin)."""
    v = value.strip().strip("'\"")
    if len(v) < 8:
        return False
    # Non-secrets structurels : chevrons/accolades (placeholder partiel), pipe (regex),
    # parenthèse d'annotation `(masqué)`, ou début `.` (`.env…`, `.+|…`).
    # Accolades incluses : un placeholder de template ou de f-string (`{password}`,
    # `password={password}\n` dans un script) n'est jamais un secret. `_ANGLE_BRACE_RE`
    # ne suffit pas — il exige que la valeur SE TERMINE par `}`, ce qu'un `{password}\n`
    # capturé avec sa fin de ligne ne fait pas (faux positif mesuré le 2026-09-03).
    if any(c in v for c in "<>|(){}") or v.startswith(".") or v.startswith("…"):
        return False
    if _ANGLE_BRACE_RE.match(v):
        return False
    if _PLACEHOLDER_VALUE_RE.match(v):
        return False
    if _ELLIPSIS_TAIL_RE.search(v):
        stem = _ELLIPSIS_TAIL_RE.sub("", v).rstrip("-_.")
        if len(stem) < 12 or _PREFIX_ONLY_RE.match(stem):
            return False
    if _CODEISH_RE.search(v):
        return False
    if _PATHISH_RE.search(v):
        return False
    if _INNER_EQUALS_RE.search(v):
        return False
    if _UPPER_SNAKE_RE.match(v):
        return False
    if _SNAKE_WORDS_RE.match(v):
        return False
    return True


# rule_id → validateur appliqué à la valeur masquée (groupe capturant). Absent = pas de filtre.
_VALUE_VALIDATORS: dict[str, Callable[[str], bool]] = {
    "env-var-secret": _is_probable_secret_value,
    "env-secret": _is_probable_secret_value,
    "dsn-password": _is_probable_secret_value,
}

# rule_id, expression, group-à-masquer (0 = tout le match)
_RULESPECS: list[tuple[str, str, int]] = [
    ("openai-api-key", r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b", 0),
    ("anthropic-api-key", r"\bsk-ant-[A-Za-z0-9_-]{20,}\b", 0),
    ("github-token", r"\b(?:gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{20,})\b", 0),
    # Forgejo/Gitea : secret d'app OAuth2 et jetons = préfixe `gt` + 1 lettre + `_`
    # (ex. `gto_` pour un OAuth client secret) suivi de ≥32 chars base32/alnum.
    # Haut signal (préfixe spécifique à la forge), bas taux de faux positifs.
    ("forgejo-token", r"\bgt[a-z]_[A-Za-z0-9]{32,}\b", 0),
    ("aws-access-key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", 0),
    ("google-api-key", r"\bAIza[0-9A-Za-z_-]{35}\b", 0),
    ("slack-token", r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b", 0),
    ("stripe-live-key", r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b", 0),
    ("cartesia-api-key", r"\bsk_car_[A-Za-z0-9_-]{16,}\b", 0),
    ("groq-api-key", r"\bgsk_[A-Za-z0-9]{40,}\b", 0),
    # Inworld TTS : clé = base64(key:secret) opaque, passée en `Authorization: Basic`
    # ou `INWORLD_API_KEY=…`, ou collée derrière le label « inworld ». Ancrée sur le mot
    # « inworld » → haut signal ; masque uniquement le groupe base64 (1), pas le label.
    (
        "inworld-api-key",
        r"(?i)\binworld[\s:_-]*(?:api[_-]?key)?[\s:='\"]*([A-Za-z0-9+/]{40,}={0,2})",
        1,
    ),
    # Authorization HTTP Basic : masque le jeton base64 (≥24 chars) après « Basic ».
    ("http-basic-credential", r"(?i)\bBasic\s+([A-Za-z0-9+/]{24,}={0,2})", 1),
    # JWT : PAS de `\b` en tête — dans un cookie/blob URL-encodé le JWT est précédé
    # de `%22` (finit par le chiffre `2`) → `\beyJ` raterait (pas de frontière de mot
    # entre `2` et `e`). `eyJ` (= base64 de `{"`) est déjà très spécifique aux JWT
    # (cas réel : un token de cookie apiV2Auth jamais masqué pour cette raison).
    # JWE (JSON Web Encryption, sérialisation compacte) — 5 segments, et avec
    # l'algorithme `dir` le 2e (clé chiffrée) est VIDE : `eyJ…..iv.ciphertext.tag`.
    # La règle `jwt` ci-dessous ne peut pas le voir, elle exige 3 segments NON vides
    # (`{10,}` ne matche pas une chaîne vide) — d'où un token de session en clair.
    # Cas fondateur : cookie `__Secure-next-auth.session-token` de Perplexity
    # (NextAuth) apparu dans un transcript le 2026-07-22, non masqué par le scope safe.
    # Même famille pour ChatGPT et Claude, qui utilisent aussi NextAuth.
    # DOIT précéder `jwt` : sur un JWE à 2e segment NON vide (RSA-OAEP), `jwt`
    # matcherait les 3 premiers segments et laisserait le ciphertext + le tag en
    # clair — `_dedupe_overlaps` garde le premier trouvé à position égale.
    # Pas de `\b` en tête : même raison d'URL-encodage que `jwt`.
    (
        "jwe",
        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]{6,}"
        r"\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}",
        0,
    ),
    ("jwt", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", 0),
    # Auth0 refresh_token : `v1.` + base64url long (token opaque single-use rotaté,
    # ex. HelloFresh/Auth0). `v1.` + 40+ chars base64url = haut signal (un préfixe de
    # version isolé ne porte jamais une telle charge). Pas de `\b` en tête (même raison
    # URL-encodage que le JWT).
    ("auth0-refresh-token", r"v1\.[A-Za-z0-9_-]{40,}", 0),
    # Telegram Bot API token : `<bot_id>:<secret>` = 8-10 chiffres, `:`, puis 32+
    # chars base64url. La structure « id numérique + `:` + secret opaque » est
    # très spécifique à Telegram (BotFather) → haut signal, bas taux de faux positifs.
    ("telegram-bot-token", r"\b\d{8,10}:[A-Za-z0-9_-]{32,}\b", 0),
    # Env-var / shell / systemd secret assignment: an UPPERCASE identifier ending
    # in _PASSWORD/_TOKEN/_SECRET/_API_KEY/_ACCESS_KEY, then `=` or `:`, then the
    # value. Very high signal (an all-caps NAME_PASSWORD=… is virtually always a
    # real secret assignment) → safe for the "safe" preset. Masks only the value
    # (group 1), keeping the var name readable. Catches the ecosystem's
    # GM2_IMAP_<ID>_PASSWORD / CALDAV_<ID>_PASSWORD forms that the lowercase
    # `password:` env-secret rule misses: there is NO word boundary inside
    # `<NAME>_PASSWORD` (`_` is a word char), so `\bpassword\b` never fires there.
    (
        "env-var-secret",
        r"\b[A-Z][A-Z0-9_]*_(?:PASSWORD|PASSWD|PWD|TOKEN|SECRET|APIKEY|API_KEY|ACCESS_KEY)"
        r"\b[ \t]*[:=][ \t]*[\"']?([^\s\"',`]{8,})",
        1,
    ),
    # Cookies de session Google (`SID`, `SAPISID`, `__Secure-3PSID`…) — un blob de cookies
    # vaut le **compte Google entier** : il rejoue la session sans mot de passe ni 2FA, et
    # signe les appels internes de la console (SAPISIDHASH). Aucune autre règle ne peut les
    # voir : ce sont des valeurs **opaques**, sans préfixe ni structure, donc ni `jwt`, ni
    # `env-secret` (le nom `SID` ne contient ni token/secret/key) ne les captent. Un dump
    # réseau de navigateur (journal réseau d'un navigateur piloté, en-tête `cookie:`)
    # en écrit des dizaines d'un coup dans un transcript.
    # Haut signal : les noms sont propres à Google et la valeur exigée est longue ; masque
    # le seul groupe 1 pour garder le nom du cookie lisible au diagnostic.
    # Alternance du plus long au plus court (`SAPISID` avant `SID`).
    # Cas fondateur : 2026-08-03, session console Cloud rejouée en HTTP (serveur MCP).
    (
        "google-session-cookie",
        r"\b(?:__Secure-[13]P(?:API)?SID(?:TS|CC|RTS)?|__Secure-ENID|SAPISID|APISID"
        r"|HSID|SSID|OSID|SIDCC|NID|SID)=([A-Za-z0-9_\-./+%]{20,})",
        1,
    ),
    ("database-url", r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s\"'<>`]+", 0),
    # DSN libpq/ODBC en `key=value` espacés : `host=… port=… user=… dbname=… password=…`.
    # `database-url` ne voit que la forme URL, et `env-var-secret` exige un NOM en MAJUSCULES
    # (`PGPASSWORD=`) — un `password=` minuscule au milieu d'un DSN n'était donc atteignable
    # que par `env-secret`, hors du preset safe. Résultat mesuré le 2026-09-03 : un mot de passe
    # PostgreSQL affiché en clair dans un transcript, scan safe répondant RAS, fuite trouvée
    # seulement par une recherche indépendante de la valeur.
    # Haut signal (≠ env-secret) : la valeur n'est masquée que si un marqueur DSN la PRÉCÈDE
    # sur la même déclaration, ce qui écarte les `password=` isolés de doc ou de code.
    (
        "dsn-password",
        r"(?i)\b(?:host|hostaddr|dbname|sslmode|user)=[^\s;'\"]{1,64}"
        r"(?:[\s;]+[a-z_]{2,16}=[^\s;'\"]{1,64}){0,6}"
        r"[\s;]+password=['\"]?([^\s'\";,]{8,})",
        1,
    ),
    ("private-key", r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", 0),
    (
        "env-secret",
        r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|pwd|private[_-]?key|client[_-]?secret)"
        r"\b[ \t]*[:=][ \t]*[\"']?([^\s\"',`]{8,})",
        1,
    ),
]

# Règles à fort signal / bas taux de faux positifs (preset "safe").
HIGH_SIGNAL_RULES = frozenset(
    {
        "literal",
        "openai-api-key",
        "anthropic-api-key",
        "github-token",
        "forgejo-token",
        "aws-access-key",
        "google-api-key",
        "slack-token",
        "stripe-live-key",
        "cartesia-api-key",
        "groq-api-key",
        "inworld-api-key",
        "http-basic-credential",
        "jwe",
        "jwt",
        "auth0-refresh-token",
        "telegram-bot-token",
        "env-var-secret",
        "dsn-password",
        "google-session-cookie",
        "private-key",
    }
)


@dataclass
class Rule:
    rule_id: str
    regex: re.Pattern[str]
    group: int
    validator: Callable[[str], bool] | None = None


@dataclass
class Finding:
    rule_id: str
    start: int
    end: int
    preview: str
    digest: str = ""


_ESCAPED_WS_OR_BOUNDARY = r"(?:(?<=\\[nrt])|\b)"


def _compile(expr: str) -> re.Pattern[str]:
    """Compile une règle ; un `\\b` initial accepte aussi un `\\n`/`\\r`/`\\t` échappé (texte JSON d'un transcript)."""
    if expr.startswith(r"\b"):
        expr = _ESCAPED_WS_OR_BOUNDARY + expr[2:]
    return re.compile(expr)


def build_rules(literals: list[str] | None = None) -> list[Rule]:
    """Construit les règles par défaut, plus une règle « literal » par secret connu.

    Les littéraux (ex. une clé API exacte lue depuis le Credential Manager) sont
    placés en tête pour primer sur les règles génériques en cas de chevauchement.
    """
    rules = [
        Rule(rid, _compile(expr), grp, _VALUE_VALIDATORS.get(rid))
        for rid, expr, grp in _RULESPECS
    ]
    for lit in literals or []:
        value = lit.strip()
        if len(value) < 6:  # garde-fou : ne jamais matcher une chaîne triviale
            continue
        rules.insert(0, Rule("literal", re.compile(re.escape(value)), 0))
    return rules


def known_rule_ids() -> set[str]:
    """Vocabulaire complet des rule_id acceptés par --rules / --exclude-rules."""
    return {rid for rid, _, _ in _RULESPECS} | {"literal"}


def mask(value: str) -> str:
    """Aperçu masqué — calque de detect.Mask : 4 premiers + ... + 4 derniers."""
    clean = value.replace("\r", "").replace("\n", "\\n")
    if len(clean) <= 8:
        return "***"
    return clean[:4] + "..." + clean[-4:]


def digest(value: str) -> str:
    """Empreinte à sens unique d'un secret — identifie une VALEUR sans jamais la porter.

    Une même clé recopiée dans dix fichiers est un seul problème, pas dix : c'est ce
    qui permet de compter des valeurs distinctes, et de reconnaître une constante
    partagée entre dépôts sans rapport (donc publique) d'une fuite propre à un dépôt."""
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:8]


def find_in_text(content: str, rules: list[Rule]) -> list[Finding]:
    findings: list[Finding] = []
    for rule in rules:
        for match in rule.regex.finditer(content):
            if rule.group and rule.group <= (match.lastindex or 0):
                start, end = match.span(rule.group)
            else:
                start, end = match.span(0)
            if start < 0 or end <= start:
                continue
            value = content[start:end]
            if REDACTION_MARKER in value:  # idempotence : déjà masqué
                continue
            if rule.validator is not None and not rule.validator(value):
                continue  # valeur non-secret (placeholder/code/chemin) — cf. #10
            findings.append(Finding(rule.rule_id, start, end, mask(value), digest(value)))
    findings.sort(key=lambda f: f.start)
    return _dedupe_overlaps(findings)


def _dedupe_overlaps(findings: list[Finding]) -> list[Finding]:
    out: list[Finding] = []
    for finding in findings:
        if any(finding.start < kept.end and kept.start < finding.end for kept in out):
            continue
        out.append(finding)
    return out
