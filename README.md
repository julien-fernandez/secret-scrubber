# secret-scrubber

Masks secrets (API keys, tokens, JWTs, private keys, database URLs…) in **AI agent transcripts**:
by default `~/.claude/projects` (Claude Code) and `~/.pi/agent/sessions` (pi), whichever exist.

## Why

Working with coding agents means their transcripts end up holding whatever passed through the
terminal: an `echo $API_KEY`, a tool output, a printed environment variable. Those `.jsonl` files
sit in plain text on disk, are synced, backed up and sometimes shared. `secret-scrubber` finds
the secrets and replaces them with `[MASKARA_REDACTED:<rule>]`.

It is the kind of control a company needs before rolling out AI agents to its teams: the agent
is useful, the data trail it leaves must be governed.

## Design choices

An auditable Python port of [`mrgoonie/maskara`](https://github.com/mrgoonie/maskara) (Go, MIT):
same regex detection rules, same value-aware JSONL/JSON redaction, atomic writes. Standard
library only, no external dependency.

Deliberate differences from maskara:

- **No `.bak` backup**: a backup would keep the secret alive in clear text. Writes are atomic
  (`tempfile` + `os.replace`).
- **`literal` rule**: injects the *exact* value of a known secret (for example read from the
  Windows Credential Manager), so it is scrubbed whatever its format.
- **Scope presets** (`--scope`): `safe` leaves out the noisy rules (`env-secret`,
  `database-url`) that mostly match code and examples.
- **Refuses to scan with no rule**: a selection that keeps no rule (unknown name in
  `--rules` / `--exclude-rules`, or `--scope literal` without a literal) exits with **code 2**
  and lists the valid names, instead of reporting `findings=0`, which would read as
  "nothing to mask".

## Install

```bash
pip install -e .          # provides the `secret-scrubber` command
# or without installing:
python -m secret_scrubber scan
```

## Usage

```bash
# Scan (dry run, writes nothing) — "safe" scope by default
secret-scrubber scan

# Apply (atomic in-place rewrite)
secret-scrubber apply

# Target a known secret read from the Windows Credential Manager
secret-scrubber apply --wcm-literal MCP_OLLAMA_API_KEY

# … or from an environment variable
OLLAMA_SCRUB_LITERAL="<key>" secret-scrubber scan --scope literal

# Scope and exclusions
secret-scrubber apply --scope safe --exclude-glob "*<current-session-id>*"
secret-scrubber scan  --scope all          # every rule, noisy ones included
secret-scrubber scan  --rules openai-api-key,jwt

# Rule names are those of detect.py::_RULESPECS (+ "literal").
# An unknown name fails with code 2 and prints the full list.
secret-scrubber scan  --rules github        # → ERROR: unknown (it is "github-token")
```

### Scopes (`--scope`)

| Scope | Rules applied |
|-------|---------------|
| `safe` (default) | all **except** `env-secret` and `database-url` (noise) |
| `all` | every rule |
| `literal` | only the literal secrets provided (`--wcm-literal` / `--literal-env`) |

`--rules` / `--exclude-rules` refine the preset.

## Detection rules

`openai-api-key`, `anthropic-api-key`, `github-token`, `aws-access-key`, `google-api-key`,
`slack-token`, `stripe-live-key`, `jwt`, `database-url`, `private-key`, `env-secret` (generic),
plus `literal` (known secrets).

The stdout report stays *silent when nothing is found*, which suits a scheduled job that should
only alert on a detection.

## Tests and lint

```bash
pip install -e . pytest
pytest -q                      # 58 tests
ruff check secret_scrubber/
pyright
```

## License

MIT, see [`LICENSE`](LICENSE), which includes the attribution to `mrgoonie/maskara`.
