# fresheyes

**Fresh eyes for risky code.** fresheyes is a fast, fully offline security
scanner that finds the risky patterns most often left in code before it
ships: hardcoded credentials, SQL built by string pasting, `shell=True`,
disabled TLS verification, weak crypto, debug mode left on, wildcard CORS,
unsafe deserialization, and `eval` on dynamic strings. Every finding is
reported in plain language with a concrete fix.

- No network calls, no telemetry, no LLM — the scanner never sends your code
  anywhere and never executes the code it reads.
- Python-first with real syntax-tree detectors; JavaScript/TypeScript and
  config files covered by careful pattern detectors.
- Fast enough to gate a commit: well under a second per thousand lines.

## Install

Requires Python 3.10 or newer.

```bash
pip install git+https://github.com/rayanalpha/fresheyes.git
```

Or from a local checkout:

```bash
git clone https://github.com/rayanalpha/fresheyes.git
cd fresheyes
pip install .
```

Verify:

```bash
fresheyes --version
```

## Quick start

```bash
cd your-project
fresheyes scan
```

Example output:

```
app.py
  CRITICAL  app.py:7:1   This file contains a hardcoded credential: API_KEY looks like a random string.  [hardcoded-secret]
            fix: Remove the value and read it from the environment (os.environ["YOUR_API_KEY_HERE"]) or a secret manager at runtime, then rotate the exposed key because anyone with this repository can use it.
  HIGH      app.py:21:5  SQL is built by pasting values into the query string, so anyone who controls those values can rewrite the statement.  [sql-injection]
            fix: Pass values as query parameters and keep the SQL in one literal: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,)) for DB-API, or cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,)) for sqlite3.

Found 2 issues (1 critical, 1 high) in 1 file in 0.01s.
Exit 1: 2 finding(s) at or above high.
```

## Commands

### `fresheyes scan [PATH]`

Scan a file or a directory tree (default: the current directory).

```bash
fresheyes scan                  # scan the current directory
fresheyes scan src/             # scan one directory
fresheyes scan app.py           # scan a single file
fresheyes scan --format json    # machine-readable output for CI
fresheyes scan --config team.toml
fresheyes scan --fail-on medium # fail on medium and above (default: high)
fresheyes scan --select sql-injection --select hardcoded-secret
fresheyes scan --ignore debug-mode
```

Noise directories (`.git`, `node_modules`, `__pycache__`, `dist`, `build`,
`.venv`) and vendored or minified files are skipped automatically.

**Exit codes:** `0` — no findings at or above the fail threshold;
`1` — findings at or above the threshold; `2` — usage or config error.

### `fresheyes rules`

List every rule with its severity, languages, and detector type.

```bash
fresheyes rules
fresheyes rules --format json
```

### `fresheyes --version`

Print the installed version.

## Rules

| id | severity | catches |
|----|----------|---------|
| `hardcoded-secret` | critical | string literals shaped like API keys or tokens assigned to secret-ish names, or sitting in config files |
| `jwt-no-verify` | critical | `jwt.decode` without signature verification, `algorithms=["none"]` |
| `sql-injection` | high | f-strings, `%` formatting or `+` concatenation flowing into `execute()` / raw SQL calls |
| `command-injection` | high | `shell=True`, `os.system`, `popen` with a shell on dynamic input |
| `insecure-deserialization` | high | `pickle.loads`, `yaml.load` without `SafeLoader`, `marshal` on untrusted data |
| `tls-no-verify` | high | `verify=False`, unverified SSL contexts |
| `template-injection` | high | `render_template_string` / Django `Template` / Nunjucks `renderString` built from user input |
| `client-side-secret` | medium | `NEXT_PUBLIC_*` / `VITE_*` / `REACT_APP_*` env var with a credential-ish name read into browser code |
| `insecure-random` | medium | `random` / `Math.random()` used to mint a token, password, salt, or session id instead of `secrets` |
| `log-injection` | medium | Untrusted input written to a log message (log forging via newlines) |
| `weak-crypto` | medium | MD5/SHA1 used for passwords, DES/3DES, ECB mode, hardcoded IVs |
| `debug-mode` | medium | Flask `debug=True`, Django `DEBUG = True` left on |
| `cors-wildcard` | medium | `Access-Control-Allow-Origin: *` together with credentials |
| `eval-exec` | medium | `eval` / `exec` on non-literal strings |

Run `fresheyes rules` to see the detector type, CWE reference, and
per-rule summary. Python detectors walk the syntax tree; JavaScript,
TypeScript, and config files use pattern detectors.

## Configuration

fresheyes reads `.fresheyes.toml` in the scanned directory, or the
`[tool.fresheyes]` table in `pyproject.toml` (a `--config FILE` path wins
over both):

```toml
# .fresheyes.toml
select = ["hardcoded-secret", "sql-injection"]  # only run these rules
ignore = ["debug-mode"]                          # never run this rule
fail_on_severity = "medium"                      # fail on medium and above

[tool.fresheyes.options."hardcoded-secret"]
ignore_names = ["EXAMPLE_TOKEN"]                 # skip this variable name
```

Inline suppression, with an optional reason:

```python
API_KEY = "YOUR_API_KEY_HERE"  # fresheyes: ignore[hardcoded-secret] - docs example
```

## JSON output

`fresheyes scan --format json` emits one object per finding:

```json
{
  "version": "0.1.0",
  "summary": {
    "total": 1,
    "by_severity": {"critical": 1, "high": 0, "medium": 0, "low": 0},
    "files_scanned": 1,
    "files_skipped": 0,
    "fail_on_severity": "high",
    "blocking": 1,
    "duration_s": 0.0123
  },
  "findings": [
    {
      "path": "app.py",
      "line": 7,
      "col": 1,
      "rule_id": "hardcoded-secret",
      "severity": "critical",
      "message": "This file contains a hardcoded credential: API_KEY looks like a random string.",
      "fix": "Remove the value and read it from the environment ..."
    }
  ]
}
```

## What fresheyes is not

- Not a replacement for a full SAST suite or for human review.
- It does not find logic bugs, and it does not need runtime information —
  everything is decided from the source text alone.

## License

MIT — see [LICENSE](LICENSE).
