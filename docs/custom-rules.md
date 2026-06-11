# Writing Custom Rules

ShipSafe's SAST scanner is powered by [semgrep](https://semgrep.dev), so
custom rules use the standard semgrep YAML format.

## Quick start

1. Create a `rules/` directory in your repository:

```yaml
# rules/no-internal-api.yml
rules:
  - id: no-internal-admin-api
    pattern: fetch("https://internal-admin.example.com/...")
    message: Do not call the internal admin API from product code.
    languages: [typescript, javascript]
    severity: ERROR
    metadata:
      category: security
```

2. Run `shipsafe scan`. Files under `rules/` with a top-level `rules:` key
   are auto-discovered and passed to semgrep — no configuration needed.

To keep rules elsewhere, point at them explicitly:

```yaml
# .shipsafe.yml
scanners:
  sast:
    rules-paths:
      - "./security/semgrep/"
      - "./team-rules/auth.yml"
```

## Severity mapping

| semgrep severity | ShipSafe severity |
|---|---|
| `ERROR` | critical |
| `WARNING` | medium |
| `INFO` | low |

## Disabling rules

Disable any rule (bundled or custom) by ID:

```yaml
scanners:
  sast:
    disabled-rules:
      - "ai-rust-unsafe-block"
```

## Bundled AI-generated-code rules

Enabled via `rules: ["ai-generated-code"]`. Sources live in
[`rules/sast/`](../rules/sast/) with semgrep `--test` cases beside each file.

| File | Rules |
|---|---|
| `python.yml` | `ai-py-hardcoded-credentials`, `ai-py-sql-injection-concat`, `ai-py-flask-sensitive-route-no-auth`, `ai-py-unsafe-yaml-load`, `ai-py-eval-on-input`, `ai-py-subprocess-shell-format` |
| `javascript.yml` | `ai-js-dangerously-set-inner-html`, `ai-js-inner-html-assignment`, `ai-js-document-write`, `ai-express-sensitive-route-no-middleware`, `ai-js-cors-wildcard-credentials`, `ai-js-insecure-cookie-defaults`, `ai-js-eval-interpolation` |
| `rust.yml` | `ai-rust-mem-transmute`, `ai-rust-static-mut`, `ai-rust-unsafe-block`, `ai-rust-unwrap-in-spawned-thread` |
| `go.yml` | `ai-go-empty-error-check`, `ai-go-discarded-error`, `ai-go-goroutine-loop-capture`, `ai-go-shell-command-concat` |

## Testing your rules

Use semgrep's test harness — annotate a sample file with `# ruleid:` /
`# ok:` comments next to lines that should (or should not) match:

```python
# tests in the same dir, same basename: rules/no-eval.yml + rules/no-eval.py
# ruleid: no-eval
eval(user_input)
# ok: no-eval
ast.literal_eval(user_input)
```

```sh
semgrep --test rules/
```

The shipsafe repository runs `semgrep --test rules/sast/` in CI; copy that
pattern for your own rules.

## Custom secret patterns

Secret detection uses gitleaks. ShipSafe bundles Japanese cloud / SaaS
patterns (Sakura Cloud, LINE, PayPay, freee, kintone) on top of the
gitleaks defaults — see [`rules/secrets/japan-cloud.toml`](../rules/secrets/japan-cloud.toml)
for the format. Suppress false positives with
`scanners.secrets.allow-patterns` in `.shipsafe.yml`.
