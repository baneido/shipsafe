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

Disable any rule (registry or custom) by ID:

```yaml
scanners:
  sast:
    disabled-rules:
      - "javascript.lang.security.audit.code-string-concat"
```

> The bundled `ai-generated-code` rule pack was removed in 0.2.0 — its
> patterns largely duplicated the OWASP registry pack. Configs that still
> list it are accepted; the entry is ignored with a warning. For noise
> reduction, use [AI triage](configuration.md) instead.

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

## Custom secret patterns

Secret detection uses gitleaks. ShipSafe bundles Japanese cloud / SaaS
patterns (Sakura Cloud, LINE, PayPay, freee, kintone) on top of the
gitleaks defaults — see [`rules/secrets/japan-cloud.toml`](../rules/secrets/japan-cloud.toml)
for the format. Suppress false positives with
`scanners.secrets.allow-patterns` in `.shipsafe.yml`.
