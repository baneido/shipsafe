# Configuration Reference (.shipsafe.yml)

Generate a starting point with `shipsafe init` and check your file with
`shipsafe validate`. All keys accept both kebab-case (preferred) and
snake_case.

```yaml
version: 1

scanners:
  # Per-scanner timeout in seconds. A scanner exceeding it is killed and
  # skipped with a warning (the rest of the gate still completes).
  timeout-seconds: 300

  sast:
    enabled: true
    # Rule packs. Built-ins:
    #   owasp-top-10        → semgrep p/owasp-top-ten (registry)
    #   ai-generated-code   → bundled AI-generated-code rules (py/js/rust/go)
    # Anything else is passed to semgrep --config verbatim
    # (registry names like p/django, local files, or directories).
    rules:
      - "owasp-top-10"
      - "ai-generated-code"
    # Extra rule files or directories (semgrep format).
    rules-paths:
      - "./security/custom-rules/"
    # Rule IDs to disable (semgrep --exclude-rule).
    disabled-rules:
      - "ai-rust-unsafe-block"
    # Paths semgrep should not scan (semgrep --exclude).
    exclude:
      - "vendor/"
    # Reserved for future language filtering.
    languages: []

  sca:
    enabled: true
    # SCA findings at/above this severity fail the build even when the
    # global --fail-on is laxer. The stricter threshold wins.
    fail-on-severity: high

  secrets:
    enabled: true
    # Regexes matched against the secret value, file path, and matched
    # text; matching findings are suppressed.
    allow-patterns:
      - "EXAMPLE_.*"
      - "tests/fixtures/"
    # Also scan git history (gitleaks --log-opts --all).
    scan-history: false

output:
  format: table   # table | json | sarif
  lang: en        # en | ja

# Glob patterns applied to the *results* of every scanner: any finding whose
# file path matches is dropped. Use for generated code, vendored trees, etc.
exclude:
  - "generated/**"
  - "third_party/**"

# Reserved for upcoming AI features (no effect in v0.1).
ai:
  triage: false
  fix-suggestions: false
```

## Custom rule auto-discovery

If the scanned directory contains a `rules/` folder, every `*.yml` /
`*.yaml` file in it with a top-level `rules:` key is passed to semgrep
automatically — no configuration needed. Non-rule YAML (docker-compose,
CI configs) is ignored. See [custom-rules.md](custom-rules.md).

## Precedence notes

- CLI flags override config: `--fail-on` (global threshold),
  `--exclude-tests` (appends test globs to `exclude`).
- `scanners.sca.fail-on-severity` and `--fail-on` are combined by taking
  the stricter for SCA findings.
- `exclude` (top level) filters results from all scanners;
  `scanners.sast.exclude` prevents semgrep from scanning paths at all
  (faster for large vendored trees).
