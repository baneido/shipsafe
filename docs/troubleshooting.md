# Troubleshooting

## "semgrep/trivy/gitleaks not found — scan skipped"

ShipSafe orchestrates external scanners and skips any that are missing.
Check what's installed:

```sh
shipsafe doctor
```

Install the missing tools:

```sh
# macOS
brew install semgrep trivy gitleaks

# Linux
pip install semgrep
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
# gitleaks: download a release binary from https://github.com/gitleaks/gitleaks/releases
```

## A scanner times out

```
⚠ semgrep timed out after 300s — skipping
```

Large repositories or first-time rule downloads can exceed the default
300-second budget. Raise it:

```yaml
scanners:
  timeout-seconds: 900
```

Also consider excluding vendored/generated trees via
`scanners.sast.exclude` — semgrep time scales with scanned bytes.

## Network errors fetching rules or vulnerability DBs

semgrep downloads registry rule packs (`p/owasp-top-ten`) and trivy
downloads its vulnerability DB on first run. ShipSafe retries transient
network failures twice with backoff. In air-gapped environments:

- semgrep: vendor the rules locally and use `rules-paths` instead of
  registry names
- trivy: pre-populate the DB cache (`trivy fs --download-db-only` on a
  connected machine, then copy `~/.cache/trivy`)

## The build fails but I expected it to pass

The exit code is controlled by two thresholds:

1. Global `--fail-on` (default `critical`)
2. `scanners.sca.fail-on-severity` (default `high`) for SCA findings —
   the stricter of the two wins

The failure reason and offending findings are printed to stderr.

## False positives

- Secrets: add `scanners.secrets.allow-patterns` regexes (matched against
  the secret, file path, and matched text)
- SAST: add the rule ID to `scanners.sast.disabled-rules`, or exclude the
  path via `scanners.sast.exclude`
- Any scanner: add a glob to the top-level `exclude` list
- Test code noise: run with `--exclude-tests`

## gitleaks reports nothing for an obvious secret

gitleaks ships an allowlist of well-known example values (e.g. AWS's
documented `AKIAIOSFODNN7EXAMPLE`) and skips low-entropy strings like
`abcdef...`. Real credentials are detected; sanitized documentation
examples often are not — by design.

## `shipsafe validate` reports "unknown key"

Keys accept kebab-case and snake_case, but typos are rejected with a
suggestion list. Compare with the [configuration reference](configuration.md).

## Windows

The Windows binary runs the same orchestration, but the bundled installer
script (`install.sh`) targets Linux/macOS. Install via
`cargo install shipsafe` or download `shipsafe-x86_64-pc-windows-msvc.zip`
from the releases page. Scanners must be on `PATH`.

## Still stuck?

Run with `--verbose` for scanner-level logs and open an issue:
https://github.com/baneido/shipsafe/issues
