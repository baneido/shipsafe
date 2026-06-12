<p align="center">
  <img src="docs/logo.svg" alt="ShipSafe" width="120" />
</p>

<h1 align="center">ShipSafe</h1>

<p align="center">
  <strong>Pre-Deploy Security Gate</strong><br>
  Scan code, dependencies, and secrets in one shot before deploying.
</p>

<p align="center">
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#github-actions">GitHub Actions</a> •
  <a href="#features">Features</a> •
  <a href="#documentation">Documentation</a> •
  <a href="#roadmap">Roadmap</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT" />
  <img src="https://github.com/baneido/shipsafe/actions/workflows/ci.yml/badge.svg" alt="CI" />
  <img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs Welcome" />
</p>

---

## Why ShipSafe?

78% of developers say "there are too many security tools." SAST, SCA, secret detection… managing disparate tools and drowning in a flood of alerts every day.

ShipSafe consolidates all of this into a single command:

- **Unified scan in one command** — SAST (semgrep) + SCA (trivy) + secret detection (gitleaks), run in parallel and merged into one deduplicated report
- **One-line CI/CD integration** — `uses: baneido/shipsafe@v1` gives you PR comments, the GitHub Security tab, and build gating
- **AI triage that cuts the noise** — Claude reviews every finding with its surrounding code and marks clear false positives (test fixtures, sample values, unreachable code). They stay in the report with the reasoning attached, but stop failing your build
- **Japanese-native support** — CLI output in Japanese (`--lang ja`) and detection rules for Japanese cloud services (Sakura Cloud, LINE, PayPay, freee, kintone)
- **Fast** — a 100k-line repository scans in about 6 seconds ([benchmarks](docs/benchmarks.md))

## Installation

```bash
# Homebrew (macOS / Linux)
brew install baneido/tap/shipsafe

# Cargo (Rust)
cargo install shipsafe

# Docker
docker pull ghcr.io/baneido/shipsafe:latest

# Binary download (Linux / macOS)
curl -sSL https://raw.githubusercontent.com/baneido/shipsafe/main/scripts/install.sh | sh
```

ShipSafe orchestrates external scanners. Install the ones you need and check with `shipsafe doctor`:

```bash
brew install semgrep trivy gitleaks   # macOS
shipsafe doctor
```

A missing scanner is skipped with a warning — the gate never blocks on tooling you haven't installed.

## Quick Start

```bash
# Run a scan in your project directory
shipsafe scan

# Run specific scanners only
shipsafe scan --scanners sast,secrets

# Fail the build on high-or-worse findings
shipsafe scan --fail-on high

# Output JSON / SARIF
shipsafe scan --format json --output results.json
shipsafe scan --format sarif --output results.sarif

# Japanese output
shipsafe scan --lang ja

# Exclude test directories from results
shipsafe scan --exclude-tests

# AI triage: drop false positives from the gate (requires ANTHROPIC_API_KEY)
export ANTHROPIC_API_KEY=sk-ant-...
shipsafe scan --ai-triage --fail-on high

# Validate your config
shipsafe validate
```

### Example Output

```
  ShipSafe v0.2.0 — Pre-Deploy Security Gate

  ▶ SAST       ... 2 findings (1 critical, 1 medium)
  ▶ SCA        ... 1 findings (1 high)
  ▶ Secrets    ... 1 findings (1 critical)
  ▶ AI Triage  ... 4 triaged (2 true positive, 1 false positive, 1 uncertain)
    false positives stay in the report but are excluded from the --fail-on gate

!! CRITICAL  python.lang.security.audit.formatted-sql-query
   at app.py:17
   Detected possible formatted SQL query. Use parameterized queries instead.
   AI triage: true positive (high confidence) — request parameter flows into the query string unsanitized

!! CRITICAL  Sakura Cloud Credential detected: Sakura Cloud API access token
   at examples/config.py:2
   Rule: sakura-cloud-api-key | Category: Sakura Cloud Credential
   CWE-798
   Fix: Remove the secret and rotate the credential immediately.
   AI triage: false positive (high confidence) — placeholder value in documented example code

====================================================
Summary: 4 findings | 2 critical | 1 high | 1 medium | 0 low

✘ Build failed: 1 finding(s) at or above the '--fail-on critical' severity threshold
```

## GitHub Actions

```yaml
# .github/workflows/security.yml
name: ShipSafe Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - uses: baneido/shipsafe@v1
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}  # for ai-triage
        with:
          scanners: "sast,sca,secrets"
          fail-on: "high"
          ai-triage: "true"
          lang: "ja"
```

On pull requests the action posts a summary comment (updated in place) and
inline review comments on the changed lines; SARIF results appear in the
repository's **Security** tab.

### Inputs

| Input | Default | Description |
|-----------|---------|-------------|
| `scanners` | `sast,sca,secrets` | Scanners to run |
| `fail-on` | `critical` | Severity that fails the build (`critical`, `high`, `medium`, `low`) |
| `format` | `sarif` | Report format (`sarif`, `json`, `table`) |
| `lang` | `en` | Output language (`en`, `ja`) |
| `config` | `.shipsafe.yml` | Path to configuration file |
| `ai-triage` | `false` | Run AI triage (set the `ANTHROPIC_API_KEY` env var on the job) |
| `pr-comment` | `true` | Post summary + inline comments on PRs |
| `upload-sarif` | `true` | Upload SARIF to the GitHub Security tab |
| `version` | `latest` | ShipSafe version to install |

### Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total number of findings |
| `critical-count` | Number of critical findings |
| `sarif-file` | Path to the SARIF report |

## Features

### AI Triage (noise reduction)
- Opt-in (`--ai-triage` or `ai.triage: true`), bring your own key: requests go directly to the Anthropic API with your `ANTHROPIC_API_KEY` — nothing passes through ShipSafe servers
- Claude reviews each finding with ±12 lines of surrounding code and classifies it as true positive / false positive / uncertain, with a one-sentence reason
- False positives stay in every report (table, JSON, SARIF) with the verdict and reasoning attached — they are only excluded from the `--fail-on` gate. Uncertain findings keep gating (fail safe)
- Cost controls: one batched API call per scan, `ai.max-findings` cap (default 50, prioritized by severity), configurable `ai.model` (default `claude-opus-4-8`)
- Never blocks the gate: a missing key, network failure, or API error just skips triage with a warning

### SAST (Static Analysis)
- High-precision pattern matching powered by Semgrep
- OWASP Top 10 coverage (`p/owasp-top-ten`)
- Custom rules: auto-loaded from your `rules/` directory or via `rules-paths` ([guide](docs/custom-rules.md))

### SCA (Dependency Scanning)
- Powered by Trivy (falls back to Grype): npm, pip, cargo, gem, go mod, and more
- CVE matching with per-scanner severity threshold (`fail-on-severity`)
- Fix versions surfaced as upgrade suggestions

### Secret Detection
- Gitleaks-powered, 800+ patterns (API keys, tokens, private keys)
- Japanese cloud / SaaS patterns bundled: Sakura Cloud, LINE Messaging API, PayPay, freee, kintone
- Optional git history scanning (`scan-history: true`)
- `allow-patterns` to suppress known-safe matches

### CI control
- `--fail-on` threshold with exit code 1 and a failure explanation in the log
- Per-scanner timeout (`scanners.timeout-seconds`), network retries, and graceful degradation when a scanner is missing

## Configuration

```yaml
# .shipsafe.yml — validate with `shipsafe validate`
version: 1

scanners:
  timeout-seconds: 300
  sast:
    enabled: true
    rules:
      - "owasp-top-10"
    rules-paths:
      - "./security/custom-rules/"
    disabled-rules:
      - "javascript.lang.security.audit.code-string-concat"
    exclude:
      - "vendor/"
  sca:
    enabled: true
    fail-on-severity: high
  secrets:
    enabled: true
    allow-patterns:
      - "EXAMPLE_.*"

# AI triage (requires ANTHROPIC_API_KEY)
ai:
  triage: true
  model: claude-opus-4-8
  max-findings: 50

output:
  format: table
  lang: ja

# Glob excludes applied to findings from every scanner
exclude:
  - "generated/**"
```

Full reference: [docs/configuration.md](docs/configuration.md)

## Documentation

- [CLI reference](docs/cli.md)
- [Configuration reference](docs/configuration.md)
- [Writing custom rules](docs/custom-rules.md)
- [Troubleshooting](docs/troubleshooting.md)
- [FAQ](docs/faq.md)
- [Benchmarks](docs/benchmarks.md)
- [Architecture](docs/architecture.md)

## Roadmap

Planned for upcoming releases (not yet implemented):

- **v0.3.0** — AI fix suggestions in PR comments, entropy-based unknown-secret detection, SBOM generation (CycloneDX / SPDX)
- **v0.4.0** — IaC scanning, organization dashboards

## Development

```bash
cargo build            # build
cargo test             # unit + integration tests
cargo run -- scan      # run locally
scripts/benchmark.sh   # performance benchmark
```

## License

MIT License. See [LICENSE](LICENSE) for details.

## Contributing

Pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

<p align="center">
  Built with ❤️ by <a href="https://baneido.com">Baneido, Inc.</a>
</p>
