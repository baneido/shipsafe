<p align="center">
  <img src="docs/logo.svg" alt="ShipSafe" width="120" />
</p>

<h1 align="center">ShipSafe</h1>

<p align="center">
  <strong>AI-Powered Pre-Deploy Security Gate</strong><br>
  Scan code, dependencies, and secrets in one shot before deploying. AI filters out noise and suggests fixes.
</p>

<p align="center">
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#github-actions">GitHub Actions</a> •
  <a href="#features">Features</a> •
  <a href="#documentation">Documentation</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT" />
  <img src="https://img.shields.io/badge/rust-1.75%2B-orange.svg" alt="Rust 1.75+" />
  <img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs Welcome" />
</p>

---

## Why ShipSafe?

78% of developers say "there are too many security tools." SAST, SCA, secret detection… managing disparate tools and drowning in a flood of alerts every day.

ShipSafe consolidates all of this into a single command:

- Unified scan in one command — Run SAST + SCA + secret detection all at once
- One-line CI/CD integration — Just add `uses: baneido/shipsafe@v1` to GitHub Actions
- AI-powered noise reduction — Reachability analysis surfaces only the vulnerabilities that actually matter
- AI-generated fix suggestions — Suggests fix code in PR comments (Pro)
- Japanese-native support — CLI output and reports available in Japanese

## Installation

```bash
# Homebrew (macOS / Linux)
brew install baneido/tap/shipsafe

# Cargo (Rust)
cargo install shipsafe

# Docker
docker pull ghcr.io/baneido/shipsafe:latest

# Binary download
curl -sSL https://install.shipsafe.dev | sh
```

## Quick Start

```bash
# Run a scan in your project directory
shipsafe scan

# Run specific scanners only
shipsafe scan --scanners sast,sca,secrets

# Output in JSON format
shipsafe scan --format json --output results.json

# Output in SARIF format (GitHub Security tab integration)
shipsafe scan --format sarif --output results.sarif

# Output in Japanese
shipsafe scan --lang ja
```

### Example Output

```
🛡️ ShipSafe v0.1.0 — Pre-Deploy Security Gate

📂 Scanning: ./src (42 files)
  ✔ SAST    ... 3 findings (1 critical, 2 medium)
  ✔ SCA     ... 1 finding  (1 high)
  ✔ Secrets ... 0 findings

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔴 CRITICAL  SQL Injection in src/db/query.rs:42
   CWE-89 | Unsanitized user input in SQL query
   Fix: Use parameterized queries instead of string concatenation

🟠 HIGH  CVE-2024-XXXXX in lodash@4.17.20
   Prototype Pollution vulnerability
   Fix: Upgrade to lodash@4.17.21

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Summary: 4 findings | 1 critical | 1 high | 2 medium | 0 low
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
        with:
          scanners: "sast,sca,secrets"
          fail-on: "critical,high"
          format: "sarif"
          lang: "ja"
```

### GitHub Actions Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `scanners` | `sast,sca,secrets` | Scanners to run |
| `fail-on` | `critical` | Severity level that fails the build |
| `format` | `table` | Output format (table, json, sarif) |
| `lang` | `en` | Output language (en, ja) |
| `config` | `.shipsafe.yml` | Path to configuration file |
| `pr-comment` | `true` | Post a comment on the PR |

## Features

### SAST (Static Analysis)
- High-precision pattern matching powered by Semgrep
- OWASP Top 10 coverage
- Rules specialized for AI-generated code (Copilot / Cursor)
- Custom rules support (YAML format)

### SCA (Dependency Scanning)
- Supports npm, pip, cargo, gem, and go mod
- Real-time matching against CVE databases
- Reachability analysis (only surfaces vulnerabilities that are actually used)
- SBOM generation (CycloneDX / SPDX)

### Secret Detection
- 800+ patterns supported (API keys, tokens, passwords)
- Support for Japanese cloud services (AWS Tokyo, Sakura Cloud, etc.)
- Entropy analysis to detect unknown secrets
- Git history scanning

## Configuration

```yaml
# .shipsafe.yml
version: 1

scanners:
  sast:
    enabled: true
    languages: [rust, typescript, python]
    rules:
      - "owasp-top-10"
      - "ai-generated-code"
    exclude:
      - "tests/"
      - "vendor/"

  sca:
    enabled: true
    fail-on-severity: high

  secrets:
    enabled: true
    allow-patterns:
      - "EXAMPLE_.*"

output:
  format: sarif
  lang: ja

ai:
  triage: true
  fix-suggestions: true
```

## Development

```bash
# Build
cargo build

# Test
cargo test

# Run locally
cargo run -- scan --path ./example-project

# Release build
cargo build --release
```

## License

MIT License. See [LICENSE](LICENSE) for details.

## Contributing

Pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

<p align="center">
  Built with ❤️ by <a href="https://github.com/baneido">Baneido, Inc.</a>
</p>
