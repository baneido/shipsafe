# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-06-12

First public release. 🚀

### Added
- CLI with `scan`, `init`, `validate`, `doctor`, `version` commands
- SAST scanning via Semgrep (`p/owasp-top-ten` + bundled rule packs)
- Bundled AI-generated-code detection rules for Python, JS/TS, Rust, and Go
  (21 rules, each with semgrep `--test` cases)
- SCA scanning via Trivy with Grype fallback; per-scanner severity
  threshold (`fail-on-severity`)
- Secret scanning via Gitleaks, extended with Japanese cloud/SaaS patterns
  (Sakura Cloud, LINE, PayPay, freee, kintone)
- Custom semgrep rules: auto-discovery from `rules/`, explicit
  `rules-paths`, per-rule disabling (`disabled-rules`)
- Global glob `exclude` applied to all scanners and `--exclude-tests` flag
- `shipsafe validate`: config schema validation with unknown-key
  suggestions, enum/regex/glob checks
- Table, JSON, and SARIF output; `--json-output` machine-readable copy
- Japanese localization (`--lang ja`): severity labels 重大/高/中/低,
  summaries, errors, fix suggestions
- `--fail-on` severity gate with exit code 1 and failure explanation
- Error handling: per-scanner timeouts (`scanners.timeout-seconds`),
  network-error retries with backoff, graceful skip of missing scanners
- True scanner parallelism (async subprocesses); ~6 s for a 100k-line
  repository (see docs/benchmarks.md)
- GitHub Actions composite action (repo-root `action.yml`): scanner
  auto-install, outputs (`findings-count`, `critical-count`,
  `sarif-file`), PR summary + inline review comments with dedup, SARIF
  upload to the Security tab, fail-on enforcement
- Installer script (`scripts/install.sh`) with `--version` and checksum
  verification
- Release pipeline: Linux x86_64/aarch64, macOS x86_64/aarch64, Windows
  x86_64 binaries with SHA256 checksums; Docker image on ghcr.io;
  crates.io publish; Homebrew tap auto-update (baneido/homebrew-tap)
- Documentation set: CLI / configuration / custom rules / troubleshooting
  / FAQ / benchmarks; landing page (site/) deployed via GitHub Pages
- Vulnerable-sample-app fixtures and e2e CI with all scanners

### Fixed
- `--lang ja` now localizes table report, scanner progress, and file-output messages
- GitHub Action no longer swallows the scan exit code; `fail-on` now actually fails the build
- Config files accept kebab-case keys (`fail-on-severity`, `allow-patterns`, `scan-history`, `fix-suggestions`) as documented, with snake_case still supported
- `ai-generated-code` SAST rule uses the bundled ShipSafe rules instead of semgrep's `p/default`
- `scanners.sca.fail-on-severity` is honored when computing the exit code (stricter of it and `--fail-on` applies to SCA findings)
- gitleaks report is written to a temp file instead of `/dev/stdout` (not writable in some sandboxed/CI environments)
- Action `run:` steps pass inputs through env vars (shell-injection hardening — caught by ShipSafe's own self-scan)
- Docker image runs as a non-root user (also caught by self-scan)
- `--lang`, `--config`, and `--verbose` are global flags
- `shipsafe init` writes `version: 1`; partial config files fall back to defaults

### Roadmap (not in this release)
- v0.2.0: AI-powered triage (noise reduction), AI fix suggestions,
  entropy-based unknown-secret detection
- v0.3.0: SBOM generation (CycloneDX / SPDX), IaC scanning, team dashboard
