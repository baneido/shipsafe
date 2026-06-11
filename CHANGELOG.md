# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Fixed
- `--lang ja` now localizes table report, scanner progress, and file-output messages
- GitHub Action no longer swallows the scan exit code; `fail-on` now actually fails the build
- Config files accept kebab-case keys (`fail-on-severity`, `allow-patterns`, `scan-history`, `fix-suggestions`) as documented in README, with snake_case still supported for backward compatibility
- `ai-generated-code` SAST rule now uses the bundled ShipSafe rules instead of semgrep's `p/default`
- `scanners.sca.fail-on-severity` is now honored when computing the exit code (stricter of it and `--fail-on` applies to SCA findings)
- CI workflow declares least-privilege `permissions` (CodeQL alert)
- `--lang`, `--config`, and `--verbose` are now global flags, so `shipsafe scan --lang ja` works as documented (previously they were only accepted before the subcommand)
- `shipsafe init` now writes `version: 1` instead of `version: 0`, and partial config files (omitted sections) fall back to defaults instead of failing to parse

### Added
- Initial project structure
- CLI with `scan`, `init`, `doctor`, `version` commands
- SAST scanning via Semgrep integration
- SCA scanning via Trivy integration
- Secret scanning via Gitleaks integration
- Table, JSON, SARIF output formats
- GitHub Actions composite action
- Japanese language support
- `.shipsafe.yml` configuration file

### Coming Soon
- AI-powered triage (noise reduction)
- AI-powered fix suggestions
- Dockerfile scanning
- IaC (Terraform/CloudFormation) scanning
- Team dashboard
- PR inline comments
