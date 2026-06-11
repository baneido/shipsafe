# CLI Reference

```
shipsafe [GLOBAL OPTIONS] <COMMAND>
```

## Global options

| Option | Default | Description |
|---|---|---|
| `-c, --config <PATH>` | `.shipsafe.yml` | Configuration file path |
| `--lang <LANG>` | `en` | Output language: `en`, `ja` |
| `-v, --verbose` | off | Debug-level logging |

## Commands

### `shipsafe scan`

Run the security gate.

| Option | Default | Description |
|---|---|---|
| `-p, --path <PATH>` | `.` | Directory to scan |
| `-s, --scanners <LIST>` | `sast,sca,secrets` | Comma-separated scanners |
| `-f, --format <FMT>` | `table` | `table`, `json`, `sarif` |
| `-o, --output <PATH>` | stdout | Write the report to a file |
| `--fail-on <SEV>` | `critical` | Exit 1 when findings at/above this severity exist: `critical`, `high`, `medium`, `low` |
| `--exclude-tests` | off | Drop findings in common test directories / test files |
| `--json-output <PATH>` | — | Additionally write JSON results (for CI integrations) |

Exit codes:

- `0` — no findings at or above the `--fail-on` threshold
- `1` — threshold exceeded (offending findings are listed on stderr)

SCA findings additionally honor `scanners.sca.fail-on-severity` from the
config; the stricter of the two thresholds wins.

### `shipsafe init`

Write a default `.shipsafe.yml` to the current directory.

### `shipsafe validate`

Validate `.shipsafe.yml` (or `--config <path>`): unknown keys (with
suggestions), enum values, regex/glob compilation, and `rules-paths`
existence. Exits 1 when problems are found.

### `shipsafe doctor`

Show which external scanners are installed:

```
ShipSafe Doctor

  ✔ Found semgrep      SAST scanner
  ✔ Found trivy        SCA / Container / IaC scanner
  ✘ Not found gitleaks Secret scanner
```

### `shipsafe version`

Print the version.

## Examples

```bash
# Gate a CI build on high-or-worse findings, writing SARIF for upload
shipsafe scan --fail-on high --format sarif --output results.sarif

# JSON results for both humans and machines
shipsafe scan --format table --json-output results.json

# Scan another directory in Japanese
shipsafe --lang ja scan -p ../my-app

# Only secrets, including git history (set scan-history: true in config)
shipsafe scan -s secrets
```
