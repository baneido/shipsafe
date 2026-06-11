# ShipSafe Performance Benchmarks

Reproduce with:

```sh
scripts/benchmark.sh            # ~100k lines (default)
scripts/benchmark.sh 115000     # custom size
```

The script generates a synthetic polyglot repository (Python / JavaScript /
Go in a realistic 1:1:1 mix plus dependency manifests) and runs a full
`shipsafe scan` (SAST + SCA + Secrets) against it, reporting wall-clock time
and peak memory.

## Results

Measured on 2026-06-12.

| Metric | Value |
|---|---|
| Repository size | 103,658 lines (3,834 files: py/js/go) |
| Scanners | semgrep 1.165.0 · trivy 0.71.1 · gitleaks 8.30.1 |
| **Wall-clock** | **5.9 s** |
| CPU time (user) | 23.0 s |
| Peak memory (RSS) | 426 MiB |
| Hardware | Apple Silicon (macOS, arm64) |

Target from the M4 milestone: **100k lines in under 30 seconds** — met with
a ~5x margin.

## Why it's fast

- **True scanner parallelism.** The three scanners run as concurrent
  subprocesses under tokio (`tokio::join!` + async `tokio::process`). The
  user/wall ratio above (~4x) shows the pipelines overlapping: total CPU
  work is 23 s but the gate finishes in under 6 s, bounded by the slowest
  scanner (semgrep) rather than the sum.
- **No double work.** Each scanner runs exactly once; results are merged,
  deduplicated by `(rule id, file, line)`, and filtered by glob excludes in
  Rust, which is negligible (<1 ms for thousands of findings).
- **Lean orchestration.** ShipSafe itself adds <10 MiB RSS on top of the
  scanners; peak memory is dominated by semgrep's Python runtime.

## Tuning knobs

| Knob | Effect |
|---|---|
| `--scanners sast,secrets` | Skip scanners you don't need; wall-clock drops to the slowest selected scanner. |
| `scanners.timeout-seconds` | Bound the worst case; a hung scanner is killed and skipped (default 300 s). |
| `scanners.sast.exclude` / global `exclude` | Skip vendored or generated trees — semgrep time scales roughly linearly with scanned bytes. |
| `--exclude-tests` | Drop test directories from results (post-filter). |

## Memory and time per scanner

Measured separately on the same 100k+ line corpus
(`shipsafe scan -s <scanner>` under `/usr/bin/time -l`):

| Scanner | Wall-clock | Peak RSS |
|---|---|---|
| SAST (semgrep) | 4.4 s | 380 MiB |
| SCA (trivy, warm DB) | 0.05 s | 90 MiB |
| Secrets (gitleaks) | 0.1 s | 53 MiB |

semgrep dominates both time and memory; the full-scan peak (426 MiB) is
essentially semgrep's own footprint, and the full-scan wall-clock tracks
the semgrep runtime plus ~1.5 s of startup overlap. trivy's first-ever run
additionally downloads its vulnerability DB (one-time, network-bound).
