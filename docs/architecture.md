# ShipSafe Architecture

## Overview

```
Developer -> CLI (Rust) -> Scan Orchestrator -> [SAST, SCA, Secrets]
                                |
                            AI Layer (Claude API)
                                |
                            Result Aggregator -> Reporter -> Output
```

## Layers

### 1. Developer Interface
- **CLI**: Rust binary with clap for argument parsing
- **GitHub Action**: Composite action wrapping CLI
- **Web Dashboard**: Next.js (Phase 2)

### 2. Scan Orchestrator
- Routes scans to appropriate engines based on file types
- Aggregates results into unified format
- Deduplicates findings across scanners

### 3. Scan Engines (OSS)
- **SAST**: Semgrep OSS + custom rules
- **SCA**: Trivy (primary) + Grype (fallback)
- **Secrets**: Gitleaks
- **IaC**: Trivy IaC mode (planned)

### 4. AI Layer (Claude API, BYOK)
- **Triage** (shipped): one batched Messages API call per scan classifies
  findings (with surrounding code context) as true/false positives via
  structured outputs; false positives are annotated and excluded from the
  `--fail-on` gate. Opt-in, fails open (a triage error never blocks the scan).
- **Fix Suggester** (planned): Claude API for code fix generation

### 5. Output
- Table (terminal)
- JSON (programmatic)
- SARIF (GitHub Security tab)
- PR Comments (GitHub API)

## Key Design Decisions

1. **OSS-first**: Use proven OSS scanners, add value through orchestration + AI
2. **Single binary**: Rust for fast startup, easy distribution
3. **Zero-config**: Works out of the box with sensible defaults
4. **Pluggable**: Scanners can be swapped or added independently
