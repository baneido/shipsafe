# FAQ

### What does ShipSafe actually run?

Three battle-tested scanners as subprocesses, in parallel: semgrep (SAST),
trivy (SCA, with grype as fallback), and gitleaks (secrets). ShipSafe
normalizes, deduplicates, and filters their findings into one report and
one exit code.

### Why not just run the three tools directly?

You can! ShipSafe adds: one command and one config instead of three, a
single severity model and fail threshold, merged + deduplicated results,
SARIF/JSON/table output, PR comments and Security-tab upload via one
action line, Japanese output, and rules tuned for AI-generated code.

### Is my code sent anywhere?

No. All scanning runs locally as subprocesses. Network access is only used
by the scanners themselves to fetch rule packs / vulnerability DBs.
ShipSafe has no telemetry.

### Do I need all three scanners installed?

No — missing scanners are skipped with a warning. `shipsafe doctor` shows
what's available.

### How is severity decided?

- SAST: semgrep `ERROR` → critical, `WARNING` → medium, `INFO` → low
- SCA: the advisory's own severity (trivy/grype)
- Secrets: by credential type — cloud infrastructure keys (AWS, GCP,
  Azure, Sakura Cloud, private keys) are critical; service tokens (GitHub,
  LINE, PayPay, freee, kintone, Slack, Stripe…) are high; generic matches
  are lower

### What are the "AI-generated code" rules?

A bundled semgrep rule pack targeting patterns AI assistants frequently
produce: hardcoded credentials, string-concatenated SQL, missing auth
middleware, XSS sinks, unsafe `yaml.load`/`eval`, shell-string commands,
`unsafe`/`static mut` in Rust, swallowed errors and goroutine
loop-capture races in Go. See [custom-rules.md](custom-rules.md).

### Does it work outside GitHub?

The CLI is CI-agnostic — gate any pipeline on its exit code and consume
the JSON/SARIF output. The composite action (PR comments, Security tab)
is GitHub-specific.

### Japanese support?

`--lang ja` localizes CLI output (severity labels 重大/高/中/低, summaries,
errors). Detection rules for Japanese cloud/SaaS credentials (Sakura
Cloud, LINE, PayPay, freee, kintone) are always on.

### How fast is it?

~6 seconds for a 100k-line polyglot repository on a laptop; see
[benchmarks.md](benchmarks.md).

### What about the AI triage / fix suggestions mentioned in the roadmap?

Not in v0.1. The `ai:` config block is reserved and has no effect yet.
Roadmap: reachability-based triage and AI fix suggestions in v0.2.0, SBOM
generation in v0.3.0.

### License?

MIT, including the bundled rules.
