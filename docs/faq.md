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
action line, Japanese output, and AI triage that keeps false positives
from failing your build.

### Is my code sent anywhere?

Not by default. All scanning runs locally as subprocesses; network access
is only used by the scanners themselves to fetch rule packs /
vulnerability DBs. ShipSafe has no telemetry.

The exception is **AI triage**, which is opt-in (`--ai-triage` or
`ai.triage: true`): for each finding it sends the finding metadata and up
to ±12 lines of surrounding code directly to the Anthropic API using your
own `ANTHROPIC_API_KEY`. Nothing is sent unless you enable it, and nothing
passes through ShipSafe-operated servers.

### How does AI triage work?

Claude (default `claude-opus-4-8`, configurable via `ai.model`) reviews
each finding with its surrounding code and classifies it as a true
positive, a false positive, or uncertain, with a one-sentence reason.
False positives stay in every report — annotated, so each verdict is
auditable — but stop counting toward `--fail-on`. Uncertain verdicts keep
gating (fail safe). Cost is bounded: one batched API call per scan, capped
at `ai.max-findings` (default 50, prioritized by severity). Any failure —
missing key, network error, refusal — skips triage with a warning and the
gate behaves exactly as without AI.

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

### What happened to the "AI-generated code" rules?

The bundled rule pack was removed in 0.2.0: its patterns (string-built
SQL, hardcoded credentials, XSS sinks, …) largely duplicated the OWASP
registry pack and double-reported the same lines. Configs that still list
`ai-generated-code` are accepted and ignored with a warning. AI triage is
the replacement strategy: instead of more overlapping rules, ShipSafe now
removes the noise from the rules you already run.

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

### What about AI fix suggestions?

AI triage shipped in v0.2.0 (see above). AI fix suggestions in PR
comments, entropy-based unknown-secret detection, and SBOM generation are
planned for upcoming releases — see the README roadmap.

### License?

MIT, including the bundled rules.
