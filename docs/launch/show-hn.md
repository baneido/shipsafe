# Show HN draft

**Title:** Show HN: ShipSafe – one-command security gate tuned for AI-generated code (Rust)

**URL:** https://github.com/baneido/shipsafe

**Text:**

Hi HN — we built ShipSafe, an open-source CLI that runs semgrep (SAST),
trivy (dependencies), and gitleaks (secrets) in parallel and merges
everything into one deduplicated report and one exit code.

Why another wrapper? Three reasons:

1. *AI-generated code has a signature.* Reviewing LLM-written PRs, we kept
   seeing the same classes of bugs: f-string SQL, routes without auth
   middleware, `dangerouslySetInnerHTML`, `yaml.load`, `static mut`,
   `if err != nil {}`. We wrote a semgrep rule pack for those patterns
   (Python/JS/TS/Rust/Go), with `semgrep --test` cases for every rule.

2. *Gates should be boring.* One severity model across tools, a
   `--fail-on` threshold, per-scanner timeouts, retry-on-network-flake,
   and graceful degradation when a scanner isn't installed. A 100k-line
   polyglot repo scans in ~6s because the scanners genuinely run
   concurrently (tokio + async subprocesses).

3. *Non-US coverage.* Most secret scanners know AWS and Stripe but not
   the providers common in Japan. ShipSafe bundles gitleaks rules for
   Sakura Cloud, LINE, PayPay, freee, and kintone, and the whole CLI
   speaks Japanese (`--lang ja`).

Favorite dogfooding moment: our own gate failed our PR because the GitHub
Action passed `${{ inputs.* }}` straight into `run:` (shell injection) and
the Dockerfile lacked a non-root USER. Both fixed before merge.

It's Rust, MIT-licensed. GitHub Action: `uses: baneido/shipsafe@v1` gives
PR comments + Security-tab SARIF. Honest limitations: the "AI triage /
fix suggestions" you may expect from the name are roadmap (v0.2), not
shipped — v0.1 is the deterministic gate.

Would love feedback, especially on the rule pack's false-positive rate on
your codebases.
