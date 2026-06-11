# Product Hunt launch draft

## Listing

- **Name:** ShipSafe
- **Tagline (60 chars):** One-command security gate for AI-generated code
- **Topics:** Developer Tools, GitHub, Open Source, Security
- **Links:** https://github.com/baneido/shipsafe · https://shipsafe.dev

## Description

ShipSafe is an open-source pre-deploy security gate that runs SAST
(semgrep), dependency scanning (trivy), and secret detection (gitleaks) in
parallel with a single command — and turns the merged result into one exit
code your CI can trust.

What makes it different:

🤖 **Rules for AI-generated code.** Copilot/Cursor/ChatGPT keep producing
the same vulnerable patterns: string-concatenated SQL, missing auth
middleware, `dangerouslySetInnerHTML`, swallowed Go errors, `unsafe` Rust.
ShipSafe ships a semgrep rule pack targeting exactly those, for Python,
JS/TS, Rust, and Go.

⚡ **Fast.** Scanners run as parallel async subprocesses; a 100k-line repo
scans in ~6 seconds.

💬 **One line in GitHub Actions.** `uses: baneido/shipsafe@v1` gets you PR
summary + inline comments, the Security tab (SARIF), and build gating.

🇯🇵 **Japanese-native.** Full Japanese output, plus secret detection for
Japanese cloud services (Sakura Cloud, LINE, PayPay, freee, kintone) that
global tools miss.

Free and MIT-licensed. We'd love your feedback!

## First comment (maker)

Hi Product Hunt! 👋

We built ShipSafe after watching teams ship AI-generated code faster than
they could review it. Existing scanners are great but fragmented — three
tools, three configs, three result formats, and a wall of noise.

ShipSafe is our answer: one command, one config, one severity model, one
exit code. The fun part: while building it, ShipSafe's own gate caught a
shell-injection pattern in our GitHub Action and a missing non-root USER
in our Dockerfile. Dogfooding works 😅

Ask us anything — and tell us which AI-generated vulnerability patterns
you keep seeing; we're growing the rule pack.

## Gallery / screenshots checklist

- [ ] Terminal: full scan with findings (ja and en)
- [ ] PR summary comment + inline comment screenshot
- [ ] GitHub Security tab with ShipSafe SARIF alerts
- [ ] `shipsafe doctor` output
- [ ] Landing page hero
