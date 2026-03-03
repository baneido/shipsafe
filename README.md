<p align="center">
  <img src="docs/logo.svg" alt="ShipSafe" width="120" />
</p>

<h1 align="center">ShipSafe</h1>

<p align="center">
  <strong>AI-Powered Pre-Deploy Security Gate</strong><br>
  Deploy前にコード・依存関係・シークレットを一括スキャン。AIがノイズを除去し、修正提案まで出す。
</p>

<p align="center">
  <a href="#インストール">インストール</a> •
  <a href="#クイックスタート">クイックスタート</a> •
  <a href="#github-actions">GitHub Actions</a> •
  <a href="#機能">機能</a> •
  <a href="#ドキュメント">ドキュメント</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT" />
  <img src="https://img.shields.io/badge/rust-1.75%2B-orange.svg" alt="Rust 1.75+" />
  <img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs Welcome" />
</p>

---

## なぜ ShipSafe？

開発者の **78%** が「セキュリティツールが多すぎる」と感じています。SAST、SCA、シークレット検出…バラバラのツールを管理し、大量のアラートに溺れる日々。

**ShipSafe** はこの問題を解決します:

- 🔗 **1コマンドで統合スキャン** — SAST + SCA + シークレット検出を一括実行
- ⚡ **1行でCI/CD統合** — GitHub Actionsに `uses: baneido/shipsafe@v1` を追加するだけ
- 🤖 **AIがノイズを除去** — 到達可能性分析で本当に危険な脆弱性だけを表示
- 🔧 **AIが修正提案** — PRコメントで修正コードを提示（Pro版）
- 🇯🇵 **日本語ネイティブ対応** — CLI出力・レポートを日本語で表示

## インストール

```bash
# Homebrew (macOS / Linux)
brew install baneido/tap/shipsafe

# Cargo (Rust)
cargo install shipsafe

# Docker
docker pull ghcr.io/baneido/shipsafe:latest

# バイナリダウンロード
curl -sSL https://install.shipsafe.dev | sh
```

## クイックスタート

```bash
# プロジェクトディレクトリでスキャン実行
shipsafe scan

# 特定のスキャナーのみ実行
shipsafe scan --scanners sast,sca,secrets

# JSON形式で出力
shipsafe scan --format json --output results.json

# SARIF形式で出力（GitHub Security tab統合）
shipsafe scan --format sarif --output results.sarif

# 日本語で出力
shipsafe scan --lang ja
```

### 出力例

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

### GitHub Actions パラメータ

| パラメータ | デフォルト | 説明 |
|-----------|-----------|------|
| `scanners` | `sast,sca,secrets` | 実行するスキャナー |
| `fail-on` | `critical` | ビルドを失敗させる重要度 |
| `format` | `table` | 出力形式 (table, json, sarif) |
| `lang` | `en` | 出力言語 (en, ja) |
| `config` | `.shipsafe.yml` | 設定ファイルパス |
| `pr-comment` | `true` | PRにコメントを投稿 |

## 機能

### 🔍 SAST（静的解析）
- Semgrepベースの高精度パターンマッチング
- OWASP Top 10 カバレッジ
- AI生成コード特化ルール（Copilot / Cursor対応）
- カスタムルール対応（YAML形式）

### 📦 SCA（依存関係スキャン）
- npm / pip / cargo / gem / go mod 対応
- CVEデータベースとのリアルタイム照合
- 到達可能性分析（本当に使われている脆弱性のみ表示）
- SBOM生成（CycloneDX / SPDX）

### 🔑 シークレット検出
- 800+ パターン対応（APIキー、トークン、パスワード）
- 日本のクラウドサービス対応（AWS Tokyo、さくらクラウド等）
- エントロピー分析による未知のシークレット検出
- Git履歴スキャン

## 設定ファイル

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
      - "tests/**"
      - "vendor/**"

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

## 料金プラン

| | Free | Pro | Team | Enterprise |
|---|---|---|---|---|
| **月額** | ¥0 | ¥2,980 | ¥9,800 | お問合せ |
| スキャン回数 | 100/月 | 無制限 | 無制限 | 無制限 |
| SAST + SCA + Secrets | ✅ | ✅ | ✅ | ✅ |
| PR コメント | ✅ | ✅ | ✅ | ✅ |
| AI 修正提案 | — | ✅ (50回/月) | ✅ (無制限) | ✅ |
| Docker/IaC スキャン | — | ✅ | ✅ | ✅ |
| チームダッシュボード | — | — | ✅ | ✅ |
| SSO/SAML | — | — | — | ✅ |

## 開発

```bash
# ビルド
cargo build

# テスト
cargo test

# ローカルで実行
cargo run -- scan --path ./example-project

# リリースビルド
cargo build --release
```

## ライセンス

MIT License — 詳細は [LICENSE](LICENSE) を参照。

## Contributing

コントリビューションを歓迎します！[CONTRIBUTING.md](CONTRIBUTING.md) をご確認ください。

---

<p align="center">
  Built with ❤️ by <a href="https://github.com/baneido">Canary Corporation</a>
</p>
