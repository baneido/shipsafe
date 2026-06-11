---
title: "AI生成コード時代のセキュリティゲート「ShipSafe」を OSS で公開しました"
emoji: "🛡️"
type: "tech"
topics: ["security", "rust", "githubactions", "semgrep", "oss"]
published: false
---

# AI がコードを書く時代、レビューは追いつかない

Copilot や Cursor、Claude にコードを書かせるのが当たり前になりました。生産性は確実に上がった一方で、こんな経験はないでしょうか。

- LLM が書いた SQL が **f-string 結合** だった
- 生成された Flask の管理画面ルートに **認証デコレータがなかった**
- React コンポーネントに `dangerouslySetInnerHTML` がしれっと入っていた
- Go のエラーハンドリングが `if err != nil {}` (空) だった

どれも既存の静的解析で「原理的には」見つかります。しかし現実には SAST・SCA・シークレット検出と 3 種類のツールを別々に設定し、別々のフォーマットの結果を読む必要があり、ノイズに埋もれて誰も見なくなる——というのが多くの現場ではないでしょうか。

そこで、**デプロイ前チェックをワンコマンドに統合するゲート** を Rust で書き、OSS として公開しました。

https://github.com/baneido/shipsafe

# ShipSafe とは

```
$ shipsafe scan --lang ja --fail-on high

  ShipSafe v0.1.0 — Pre-Deploy Security Gate

  ▶ SAST       ... 検出 2 件 (重大 1 件, 中 1 件)
  ▶ SCA        ... 検出 1 件 (高 1 件)
  ▶ Secrets    ... 検出 1 件 (高 1 件)

!! 重大  ai-py-sql-injection-concat
   場所: app.py:17
   SQL クエリの文字列結合。パラメータ化クエリを使ってください。

====================================================
集計: 検出 4 件 | 重大 1 | 高 2 | 中 1 | 低 0

✘ ビルド失敗: 重要度しきい値 (--fail-on high) 以上の検出が 3 件あります
```

中身は実績あるスキャナーのオーケストレーションです。

| レイヤ | エンジン | 役割 |
|---|---|---|
| SAST | semgrep | コードの脆弱パターン検出 |
| SCA | trivy (grype フォールバック) | 依存関係の CVE |
| Secrets | gitleaks | 認証情報の混入 |

3 つを **tokio の非同期サブプロセスとして並列実行** し、結果を単一の severity モデルに正規化、`(ルールID, ファイル, 行)` で重複排除して 1 つのレポートと 1 つの exit code にまとめます。手元の計測では **10 万行のリポジトリで約 6 秒** です ([ベンチマーク](https://github.com/baneido/shipsafe/blob/main/docs/benchmarks.md))。

# 特徴 1: AI 生成コード検出ルール

semgrep ルールパックを同梱しています。LLM が出力しがちな脆弱パターンに特化したもので、全ルールに `semgrep --test` のテストケース付きです。

- **Python**: ハードコード認証情報 / SQL 文字列結合 / Flask センシティブルートの認証欠落 / `yaml.load` / `eval(input())` / `shell=True` 結合
- **JS/TS**: `dangerouslySetInnerHTML` / `innerHTML` 補間 / Express ルートのミドルウェア欠落 / CORS ワイルドカード + credentials / 不安全 Cookie / `eval`
- **Rust**: `mem::transmute` / `static mut` / 根拠のない `unsafe` / spawn 内 `unwrap`
- **Go**: 空のエラーチェック / エラー破棄 / goroutine のループ変数キャプチャ / シェル文字列結合

# 特徴 2: 日本のクラウドサービス対応

グローバルのシークレットスキャナーは AWS や Stripe には強い一方、国内サービスのキーはスルーしがちです。ShipSafe は gitleaks の拡張ルールとして以下を同梱しています。

- さくらのクラウド API トークン (重大)
- LINE Messaging API チャネルアクセストークン / シークレット
- PayPay API キー
- freee アクセストークン
- kintone API トークン

`--lang ja` で出力も完全に日本語化されます (重要度は 重大/高/中/低)。

# 特徴 3: GitHub Actions に 1 行

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: baneido/shipsafe@v1
    with:
      fail-on: high
      lang: ja
```

これだけで:

- PR に **サマリーコメント** (再実行時は同じコメントを更新、重複しない)
- 変更行への **インラインレビューコメント**
- SARIF を **Security タブ** にアップロード
- しきい値超過で **ビルドを失敗** させる

# ドッグフーディングで自分のバグを検出した話

開発中、ShipSafe 自身のリポジトリを ShipSafe でスキャンする self-scan CI を組んだところ、初回実行で **自分のコードの問題を検出してビルドが落ちました**。

1. `action.yml` の `run:` に `${{ inputs.* }}` を直接埋め込んでいた (GitHub Actions の shell injection パターン)
2. Dockerfile に非 root `USER` がなかった

どちらも修正してからマージしました。セキュリティツールが自分のゲートを通れないままリリースするわけにはいかないので、地味に効くプラクティスです。

# 正直な注意点

- ShipSafe は **オーケストレーター** です。semgrep / trivy / gitleaks は別途インストールが必要です (`shipsafe doctor` で確認、なければ警告してスキップ)
- 名前から想像される「AI によるトリアージ・修正提案」は **v0.2 のロードマップ** で、v0.1 にはまだありません。v0.1 は決定的なゲートに集中しています
- 検出は各エンジンの能力に依存します。誤検知は `allow-patterns` / `disabled-rules` / glob exclude で制御できます

# インストール

```bash
brew install baneido/tap/shipsafe   # Homebrew
cargo install shipsafe               # Cargo
docker pull ghcr.io/baneido/shipsafe # Docker
```

MIT ライセンスです。誤検知の報告・ルールの追加 PR を歓迎します!

https://github.com/baneido/shipsafe
