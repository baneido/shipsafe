# X (Twitter) 告知ドラフト

## 日本語メインツイート

🛡️ ShipSafe v0.1.0 をリリースしました

デプロイ前のセキュリティチェックをワンコマンドに:
✅ SAST + 依存関係 + シークレット検出を並列実行
🤖 AI が生成しがちな脆弱コードの検出ルール同梱
🇯🇵 さくら/LINE/PayPay/freee/kintone のキー検出
⚡ 10万行を約6秒でスキャン

OSS (MIT) です👇
https://github.com/baneido/shipsafe

## スレッド (2/4)

GitHub Actions なら 1 行で導入できます。

PR にサマリー+変更行へのインラインコメント、
Security タブに SARIF 連携、しきい値でビルド制御。

```yaml
- uses: baneido/shipsafe@v1
  with:
    fail-on: high
    lang: ja
```

## スレッド (3/4)

おもしろかったのは、開発中に ShipSafe 自身のゲートが
自分のリポジトリの問題を 2 つ検出したこと。

- GitHub Action の shell injection パターン
- Dockerfile の非 root USER 欠落

ドッグフーディング大事 😅

## スレッド (4/4)

v0.1 は「決定的なゲート」に集中しています。
AI トリアージ / AI 修正提案は v0.2 のロードマップ。

フィードバック・誤検知報告お待ちしています!
⭐ もらえると励みになります
https://github.com/baneido/shipsafe

## English tweet

🛡️ ShipSafe v0.1.0 is out — an open-source, one-command pre-deploy
security gate.

✅ SAST + SCA + secrets, run in parallel (~6s for 100k lines)
🤖 semgrep rules tuned for AI-generated code (py/js/ts/rust/go)
💬 1-line GitHub Action: PR comments + Security tab
🇯🇵 Japanese cloud secrets support

MIT licensed → https://github.com/baneido/shipsafe
