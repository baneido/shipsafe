# GitHub Actions Marketplace 公開手順 (#15)

action.yml はリポジトリルートにあり、Marketplace 公開要件 (root action /
`name` / `description` / `branding`) を満たしています。

- name: **ShipSafe Security Scan**
- branding: shield / red
- カテゴリ: **Security** (primary), **Code quality** (secondary)

## 公開手順 (リリース時の手動ステップ)

Marketplace への掲載はリリース UI のチェックボックスでのみ行えます
(API 非対応)。v0.1.0 リリース時に:

1. https://github.com/baneido/shipsafe/releases で v0.1.0 リリースを開き
   **Edit** する
2. **Publish this Action to the GitHub Marketplace** にチェック
   - 初回は Marketplace Developer Agreement への同意と 2FA が必要
3. Primary category: **Security** / Another category: **Code quality**
4. **Update release** で公開

公開後、`uses: baneido/shipsafe@v1` 用に major タグを维持する:

```sh
git tag -f v1 v0.1.0 && git push -f origin v1
```

(以後のパッチリリースごとに v1 を進める)

## README スクリーンショット

Marketplace 掲載ページは README を表示する。以下を撮影して
`docs/images/` に追加し README から参照する (任意だが推奨):

- [ ] PR サマリーコメント + インラインコメント
- [ ] Security タブの ShipSafe アラート
- [ ] ターミナルのスキャン出力 (ja)

## サンプルワークフロー

README の [GitHub Actions セクション](../../README.md#github-actions) と
self-scan 実例 [.github/workflows/shipsafe.yml](../../.github/workflows/shipsafe.yml)
がそのままサンプルとして機能する。
