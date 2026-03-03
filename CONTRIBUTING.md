# Contributing to ShipSafe

ShipSafe へのコントリビューションを歓迎します！

## 開発環境のセットアップ

```bash
# Rust のインストール
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# スキャナーのインストール
pip install semgrep
brew install trivy gitleaks  # macOS
# or
sudo apt-get install -y trivy gitleaks  # Ubuntu

# ビルド & テスト
cargo build
cargo test
```

## プルリクエストの手順

1. このリポジトリをフォーク
2. フィーチャーブランチを作成 (`git checkout -b feature/amazing-feature`)
3. 変更をコミット (`git commit -m 'Add amazing feature'`)
4. ブランチにプッシュ (`git push origin feature/amazing-feature`)
5. プルリクエストを作成

## コーディング規約

- `cargo fmt` でフォーマット
- `cargo clippy` で警告ゼロを維持
- 新機能にはテストを追加
- コミットメッセージは [Conventional Commits](https://www.conventionalcommits.org/) に従う

## イシューの報告

バグ報告や機能リクエストは [Issues](https://github.com/baneido/shipsafe/issues) からお願いします。
