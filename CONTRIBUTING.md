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

## リリース手順

バージョンは **Cargo.toml**・**Cargo.lock**・**git tag** の3か所で一致している必要があります（ずれると `cargo publish` や Docker / Homebrew の成果物が壊れます）。`make bump` が Cargo.toml と Cargo.lock を一括で更新します。

```bash
# 1. バージョンを更新（Cargo.toml + Cargo.lock を同期）
make bump VERSION=0.2.2

# 2. CHANGELOG.md を更新

# 3. PR を作成・マージ後、マージコミットにタグを打つ
git tag v0.2.2 && git push origin v0.2.2
```

タグの push で Release ワークフローが起動します。`verify-version` ジョブがタグと Cargo.toml / Cargo.lock の一致を検証し、ずれていればビルド前に失敗します。crates.io への publish は冪等で、同一バージョンが既に公開済みなら skip するため、Docker や Homebrew の失敗で再実行しても安全です。

## イシューの報告

バグ報告や機能リクエストは [Issues](https://github.com/baneido/shipsafe/issues) からお願いします。
