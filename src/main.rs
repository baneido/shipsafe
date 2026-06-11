use clap::{Parser, Subcommand};
use colored::Colorize;
use std::path::PathBuf;

mod ai;
mod config;
mod reporters;
mod scanners;

#[derive(Parser)]
#[command(
    name = "shipsafe",
    about = "ShipSafe - AI-Powered Pre-Deploy Security Gate",
    version,
    long_about = "Deploy前にコード・依存関係・シークレットを一括スキャン。\nAIがノイズを除去し、修正提案まで出す。"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// 設定ファイルのパス
    #[arg(short, long, global = true, default_value = ".shipsafe.yml")]
    config: PathBuf,

    /// 出力言語 (en, ja)
    #[arg(long, global = true, default_value = "en")]
    lang: String,

    /// 詳細ログを出力
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// セキュリティスキャンを実行
    Scan {
        /// スキャン対象のパス
        #[arg(short, long, default_value = ".")]
        path: PathBuf,

        /// 実行するスキャナー (カンマ区切り: sast,sca,secrets)
        #[arg(short, long, default_value = "sast,sca,secrets")]
        scanners: String,

        /// 出力形式 (table, json, sarif)
        #[arg(short, long, default_value = "table")]
        format: String,

        /// 出力ファイルパス
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// この重要度以上でビルド失敗 (critical, high, medium, low)
        #[arg(long, default_value = "critical")]
        fail_on: String,

        /// テストディレクトリ・テストファイルを除外
        #[arg(long)]
        exclude_tests: bool,

        /// メイン出力に加えて JSON 結果をこのパスへ書き出す (CI 連携用)
        #[arg(long)]
        json_output: Option<PathBuf>,
    },

    /// 設定ファイルを初期化
    Init,

    /// 設定ファイルを検証
    Validate,

    /// インストールされているスキャナーを確認
    Doctor,

    /// バージョン情報を表示
    Version,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt().with_env_filter(log_level).init();

    match cli.command {
        Commands::Scan {
            path,
            scanners,
            format,
            output,
            fail_on,
            exclude_tests,
            json_output,
        } => {
            print_banner();

            let mut config = config::Config::load(&cli.config, &cli.lang)?;
            if exclude_tests {
                config
                    .exclude
                    .extend(scanners::TEST_EXCLUDE_GLOBS.iter().map(|s| s.to_string()));
            }
            let config = config;
            let scanner_list: Vec<&str> = scanners.split(',').map(|s| s.trim()).collect();

            let results = scanners::run_all(&path, &scanner_list, &config).await?;

            reporters::report(&results, &format, output.as_deref(), &config)?;

            // Machine-readable copy for CI integrations (action outputs and
            // PR comments) regardless of the primary format.
            if let Some(ref json_path) = json_output {
                std::fs::write(json_path, reporters::json::render(&results)?)?;
            }

            if results.max_severity_exit_code(&fail_on, &config) != 0 {
                let failing = results.failing_findings(&fail_on, &config);
                // Surface the failure reason so CI logs explain why the build
                // failed, not just that it failed.
                if config.lang == "ja" {
                    eprintln!(
                        "{} ビルド失敗: 重要度しきい値 (--fail-on {}) 以上の検出が {} 件あります",
                        "✘".red().bold(),
                        fail_on,
                        failing.len()
                    );
                } else {
                    eprintln!(
                        "{} Build failed: {} finding(s) at or above the '--fail-on {}' severity threshold",
                        "✘".red().bold(),
                        failing.len(),
                        fail_on
                    );
                }
                for f in failing.iter().take(10) {
                    let loc = match f.line {
                        Some(line) => format!("{}:{}", f.file, line),
                        None => f.file.clone(),
                    };
                    eprintln!(
                        "    [{}] {} ({})",
                        f.severity.label(&config.lang),
                        f.title,
                        loc
                    );
                }
                if failing.len() > 10 {
                    if config.lang == "ja" {
                        eprintln!("    ... ほか {} 件", failing.len() - 10);
                    } else {
                        eprintln!("    ... and {} more", failing.len() - 10);
                    }
                }
                std::process::exit(1);
            }
        }

        Commands::Init => {
            config::init_config()?;
            if cli.lang == "ja" {
                println!("{} .shipsafe.yml を作成しました", "✔".green().bold());
            } else {
                println!("{} Created .shipsafe.yml", "✔".green().bold());
            }
        }

        Commands::Validate => {
            let ja = cli.lang == "ja";
            let errors = config::validate_file(&cli.config)?;
            if errors.is_empty() {
                if ja {
                    println!(
                        "{} {} は有効な設定です",
                        "✔".green().bold(),
                        cli.config.display()
                    );
                } else {
                    println!(
                        "{} {} is a valid configuration",
                        "✔".green().bold(),
                        cli.config.display()
                    );
                }
            } else {
                if ja {
                    eprintln!(
                        "{} {} に {} 件の問題があります:",
                        "✘".red().bold(),
                        cli.config.display(),
                        errors.len()
                    );
                } else {
                    eprintln!(
                        "{} {} has {} problem(s):",
                        "✘".red().bold(),
                        cli.config.display(),
                        errors.len()
                    );
                }
                for e in &errors {
                    eprintln!("  - {}", e);
                }
                std::process::exit(1);
            }
        }

        Commands::Doctor => {
            println!("{}", "ShipSafe Doctor".bold());
            println!();
            scanners::check_dependencies(&cli.lang);
        }

        Commands::Version => {
            println!("shipsafe {}", env!("CARGO_PKG_VERSION"));
        }
    }

    Ok(())
}

fn print_banner() {
    println!();
    println!(
        "  {} v{} — Pre-Deploy Security Gate",
        "ShipSafe".bold().cyan(),
        env!("CARGO_PKG_VERSION")
    );
    println!();
}
