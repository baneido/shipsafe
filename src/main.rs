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

        /// AI トリアージを実行 (要 ANTHROPIC_API_KEY)。誤検知と判定された
        /// 検出はレポートに注釈付きで残しつつ --fail-on の判定から除外する
        #[arg(long)]
        ai_triage: bool,
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
            ai_triage,
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

            let mut results = scanners::run_all(&path, &scanner_list, &config).await?;

            if ai_triage || config.ai.triage {
                run_ai_triage(&mut results, &path, &config).await;
            }
            let results = results;

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

/// Run AI triage and print a one-line summary. Failures only warn — the AI
/// layer must never break the gate, so an untriaged scan proceeds as usual.
async fn run_ai_triage(
    results: &mut scanners::ScanResults,
    path: &std::path::Path,
    config: &config::Config,
) {
    let ja = config.lang == "ja";
    match ai::triage::run(results, path, config).await {
        Ok(summary) => {
            let prefix = format!("  {} {:<10} ... ", "▶".cyan(), "AI Triage");
            if ja {
                let mut line = format!(
                    "{}件を判定 (要対応 {} / 誤検知 {} / 要確認 {})",
                    summary.triaged,
                    summary.true_positives,
                    summary.false_positives,
                    summary.uncertain
                );
                if summary.skipped > 0 {
                    line.push_str(&format!(
                        " — {} 件は ai.max-findings 超過のため未判定",
                        summary.skipped
                    ));
                }
                println!("{}{}", prefix, line);
                if summary.false_positives > 0 {
                    println!(
                        "    誤検知と判定された検出はレポートに残り、--fail-on の集計からは除外されます"
                    );
                }
            } else {
                let mut line = format!(
                    "{} triaged ({} true positive, {} false positive, {} uncertain)",
                    summary.triaged,
                    summary.true_positives,
                    summary.false_positives,
                    summary.uncertain
                );
                if summary.skipped > 0 {
                    line.push_str(&format!(
                        " — {} left untriaged (over ai.max-findings)",
                        summary.skipped
                    ));
                }
                println!("{}{}", prefix, line);
                if summary.false_positives > 0 {
                    println!(
                        "    false positives stay in the report but are excluded from the --fail-on gate"
                    );
                }
            }
        }
        Err(e) => {
            scanners::exec::warn_user(
                &config.lang,
                &format!("AI triage skipped: {:#}", e),
                &format!("AI トリアージをスキップしました: {:#}", e),
            );
        }
    }
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
