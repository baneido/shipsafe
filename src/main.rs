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
    },

    /// 設定ファイルを初期化
    Init,

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
        } => {
            print_banner();

            let config = config::Config::load(&cli.config, &cli.lang)?;
            let scanner_list: Vec<&str> = scanners.split(',').map(|s| s.trim()).collect();

            let results = scanners::run_all(&path, &scanner_list, &config).await?;

            reporters::report(&results, &format, output.as_deref(), &config)?;

            let exit_code = results.max_severity_exit_code(&fail_on, &config);
            if exit_code > 0 {
                std::process::exit(exit_code);
            }
        }

        Commands::Init => {
            config::init_config()?;
            println!("{} .shipsafe.yml を作成しました", "✔".green().bold());
        }

        Commands::Doctor => {
            println!("{}", "ShipSafe Doctor".bold());
            println!();
            scanners::check_dependencies();
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
