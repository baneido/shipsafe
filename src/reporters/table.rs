use crate::config::Config;
use crate::scanners::{ScanResults, Severity};
use colored::Colorize;

pub fn render(results: &ScanResults, _config: &Config) {
    println!();

    for finding in &results.findings {
        let severity_str = match finding.severity {
            Severity::Critical => "CRITICAL".red().bold().to_string(),
            Severity::High => "HIGH".yellow().bold().to_string(),
            Severity::Medium => "MEDIUM".blue().bold().to_string(),
            Severity::Low => "LOW".dimmed().to_string(),
        };

        let icon = match finding.severity {
            Severity::Critical => "!!",
            Severity::High => "!.",
            Severity::Medium => "..",
            Severity::Low => "  ",
        };

        println!("{} {}  {}", icon, severity_str, finding.title.bold());

        if let Some(line) = finding.line {
            println!("   {} {}:{}", "at".dimmed(), finding.file, line);
        } else if !finding.file.is_empty() {
            println!("   {} {}", "in".dimmed(), finding.file);
        }

        if !finding.description.is_empty() {
            println!("   {}", finding.description.dimmed());
        }

        if let Some(ref cwe) = finding.cwe {
            print!("   {}", cwe.cyan());
        }
        if let Some(ref cve) = finding.cve {
            print!("  {}", cve.cyan());
        }
        println!();

        if let Some(ref fix) = finding.fix_suggestion {
            println!("   {} {}", "Fix:".green().bold(), fix);
        }

        println!();
    }

    // Summary
    println!("{}", "=".repeat(52));
    println!(
        "Summary: {} findings | {} critical | {} high | {} medium | {} low",
        results.summary.total,
        results.summary.critical,
        results.summary.high,
        results.summary.medium,
        results.summary.low,
    );
    println!();
}
