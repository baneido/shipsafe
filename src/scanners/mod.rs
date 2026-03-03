pub mod sast;
pub mod sca;
pub mod secrets;

use crate::config::Config;
use anyhow::Result;
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResults {
    pub findings: Vec<Finding>,
    pub summary: ScanSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub scanner: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub file: String,
    pub line: Option<u32>,
    pub cwe: Option<String>,
    pub cve: Option<String>,
    pub fix_suggestion: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

impl ScanResults {
    pub fn new() -> Self {
        Self {
            findings: vec![],
            summary: ScanSummary { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
        }
    }

    pub fn merge(&mut self, other: ScanResults) {
        self.findings.extend(other.findings);
        self.recalculate_summary();
    }

    fn recalculate_summary(&mut self) {
        self.summary = ScanSummary {
            total: self.findings.len(),
            critical: self.findings.iter().filter(|f| f.severity == Severity::Critical).count(),
            high: self.findings.iter().filter(|f| f.severity == Severity::High).count(),
            medium: self.findings.iter().filter(|f| f.severity == Severity::Medium).count(),
            low: self.findings.iter().filter(|f| f.severity == Severity::Low).count(),
        };
    }

    pub fn max_severity_exit_code(&self, fail_on: &str) -> i32 {
        let threshold = match fail_on {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Critical,
        };
        if self.findings.iter().any(|f| f.severity >= threshold) { 1 } else { 0 }
    }
}

pub async fn run_all(path: &Path, scanners: &[&str], config: &Config) -> Result<ScanResults> {
    let mut results = ScanResults::new();

    for scanner_name in scanners {
        match *scanner_name {
            "sast" if config.scanners.sast.enabled => {
                print_scanner_start("SAST");
                let r = sast::run(path, config).await?;
                print_scanner_done("SAST", &r);
                results.merge(r);
            }
            "sca" if config.scanners.sca.enabled => {
                print_scanner_start("SCA");
                let r = sca::run(path, config).await?;
                print_scanner_done("SCA", &r);
                results.merge(r);
            }
            "secrets" if config.scanners.secrets.enabled => {
                print_scanner_start("Secrets");
                let r = secrets::run(path, config).await?;
                print_scanner_done("Secrets", &r);
                results.merge(r);
            }
            _ => {}
        }
    }

    Ok(results)
}

fn print_scanner_start(name: &str) {
    print!("  {} {:<10} ... ", "▶".cyan(), name);
}

fn print_scanner_done(_name: &str, results: &ScanResults) {
    let count = results.summary.total;
    if count == 0 {
        println!("{}", "0 findings".green());
    } else {
        let parts: Vec<String> = [
            (results.summary.critical, "critical", "red"),
            (results.summary.high, "high", "yellow"),
            (results.summary.medium, "medium", "blue"),
            (results.summary.low, "low", "white"),
        ]
        .iter()
        .filter(|(c, _, _)| *c > 0)
        .map(|(c, label, _)| format!("{} {}", c, label))
        .collect();
        println!("{} findings ({})", count, parts.join(", "));
    }
}

pub fn check_dependencies() {
    let tools = vec![
        ("semgrep", "SAST scanner"),
        ("trivy", "SCA / Container / IaC scanner"),
        ("gitleaks", "Secret scanner"),
    ];

    for (cmd, desc) in tools {
        let status = if which::which(cmd).is_ok() {
            format!("{} Found", "✔".green())
        } else {
            format!("{} Not found", "✘".red())
        };
        println!("  {} {:<12} {}", status, cmd, desc.dimmed());
    }
}
