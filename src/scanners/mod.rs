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
            summary: ScanSummary {
                total: 0,
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
            },
        }
    }

    pub fn merge(&mut self, other: ScanResults) {
        self.findings.extend(other.findings);
        self.recalculate_summary();
    }

    pub(crate) fn recalculate_summary(&mut self) {
        self.summary = ScanSummary {
            total: self.findings.len(),
            critical: self
                .findings
                .iter()
                .filter(|f| f.severity == Severity::Critical)
                .count(),
            high: self
                .findings
                .iter()
                .filter(|f| f.severity == Severity::High)
                .count(),
            medium: self
                .findings
                .iter()
                .filter(|f| f.severity == Severity::Medium)
                .count(),
            low: self
                .findings
                .iter()
                .filter(|f| f.severity == Severity::Low)
                .count(),
        };
    }

    /// Exit code based on severity thresholds. SCA findings honor the
    /// stricter of the global `--fail-on` and `scanners.sca.fail-on-severity`.
    pub fn max_severity_exit_code(&self, fail_on: &str, config: &Config) -> i32 {
        let global = parse_severity(fail_on).unwrap_or_else(|| {
            tracing::warn!(
                "unknown fail-on value '{}', defaulting to critical",
                fail_on
            );
            Severity::Critical
        });
        let sca_threshold = parse_severity(&config.scanners.sca.fail_on_severity)
            .unwrap_or_else(|| global.clone())
            .min(global.clone());

        let failed = self.findings.iter().any(|f| {
            let threshold = if f.scanner == "sca" {
                &sca_threshold
            } else {
                &global
            };
            f.severity >= *threshold
        });
        if failed {
            1
        } else {
            0
        }
    }
}

/// Parse a severity string (as used in `--fail-on` and config files).
fn parse_severity(s: &str) -> Option<Severity> {
    match s {
        "critical" => Some(Severity::Critical),
        "high" => Some(Severity::High),
        "medium" => Some(Severity::Medium),
        "low" => Some(Severity::Low),
        _ => None,
    }
}

pub async fn run_all(path: &Path, scanners: &[&str], config: &Config) -> Result<ScanResults> {
    let mut results = ScanResults::new();

    for scanner_name in scanners {
        match *scanner_name {
            "sast" if config.scanners.sast.enabled => {
                print_scanner_start("SAST");
                let r = sast::run(path, config).await?;
                print_scanner_done("SAST", &r, config);
                results.merge(r);
            }
            "sca" if config.scanners.sca.enabled => {
                print_scanner_start("SCA");
                let r = sca::run(path, config).await?;
                print_scanner_done("SCA", &r, config);
                results.merge(r);
            }
            "secrets" if config.scanners.secrets.enabled => {
                print_scanner_start("Secrets");
                let r = secrets::run(path, config).await?;
                print_scanner_done("Secrets", &r, config);
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

fn print_scanner_done(_name: &str, results: &ScanResults, config: &Config) {
    let ja = config.lang == "ja";
    let count = results.summary.total;
    if count == 0 {
        let msg = if ja { "検出 0 件" } else { "0 findings" };
        println!("{}", msg.green());
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
        if ja {
            println!("検出 {} 件 ({})", count, parts.join(", "));
        } else {
            println!("{} findings ({})", count, parts.join(", "));
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(scanner: &str, severity: Severity) -> Finding {
        Finding {
            id: "test".into(),
            scanner: scanner.into(),
            severity,
            title: "test".into(),
            description: String::new(),
            file: "test.rs".into(),
            line: None,
            cwe: None,
            cve: None,
            fix_suggestion: None,
        }
    }

    fn results_with(findings: Vec<Finding>) -> ScanResults {
        let mut r = ScanResults::new();
        r.findings = findings;
        r.recalculate_summary();
        r
    }

    #[test]
    fn test_exit_code_global_threshold() {
        let config = Config::default();
        let r = results_with(vec![finding("sast", Severity::High)]);
        assert_eq!(r.max_severity_exit_code("critical", &config), 0);
        assert_eq!(r.max_severity_exit_code("high", &config), 1);
        assert_eq!(r.max_severity_exit_code("low", &config), 1);
    }

    #[test]
    fn test_exit_code_sca_uses_config_threshold() {
        // Default ScaConfig.fail_on_severity is "high": an SCA high finding
        // fails the build even when the global threshold is critical.
        let config = Config::default();
        let r = results_with(vec![finding("sca", Severity::High)]);
        assert_eq!(r.max_severity_exit_code("critical", &config), 1);

        let r_medium = results_with(vec![finding("sca", Severity::Medium)]);
        assert_eq!(r_medium.max_severity_exit_code("critical", &config), 0);
    }

    #[test]
    fn test_exit_code_sca_honors_stricter_global() {
        // Global --fail-on low is stricter than sca fail-on-severity high.
        let config = Config::default();
        let r = results_with(vec![finding("sca", Severity::Low)]);
        assert_eq!(r.max_severity_exit_code("low", &config), 1);
    }

    #[test]
    fn test_exit_code_unknown_fail_on_defaults_to_critical() {
        let config = Config::default();
        let r = results_with(vec![finding("sast", Severity::High)]);
        assert_eq!(r.max_severity_exit_code("bogus", &config), 0);
        let r_crit = results_with(vec![finding("sast", Severity::Critical)]);
        assert_eq!(r_crit.max_severity_exit_code("bogus", &config), 1);
    }

    #[test]
    fn test_parse_severity() {
        assert_eq!(parse_severity("critical"), Some(Severity::Critical));
        assert_eq!(parse_severity("high"), Some(Severity::High));
        assert_eq!(parse_severity("medium"), Some(Severity::Medium));
        assert_eq!(parse_severity("low"), Some(Severity::Low));
        assert_eq!(parse_severity("bogus"), None);
    }
}
