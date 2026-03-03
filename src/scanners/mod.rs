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

    /// Remove duplicate findings keyed on `(id, file, line)`. Scanners can
    /// surface the same issue (e.g. SAST and a custom rule), so dedup after
    /// merging all results.
    pub fn deduplicate(&mut self) {
        let mut seen = std::collections::HashSet::with_capacity(self.findings.len());
        self.findings
            .retain(|f| seen.insert((f.id.clone(), f.file.clone(), f.line)));
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
    let run_sast = scanners.contains(&"sast") && config.scanners.sast.enabled;
    let run_sca = scanners.contains(&"sca") && config.scanners.sca.enabled;
    let run_secrets = scanners.contains(&"secrets") && config.scanners.secrets.enabled;

    let sast_fut = async {
        if run_sast {
            sast::run(path, config).await
        } else {
            Ok(ScanResults::new())
        }
    };

    let sca_fut = async {
        if run_sca {
            sca::run(path, config).await
        } else {
            Ok(ScanResults::new())
        }
    };

    let secrets_fut = async {
        if run_secrets {
            secrets::run(path, config).await
        } else {
            Ok(ScanResults::new())
        }
    };

    let (sast_result, sca_result, secrets_result) = tokio::join!(sast_fut, sca_fut, secrets_fut);

    let mut results = ScanResults::new();

    // Scanners run concurrently above; print each result atomically (and in a
    // stable order) here so the lines never interleave.
    if run_sast {
        let r = sast_result?;
        print_scanner_done("SAST", &r, config);
        results.merge(r);
    }
    if run_sca {
        let r = sca_result?;
        print_scanner_done("SCA", &r, config);
        results.merge(r);
    }
    if run_secrets {
        let r = secrets_result?;
        print_scanner_done("Secrets", &r, config);
        results.merge(r);
    }

    results.deduplicate();

    Ok(results)
}

fn print_scanner_done(name: &str, results: &ScanResults, config: &Config) {
    let ja = config.lang == "ja";
    let prefix = format!("  {} {:<10} ... ", "▶".cyan(), name);
    let count = results.summary.total;
    if count == 0 {
        let msg = if ja { "検出 0 件" } else { "0 findings" };
        println!("{}{}", prefix, msg.green());
    } else {
        let parts: Vec<String> = [
            (results.summary.critical, "critical"),
            (results.summary.high, "high"),
            (results.summary.medium, "medium"),
            (results.summary.low, "low"),
        ]
        .iter()
        .filter(|(c, _)| *c > 0)
        .map(|(c, label)| format!("{} {}", c, label))
        .collect();
        if ja {
            println!("{}検出 {} 件 ({})", prefix, count, parts.join(", "));
        } else {
            println!("{}{} findings ({})", prefix, count, parts.join(", "));
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

    fn make_finding(
        id: &str,
        scanner: &str,
        severity: Severity,
        file: &str,
        line: Option<u32>,
    ) -> Finding {
        Finding {
            id: id.to_string(),
            scanner: scanner.to_string(),
            severity,
            title: id.to_string(),
            description: String::new(),
            file: file.to_string(),
            line,
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

    #[test]
    fn test_deduplicate_removes_duplicates() {
        let mut results = ScanResults::new();
        results.findings.push(make_finding(
            "CVE-1",
            "sast",
            Severity::High,
            "app.py",
            Some(10),
        ));
        results.findings.push(make_finding(
            "CVE-1",
            "sast",
            Severity::High,
            "app.py",
            Some(10),
        ));
        results.findings.push(make_finding(
            "CVE-2",
            "sca",
            Severity::Critical,
            "lib.py",
            None,
        ));

        results.deduplicate();

        assert_eq!(results.findings.len(), 2);
        assert_eq!(results.summary.total, 2);
        assert_eq!(results.summary.high, 1);
        assert_eq!(results.summary.critical, 1);
    }

    #[test]
    fn test_deduplicate_keeps_different_lines() {
        let mut results = ScanResults::new();
        results.findings.push(make_finding(
            "CVE-1",
            "sast",
            Severity::High,
            "app.py",
            Some(10),
        ));
        results.findings.push(make_finding(
            "CVE-1",
            "sast",
            Severity::High,
            "app.py",
            Some(20),
        ));

        results.deduplicate();

        assert_eq!(results.findings.len(), 2);
    }

    #[test]
    fn test_deduplicate_keeps_different_files() {
        let mut results = ScanResults::new();
        results.findings.push(make_finding(
            "CVE-1",
            "sast",
            Severity::High,
            "a.py",
            Some(10),
        ));
        results.findings.push(make_finding(
            "CVE-1",
            "sast",
            Severity::High,
            "b.py",
            Some(10),
        ));

        results.deduplicate();

        assert_eq!(results.findings.len(), 2);
    }

    #[test]
    fn test_deduplicate_no_duplicates() {
        let mut results = ScanResults::new();
        results.findings.push(make_finding(
            "CVE-1",
            "sast",
            Severity::High,
            "a.py",
            Some(1),
        ));
        results
            .findings
            .push(make_finding("CVE-2", "sca", Severity::Low, "b.py", Some(2)));

        results.deduplicate();

        assert_eq!(results.findings.len(), 2);
    }

    #[test]
    fn test_deduplicate_empty() {
        let mut results = ScanResults::new();
        results.deduplicate();
        assert_eq!(results.findings.len(), 0);
        assert_eq!(results.summary.total, 0);
    }

    #[test]
    fn test_merge_and_recalculate_summary() {
        let mut results = ScanResults::new();
        results.findings.push(make_finding(
            "CVE-1",
            "sast",
            Severity::Critical,
            "a.py",
            Some(1),
        ));

        let mut other = ScanResults::new();
        other.findings.push(make_finding(
            "CVE-2",
            "sca",
            Severity::High,
            "b.py",
            Some(2),
        ));
        other.findings.push(make_finding(
            "CVE-3",
            "sca",
            Severity::Medium,
            "c.py",
            Some(3),
        ));

        results.merge(other);

        assert_eq!(results.summary.total, 3);
        assert_eq!(results.summary.critical, 1);
        assert_eq!(results.summary.high, 1);
        assert_eq!(results.summary.medium, 1);
        assert_eq!(results.summary.low, 0);
    }
}
