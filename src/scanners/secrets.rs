use crate::config::Config;
use crate::scanners::{Finding, ScanResults, Severity};
use anyhow::Result;
use std::path::Path;
use std::process::Command;

pub async fn run(path: &Path, config: &Config) -> Result<ScanResults> {
    let mut results = ScanResults::new();

    if which::which("gitleaks").is_err() {
        tracing::warn!("gitleaks not found, skipping secrets scan");
        return Ok(results);
    }

    let output = Command::new("gitleaks")
        .arg("detect")
        .arg("--source").arg(path)
        .arg("--report-format").arg("json")
        .arg("--report-path").arg("/dev/stdout")
        .arg("--no-banner")
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    if let Ok(leaks) = serde_json::from_str::<Vec<serde_json::Value>>(&stdout) {
        for leak in &leaks {
            let finding = Finding {
                id: format!("secret-{}", leak.get("RuleID").and_then(|r| r.as_str()).unwrap_or("unknown")),
                scanner: "secrets".to_string(),
                severity: Severity::Critical,
                title: format!("Secret detected: {}",
                    leak.get("Description").and_then(|d| d.as_str()).unwrap_or("Unknown secret")),
                description: format!("Rule: {}",
                    leak.get("RuleID").and_then(|r| r.as_str()).unwrap_or("")),
                file: leak.get("File").and_then(|f| f.as_str()).unwrap_or("").to_string(),
                line: leak.get("StartLine").and_then(|l| l.as_u64()).map(|l| l as u32),
                cwe: Some("CWE-798".to_string()),
                cve: None,
                fix_suggestion: Some("Remove the secret and rotate the credential immediately.".to_string()),
            };
            results.findings.push(finding);
        }
    }

    results.summary.total = results.findings.len();
    results.summary.critical = results.findings.iter().filter(|f| f.severity == Severity::Critical).count();
    Ok(results)
}
