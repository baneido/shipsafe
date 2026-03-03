use crate::config::Config;
use crate::scanners::{Finding, ScanResults, Severity};
use anyhow::Result;
use std::path::Path;
use std::process::Command;

pub async fn run(path: &Path, config: &Config) -> Result<ScanResults> {
    let mut results = ScanResults::new();

    // Check if semgrep is available
    if which::which("semgrep").is_err() {
        tracing::warn!("semgrep not found, skipping SAST scan");
        return Ok(results);
    }

    let mut cmd = Command::new("semgrep");
    cmd.arg("scan")
        .arg("--json")
        .arg("--quiet")
        .arg(path);

    // Add rule configs
    for rule in &config.scanners.sast.rules {
        match rule.as_str() {
            "owasp-top-10" => { cmd.arg("--config").arg("p/owasp-top-ten"); }
            "ai-generated-code" => { cmd.arg("--config").arg("p/default"); }
            other => { cmd.arg("--config").arg(other); }
        }
    }

    // Add excludes
    for exclude in &config.scanners.sast.exclude {
        cmd.arg("--exclude").arg(exclude);
    }

    let output = cmd.output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        if let Some(semgrep_results) = json.get("results").and_then(|r| r.as_array()) {
            for result in semgrep_results {
                let severity = match result.get("extra")
                    .and_then(|e| e.get("severity"))
                    .and_then(|s| s.as_str())
                {
                    Some("ERROR") => Severity::Critical,
                    Some("WARNING") => Severity::Medium,
                    Some("INFO") => Severity::Low,
                    _ => Severity::Medium,
                };

                let finding = Finding {
                    id: result.get("check_id").and_then(|c| c.as_str()).unwrap_or("unknown").to_string(),
                    scanner: "sast".to_string(),
                    severity,
                    title: result.get("check_id").and_then(|c| c.as_str()).unwrap_or("").to_string(),
                    description: result.get("extra")
                        .and_then(|e| e.get("message"))
                        .and_then(|m| m.as_str())
                        .unwrap_or("")
                        .to_string(),
                    file: result.get("path").and_then(|p| p.as_str()).unwrap_or("").to_string(),
                    line: result.get("start").and_then(|s| s.get("line")).and_then(|l| l.as_u64()).map(|l| l as u32),
                    cwe: result.get("extra")
                        .and_then(|e| e.get("metadata"))
                        .and_then(|m| m.get("cwe"))
                        .and_then(|c| c.as_str())
                        .map(|s| s.to_string()),
                    cve: None,
                    fix_suggestion: result.get("extra")
                        .and_then(|e| e.get("fix"))
                        .and_then(|f| f.as_str())
                        .map(|s| s.to_string()),
                };
                results.findings.push(finding);
            }
        }
    }

    results.summary.total = results.findings.len();
    results.summary.critical = results.findings.iter().filter(|f| f.severity == Severity::Critical).count();
    results.summary.high = results.findings.iter().filter(|f| f.severity == Severity::High).count();
    results.summary.medium = results.findings.iter().filter(|f| f.severity == Severity::Medium).count();
    results.summary.low = results.findings.iter().filter(|f| f.severity == Severity::Low).count();

    Ok(results)
}
