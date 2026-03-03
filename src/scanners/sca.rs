use crate::config::Config;
use crate::scanners::{Finding, ScanResults, Severity};
use anyhow::Result;
use std::path::Path;
use std::process::Command;

pub async fn run(path: &Path, config: &Config) -> Result<ScanResults> {
    let mut results = ScanResults::new();

    // Try trivy first, then grype
    if which::which("trivy").is_ok() {
        results = run_trivy(path, config).await?;
    } else if which::which("grype").is_ok() {
        results = run_grype(path, config).await?;
    } else {
        tracing::warn!("Neither trivy nor grype found, skipping SCA scan");
    }

    Ok(results)
}

async fn run_trivy(path: &Path, _config: &Config) -> Result<ScanResults> {
    let mut results = ScanResults::new();

    let output = Command::new("trivy")
        .arg("fs")
        .arg("--format").arg("json")
        .arg("--quiet")
        .arg("--scanners").arg("vuln")
        .arg(path)
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        if let Some(trivy_results) = json.get("Results").and_then(|r| r.as_array()) {
            for target in trivy_results {
                if let Some(vulns) = target.get("Vulnerabilities").and_then(|v| v.as_array()) {
                    for vuln in vulns {
                        let severity = match vuln.get("Severity").and_then(|s| s.as_str()) {
                            Some("CRITICAL") => Severity::Critical,
                            Some("HIGH") => Severity::High,
                            Some("MEDIUM") => Severity::Medium,
                            _ => Severity::Low,
                        };

                        let finding = Finding {
                            id: vuln.get("VulnerabilityID").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            scanner: "sca".to_string(),
                            severity,
                            title: format!("{} in {}@{}",
                                vuln.get("VulnerabilityID").and_then(|v| v.as_str()).unwrap_or(""),
                                vuln.get("PkgName").and_then(|p| p.as_str()).unwrap_or(""),
                                vuln.get("InstalledVersion").and_then(|v| v.as_str()).unwrap_or("")
                            ),
                            description: vuln.get("Title").and_then(|t| t.as_str()).unwrap_or("").to_string(),
                            file: target.get("Target").and_then(|t| t.as_str()).unwrap_or("").to_string(),
                            line: None,
                            cwe: None,
                            cve: vuln.get("VulnerabilityID").and_then(|v| v.as_str()).map(|s| s.to_string()),
                            fix_suggestion: vuln.get("FixedVersion").and_then(|v| v.as_str())
                                .map(|v| format!("Upgrade to version {}", v)),
                        };
                        results.findings.push(finding);
                    }
                }
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

async fn run_grype(path: &Path, _config: &Config) -> Result<ScanResults> {
    let results = ScanResults::new();
    // TODO: Implement grype integration
    tracing::info!("Grype integration: coming soon");
    Ok(results)
}
