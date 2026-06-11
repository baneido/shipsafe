use crate::config::Config;
use crate::scanners::exec;
use crate::scanners::{Finding, ScanResults, Severity};
use anyhow::Result;
use std::path::Path;
use tokio::process::Command;

/// Detect package managers present in the target directory by checking for
/// lock files and manifest files commonly scanned by trivy/grype.
fn detect_package_managers(path: &Path) -> Vec<&'static str> {
    let indicators: &[(&str, &str)] = &[
        ("package-lock.json", "npm"),
        ("yarn.lock", "yarn"),
        ("pnpm-lock.yaml", "pnpm"),
        ("Cargo.lock", "cargo"),
        ("Gemfile.lock", "bundler"),
        ("poetry.lock", "poetry"),
        ("Pipfile.lock", "pipenv"),
        ("requirements.txt", "pip"),
        ("go.sum", "gomod"),
        ("composer.lock", "composer"),
        ("pom.xml", "maven"),
        ("build.gradle", "gradle"),
        ("build.gradle.kts", "gradle"),
        ("packages.lock.json", "nuget"),
    ];

    let mut detected: Vec<&str> = indicators
        .iter()
        .filter(|(file, _)| path.join(file).exists())
        .map(|(_, manager)| *manager)
        .collect();
    detected.sort_unstable();
    detected.dedup();
    detected
}

pub async fn run(path: &Path, config: &Config) -> Result<ScanResults> {
    let mut results = ScanResults::new();

    let detected = detect_package_managers(path);
    if !detected.is_empty() {
        tracing::info!("Detected package managers: {:?}", detected);
    }

    // Try trivy first, then grype
    if which::which("trivy").is_ok() {
        results = run_trivy(path, config).await?;
    } else if which::which("grype").is_ok() {
        tracing::info!("trivy not found, falling back to grype");
        results = run_grype(path, config).await?;
    } else {
        exec::warn_user(
            &config.lang,
            "neither trivy nor grype found — SCA scan skipped. Run 'shipsafe doctor' for install instructions.",
            "trivy / grype が見つかりません — SCA スキャンをスキップしました。'shipsafe doctor' でインストール方法を確認できます。",
        );
    }

    Ok(results)
}

async fn run_trivy(path: &Path, config: &Config) -> Result<ScanResults> {
    let output = exec::run_scanner(
        "trivy",
        || {
            let mut cmd = Command::new("trivy");
            cmd.arg("fs")
                .arg("--format")
                .arg("json")
                .arg("--quiet")
                .arg("--scanners")
                .arg("vuln")
                .arg(path);
            cmd
        },
        config.scanners.timeout_seconds,
        &config.lang,
    )
    .await?;

    let Some(output) = output else {
        return Ok(ScanResults::new());
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if output.stdout.is_empty() {
            anyhow::bail!("trivy failed with status {}: {}", output.status, stderr);
        }
        tracing::warn!("trivy exited with status {}: {}", output.status, stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let results = parse_trivy_json(&stdout);
    Ok(results)
}

fn parse_trivy_json(json_str: &str) -> ScanResults {
    let mut results = ScanResults::new();

    let json = match serde_json::from_str::<serde_json::Value>(json_str) {
        Ok(v) => v,
        Err(_) => return results,
    };

    if let Some(trivy_results) = json.get("Results").and_then(|r| r.as_array()) {
        for target in trivy_results {
            let target_file = target.get("Target").and_then(|t| t.as_str()).unwrap_or("");
            if let Some(vulns) = target.get("Vulnerabilities").and_then(|v| v.as_array()) {
                for vuln in vulns {
                    let severity = match vuln.get("Severity").and_then(|s| s.as_str()) {
                        Some("CRITICAL") => Severity::Critical,
                        Some("HIGH") => Severity::High,
                        Some("MEDIUM") => Severity::Medium,
                        _ => Severity::Low,
                    };

                    let vuln_id = vuln
                        .get("VulnerabilityID")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let pkg_name = vuln.get("PkgName").and_then(|p| p.as_str()).unwrap_or("");
                    let installed_ver = vuln
                        .get("InstalledVersion")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");

                    let finding = Finding {
                        id: vuln_id.to_string(),
                        scanner: "sca".to_string(),
                        severity,
                        title: format!("{} in {}@{}", vuln_id, pkg_name, installed_ver),
                        description: vuln
                            .get("Title")
                            .and_then(|t| t.as_str())
                            .unwrap_or("")
                            .to_string(),
                        file: target_file.to_string(),
                        line: None,
                        cwe: None,
                        cve: if vuln_id.is_empty() {
                            None
                        } else {
                            Some(vuln_id.to_string())
                        },
                        fix_suggestion: vuln
                            .get("FixedVersion")
                            .and_then(|v| v.as_str())
                            .map(|v| format!("Upgrade to version {}", v)),
                    };
                    results.findings.push(finding);
                }
            }
        }
    }

    results.recalculate_summary();
    results
}

async fn run_grype(path: &Path, config: &Config) -> Result<ScanResults> {
    let output = exec::run_scanner(
        "grype",
        || {
            let mut cmd = Command::new("grype");
            cmd.arg(format!("dir:{}", path.display()))
                .arg("-o")
                .arg("json")
                .arg("--quiet");
            cmd
        },
        config.scanners.timeout_seconds,
        &config.lang,
    )
    .await?;

    let Some(output) = output else {
        return Ok(ScanResults::new());
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if output.stdout.is_empty() {
            anyhow::bail!("grype failed with status {}: {}", output.status, stderr);
        }
        tracing::warn!("grype exited with status {}: {}", output.status, stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let results = parse_grype_json(&stdout);
    Ok(results)
}

fn parse_grype_json(json_str: &str) -> ScanResults {
    let mut results = ScanResults::new();

    let json = match serde_json::from_str::<serde_json::Value>(json_str) {
        Ok(v) => v,
        Err(_) => return results,
    };

    if let Some(matches) = json.get("matches").and_then(|m| m.as_array()) {
        for m in matches {
            let vuln = match m.get("vulnerability") {
                Some(v) => v,
                None => continue,
            };
            let artifact = m.get("artifact");

            let vuln_id = vuln.get("id").and_then(|v| v.as_str()).unwrap_or("");

            let severity = match vuln.get("severity").and_then(|s| s.as_str()) {
                Some("Critical") => Severity::Critical,
                Some("High") => Severity::High,
                Some("Medium") => Severity::Medium,
                _ => Severity::Low,
            };

            let pkg_name = artifact
                .and_then(|a| a.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("");
            let installed_ver = artifact
                .and_then(|a| a.get("version"))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let fixed_version = vuln
                .get("fix")
                .and_then(|f| f.get("versions"))
                .and_then(|v| v.as_array())
                .and_then(|arr| arr.first())
                .and_then(|v| v.as_str());

            let file = artifact
                .and_then(|a| a.get("locations"))
                .and_then(|l| l.as_array())
                .and_then(|arr| arr.first())
                .and_then(|loc| loc.get("path"))
                .and_then(|p| p.as_str())
                .unwrap_or("");

            let description = vuln
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or("");

            let finding = Finding {
                id: vuln_id.to_string(),
                scanner: "sca".to_string(),
                severity,
                title: format!("{} in {}@{}", vuln_id, pkg_name, installed_ver),
                description: description.to_string(),
                file: file.to_string(),
                line: None,
                cwe: None,
                cve: if vuln_id.is_empty() {
                    None
                } else {
                    Some(vuln_id.to_string())
                },
                fix_suggestion: fixed_version.map(|v| format!("Upgrade to version {}", v)),
            };
            results.findings.push(finding);
        }
    }

    results.recalculate_summary();
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_trivy_json_basic() {
        let json = r#"{
            "Results": [
                {
                    "Target": "package-lock.json",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2021-44228",
                            "PkgName": "log4j-core",
                            "InstalledVersion": "2.14.1",
                            "FixedVersion": "2.17.0",
                            "Severity": "CRITICAL",
                            "Title": "Apache Log4j2 Remote Code Execution"
                        },
                        {
                            "VulnerabilityID": "CVE-2022-22965",
                            "PkgName": "spring-beans",
                            "InstalledVersion": "5.3.17",
                            "Severity": "HIGH",
                            "Title": "Spring Framework RCE"
                        }
                    ]
                }
            ]
        }"#;

        let results = parse_trivy_json(json);
        assert_eq!(results.findings.len(), 2);
        assert_eq!(results.summary.total, 2);
        assert_eq!(results.summary.critical, 1);
        assert_eq!(results.summary.high, 1);

        let f0 = &results.findings[0];
        assert_eq!(f0.id, "CVE-2021-44228");
        assert_eq!(f0.cve, Some("CVE-2021-44228".to_string()));
        assert_eq!(f0.title, "CVE-2021-44228 in log4j-core@2.14.1");
        assert_eq!(f0.severity, Severity::Critical);
        assert_eq!(f0.file, "package-lock.json");
        assert_eq!(
            f0.fix_suggestion,
            Some("Upgrade to version 2.17.0".to_string())
        );
        assert_eq!(f0.scanner, "sca");

        let f1 = &results.findings[1];
        assert_eq!(f1.id, "CVE-2022-22965");
        assert_eq!(f1.severity, Severity::High);
        assert_eq!(f1.fix_suggestion, None);
    }

    #[test]
    fn test_parse_trivy_json_empty_results() {
        let json = r#"{"Results": []}"#;
        let results = parse_trivy_json(json);
        assert_eq!(results.findings.len(), 0);
        assert_eq!(results.summary.total, 0);
    }

    #[test]
    fn test_parse_trivy_json_no_vulnerabilities() {
        let json = r#"{"Results": [{"Target": "Cargo.lock"}]}"#;
        let results = parse_trivy_json(json);
        assert_eq!(results.findings.len(), 0);
    }

    #[test]
    fn test_parse_trivy_json_invalid() {
        let results = parse_trivy_json("not valid json");
        assert_eq!(results.findings.len(), 0);
    }

    #[test]
    fn test_parse_trivy_json_severity_mapping() {
        let json = r#"{
            "Results": [{
                "Target": "go.sum",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-1", "Severity": "CRITICAL", "PkgName": "a", "InstalledVersion": "1"},
                    {"VulnerabilityID": "CVE-2", "Severity": "HIGH", "PkgName": "b", "InstalledVersion": "1"},
                    {"VulnerabilityID": "CVE-3", "Severity": "MEDIUM", "PkgName": "c", "InstalledVersion": "1"},
                    {"VulnerabilityID": "CVE-4", "Severity": "LOW", "PkgName": "d", "InstalledVersion": "1"},
                    {"VulnerabilityID": "CVE-5", "Severity": "UNKNOWN", "PkgName": "e", "InstalledVersion": "1"}
                ]
            }]
        }"#;

        let results = parse_trivy_json(json);
        assert_eq!(results.findings[0].severity, Severity::Critical);
        assert_eq!(results.findings[1].severity, Severity::High);
        assert_eq!(results.findings[2].severity, Severity::Medium);
        assert_eq!(results.findings[3].severity, Severity::Low);
        assert_eq!(results.findings[4].severity, Severity::Low); // UNKNOWN maps to Low
    }

    #[test]
    fn test_parse_grype_json_basic() {
        let json = r#"{
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2023-12345",
                        "severity": "Critical",
                        "description": "Critical vulnerability in example-lib",
                        "fix": {
                            "versions": ["2.0.0"],
                            "state": "fixed"
                        }
                    },
                    "artifact": {
                        "name": "example-lib",
                        "version": "1.0.0",
                        "type": "npm-pkg",
                        "locations": [
                            {"path": "node_modules/example-lib/package.json"}
                        ]
                    }
                },
                {
                    "vulnerability": {
                        "id": "CVE-2023-67890",
                        "severity": "Medium",
                        "description": "Medium severity issue"
                    },
                    "artifact": {
                        "name": "another-pkg",
                        "version": "3.1.0",
                        "type": "python-pkg",
                        "locations": [
                            {"path": "requirements.txt"}
                        ]
                    }
                }
            ]
        }"#;

        let results = parse_grype_json(json);
        assert_eq!(results.findings.len(), 2);
        assert_eq!(results.summary.total, 2);
        assert_eq!(results.summary.critical, 1);
        assert_eq!(results.summary.medium, 1);

        let f0 = &results.findings[0];
        assert_eq!(f0.id, "CVE-2023-12345");
        assert_eq!(f0.cve, Some("CVE-2023-12345".to_string()));
        assert_eq!(f0.title, "CVE-2023-12345 in example-lib@1.0.0");
        assert_eq!(f0.severity, Severity::Critical);
        assert_eq!(f0.file, "node_modules/example-lib/package.json");
        assert_eq!(
            f0.fix_suggestion,
            Some("Upgrade to version 2.0.0".to_string())
        );
        assert_eq!(f0.description, "Critical vulnerability in example-lib");
        assert_eq!(f0.scanner, "sca");

        let f1 = &results.findings[1];
        assert_eq!(f1.id, "CVE-2023-67890");
        assert_eq!(f1.severity, Severity::Medium);
        assert_eq!(f1.fix_suggestion, None);
    }

    #[test]
    fn test_parse_grype_json_empty_matches() {
        let json = r#"{"matches": []}"#;
        let results = parse_grype_json(json);
        assert_eq!(results.findings.len(), 0);
    }

    #[test]
    fn test_parse_grype_json_invalid() {
        let results = parse_grype_json("not valid json");
        assert_eq!(results.findings.len(), 0);
    }

    #[test]
    fn test_parse_grype_json_severity_mapping() {
        let json = r#"{
            "matches": [
                {"vulnerability": {"id": "CVE-1", "severity": "Critical"}, "artifact": {"name": "a", "version": "1"}},
                {"vulnerability": {"id": "CVE-2", "severity": "High"}, "artifact": {"name": "b", "version": "1"}},
                {"vulnerability": {"id": "CVE-3", "severity": "Medium"}, "artifact": {"name": "c", "version": "1"}},
                {"vulnerability": {"id": "CVE-4", "severity": "Low"}, "artifact": {"name": "d", "version": "1"}},
                {"vulnerability": {"id": "CVE-5", "severity": "Negligible"}, "artifact": {"name": "e", "version": "1"}}
            ]
        }"#;

        let results = parse_grype_json(json);
        assert_eq!(results.findings[0].severity, Severity::Critical);
        assert_eq!(results.findings[1].severity, Severity::High);
        assert_eq!(results.findings[2].severity, Severity::Medium);
        assert_eq!(results.findings[3].severity, Severity::Low);
        assert_eq!(results.findings[4].severity, Severity::Low); // Negligible maps to Low
    }

    #[test]
    fn test_parse_grype_json_no_fix_versions() {
        let json = r#"{
            "matches": [{
                "vulnerability": {
                    "id": "CVE-2023-99999",
                    "severity": "High",
                    "fix": {"versions": [], "state": "not-fixed"}
                },
                "artifact": {"name": "pkg", "version": "1.0.0"}
            }]
        }"#;

        let results = parse_grype_json(json);
        assert_eq!(results.findings.len(), 1);
        assert_eq!(results.findings[0].fix_suggestion, None);
    }

    #[test]
    fn test_detect_package_managers() {
        let base = std::env::temp_dir();
        let dir = base.join("detect_package_managers_test");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("package-lock.json"), "{}").unwrap();
        std::fs::write(dir.join("Cargo.lock"), "").unwrap();

        let detected = detect_package_managers(&dir);
        assert!(detected.contains(&"npm"));
        assert!(detected.contains(&"cargo"));
        assert!(!detected.contains(&"pip"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_detect_package_managers_empty() {
        let base = std::env::temp_dir();
        let dir = base.join("detect_package_managers_empty_test");
        std::fs::create_dir_all(&dir).unwrap();

        let detected = detect_package_managers(&dir);
        assert!(detected.is_empty());

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
