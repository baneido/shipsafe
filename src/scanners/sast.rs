use crate::config::Config;
use crate::scanners::{Finding, ScanResults, Severity};
use anyhow::Result;
use std::path::Path;
use std::process::Command;

pub async fn run(path: &Path, config: &Config) -> Result<ScanResults> {
    // Check if semgrep is available
    if which::which("semgrep").is_err() {
        tracing::warn!("semgrep not found, skipping SAST scan");
        return Ok(ScanResults::new());
    }

    let mut cmd = Command::new("semgrep");
    cmd.arg("scan").arg("--json").arg("--quiet").arg(path);
    build_semgrep_args(&mut cmd, config);

    let output = cmd.output()?;

    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.is_empty() {
        tracing::debug!("semgrep stderr: {}", stderr);
    }

    if !output.status.success() {
        tracing::warn!(
            "semgrep exited with status {}: {}",
            output.status,
            stderr.lines().next().unwrap_or("(no details)")
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_semgrep_json(&stdout)
}

/// Bundled semgrep rules for AI-generated code patterns, embedded at build
/// time so the distributed binary does not depend on the repo layout.
const AI_GENERATED_CODE_RULES: &str = include_str!("../../rules/sast/ai-generated-code.yml");

/// Materialize the bundled AI-generated-code rules to a temp file so semgrep
/// can consume them via --config. Writes to a unique staging file first and
/// renames into place so concurrent invocations never observe a partial file.
fn ai_generated_code_rules_path() -> std::io::Result<std::path::PathBuf> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static STAGING_COUNTER: AtomicUsize = AtomicUsize::new(0);

    let path = std::env::temp_dir().join(format!(
        "shipsafe-{}-ai-generated-code.yml",
        env!("CARGO_PKG_VERSION")
    ));
    let staging = path.with_extension(format!(
        "yml.{}.{}",
        std::process::id(),
        STAGING_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&staging, AI_GENERATED_CODE_RULES)?;
    std::fs::rename(&staging, &path)?;
    Ok(path)
}

/// Build semgrep rule config and exclude arguments.
fn build_semgrep_args(cmd: &mut Command, config: &Config) {
    // Add rule configs; default to OWASP Top 10 if none specified
    let rules = &config.scanners.sast.rules;
    if rules.is_empty() {
        cmd.arg("--config").arg("p/owasp-top-ten");
    } else {
        for rule in rules {
            match rule.as_str() {
                "owasp-top-10" => {
                    cmd.arg("--config").arg("p/owasp-top-ten");
                }
                "ai-generated-code" => match ai_generated_code_rules_path() {
                    Ok(path) => {
                        cmd.arg("--config").arg(path);
                    }
                    Err(e) => {
                        tracing::warn!(
                            "failed to materialize bundled ai-generated-code rules, skipping: {}",
                            e
                        );
                    }
                },
                other => {
                    cmd.arg("--config").arg(other);
                }
            }
        }
    }

    // Add excludes
    for exclude in &config.scanners.sast.exclude {
        cmd.arg("--exclude").arg(exclude);
    }
}

/// Map semgrep severity string to internal Severity enum.
fn map_severity(s: Option<&str>) -> Severity {
    match s {
        Some("ERROR") => Severity::Critical,
        Some("WARNING") => Severity::Medium,
        Some("INFO") => Severity::Low,
        _ => Severity::Medium,
    }
}

/// Extract CWE from semgrep metadata, handling both string and array values.
fn extract_cwe(metadata: Option<&serde_json::Value>) -> Option<String> {
    let cwe = metadata?.get("cwe")?;
    if let Some(s) = cwe.as_str() {
        return Some(s.to_string());
    }
    if let Some(arr) = cwe.as_array() {
        let cwe_strs: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
        if !cwe_strs.is_empty() {
            return Some(cwe_strs.join(", "));
        }
    }
    None
}

/// Parse semgrep JSON output and convert to ScanResults.
fn parse_semgrep_json(json_str: &str) -> Result<ScanResults> {
    let mut results = ScanResults::new();

    let json: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => return Ok(results),
    };

    if let Some(semgrep_results) = json.get("results").and_then(|r| r.as_array()) {
        for result in semgrep_results {
            let severity = map_severity(
                result
                    .get("extra")
                    .and_then(|e| e.get("severity"))
                    .and_then(|s| s.as_str()),
            );

            let metadata = result.get("extra").and_then(|e| e.get("metadata"));

            let finding = Finding {
                id: result
                    .get("check_id")
                    .and_then(|c| c.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
                scanner: "sast".to_string(),
                severity,
                title: result
                    .get("check_id")
                    .and_then(|c| c.as_str())
                    .unwrap_or("")
                    .to_string(),
                description: result
                    .get("extra")
                    .and_then(|e| e.get("message"))
                    .and_then(|m| m.as_str())
                    .unwrap_or("")
                    .to_string(),
                file: result
                    .get("path")
                    .and_then(|p| p.as_str())
                    .unwrap_or("")
                    .to_string(),
                line: result
                    .get("start")
                    .and_then(|s| s.get("line"))
                    .and_then(|l| l.as_u64())
                    .map(|l| l as u32),
                cwe: extract_cwe(metadata),
                cve: None,
                fix_suggestion: result
                    .get("extra")
                    .and_then(|e| e.get("fix"))
                    .and_then(|f| f.as_str())
                    .map(|s| s.to_string()),
            };
            results.findings.push(finding);
        }
    }

    results.recalculate_summary();

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_mapping() {
        assert_eq!(map_severity(Some("ERROR")), Severity::Critical);
        assert_eq!(map_severity(Some("WARNING")), Severity::Medium);
        assert_eq!(map_severity(Some("INFO")), Severity::Low);
        assert_eq!(map_severity(Some("UNKNOWN")), Severity::Medium);
        assert_eq!(map_severity(None), Severity::Medium);
    }

    #[test]
    fn test_extract_cwe_string() {
        let json: serde_json::Value = serde_json::json!({
            "cwe": "CWE-89: SQL Injection"
        });
        assert_eq!(
            extract_cwe(Some(&json)),
            Some("CWE-89: SQL Injection".to_string())
        );
    }

    #[test]
    fn test_extract_cwe_array() {
        let json: serde_json::Value = serde_json::json!({
            "cwe": ["CWE-79: XSS", "CWE-89: SQL Injection"]
        });
        assert_eq!(
            extract_cwe(Some(&json)),
            Some("CWE-79: XSS, CWE-89: SQL Injection".to_string())
        );
    }

    #[test]
    fn test_extract_cwe_missing() {
        let json: serde_json::Value = serde_json::json!({});
        assert_eq!(extract_cwe(Some(&json)), None);
        assert_eq!(extract_cwe(None), None);
    }

    #[test]
    fn test_parse_semgrep_json_with_results() {
        let json_str = r#"{
            "results": [
                {
                    "check_id": "python.lang.security.audit.exec-detected",
                    "path": "app.py",
                    "start": {"line": 42, "col": 1},
                    "end": {"line": 42, "col": 20},
                    "extra": {
                        "severity": "ERROR",
                        "message": "Detected use of exec(). This is dangerous.",
                        "metadata": {
                            "cwe": ["CWE-95: Improper Neutralization"]
                        },
                        "fix": "Use ast.literal_eval() instead."
                    }
                },
                {
                    "check_id": "python.lang.security.audit.logging-warn",
                    "path": "utils.py",
                    "start": {"line": 10, "col": 1},
                    "end": {"line": 10, "col": 30},
                    "extra": {
                        "severity": "WARNING",
                        "message": "Logging sensitive data.",
                        "metadata": {
                            "cwe": "CWE-532"
                        }
                    }
                },
                {
                    "check_id": "python.lang.best-practice.info-rule",
                    "path": "main.py",
                    "start": {"line": 5, "col": 1},
                    "end": {"line": 5, "col": 15},
                    "extra": {
                        "severity": "INFO",
                        "message": "Consider using a constant.",
                        "metadata": {}
                    }
                }
            ]
        }"#;

        let results = parse_semgrep_json(json_str).unwrap();

        assert_eq!(results.findings.len(), 3);
        assert_eq!(results.summary.total, 3);
        assert_eq!(results.summary.critical, 1);
        assert_eq!(results.summary.medium, 1);
        assert_eq!(results.summary.low, 1);

        // Check ERROR -> Critical mapping
        let f0 = &results.findings[0];
        assert_eq!(f0.severity, Severity::Critical);
        assert_eq!(f0.id, "python.lang.security.audit.exec-detected");
        assert_eq!(f0.scanner, "sast");
        assert_eq!(f0.file, "app.py");
        assert_eq!(f0.line, Some(42));
        assert_eq!(f0.cwe, Some("CWE-95: Improper Neutralization".to_string()));
        assert_eq!(
            f0.fix_suggestion,
            Some("Use ast.literal_eval() instead.".to_string())
        );

        // Check WARNING -> Medium mapping
        let f1 = &results.findings[1];
        assert_eq!(f1.severity, Severity::Medium);
        assert_eq!(f1.cwe, Some("CWE-532".to_string()));

        // Check INFO -> Low mapping
        let f2 = &results.findings[2];
        assert_eq!(f2.severity, Severity::Low);
        assert_eq!(f2.cwe, None);
    }

    #[test]
    fn test_parse_semgrep_json_empty_results() {
        let json_str = r#"{"results": []}"#;
        let results = parse_semgrep_json(json_str).unwrap();
        assert_eq!(results.findings.len(), 0);
        assert_eq!(results.summary.total, 0);
    }

    #[test]
    fn test_parse_semgrep_json_invalid() {
        let results = parse_semgrep_json("not valid json").unwrap();
        assert_eq!(results.findings.len(), 0);
    }

    #[test]
    fn test_parse_semgrep_json_missing_fields() {
        let json_str = r#"{
            "results": [
                {
                    "extra": {
                        "severity": "ERROR",
                        "message": "Some issue"
                    }
                }
            ]
        }"#;
        let results = parse_semgrep_json(json_str).unwrap();
        assert_eq!(results.findings.len(), 1);
        assert_eq!(results.findings[0].id, "unknown");
        assert_eq!(results.findings[0].file, "");
        assert_eq!(results.findings[0].line, None);
        assert_eq!(results.findings[0].cwe, None);
    }

    #[test]
    fn test_default_config_has_owasp_rules() {
        let config = Config::default();
        assert!(config
            .scanners
            .sast
            .rules
            .contains(&"owasp-top-10".to_string()));
    }

    /// Helper to extract args from a Command for testing.
    fn get_args(cmd: &Command) -> Vec<String> {
        cmd.get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect()
    }

    #[test]
    fn test_empty_rules_defaults_to_owasp_args() {
        let mut config = Config::default();
        config.scanners.sast.rules = vec![];
        config.scanners.sast.exclude = vec![];

        let mut cmd = Command::new("semgrep");
        build_semgrep_args(&mut cmd, &config);

        let args = get_args(&cmd);
        assert!(args.contains(&"--config".to_string()));
        assert!(args.contains(&"p/owasp-top-ten".to_string()));
    }

    #[test]
    fn test_custom_rules_args() {
        let mut config = Config::default();
        config.scanners.sast.rules = vec!["owasp-top-10".into(), "ai-generated-code".into()];
        config.scanners.sast.exclude = vec!["vendor".into()];

        let mut cmd = Command::new("semgrep");
        build_semgrep_args(&mut cmd, &config);

        let args = get_args(&cmd);
        assert!(args.contains(&"p/owasp-top-ten".to_string()));
        assert!(args
            .iter()
            .any(|a| a.ends_with("ai-generated-code.yml") && !a.contains("p/default")));
        assert!(args.contains(&"--exclude".to_string()));
        assert!(args.contains(&"vendor".to_string()));
    }

    #[test]
    fn test_ai_generated_code_rules_materialized() {
        let path = ai_generated_code_rules_path().unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("ai-hardcoded-credentials"));
        assert!(content.contains("ai-sql-injection"));
    }
}
