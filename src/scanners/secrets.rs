use crate::config::Config;
use crate::scanners::exec;
use crate::scanners::{Finding, ScanResults, Severity};
use anyhow::Result;
use regex::Regex;
use std::path::Path;
use tokio::process::Command;

/// Bundled gitleaks extension config with Japanese cloud / SaaS credential
/// patterns (Sakura Cloud, LINE, PayPay, freee, kintone). Extends the
/// gitleaks default ruleset via `useDefault = true`.
const JAPAN_CLOUD_RULES: &str = include_str!("../../rules/secrets/japan-cloud.toml");

/// Materialize the bundled gitleaks config to a temp file so gitleaks can
/// consume it via --config. Writes to a unique staging file first and renames
/// into place so concurrent invocations never observe a partial file.
fn gitleaks_config_path() -> std::io::Result<std::path::PathBuf> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static STAGING_COUNTER: AtomicUsize = AtomicUsize::new(0);

    let path = std::env::temp_dir().join(format!(
        "shipsafe-{}-gitleaks.toml",
        env!("CARGO_PKG_VERSION")
    ));
    let staging = path.with_extension(format!(
        "toml.{}.{}",
        std::process::id(),
        STAGING_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&staging, JAPAN_CLOUD_RULES)?;
    if let Err(e) = std::fs::rename(&staging, &path) {
        let _ = std::fs::remove_file(&staging);
        if !path.is_file() {
            return Err(e);
        }
    }
    Ok(path)
}

/// Classify a gitleaks RuleID into a secret category.
fn classify_secret(rule_id: &str) -> &'static str {
    let id = rule_id.to_lowercase();
    // Japanese cloud / SaaS rules (matched before generic substrings:
    // e.g. "linear-api-key" must not classify as a LINE token).
    if id.starts_with("sakura-cloud") {
        return "Sakura Cloud Credential";
    }
    if id.starts_with("line-channel") {
        return "LINE API Credential";
    }
    if id.starts_with("paypay") {
        return "PayPay API Key";
    }
    if id.starts_with("freee") {
        return "freee API Credential";
    }
    if id.starts_with("kintone") {
        return "kintone API Token";
    }
    if id.contains("aws") {
        "AWS Credential"
    } else if id.contains("gcp") || id.contains("google") {
        "GCP Credential"
    } else if id.contains("azure") {
        "Azure Credential"
    } else if id.contains("github") {
        "GitHub Token"
    } else if id.contains("gitlab") {
        "GitLab Token"
    } else if id.contains("slack") {
        "Slack Token"
    } else if id.contains("stripe") {
        "Stripe Key"
    } else if id.contains("twilio") {
        "Twilio Key"
    } else if id.contains("sendgrid") {
        "SendGrid Key"
    } else if id.contains("npm") {
        "npm Token"
    } else if id.contains("pypi") {
        "PyPI Token"
    } else if id.contains("private-key") || id.contains("privatekey") {
        "Private Key"
    } else if id.contains("jwt") {
        "JWT Secret"
    } else if id.contains("password") || id.contains("passwd") {
        "Password"
    } else if id.contains("generic") {
        "Generic Secret"
    } else if id.contains("api-key") || id.contains("apikey") {
        "API Key"
    } else {
        "Secret"
    }
}

/// Map a gitleaks RuleID to severity.
fn severity_from_rule_id(rule_id: &str) -> Severity {
    let id = rule_id.to_lowercase();
    // Japanese cloud / SaaS rules. Cloud infrastructure credentials are
    // critical; payment/messaging/SaaS tokens are high.
    if id.starts_with("sakura-cloud") {
        return Severity::Critical;
    }
    if id.starts_with("line-channel")
        || id.starts_with("paypay")
        || id.starts_with("freee")
        || id.starts_with("kintone")
    {
        return Severity::High;
    }
    // Cloud provider credentials and private keys are critical
    if id.contains("aws")
        || id.contains("gcp")
        || id.contains("google")
        || id.contains("azure")
        || id.contains("private-key")
        || id.contains("privatekey")
    {
        Severity::Critical
    // Service tokens and API keys are high
    } else if id.contains("github")
        || id.contains("gitlab")
        || id.contains("slack")
        || id.contains("stripe")
        || id.contains("twilio")
        || id.contains("sendgrid")
        || id.contains("npm")
        || id.contains("pypi")
        || id.contains("jwt")
    {
        Severity::High
    // Passwords and API keys are medium
    } else if id.contains("password")
        || id.contains("passwd")
        || id.contains("api-key")
        || id.contains("apikey")
    {
        Severity::Medium
    // Generic secrets are low
    } else if id.contains("generic") {
        Severity::Low
    // Default to high for unknown rules
    } else {
        Severity::High
    }
}

/// Check if a finding should be excluded based on allow_patterns.
/// Returns `true` if the finding matches any allow_pattern and should be filtered out.
fn is_excluded_by_allow_patterns(leak: &serde_json::Value, allow_patterns: &[Regex]) -> bool {
    if allow_patterns.is_empty() {
        return false;
    }
    let secret = leak.get("Secret").and_then(|s| s.as_str()).unwrap_or("");
    let file = leak.get("File").and_then(|f| f.as_str()).unwrap_or("");
    let match_val = leak.get("Match").and_then(|m| m.as_str()).unwrap_or("");

    for pattern in allow_patterns {
        if pattern.is_match(secret) || pattern.is_match(file) || pattern.is_match(match_val) {
            return true;
        }
    }
    false
}

/// Parse gitleaks JSON output into findings, applying classification and filtering.
fn parse_gitleaks_output(stdout: &str, allow_patterns: &[Regex]) -> Vec<Finding> {
    let leaks: Vec<serde_json::Value> = match serde_json::from_str(stdout) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("Failed to parse gitleaks JSON output: {}", e);
            return vec![];
        }
    };

    leaks
        .iter()
        .filter(|leak| !is_excluded_by_allow_patterns(leak, allow_patterns))
        .map(|leak| {
            let rule_id = leak
                .get("RuleID")
                .and_then(|r| r.as_str())
                .unwrap_or("unknown");
            let category = classify_secret(rule_id);
            let severity = severity_from_rule_id(rule_id);

            Finding {
                id: format!("secret-{}", rule_id),
                scanner: "secrets".to_string(),
                severity,
                title: format!(
                    "{} detected: {}",
                    category,
                    leak.get("Description")
                        .and_then(|d| d.as_str())
                        .unwrap_or("Unknown secret")
                ),
                description: format!("Rule: {} | Category: {}", rule_id, category),
                file: leak
                    .get("File")
                    .and_then(|f| f.as_str())
                    .unwrap_or("")
                    .to_string(),
                line: leak
                    .get("StartLine")
                    .and_then(|l| l.as_u64())
                    .map(|l| l as u32),
                cwe: Some("CWE-798".to_string()),
                cve: None,
                fix_suggestion: Some(
                    "Remove the secret and rotate the credential immediately.".to_string(),
                ),
                ai_triage: None,
            }
        })
        .collect()
}

pub async fn run(path: &Path, config: &Config) -> Result<ScanResults> {
    let mut results = ScanResults::new();

    if which::which("gitleaks").is_err() {
        exec::warn_user(
            &config.lang,
            "gitleaks not found — secrets scan skipped. Run 'shipsafe doctor' for install instructions.",
            "gitleaks が見つかりません — シークレットスキャンをスキップしました。'shipsafe doctor' でインストール方法を確認できます。",
        );
        return Ok(results);
    }

    // Compile allow_patterns into regexes
    let allow_patterns: Vec<Regex> = config
        .scanners
        .secrets
        .allow_patterns
        .iter()
        .filter_map(|p| match Regex::new(p) {
            Ok(re) => Some(re),
            Err(e) => {
                tracing::warn!("Invalid allow_pattern '{}': {}", p, e);
                None
            }
        })
        .collect();

    // Write the report to a temp file: /dev/stdout is not writable in some
    // sandboxed/CI environments, and a real file works everywhere.
    let report_path = std::env::temp_dir().join(format!(
        "shipsafe-gitleaks-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));

    // Extend the default ruleset with bundled Japanese cloud/SaaS patterns.
    let gitleaks_config = match gitleaks_config_path() {
        Ok(config_path) => Some(config_path),
        Err(e) => {
            tracing::warn!(
                "failed to materialize bundled gitleaks config, using defaults: {}",
                e
            );
            None
        }
    };

    let output = exec::run_scanner(
        "gitleaks",
        || {
            let mut cmd = Command::new("gitleaks");
            cmd.arg("detect")
                .arg("--source")
                .arg(path)
                .arg("--report-format")
                .arg("json")
                .arg("--report-path")
                .arg(&report_path)
                .arg("--no-banner");

            if let Some(ref config_path) = gitleaks_config {
                cmd.arg("--config").arg(config_path);
            }

            // Enable git history scanning
            if config.scanners.secrets.scan_history {
                cmd.arg("--log-opts").arg("--all");
            } else {
                cmd.arg("--no-git");
            }
            cmd
        },
        config.scanners.timeout_seconds,
        &config.lang,
    )
    .await?;

    let Some(output) = output else {
        return Ok(results);
    };

    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.is_empty() {
        tracing::debug!("gitleaks stderr: {}", stderr);
    }

    if !output.status.success() {
        let exit_code = output.status.code().unwrap_or(-1);
        // Exit code 1 = leaks found (expected), other codes = actual errors
        if exit_code != 1 {
            tracing::warn!(
                "gitleaks exited with status {}: {}",
                exit_code,
                stderr.lines().next().unwrap_or("(no details)")
            );
            let _ = std::fs::remove_file(&report_path);
            return Ok(results);
        }
    }

    let report = std::fs::read_to_string(&report_path).unwrap_or_else(|e| {
        tracing::warn!("failed to read gitleaks report: {}", e);
        String::from("[]")
    });
    let _ = std::fs::remove_file(&report_path);

    results.findings = parse_gitleaks_output(&report, &allow_patterns);
    results.recalculate_summary();

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_secret() {
        assert_eq!(classify_secret("aws-access-key"), "AWS Credential");
        assert_eq!(classify_secret("gcp-api-key"), "GCP Credential");
        assert_eq!(classify_secret("azure-storage-key"), "Azure Credential");
        assert_eq!(classify_secret("github-pat"), "GitHub Token");
        assert_eq!(classify_secret("gitlab-token"), "GitLab Token");
        assert_eq!(classify_secret("slack-webhook"), "Slack Token");
        assert_eq!(classify_secret("stripe-secret-key"), "Stripe Key");
        assert_eq!(classify_secret("twilio-api-key"), "Twilio Key");
        assert_eq!(classify_secret("sendgrid-api-key"), "SendGrid Key");
        assert_eq!(classify_secret("npm-access-token"), "npm Token");
        assert_eq!(classify_secret("pypi-upload-token"), "PyPI Token");
        assert_eq!(classify_secret("private-key"), "Private Key");
        assert_eq!(classify_secret("jwt-secret"), "JWT Secret");
        assert_eq!(classify_secret("password-in-url"), "Password");
        assert_eq!(classify_secret("generic-api-key"), "Generic Secret");
        assert_eq!(classify_secret("some-unknown-rule"), "Secret");
    }

    #[test]
    fn test_severity_from_rule_id() {
        assert_eq!(severity_from_rule_id("aws-access-key"), Severity::Critical);
        assert_eq!(
            severity_from_rule_id("gcp-service-account"),
            Severity::Critical
        );
        assert_eq!(
            severity_from_rule_id("azure-storage-key"),
            Severity::Critical
        );
        assert_eq!(severity_from_rule_id("private-key"), Severity::Critical);
        assert_eq!(severity_from_rule_id("github-pat"), Severity::High);
        assert_eq!(severity_from_rule_id("slack-webhook"), Severity::High);
        assert_eq!(severity_from_rule_id("stripe-secret"), Severity::High);
        assert_eq!(severity_from_rule_id("jwt-token"), Severity::High);
        assert_eq!(severity_from_rule_id("password-in-url"), Severity::Medium);
        assert_eq!(severity_from_rule_id("api-key-leak"), Severity::Medium);
        assert_eq!(severity_from_rule_id("generic-api-key"), Severity::Medium);
        assert_eq!(severity_from_rule_id("generic-secret"), Severity::Low);
        assert_eq!(severity_from_rule_id("unknown-rule"), Severity::High);
    }

    #[test]
    fn test_parse_gitleaks_output_basic() {
        let json = r#"[
            {
                "RuleID": "aws-access-key",
                "Description": "AWS Access Key",
                "Secret": "AKIAIOSFODNN7EXAMPLE",
                "File": "config.yml",
                "StartLine": 10,
                "Match": "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"
            },
            {
                "RuleID": "generic-api-key",
                "Description": "Generic API Key",
                "Secret": "some-api-key-value",
                "File": "app.py",
                "StartLine": 25,
                "Match": "API_KEY=some-api-key-value"
            }
        ]"#;

        let findings = parse_gitleaks_output(json, &[]);
        assert_eq!(findings.len(), 2);

        assert_eq!(findings[0].id, "secret-aws-access-key");
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].title.contains("AWS Credential"));
        assert_eq!(findings[0].file, "config.yml");
        assert_eq!(findings[0].line, Some(10));

        assert_eq!(findings[1].id, "secret-generic-api-key");
        assert_eq!(findings[1].severity, Severity::Medium);
        assert!(findings[1].title.contains("Generic Secret"));
    }

    #[test]
    fn test_parse_gitleaks_output_invalid_json() {
        let findings = parse_gitleaks_output("not valid json", &[]);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_parse_gitleaks_output_empty_array() {
        let findings = parse_gitleaks_output("[]", &[]);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_allow_patterns_filter_by_secret() {
        let json = r#"[
            {
                "RuleID": "generic-api-key",
                "Description": "Generic API Key",
                "Secret": "EXAMPLE_KEY_12345",
                "File": "config.yml",
                "StartLine": 1,
                "Match": "key=EXAMPLE_KEY_12345"
            }
        ]"#;

        let patterns = vec![Regex::new("EXAMPLE_KEY").unwrap()];
        let findings = parse_gitleaks_output(json, &patterns);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_allow_patterns_filter_by_file() {
        let json = r#"[
            {
                "RuleID": "generic-api-key",
                "Description": "Generic API Key",
                "Secret": "real-secret",
                "File": "test/fixtures/dummy.yml",
                "StartLine": 1,
                "Match": "key=real-secret"
            }
        ]"#;

        let patterns = vec![Regex::new(r"test/fixtures/").unwrap()];
        let findings = parse_gitleaks_output(json, &patterns);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_allow_patterns_no_match_keeps_finding() {
        let json = r#"[
            {
                "RuleID": "aws-access-key",
                "Description": "AWS Access Key",
                "Secret": "AKIAIOSFODNN7EXAMPLE",
                "File": "production/config.yml",
                "StartLine": 5,
                "Match": "aws_key=AKIAIOSFODNN7EXAMPLE"
            }
        ]"#;

        let patterns = vec![Regex::new(r"test/fixtures/").unwrap()];
        let findings = parse_gitleaks_output(json, &patterns);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_allow_patterns_filter_by_match() {
        let json = r#"[
            {
                "RuleID": "generic-api-key",
                "Description": "Generic API Key",
                "Secret": "abc123",
                "File": "src/main.rs",
                "StartLine": 1,
                "Match": "DUMMY_TOKEN=abc123"
            }
        ]"#;

        let patterns = vec![Regex::new("DUMMY_TOKEN").unwrap()];
        let findings = parse_gitleaks_output(json, &patterns);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_is_excluded_by_allow_patterns_empty() {
        let leak: serde_json::Value = serde_json::json!({
            "Secret": "some-secret",
            "File": "config.yml",
            "Match": "key=some-secret"
        });
        assert!(!is_excluded_by_allow_patterns(&leak, &[]));
    }

    #[test]
    fn test_classify_japan_cloud_rules() {
        assert_eq!(
            classify_secret("sakura-cloud-api-key"),
            "Sakura Cloud Credential"
        );
        assert_eq!(
            classify_secret("line-channel-access-token"),
            "LINE API Credential"
        );
        assert_eq!(
            classify_secret("line-channel-secret"),
            "LINE API Credential"
        );
        assert_eq!(classify_secret("paypay-api-key"), "PayPay API Key");
        assert_eq!(
            classify_secret("freee-access-token"),
            "freee API Credential"
        );
        assert_eq!(classify_secret("kintone-api-token"), "kintone API Token");
        // "linear-api-key" (gitleaks default) must NOT classify as LINE.
        assert_ne!(classify_secret("linear-api-key"), "LINE API Credential");
    }

    #[test]
    fn test_severity_japan_cloud_rules() {
        assert_eq!(
            severity_from_rule_id("sakura-cloud-api-key"),
            Severity::Critical
        );
        assert_eq!(
            severity_from_rule_id("line-channel-access-token"),
            Severity::High
        );
        assert_eq!(severity_from_rule_id("paypay-api-key"), Severity::High);
        assert_eq!(severity_from_rule_id("freee-access-token"), Severity::High);
        assert_eq!(severity_from_rule_id("kintone-api-token"), Severity::High);
    }

    #[test]
    fn test_gitleaks_config_materialized() {
        let path = gitleaks_config_path().unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("useDefault = true"));
        for id in [
            "sakura-cloud-api-key",
            "line-channel-access-token",
            "line-channel-secret",
            "paypay-api-key",
            "freee-access-token",
            "kintone-api-token",
        ] {
            assert!(content.contains(id), "missing rule id {}", id);
        }
    }

    /// Extract `regex = '''...'''` values from the bundled TOML, in order.
    fn bundled_regexes() -> Vec<String> {
        JAPAN_CLOUD_RULES
            .lines()
            .filter_map(|line| {
                line.trim()
                    .strip_prefix("regex = '''")?
                    .strip_suffix("'''")
                    .map(|s| s.to_string())
            })
            .collect()
    }

    #[test]
    fn test_japan_cloud_regexes_match_examples() {
        // The TOML regexes use RE2-compatible syntax, which the rust regex
        // crate also accepts; verify each bundled pattern (extracted from the
        // embedded TOML so this test cannot drift) matches a representative
        // fake credential and skips benign text. Order follows the TOML.
        let line_token = format!(r#"LINE_CHANNEL_ACCESS_TOKEN = "{}""#, "Ab1+/".repeat(24));
        let cases: &[(&str, &str)] = &[
            (
                r#"SAKURA_ACCESS_TOKEN = "01234567-89ab-cdef-0123-456789abcdef""#,
                r#"sakura_no = "short""#,
            ),
            (&line_token, r#"channel_token = "short""#),
            (
                r#"LINE_CHANNEL_SECRET = "0123456789abcdef0123456789abcdef""#,
                r#"channel_secret = "not-hex""#,
            ),
            (
                r#"PAYPAY_API_KEY = "a_1Bc-2De3Fg4Hi5Jk6L""#,
                r#"paypay_url = "https://x.test""#,
            ),
            (
                r#"FREEE_ACCESS_TOKEN = "0123456789abcdef0123456789abcdef0123456789abcdef""#,
                r#"freee_plan = "basic""#,
            ),
            (
                r#"KINTONE_API_TOKEN = "abcdefghijklmnopqrstuvwxyz012345""#,
                r#"kintone_domain = "example.cybozu.com""#,
            ),
        ];

        let regexes = bundled_regexes();
        assert_eq!(regexes.len(), cases.len(), "rule count drifted");

        for (pattern, (positive, negative)) in regexes.iter().zip(cases) {
            let re = Regex::new(pattern).unwrap();
            assert!(re.is_match(positive), "pattern should match: {}", positive);
            assert!(
                !re.is_match(negative),
                "pattern should not match: {}",
                negative
            );
        }
    }
}
