use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub version: u32,
    pub scanners: ScannersConfig,
    pub output: OutputConfig,
    pub ai: AiConfig,
    /// Glob patterns excluded from all scanners (matched against finding
    /// file paths).
    pub exclude: Vec<String>,
    #[serde(skip)]
    pub lang: String,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            version: 1,
            scanners: ScannersConfig::default(),
            output: OutputConfig::default(),
            ai: AiConfig::default(),
            exclude: vec![],
            lang: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct ScannersConfig {
    pub sast: SastConfig,
    pub sca: ScaConfig,
    pub secrets: SecretsConfig,
    /// Per-scanner timeout in seconds; a scanner exceeding it is skipped.
    #[serde(alias = "timeout_seconds")]
    pub timeout_seconds: u64,
}
impl Default for ScannersConfig {
    fn default() -> Self {
        Self {
            sast: SastConfig::default(),
            sca: ScaConfig::default(),
            secrets: SecretsConfig::default(),
            timeout_seconds: 300,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct SastConfig {
    pub enabled: bool,
    pub languages: Vec<String>,
    pub rules: Vec<String>,
    pub exclude: Vec<String>,
    /// Extra rule files or directories passed to semgrep --config.
    #[serde(alias = "rules_paths")]
    pub rules_paths: Vec<String>,
    /// Rule IDs disabled via semgrep --exclude-rule.
    #[serde(alias = "disabled_rules")]
    pub disabled_rules: Vec<String>,
}
impl Default for SastConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            languages: vec![],
            rules: vec!["owasp-top-10".into()],
            exclude: vec![],
            rules_paths: vec![],
            disabled_rules: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct ScaConfig {
    pub enabled: bool,
    #[serde(alias = "fail_on_severity")]
    pub fail_on_severity: String,
}
impl Default for ScaConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            fail_on_severity: "high".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct SecretsConfig {
    pub enabled: bool,
    #[serde(alias = "allow_patterns")]
    pub allow_patterns: Vec<String>,
    #[serde(default, alias = "scan_history")]
    pub scan_history: bool,
}
impl Default for SecretsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allow_patterns: vec![],
            scan_history: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OutputConfig {
    pub format: String,
    pub lang: String,
}
impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: "table".into(),
            lang: "en".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case", default)]
pub struct AiConfig {
    pub triage: bool,
    #[serde(alias = "fix_suggestions")]
    pub fix_suggestions: bool,
}

impl Config {
    pub fn load(path: &Path, lang: &str) -> Result<Self> {
        let mut config = if path.exists() {
            let content = std::fs::read_to_string(path)?;
            serde_yaml::from_str(&content)?
        } else {
            Config::default()
        };
        config.lang = lang.to_string();
        Ok(config)
    }
}

pub fn init_config() -> Result<()> {
    let yaml = serde_yaml::to_string(&Config::default())?;
    std::fs::write(".shipsafe.yml", yaml)?;
    Ok(())
}

/// Known config keys per section, accepting both kebab-case and snake_case.
const KNOWN_KEYS: &[(&str, &[&str])] = &[
    ("", &["version", "scanners", "output", "ai", "exclude"]),
    (
        "scanners",
        &[
            "sast",
            "sca",
            "secrets",
            "timeout-seconds",
            "timeout_seconds",
        ],
    ),
    (
        "scanners.sast",
        &[
            "enabled",
            "languages",
            "rules",
            "exclude",
            "rules-paths",
            "rules_paths",
            "disabled-rules",
            "disabled_rules",
        ],
    ),
    (
        "scanners.sca",
        &["enabled", "fail-on-severity", "fail_on_severity"],
    ),
    (
        "scanners.secrets",
        &[
            "enabled",
            "allow-patterns",
            "allow_patterns",
            "scan-history",
            "scan_history",
        ],
    ),
    ("output", &["format", "lang"]),
    ("ai", &["triage", "fix-suggestions", "fix_suggestions"]),
];

fn check_unknown_keys(value: &serde_yaml::Value, section: &str, errors: &mut Vec<String>) {
    let serde_yaml::Value::Mapping(map) = value else {
        return;
    };
    let Some((_, known)) = KNOWN_KEYS.iter().find(|(s, _)| *s == section) else {
        return;
    };
    for (key, child) in map {
        let Some(key) = key.as_str() else { continue };
        if !known.contains(&key) {
            let path = if section.is_empty() {
                key.to_string()
            } else {
                format!("{}.{}", section, key)
            };
            errors.push(format!(
                "unknown key '{}' (did you mean one of: {}?)",
                path,
                known.join(", ")
            ));
            continue;
        }
        let child_section = if section.is_empty() {
            key.to_string()
        } else {
            format!("{}.{}", section, key)
        };
        if KNOWN_KEYS.iter().any(|(s, _)| *s == child_section) {
            check_unknown_keys(child, &child_section, errors);
        }
    }
}

/// Validate a .shipsafe.yml file. Returns a list of human-readable problems;
/// an empty list means the config is valid.
pub fn validate_file(path: &Path) -> Result<Vec<String>> {
    let mut errors = Vec::new();

    if !path.exists() {
        errors.push(format!("config file not found: {}", path.display()));
        return Ok(errors);
    }

    let content = std::fs::read_to_string(path)?;
    let value: serde_yaml::Value = match serde_yaml::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            errors.push(format!("invalid YAML: {}", e));
            return Ok(errors);
        }
    };

    check_unknown_keys(&value, "", &mut errors);

    let config: Config = match serde_yaml::from_str(&content) {
        Ok(c) => c,
        Err(e) => {
            errors.push(format!("schema error: {}", e));
            return Ok(errors);
        }
    };

    if config.version != 1 {
        errors.push(format!(
            "version: expected 1, found {} (only version 1 is supported)",
            config.version
        ));
    }

    const FORMATS: &[&str] = &["table", "json", "sarif"];
    if !FORMATS.contains(&config.output.format.as_str()) {
        errors.push(format!(
            "output.format: '{}' is not one of {}",
            config.output.format,
            FORMATS.join(", ")
        ));
    }

    const LANGS: &[&str] = &["en", "ja"];
    if !LANGS.contains(&config.output.lang.as_str()) {
        errors.push(format!(
            "output.lang: '{}' is not one of {}",
            config.output.lang,
            LANGS.join(", ")
        ));
    }

    const SEVERITIES: &[&str] = &["critical", "high", "medium", "low"];
    if !SEVERITIES.contains(&config.scanners.sca.fail_on_severity.as_str()) {
        errors.push(format!(
            "scanners.sca.fail-on-severity: '{}' is not one of {}",
            config.scanners.sca.fail_on_severity,
            SEVERITIES.join(", ")
        ));
    }

    if config.scanners.timeout_seconds == 0 {
        errors.push("scanners.timeout-seconds: must be greater than 0".to_string());
    }

    for pattern in &config.scanners.secrets.allow_patterns {
        if let Err(e) = regex::Regex::new(pattern) {
            errors.push(format!(
                "scanners.secrets.allow-patterns: invalid regex '{}': {}",
                pattern, e
            ));
        }
    }

    for pattern in &config.exclude {
        if let Err(e) = glob::Pattern::new(pattern) {
            errors.push(format!("exclude: invalid glob '{}': {}", pattern, e));
        }
    }

    let base = path.parent().unwrap_or_else(|| Path::new("."));
    for rules_path in &config.scanners.sast.rules_paths {
        let p = Path::new(rules_path);
        let resolved = if p.is_absolute() {
            p.to_path_buf()
        } else {
            base.join(p)
        };
        if !resolved.exists() {
            errors.push(format!(
                "scanners.sast.rules-paths: path does not exist: {}",
                rules_path
            ));
        }
    }

    Ok(errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_kebab_case_config() {
        let yaml = r#"
version: 1
scanners:
  sca:
    enabled: true
    fail-on-severity: medium
  secrets:
    enabled: true
    allow-patterns:
      - "EXAMPLE_.*"
    scan-history: true
ai:
  triage: true
  fix-suggestions: true
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.scanners.sca.fail_on_severity, "medium");
        assert_eq!(config.scanners.secrets.allow_patterns, vec!["EXAMPLE_.*"]);
        assert!(config.scanners.secrets.scan_history);
        assert!(config.ai.fix_suggestions);
    }

    #[test]
    fn test_parse_snake_case_config_backward_compat() {
        let yaml = r#"
version: 1
scanners:
  sca:
    enabled: true
    fail_on_severity: low
  secrets:
    enabled: true
    allow_patterns:
      - "TEST_.*"
    scan_history: true
ai:
  triage: false
  fix_suggestions: true
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.scanners.sca.fail_on_severity, "low");
        assert_eq!(config.scanners.secrets.allow_patterns, vec!["TEST_.*"]);
        assert!(config.scanners.secrets.scan_history);
        assert!(config.ai.fix_suggestions);
    }

    #[test]
    fn test_missing_version_defaults_to_1() {
        // Container-level #[serde(default)] fills missing fields from the
        // struct's Default impl, so a partial config gets version: 1.
        let config: Config = serde_yaml::from_str("scanners: {}").unwrap();
        assert_eq!(config.version, 1);
        assert!(config.scanners.sast.enabled);
    }

    #[test]
    fn test_default_config_serializes_kebab_case() {
        let yaml = serde_yaml::to_string(&Config::default()).unwrap();
        assert!(yaml.contains("fail-on-severity"));
        assert!(yaml.contains("allow-patterns"));
        assert!(!yaml.contains("fail_on_severity"));
    }

    fn write_temp_config(content: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "shipsafe-validate-test-{}-{}.yml",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn test_validate_valid_config() {
        let path = write_temp_config(
            r#"
version: 1
scanners:
  sast:
    enabled: true
    rules: [owasp-top-10]
  sca:
    fail-on-severity: high
  secrets:
    allow-patterns: ["EXAMPLE_.*"]
output:
  format: table
  lang: ja
exclude:
  - "vendor/**"
"#,
        );
        let errors = validate_file(&path).unwrap();
        std::fs::remove_file(&path).ok();
        assert!(errors.is_empty(), "unexpected errors: {:?}", errors);
    }

    #[test]
    fn test_validate_missing_file() {
        let errors = validate_file(Path::new("/nonexistent/shipsafe.yml")).unwrap();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("not found"));
    }

    #[test]
    fn test_validate_unknown_key() {
        let path = write_temp_config("version: 1\nscannres: {}\n");
        let errors = validate_file(&path).unwrap();
        std::fs::remove_file(&path).ok();
        assert!(errors.iter().any(|e| e.contains("unknown key 'scannres'")));
    }

    #[test]
    fn test_validate_nested_unknown_key() {
        let path = write_temp_config("version: 1\nscanners:\n  sast:\n    enabld: true\n");
        let errors = validate_file(&path).unwrap();
        std::fs::remove_file(&path).ok();
        assert!(errors
            .iter()
            .any(|e| e.contains("unknown key 'scanners.sast.enabld'")));
    }

    #[test]
    fn test_validate_bad_values() {
        let path = write_temp_config(
            r#"
version: 2
scanners:
  sca:
    fail-on-severity: extreme
  secrets:
    allow-patterns: ["[invalid"]
output:
  format: xml
  lang: fr
exclude:
  - "[bad-glob"
"#,
        );
        let errors = validate_file(&path).unwrap();
        std::fs::remove_file(&path).ok();
        assert!(errors.iter().any(|e| e.contains("version")));
        assert!(errors.iter().any(|e| e.contains("output.format")));
        assert!(errors.iter().any(|e| e.contains("output.lang")));
        assert!(errors.iter().any(|e| e.contains("fail-on-severity")));
        assert!(errors.iter().any(|e| e.contains("invalid regex")));
        assert!(errors.iter().any(|e| e.contains("invalid glob")));
    }

    #[test]
    fn test_validate_invalid_yaml() {
        let path = write_temp_config(": not yaml :\n  - {");
        let errors = validate_file(&path).unwrap();
        std::fs::remove_file(&path).ok();
        assert!(errors.iter().any(|e| e.contains("invalid YAML")));
    }

    #[test]
    fn test_validate_missing_rules_path() {
        let path = write_temp_config(
            "version: 1\nscanners:\n  sast:\n    rules-paths:\n      - ./no-such-rules.yml\n",
        );
        let errors = validate_file(&path).unwrap();
        std::fs::remove_file(&path).ok();
        assert!(errors.iter().any(|e| e.contains("does not exist")));
    }

    #[test]
    fn test_parse_rules_paths_and_disabled_rules() {
        let yaml = r#"
version: 1
scanners:
  sast:
    rules-paths:
      - ./custom-rules/
    disabled-rules:
      - ai-rust-unsafe-block
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.scanners.sast.rules_paths, vec!["./custom-rules/"]);
        assert_eq!(
            config.scanners.sast.disabled_rules,
            vec!["ai-rust-unsafe-block"]
        );
    }
}
