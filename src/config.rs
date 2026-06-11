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
            lang: String::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ScannersConfig {
    pub sast: SastConfig,
    pub sca: ScaConfig,
    pub secrets: SecretsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SastConfig {
    pub enabled: bool,
    pub languages: Vec<String>,
    pub rules: Vec<String>,
    pub exclude: Vec<String>,
}
impl Default for SastConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            languages: vec![],
            rules: vec!["owasp-top-10".into()],
            exclude: vec![],
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
    fn test_default_config_serializes_kebab_case() {
        let yaml = serde_yaml::to_string(&Config::default()).unwrap();
        assert!(yaml.contains("fail-on-severity"));
        assert!(yaml.contains("allow-patterns"));
        assert!(!yaml.contains("fail_on_severity"));
    }
}
