use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    pub version: u32,
    pub scanners: ScannersConfig,
    pub output: OutputConfig,
    pub ai: AiConfig,
    #[serde(skip)]
    pub lang: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScannersConfig {
    pub sast: SastConfig,
    pub sca: ScaConfig,
    pub secrets: SecretsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
pub struct ScaConfig {
    pub enabled: bool,
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
pub struct SecretsConfig {
    pub enabled: bool,
    pub allow_patterns: Vec<String>,
}
impl Default for SecretsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allow_patterns: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
pub struct AiConfig {
    pub triage: bool,
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
