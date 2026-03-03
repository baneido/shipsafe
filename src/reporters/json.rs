use crate::scanners::ScanResults;
use anyhow::Result;

pub fn render(results: &ScanResults) -> Result<String> {
    Ok(serde_json::to_string_pretty(results)?)
}
