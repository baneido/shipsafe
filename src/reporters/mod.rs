pub mod json;
pub mod sarif;
pub mod table;

use crate::config::Config;
use crate::scanners::ScanResults;
use anyhow::Result;
use std::path::Path;

pub fn report(
    results: &ScanResults,
    format: &str,
    output: Option<&Path>,
    config: &Config,
) -> Result<()> {
    let content = match format {
        "json" => json::render(results)?,
        "sarif" => sarif::render(results)?,
        _ => {
            table::render(results, config);
            return Ok(());
        }
    };

    if let Some(path) = output {
        std::fs::write(path, &content)?;
        println!("Results written to {}", path.display());
    } else {
        println!("{}", content);
    }

    Ok(())
}
