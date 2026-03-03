use crate::scanners::{ScanResults, Severity};
use anyhow::Result;
use serde_json::json;

pub fn render(results: &ScanResults) -> Result<String> {
    let sarif = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ShipSafe",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/baneido/shipsafe",
                    "rules": results.findings.iter().map(|f| {
                        json!({
                            "id": f.id,
                            "shortDescription": { "text": &f.title },
                            "defaultConfiguration": {
                                "level": match f.severity {
                                    Severity::Critical | Severity::High => "error",
                                    Severity::Medium => "warning",
                                    Severity::Low => "note",
                                }
                            }
                        })
                    }).collect::<Vec<_>>()
                }
            },
            "results": results.findings.iter().map(|f| {
                json!({
                    "ruleId": f.id,
                    "level": match f.severity {
                        Severity::Critical | Severity::High => "error",
                        Severity::Medium => "warning",
                        Severity::Low => "note",
                    },
                    "message": { "text": &f.description },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": { "uri": &f.file },
                            "region": {
                                "startLine": f.line.unwrap_or(1)
                            }
                        }
                    }]
                })
            }).collect::<Vec<_>>()
        }]
    });

    Ok(serde_json::to_string_pretty(&sarif)?)
}
