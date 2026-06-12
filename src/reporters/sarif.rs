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
                let mut result = json!({
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
                });
                // Surface the AI triage verdict so downstream consumers can
                // audit (or filter on) it.
                if let Some(ref triage) = f.ai_triage {
                    result["properties"] = json!({ "aiTriage": triage });
                }
                result
            }).collect::<Vec<_>>()
        }]
    });

    Ok(serde_json::to_string_pretty(&sarif)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanners::Finding;

    fn finding(id: &str, severity: Severity, line: Option<u32>) -> Finding {
        Finding {
            id: id.into(),
            scanner: "sast".into(),
            severity,
            title: format!("title-{}", id),
            description: format!("desc-{}", id),
            file: "src/app.py".into(),
            line,
            cwe: None,
            cve: None,
            fix_suggestion: None,
            ai_triage: None,
        }
    }

    fn results_with(findings: Vec<Finding>) -> ScanResults {
        let mut r = ScanResults::new();
        r.findings = findings;
        r.recalculate_summary();
        r
    }

    #[test]
    fn test_sarif_structure_and_levels() {
        let results = results_with(vec![
            finding("rule-critical", Severity::Critical, Some(3)),
            finding("rule-high", Severity::High, Some(4)),
            finding("rule-medium", Severity::Medium, Some(5)),
            finding("rule-low", Severity::Low, None),
        ]);
        let rendered = render(&results).unwrap();
        let sarif: serde_json::Value = serde_json::from_str(&rendered).unwrap();

        assert_eq!(sarif["version"], "2.1.0");
        let run = &sarif["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "ShipSafe");

        let res = run["results"].as_array().unwrap();
        assert_eq!(res.len(), 4);
        assert_eq!(res[0]["level"], "error"); // critical
        assert_eq!(res[1]["level"], "error"); // high
        assert_eq!(res[2]["level"], "warning"); // medium
        assert_eq!(res[3]["level"], "note"); // low

        // Region line defaults to 1 when the finding has no line.
        assert_eq!(
            res[3]["locations"][0]["physicalLocation"]["region"]["startLine"],
            1
        );
        assert_eq!(
            res[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "src/app.py"
        );

        let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 4);
        assert_eq!(rules[0]["id"], "rule-critical");
    }

    #[test]
    fn test_sarif_includes_ai_triage_properties() {
        use crate::ai::triage::{Triage, TriageConfidence, Verdict};
        let mut f = finding("rule-fp", Severity::High, Some(3));
        f.ai_triage = Some(Triage {
            verdict: Verdict::FalsePositive,
            confidence: TriageConfidence::High,
            reason: "fixture".into(),
            model: "claude-opus-4-8".into(),
        });
        let results = results_with(vec![f, finding("rule-plain", Severity::Low, None)]);
        let sarif: serde_json::Value = serde_json::from_str(&render(&results).unwrap()).unwrap();

        let res = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(
            res[0]["properties"]["aiTriage"]["verdict"],
            "false_positive"
        );
        assert_eq!(res[0]["properties"]["aiTriage"]["confidence"], "high");
        assert!(res[1].get("properties").is_none());
    }

    #[test]
    fn test_sarif_empty_results() {
        let rendered = render(&ScanResults::new()).unwrap();
        let sarif: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(sarif["runs"][0]["results"].as_array().unwrap().len(), 0);
    }
}
