use crate::scanners::ScanResults;
use anyhow::Result;

pub fn render(results: &ScanResults) -> Result<String> {
    Ok(serde_json::to_string_pretty(results)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanners::{Finding, Severity};

    fn sample_results() -> ScanResults {
        let mut r = ScanResults::new();
        r.findings.push(Finding {
            id: "CVE-2021-44228".into(),
            scanner: "sca".into(),
            severity: Severity::Critical,
            title: "log4shell".into(),
            description: "RCE in log4j".into(),
            file: "pom.xml".into(),
            line: Some(12),
            cwe: Some("CWE-502".into()),
            cve: Some("CVE-2021-44228".into()),
            fix_suggestion: Some("Upgrade to 2.17.0".into()),
        });
        r.recalculate_summary();
        r
    }

    #[test]
    fn test_json_roundtrip() {
        let rendered = render(&sample_results()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(parsed["summary"]["total"], 1);
        assert_eq!(parsed["summary"]["critical"], 1);
        let f = &parsed["findings"][0];
        assert_eq!(f["id"], "CVE-2021-44228");
        assert_eq!(f["severity"], "critical");
        assert_eq!(f["line"], 12);
        assert_eq!(f["fix_suggestion"], "Upgrade to 2.17.0");
    }

    #[test]
    fn test_json_empty_results() {
        let rendered = render(&ScanResults::new()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(parsed["summary"]["total"], 0);
        assert_eq!(parsed["findings"].as_array().unwrap().len(), 0);
    }
}
