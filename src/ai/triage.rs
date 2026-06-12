//! AI triage: send scan findings (with surrounding code context) to the
//! Claude API and classify each one as a true positive, a false positive, or
//! uncertain. False positives stay in the report — annotated with the model's
//! reasoning — but are excluded from the `--fail-on` gate, so noisy findings
//! stop breaking builds without ever being silently hidden.
//!
//! Opt-in only (`ai.triage: true` or `--ai-triage`) and BYOK: the request is
//! sent directly to the Anthropic API with the user's own ANTHROPIC_API_KEY.
//! Any failure (missing key, network, refusal) degrades gracefully: the scan
//! result is simply left untriaged and the gate behaves exactly as without AI.

use crate::config::Config;
use crate::scanners::{Finding, ScanResults};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

pub const API_KEY_ENV: &str = "ANTHROPIC_API_KEY";
const API_URL: &str = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION: &str = "2023-06-01";
/// 1 initial try + 2 retries on rate limits / server errors.
const MAX_ATTEMPTS: u32 = 3;
/// Lines of code context included before and after each finding line.
const CONTEXT_LINES: usize = 12;
/// Findings descriptions are clipped to keep the request small.
const MAX_DESCRIPTION_CHARS: usize = 400;

/// Triage verdict attached to a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Likely exploitable / real — keeps gating the build.
    TruePositive,
    /// Not exploitable in this context — annotated, excluded from the gate.
    FalsePositive,
    /// The model could not decide — treated like a true positive (fail safe).
    Uncertain,
}

impl Verdict {
    pub fn label(&self, lang: &str) -> &'static str {
        if lang == "ja" {
            match self {
                Verdict::TruePositive => "要対応",
                Verdict::FalsePositive => "誤検知",
                Verdict::Uncertain => "要確認",
            }
        } else {
            match self {
                Verdict::TruePositive => "true positive",
                Verdict::FalsePositive => "false positive",
                Verdict::Uncertain => "uncertain",
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriageConfidence {
    Low,
    Medium,
    High,
}

impl TriageConfidence {
    pub fn label(&self, lang: &str) -> &'static str {
        if lang == "ja" {
            match self {
                TriageConfidence::Low => "低",
                TriageConfidence::Medium => "中",
                TriageConfidence::High => "高",
            }
        } else {
            match self {
                TriageConfidence::Low => "low",
                TriageConfidence::Medium => "medium",
                TriageConfidence::High => "high",
            }
        }
    }
}

/// AI triage result carried on a `Finding` and serialized into JSON / SARIF
/// reports, so every verdict is auditable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Triage {
    pub verdict: Verdict,
    pub confidence: TriageConfidence,
    /// Short explanation of the verdict, in the configured output language.
    pub reason: String,
    /// Model that produced the verdict.
    pub model: String,
}

/// Counts reported after a triage run.
#[derive(Debug, Default)]
pub struct TriageSummary {
    pub triaged: usize,
    pub true_positives: usize,
    pub false_positives: usize,
    pub uncertain: usize,
    /// Findings beyond `ai.max-findings` that were left untriaged.
    pub skipped: usize,
}

/// Run AI triage over the scan results, annotating findings in place.
///
/// Errors are returned to the caller, which warns and continues — triage must
/// never break the gate.
pub async fn run(
    results: &mut ScanResults,
    scan_path: &Path,
    config: &Config,
) -> Result<TriageSummary> {
    if results.findings.is_empty() {
        return Ok(TriageSummary::default());
    }

    let api_key = std::env::var(API_KEY_ENV)
        .ok()
        .filter(|k| !k.trim().is_empty())
        .ok_or_else(|| anyhow!("{} is not set", API_KEY_ENV))?;

    // Severity-descending order; cap at ai.max-findings to bound cost.
    let mut order: Vec<usize> = (0..results.findings.len()).collect();
    order.sort_by(|a, b| {
        results.findings[*b]
            .severity
            .cmp(&results.findings[*a].severity)
    });
    let selected: Vec<usize> = order.into_iter().take(config.ai.max_findings).collect();
    let skipped = results.findings.len() - selected.len();

    let prompt = build_prompt(&results.findings, &selected, scan_path);
    let body = build_request_body(&config.ai.model, &config.lang, &prompt);

    let response = send_with_retries(&api_key, &body, config.ai.timeout_seconds).await?;
    let verdicts = parse_response(&response)?;

    let mut summary = TriageSummary {
        skipped,
        ..TriageSummary::default()
    };
    for v in verdicts {
        let Some(&finding_idx) = selected.get(v.index) else {
            tracing::warn!("triage verdict for unknown finding index {}", v.index);
            continue;
        };
        match v.verdict {
            Verdict::TruePositive => summary.true_positives += 1,
            Verdict::FalsePositive => summary.false_positives += 1,
            Verdict::Uncertain => summary.uncertain += 1,
        }
        summary.triaged += 1;
        results.findings[finding_idx].ai_triage = Some(Triage {
            verdict: v.verdict,
            confidence: v.confidence,
            reason: v.reason,
            model: config.ai.model.clone(),
        });
    }
    Ok(summary)
}

/// Per-finding verdict as returned by the model (indexes into the list of
/// findings that were sent, not into `results.findings`).
#[derive(Debug, Deserialize)]
struct RawVerdict {
    index: usize,
    verdict: Verdict,
    confidence: TriageConfidence,
    reason: String,
}

#[derive(Debug, Deserialize)]
struct RawVerdicts {
    verdicts: Vec<RawVerdict>,
}

fn system_prompt(lang: &str) -> String {
    let reason_lang = if lang == "ja" { "Japanese" } else { "English" };
    format!(
        "You are the triage engine of ShipSafe, a pre-deploy security gate. You receive \
         findings from SAST, dependency (SCA), and secret scanners, each with surrounding \
         code context. Classify every finding:\n\
         - true_positive: plausibly real and reachable in this code.\n\
         - false_positive: clearly not exploitable here — e.g. test/fixture/example code, \
         a placeholder or documented sample value, dead code, input that is already \
         sanitized or constant, or a finding that misreads the code.\n\
         - uncertain: not enough context to decide.\n\
         Be conservative: a false_positive verdict removes the finding from the build \
         gate, so only use it when the evidence in the provided context is clear. When \
         in doubt, answer uncertain. Never invent code that is not shown.\n\
         For each finding give a one-sentence reason in {reason_lang}, written for the \
         developer who will review the report."
    )
}

/// JSON schema the model's answer must conform to (structured outputs).
fn output_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "verdicts": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "index": { "type": "integer", "description": "Finding index as given in the input" },
                        "verdict": { "type": "string", "enum": ["true_positive", "false_positive", "uncertain"] },
                        "confidence": { "type": "string", "enum": ["low", "medium", "high"] },
                        "reason": { "type": "string", "description": "One-sentence justification" }
                    },
                    "required": ["index", "verdict", "confidence", "reason"],
                    "additionalProperties": false
                }
            }
        },
        "required": ["verdicts"],
        "additionalProperties": false
    })
}

fn build_request_body(model: &str, lang: &str, prompt: &str) -> serde_json::Value {
    serde_json::json!({
        "model": model,
        "max_tokens": 16000,
        "thinking": { "type": "adaptive" },
        "system": system_prompt(lang),
        "messages": [ { "role": "user", "content": prompt } ],
        "output_config": { "format": { "type": "json_schema", "schema": output_schema() } }
    })
}

/// Render the selected findings (with code context) into the user prompt.
fn build_prompt(findings: &[Finding], selected: &[usize], scan_path: &Path) -> String {
    let mut prompt = String::with_capacity(selected.len() * 1024);
    prompt.push_str(
        "Triage the following security findings. Reply with one verdict per finding, \
         keyed by its index.\n",
    );
    for (sent_idx, &finding_idx) in selected.iter().enumerate() {
        let f = &findings[finding_idx];
        let mut description = f.description.clone();
        if description.len() > MAX_DESCRIPTION_CHARS {
            let mut cut = MAX_DESCRIPTION_CHARS;
            while !description.is_char_boundary(cut) {
                cut -= 1;
            }
            description.truncate(cut);
            description.push('…');
        }
        prompt.push_str(&format!(
            "\n## Finding {sent_idx}\n- rule: {} (scanner: {})\n- severity: {}\n- title: {}\n",
            f.id, f.scanner, f.severity, f.title
        ));
        if !description.is_empty() {
            prompt.push_str(&format!("- description: {description}\n"));
        }
        let location = match f.line {
            Some(line) => format!("{}:{}", f.file, line),
            None => f.file.clone(),
        };
        prompt.push_str(&format!("- location: {location}\n"));
        if let Some(snippet) = code_context(scan_path, f) {
            prompt.push_str(&format!("- code context:\n```\n{snippet}```\n"));
        }
    }
    prompt
}

/// Read ±CONTEXT_LINES around the finding line, with line numbers and a
/// `>` marker on the flagged line. Returns None when the file or line is
/// unavailable (e.g. SCA findings on lockfiles are judged without context).
fn code_context(scan_path: &Path, finding: &Finding) -> Option<String> {
    let line = finding.line? as usize;
    if finding.file.is_empty() {
        return None;
    }
    let path = Path::new(&finding.file);
    let resolved = if path.is_absolute() {
        path.to_path_buf()
    } else {
        scan_path.join(path)
    };
    let content = std::fs::read_to_string(&resolved).ok()?;
    let lines: Vec<&str> = content.lines().collect();
    if line == 0 || line > lines.len() {
        return None;
    }
    let start = line.saturating_sub(CONTEXT_LINES + 1);
    let end = (line + CONTEXT_LINES).min(lines.len());
    let mut snippet = String::new();
    for (i, text) in lines[start..end].iter().enumerate() {
        let n = start + i + 1;
        let marker = if n == line { ">" } else { " " };
        snippet.push_str(&format!("{marker}{n:>5} | {text}\n"));
    }
    Some(snippet)
}

/// POST to the Messages API, retrying rate limits and server errors with
/// backoff. Other HTTP errors fail immediately.
async fn send_with_retries(
    api_key: &str,
    body: &serde_json::Value,
    timeout_seconds: u64,
) -> Result<serde_json::Value> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_seconds))
        .build()
        .context("failed to build HTTP client")?;

    let mut last_error = None;
    for attempt in 1..=MAX_ATTEMPTS {
        let result = client
            .post(API_URL)
            .header("x-api-key", api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("content-type", "application/json")
            .json(body)
            .send()
            .await;

        match result {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    return response.json().await.context("invalid JSON from the API");
                }
                let text = response.text().await.unwrap_or_default();
                let first = text.lines().next().unwrap_or("").to_string();
                let retryable = status.as_u16() == 429 || status.is_server_error();
                last_error = Some(anyhow!("API returned {status}: {first}"));
                if !retryable {
                    break;
                }
            }
            Err(e) => {
                last_error = Some(anyhow!(e).context("request to the Anthropic API failed"));
            }
        }
        if attempt < MAX_ATTEMPTS {
            tokio::time::sleep(Duration::from_millis(1000 * u64::from(attempt))).await;
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow!("triage request failed")))
}

/// Extract the verdicts from a Messages API response.
fn parse_response(response: &serde_json::Value) -> Result<Vec<RawVerdict>> {
    if response.get("stop_reason").and_then(|s| s.as_str()) == Some("refusal") {
        bail!("the model declined to triage this scan (stop_reason: refusal)");
    }
    if response.get("stop_reason").and_then(|s| s.as_str()) == Some("max_tokens") {
        bail!("triage response was truncated (stop_reason: max_tokens)");
    }
    let text = response
        .get("content")
        .and_then(|c| c.as_array())
        .and_then(|blocks| {
            blocks
                .iter()
                .find(|b| b.get("type").and_then(|t| t.as_str()) == Some("text"))
        })
        .and_then(|b| b.get("text"))
        .and_then(|t| t.as_str())
        .ok_or_else(|| anyhow!("no text block in the API response"))?;
    let parsed: RawVerdicts =
        serde_json::from_str(text).context("triage response did not match the expected schema")?;
    Ok(parsed.verdicts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanners::Severity;

    fn finding(id: &str, severity: Severity, file: &str, line: Option<u32>) -> Finding {
        Finding {
            id: id.into(),
            scanner: "sast".into(),
            severity,
            title: id.into(),
            description: "desc".into(),
            file: file.into(),
            line,
            cwe: None,
            cve: None,
            fix_suggestion: None,
            ai_triage: None,
        }
    }

    #[test]
    fn test_parse_response_extracts_verdicts() {
        let response = serde_json::json!({
            "stop_reason": "end_turn",
            "content": [
                { "type": "thinking", "thinking": "..." },
                { "type": "text", "text": r#"{"verdicts":[
                    {"index":0,"verdict":"false_positive","confidence":"high","reason":"test fixture"},
                    {"index":1,"verdict":"true_positive","confidence":"medium","reason":"reachable"}
                ]}"# }
            ]
        });
        let verdicts = parse_response(&response).unwrap();
        assert_eq!(verdicts.len(), 2);
        assert_eq!(verdicts[0].verdict, Verdict::FalsePositive);
        assert_eq!(verdicts[0].confidence, TriageConfidence::High);
        assert_eq!(verdicts[1].verdict, Verdict::TruePositive);
    }

    #[test]
    fn test_parse_response_refusal_is_error() {
        let response = serde_json::json!({ "stop_reason": "refusal", "content": [] });
        let err = parse_response(&response).unwrap_err();
        assert!(err.to_string().contains("refusal"));
    }

    #[test]
    fn test_parse_response_truncated_is_error() {
        let response = serde_json::json!({ "stop_reason": "max_tokens", "content": [] });
        assert!(parse_response(&response).is_err());
    }

    #[test]
    fn test_parse_response_invalid_json_is_error() {
        let response = serde_json::json!({
            "stop_reason": "end_turn",
            "content": [ { "type": "text", "text": "not json" } ]
        });
        assert!(parse_response(&response).is_err());
    }

    #[test]
    fn test_build_prompt_includes_findings_and_indexes() {
        let findings = vec![
            finding("sql-injection", Severity::Critical, "app.py", Some(3)),
            finding("xss", Severity::Medium, "web.js", None),
        ];
        let prompt = build_prompt(&findings, &[0, 1], Path::new("/nonexistent"));
        assert!(prompt.contains("## Finding 0"));
        assert!(prompt.contains("sql-injection"));
        assert!(prompt.contains("app.py:3"));
        assert!(prompt.contains("## Finding 1"));
        assert!(prompt.contains("web.js"));
    }

    #[test]
    fn test_build_prompt_clips_long_descriptions() {
        let mut f = finding("rule", Severity::Low, "a.py", Some(1));
        f.description = "x".repeat(2000);
        let prompt = build_prompt(std::slice::from_ref(&f), &[0], Path::new("/nonexistent"));
        assert!(prompt.contains('…'));
        assert!(prompt.len() < 2000);
    }

    #[test]
    fn test_code_context_marks_finding_line() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("app.py");
        let body: String = (1..=40).map(|i| format!("line {i}\n")).collect();
        std::fs::write(&file, body).unwrap();

        let f = finding("rule", Severity::High, "app.py", Some(20));
        let snippet = code_context(dir.path(), &f).unwrap();
        assert!(snippet.contains(">   20 | line 20"));
        assert!(snippet.contains("    8 | line 8"));
        assert!(snippet.contains("   32 | line 32"));
        assert!(!snippet.contains("line 7\n"));
    }

    #[test]
    fn test_code_context_missing_file_is_none() {
        let f = finding("rule", Severity::High, "missing.py", Some(1));
        assert!(code_context(Path::new("/nonexistent-shipsafe"), &f).is_none());
    }

    #[test]
    fn test_code_context_out_of_range_line_is_none() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "one line\n").unwrap();
        let f = finding("rule", Severity::High, "a.py", Some(99));
        assert!(code_context(dir.path(), &f).is_none());
    }

    #[test]
    fn test_request_body_shape() {
        let body = build_request_body("claude-opus-4-8", "ja", "PROMPT");
        assert_eq!(body["model"], "claude-opus-4-8");
        assert_eq!(body["thinking"]["type"], "adaptive");
        assert_eq!(body["output_config"]["format"]["type"], "json_schema");
        assert_eq!(body["messages"][0]["content"], "PROMPT");
        assert!(body["system"].as_str().unwrap().contains("Japanese"));
        let schema = &body["output_config"]["format"]["schema"];
        assert_eq!(schema["properties"]["verdicts"]["type"], "array");
    }

    #[tokio::test]
    async fn test_run_without_api_key_fails_gracefully() {
        // Ensure the variable is unset for this test.
        std::env::remove_var(API_KEY_ENV);
        let mut results = ScanResults::new();
        results
            .findings
            .push(finding("rule", Severity::High, "a.py", Some(1)));
        results.recalculate_summary();

        let config = Config::default();
        let err = run(&mut results, Path::new("."), &config)
            .await
            .unwrap_err();
        assert!(err.to_string().contains(API_KEY_ENV));
        assert!(results.findings[0].ai_triage.is_none());
    }
}
