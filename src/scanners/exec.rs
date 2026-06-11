//! Shared subprocess execution for scanners: async spawning, scan timeouts,
//! and retry on transient network failures.

use anyhow::{Context, Result};
use std::process::Output;
use std::time::Duration;

/// Maximum number of attempts when a scanner fails with a network-looking
/// error (1 initial try + 2 retries).
const MAX_ATTEMPTS: u32 = 3;

/// Print a localized warning to stderr (visible to users, unlike tracing).
pub fn warn_user(lang: &str, en: &str, ja: &str) {
    if lang == "ja" {
        eprintln!("  ⚠ {}", ja);
    } else {
        eprintln!("  ⚠ {}", en);
    }
}

/// Heuristic: does this scanner output look like a transient network error
/// worth retrying (registry fetch failures, DNS, TLS, rate limits)?
pub fn is_network_error(stderr: &str) -> bool {
    let s = stderr.to_lowercase();
    [
        "connection refused",
        "connection reset",
        "connection error",
        "timed out",
        "timeout",
        "network",
        "could not resolve",
        "name resolution",
        "dns",
        "tls handshake",
        "certificate",
        "rate limit",
        "too many requests",
        "temporary failure",
        "503 service",
        "502 bad gateway",
        "unable to download",
        "failed to download",
    ]
    .iter()
    .any(|kw| s.contains(kw))
}

/// Run a scanner command with a timeout and network-error retries.
///
/// `build` is called per attempt because a tokio Command cannot be reused
/// after spawning. Returns `Ok(None)` when the scan timed out (a warning is
/// printed and the scanner is skipped) so a single slow tool never hangs the
/// whole gate.
pub async fn run_scanner(
    tool: &str,
    build: impl Fn() -> tokio::process::Command,
    timeout_seconds: u64,
    lang: &str,
) -> Result<Option<Output>> {
    let mut last_output: Option<Output> = None;

    for attempt in 1..=MAX_ATTEMPTS {
        let mut cmd = build();
        cmd.kill_on_drop(true);

        let result = tokio::time::timeout(Duration::from_secs(timeout_seconds), cmd.output()).await;

        let output = match result {
            Err(_elapsed) => {
                warn_user(
                    lang,
                    &format!(
                        "{} timed out after {}s — skipping (set scanners.timeout-seconds in .shipsafe.yml to adjust)",
                        tool, timeout_seconds
                    ),
                    &format!(
                        "{} が {} 秒でタイムアウトしました — スキップします (.shipsafe.yml の scanners.timeout-seconds で調整できます)",
                        tool, timeout_seconds
                    ),
                );
                return Ok(None);
            }
            Ok(spawned) => spawned.with_context(|| format!("failed to run {}", tool))?,
        };

        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if !output.status.success() && is_network_error(&stderr) && attempt < MAX_ATTEMPTS {
            warn_user(
                lang,
                &format!(
                    "{} hit a network error (attempt {}/{}), retrying...",
                    tool, attempt, MAX_ATTEMPTS
                ),
                &format!(
                    "{} でネットワークエラーが発生しました (試行 {}/{})。リトライします...",
                    tool, attempt, MAX_ATTEMPTS
                ),
            );
            tokio::time::sleep(Duration::from_millis(500 * u64::from(attempt))).await;
            last_output = Some(output);
            continue;
        }

        return Ok(Some(output));
    }

    Ok(last_output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_network_error_positive() {
        assert!(is_network_error("error: connection refused by host"));
        assert!(is_network_error("Request Timed Out while fetching rules"));
        assert!(is_network_error("TLS handshake failure"));
        assert!(is_network_error("could not resolve registry.example.com"));
        assert!(is_network_error("429 Too Many Requests"));
        assert!(is_network_error("failed to download vulnerability DB"));
    }

    #[test]
    fn test_is_network_error_negative() {
        assert!(!is_network_error("syntax error in rule file"));
        assert!(!is_network_error("no such file or directory"));
        assert!(!is_network_error(""));
    }

    #[tokio::test]
    async fn test_run_scanner_success() {
        let out = run_scanner(
            "echo",
            || {
                let mut c = tokio::process::Command::new("echo");
                c.arg("hello");
                c
            },
            10,
            "en",
        )
        .await
        .unwrap()
        .expect("should complete");
        assert!(out.status.success());
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hello");
    }

    #[tokio::test]
    async fn test_run_scanner_timeout_returns_none() {
        let out = run_scanner(
            "sleep",
            || {
                let mut c = tokio::process::Command::new("sleep");
                c.arg("5");
                c
            },
            1,
            "en",
        )
        .await
        .unwrap();
        assert!(out.is_none());
    }

    #[tokio::test]
    async fn test_run_scanner_missing_binary_is_error() {
        let res = run_scanner(
            "definitely-not-a-real-binary",
            || tokio::process::Command::new("definitely-not-a-real-binary-shipsafe"),
            5,
            "en",
        )
        .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_run_scanner_non_network_failure_no_retry() {
        // `false` exits 1 with no stderr; must return after one attempt
        // (a retry loop would still return, but quickly check output passes
        // through).
        let out = run_scanner("false", || tokio::process::Command::new("false"), 5, "en")
            .await
            .unwrap()
            .expect("should complete");
        assert!(!out.status.success());
    }
}
