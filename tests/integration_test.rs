//! Integration tests for the shipsafe CLI.
//!
//! Tests that need external scanners (semgrep / trivy / gitleaks) adapt to
//! their presence: when a scanner is missing the graceful-degradation path is
//! asserted instead. Set SHIPSAFE_REQUIRE_SCANNERS=1 (as the e2e CI job does)
//! to fail instead of downgrading, so the full detection path is guaranteed.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::{Path, PathBuf};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/vulnerable-sample-app")
        .join(name)
}

/// Copy a fixture directory into a temp dir, stripping the ".fixture"
/// suffix from file names. Dependency manifests are stored with the suffix
/// so Dependabot / the GitHub dependency graph don't report the deliberately
/// vulnerable pins as real repository vulnerabilities.
fn staged_fixture(name: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let src = fixture(name);
    let dst = dir.path().join(name);
    copy_unfixtured(&src, &dst);
    (dir, dst)
}

fn copy_unfixtured(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let file_name = entry.file_name().to_string_lossy().to_string();
        let target_name = file_name.strip_suffix(".fixture").unwrap_or(&file_name);
        let target = dst.join(target_name);
        if entry.file_type().unwrap().is_dir() {
            copy_unfixtured(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

fn scanner_available(name: &str) -> bool {
    let available = which::which(name).is_ok();
    if !available && std::env::var("SHIPSAFE_REQUIRE_SCANNERS").is_ok() {
        panic!(
            "{} is required (SHIPSAFE_REQUIRE_SCANNERS is set) but missing",
            name
        );
    }
    available
}

fn shipsafe() -> Command {
    Command::new(env!("CARGO_BIN_EXE_shipsafe"))
}

// --- basic commands ---

#[test]
fn test_version() {
    shipsafe()
        .arg("version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn test_doctor_runs() {
    shipsafe()
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("semgrep"))
        .stdout(predicate::str::contains("trivy"))
        .stdout(predicate::str::contains("gitleaks"));
}

#[test]
fn test_doctor_japanese() {
    shipsafe()
        .args(["--lang", "ja", "doctor"])
        .assert()
        .success()
        .stdout(predicate::str::contains("スキャナー"));
}

#[test]
fn test_init_creates_config() {
    let dir = tempfile::tempdir().unwrap();
    shipsafe()
        .current_dir(dir.path())
        .arg("init")
        .assert()
        .success();
    let content = std::fs::read_to_string(dir.path().join(".shipsafe.yml")).unwrap();
    assert!(content.contains("scanners"));
    assert!(content.contains("fail-on-severity"));
}

#[test]
fn test_init_then_validate_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    shipsafe()
        .current_dir(dir.path())
        .arg("init")
        .assert()
        .success();
    shipsafe()
        .current_dir(dir.path())
        .arg("validate")
        .assert()
        .success()
        .stdout(predicate::str::contains("valid"));
}

// --- validate ---

#[test]
fn test_validate_reports_problems_and_fails() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(".shipsafe.yml"),
        "version: 1\nscannres: {}\noutput:\n  format: xml\n",
    )
    .unwrap();
    shipsafe()
        .current_dir(dir.path())
        .arg("validate")
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown key 'scannres'"))
        .stderr(predicate::str::contains("output.format"));
}

#[test]
fn test_validate_missing_config_fails() {
    let dir = tempfile::tempdir().unwrap();
    shipsafe()
        .current_dir(dir.path())
        .args(["--config", "missing.yml", "validate"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

// --- scan: graceful degradation (no scanners needed) ---

#[test]
fn test_scan_empty_dir_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("main.txt"), "nothing to see").unwrap();
    shipsafe()
        .current_dir(dir.path())
        .args(["scan", "-s", "secrets"])
        .assert()
        .success();
}

#[test]
fn test_scan_missing_scanner_warns_and_succeeds() {
    // Run with an empty-ish PATH so no scanner resolves; the gate must skip
    // each scanner with a visible warning instead of crashing.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "x = 1\n").unwrap();
    shipsafe()
        .current_dir(dir.path())
        .env("PATH", "/nonexistent-bin")
        .arg("scan")
        .assert()
        .success()
        .stderr(predicate::str::contains("doctor"));
}

// --- scan: JSON / SARIF output shape ---

#[test]
fn test_scan_json_output_file() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "x = 1\n").unwrap();
    let out = dir.path().join("results.json");
    shipsafe()
        .current_dir(dir.path())
        .args([
            "scan",
            "-s",
            "secrets",
            "--format",
            "json",
            "--output",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert!(json.get("findings").is_some());
    assert!(json.get("summary").is_some());
}

#[test]
fn test_scan_sarif_output_file() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "x = 1\n").unwrap();
    let out = dir.path().join("results.sarif");
    shipsafe()
        .current_dir(dir.path())
        .args([
            "scan",
            "-s",
            "secrets",
            "--format",
            "sarif",
            "--output",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();
    let sarif: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(sarif.get("version").and_then(|v| v.as_str()), Some("2.1.0"));
    assert!(sarif.get("runs").and_then(|r| r.as_array()).is_some());
}

// --- scan: secrets detection on fixtures (gitleaks) ---

fn scan_json(target: &Path, scanners: &str, extra: &[&str]) -> serde_json::Value {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("results.json");
    let mut cmd = shipsafe();
    // A non-existent config falls back to defaults, keeping the test
    // hermetic from the repository's own .shipsafe.yml (which allowlists
    // the fixtures).
    let no_config = dir.path().join("no-config.yml");
    cmd.args([
        "scan",
        "--config",
        no_config.to_str().unwrap(),
        "-p",
        target.to_str().unwrap(),
        "-s",
        scanners,
        "--format",
        "json",
        "--output",
        out.to_str().unwrap(),
        "--fail-on",
        "critical",
    ]);
    cmd.args(extra);
    // --fail-on critical may still exit 1 when criticals exist; accept both.
    let _ = cmd.assert();
    serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap()
}

fn finding_ids(json: &serde_json::Value) -> Vec<String> {
    json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap_or("").to_string())
        .collect()
}

#[test]
fn test_secrets_detection_japan_cloud_fixture() {
    if !scanner_available("gitleaks") {
        eprintln!("gitleaks missing — skipping detection assertions");
        return;
    }
    let json = scan_json(&fixture("secrets"), "secrets", &[]);
    let ids = finding_ids(&json);
    assert!(
        ids.iter().any(|i| i.contains("sakura-cloud")),
        "expected sakura-cloud finding, got: {:?}",
        ids
    );
    assert!(
        ids.iter().any(|i| i.contains("line-channel-secret")),
        "expected line-channel-secret finding, got: {:?}",
        ids
    );
    assert!(
        ids.iter().any(|i| i.contains("kintone")),
        "expected kintone finding, got: {:?}",
        ids
    );
}

// --- scan: SAST detection on fixtures (semgrep, OWASP registry pack) ---

#[test]
fn test_sast_detection_python_fixture() {
    if !scanner_available("semgrep") {
        eprintln!("semgrep missing — skipping detection assertions");
        return;
    }
    // The python fixture contains SQL injection / unsafe-yaml / command
    // injection patterns that the default OWASP Top 10 registry pack flags.
    let json = scan_json(&fixture("python"), "sast", &[]);
    let findings = json["findings"].as_array().unwrap();
    assert!(
        !findings.is_empty(),
        "expected OWASP findings in the python fixture, got none"
    );
}

// --- scan: SCA detection on fixtures (trivy) ---

#[test]
fn test_sca_detection_js_lockfile() {
    if !scanner_available("trivy") {
        eprintln!("trivy missing — skipping detection assertions");
        return;
    }
    let (_guard, staged) = staged_fixture("js");
    let json = scan_json(&staged, "sca", &[]);
    let findings = json["findings"].as_array().unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f["title"].as_str().unwrap_or("").contains("lodash")),
        "expected a lodash CVE finding"
    );
}

#[test]
fn test_sca_detection_python_requirements() {
    if !scanner_available("trivy") {
        eprintln!("trivy missing — skipping detection assertions");
        return;
    }
    let (_guard, staged) = staged_fixture("python");
    let json = scan_json(&staged, "sca", &[]);
    let findings = json["findings"].as_array().unwrap();
    assert!(
        findings.iter().any(|f| {
            let t = f["title"].as_str().unwrap_or("");
            t.contains("PyYAML") || t.contains("pyyaml") || t.contains("requests")
        }),
        "expected a PyYAML/requests CVE finding"
    );
}

// --- exit code behavior ---

#[test]
fn test_fail_on_exit_code_with_findings() {
    if !scanner_available("gitleaks") {
        eprintln!("gitleaks missing — skipping exit-code assertions");
        return;
    }
    shipsafe()
        .args([
            "scan",
            "--config",
            "/nonexistent-shipsafe.yml",
            "-p",
            fixture("secrets").to_str().unwrap(),
            "-s",
            "secrets",
            "--fail-on",
            "high",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--fail-on high"));
}

#[test]
fn test_exclude_tests_flag_filters_findings() {
    if !scanner_available("gitleaks") {
        eprintln!("gitleaks missing — skipping exclude assertions");
        return;
    }
    // The fixture lives under tests/fixtures/... so scanning the repo's
    // tests directory with --exclude-tests must drop those findings.
    let dir = tempfile::tempdir().unwrap();
    let tests_dir = dir.path().join("tests");
    std::fs::create_dir_all(&tests_dir).unwrap();
    std::fs::write(
        tests_dir.join("config.py"),
        "KINTONE_API_TOKEN = \"x7Gp2qLm9RtV4wYz8KdN3hBj6FsC1aQe\"\n",
    )
    .unwrap();

    let out = dir.path().join("with.json");
    let mut cmd = shipsafe();
    cmd.current_dir(dir.path()).args([
        "scan",
        "-s",
        "secrets",
        "--format",
        "json",
        "--output",
        out.to_str().unwrap(),
    ]);
    let _ = cmd.assert();
    let with: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();

    let out2 = dir.path().join("without.json");
    let mut cmd = shipsafe();
    cmd.current_dir(dir.path()).args([
        "scan",
        "-s",
        "secrets",
        "--exclude-tests",
        "--format",
        "json",
        "--output",
        out2.to_str().unwrap(),
    ]);
    let _ = cmd.assert();
    let without: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out2).unwrap()).unwrap();

    let n_with = with["summary"]["total"].as_u64().unwrap();
    let n_without = without["summary"]["total"].as_u64().unwrap();
    assert!(n_with >= 1, "fixture secret should be detected");
    assert_eq!(n_without, 0, "--exclude-tests should drop tests/ findings");
}

// --- Japanese output ---

#[test]
fn test_scan_japanese_summary() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "x = 1\n").unwrap();
    shipsafe()
        .current_dir(dir.path())
        .args(["--lang", "ja", "scan", "-s", "secrets"])
        .assert()
        .success()
        .stdout(predicate::str::contains("集計"));
}
