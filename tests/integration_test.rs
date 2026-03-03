use assert_cmd::Command;

#[test]
fn test_version() {
    let mut cmd = Command::cargo_bin("shipsafe").unwrap();
    cmd.arg("version");
    cmd.assert().success();
}
