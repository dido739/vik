use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

fn run_ok(cwd: &Path, args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_vik"))
        .current_dir(cwd)
        .env("VIK_AUTHOR", "tester")
        .args(args)
        .output()
        .expect("run command");
    assert!(
        output.status.success(),
        "command failed: {:?}\nstdout:{}\nstderr:{}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf8 stdout")
}

#[test]
fn init_is_idempotent() {
    let tmp = tempdir().unwrap();
    run_ok(tmp.path(), &["init"]);
    run_ok(tmp.path(), &["init"]);
    assert!(tmp.path().join(".vik/objects").is_dir());
    assert!(tmp.path().join(".vik/refs/heads/main").is_file());
}

#[test]
fn hash_and_cat_blob_object() {
    let tmp = tempdir().unwrap();
    run_ok(tmp.path(), &["init"]);
    fs::write(tmp.path().join("note.txt"), "hello vik\n").unwrap();

    let oid = run_ok(tmp.path(), &["hash-object", "note.txt", "--write"])
        .trim()
        .to_string();
    assert_eq!(oid.len(), 64);

    let content = run_ok(tmp.path(), &["cat-file", "-p", &oid]);
    assert_eq!(content, "hello vik\n");
}

#[test]
fn add_commit_log_branch_checkout_flow() {
    let tmp = tempdir().unwrap();
    run_ok(tmp.path(), &["init"]);

    fs::write(tmp.path().join("file.txt"), "main\n").unwrap();
    run_ok(tmp.path(), &["add", "file.txt"]);
    run_ok(tmp.path(), &["commit", "-m", "initial"]);

    run_ok(tmp.path(), &["branch", "feature"]);
    run_ok(tmp.path(), &["checkout", "feature"]);

    fs::write(tmp.path().join("file.txt"), "feature\n").unwrap();
    run_ok(tmp.path(), &["add", "file.txt"]);
    run_ok(tmp.path(), &["commit", "-m", "feature commit"]);

    run_ok(tmp.path(), &["checkout", "main"]);
    let main_content = fs::read_to_string(tmp.path().join("file.txt")).unwrap();
    assert_eq!(main_content, "main\n");

    let log = run_ok(tmp.path(), &["log"]);
    assert!(log.contains("initial"));
}
