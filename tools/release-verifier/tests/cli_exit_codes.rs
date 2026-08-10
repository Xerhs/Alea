//! Regression test (WP-32, SPEC §10) for the `release-verifier` CLI's
//! exit codes when `SHA256SUMS.minisig` is present but was NOT
//! cryptographically authenticated.
//!
//! Adversarial/UX review flagged that, before this fix, such a run
//! printed a `WARNING` to stdout but still exited `0` — indistinguishable,
//! to a caller/CI script that only checks the process exit code, from a
//! release whose signature was genuinely verified. That is exactly the
//! "hash from the same possibly-compromised source proves nothing"
//! failure mode SPEC §10 warns about: it must never look like a pass.
//!
//! This test drives the actual compiled binary (not the library
//! functions directly) because the defect was specifically in
//! `main.rs`'s exit-code wiring, not in `check_minisig`'s classification
//! (which was already correct).
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn fresh_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "release-verifier-cli-test-{}-{}-{}",
        std::process::id(),
        tag,
        n
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(dir: &Path, name: &str, contents: &[u8]) {
    std::fs::write(dir.join(name), contents).unwrap();
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Build a release directory with one file and a matching, self-consistent
/// `SHA256SUMS` (so the hash-check step always passes, isolating the test
/// to the minisig exit-code behavior under test).
fn clean_release_dir(tag: &str) -> PathBuf {
    let dir = fresh_dir(tag);
    let content = b"release-verifier WP-32 regression fixture\n";
    write(&dir, "artifact.bin", content);
    let hex = sha256_hex(content);
    write(&dir, "SHA256SUMS", format!("{hex}  artifact.bin\n").as_bytes());
    dir
}

fn run(dir: &Path, extra_args: &[&str]) -> (i32, String) {
    let bin = env!("CARGO_BIN_EXE_release-verifier");
    let output = Command::new(bin)
        .arg(dir)
        .args(extra_args)
        .output()
        .expect("failed to run release-verifier binary");
    let code = output
        .status
        .code()
        .expect("release-verifier exited via signal, not a status code");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    (code, stdout)
}

#[test]
fn minisig_present_without_pubkey_exits_nonzero_never_zero() {
    let dir = clean_release_dir("no-pubkey");
    write(&dir, "SHA256SUMS.minisig", b"untrusted-minisig-fixture-bytes\n");

    let (code, stdout) = run(&dir, &[]);

    assert!(
        stdout.contains("WARNING"),
        "expected a WARNING about the unauthenticated signature, got:\n{stdout}"
    );
    assert_ne!(
        code, 0,
        "an unauthenticated SHA256SUMS.minisig (no --pubkey given) must NEVER exit 0 \
         (that would be indistinguishable from a real cryptographic verification, \
         precisely the failure mode SPEC §10 warns about); stdout was:\n{stdout}"
    );
    assert_eq!(
        code, 3,
        "expected the dedicated 'present but unauthenticated' exit code 3; stdout was:\n{stdout}"
    );
}

#[test]
fn minisig_present_with_missing_minisign_binary_exits_nonzero_never_zero() {
    let dir = clean_release_dir("no-tool");
    write(&dir, "SHA256SUMS.minisig", b"untrusted-minisig-fixture-bytes\n");

    let (code, stdout) = run(
        &dir,
        &[
            "--pubkey",
            "RWfakekeyfakekeyfakekeyfakekeyfakekeyfakekeyfakekeyfakekeyfake",
            "--minisign-bin",
            "definitely-not-a-real-binary-xyz-wp32",
        ],
    );

    assert!(
        stdout.contains("WARNING"),
        "expected a WARNING that the tool was not found, got:\n{stdout}"
    );
    assert_ne!(
        code, 0,
        "a missing `minisign` binary must never exit 0 when a signature was present \
         but could not be checked; stdout was:\n{stdout}"
    );
    assert_eq!(code, 3, "expected exit code 3; stdout was:\n{stdout}");
}

#[test]
fn no_minisig_file_still_exits_zero_on_clean_release() {
    // Guards against over-correcting: a release with NO
    // SHA256SUMS.minisig at all (nothing to authenticate) must still
    // exit 0 when the hashes match — only a *present-but-unauthenticated*
    // signature should be penalized.
    let dir = clean_release_dir("clean");

    let (code, stdout) = run(&dir, &[]);

    assert_eq!(
        code, 0,
        "a clean release with no minisig file to check must still exit 0; stdout was:\n{stdout}"
    );
}

#[test]
fn corrupted_hash_plus_unauthenticated_minisig_reports_both_and_stays_nonzero() {
    // Two independent problems at once (hash mismatch AND an
    // unauthenticated signature) must never cancel out to 0, and the
    // worse-numbered finding (3: present-but-unauthenticated signature)
    // must win, per the existing worst_exit = max(...) design already
    // used to prefer exit 2 (invalid signature) over exit 1 (hash
    // mismatch).
    let dir = clean_release_dir("corrupt");
    write(&dir, "SHA256SUMS.minisig", b"untrusted-minisig-fixture-bytes\n");
    // Corrupt the file after SHA256SUMS was written against the original.
    write(&dir, "artifact.bin", b"tampered contents");

    let (code, stdout) = run(&dir, &[]);

    assert!(
        stdout.contains("MISMATCH"),
        "expected the hash mismatch to still be reported; stdout was:\n{stdout}"
    );
    assert!(
        stdout.contains("WARNING"),
        "expected the minisig warning to still be reported; stdout was:\n{stdout}"
    );
    assert_eq!(
        code, 3,
        "worst_exit must take the max across both independent findings; stdout was:\n{stdout}"
    );
}

// ---- ALEA-2026-007: SSH SHA256SUMS.sig support + --require-signature ----

/// Core regression: `--require-signature` on a clean release that ships NO
/// detached signature must exit 3, never 0 (the old minisign-only path
/// silently passed here).
#[test]
fn require_signature_with_no_signature_present_exits_nonzero() {
    let dir = clean_release_dir("require-no-sig");
    let (code, stdout) = run(&dir, &["--require-signature"]);
    assert_eq!(code, 3, "must fail closed; stdout:\n{stdout}");
    assert!(stdout.contains("ships no"), "stdout:\n{stdout}");
}

/// Over-correction guard: without `--require-signature`, no signature
/// stays exit 0 (back-compat).
#[test]
fn no_signature_present_without_require_still_exits_zero() {
    let dir = clean_release_dir("no-sig-no-require");
    let (code, _stdout) = run(&dir, &[]);
    assert_eq!(code, 0);
}

/// `SHA256SUMS.sig` present with no `--allowed-signers`/`--signer-identity`:
/// WARN + exit 3 (no trust root); never 0, never a release-dir fallback
/// (ALEA-2026-001).
#[test]
fn ssh_sig_present_without_allowed_signers_exits_3() {
    let dir = clean_release_dir("ssh-sig-notrust");
    write(&dir, "SHA256SUMS.sig", b"untrusted-ssh-sig-fixture\n");
    let (code, stdout) = run(&dir, &[]);
    assert_eq!(code, 3, "stdout:\n{stdout}");
    assert!(stdout.contains("WARNING"), "stdout:\n{stdout}");
    assert!(stdout.contains("out-of-band"), "stdout:\n{stdout}");
}

/// `SHA256SUMS.sig` with a bogus `--ssh-keygen-bin`: WARN + exit 3, never 0.
#[test]
fn ssh_sig_present_with_missing_ssh_keygen_binary_exits_3() {
    let dir = clean_release_dir("ssh-sig-notool");
    write(&dir, "SHA256SUMS.sig", b"untrusted-ssh-sig-fixture\n");
    let (code, stdout) = run(
        &dir,
        &[
            "--allowed-signers",
            "/tmp/allowed_signers",
            "--signer-identity",
            "someone@example",
            "--ssh-keygen-bin",
            "definitely-not-a-real-ssh-keygen-xyz",
        ],
    );
    assert_eq!(code, 3, "stdout:\n{stdout}");
    assert!(stdout.contains("was not found"), "stdout:\n{stdout}");
}
