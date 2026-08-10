//! `release-verifier` (WP-32) — a host-only tool that checks a
//! Alea release directory against its published `SHA256SUMS` file
//! and, where a detached `minisign` signature is present, its signature.
//!
//! # Scope and non-goals (SPEC §10, §31, §32)
//!
//! This tool implements the *mechanical* parts of the SPEC §10
//! release-verification ceremony that can be automated on a release
//! directory already sitting on disk: recomputing every listed file's
//! SHA-256 digest and comparing it against `SHA256SUMS`
//! ([`verify_sha256sums`]), and invoking a locally installed `minisign`
//! binary to check `SHA256SUMS.minisig` against a project public key
//! ([`check_minisig`]).
//!
//! It deliberately does **not** vendor any signature-verification
//! cryptography (no Ed25519 implementation lives in this crate). SPEC
//! §31 keeps the production dependency set minimal and reviewed; a
//! release-engineering *tool* outside the production graph is not
//! obligated to add a signing-crypto dependency of its own when the
//! reference `minisign` CLI already exists, is independently
//! maintained, and is the tool `VERIFYING-MEDIA.md` tells end users to
//! install. When that binary is not available on `PATH`, this tool
//! reports [`MinisigStatus::ToolMissing`] with the exact manual command
//! a user or CI system can run instead — it never claims a signature
//! check happened when one did not.
//!
//! This tool does **not** perform SPEC §10 steps 1-4 (fingerprint
//! cross-channel verification, second-device re-check, revocation-list
//! lookup) or steps 5-9 (writing/reading back physical removable media,
//! confirming the booted build identifier) — those are procedural,
//! human/media steps documented in `VERIFYING-MEDIA.md`, not something a
//! program running against a release directory can attest to on its
//! own.
#![forbid(unsafe_code)]

pub mod dependency_policy;
pub mod manifest;

use sha2::{Digest, Sha256};
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Default `SHA256SUMS` file name (SPEC §32 release-archive contents
/// list).
pub const SHA256SUMS_NAME: &str = "SHA256SUMS";

/// Default detached-signature file name (SPEC §32 release-archive
/// contents list).
pub const MINISIG_NAME: &str = "SHA256SUMS.minisig";

/// The SSH detached-signature file name the current release process
/// actually ships (`ssh-keygen -Y sign`, verified against the committed
/// `allowed_signers` keyring). Added for ALEA-2026-007: the release
/// switched from minisign to an SSH signature for the checksum manifest,
/// but this tool only knew `SHA256SUMS.minisig` and silently passed the
/// real release. Both names are recognized now; see [`check_ssh_sig`].
pub const SSH_SIG_NAME: &str = "SHA256SUMS.sig";

/// One parsed line of a `SHA256SUMS` file: a lowercase hex SHA-256
/// digest and the release-relative file name it names, in the
/// conventional `coreutils sha256sum` text format (`<hex>␠␠<name>`,
/// i.e. GNU "text mode" with two spaces — this parser also accepts a
/// single space and an optional leading `*` binary-mode marker for
/// interoperability with other generators).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChecksumEntry {
    /// Lowercase hex-encoded expected SHA-256 digest, exactly 64 hex
    /// characters.
    pub hex: String,
    /// File name exactly as written in `SHA256SUMS`, interpreted
    /// relative to the release directory.
    pub filename: String,
}

/// Failure parsing or reading a `SHA256SUMS` file.
#[derive(Debug)]
pub enum VerifyError {
    /// `SHA256SUMS` itself could not be read (missing release
    /// directory, permissions, etc).
    ReadSums(io::Error),
    /// A line in `SHA256SUMS` was not in the recognized
    /// `<hex>␠␠<name>` / `<hex>␠*<name>` format.
    MalformedLine { line_no: usize, line: String },
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::ReadSums(e) => write!(f, "could not read {SHA256SUMS_NAME}: {e}"),
            VerifyError::MalformedLine { line_no, line } => {
                write!(f, "{SHA256SUMS_NAME} line {line_no} is malformed: {line:?}")
            }
        }
    }
}

impl std::error::Error for VerifyError {}

/// Parse a `SHA256SUMS` file's textual contents into [`ChecksumEntry`]
/// rows (SPEC §32). Blank lines and lines starting with `#` are
/// skipped (not part of the coreutils format, but harmless and useful
/// for hand-annotated release notes).
///
/// # Errors
///
/// Returns [`VerifyError::MalformedLine`] naming the offending
/// (1-indexed) line if any non-blank, non-comment line does not parse
/// as `<64 lowercase hex chars><space or two-spaces or " *"><name>`.
pub fn parse_sha256sums(contents: &str) -> Result<Vec<ChecksumEntry>, VerifyError> {
    let mut entries = Vec::new();
    for (idx, raw_line) in contents.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw_line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Hex digest is a fixed 64-char run; whatever separator scheme
        // follows (one space, two spaces, or " *" for binary mode), the
        // file name is everything after the first run of separator
        // characters starting at byte 64.
        if line.len() < 66 {
            return Err(VerifyError::MalformedLine {
                line_no,
                line: line.to_string(),
            });
        }
        let (hex, rest) = line.split_at(64);
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) || !hex.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()) {
            return Err(VerifyError::MalformedLine {
                line_no,
                line: line.to_string(),
            });
        }
        let rest = rest.strip_prefix("  ").or_else(|| rest.strip_prefix(" *")).or_else(|| rest.strip_prefix(' '));
        let filename = match rest {
            Some(name) if !name.is_empty() => name.to_string(),
            _ => {
                return Err(VerifyError::MalformedLine {
                    line_no,
                    line: line.to_string(),
                })
            }
        };
        entries.push(ChecksumEntry { hex: hex.to_string(), filename });
    }
    Ok(entries)
}

/// Outcome of checking one [`ChecksumEntry`] against the file on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryResult {
    /// The file exists and its SHA-256 digest matches `SHA256SUMS`.
    Match { filename: String },
    /// The file exists but its digest does not match.
    Mismatch {
        filename: String,
        expected_hex: String,
        actual_hex: String,
    },
    /// `SHA256SUMS` lists a file that is not present in the release
    /// directory.
    Missing { filename: String },
    /// The file exists but could not be read (permissions, etc).
    Unreadable { filename: String, message: String },
}

impl EntryResult {
    /// True only for [`EntryResult::Match`].
    #[must_use]
    pub fn is_ok(&self) -> bool {
        matches!(self, EntryResult::Match { .. })
    }

    /// The file name this result concerns, regardless of variant.
    #[must_use]
    pub fn filename(&self) -> &str {
        match self {
            EntryResult::Match { filename }
            | EntryResult::Mismatch { filename, .. }
            | EntryResult::Missing { filename }
            | EntryResult::Unreadable { filename, .. } => filename,
        }
    }
}

/// Full result of verifying a release directory's `SHA256SUMS` file
/// (SPEC §10 step 7: "compare the read-back image against the
/// published expected hash" — this is the general form of that
/// comparison, applied to every file the release ships, not only the
/// disk image).
#[derive(Debug, Clone)]
pub struct Sha256sumsReport {
    pub entries: Vec<EntryResult>,
}

impl Sha256sumsReport {
    /// True only if every entry matched (no mismatch, no missing, no
    /// unreadable file).
    #[must_use]
    pub fn all_ok(&self) -> bool {
        !self.entries.is_empty() && self.entries.iter().all(EntryResult::is_ok)
    }
}

/// Compute the SHA-256 digest of a file, streaming it in fixed-size
/// chunks so this tool never allocates a buffer sized to the whole
/// file (release images can be large).
fn sha256_file(path: &Path) -> io::Result<[u8; 32]> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Read `<release_dir>/SHA256SUMS`, recompute the SHA-256 digest of
/// every file it lists (resolved relative to `release_dir`), and
/// report per-file agreement (SPEC §10 step 7, SPEC §32).
///
/// # Errors
///
/// [`VerifyError`] if `SHA256SUMS` itself cannot be read or parsed.
/// Per-file digest mismatches are *not* errors at this layer — they are
/// reported as [`EntryResult::Mismatch`] rows in the returned report,
/// so a caller can still see every file's status even when some fail;
/// check [`Sha256sumsReport::all_ok`] for the pass/fail verdict.
pub fn verify_sha256sums(release_dir: &Path) -> Result<Sha256sumsReport, VerifyError> {
    let sums_path = release_dir.join(SHA256SUMS_NAME);
    let contents = fs::read_to_string(&sums_path).map_err(VerifyError::ReadSums)?;
    let listed = parse_sha256sums(&contents)?;

    let mut entries = Vec::with_capacity(listed.len());
    for entry in listed {
        let file_path = release_dir.join(&entry.filename);
        if !file_path.is_file() {
            entries.push(EntryResult::Missing {
                filename: entry.filename,
            });
            continue;
        }
        match sha256_file(&file_path) {
            Ok(digest) => {
                let actual_hex = hex_encode(&digest);
                if actual_hex.eq_ignore_ascii_case(&entry.hex) {
                    entries.push(EntryResult::Match {
                        filename: entry.filename,
                    });
                } else {
                    entries.push(EntryResult::Mismatch {
                        filename: entry.filename,
                        expected_hex: entry.hex,
                        actual_hex,
                    });
                }
            }
            Err(e) => entries.push(EntryResult::Unreadable {
                filename: entry.filename,
                message: e.to_string(),
            }),
        }
    }
    Ok(Sha256sumsReport { entries })
}

/// Outcome of the minisign detached-signature check (SPEC §10 step 2-3
/// context, SPEC §32's `SHA256SUMS.minisig`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MinisigStatus {
    /// `SHA256SUMS.minisig` does not exist in the release directory —
    /// nothing to check. Not itself a failure at this layer, but
    /// `VERIFYING-MEDIA.md` treats an unsigned release as a Level-1
    /// (SPEC §33) case only, never sufficient alone.
    NotPresent,
    /// `minisign` verified the signature successfully against the
    /// given public key.
    Verified,
    /// `minisign` ran and reported the signature as INVALID — this is
    /// a genuine failure (tampered or wrong-key file), distinct from
    /// "could not check".
    Invalid { stderr: String },
    /// No `minisign` binary was found on `PATH` (or at the given
    /// override path). The manual verification command that reproduces
    /// this check is included so a caller can print it for the user
    /// (see `VERIFYING-MEDIA.md`).
    ToolMissing { manual_command: String },
    /// A minisig file is present but no public key was supplied, so
    /// this tool has nothing to verify against even if `minisign`
    /// itself is installed.
    NoPublicKey,
}

impl MinisigStatus {
    /// True for [`MinisigStatus::NotPresent`] or [`MinisigStatus::Verified`]
    /// — i.e., nothing indicates the release is tampered. [`MinisigStatus::ToolMissing`]
    /// and [`MinisigStatus::NoPublicKey`] are deliberately *not* "ok": the
    /// caller must decide whether an unverified signature blocks a
    /// release ceremony (SPEC §10 says it must for an end user; a CI
    /// smoke test may treat it as a warning).
    #[must_use]
    pub fn definitely_not_bad(&self) -> bool {
        matches!(self, MinisigStatus::NotPresent | MinisigStatus::Verified)
    }

    /// True only for [`MinisigStatus::Invalid`] — an explicit,
    /// positively-detected signature failure.
    #[must_use]
    pub fn is_invalid(&self) -> bool {
        matches!(self, MinisigStatus::Invalid { .. })
    }
}

/// Check `<release_dir>/SHA256SUMS.minisig` against
/// `<release_dir>/SHA256SUMS` using an external `minisign` binary
/// (SPEC §31: "do not vendor crypto for this" is this crate's own
/// design choice, documented in the module doc comment).
///
/// `minisign_bin` overrides the binary name/path to invoke (default
/// `"minisign"`, resolved via `PATH`). `pubkey` is either a minisign
/// public-key string (the `RW...` base64 blob) or a path to a
/// `.pub` file — both forms are accepted by `minisign -P`/`-p`
/// respectively; this function takes a raw string and passes it via
/// `-P` (inline key) when it looks like a minisign public key literal
/// (starts with `RW`), otherwise via `-p` (key file path).
///
/// Returns [`MinisigStatus::NotPresent`] immediately, without invoking
/// any subprocess, when `SHA256SUMS.minisig` is absent.
pub fn check_minisig(release_dir: &Path, minisign_bin: &str, pubkey: Option<&str>) -> MinisigStatus {
    let sig_path = release_dir.join(MINISIG_NAME);
    if !sig_path.is_file() {
        return MinisigStatus::NotPresent;
    }
    let sums_path = release_dir.join(SHA256SUMS_NAME);

    let Some(pubkey) = pubkey else {
        return MinisigStatus::NoPublicKey;
    };

    let key_flag = if pubkey.starts_with("RW") { "-P" } else { "-p" };
    let manual_command = format!(
        "{minisign_bin} -Vm {sums} -x {sig} {flag} {key}",
        sums = sums_path.display(),
        sig = sig_path.display(),
        flag = key_flag,
        key = pubkey,
    );

    let output = Command::new(minisign_bin)
        .arg("-Vm")
        .arg(&sums_path)
        .arg("-x")
        .arg(&sig_path)
        .arg(key_flag)
        .arg(pubkey)
        .output();

    match output {
        Ok(out) if out.status.success() => MinisigStatus::Verified,
        Ok(out) => MinisigStatus::Invalid {
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        },
        Err(_) => MinisigStatus::ToolMissing { manual_command },
    }
}

/// Outcome of the SSH detached-signature check
/// (`SHA256SUMS.sig` via `ssh-keygen -Y verify`, ALEA-2026-007). The SSH
/// analogue of [`MinisigStatus`], with one extra variant: [`SshSigStatus::NoTrustRoot`]
/// — an SSH signature cannot even be attempted without a caller-supplied
/// `allowed_signers` keyring AND signer identity, and this tool
/// deliberately refuses to fall back to a keyring bundled in the release
/// directory itself (ALEA-2026-001: the trust root must come from an
/// out-of-band channel, never the artifact being verified).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshSigStatus {
    /// `SHA256SUMS.sig` does not exist — nothing to check here.
    NotPresent,
    /// `ssh-keygen -Y verify` accepted the signature against the supplied
    /// `allowed_signers`/identity.
    Verified,
    /// `ssh-keygen` ran and reported the signature INVALID (tampered
    /// `SHA256SUMS`, wrong signer, or malformed signature).
    Invalid { stderr: String },
    /// No `ssh-keygen` binary was found; the exact manual command is
    /// included so a caller can print it.
    ToolMissing { manual_command: String },
    /// `SHA256SUMS.sig` is present but no out-of-band `allowed_signers`
    /// AND `--signer-identity` were supplied, so there is no trust root
    /// to verify against (ALEA-2026-001). Never falls back to a
    /// release-dir keyring.
    NoTrustRoot,
}

impl SshSigStatus {
    /// True for [`SshSigStatus::NotPresent`] or [`SshSigStatus::Verified`]
    /// — nothing indicates tampering. `ToolMissing`/`NoTrustRoot` are
    /// deliberately not "ok" (checked-nothing must differ from verified).
    #[must_use]
    pub fn definitely_not_bad(&self) -> bool {
        matches!(self, SshSigStatus::NotPresent | SshSigStatus::Verified)
    }

    /// True only for [`SshSigStatus::Invalid`].
    #[must_use]
    pub fn is_invalid(&self) -> bool {
        matches!(self, SshSigStatus::Invalid { .. })
    }

    /// True when a `SHA256SUMS.sig` file exists (any status except
    /// [`SshSigStatus::NotPresent`]) — used by the `--require-signature`
    /// gate to tell "a signature exists" from "none shipped".
    #[must_use]
    pub fn is_present(&self) -> bool {
        !matches!(self, SshSigStatus::NotPresent)
    }
}

/// Check `<release_dir>/SHA256SUMS.sig` against `<release_dir>/SHA256SUMS`
/// with `ssh-keygen -Y verify` (ALEA-2026-007). Shells out to
/// `ssh-keygen`, mirroring [`check_minisig`]'s no-vendored-crypto design.
///
/// `allowed_signers` is a path to an SSH allowed-signers file and
/// `identity` is the signer principal (the email/name in that file) —
/// **both must be supplied by the caller out-of-band**; when either is
/// `None` this returns [`SshSigStatus::NoTrustRoot`] and NEVER falls back
/// to a keyring found inside `release_dir` (ALEA-2026-001).
///
/// Returns [`SshSigStatus::NotPresent`] without any subprocess when
/// `SHA256SUMS.sig` is absent.
pub fn check_ssh_sig(
    release_dir: &Path,
    ssh_keygen_bin: &str,
    allowed_signers: Option<&str>,
    identity: Option<&str>,
) -> SshSigStatus {
    let sig_path = release_dir.join(SSH_SIG_NAME);
    if !sig_path.is_file() {
        return SshSigStatus::NotPresent;
    }
    let (Some(allowed), Some(id)) = (allowed_signers, identity) else {
        return SshSigStatus::NoTrustRoot;
    };
    let sums_path = release_dir.join(SHA256SUMS_NAME);
    let manual_command = format!(
        "{ssh_keygen_bin} -Y verify -f {allowed} -I {id} -n file -s {sig} < {sums}",
        sig = sig_path.display(),
        sums = sums_path.display(),
    );
    // ssh-keygen -Y verify reads the signed payload (the SHA256SUMS bytes)
    // from stdin.
    let sums_bytes = match fs::read(&sums_path) {
        Ok(b) => b,
        Err(e) => {
            return SshSigStatus::Invalid {
                stderr: format!("could not read {SHA256SUMS_NAME} to verify its signature: {e}"),
            }
        }
    };
    let child = Command::new(ssh_keygen_bin)
        .args(["-Y", "verify", "-f", allowed, "-I", id, "-n", "file", "-s"])
        .arg(&sig_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(_) => return SshSigStatus::ToolMissing { manual_command },
    };
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = stdin.write_all(&sums_bytes);
        // drop stdin to send EOF
    }
    match child.wait_with_output() {
        Ok(out) if out.status.success() => SshSigStatus::Verified,
        Ok(out) => SshSigStatus::Invalid {
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        },
        Err(_) => SshSigStatus::ToolMissing { manual_command },
    }
}

/// Combined SHA256SUMS + minisig verdict for a release directory, plus
/// the pieces of the SPEC §10 ceremony this tool cannot itself perform
/// (documented so a CLI can print them as an explicit reminder rather
/// than silently omitting them).
#[derive(Debug)]
pub struct ReleaseReport {
    pub release_dir: PathBuf,
    pub sums: Result<Sha256sumsReport, VerifyError>,
    pub minisig: MinisigStatus,
    /// SSH detached-signature verdict (`SHA256SUMS.sig`, ALEA-2026-007).
    pub ssh: SshSigStatus,
}

impl ReleaseReport {
    /// Overall pass/fail for automated use (e.g. a CI gate or this
    /// crate's own exit code): every `SHA256SUMS` entry matched AND
    /// neither the minisig nor the SSH signature check positively failed.
    /// A missing tool or missing key/keyring does *not* fail this — see
    /// [`MinisigStatus::definitely_not_bad`]/[`SshSigStatus::definitely_not_bad`]
    /// — because "could not check" and "checked and it's wrong" are
    /// different findings that SPEC §10's honesty requirement says must
    /// never be conflated. A caller that wants "a valid signature MUST
    /// exist" applies [`ReleaseReport::signature_present`] +
    /// require-signature policy on top (see the CLI's `--require-signature`).
    #[must_use]
    pub fn passed(&self) -> bool {
        let sums_ok = matches!(&self.sums, Ok(r) if r.all_ok());
        sums_ok && !self.minisig.is_invalid() && !self.ssh.is_invalid()
    }

    /// True when at least one detached-signature file (`.sig` or
    /// `.minisig`) exists in the release directory, regardless of whether
    /// it could be verified. The `--require-signature` gate distinguishes
    /// "no signature shipped at all" (this is false) from "a signature
    /// exists but we lacked the tool/key" (this is true).
    #[must_use]
    pub fn signature_present(&self) -> bool {
        self.ssh.is_present() || !matches!(self.minisig, MinisigStatus::NotPresent)
    }
}

/// Run the full (automatable) check against a release directory (SPEC
/// §10, §32), including both the legacy minisign and the current SSH
/// detached-signature formats (ALEA-2026-007).
pub fn verify_release(
    release_dir: &Path,
    minisign_bin: &str,
    pubkey: Option<&str>,
    ssh_keygen_bin: &str,
    allowed_signers: Option<&str>,
    signer_identity: Option<&str>,
) -> ReleaseReport {
    let sums = verify_sha256sums(release_dir);
    let minisig = check_minisig(release_dir, minisign_bin, pubkey);
    let ssh = check_ssh_sig(release_dir, ssh_keygen_bin, allowed_signers, signer_identity);
    ReleaseReport {
        release_dir: release_dir.to_path_buf(),
        sums,
        minisig,
        ssh,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// A fresh, empty directory under the system temp dir, unique per
    /// call (and per process via `std::process::id`) so parallel test
    /// runs never collide. Left on disk; `/tmp`-style dirs are cleaned
    /// by the OS/CI, and leaving them aids failure post-mortems.
    fn fresh_dir(tag: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "release-verifier-test-{}-{}-{}",
            std::process::id(),
            tag,
            n
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(dir: &Path, name: &str, contents: &[u8]) {
        fs::write(dir.join(name), contents).unwrap();
    }

    #[test]
    fn parses_two_space_and_one_space_and_binary_mode_lines() {
        let hex = "a".repeat(64);
        let text = format!(
            "{hex}  two-space.bin\n{hex} one-space.bin\n{hex} *binary.bin\n# comment\n\n"
        );
        let entries = parse_sha256sums(&text).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].filename, "two-space.bin");
        assert_eq!(entries[1].filename, "one-space.bin");
        assert_eq!(entries[2].filename, "binary.bin");
    }

    #[test]
    fn rejects_malformed_line() {
        let err = parse_sha256sums("not-a-valid-line\n").unwrap_err();
        assert!(matches!(err, VerifyError::MalformedLine { line_no: 1, .. }));
    }

    #[test]
    fn end_to_end_pass_then_corrupt_fails() {
        let dir = fresh_dir("e2e");
        write(&dir, "a.bin", b"hello world");
        write(&dir, "b.bin", b"second file contents");

        let hash_a = hex_encode(&sha256_file(&dir.join("a.bin")).unwrap());
        let hash_b = hex_encode(&sha256_file(&dir.join("b.bin")).unwrap());
        let sums = format!("{hash_a}  a.bin\n{hash_b}  b.bin\n");
        write(&dir, SHA256SUMS_NAME, sums.as_bytes());

        let report = verify_sha256sums(&dir).expect("SHA256SUMS reads and parses");
        assert!(report.all_ok(), "expected all entries to match: {report:?}");

        // Corrupt one file in place -> must now fail, and specifically
        // that file's entry must be the Mismatch.
        write(&dir, "a.bin", b"HELLO WORLD (tampered)");
        let report2 = verify_sha256sums(&dir).expect("SHA256SUMS still reads");
        assert!(!report2.all_ok(), "corrupted release must not verify as ok");
        let a_entry = report2.entries.iter().find(|e| e.filename() == "a.bin").unwrap();
        assert!(matches!(a_entry, EntryResult::Mismatch { .. }));
        let b_entry = report2.entries.iter().find(|e| e.filename() == "b.bin").unwrap();
        assert!(b_entry.is_ok(), "untouched file must still verify");
    }

    #[test]
    fn missing_file_is_reported_not_panicked() {
        let dir = fresh_dir("missing");
        let fake_hex = "0".repeat(64);
        write(&dir, SHA256SUMS_NAME, format!("{fake_hex}  ghost.bin\n").as_bytes());
        let report = verify_sha256sums(&dir).unwrap();
        assert!(!report.all_ok());
        assert!(matches!(report.entries[0], EntryResult::Missing { .. }));
    }

    #[test]
    fn verify_release_reports_missing_sums_file_as_error_not_panic() {
        let dir = fresh_dir("nosums");
        let report = verify_release(&dir, "minisign", None, "ssh-keygen", None, None);
        assert!(report.sums.is_err());
        assert!(!report.passed());
    }

    #[test]
    fn ssh_sig_not_present_when_no_sig_file() {
        let dir = fresh_dir("no-ssh-sig");
        let status = check_ssh_sig(&dir, "ssh-keygen", Some("/tmp/allowed"), Some("a@b"));
        assert_eq!(status, SshSigStatus::NotPresent);
        assert!(status.definitely_not_bad());
        assert!(!status.is_present());
    }

    #[test]
    fn ssh_sig_present_without_trust_root_is_no_trust_root() {
        let dir = fresh_dir("ssh-sig-notrust");
        write(&dir, SHA256SUMS_NAME, b"irrelevant");
        write(&dir, SSH_SIG_NAME, b"fake ssh signature");
        // No allowed_signers/identity supplied -> must NOT try, must NOT
        // fall back to a release-dir keyring (ALEA-2026-001).
        let status = check_ssh_sig(&dir, "ssh-keygen", None, None);
        assert_eq!(status, SshSigStatus::NoTrustRoot);
        assert!(!status.definitely_not_bad());
        assert!(status.is_present());
    }

    #[test]
    fn ssh_sig_present_with_nonexistent_binary_reports_tool_missing() {
        let dir = fresh_dir("ssh-sig-notool");
        write(&dir, SHA256SUMS_NAME, b"irrelevant");
        write(&dir, SSH_SIG_NAME, b"fake ssh signature");
        let status = check_ssh_sig(
            &dir,
            "definitely-not-a-real-ssh-keygen-xyz",
            Some("/tmp/allowed_signers"),
            Some("signer@example"),
        );
        match status {
            SshSigStatus::ToolMissing { manual_command } => {
                assert!(manual_command.contains("definitely-not-a-real-ssh-keygen-xyz"));
                assert!(manual_command.contains("-Y verify"));
            }
            other => panic!("expected ToolMissing, got {other:?}"),
        }
    }

    /// Host-gated end-to-end: if `ssh-keygen` exists, generate a throwaway
    /// ed25519 key, build an allowed_signers, sign SHA256SUMS, and verify
    /// it round-trips; then tamper SHA256SUMS and confirm Invalid. Skips
    /// cleanly when ssh-keygen is unavailable.
    #[test]
    fn ssh_sig_end_to_end_verifies_and_detects_tamper() {
        if Command::new("ssh-keygen").arg("-Q").output().is_err()
            && Command::new("ssh-keygen").arg("--help").output().is_err()
        {
            eprintln!("skipping: ssh-keygen not available");
            return;
        }
        let dir = fresh_dir("ssh-sig-e2e");
        let key = dir.join("id");
        // -N "" = no passphrase, -q quiet
        let kg = Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-N", "", "-q", "-f"])
            .arg(&key)
            .output();
        if kg.map(|o| !o.status.success()).unwrap_or(true) {
            eprintln!("skipping: ssh-keygen keygen failed");
            return;
        }
        let pubkey = fs::read_to_string(dir.join("id.pub")).unwrap();
        let identity = "test@alea";
        let allowed = dir.join("allowed_signers");
        // "<principal> <keytype> <base64>"
        let parts: Vec<&str> = pubkey.split_whitespace().collect();
        fs::write(&allowed, format!("{identity} {} {}\n", parts[0], parts[1])).unwrap();
        write(&dir, SHA256SUMS_NAME, b"the checksum list\n");
        // sign
        let sign = Command::new("ssh-keygen")
            .args(["-Y", "sign", "-n", "file", "-f"])
            .arg(&key)
            .arg(dir.join(SHA256SUMS_NAME))
            .output()
            .unwrap();
        assert!(sign.status.success(), "ssh-keygen -Y sign failed: {sign:?}");
        // ssh-keygen writes <file>.sig
        assert!(dir.join(SSH_SIG_NAME).is_file(), "expected SHA256SUMS.sig");

        let ok = check_ssh_sig(&dir, "ssh-keygen", allowed.to_str(), Some(identity));
        assert_eq!(ok, SshSigStatus::Verified, "valid signature must verify");

        // Tamper the signed payload -> Invalid.
        write(&dir, SHA256SUMS_NAME, b"the checksum list (tampered)\n");
        let bad = check_ssh_sig(&dir, "ssh-keygen", allowed.to_str(), Some(identity));
        assert!(bad.is_invalid(), "tampered SHA256SUMS must fail: {bad:?}");
    }

    #[test]
    fn minisig_not_present_when_no_sig_file() {
        let dir = fresh_dir("nominisig");
        let status = check_minisig(&dir, "minisign", Some("RWpubkeyfake"));
        assert_eq!(status, MinisigStatus::NotPresent);
        assert!(status.definitely_not_bad());
    }

    #[test]
    fn minisig_present_without_pubkey_is_no_public_key() {
        let dir = fresh_dir("minisig-nopubkey");
        write(&dir, SHA256SUMS_NAME, b"irrelevant");
        write(&dir, MINISIG_NAME, b"fake signature bytes");
        let status = check_minisig(&dir, "minisign", None);
        assert_eq!(status, MinisigStatus::NoPublicKey);
        assert!(!status.definitely_not_bad());
        assert!(!status.is_invalid());
    }

    #[test]
    fn minisig_present_with_nonexistent_binary_reports_tool_missing() {
        let dir = fresh_dir("minisig-notool");
        write(&dir, SHA256SUMS_NAME, b"irrelevant");
        write(&dir, MINISIG_NAME, b"fake signature bytes");
        let status = check_minisig(&dir, "definitely-not-a-real-binary-xyz", Some("RWfakekey"));
        match status {
            MinisigStatus::ToolMissing { manual_command } => {
                assert!(manual_command.contains("definitely-not-a-real-binary-xyz"));
                assert!(manual_command.contains("-Vm"));
            }
            other => panic!("expected ToolMissing, got {other:?}"),
        }
    }
}
