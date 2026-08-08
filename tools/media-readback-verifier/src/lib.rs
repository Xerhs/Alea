//! Media readback verification (SPEC §10 steps 6-7):
//!
//! > 6. Read back the complete written media.
//! > 7. Compare the read-back image against the published expected hash.
//!
//! This crate reads a written device or file, hashes its complete
//! contents with SHA-256, and compares the digest against a published
//! expected hash — the same digest published alongside the release image
//! (SPEC §32: "published binary and source hashes"). It performs no
//! writing and requires no elevated privileges or mounting: it treats the
//! target purely as a byte stream, exactly matching how the writing tool
//! (`dd`, Rufus, `image-builder`'s own output, etc.) would have produced
//! it.
//!
//! SPEC §10 is explicit that this ceremony step "raises the attacker's
//! required effort; it does not create a trusted channel out of an
//! untrusted machine" — this tool is one link in that documented,
//! non-self-authenticating chain, not a security boundary by itself.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

/// Result of comparing a read-back digest against the expected hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyResult {
    /// SPEC §10 step 7 succeeded: digests match.
    Match,
    /// SPEC §10 step 7 failed: digests differ. The media MUST be treated
    /// as unverified and not booted (SPEC §10 step 9 depends on a
    /// verified chain up to this point).
    Mismatch,
}

/// Errors reading the target media/file or parsing the expected hash.
#[derive(Debug)]
pub enum VerifyError {
    Io(io::Error),
    /// The expected-hash argument was neither 64 hex characters nor a
    /// path to a readable hash file.
    InvalidExpectedHash(String),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::Io(e) => write!(f, "I/O error: {e}"),
            VerifyError::InvalidExpectedHash(s) => {
                write!(f, "could not parse expected hash from '{s}'")
            }
        }
    }
}

impl std::error::Error for VerifyError {}

impl From<io::Error> for VerifyError {
    fn from(e: io::Error) -> Self {
        VerifyError::Io(e)
    }
}

/// Computes the SHA-256 digest of the complete contents at `path`,
/// reading in fixed-size chunks so arbitrarily large block devices or
/// image files are handled without loading the whole thing into memory
/// (SPEC §10 step 6: "Read back the complete written media").
pub fn hash_file(path: &Path) -> io::Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let mut f = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

/// Renders a digest as lowercase hex, matching the vector-file and
/// `SHA256SUMS` convention (IMPLEMENTATION_MAP.md §4: "all hex
/// lowercase").
pub fn to_hex(digest: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Parses a 64-character lowercase-or-uppercase hex string into a
/// 32-byte digest.
fn parse_hex_digest(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Parses one line of a `SHA256SUMS`-style file into `(digest, filename)`,
/// tolerant of both the two-space text-mode convention (`<hex>  <name>`)
/// and the `sha256sum -b` binary-mode convention (`<hex> *<name>`)
/// emitted by `sha256sum` and by this workspace's own `image-builder`
/// tool. Returns `None` for blank lines or lines whose first token is not
/// a valid 64-hex-character digest.
fn parse_sha256sums_line(line: &str) -> Option<([u8; 32], &str)> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let mut parts = line.splitn(2, char::is_whitespace);
    let digest = parse_hex_digest(parts.next()?)?;
    let filename = parts.next()?.trim_start().trim_start_matches('*').trim();
    if filename.is_empty() {
        return None;
    }
    Some((digest, filename))
}

/// Resolves the "expected hash" CLI argument, accepting either:
///
/// - a bare 64-hex-character digest, or
/// - a path to a `SHA256SUMS`-style file containing one or more
///   `<hex>  <filename>` entries (the format emitted by both
///   `sha256sum` and this workspace's own `image-builder` tool).
///
/// When resolving from a hash file, the entry is selected by matching
/// `media_path`'s file name against each entry's recorded filename —
/// **not** by taking whichever entry happens to be listed first. A real
/// release `SHA256SUMS` lists every artifact in the release (image,
/// binaries, etc.), and VERIFYING-MEDIA.md §2 explicitly recommends
/// pointing this tool at that same multi-entry file from a release
/// pipeline, so silently trusting the first line would compare the
/// read-back media against the wrong artifact's published hash whenever
/// it isn't first in the file.
///
/// Returns [`VerifyError::InvalidExpectedHash`] if the hash file contains
/// no entry whose filename matches `media_path`'s file name, or more than
/// one such entry (an ambiguous file) — failing closed rather than
/// guessing, since a wrong silent match here defeats the whole point of
/// SPEC §10 step 7.
pub fn resolve_expected_hash(arg: &str, media_path: &Path) -> Result<[u8; 32], VerifyError> {
    if let Some(digest) = parse_hex_digest(arg) {
        return Ok(digest);
    }
    let path = Path::new(arg);
    if path.is_file() {
        let contents = std::fs::read_to_string(path)?;
        let media_name = media_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| VerifyError::InvalidExpectedHash(arg.to_string()))?;

        let mut matches = contents.lines().filter_map(parse_sha256sums_line).filter(
            |(_, filename)| {
                Path::new(filename).file_name().and_then(|n| n.to_str()) == Some(media_name)
            },
        );

        let first = matches.next();
        return match first {
            Some((digest, _)) if matches.next().is_none() => Ok(digest),
            Some(_) => Err(VerifyError::InvalidExpectedHash(format!(
                "'{arg}' has more than one entry matching media file name '{media_name}'"
            ))),
            None => Err(VerifyError::InvalidExpectedHash(format!(
                "'{arg}' has no entry matching media file name '{media_name}'"
            ))),
        };
    }
    Err(VerifyError::InvalidExpectedHash(arg.to_string()))
}

/// Performs SPEC §10 steps 6-7 end to end: hash the media at `media_path`
/// and compare it against `expected`.
pub fn verify(media_path: &Path, expected: &[u8; 32]) -> Result<VerifyResult, VerifyError> {
    let actual = hash_file(media_path)?;
    if &actual == expected {
        Ok(VerifyResult::Match)
    } else {
        Ok(VerifyResult::Mismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp(dir: &Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = dir.join(name);
        let mut f = File::create(&path).unwrap();
        f.write_all(bytes).unwrap();
        path
    }

    #[test]
    fn matching_media_verifies_as_match() {
        let tmp = std::env::temp_dir().join(format!("mrv-test-match-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let payload = b"deterministic image bytes go here".repeat(100);
        let media = write_temp(&tmp, "media.img", &payload);
        let digest = hash_file(&media).unwrap();

        let result = verify(&media, &digest).unwrap();
        assert_eq!(result, VerifyResult::Match);
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn corrupted_copy_is_detected_as_mismatch() {
        let tmp = std::env::temp_dir().join(format!("mrv-test-mismatch-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let mut payload = b"deterministic image bytes go here".repeat(100);
        let original = write_temp(&tmp, "original.img", &payload);
        let expected = hash_file(&original).unwrap();

        // Corrupt a single byte in a copy, as a bit-flip during a bad
        // write would.
        payload[42] ^= 0xFF;
        let corrupted = write_temp(&tmp, "corrupted.img", &payload);

        let result = verify(&corrupted, &expected).unwrap();
        assert_eq!(result, VerifyResult::Mismatch);
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn resolves_bare_hex_digest() {
        let hex = "a".repeat(64);
        // A bare hex digest needs no media path to disambiguate against;
        // pass an arbitrary path to satisfy the signature.
        let digest = resolve_expected_hash(&hex, Path::new("/dev/null")).unwrap();
        assert_eq!(to_hex(&digest), hex);
    }

    #[test]
    fn resolves_sha256sums_style_file_by_matching_media_filename() {
        let tmp = std::env::temp_dir().join(format!("mrv-test-hashfile-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let hex = "b".repeat(64);
        let hash_file_path = write_temp(&tmp, "SHA256SUMS", format!("{hex}  alea-usb.img\n").as_bytes());
        let media_path = tmp.join("alea-usb.img");
        let digest = resolve_expected_hash(hash_file_path.to_str().unwrap(), &media_path).unwrap();
        assert_eq!(to_hex(&digest), hex);
        std::fs::remove_dir_all(&tmp).ok();
    }

    /// Regression test for the WP-29 review finding: a real release
    /// `SHA256SUMS` lists multiple artifacts (image, binaries, etc.), per
    /// VERIFYING-MEDIA.md §2's explicit recommendation to point this tool
    /// at that same file from a release pipeline. `resolve_expected_hash`
    /// must select the entry matching the media file actually being
    /// verified, not merely the first parseable 64-hex-char token in the
    /// file.
    #[test]
    fn multi_entry_sha256sums_selects_entry_matching_media_filename_not_first_line() {
        let tmp = std::env::temp_dir().join(format!("mrv-test-multisums-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();

        let first_entry_hex = "1".repeat(64);
        let target_hex = "2".repeat(64);
        let third_entry_hex = "3".repeat(64);
        let sums_contents = format!(
            "{first_entry_hex}  alea-x86_64-signed.efi\n{target_hex}  alea-x86_64-usb.img\n{third_entry_hex}  alea-x86_64-unsigned.efi\n"
        );
        let hash_file_path = write_temp(&tmp, "SHA256SUMS", sums_contents.as_bytes());

        // The media file being verified is the *second* listed artifact,
        // not the first — this is the exact scenario the bug got wrong.
        let media_path = tmp.join("alea-x86_64-usb.img");

        let digest = resolve_expected_hash(hash_file_path.to_str().unwrap(), &media_path).unwrap();
        assert_eq!(
            to_hex(&digest),
            target_hex,
            "must match the SHA256SUMS entry named after the media file, not the first line"
        );

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn sha256sums_file_with_no_entry_for_media_filename_is_rejected() {
        let tmp = std::env::temp_dir().join(format!("mrv-test-nomatch-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let hex = "c".repeat(64);
        let hash_file_path = write_temp(&tmp, "SHA256SUMS", format!("{hex}  some-other-file.img\n").as_bytes());
        let media_path = tmp.join("alea-usb.img");

        let result = resolve_expected_hash(hash_file_path.to_str().unwrap(), &media_path);
        assert!(result.is_err(), "must fail closed rather than silently use an unrelated entry");

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn sha256sums_file_with_duplicate_entries_for_media_filename_is_rejected() {
        let tmp = std::env::temp_dir().join(format!("mrv-test-ambiguous-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let hex_a = "d".repeat(64);
        let hex_b = "e".repeat(64);
        let sums_contents = format!("{hex_a}  alea-usb.img\n{hex_b}  alea-usb.img\n");
        let hash_file_path = write_temp(&tmp, "SHA256SUMS", sums_contents.as_bytes());
        let media_path = tmp.join("alea-usb.img");

        let result = resolve_expected_hash(hash_file_path.to_str().unwrap(), &media_path);
        assert!(result.is_err(), "an ambiguous hash file must not silently pick one entry");

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn rejects_garbage_expected_hash() {
        assert!(resolve_expected_hash("not-a-hash-or-path", Path::new("/dev/null")).is_err());
    }
}
