//! `release-verifier` CLI (WP-32, SPEC §10, §32).
//!
//! ```text
//! release-verifier <release-dir> [--pubkey <minisign-pubkey-or-@file>] [--minisign-bin <path>]
//! ```
//!
//! Exit codes (deliberately distinguishing "verified bad" from "could
//! not verify" — SPEC §10's honesty requirement, which SPEC §10 also
//! extends to *this exit code itself*: a hash re-derived from the same
//! release directory never proves the release wasn't tampered with at
//! the source, so an unauthenticated signature MUST NOT produce the
//! same exit code as a real cryptographic verification):
//!
//! - `0` — every `SHA256SUMS` entry matched, and the minisig check
//!   either passed or found nothing to check (no `SHA256SUMS.minisig`
//!   in the release directory at all).
//! - `1` — at least one `SHA256SUMS` entry did not match, was missing,
//!   or `SHA256SUMS` itself could not be read/parsed.
//! - `2` — `SHA256SUMS.minisig` was present and `minisign` positively
//!   reported it as INVALID.
//! - `3` — `SHA256SUMS.minisig` was present but could NOT be
//!   cryptographically authenticated (no `--pubkey` was given, or the
//!   `minisign` binary is missing) — printed as a WARNING, but this is
//!   deliberately a *distinct nonzero* exit code, never `0`, so a
//!   caller/CI script that gates on the exit code alone cannot mistake
//!   "we never actually checked the signature" for "the signature
//!   verified". The SHA256SUMS hash check may still have passed; that
//!   alone proves nothing about a compromised source (SPEC §10).
//! - `4` — only reachable with `--check-manifest` (see below): the
//!   release directory is missing one or more of the fifteen files SPEC
//!   §32 names as required, or contains a desktop-test-edition artifact
//!   alongside the production release (SPEC §32, §37, §4.3; see
//!   [`release_verifier::manifest`]).
//! - `64` — usage error (bad arguments).
//!
//! `--check-manifest` is opt-in (default off): the SHA256SUMS/minisig
//! checks above are meaningful against *any* directory containing a
//! `SHA256SUMS` file (e.g. a single-artifact CI fixture), whereas the
//! full fifteen-file manifest check only makes sense against a genuine,
//! complete release directory. Making it opt-in keeps the default
//! exit-code contract for the hash/signature checks unchanged for every
//! existing caller, while still making the completeness check available
//! as an explicit, scriptable release gate (e.g. `ci.sh`'s eventual
//! full-release-assembly step) by passing the flag.
use release_verifier::manifest::{check_manifest, ManifestEntry};
use release_verifier::{
    check_minisig, verify_sha256sums, EntryResult, MinisigStatus, MINISIG_NAME, SHA256SUMS_NAME,
};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

fn usage(prog: &str) -> String {
    format!(
        "usage: {prog} <release-dir> [--pubkey <minisign-pubkey-or-@keyfile>] [--minisign-bin <path>] [--check-manifest] [--unsigned]\n\n\
         Verifies <release-dir>/{SHA256SUMS_NAME} against the files it lists (SPEC §10, §32),\n\
         and, if <release-dir>/{MINISIG_NAME} exists, checks it with the `minisign` CLI\n\
         (see VERIFYING-MEDIA.md if `minisign` is not installed — no signature crypto is\n\
         vendored in this tool).\n\n\
         --check-manifest additionally verifies that <release-dir> contains every file SPEC\n\
         §32 requires in a stable release and no desktop-test-edition artifact (SPEC §32,\n\
         §37, §4.3); opt-in because it assumes a complete release directory, not just a\n\
         SHA256SUMS-bearing one.\n\n\
         --unsigned relaxes --check-manifest for a legitimately UNSIGNED release: the two\n\
         signature files (alea-x86_64-signed.efi, SHA256SUMS.minisig) are not required (their\n\
         absence is OK; their presence is still fine). Every other required file, including\n\
         plain SHA256SUMS itself, is still required. Without --unsigned (the default),\n\
         --check-manifest requires all fifteen files — a signed release still needs its\n\
         signature files. --unsigned has no effect unless --check-manifest is also given."
    )
}

struct Args {
    release_dir: PathBuf,
    pubkey: Option<String>,
    minisign_bin: String,
    check_manifest: bool,
    unsigned: bool,
}

fn parse_args(mut argv: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut release_dir = None;
    let mut pubkey = None;
    let mut minisign_bin = "minisign".to_string();
    let mut check_manifest = false;
    let mut unsigned = false;

    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "--pubkey" => {
                let v = argv.next().ok_or("--pubkey requires a value")?;
                pubkey = Some(if let Some(path) = v.strip_prefix('@') {
                    fs::read_to_string(path)
                        .map_err(|e| format!("could not read pubkey file {path}: {e}"))?
                        .trim()
                        .to_string()
                } else {
                    v
                });
            }
            "--minisign-bin" => {
                minisign_bin = argv.next().ok_or("--minisign-bin requires a value")?;
            }
            "--check-manifest" => {
                check_manifest = true;
            }
            "--unsigned" => {
                unsigned = true;
            }
            "-h" | "--help" => return Err(String::new()),
            other if release_dir.is_none() => release_dir = Some(PathBuf::from(other)),
            other => return Err(format!("unexpected argument: {other}")),
        }
    }

    let release_dir = release_dir.ok_or("missing <release-dir> argument")?;
    Ok(Args {
        release_dir,
        pubkey,
        minisign_bin,
        check_manifest,
        unsigned,
    })
}

fn main() -> ExitCode {
    let prog = env::args().next().unwrap_or_else(|| "release-verifier".to_string());
    let args = match parse_args(env::args().skip(1)) {
        Ok(a) => a,
        Err(msg) => {
            if !msg.is_empty() {
                eprintln!("error: {msg}\n");
            }
            eprintln!("{}", usage(&prog));
            return ExitCode::from(64);
        }
    };

    println!("release-verifier: checking {}", args.release_dir.display());
    println!();

    let mut worst_exit: u8 = 0;

    println!("== {SHA256SUMS_NAME} ==");
    match verify_sha256sums(&args.release_dir) {
        Ok(report) => {
            for entry in &report.entries {
                match entry {
                    EntryResult::Match { filename } => println!("  OK       {filename}"),
                    EntryResult::Mismatch {
                        filename,
                        expected_hex,
                        actual_hex,
                    } => {
                        println!("  MISMATCH {filename}");
                        println!("           expected {expected_hex}");
                        println!("           actual   {actual_hex}");
                    }
                    EntryResult::Missing { filename } => println!("  MISSING  {filename}"),
                    EntryResult::Unreadable { filename, message } => {
                        println!("  UNREADABLE {filename} ({message})")
                    }
                }
            }
            if report.entries.is_empty() {
                println!("  (SHA256SUMS is empty — nothing was verified)");
                worst_exit = worst_exit.max(1);
            } else if report.all_ok() {
                println!("PASS: all {} file(s) match {SHA256SUMS_NAME}.", report.entries.len());
            } else {
                println!("FAIL: one or more files do not match {SHA256SUMS_NAME}.");
                worst_exit = worst_exit.max(1);
            }
        }
        Err(e) => {
            println!("FAIL: {e}");
            worst_exit = worst_exit.max(1);
        }
    }

    println!();
    println!("== {MINISIG_NAME} ==");
    let minisig = check_minisig(&args.release_dir, &args.minisign_bin, args.pubkey.as_deref());
    match &minisig {
        MinisigStatus::NotPresent => {
            println!("(no {MINISIG_NAME} in this release directory — nothing to check)");
        }
        MinisigStatus::Verified => {
            println!("PASS: minisign verified {SHA256SUMS_NAME} against the supplied public key.");
        }
        MinisigStatus::Invalid { stderr } => {
            println!("FAIL: minisign reported an INVALID signature.");
            if !stderr.is_empty() {
                println!("  minisign said: {stderr}");
            }
            worst_exit = worst_exit.max(2);
        }
        MinisigStatus::NoPublicKey => {
            println!(
                "WARNING: {MINISIG_NAME} is present but no --pubkey was given, so it was not checked."
            );
            println!("  Manual verification (see VERIFYING-MEDIA.md):");
            println!(
                "    minisign -Vm {} -x {} -p <path-to-project-pubkey.pub>",
                args.release_dir.join(SHA256SUMS_NAME).display(),
                args.release_dir.join(MINISIG_NAME).display()
            );
            // Deliberately NOT exit 0: a signature that was never
            // cryptographically checked must never look, to a caller
            // gating on exit code alone, like a passed verification
            // (SPEC §10 — see the exit-code table in this file's doc
            // comment).
            worst_exit = worst_exit.max(3);
        }
        MinisigStatus::ToolMissing { manual_command } => {
            println!(
                "WARNING: `{}` was not found; signature was NOT checked automatically.",
                args.minisign_bin
            );
            println!("  Install minisign, or verify manually (see VERIFYING-MEDIA.md):");
            println!("    {manual_command}");
            // Same reasoning as the NoPublicKey case above: no crypto
            // check happened, so this must not be exit-code 0.
            worst_exit = worst_exit.max(3);
        }
    }

    if args.check_manifest {
        println!();
        if args.unsigned {
            println!("== release manifest completeness (SPEC §32, §37, §4.3; --unsigned: signature files optional) ==");
        } else {
            println!("== release manifest completeness (SPEC §32, §37, §4.3) ==");
        }
        let manifest_report = check_manifest(&args.release_dir, !args.unsigned);
        for entry in &manifest_report.required {
            match entry {
                ManifestEntry::Present { filename } => println!("  OK       {filename}"),
                ManifestEntry::Missing { filename } => {
                    if args.unsigned
                        && release_verifier::manifest::SIGNATURE_FILES.contains(filename)
                    {
                        println!("  ABSENT   {filename}  (OK — unsigned release)");
                    } else {
                        println!("  MISSING  {filename}");
                    }
                }
            }
        }
        for forbidden in &manifest_report.forbidden_present {
            println!("  FORBIDDEN desktop-test-edition artifact present: {forbidden}");
        }
        if manifest_report.is_complete() {
            if args.unsigned {
                println!(
                    "PASS: all {} required release file(s) present (unsigned mode — signature \
                     files not required); no desktop-test-edition artifact found.",
                    release_verifier::manifest::core_required_files().len()
                );
            } else {
                println!(
                    "PASS: all {} required release file(s) present; no desktop-test-edition artifact found.",
                    release_verifier::manifest::REQUIRED_RELEASE_FILES.len()
                );
            }
        } else {
            println!("FAIL: release directory is not a complete, isolated production release.");
            worst_exit = worst_exit.max(4);
        }
    }

    println!();
    println!(
        "NOTE: this tool automates SPEC §10 step 7 (hash comparison) and an optional"
    );
    println!(
        "detached-signature check. It does NOT perform steps 1-4 (cross-channel key"
    );
    println!(
        "verification, second-device check, revocation-list check) or steps 5-9"
    );
    println!(
        "(write/read-back physical media, booted build-identifier confirmation)."
    );
    println!("See VERIFYING-MEDIA.md for the complete ceremony.");

    if worst_exit == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(worst_exit)
    }
}
