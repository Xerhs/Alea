//! CLI front-end for the media readback verifier (SPEC §10 steps 6-7).
//!
//! Usage:
//!
//! ```text
//! media-readback-verifier <device-or-file-path> <expected-sha256-hex-or-hashfile>
//! ```
//!
//! Exit codes (clear pass/fail, per work-package requirement):
//! - `0`: hashes match (SPEC §10 step 7 satisfied).
//! - `1`: hashes differ (verification failed — media must not be trusted).
//! - `2`: usage error or I/O failure (could not complete the check at all).

use std::env;
use std::path::Path;
use std::process::ExitCode;

use media_readback_verifier::{resolve_expected_hash, to_hex, verify, VerifyResult};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: media-readback-verifier <device-or-file-path> <expected-sha256-hex-or-hashfile>");
        return ExitCode::from(2);
    }
    let media_path = Path::new(&args[1]);
    let expected = match resolve_expected_hash(&args[2], media_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };

    match verify(media_path, &expected) {
        Ok(VerifyResult::Match) => {
            println!("PASS: read-back hash matches expected {}", to_hex(&expected));
            ExitCode::SUCCESS
        }
        Ok(VerifyResult::Mismatch) => {
            eprintln!("FAIL: read-back hash does not match expected {}", to_hex(&expected));
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}
