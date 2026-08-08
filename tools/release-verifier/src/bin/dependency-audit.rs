//! CLI front-end for [`release_verifier::dependency_policy`] (WP-32,
//! SPEC §31).
//!
//! ```text
//! dependency-audit <Cargo.lock> <root Cargo.toml>
//! ```
//!
//! Prints the SPEC §31 mechanical dependency-audit report to stdout and
//! exits nonzero if either check found a violation (unpinned git-sourced
//! package, or a workspace dependency not pinned with `=`).

use release_verifier::dependency_policy::{check_dependency_policy, render_report};
use std::env;
use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: dependency-audit <Cargo.lock> <root Cargo.toml>");
        return ExitCode::from(2);
    }
    let lock_path = &args[1];
    let toml_path = &args[2];

    let lock_contents = match fs::read_to_string(lock_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: reading '{lock_path}': {e}");
            return ExitCode::from(2);
        }
    };
    let toml_contents = match fs::read_to_string(toml_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: reading '{toml_path}': {e}");
            return ExitCode::from(2);
        }
    };

    let report = check_dependency_policy(&lock_contents, &toml_contents);
    print!("{}", render_report(&report));

    if report.is_clean() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
