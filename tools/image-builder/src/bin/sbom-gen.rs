//! CLI front-end for [`image_builder::sbom::generate_spdx_sbom`] (WP-29,
//! SPEC §31, §32).
//!
//! ```text
//! sbom-gen <Cargo.lock> <SBOM.spdx.json>
//! ```
//!
//! Reads a `Cargo.lock` and writes a deterministic SPDX 2.3 JSON SBOM
//! (the `SBOM.spdx.json` file SPEC §32's release-archive list names).

use image_builder::sbom::{generate_spdx_sbom, SbomOptions};
use std::env;
use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: sbom-gen <Cargo.lock> <SBOM.spdx.json>");
        return ExitCode::from(2);
    }
    let input_path = &args[1];
    let output_path = &args[2];

    let contents = match fs::read_to_string(input_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: reading '{input_path}': {e}");
            return ExitCode::from(2);
        }
    };

    let sbom = match generate_spdx_sbom(&contents, &SbomOptions::default()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: generating SBOM: {e}");
            return ExitCode::from(1);
        }
    };

    if let Err(e) = fs::write(output_path, &sbom) {
        eprintln!("error: writing '{output_path}': {e}");
        return ExitCode::from(1);
    }

    println!("wrote {output_path} ({} bytes)", sbom.len());
    ExitCode::SUCCESS
}
