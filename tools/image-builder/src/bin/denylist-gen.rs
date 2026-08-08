//! CLI front-end for [`image_builder::denylist::generate_denylist_txt`]
//! (WP-29, SPEC §15, §31, §32).
//!
//! ```text
//! denylist-gen <entropy-policy.toml> <DENYLIST.txt>
//! ```

use image_builder::denylist::generate_denylist_txt;
use std::env;
use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: denylist-gen <entropy-policy.toml> <DENYLIST.txt>");
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

    let txt = match generate_denylist_txt(&contents) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: generating DENYLIST.txt: {e}");
            return ExitCode::from(1);
        }
    };

    if let Err(e) = fs::write(output_path, &txt) {
        eprintln!("error: writing '{output_path}': {e}");
        return ExitCode::from(1);
    }

    println!("wrote {output_path} ({} bytes)", txt.len());
    ExitCode::SUCCESS
}
