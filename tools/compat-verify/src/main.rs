//! `compat-verify` CLI entry point (SPEC_COMPAT §7, §9;
//! IMPLEMENTATION_MAP_COMPAT.md §4 WP-C4). Thin `std::env::args()` parser
//! over `compat_verify`'s library logic -- see `lib.rs` for the actual
//! screens/derivation/vector-generation implementation.
//!
//! ```text
//! compat-verify profiles
//! compat-verify method   --profile <id>
//! compat-verify run      --profile <id> --events <string> [--words 12|24] [--show-entropy]
//! compat-verify vectors  --profile <id> --events <string> [--words 12|24] \
//!                        --name <name> --out <path> [--oracle-kind <kind>] \
//!                        [--ground-truth <tag> ...]
//! ```
//!
//! Exit codes (SPEC_COMPAT §7: a refusal is a correct, expected outcome,
//! not a tool malfunction, so it gets its own distinct code rather than
//! sharing one with a usage error):
//! - `0`: command completed normally (menu/method printed, or a mnemonic
//!   was derived and shown).
//! - `1`: REFUSED -- the device this profile emulates would refuse this
//!   input (SPEC_COMPAT §7, review F1). This is the expected outcome for
//!   an out-of-range `DerivedFromLength` count, not an error.
//! - `2`: BadAlphabet -- an event character outside the profile's alphabet.
//! - `3`: Empty -- no events entered.
//! - `4`: usage error (bad arguments, unknown profile id, I/O failure).

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use compat_verify::derive::{self, EntropyOutcome, Outcome};
use compat_verify::screens;
use compat_verify::{profile, Encoding, WordCount};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut it = args.iter();
    match it.next().map(String::as_str) {
        Some("profiles") => {
            println!("{}", screens::MODE_BANNER);
            println!();
            println!("{}", screens::profile_menu());
            ExitCode::SUCCESS
        }
        Some("method") => run_method(&args[1..]),
        Some("run") => run_derive(&args[1..]),
        Some("vectors") => run_vectors(&args[1..]),
        // Method C — EntropyEncodingRaw (SPEC_COMPAT_ENTROPY.md)
        Some("encodings") => {
            println!("{}", screens::MODE_BANNER);
            println!();
            println!("{}", screens::entropy_encodings_menu());
            ExitCode::SUCCESS
        }
        Some("encoding-method") => run_encoding_method(&args[1..]),
        Some("verify-entropy") => run_verify_entropy(&args[1..]),
        _ => {
            print_usage();
            ExitCode::from(4)
        }
    }
}

fn print_usage() {
    eprintln!("{}", screens::MODE_BANNER);
    eprintln!();
    eprintln!("usage:");
    eprintln!("  compat-verify profiles");
    eprintln!("  compat-verify method  --profile <id>");
    eprintln!("  compat-verify run     --profile <id> --events <string> [--words 12|24] [--show-entropy]");
    eprintln!("  compat-verify vectors --profile <id> --events <string> [--words 12|24] --name <name> --out <path> [--oracle-kind <kind>] [--ground-truth <tag>]...");
    eprintln!();
    eprintln!("  compat-verify encodings");
    eprintln!("  compat-verify encoding-method --encoding <id>");
    eprintln!("  compat-verify verify-entropy  --encoding <id> --input <string> [--show-entropy]");
    eprintln!();
    eprintln!("known profile ids:");
    for id in screens::known_profile_ids() {
        eprintln!("  {id}");
    }
    eprintln!();
    eprintln!("known encoding ids (Method C — EntropyEncodingRaw):");
    for e in Encoding::ALL {
        eprintln!("  {}", e.id());
    }
}

/// Parses `--flag value` pairs (and the bare `--show-entropy` switch) from
/// `args` into a small lookup, plus repeated `--ground-truth` values kept
/// in order. Deliberately hand-rolled (IMPLEMENTATION_MAP_COMPAT.md §1
/// rule 7: no new dependency beyond `seed-core`/`seed-derive` and a
/// minimal arg parser already permitted for tools) -- this tool's flag set
/// is small and fixed, so a dependency buys nothing here.
struct Args {
    profile: Option<String>,
    events: Option<String>,
    words: Option<String>,
    show_entropy: bool,
    name: Option<String>,
    out: Option<String>,
    oracle_kind: Option<String>,
    ground_truth: Vec<String>,
    encoding: Option<String>,
    input: Option<String>,
}

fn parse_args(args: &[String]) -> Args {
    let mut a = Args {
        profile: None,
        events: None,
        words: None,
        show_entropy: false,
        name: None,
        out: None,
        oracle_kind: None,
        ground_truth: Vec::new(),
        encoding: None,
        input: None,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--profile" => {
                a.profile = args.get(i + 1).cloned();
                i += 2;
            }
            "--events" => {
                a.events = args.get(i + 1).cloned();
                i += 2;
            }
            "--words" => {
                a.words = args.get(i + 1).cloned();
                i += 2;
            }
            "--show-entropy" => {
                a.show_entropy = true;
                i += 1;
            }
            "--name" => {
                a.name = args.get(i + 1).cloned();
                i += 2;
            }
            "--out" => {
                a.out = args.get(i + 1).cloned();
                i += 2;
            }
            "--oracle-kind" => {
                a.oracle_kind = args.get(i + 1).cloned();
                i += 2;
            }
            "--ground-truth" => {
                if let Some(v) = args.get(i + 1) {
                    a.ground_truth.push(v.clone());
                }
                i += 2;
            }
            "--encoding" => {
                a.encoding = args.get(i + 1).cloned();
                i += 2;
            }
            "--input" => {
                a.input = args.get(i + 1).cloned();
                i += 2;
            }
            _ => {
                i += 1;
            }
        }
    }
    a
}

fn parse_words(s: &str) -> Option<WordCount> {
    match s {
        "12" => Some(WordCount::W12),
        "24" => Some(WordCount::W24),
        _ => None,
    }
}

fn run_method(raw: &[String]) -> ExitCode {
    let a = parse_args(raw);
    let Some(id) = a.profile else {
        eprintln!("error: --profile <id> is required");
        return ExitCode::from(4);
    };
    let Some(p) = profile(&id) else {
        eprintln!("error: unknown or non-user-facing profile id {id:?}");
        print_usage();
        return ExitCode::from(4);
    };
    println!("{}", screens::MODE_BANNER);
    println!();
    println!("{}", screens::method_screen(p));
    ExitCode::SUCCESS
}

fn run_derive(raw: &[String]) -> ExitCode {
    let a = parse_args(raw);
    let Some(id) = a.profile else {
        eprintln!("error: --profile <id> is required");
        return ExitCode::from(4);
    };
    let Some(p) = profile(&id) else {
        eprintln!("error: unknown or non-user-facing profile id {id:?}");
        print_usage();
        return ExitCode::from(4);
    };
    let Some(events) = a.events else {
        eprintln!("error: --events <string> is required");
        return ExitCode::from(4);
    };
    let requested = match a.words.as_deref() {
        Some(w) => match parse_words(w) {
            Some(wc) => Some(wc),
            None => {
                eprintln!("error: --words must be 12 or 24");
                return ExitCode::from(4);
            }
        },
        None => None,
    };

    match derive::run(p, &events, requested) {
        Outcome::Success(success) => {
            println!("{}", screens::result_screen(&success, &events, a.show_entropy));
            ExitCode::SUCCESS
        }
        Outcome::Refused { entered, .. } => {
            let requested_words = requested.map(|w| match w {
                WordCount::W12 => 12,
                WordCount::W24 => 24,
            });
            println!("{}", screens::MODE_BANNER);
            println!();
            println!("{}", screens::refusal_screen(p, entered, requested_words));
            ExitCode::from(1)
        }
        Outcome::BadAlphabet { at } => {
            eprintln!("REFUSED: event character at position {at} is outside this profile's alphabet.");
            ExitCode::from(2)
        }
        Outcome::Empty => {
            eprintln!("REFUSED: no events entered -- there is nothing to hash.");
            ExitCode::from(3)
        }
    }
}

fn run_vectors(raw: &[String]) -> ExitCode {
    let a = parse_args(raw);
    let (Some(id), Some(events), Some(name), Some(out)) =
        (a.profile.clone(), a.events.clone(), a.name.clone(), a.out.clone())
    else {
        eprintln!("error: vectors mode requires --profile, --events, --name, and --out");
        return ExitCode::from(4);
    };
    let Some(p) = profile(&id) else {
        eprintln!("error: unknown or non-user-facing profile id {id:?}");
        return ExitCode::from(4);
    };
    let requested = match a.words.as_deref() {
        Some(w) => match parse_words(w) {
            Some(wc) => Some(wc),
            None => {
                eprintln!("error: --words must be 12 or 24");
                return ExitCode::from(4);
            }
        },
        None => None,
    };
    let oracle_kind = a.oracle_kind.as_deref().unwrap_or("math_boundary_no_oracle");
    let ground_truth: Vec<&str> = a.ground_truth.iter().map(String::as_str).collect();

    let case_json = match compat_verify::vectors::build_case(&name, p, &events, requested, oracle_kind, &ground_truth) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(4);
        }
    };

    let out_path = PathBuf::from(out);
    if let Err(e) = compat_verify::vectors::write_case_file(&out_path, &case_json) {
        eprintln!("error: could not write {out_path:?}: {e}");
        return ExitCode::from(4);
    }
    println!("wrote {out_path:?}");
    ExitCode::SUCCESS
}

// ---------------------------------------------------------------------------
// Method C — EntropyEncodingRaw (SPEC_COMPAT_ENTROPY.md)
// ---------------------------------------------------------------------------

fn parse_encoding(a: &Args) -> Result<Encoding, ExitCode> {
    let Some(id) = a.encoding.as_deref() else {
        eprintln!("error: --encoding <id> is required");
        print_usage();
        return Err(ExitCode::from(4));
    };
    match Encoding::from_id(id) {
        Some(e) => Ok(e),
        None => {
            eprintln!("error: unknown encoding id {id:?}");
            print_usage();
            Err(ExitCode::from(4))
        }
    }
}

fn run_encoding_method(raw: &[String]) -> ExitCode {
    let a = parse_args(raw);
    let encoding = match parse_encoding(&a) {
        Ok(e) => e,
        Err(code) => return code,
    };
    println!("{}", screens::MODE_BANNER);
    println!();
    println!("{}", screens::entropy_method_screen(encoding));
    ExitCode::SUCCESS
}

fn run_verify_entropy(raw: &[String]) -> ExitCode {
    let a = parse_args(raw);
    let encoding = match parse_encoding(&a) {
        Ok(e) => e,
        Err(code) => return code,
    };
    let Some(input) = a.input else {
        eprintln!("error: --input <string> is required");
        return ExitCode::from(4);
    };

    match derive::run_entropy(encoding, &input) {
        EntropyOutcome::Success(success) => {
            println!("{}", screens::entropy_result_screen(&success, &input, a.show_entropy));
            ExitCode::SUCCESS
        }
        // Every Method-C refusal is a correct, expected outcome (a non-{128,
        // 256}-bit length, no accepted symbols, or oversized input) — never a
        // tool malfunction — so it shares the distinct REFUSED exit code 1
        // with Method A's F1 refusal, and never renders a fabricated phrase
        // (SPEC_COMPAT_ENTROPY §5.5).
        EntropyOutcome::Refused(error) => {
            println!("{}", screens::MODE_BANNER);
            println!();
            println!("{}", screens::entropy_refusal_screen(encoding, error));
            ExitCode::from(1)
        }
    }
}
