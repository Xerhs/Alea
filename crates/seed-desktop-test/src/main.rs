//! `seed-desktop-test` — the in-OS rehearsal/verification build for
//! Windows and Linux (SPEC §4.3). `std`. Owned by WP-28.
//!
//! MUST: run the full UI workflow on public fixed entropy only ([`ceremony`],
//! reusing [`seed_flow`]'s pre-secret flow verbatim and its secret-phase
//! screens where practical — see that module's doc comment), reproduce
//! published deterministic vectors bit-for-bit ([`check`]), display a
//! permanent watermark ([`window`]), and never appear on the production
//! USB image or release archive (this crate is not, and must never
//! become, a dependency of `seed-uefi-production` — verify with
//! `cargo tree -p seed-uefi-production`, which never lists this crate at
//! all, per `ci.sh`).
//!
//! # CLI
//!
//! - `seed-desktop-test` (no arguments): opens the real rehearsal window
//!   ([`window::run`]).
//! - `seed-desktop-test check`: headless vector-reproduction check
//!   ([`check::run`]), no window opened, exits non-zero on any mismatch.

/// Minimal, hand-written reader for the frozen `tests/vectors/` JSON
/// schema, used by both [`check`] (runtime directory walk) and
/// [`fixed_entropy`] (compile-time embedded text).
mod vectors;

/// Runs a parsed vector case through the real Rust pipeline and reports
/// every stage's output for bit-for-bit comparison.
mod pipeline;

/// `check` subcommand: headless, no window, bit-for-bit comparison
/// against every `tests/vectors/frozen/*.json` case (SPEC §4.3, §29.2).
mod check;

/// SPEC §4.3 "public fixed entropy only": the two `include_str!`-embedded
/// frozen vectors this rehearsal's ceremony always (and only) derives
/// from, by word count.
mod fixed_entropy;

/// Structural ("grep-proof") proof that no real-entropy/OS-RNG API
/// surface exists anywhere in this crate's own source.
mod guardrails;

/// Desktop implementations of every `seed-flow` provider trait this
/// rehearsal needs (SPEC §11 gates, machine-availability, watchdog,
/// shutdown, fault hook).
mod providers;

/// The shared pixel-buffer `Framebuffer` + `TextOutput` backend both
/// threads (window thread, ceremony thread) render into / present from.
mod shared_screen;

/// Keyboard-event bridge between the OS window thread and the ceremony
/// worker thread (SPEC §12.3, §17.4, §22.1 smooth key mapping).
mod channel_keys;

/// The rehearsal ceremony itself: `seed_flow::run_pre_secret_flow`
/// verbatim, then a WP-28-owned secret-phase driver reusing every
/// `seed-flow` screen function it can, substituting the fixed public
/// transcript at the one point that must never be real user input.
mod ceremony;

/// The real desktop window (`winit` + `softbuffer`); never reachable from
/// `check` or any `#[cfg(test)]` test (see that module's own doc comment)
/// so this crate builds and tests cleanly with no display server at all.
mod window;

/// The desktop rehearsal edition's landing screen / tools menu
/// (SPEC_MAIN_MENU.md §4, §6.1): "Generate/rehearse", "Cross-device
/// verification", "Learn", "Self-check", "About/audit-status". Not yet
/// wired into `window::run` in place of `ceremony::run` — see
/// `launcher::run`'s own doc comment (WP-M1 owns that swap).
mod launcher;

/// UX-POLISH ergonomics (task brief): what this CLI does with its
/// argument, decided by pure pattern match so it is host-testable without
/// touching `std::process::exit`, a real window, or a real filesystem
/// walk (see [`tests`] below).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Action {
    /// No arguments: open the real rehearsal window.
    OpenWindow,
    /// `check`: headless vector-reproduction check.
    Check,
    /// `--help` / `-h` / `help`: print usage and exit 0.
    Help,
    /// Anything else: not a typo silently launching a GUI window (the
    /// previous behavior) -- report it plainly and exit non-zero instead.
    Unrecognized(String),
}

fn classify(args: &[String]) -> Action {
    match args.get(1).map(String::as_str) {
        None => Action::OpenWindow,
        Some("check") => Action::Check,
        Some("--help" | "-h" | "help") => Action::Help,
        Some(other) => Action::Unrecognized(other.to_string()),
    }
}

const USAGE: &str = "\
Usage:
  seed-desktop-test          Open the rehearsal window (public fixed entropy only, SPEC \u{a7}4.3).
  seed-desktop-test check    Headless: compare this build against every frozen test vector,\n                              exit non-zero on any mismatch.
  seed-desktop-test --help   Show this message.
";

fn main() {
    let args: Vec<String> = std::env::args().collect();

    match classify(&args) {
        Action::Check => {
            let report = check::run(&vectors::frozen_dir());
            check::print_report(&report);
            if !report.all_passed() {
                std::process::exit(1);
            }
        }
        Action::Help => {
            print!("{USAGE}");
        }
        Action::Unrecognized(arg) => {
            eprintln!("seed-desktop-test: unrecognized argument '{arg}'\n");
            eprint!("{USAGE}");
            std::process::exit(2);
        }
        Action::OpenWindow => {
            if let Err(e) = window::run() {
                eprintln!("seed-desktop-test: failed to open the rehearsal window: {e}");
                eprintln!("(this build's headless \"check\" mode does not require a display: run");
                eprintln!(" `seed-desktop-test check` instead if no display is available here.)");
                std::process::exit(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(extra: &[&str]) -> Vec<String> {
        std::iter::once("seed-desktop-test".to_string()).chain(extra.iter().map(|s| s.to_string())).collect()
    }

    #[test]
    fn no_arguments_opens_the_window() {
        assert_eq!(classify(&args(&[])), Action::OpenWindow);
    }

    #[test]
    fn check_argument_runs_the_headless_check() {
        assert_eq!(classify(&args(&["check"])), Action::Check);
    }

    #[test]
    fn help_is_recognized_in_every_spelling() {
        assert_eq!(classify(&args(&["--help"])), Action::Help);
        assert_eq!(classify(&args(&["-h"])), Action::Help);
        assert_eq!(classify(&args(&["help"])), Action::Help);
    }

    /// Ergonomics regression guard: a typo (e.g. "chekc") must be reported
    /// plainly, not silently fall through to opening a GUI window (which
    /// would previously happen -- surprising on a headless host, and
    /// confusing everywhere else).
    #[test]
    fn unrecognized_argument_is_reported_not_silently_treated_as_opening_the_window() {
        assert_eq!(classify(&args(&["chekc"])), Action::Unrecognized("chekc".to_string()));
        assert_ne!(classify(&args(&["chekc"])), Action::OpenWindow);
    }
}
