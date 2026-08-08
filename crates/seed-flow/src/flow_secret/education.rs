//! Completion education screen (SPEC §23.3, `AppState::CompletionEducation`).
//!
//! Shown once re-entry has fully matched and the (optional) derivation
//! verification step has been shown or skipped — the last informational
//! screen before the final scrub-and-shutdown sequence. GOP-only (SPEC
//! §12.2): this state is deep post-secret.
//!
//! [`HEADER`] and [`MATCHED_LINE`] are copied byte-for-byte from SPEC
//! §23.3's blockquote:
//!
//! > **RE-ENTRY MATCHED**
//! > Every word you entered matched the generated mnemonic.
//!
//! and are pinned by an exact-text test. The remaining bullet lines cover
//! every additional point SPEC §23.3 requires the screen to state (not
//! independently verbatim-quoted by the spec, so their exact wording is
//! this crate's own, but a test below asserts each required *topic* is
//! present):
//!
//! - a memorized phrase could pass this check;
//! - the durability and secrecy of the physical backup remain the user's
//!   responsibility;
//! - the user should restore the phrase in the intended signing device
//!   and verify derivation (§24);
//! - receiving addresses should be independently confirmed;
//! - a small test amount should precede substantial funds.
//!
//! SPEC §23.3 also requires the screen NOT claim the application
//! inspected or proved the correctness of the physical backup — no line
//! below makes that claim (re-verified by
//! [`tests::never_claims_backup_was_inspected_or_proved`]).

/// SPEC §23.3, verbatim.
pub const HEADER: &str = "RE-ENTRY MATCHED";
/// SPEC §23.3, verbatim.
pub const MATCHED_LINE: &str = "Every word you entered matched the generated mnemonic.";

pub const REMINDER_LINES: &[&str] = &[
    "A memorized phrase could also pass this check.",
    "The durability and secrecy of your physical backup remain your",
    "responsibility -- this check does not prove it.",
    "",
    "Restore this phrase in your intended signing device and verify",
    "derivation (master fingerprint and addresses) before use.",
    "Independently confirm any receiving address before relying on it.",
    "Send a small test amount before depositing substantial funds.",
];

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    #[test]
    fn header_and_matched_line_are_verbatim() {
        assert_eq!(HEADER, "RE-ENTRY MATCHED");
        assert_eq!(MATCHED_LINE, "Every word you entered matched the generated mnemonic.");
    }

    #[test]
    fn never_claims_backup_was_inspected_or_proved() {
        let forbidden = ["inspected", "proved the", "proves the", "verified your backup"];
        for line in REMINDER_LINES.iter().chain([HEADER, MATCHED_LINE].iter()) {
            let lower = line.to_lowercase();
            for bad in forbidden {
                assert!(!lower.contains(bad), "line {line:?} must not claim inspection/proof of the physical backup");
            }
        }
    }

    #[test]
    fn covers_every_required_topic() {
        let mut all = std::string::String::new();
        for l in REMINDER_LINES {
            all.push_str(l);
            all.push(' ');
        }
        let all = all.to_lowercase();
        assert!(all.contains("memorized"), "must mention a memorized phrase could pass");
        assert!(all.contains("responsibility"), "must mention backup remains user's responsibility");
        assert!(all.contains("signing device") && all.contains("derivation"), "must mention restoring + verifying derivation");
        assert!(all.contains("independently confirm"), "must mention independently confirming addresses");
        assert!(all.contains("small test amount"), "must mention a small test amount first");
    }
}
