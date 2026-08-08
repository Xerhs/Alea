//! Frozen test vectors for Method C — `EntropyEncodingRaw`
//! (SPEC_COMPAT_ENTROPY.md §8), the byte-exact `iancoleman/bip39`
//! raw-entropy reproduction.
//!
//! These freeze all **20** SPEC_COMPAT_ENTROPY §8 vectors across the six
//! encodings (≥3 each) as passing end-to-end tests: each runs the real
//! `compat_verify::derive::run_entropy` pipeline (the byte-exact `eventBits`
//! front end -> the last-32·k-bit leading-discard truncation -> the SAME
//! `seed_core::bip39` conversion production uses) and asserts the retained
//! bit count, the entropy hex, and the reproduced BIP39 mnemonic.
//!
//! **Confidence (SPEC_COMPAT_ENTROPY §8 legend):**
//! - `ANCHORED` (16 vectors): the derived entropy equals a *published*
//!   BIP39/Trezor test-vector entropy (`00…00` -> abandon…about,
//!   `ff…ff` -> zoo…wrong, `7f…7f` -> legal winner…yellow,
//!   `80…80` -> letter advice…above), so BOTH halves (front end + BIP39)
//!   are independently verified. Includes the B4 leading-discard
//!   discriminator (`1` then `0{128}` -> all-zero, NOT `80…00`).
//! - `PROVENANCE_PENDING` (4 vectors: D1, S3, C3 — the `0x5555…55` case
//!   reached three different ways; and C4 — the mixed-width card hand):
//!   **value-confirmed by independent recomputation from the verbatim
//!   iancoleman master source** (`entropy.js`/`index.js`) + the repo's
//!   byte-exact BIP39, and they reproduce exactly. The remaining
//!   live-`iancoleman.io/bip39` run is for **version provenance only**
//!   (pinning a specific deployed build), NOT for discovering or validating
//!   the value (SPEC_COMPAT_ENTROPY §8, Open Question Q1). They are frozen
//!   here and clearly labelled; the byte-exactness claim for them is not yet
//!   backed by a live-tool capture (SPEC_COMPAT_ENTROPY §9).

use std::process::Command;

use compat_verify::derive::{run_entropy, EntropyOutcome};
use compat_verify::Encoding;

#[derive(Clone, Copy)]
enum Conf {
    Anchored,
    ProvenancePending,
}

struct Vector {
    id: &'static str,
    encoding: Encoding,
    /// The typed input string, already expanded (`x{N}` notation resolved).
    input: String,
    retained_bits: u16,
    entropy_hex: &'static str,
    mnemonic: &'static str,
    conf: Conf,
}

fn rep(s: &str, n: usize) -> String {
    s.repeat(n)
}

const ABANDON_ABOUT: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const ZOO_WRONG: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
const LEGAL_WINNER: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";
const LETTER_ADVICE: &str = "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";
const FETCH_PRIMARY: &str = "fetch primary fetch primary fetch primary fetch primary fetch primary fetch problem";
const ABLE_CANOE: &str = "able canoe lunch model census force strong vacuum gown sport remind custom";

const ZERO16: &str = "00000000000000000000000000000000";
const FF16: &str = "ffffffffffffffffffffffffffffffff";

fn vectors() -> Vec<Vector> {
    use Conf::*;
    use Encoding::*;
    vec![
        // ---- 8.1 Binary [0-1] ----
        Vector { id: "B1", encoding: Binary, input: rep("0", 128), retained_bits: 128, entropy_hex: ZERO16, mnemonic: ABANDON_ABOUT, conf: Anchored },
        Vector { id: "B2", encoding: Binary, input: rep("1", 128), retained_bits: 128, entropy_hex: FF16, mnemonic: ZOO_WRONG, conf: Anchored },
        Vector { id: "B3", encoding: Binary, input: rep("0", 130), retained_bits: 128, entropy_hex: ZERO16, mnemonic: ABANDON_ABOUT, conf: Anchored },
        // B4: discriminates leading-vs-trailing discard (§5.5) — trailing
        // discard would give 80…00 -> "length abandon …", not abandon…about.
        Vector { id: "B4", encoding: Binary, input: format!("1{}", rep("0", 128)), retained_bits: 128, entropy_hex: ZERO16, mnemonic: ABANDON_ABOUT, conf: Anchored },

        // ---- 8.2 Hex [0-9A-F] ----
        Vector { id: "H1", encoding: Hex, input: rep("0", 32), retained_bits: 128, entropy_hex: ZERO16, mnemonic: ABANDON_ABOUT, conf: Anchored },
        Vector { id: "H2", encoding: Hex, input: rep("f", 32), retained_bits: 128, entropy_hex: FF16, mnemonic: ZOO_WRONG, conf: Anchored },
        Vector { id: "H3", encoding: Hex, input: rep("7f", 16), retained_bits: 128, entropy_hex: "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", mnemonic: LEGAL_WINNER, conf: Anchored },
        Vector { id: "H4", encoding: Hex, input: rep("80", 16), retained_bits: 128, entropy_hex: "80808080808080808080808080808080", mnemonic: LETTER_ADVICE, conf: Anchored },

        // ---- 8.3 Dice [1-6] (face 6->0, base-6 table) ----
        Vector { id: "D1", encoding: Dice, input: rep("1", 64), retained_bits: 128, entropy_hex: "55555555555555555555555555555555", mnemonic: FETCH_PRIMARY, conf: ProvenancePending },
        Vector { id: "D2", encoding: Dice, input: rep("6", 64), retained_bits: 128, entropy_hex: ZERO16, mnemonic: ABANDON_ABOUT, conf: Anchored },
        Vector { id: "D3", encoding: Dice, input: rep("5", 128), retained_bits: 128, entropy_hex: FF16, mnemonic: ZOO_WRONG, conf: Anchored },

        // ---- 8.4 Base-6 [0-5] (base-6 table, no 6->0) ----
        Vector { id: "S1", encoding: Base6, input: rep("0", 64), retained_bits: 128, entropy_hex: ZERO16, mnemonic: ABANDON_ABOUT, conf: Anchored },
        Vector { id: "S2", encoding: Base6, input: rep("3", 64), retained_bits: 128, entropy_hex: FF16, mnemonic: ZOO_WRONG, conf: Anchored },
        Vector { id: "S3", encoding: Base6, input: rep("1", 64), retained_bits: 128, entropy_hex: "55555555555555555555555555555555", mnemonic: FETCH_PRIMARY, conf: ProvenancePending },

        // ---- 8.5 Base-10 [0-9] ----
        Vector { id: "T1", encoding: Base10, input: rep("8", 128), retained_bits: 128, entropy_hex: ZERO16, mnemonic: ABANDON_ABOUT, conf: Anchored },
        Vector { id: "T2", encoding: Base10, input: rep("9", 128), retained_bits: 128, entropy_hex: FF16, mnemonic: ZOO_WRONG, conf: Anchored },
        // T3: 43 zeros -> "000" each = 129 bits -> retained 128 (1 leading dropped).
        Vector { id: "T3", encoding: Base10, input: rep("0", 43), retained_bits: 128, entropy_hex: ZERO16, mnemonic: ABANDON_ABOUT, conf: Anchored },

        // ---- 8.6 Cards [A2-9TJQK][CDHS] ----
        Vector { id: "C1", encoding: Cards, input: rep("KS", 64), retained_bits: 128, entropy_hex: FF16, mnemonic: ZOO_WRONG, conf: Anchored },
        Vector { id: "C2", encoding: Cards, input: rep("TS", 64), retained_bits: 128, entropy_hex: ZERO16, mnemonic: ABANDON_ABOUT, conf: Anchored },
        Vector { id: "C3", encoding: Cards, input: rep("JS", 64), retained_bits: 128, entropy_hex: "55555555555555555555555555555555", mnemonic: FETCH_PRIMARY, conf: ProvenancePending },
        // C4: 24 five-bit cards (120 bits) + 4 two-bit cards (8 bits) = 128 bits.
        Vector { id: "C4", encoding: Cards, input: "AC 2C 3C 4C 5C 6C 7C 8C 9C TC JC QC KC AD 2D 3D 4D 5D 6D 7D 8D 9D TD JD TS JS QS KS".to_string(), retained_bits: 128, entropy_hex: "00443214c74254b635cf84653a56d71b", mnemonic: ABLE_CANOE, conf: ProvenancePending },
    ]
}

/// Every §8 vector reproduced end-to-end through the real Method-C pipeline.
#[test]
fn frozen_entropy_vectors_reproduce_byte_exact() {
    let vectors = vectors();
    // SPEC_COMPAT_ENTROPY §8's summary prose says "20 vectors / 16 ANCHORED",
    // but its §8.1–§8.6 tables actually ENUMERATE 21 rows (B1-4, H1-4, D1-3,
    // S1-3, T1-3, C1-4) of which 17 are anchored and 4 are provenance-pending
    // (D1, S3, C3, C4). That is an off-by-one in the summary line, not the
    // tables. We freeze every enumerated row — dropping one to match the
    // summary count would leave a real published-vector-anchored case
    // unfrozen — so the counts below are 21 / 17 / 4.
    assert_eq!(vectors.len(), 21, "every enumerated SPEC_COMPAT_ENTROPY §8 table row is frozen");

    let mut anchored = 0usize;
    let mut pending = 0usize;

    for v in &vectors {
        match v.conf {
            Conf::Anchored => anchored += 1,
            Conf::ProvenancePending => pending += 1,
        }

        let success = match run_entropy(v.encoding, &v.input) {
            EntropyOutcome::Success(s) => s,
            EntropyOutcome::Refused(e) => {
                panic!("vector {}: expected a mnemonic, got refusal {e:?}", v.id)
            }
        };

        assert_eq!(success.retained_bits, v.retained_bits, "vector {}: retained bits", v.id);
        assert_eq!(success.entropy_hex(), v.entropy_hex, "vector {}: entropy hex", v.id);

        let got: Vec<&str> = success.words_slice().to_vec();
        let want: Vec<&str> = v.mnemonic.split(' ').collect();
        assert_eq!(got, want, "vector {}: mnemonic mismatch", v.id);
    }

    assert_eq!(anchored, 17, "17 enumerated vectors are ANCHORED to published BIP39/Trezor vectors");
    assert_eq!(pending, 4, "4 vectors are PROVENANCE_PENDING (value-confirmed by recomputation)");
}

/// The three distinct encodings (Dice D1, Base-6 S3, Cards C3) that each
/// reach `0x5555…55` must all reproduce the identical entropy and mnemonic —
/// the mutual-consistency cross-check SPEC_COMPAT_ENTROPY §8 relies on.
#[test]
fn the_5555_case_agrees_across_three_encodings() {
    let inputs = [
        (Encoding::Dice, "1".repeat(64)),
        (Encoding::Base6, "1".repeat(64)),
        (Encoding::Cards, "JS".repeat(64)),
    ];
    for (enc, input) in inputs {
        let s = match run_entropy(enc, &input) {
            EntropyOutcome::Success(s) => s,
            EntropyOutcome::Refused(e) => panic!("{enc:?}: unexpected refusal {e:?}"),
        };
        assert_eq!(s.entropy_hex(), "55555555555555555555555555555555");
        assert_eq!(s.words_slice()[0], "fetch");
        assert_eq!(s.words_slice()[11], "problem");
    }
}

/// A scripted run of the actual compiled `compat-verify` binary reproduces
/// an anchored vector (H3, the published Trezor `legal winner…` vector),
/// carries the permanent watermark, and does NOT leak entropy hex without
/// `--show-entropy` (review F7).
#[test]
fn scripted_binary_reproduces_anchored_h3_vector() {
    let bin = env!("CARGO_BIN_EXE_compat-verify");
    let input = "7f".repeat(16);
    let output = Command::new(bin)
        .args(["verify-entropy", "--encoding", "hex", "--input", &input])
        .output()
        .expect("failed to run compat-verify binary");

    assert!(output.status.success(), "verify-entropy exited non-zero: {:?}", output.status.code());
    let stdout = String::from_utf8_lossy(&output.stdout);

    for word in "legal winner thank year wave sausage worth useful legal winner thank yellow".split(' ') {
        assert!(stdout.contains(word), "stdout missing word {word:?}:\n{stdout}");
    }
    assert!(
        stdout.contains("[COMPATIBILITY / VERIFICATION — NOT AN ALEA SEED — PUBLIC/THROWAWAY]"),
        "stdout missing permanent watermark:\n{stdout}"
    );
    assert!(
        stdout.contains("never to CREATE one you will fund"),
        "stdout missing the honesty caveat:\n{stdout}"
    );
    // Entropy hex must NOT appear by default (review F7).
    assert!(!stdout.contains("Entropy hex ("), "entropy hex leaked without --show-entropy:\n{stdout}");
}

/// A scripted run refuses a non-standard (160-bit / 15-word) length with the
/// distinct REFUSED exit code, NAMES iancoleman's divergence, and never
/// renders a mnemonic (SPEC_COMPAT_ENTROPY §5.5).
#[test]
fn scripted_binary_refuses_nonstandard_length_naming_divergence() {
    let bin = env!("CARGO_BIN_EXE_compat-verify");
    let input = "1".repeat(160);
    let output = Command::new(bin)
        .args(["verify-entropy", "--encoding", "binary", "--input", &input])
        .output()
        .expect("failed to run compat-verify binary");

    assert_eq!(output.status.code(), Some(1), "expected exit code 1 (Refused) for a 160-bit length");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("REFUSED"), "stdout missing REFUSED:\n{stdout}");
    assert!(stdout.contains("15-word"), "refusal must name iancoleman's 15-word divergence:\n{stdout}");
    assert!(stdout.contains("160 retained bits"), "refusal must show the retained-bit count:\n{stdout}");
    // No BIP39 word should ever appear on a refusal screen.
    assert!(!stdout.contains("abandon"), "a mnemonic word leaked into a refusal screen:\n{stdout}");
}
