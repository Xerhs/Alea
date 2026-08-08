//! `seed-test-vectors` — owned by WP-16 (SPEC §29.2).
//!
//! Wires the golden `tests/vectors/` corpus (schema in
//! `tests/vectors/SCHEMA.md`) through the real Rust pipeline so every
//! downstream crate consumes the same frozen files. Before the WP-16
//! golden-vector-freeze barrier, vectors are "candidate"
//! (`tests/vectors/candidates/`); after, they are law
//! (`tests/vectors/frozen/`, `AGENTS.md` §1 rule 3).
//!
//! The host `#[cfg(test)]` suite in this crate runs every corpus case
//! end-to-end through the production code paths (SPEC §29.2):
//!
//! - `seed_protocol::transcript::TranscriptBuilder` — canonical
//!   transcript bytes (SPEC §19.2),
//! - `seed_core::pipeline::derive_final_entropy` — final entropy +
//!   mnemonic indexes (SPEC §19.3, §14),
//! - `seed_core::bip39::word` — rendered mnemonic words (SPEC §14),
//! - `seed_core::pipeline::compute_verification_values` backed by
//!   `seed_derive::{bip32, address}` — BIP39 seed, master fingerprint
//!   and all four first addresses (SPEC §24.2–§24.3),
//!
//! and compares each stage byte-for-byte against the independently
//! generated Python-reference values (SPEC §4.4, WP-11).
//!
//! `seed-uefi-production` MUST NOT depend on this crate (SPEC §9, §28).
//!
//! `#![no_std]`: this crate is linked into the `seed-uefi-test` UEFI
//! binary (which has no `std`), not just run in host `cargo test`. Host
//! tests pull in `std` under `#[cfg(test)]` per `AGENTS.md`.
#![no_std]

/// The exact `schema` field value every corpus file must carry
/// (`tests/vectors/SCHEMA.md`); a mismatch is a hard parse failure for
/// every consumer, never a warning.
pub const SCHEMA_ID: &str = "alea-vectors-v1";

// ============================================================================
// Adapters: the frozen contract shapes in `seed-core::pipeline` are traits
// (`TranscriptSink`, `KeyDeriver`) precisely so `seed-protocol` /
// `seed-derive` implementations can be slotted in by a crate that sees all
// three (WP-15's crate-boundary design note). This is that crate.
// ============================================================================

use seed_core::contracts::{
    AddressBuf, ArchId, DeriveError, PathStandard, SourceTag, TargetBits,
};
use seed_core::pipeline::{KeyDeriver, TranscriptSink};
use seed_protocol::transcript::{TranscriptBuilder, TranscriptError};

/// Newtype wiring the real WP-08 [`TranscriptBuilder`] into the WP-15
/// pipeline facade's [`TranscriptSink`] slot (orphan rule: foreign trait,
/// foreign type — so the impl lives on this local wrapper).
pub struct RealTranscript(pub TranscriptBuilder);

impl RealTranscript {
    /// Fresh empty transcript sink.
    pub fn new() -> Self {
        RealTranscript(TranscriptBuilder::new())
    }
}

impl Default for RealTranscript {
    fn default() -> Self {
        Self::new()
    }
}

impl TranscriptSink for RealTranscript {
    type Error = TranscriptError;

    fn add_source(
        &mut self,
        tag: SourceTag,
        algo_id: &[u8],
        bytes: &[u8],
    ) -> Result<(), Self::Error> {
        self.0.add_source(tag, algo_id, bytes)
    }

    fn finalize(self, arch: ArchId, bits: TargetBits, policy_ver: u16, out: &mut [u8; 32]) {
        self.0.finalize(arch, bits, policy_ver, out)
    }
}

/// Marker type wiring the real WP-13/WP-14 free functions
/// (`seed_derive::bip32`, `seed_derive::address`) into the WP-15 pipeline
/// facade's [`KeyDeriver`] slot.
pub struct RealDeriver;

impl KeyDeriver for RealDeriver {
    fn master_from_seed(seed: &[u8; 64], key_out: &mut [u8; 32], cc_out: &mut [u8; 32]) {
        seed_derive::bip32::master_from_seed(seed, key_out, cc_out)
    }

    fn master_fingerprint(key: &[u8; 32]) -> [u8; 4] {
        seed_derive::bip32::master_fingerprint(key)
    }

    fn first_address(
        seed: &[u8; 64],
        standard: PathStandard,
        out: &mut AddressBuf,
    ) -> Result<(), DeriveError> {
        seed_derive::address::first_address(seed, standard, out)
    }

    fn grid_address(
        seed: &[u8; 64],
        standard: PathStandard,
        account: u32,
        change: u32,
        index: u32,
        out: &mut AddressBuf,
    ) -> Result<(), DeriveError> {
        let path = seed_derive::bip32::preset_path(standard, account, change, index);
        let script_type = seed_derive::address::ScriptType::for_standard(standard);
        seed_derive::address::address_at(seed, script_type, &path, out)
    }
}

// ============================================================================
// Host test suite: run every corpus case through the real pipeline and
// compare byte-for-byte with the Python-reference values (SPEC §29.2).
// ============================================================================

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use seed_core::arena::SecretArena;
    use seed_core::bip39;
    use seed_core::contracts::{WordCount, TRANSCRIPT_CAPACITY};
    use seed_core::pipeline::{compute_verification_values, derive_final_entropy};
    use std::format;
    use std::path::PathBuf;
    use std::string::{String, ToString};
    use std::vec::Vec;

    // ------------------------------------------------------------------
    // Corpus location: frozen corpus once the WP-16 barrier has passed,
    // candidate corpus before that. Never both, never merged.
    // ------------------------------------------------------------------

    fn corpus_dir() -> PathBuf {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors");
        let frozen = root.join("frozen");
        if frozen.is_dir() {
            frozen
        } else {
            root.join("candidates")
        }
    }

    // ------------------------------------------------------------------
    // Minimal JSON reader for the fixed `tests/vectors/SCHEMA.md` shape.
    // No third-party JSON dependency exists in the approved set
    // (IMPLEMENTATION_MAP.md §3), and the schema is frozen, so a small
    // recursive parser here is both sufficient and reviewable. It is
    // strict: any structural surprise panics the test (SCHEMA.md rule 4:
    // hard error, never silently skipped).
    // ------------------------------------------------------------------

    #[derive(Debug, Clone, PartialEq)]
    enum Json {
        Obj(Vec<(String, Json)>),
        Arr(Vec<Json>),
        Str(String),
        Num(i64),
    }

    impl Json {
        fn get(&self, key: &str) -> &Json {
            match self {
                Json::Obj(pairs) => pairs
                    .iter()
                    .find(|(k, _)| k == key)
                    .map(|(_, v)| v)
                    .unwrap_or_else(|| panic!("missing key {key:?}")),
                other => panic!("expected object for key {key:?}, got {other:?}"),
            }
        }

        fn str(&self) -> &str {
            match self {
                Json::Str(s) => s,
                other => panic!("expected string, got {other:?}"),
            }
        }

        fn num(&self) -> i64 {
            match self {
                Json::Num(n) => *n,
                other => panic!("expected number, got {other:?}"),
            }
        }

        fn arr(&self) -> &[Json] {
            match self {
                Json::Arr(items) => items,
                other => panic!("expected array, got {other:?}"),
            }
        }
    }

    struct Parser<'a> {
        bytes: &'a [u8],
        pos: usize,
    }

    impl<'a> Parser<'a> {
        fn new(text: &'a str) -> Self {
            Parser { bytes: text.as_bytes(), pos: 0 }
        }

        fn skip_ws(&mut self) {
            while self.pos < self.bytes.len()
                && matches!(self.bytes[self.pos], b' ' | b'\t' | b'\n' | b'\r')
            {
                self.pos += 1;
            }
        }

        fn peek(&mut self) -> u8 {
            self.skip_ws();
            assert!(self.pos < self.bytes.len(), "unexpected end of JSON");
            self.bytes[self.pos]
        }

        fn expect(&mut self, b: u8) {
            let got = self.peek();
            assert_eq!(got, b, "expected {:?}, got {:?}", b as char, got as char);
            self.pos += 1;
        }

        fn value(&mut self) -> Json {
            match self.peek() {
                b'{' => self.object(),
                b'[' => self.array(),
                b'"' => Json::Str(self.string()),
                b'-' | b'0'..=b'9' => self.number(),
                other => panic!("unexpected JSON byte {:?}", other as char),
            }
        }

        fn object(&mut self) -> Json {
            self.expect(b'{');
            let mut pairs = Vec::new();
            if self.peek() == b'}' {
                self.pos += 1;
                return Json::Obj(pairs);
            }
            loop {
                let key = {
                    assert_eq!(self.peek(), b'"', "object key must be a string");
                    self.string()
                };
                self.expect(b':');
                let val = self.value();
                pairs.push((key, val));
                match self.peek() {
                    b',' => self.pos += 1,
                    b'}' => {
                        self.pos += 1;
                        break;
                    }
                    other => panic!("expected ',' or '}}', got {:?}", other as char),
                }
            }
            Json::Obj(pairs)
        }

        fn array(&mut self) -> Json {
            self.expect(b'[');
            let mut items = Vec::new();
            if self.peek() == b']' {
                self.pos += 1;
                return Json::Arr(items);
            }
            loop {
                items.push(self.value());
                match self.peek() {
                    b',' => self.pos += 1,
                    b']' => {
                        self.pos += 1;
                        break;
                    }
                    other => panic!("expected ',' or ']', got {:?}", other as char),
                }
            }
            Json::Arr(items)
        }

        fn string(&mut self) -> String {
            self.expect(b'"');
            let mut out = String::new();
            loop {
                assert!(self.pos < self.bytes.len(), "unterminated string");
                let b = self.bytes[self.pos];
                self.pos += 1;
                match b {
                    b'"' => break,
                    // The frozen corpus (names, hex, BIP39 words,
                    // addresses) is plain ASCII with no escapes; reject
                    // rather than mis-decode anything fancier.
                    b'\\' => panic!("unexpected escape in corpus string"),
                    _ => out.push(b as char),
                }
            }
            out
        }

        fn number(&mut self) -> Json {
            self.skip_ws();
            let start = self.pos;
            if self.bytes[self.pos] == b'-' {
                self.pos += 1;
            }
            while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_digit() {
                self.pos += 1;
            }
            let text = core::str::from_utf8(&self.bytes[start..self.pos]).unwrap();
            Json::Num(text.parse::<i64>().expect("integer"))
        }

        fn parse_document(text: &'a str) -> Json {
            let mut p = Parser::new(text);
            let v = p.value();
            p.skip_ws();
            assert_eq!(p.pos, p.bytes.len(), "trailing bytes after JSON document");
            v
        }
    }

    // ------------------------------------------------------------------
    // Hex helpers (SCHEMA.md rule 1: all hex is lowercase — enforced).
    // ------------------------------------------------------------------

    fn hex_to_bytes(hex: &str, context: &str) -> Vec<u8> {
        assert!(hex.len() % 2 == 0, "{context}: odd-length hex");
        assert!(
            hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "{context}: non-lowercase or non-hex digit in {hex:?}"
        );
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn bytes_to_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 0x0f) as usize] as char);
        }
        s
    }

    // ------------------------------------------------------------------
    // Schema field mappings
    // ------------------------------------------------------------------

    fn tag_from_str(tag: &str, context: &str) -> SourceTag {
        match tag {
            "0x01" => SourceTag::ApprovedEfiRng,
            "0x02" => SourceTag::X86Rdseed64,
            "0x03" => SourceTag::X86RdrandSupplementary,
            "0x10" => SourceTag::DiceRolls,
            "0x11" => SourceTag::CoinFlips,
            other => panic!("{context}: unknown source tag {other:?}"),
        }
    }

    fn arch_from_str(arch: &str, context: &str) -> ArchId {
        match arch {
            "x86_64" => ArchId::X86_64,
            other => panic!("{context}: unknown arch {other:?}"),
        }
    }

    fn bits_from_num(bits: i64, context: &str) -> TargetBits {
        match bits {
            128 => TargetBits::Bits128,
            256 => TargetBits::Bits256,
            other => panic!("{context}: unsupported bits {other}"),
        }
    }

    // ------------------------------------------------------------------
    // One fully decoded corpus case
    // ------------------------------------------------------------------

    struct CaseSource {
        tag: SourceTag,
        algo: Vec<u8>,
        bytes: Vec<u8>,
    }

    struct Case {
        name: String,
        sources: Vec<CaseSource>,
        arch: ArchId,
        bits: TargetBits,
        policy_version: u16,
        transcript: Vec<u8>,
        final_entropy: Vec<u8>,
        mnemonic_indexes: Vec<u16>,
        mnemonic_words: Vec<String>,
        bip39_seed: Vec<u8>,
        master_fingerprint: Vec<u8>,
        addr_bip44: String,
        addr_bip49: String,
        addr_bip84: String,
        addr_bip86: String,
    }

    fn load_corpus() -> Vec<Case> {
        let dir = corpus_dir();
        let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("corpus dir {dir:?} unreadable: {e}"))
            .map(|entry| entry.unwrap().path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
            .collect();
        files.sort();
        assert!(!files.is_empty(), "no corpus files in {dir:?}");

        let mut cases = Vec::new();
        for path in files {
            let ctx = format!("{path:?}");
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("{ctx}: unreadable: {e}"));
            let doc = Parser::parse_document(&text);

            // SCHEMA.md rule 4: schema mismatch is a hard failure.
            assert_eq!(doc.get("schema").str(), SCHEMA_ID, "{ctx}: bad schema field");

            for case in doc.get("cases").arr() {
                let name = case.get("name").str().to_string();
                let cctx = format!("{ctx} case {name:?}");

                let sources = case
                    .get("sources")
                    .arr()
                    .iter()
                    .map(|s| CaseSource {
                        tag: tag_from_str(s.get("tag").str(), &cctx),
                        algo: s.get("algo").str().as_bytes().to_vec(),
                        bytes: hex_to_bytes(s.get("bytes_hex").str(), &cctx),
                    })
                    .collect();

                cases.push(Case {
                    arch: arch_from_str(case.get("arch").str(), &cctx),
                    bits: bits_from_num(case.get("bits").num(), &cctx),
                    policy_version: u16::try_from(case.get("policy_version").num())
                        .unwrap_or_else(|_| panic!("{cctx}: policy_version out of range")),
                    transcript: hex_to_bytes(case.get("transcript_hex").str(), &cctx),
                    final_entropy: hex_to_bytes(case.get("final_entropy_hex").str(), &cctx),
                    mnemonic_indexes: case
                        .get("mnemonic_indexes")
                        .arr()
                        .iter()
                        .map(|n| {
                            let v = n.num();
                            assert!((0..2048).contains(&v), "{cctx}: index {v} out of range");
                            v as u16
                        })
                        .collect(),
                    mnemonic_words: case
                        .get("mnemonic_words")
                        .arr()
                        .iter()
                        .map(|w| w.str().to_string())
                        .collect(),
                    bip39_seed: hex_to_bytes(case.get("bip39_seed_hex").str(), &cctx),
                    master_fingerprint: hex_to_bytes(
                        case.get("master_fingerprint_hex").str(),
                        &cctx,
                    ),
                    addr_bip44: case.get("addresses").get("bip44").str().to_string(),
                    addr_bip49: case.get("addresses").get("bip49").str().to_string(),
                    addr_bip84: case.get("addresses").get("bip84").str().to_string(),
                    addr_bip86: case.get("addresses").get("bip86").str().to_string(),
                    sources,
                    name,
                });
            }
        }
        cases
    }

    // ------------------------------------------------------------------
    // Corpus shape checks (WP-16 DoD: >= 20 cases spanning the required
    // classes; unique names)
    // ------------------------------------------------------------------

    #[test]
    fn corpus_has_at_least_20_cases_with_unique_names_and_required_classes() {
        let cases = load_corpus();
        assert!(cases.len() >= 20, "need >= 20 cases, found {}", cases.len());

        let mut names: Vec<&str> = cases.iter().map(|c| c.name.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), cases.len(), "duplicate case names");

        let has = |f: &dyn Fn(&Case) -> bool| cases.iter().any(|c| f(c));
        let machine_tags = [
            SourceTag::ApprovedEfiRng,
            SourceTag::X86Rdseed64,
            SourceTag::X86RdrandSupplementary,
        ];

        // dice-only, both word counts
        for bits in [TargetBits::Bits128, TargetBits::Bits256] {
            assert!(
                has(&|c| c.bits == bits
                    && c.sources.len() == 1
                    && c.sources[0].tag == SourceTag::DiceRolls),
                "missing dice-only case for {bits:?}"
            );
            assert!(
                has(&|c| c.bits == bits
                    && c.sources.len() == 1
                    && c.sources[0].tag == SourceTag::CoinFlips),
                "missing coins-only case for {bits:?}"
            );
            assert!(
                has(&|c| c.bits == bits
                    && c.sources.iter().any(|s| s.tag == SourceTag::DiceRolls)
                    && c.sources.iter().any(|s| s.tag == SourceTag::CoinFlips)),
                "missing mixed dice+coin case for {bits:?}"
            );
        }
        // machine-tagged sources appear
        for tag in machine_tags {
            assert!(
                has(&|c| c.sources.iter().any(|s| s.tag == tag)),
                "missing machine-tagged case for {tag:?}"
            );
        }
        // budget edges (SPEC §17.2: 50/100 dice, 128/256 flips minimums)
        assert!(
            has(&|c| c.sources.len() == 1
                && c.sources[0].tag == SourceTag::DiceRolls
                && c.bits == TargetBits::Bits128
                && c.sources[0].bytes.len() == 50),
            "missing dice min-budget edge (50 rolls @128)"
        );
        assert!(
            has(&|c| c.sources.len() == 1
                && c.sources[0].tag == SourceTag::CoinFlips
                && c.bits == TargetBits::Bits256
                && c.sources[0].bytes.len() == 256),
            "missing coin min-budget edge (256 flips @256)"
        );
    }

    // ------------------------------------------------------------------
    // The cross-implementation test itself (SPEC §29.2): every case,
    // every stage, byte-for-byte.
    // ------------------------------------------------------------------

    #[test]
    fn every_corpus_case_reproduces_bit_for_bit_through_the_rust_pipeline() {
        let cases = load_corpus();
        assert!(!cases.is_empty());

        for case in &cases {
            let name = &case.name;

            // --- Stage 0: canonical transcript bytes (SPEC §19.2) ---
            let mut builder = TranscriptBuilder::new();
            for s in &case.sources {
                builder
                    .add_source(s.tag, &s.algo, &s.bytes)
                    .unwrap_or_else(|e| panic!("{name}: add_source failed: {e:?}"));
            }
            let mut wire = [0u8; TRANSCRIPT_CAPACITY];
            let wire_len = builder.serialize(case.arch, case.bits, case.policy_version, &mut wire);
            assert_eq!(
                bytes_to_hex(&wire[..wire_len]),
                bytes_to_hex(&case.transcript),
                "{name}: transcript bytes mismatch"
            );

            // --- Stage 1: sources -> final entropy -> mnemonic indexes ---
            // Rebuilt through the pipeline facade with a fresh sink (the
            // serialize-only builder above is separate on purpose:
            // `finalize` consumes and scrubs).
            let source_inputs: Vec<seed_core::pipeline::SourceInput<'_>> = case
                .sources
                .iter()
                .map(|s| seed_core::pipeline::SourceInput {
                    tag: s.tag,
                    algo_id: &s.algo,
                    bytes: &s.bytes,
                })
                .collect();

            let mut arena = SecretArena::new();
            let word_count = derive_final_entropy(
                &mut arena,
                RealTranscript::new(),
                &source_inputs,
                case.arch,
                case.bits,
                case.policy_version,
            )
            .unwrap_or_else(|e| panic!("{name}: derive_final_entropy failed: {e:?}"));

            let expected_count = match case.bits {
                TargetBits::Bits128 => WordCount::Twelve,
                TargetBits::Bits256 => WordCount::TwentyFour,
            };
            assert_eq!(word_count, expected_count, "{name}: word count mismatch");

            let entropy_len = case.final_entropy.len();
            assert_eq!(
                entropy_len,
                match case.bits {
                    TargetBits::Bits128 => 16,
                    TargetBits::Bits256 => 32,
                },
                "{name}: final_entropy_hex length inconsistent with bits"
            );
            assert_eq!(
                bytes_to_hex(&arena.final_entropy()[..entropy_len]),
                bytes_to_hex(&case.final_entropy),
                "{name}: final entropy mismatch"
            );

            // --- Mnemonic indexes and words (SPEC §14) ---
            let n_words = expected_count as usize;
            assert_eq!(case.mnemonic_indexes.len(), n_words, "{name}: index count");
            assert_eq!(case.mnemonic_words.len(), n_words, "{name}: word count field");
            let got_indexes: Vec<u16> = arena.mnemonic_indexes()[..n_words].to_vec();
            assert_eq!(got_indexes, case.mnemonic_indexes, "{name}: mnemonic indexes mismatch");
            for (i, (&idx, expected_word)) in
                got_indexes.iter().zip(case.mnemonic_words.iter()).enumerate()
            {
                assert_eq!(
                    bip39::word(idx),
                    expected_word.as_str(),
                    "{name}: mnemonic word {i} mismatch"
                );
            }

            // --- Stage 2: seed, fingerprint, four addresses (SPEC §24) ---
            let values = compute_verification_values::<RealDeriver>(&mut arena, word_count)
                .unwrap_or_else(|e| panic!("{name}: compute_verification_values failed: {e:?}"));

            assert_eq!(
                bytes_to_hex(arena.bip39_seed()),
                bytes_to_hex(&case.bip39_seed),
                "{name}: bip39 seed mismatch"
            );
            assert_eq!(
                bytes_to_hex(&values.master_fingerprint),
                bytes_to_hex(&case.master_fingerprint),
                "{name}: master fingerprint mismatch"
            );

            let expected_addresses = [
                (PathStandard::Bip44, case.addr_bip44.as_str()),
                (PathStandard::Bip49, case.addr_bip49.as_str()),
                (PathStandard::Bip84, case.addr_bip84.as_str()),
                (PathStandard::Bip86, case.addr_bip86.as_str()),
            ];
            for (slot, (standard, expected)) in
                values.addresses.iter().zip(expected_addresses.iter())
            {
                assert_eq!(slot.standard, *standard, "{name}: address standard order");
                let got = slot.address.as_str()
                    .unwrap_or_else(|| panic!("{name}: non-UTF8 address for {standard:?}"));
                assert_eq!(got, *expected, "{name}: {standard:?} address mismatch");
            }
        }
    }
}
