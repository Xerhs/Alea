//! `seed-compat-vectors` — owned by WP-C3 (SPEC_COMPAT §10, the vector-freeze
//! barrier; IMPLEMENTATION_MAP_COMPAT.md §4 WP-C3).
//!
//! Wires the `tests/vectors/compat/` corpus through the **real** Rust
//! `seed-compat` crate so every candidate/frozen case is proven against the
//! production digest + word-count-rule + refusal logic, and — for `mnemonic`
//! cases — the real `seed-derive` BIP32/address chain:
//!
//! - `seed_compat::compat_derive` — the Method-A digest, `WordCountRule`
//!   application, and F1 refusal behavior (SPEC_COMPAT §5, §6, §12),
//! - `seed_core::bip39::word` — rendered mnemonic words (SPEC §14),
//! - `seed_core::bip39::mnemonic_to_seed` — the 64-byte BIP39 seed (SPEC §14),
//! - `seed_derive::bip32::{master_from_seed, master_fingerprint}` and
//!   `seed_derive::address::first_address` — master fingerprint and all four
//!   first receive addresses (SPEC §24.2–§24.3).
//!
//! Each stage is compared byte-for-byte against the independently generated
//! Python-reference values (SPEC_COMPAT §4.4, WP-C2). This is the Rust ≡
//! Python leg of the §10.2 ground-truth rule; the vendor-oracle leg is a
//! separate WP-C3 gate recorded in `tests/vectors/compat/frozen/FROZEN.md`.
//!
//! Before the WP-C3 freeze barrier, cases are read from
//! `tests/vectors/compat/candidates/`; after, from
//! `tests/vectors/compat/frozen/` (SPEC_COMPAT §10, IMPLEMENTATION_MAP_COMPAT
//! §1.3 rule 3). This crate NEVER mixes the two directories.
//!
//! `seed-uefi-production` MUST NOT depend on this crate (SPEC_COMPAT §9): it
//! is a host-test-only vector consumer.
//!
//! `#![no_std]`: mirrors the `seed-compat` / `seed-test-vectors` discipline
//! (IMPLEMENTATION_MAP_COMPAT.md §1 rule 7). Host tests pull in `std` only
//! under `#[cfg(test)]`.
#![no_std]

/// The exact `schema` field value every compat corpus file must carry
/// (SPEC_COMPAT §10.1); a mismatch is a hard parse failure, never a warning.
pub const SCHEMA_ID: &str = "alea-compat-vectors-v1";

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::SCHEMA_ID;

    use seed_compat::{compat_derive, CompatError, CompatOutput, CompatProfile, WordCount, PROFILES};
    use seed_core::contracts::{AddressBuf, PathStandard, WordCount as CoreWordCount};

    use std::format;
    use std::path::PathBuf;
    use std::string::{String, ToString};
    use std::vec::Vec;

    // ------------------------------------------------------------------
    // Corpus location: frozen corpus once the WP-C3 barrier has passed,
    // candidate corpus before that. Never both, never merged
    // (SPEC_COMPAT §10, IMPLEMENTATION_MAP_COMPAT.md §1.3 rule 3).
    // ------------------------------------------------------------------

    fn corpus_dir() -> PathBuf {
        let root =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/compat");
        let frozen = root.join("frozen");
        if frozen.is_dir() {
            frozen
        } else {
            root.join("candidates")
        }
    }

    // ------------------------------------------------------------------
    // Minimal JSON reader for the fixed SPEC_COMPAT §10.1 schema. No
    // third-party JSON dependency exists in the approved set
    // (IMPLEMENTATION_MAP_COMPAT.md §1 rule 7), and the schema is frozen,
    // so a small recursive parser here is sufficient and reviewable — the
    // same approach `seed-test-vectors` takes. It is strict: any structural
    // surprise panics the test. Unlike the production-corpus parser it also
    // decodes `\uXXXX` / basic escapes, because compat `reason` strings
    // carry em-dashes (`—`); those human-readable fields are parsed but
    // never load-bearing in an assertion.
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
            self.get_opt(key)
                .unwrap_or_else(|| panic!("missing key {key:?}"))
        }

        fn get_opt(&self, key: &str) -> Option<&Json> {
            match self {
                Json::Obj(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
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
                    b'\\' => {
                        assert!(self.pos < self.bytes.len(), "dangling escape");
                        let e = self.bytes[self.pos];
                        self.pos += 1;
                        match e {
                            b'"' => out.push('"'),
                            b'\\' => out.push('\\'),
                            b'/' => out.push('/'),
                            b'n' => out.push('\n'),
                            b't' => out.push('\t'),
                            b'r' => out.push('\r'),
                            b'b' => out.push('\u{0008}'),
                            b'f' => out.push('\u{000C}'),
                            b'u' => {
                                let cp = self.hex4();
                                // The compat corpus uses only BMP escapes
                                // (e.g. em-dash —); surrogate pairs are
                                // not expected and are rejected rather than
                                // mis-decoded.
                                let ch = char::from_u32(cp)
                                    .unwrap_or_else(|| panic!("invalid \\u escape {cp:#06x}"));
                                out.push(ch);
                            }
                            other => panic!("unsupported escape \\{:?}", other as char),
                        }
                    }
                    // Bytes >= 0x80 are raw UTF-8 continuation bytes for a
                    // multibyte char already present in the file; collect
                    // them verbatim and let `String` hold valid UTF-8.
                    _ => out.push(b as char),
                }
            }
            out
        }

        fn hex4(&mut self) -> u32 {
            let mut v = 0u32;
            for _ in 0..4 {
                assert!(self.pos < self.bytes.len(), "truncated \\u escape");
                let b = self.bytes[self.pos];
                self.pos += 1;
                let d = match b {
                    b'0'..=b'9' => (b - b'0') as u32,
                    b'a'..=b'f' => (b - b'a' + 10) as u32,
                    b'A'..=b'F' => (b - b'A' + 10) as u32,
                    other => panic!("bad hex digit in \\u escape: {:?}", other as char),
                };
                v = v * 16 + d;
            }
            v
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
    // Hex helper (SPEC_COMPAT §10: hex is lowercase).
    // ------------------------------------------------------------------

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
    // Profile lookup: unlike the user-facing `seed_compat::profile()`,
    // this consults the full `PROFILES` table directly, because the corpus
    // contains `iancoleman-hex` digest-oracle cases that `profile()`
    // intentionally hides (SPEC_COMPAT §5.1.4).
    // ------------------------------------------------------------------

    fn profile_by_id(id: &str) -> &'static CompatProfile {
        PROFILES
            .iter()
            .find(|p| p.id == id)
            .unwrap_or_else(|| panic!("unknown profile id {id:?} in corpus"))
    }

    fn compat_wc_from_num(n: i64) -> WordCount {
        match n {
            12 => WordCount::W12,
            24 => WordCount::W24,
            other => panic!("unsupported word count {other}"),
        }
    }

    fn core_wc(wc: WordCount) -> CoreWordCount {
        match wc {
            WordCount::W12 => CoreWordCount::Twelve,
            WordCount::W24 => CoreWordCount::TwentyFour,
        }
    }

    fn address_str(buf: &AddressBuf) -> String {
        buf.as_str().expect("address is ASCII").to_string()
    }

    // ------------------------------------------------------------------
    // Corpus loading
    // ------------------------------------------------------------------

    struct Case {
        file: String,
        name: String,
        profile: String,
        events: String,
        expected: String, // "mnemonic" | "refusal"
        requested_word_count: Option<i64>,
        // mnemonic-only fields
        word_count: Option<i64>,
        mnemonic_indexes: Vec<u16>,
        mnemonic_words: Vec<String>,
        bip39_seed_hex: Option<String>,
        master_fingerprint_hex: Option<String>,
        addr_bip44: Option<String>,
        addr_bip49: Option<String>,
        addr_bip84: Option<String>,
        addr_bip86: Option<String>,
        // refusal-only field
        error_kind: Option<String>,
    }

    fn load_corpus() -> Vec<Case> {
        let dir = corpus_dir();
        let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("compat corpus dir {dir:?} unreadable: {e}"))
            .map(|entry| entry.unwrap().path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
            .filter(|p| p.file_name().and_then(|n| n.to_str()) != Some("FROZEN.md"))
            .collect();
        files.sort();
        assert!(!files.is_empty(), "no compat corpus files in {dir:?}");

        let mut cases = Vec::new();
        for path in files {
            let fname = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("?")
                .to_string();
            let ctx = format!("{path:?}");
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("{ctx}: unreadable: {e}"));
            let doc = Parser::parse_document(&text);

            assert_eq!(
                doc.get("schema").str(),
                SCHEMA_ID,
                "{ctx}: bad schema field"
            );

            for case in doc.get("cases").arr() {
                let name = case.get("name").str().to_string();
                let cctx = format!("{ctx} case {name:?}");

                let expected = case.get("expected").str().to_string();
                assert!(
                    expected == "mnemonic" || expected == "refusal",
                    "{cctx}: unknown expected {expected:?}"
                );

                let indexes = case
                    .get_opt("mnemonic_indexes")
                    .map(|a| {
                        a.arr()
                            .iter()
                            .map(|n| {
                                let v = n.num();
                                assert!(
                                    (0..2048).contains(&v),
                                    "{cctx}: index {v} out of range"
                                );
                                v as u16
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                let words = case
                    .get_opt("mnemonic_words")
                    .map(|a| a.arr().iter().map(|w| w.str().to_string()).collect())
                    .unwrap_or_default();

                let addrs = case.get_opt("addresses");

                cases.push(Case {
                    file: fname.clone(),
                    name,
                    profile: case.get("profile").str().to_string(),
                    events: case.get("events").str().to_string(),
                    expected,
                    requested_word_count: case.get_opt("requested_word_count").map(|v| v.num()),
                    word_count: case.get_opt("word_count").map(|v| v.num()),
                    mnemonic_indexes: indexes,
                    mnemonic_words: words,
                    bip39_seed_hex: case
                        .get_opt("bip39_seed_hex")
                        .map(|v| v.str().to_string()),
                    master_fingerprint_hex: case
                        .get_opt("master_fingerprint_hex")
                        .map(|v| v.str().to_string()),
                    addr_bip44: addrs.map(|a| a.get("bip44").str().to_string()),
                    addr_bip49: addrs.map(|a| a.get("bip49").str().to_string()),
                    addr_bip84: addrs.map(|a| a.get("bip84").str().to_string()),
                    addr_bip86: addrs.map(|a| a.get("bip86").str().to_string()),
                    error_kind: case.get_opt("error_kind").map(|v| v.str().to_string()),
                });
            }
        }
        cases
    }

    // ------------------------------------------------------------------
    // The barrier assertions.
    // ------------------------------------------------------------------

    /// Drive one `mnemonic` case through the real Rust `seed-compat` +
    /// `seed-derive` chain and check it reproduces words + seed +
    /// fingerprint + all four addresses (WP-C3 DoD).
    fn run_mnemonic_case(c: &Case) {
        let profile = profile_by_id(&c.profile);
        let requested = c.requested_word_count.map(compat_wc_from_num);

        let out: CompatOutput = compat_derive(profile, &c.events, requested).unwrap_or_else(|e| {
            panic!(
                "{}::{}: expected a mnemonic but compat_derive refused: {:?}",
                c.file, c.name, e
            )
        });

        let want_wc =
            compat_wc_from_num(c.word_count.unwrap_or_else(|| {
                panic!("{}::{}: mnemonic case missing word_count", c.file, c.name)
            }));
        assert_eq!(
            out.word_count, want_wc,
            "{}::{}: word count mismatch",
            c.file, c.name
        );

        let n = match out.word_count {
            WordCount::W12 => 12usize,
            WordCount::W24 => 24usize,
        };

        // 1. indexes
        assert_eq!(
            &out.mnemonic_indexes[..n],
            &c.mnemonic_indexes[..],
            "{}::{}: mnemonic_indexes mismatch",
            c.file,
            c.name
        );

        // 2. rendered words (seed_core::bip39::word, SPEC §14)
        let got_words: Vec<&'static str> = out.mnemonic_indexes[..n]
            .iter()
            .map(|&i| seed_core::bip39::word(i))
            .collect();
        assert_eq!(
            got_words.len(),
            c.mnemonic_words.len(),
            "{}::{}: word-count length mismatch",
            c.file,
            c.name
        );
        for (i, (g, w)) in got_words.iter().zip(c.mnemonic_words.iter()).enumerate() {
            assert_eq!(*g, w.as_str(), "{}::{}: word {i} mismatch", c.file, c.name);
        }

        // 3. 64-byte BIP39 seed (seed_core::bip39::mnemonic_to_seed, SPEC §14)
        let mut seed = [0u8; 64];
        seed_core::bip39::mnemonic_to_seed(&out.mnemonic_indexes, core_wc(out.word_count), &mut seed);
        if let Some(want_seed) = &c.bip39_seed_hex {
            assert_eq!(
                bytes_to_hex(&seed),
                *want_seed,
                "{}::{}: bip39_seed_hex mismatch",
                c.file,
                c.name
            );
        }

        // 4. master fingerprint (seed_derive::bip32, SPEC §24.2)
        let mut key = [0u8; 32];
        let mut cc = [0u8; 32];
        seed_derive::bip32::master_from_seed(&seed, &mut key, &mut cc);
        let fp = seed_derive::bip32::master_fingerprint(&key);
        if let Some(want_fp) = &c.master_fingerprint_hex {
            assert_eq!(
                bytes_to_hex(&fp),
                *want_fp,
                "{}::{}: master_fingerprint_hex mismatch",
                c.file,
                c.name
            );
        }

        // 5. all four first receive addresses (seed_derive::address, SPEC §24.3)
        for (standard, want) in [
            (PathStandard::Bip44, &c.addr_bip44),
            (PathStandard::Bip49, &c.addr_bip49),
            (PathStandard::Bip84, &c.addr_bip84),
            (PathStandard::Bip86, &c.addr_bip86),
        ] {
            if let Some(want) = want {
                let mut buf = AddressBuf::empty();
                seed_derive::address::first_address(&seed, standard, &mut buf).unwrap_or_else(
                    |e| panic!("{}::{}: address {standard:?} derive failed: {e:?}", c.file, c.name),
                );
                assert_eq!(
                    address_str(&buf),
                    *want,
                    "{}::{}: {standard:?} address mismatch",
                    c.file,
                    c.name
                );
            }
        }
    }

    /// Drive one `refusal` case and assert `compat_derive` returns the
    /// matching `Err` variant — never a fabricated phrase (SPEC_COMPAT
    /// review F1, §10.4).
    fn run_refusal_case(c: &Case) {
        let profile = profile_by_id(&c.profile);
        let requested = c.requested_word_count.map(compat_wc_from_num);

        let res = compat_derive(profile, &c.events, requested);
        let err = match res {
            Ok(out) => panic!(
                "{}::{}: expected a REFUSAL but compat_derive produced {} words \
                 (F1 regression: a device-refused input must never render a phrase)",
                c.file,
                c.name,
                match out.word_count {
                    WordCount::W12 => 12,
                    WordCount::W24 => 24,
                }
            ),
            Err(e) => e,
        };

        // If the corpus pins a specific error_kind, the Rust variant must
        // match it exactly; otherwise any Err is accepted.
        if let Some(kind) = &c.error_kind {
            let ok = match kind.as_str() {
                "Empty" => matches!(err, CompatError::Empty),
                "Refused" => matches!(err, CompatError::Refused { .. }),
                "BadAlphabet" => matches!(err, CompatError::BadAlphabet { .. }),
                other => panic!("{}::{}: unknown error_kind {other:?}", c.file, c.name),
            };
            assert!(
                ok,
                "{}::{}: expected error_kind {:?}, got {:?}",
                c.file, c.name, kind, err
            );
        }
    }

    // ------------------------------------------------------------------
    // Tests
    // ------------------------------------------------------------------

    #[test]
    fn corpus_is_non_empty_and_covers_required_shapes() {
        let cases = load_corpus();
        assert!(!cases.is_empty(), "compat corpus is empty");

        let mnemonic = cases.iter().filter(|c| c.expected == "mnemonic").count();
        let refusal = cases.iter().filter(|c| c.expected == "refusal").count();
        assert!(mnemonic > 0, "corpus has no mnemonic cases");
        assert!(refusal > 0, "corpus has no refusal cases");

        // SPEC_COMPAT §10.4: at least one refusal case per DerivedFromLength
        // profile (the F1 regression guard).
        for prof in ["seedsigner-dice", "seedsigner-coin"] {
            let has_refusal = cases
                .iter()
                .any(|c| c.profile == prof && c.expected == "refusal");
            assert!(
                has_refusal,
                "SPEC_COMPAT §10.4: no F1 refusal case for {prof:?}"
            );
        }

        std::eprintln!(
            "seed-compat-vectors: {} case(s) loaded ({} mnemonic, {} refusal) from {:?}",
            cases.len(),
            mnemonic,
            refusal,
            corpus_dir()
        );
    }

    #[test]
    fn every_mnemonic_case_reproduces_words_seed_fingerprint_addresses() {
        let cases = load_corpus();
        let mut ran = 0;
        for c in &cases {
            if c.expected == "mnemonic" {
                run_mnemonic_case(c);
                ran += 1;
            }
        }
        assert!(ran > 0, "no mnemonic cases exercised");
    }

    #[test]
    fn every_refusal_case_returns_err_not_a_phrase() {
        let cases = load_corpus();
        let mut ran = 0;
        for c in &cases {
            if c.expected == "refusal" {
                run_refusal_case(c);
                ran += 1;
            }
        }
        assert!(ran > 0, "no refusal cases exercised");
    }
}
