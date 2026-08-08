//! Minimal reader for the frozen `tests/vectors/` JSON schema
//! (`tests/vectors/SCHEMA.md`, owned by WP-16; SPEC §29.2, §4.3).
//!
//! This is deliberately a small, dependency-free, hand-written parser
//! (mirroring the private `#[cfg(test)]`-only one `seed-test-vectors`
//! keeps for its own corpus test — that one cannot be imported from here,
//! and this crate needs the *same* parsing at ordinary runtime for the
//! `check` subcommand, not only under `#[cfg(test)]`) rather than a new
//! third-party JSON dependency (IMPLEMENTATION_MAP.md §1 rule 5: minimal,
//! reviewed dependencies only). The schema is frozen (SCHEMA.md rule 2),
//! so a small reviewable parser is both sufficient and appropriate.
//!
//! Used two ways:
//! - [`check`](crate::check) walks `tests/vectors/frozen/*.json` at
//!   runtime and parses each file with [`parse_document`].
//! - [`fixed_entropy`](crate::fixed_entropy) parses two specific frozen
//!   files' text, `include_str!`-embedded at compile time (SPEC §4.3:
//!   "public fixed entropy only" — the bytes are baked into the binary,
//!   never read from disk for that path).

use seed_core::contracts::{ArchId, SourceTag, TargetBits};

/// One decoded `cases[]` entry (`tests/vectors/SCHEMA.md`).
#[derive(Debug, Clone)]
pub struct CaseSource {
    pub tag: SourceTag,
    pub algo: Vec<u8>,
    pub bytes: Vec<u8>,
}

/// One decoded test-vector case, exactly the fields
/// `tests/vectors/SCHEMA.md` defines.
#[derive(Debug, Clone)]
pub struct Case {
    pub name: String,
    pub sources: Vec<CaseSource>,
    pub arch: ArchId,
    pub bits: TargetBits,
    pub policy_version: u16,
    pub transcript_hex: String,
    pub final_entropy_hex: String,
    pub mnemonic_indexes: Vec<u16>,
    pub mnemonic_words: Vec<String>,
    pub bip39_seed_hex: String,
    pub master_fingerprint_hex: String,
    pub addr_bip44: String,
    pub addr_bip49: String,
    pub addr_bip84: String,
    pub addr_bip86: String,
}

/// The exact `schema` field every corpus file must carry
/// (`tests/vectors/SCHEMA.md`); re-exported from `seed-test-vectors`
/// (WP-16's own owned constant) rather than duplicated, so the two crates
/// can never silently drift apart on which literal string is required.
pub const SCHEMA_ID: &str = seed_test_vectors::SCHEMA_ID;

// ============================================================================
// Tiny JSON reader, scoped to exactly this schema (see module doc comment).
// ============================================================================

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
            Json::Obj(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v).unwrap_or_else(|| panic!("missing key {key:?}")),
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
        while self.pos < self.bytes.len() && matches!(self.bytes[self.pos], b' ' | b'\t' | b'\n' | b'\r') {
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
            assert_eq!(self.peek(), b'"', "object key must be a string");
            let key = self.string();
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
                // The frozen corpus is plain ASCII, no escapes (mirrors
                // `seed-test-vectors`' own parser, SCHEMA.md scope).
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

fn hex_to_bytes(hex: &str, context: &str) -> Vec<u8> {
    assert!(hex.len() % 2 == 0, "{context}: odd-length hex");
    assert!(hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')), "{context}: non-lowercase or non-hex digit in {hex:?}");
    (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect()
}

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

/// Parse one frozen-vector JSON document's text into its `cases[]`
/// (`tests/vectors/SCHEMA.md`). A schema mismatch or any structural
/// surprise is a hard panic (SCHEMA.md rule 4: "MUST be treated as a hard
/// error by every consumer, not silently skipped").
#[must_use]
pub fn parse_document(text: &str, file_context: &str) -> Vec<Case> {
    let doc = Parser::parse_document(text);
    assert_eq!(doc.get("schema").str(), SCHEMA_ID, "{file_context}: bad schema field");

    let mut cases = Vec::new();
    for case in doc.get("cases").arr() {
        let name = case.get("name").str().to_string();
        let cctx = format!("{file_context} case {name:?}");
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
            policy_version: u16::try_from(case.get("policy_version").num()).unwrap_or_else(|_| panic!("{cctx}: policy_version out of range")),
            transcript_hex: case.get("transcript_hex").str().to_string(),
            final_entropy_hex: case.get("final_entropy_hex").str().to_string(),
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
            mnemonic_words: case.get("mnemonic_words").arr().iter().map(|w| w.str().to_string()).collect(),
            bip39_seed_hex: case.get("bip39_seed_hex").str().to_string(),
            master_fingerprint_hex: case.get("master_fingerprint_hex").str().to_string(),
            addr_bip44: case.get("addresses").get("bip44").str().to_string(),
            addr_bip49: case.get("addresses").get("bip49").str().to_string(),
            addr_bip84: case.get("addresses").get("bip84").str().to_string(),
            addr_bip86: case.get("addresses").get("bip86").str().to_string(),
            sources,
            name,
        });
    }
    cases
}

/// Absolute path to `tests/vectors/frozen/` from this crate's manifest
/// directory (matches the identical pattern `seed-test-vectors` and
/// `seed-flow`'s own host tests already use to locate the corpus).
#[must_use]
pub fn frozen_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/frozen")
}

/// Load and parse every `*.json` file directly under `dir`, in sorted
/// (deterministic) filename order, returning every case from every file
/// flattened into one list alongside the file name it came from.
#[must_use]
pub fn load_all(dir: &std::path::Path) -> Vec<(String, Case)> {
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("corpus dir {dir:?} unreadable: {e}"))
        .map(|entry| entry.unwrap().path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    files.sort();

    let mut out = Vec::new();
    for path in files {
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("?").to_string();
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: unreadable: {e}"));
        for case in parse_document(&text, &file_name) {
            out.push((file_name.clone(), case));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_real_frozen_vector_file() {
        let path = frozen_dir().join("dice_only_12w_min_budget.json");
        let text = std::fs::read_to_string(&path).unwrap();
        let cases = parse_document(&text, "dice_only_12w_min_budget.json");
        assert_eq!(cases.len(), 1);
        let case = &cases[0];
        assert_eq!(case.name, "dice_only_12w_min_budget");
        assert_eq!(case.bits, TargetBits::Bits128);
        assert_eq!(case.sources.len(), 1);
        assert_eq!(case.sources[0].tag, SourceTag::DiceRolls);
        assert_eq!(case.mnemonic_words.len(), 12);
        assert_eq!(case.mnemonic_words[0], "process");
        assert_eq!(case.master_fingerprint_hex, "82ec24f2");
    }

    #[test]
    fn load_all_finds_every_frozen_file() {
        let cases = load_all(&frozen_dir());
        assert!(cases.len() >= 20, "expected >= 20 total cases, found {}", cases.len());
        assert!(cases.iter().any(|(_, c)| c.name == "dice_only_24w_min_budget"));
    }

    #[test]
    #[should_panic(expected = "bad schema field")]
    fn rejects_wrong_schema_field() {
        let bogus = r#"{"schema": "not-the-right-schema", "cases": []}"#;
        let _ = parse_document(bogus, "bogus");
    }
}
