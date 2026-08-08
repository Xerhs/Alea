//! Host tests over the frozen compat corpus (IMPLEMENTATION_MAP_COMPAT.md
//! §4 WP-C4 DoD: "compat-verify reproduces frozen cases; refusal paths
//! tested").
//!
//! Reads every case in `tests/vectors/compat/frozen/` (read-only per
//! IMPLEMENTATION_MAP_COMPAT.md §1 rule 2/§6 -- this test only ever reads
//! that directory, never writes to it) and, for each:
//!
//! - `expected: "mnemonic"` -- runs `compat_verify::derive::run` and
//!   asserts the produced words, master fingerprint, and all four
//!   addresses match the frozen vector byte-for-byte;
//! - `expected: "refusal"` -- asserts `compat_verify::derive::run` returns
//!   `Outcome::Refused`, never a rendered mnemonic (SPEC_COMPAT §5.1.2/
//!   §5.1.3, review F1 -- the whole point of this feature).
//!
//! A separate test (`scripted_run_reproduces_frozen_seedsigner_case`)
//! invokes the actual built `compat-verify` binary as a subprocess over a
//! frozen SeedSigner case, matching the WP-C4 DoD's literal "a scripted
//! run reproduces a frozen seedsigner case" requirement.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use compat_verify::derive::{self, Outcome};
use compat_verify::profile;

// ----------------------------------------------------------------------
// Minimal JSON reader for the fixed `alea-compat-vectors-v1` schema
// (SPEC_COMPAT §10.1). Hand-rolled: no third-party JSON dependency exists
// in the approved set (IMPLEMENTATION_MAP_COMPAT.md §1 rule 7), matching
// the same approach `crates/seed-compat-vectors` takes. Strict: any
// structural surprise panics the test.
// ----------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Json {
    Obj(Vec<(String, Json)>),
    Arr(Vec<Json>),
    Str(String),
    Num(i64),
}

impl Json {
    fn get(&self, key: &str) -> &Json {
        self.get_opt(key).unwrap_or_else(|| panic!("missing key {key:?} in {self:?}"))
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
                        b'u' => {
                            let cp = self.hex4();
                            let ch = char::from_u32(cp).unwrap_or_else(|| panic!("invalid \\u escape {cp:#06x}"));
                            out.push(ch);
                        }
                        other => panic!("unsupported escape \\{:?}", other as char),
                    }
                }
                _ => out.push(b as char),
            }
        }
        out
    }
    fn hex4(&mut self) -> u32 {
        let mut v = 0u32;
        for _ in 0..4 {
            let b = self.bytes[self.pos];
            self.pos += 1;
            let d = match b {
                b'0'..=b'9' => (b - b'0') as u32,
                b'a'..=b'f' => (b - b'a' + 10) as u32,
                b'A'..=b'F' => (b - b'A' + 10) as u32,
                other => panic!("bad hex digit {:?}", other as char),
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
        let text = std::str::from_utf8(&self.bytes[start..self.pos]).unwrap();
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

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/compat/frozen")
}

fn load_cases() -> Vec<Json> {
    let dir = corpus_dir();
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("frozen compat corpus dir {dir:?} unreadable: {e}"))
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no frozen compat vector files found in {dir:?}");

    let mut cases = Vec::new();
    for path in files {
        let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: unreadable: {e}"));
        let doc = Parser::parse_document(&text);
        assert_eq!(
            doc.get("schema").str(),
            "alea-compat-vectors-v1",
            "{path:?}: bad schema field"
        );
        for case in doc.get("cases").arr() {
            cases.push(case.clone());
        }
    }
    cases
}

/// Every frozen case's `profile` field reproduced end-to-end
/// (IMPLEMENTATION_MAP_COMPAT.md §4 WP-C4 DoD: "compat-verify reproduces
/// frozen cases; refusal paths tested").
#[test]
fn compat_verify_reproduces_every_frozen_case() {
    let cases = load_cases();
    assert!(!cases.is_empty());

    let mut mnemonic_cases = 0usize;
    let mut refusal_cases = 0usize;

    for case in &cases {
        let name = case.get("name").str().to_string();
        let profile_id = case.get("profile").str().to_string();
        let events = case.get("events").str().to_string();
        let expected = case.get("expected").str().to_string();

        let p = profile(&profile_id)
            .unwrap_or_else(|| panic!("case {name:?}: unknown or non-user-facing profile {profile_id:?}"));

        let requested = case.get_opt("requested_word_count").map(|v| match v.num() {
            12 => compat_verify::WordCount::W12,
            24 => compat_verify::WordCount::W24,
            other => panic!("case {name:?}: unsupported requested_word_count {other}"),
        });

        let outcome = derive::run(p, &events, requested);

        match expected.as_str() {
            "mnemonic" => {
                mnemonic_cases += 1;
                let success = match outcome {
                    Outcome::Success(s) => s,
                    Outcome::Refused { reason, .. } => {
                        panic!("case {name:?}: expected mnemonic, got Refused: {reason}")
                    }
                    Outcome::BadAlphabet { at } => panic!("case {name:?}: expected mnemonic, got BadAlphabet at {at}"),
                    Outcome::Empty => panic!("case {name:?}: expected mnemonic, got Empty"),
                };

                let expected_words: Vec<String> =
                    case.get("mnemonic_words").arr().iter().map(|w| w.str().to_string()).collect();
                let got_words: Vec<String> = success.words_slice().iter().map(|w| w.to_string()).collect();
                assert_eq!(got_words, expected_words, "case {name:?}: mnemonic words mismatch");

                if let Some(fp) = case.get_opt("master_fingerprint_hex") {
                    assert_eq!(
                        success.master_fingerprint_hex(),
                        fp.str(),
                        "case {name:?}: master fingerprint mismatch"
                    );
                }

                if let Some(addrs) = case.get_opt("addresses") {
                    let expected_addrs: BTreeMap<&str, &str> = addrs
                        .arr_or_obj_pairs()
                        .into_iter()
                        .map(|(k, v)| (k, v.str()))
                        .collect();
                    for rendered in &success.addresses {
                        let label_lower = rendered.label.to_lowercase();
                        if let Some(expected_addr) = expected_addrs.get(label_lower.as_str()) {
                            assert_eq!(
                                rendered.as_str(),
                                *expected_addr,
                                "case {name:?}: {} address mismatch",
                                rendered.label
                            );
                        }
                    }
                }
            }
            "refusal" => {
                refusal_cases += 1;
                match outcome {
                    Outcome::Refused { .. } => {}
                    Outcome::Success(_) => {
                        panic!("case {name:?}: expected refusal, but compat-verify produced a mnemonic (F1 regression!)")
                    }
                    Outcome::BadAlphabet { at } => panic!("case {name:?}: expected refusal, got BadAlphabet at {at}"),
                    Outcome::Empty => panic!("case {name:?}: expected refusal, got Empty"),
                }
            }
            other => panic!("case {name:?}: unknown expected value {other:?}"),
        }
    }

    // Sanity: the frozen corpus (SPEC_COMPAT §10.4) is required to contain
    // both outcome kinds -- if either count is zero, this test would be
    // exercising only half of WP-C4's DoD ("reproduces frozen cases; refusal
    // paths tested") without anyone noticing.
    assert!(mnemonic_cases > 0, "frozen corpus contained no mnemonic cases");
    assert!(refusal_cases > 0, "frozen corpus contained no refusal cases");
}

// Small helper trait so the `addresses` object (SPEC_COMPAT §10.1:
// `{"bip44": "...", ...}`) can be read as key/value pairs without a
// dedicated `Json::Obj` accessor duplicated at every call site.
trait ObjPairs {
    fn arr_or_obj_pairs(&self) -> Vec<(&str, &Json)>;
}
impl ObjPairs for Json {
    fn arr_or_obj_pairs(&self) -> Vec<(&str, &Json)> {
        match self {
            Json::Obj(pairs) => pairs.iter().map(|(k, v)| (k.as_str(), v)).collect(),
            other => panic!("expected object, got {other:?}"),
        }
    }
}

/// WP-C4 DoD: "a scripted run reproduces a frozen seedsigner case" -- runs
/// the actual compiled `compat-verify` binary as a subprocess (not just the
/// library function) over the frozen 99-roll SeedSigner vendor example
/// (SPEC_COMPAT §5.1.2's published cross-check) and checks its stdout
/// contains the exact expected mnemonic and master fingerprint.
#[test]
fn scripted_run_reproduces_frozen_seedsigner_case() {
    let path = corpus_dir().join("seedsigner_dice_24w_vendor_example.json");
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: unreadable: {e}"));
    let doc = Parser::parse_document(&text);
    let case = &doc.get("cases").arr()[0];
    let events = case.get("events").str().to_string();
    let expected_words: Vec<String> =
        case.get("mnemonic_words").arr().iter().map(|w| w.str().to_string()).collect();
    let expected_fp = case.get("master_fingerprint_hex").str().to_string();

    let bin = env!("CARGO_BIN_EXE_compat-verify");
    let output = Command::new(bin)
        .args(["run", "--profile", "seedsigner-dice", "--events", &events])
        .output()
        .expect("failed to run compat-verify binary");

    assert!(
        output.status.success(),
        "compat-verify run exited with {:?}; stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    for word in &expected_words {
        assert!(stdout.contains(word.as_str()), "stdout missing word {word:?}:\n{stdout}");
    }
    assert!(stdout.contains(&expected_fp), "stdout missing master fingerprint {expected_fp:?}:\n{stdout}");
    assert!(
        stdout.contains("[COMPATIBILITY / VERIFICATION — NOT AN ALEA SEED — PUBLIC/THROWAWAY]"),
        "stdout missing permanent watermark:\n{stdout}"
    );
    // Entropy hex must NOT appear by default (review F7 -- no
    // concatenation of entropy hex with the mnemonic without
    // `--show-entropy`).
    assert!(
        !stdout.contains("Entropy hex ("),
        "entropy hex leaked into default output without --show-entropy:\n{stdout}"
    );
}

/// WP-C4 DoD: "refusal path tested" -- the exact F1 phantom-pairing case
/// (99 canonical rolls explicitly requested as 12 words, SPEC_COMPAT §7's
/// literal refusal example) via the real binary, asserting the distinct
/// REFUSED exit code and that no mnemonic word ever appears in the output.
#[test]
fn scripted_run_refuses_f1_phantom_pairing_via_binary() {
    let events = "655152231316521321611331544441236164664431121534415633\
526456254462245546236542364246312613322234612";
    assert_eq!(events.len(), 99);

    let bin = env!("CARGO_BIN_EXE_compat-verify");
    let output = Command::new(bin)
        .args(["run", "--profile", "seedsigner-dice", "--events", events, "--words", "12"])
        .output()
        .expect("failed to run compat-verify binary");

    assert_eq!(output.status.code(), Some(1), "expected exit code 1 (Refused) for the F1 phantom pairing");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("REFUSED"), "stdout missing REFUSED:\n{stdout}");
    // The 24-word mnemonic this exact 99-roll string DOES produce at its
    // real (derived) word count must never appear here -- that would be
    // exactly the F1 bug (a fabricated/mismatched phrase alongside a
    // refusal).
    assert!(!stdout.contains("eyebrow"), "a mnemonic word leaked into a refusal screen:\n{stdout}");
}

/// Direct library-level regression for the same F1 case, independent of
/// the binary/subprocess path above.
#[test]
fn library_refuses_f1_phantom_pairing() {
    let p = profile("seedsigner-dice").expect("seedsigner-dice must be user-facing");
    let events = "655152231316521321611331544441236164664431121534415633\
526456254462245546236542364246312613322234612";
    match derive::run(p, events, Some(compat_verify::WordCount::W12)) {
        Outcome::Refused { entered, .. } => assert_eq!(entered, 99),
        _ => panic!("expected Refused, got a different outcome variant"),
    }
}
