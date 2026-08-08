//! Shared test-support code for the WP-34 leakage suite (SPEC §29.6).
//!
//! Nothing in this module is itself a leakage *check* — it is the
//! plumbing every `tests/leakage/tests/*.rs` file needs: a spy
//! [`Framebuffer`] test double, a scripted [`KeySource`] test double, a
//! minimal reader for the frozen public-vector corpus
//! (`tests/vectors/frozen/`, `IMPLEMENTATION_MAP.md` §4 schema), and a
//! couple of small source-text scanning primitives reused by more than
//! one check file.
//!
//! Every mnemonic word, index, seed byte, key byte and address used
//! anywhere in this suite comes from `tests/vectors/frozen/*.json` — the
//! project's own frozen, published, PUBLIC test vectors (never invented
//! locally, never real user material). See `IMPLEMENTATION_MAP.md` §4's
//! vector schema and `tests/vectors/SCHEMA.md`.
#![allow(dead_code)]

use std::path::PathBuf;

use seed_core::contracts::Framebuffer;
use seed_platform_x86::input::{InputEvent, KeySource};

// ============================================================================
// Framebuffer / keyboard test doubles
//
// Same shape as every `VecFb`/`ScriptedKeys` double already used by
// `crates/seed-flow/src/flow_secret/*.rs`'s own unit tests
// (`display.rs`, `reentry.rs`, `verification.rs`, `shutdown.rs`,
// `gop_screen.rs`) — duplicated here (rather than exported from that
// crate) because those are `#[cfg(test)]`-private to their own crate.
// ============================================================================

/// In-memory spy framebuffer: every `put_row` call is recorded into a
/// flat `Vec<u32>`, so a test can inspect exactly what pixels a real
/// rendering call left behind (SPEC §29.6: "residual rendering buffers").
pub struct VecFb {
    w: u32,
    h: u32,
    pub buf: Vec<u32>,
}

impl VecFb {
    #[must_use]
    pub fn new(w: u32, h: u32) -> Self {
        Self { w, h, buf: vec![0u32; (w as usize) * (h as usize)] }
    }

    /// `true` if every pixel is exactly `0` (fully blank).
    #[must_use]
    pub fn is_blank(&self) -> bool {
        self.buf.iter().all(|&p| p == 0)
    }

    /// `true` if at least one pixel equals `value` anywhere in the
    /// buffer.
    #[must_use]
    pub fn contains_pixel(&self, value: u32) -> bool {
        self.buf.iter().any(|&p| p == value)
    }
}

impl Framebuffer for VecFb {
    fn dims(&self) -> (u32, u32) {
        (self.w, self.h)
    }
    fn put_row(&mut self, x: u32, y: u32, px: &[u32]) {
        let start = (y as usize) * (self.w as usize) + (x as usize);
        self.buf[start..start + px.len()].copy_from_slice(px);
    }
}

/// Scripted [`KeySource`]: replays a fixed sequence of [`InputEvent`]s,
/// panicking (test failure, not a silent hang) if more keys are read than
/// were scripted.
pub struct ScriptedKeys {
    events: Vec<InputEvent>,
    pos: usize,
}

impl ScriptedKeys {
    #[must_use]
    pub fn new(events: Vec<InputEvent>) -> Self {
        Self { events, pos: 0 }
    }

    /// Builds the scripted keystream for one hidden-re-entry word prompt:
    /// the caller-supplied prefix (already reduced to <= 4 characters by
    /// [`prefix_for_word`]) followed by `Enter`.
    #[must_use]
    pub fn word_entry(prefix: &str) -> Vec<InputEvent> {
        let mut v: Vec<InputEvent> = prefix.chars().map(InputEvent::Char).collect();
        v.push(InputEvent::Enter);
        v
    }
}

impl KeySource for ScriptedKeys {
    fn read_key_blocking(&mut self) -> InputEvent {
        let ev = self.events.get(self.pos).copied().unwrap_or_else(|| {
            panic!("ScriptedKeys: read past the end of the scripted keystream (pos {})", self.pos)
        });
        self.pos += 1;
        ev
    }
}

/// SPEC §12.3 word-entry rule: the first four letters of the word, or the
/// complete word if it is shorter than four letters.
#[must_use]
pub fn prefix_for_word(word: &str) -> &str {
    if word.len() <= 4 {
        word
    } else {
        &word[..4]
    }
}

// ============================================================================
// Frozen public-vector corpus reader
//
// A second, independent, minimal JSON reader for the exact same fixed
// `tests/vectors/SCHEMA.md` shape `crates/seed-test-vectors/src/lib.rs`'s
// own (crate-private, `#[cfg(test)]`-only) reader already parses — not
// reused from there because that reader lives inside another crate's own
// test module and is not a public API this crate (which must not touch
// `tests/vectors/frozen/`, read-only to WP-34) can import. Deliberately
// strict, matching `SCHEMA.md` rule 4 ("a mismatch is a hard parse
// failure, not a warning"): any structural surprise panics loudly.
// ============================================================================

pub const SCHEMA_ID: &str = "alea-vectors-v1";

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

fn hex_to_bytes(hex: &str, context: &str) -> Vec<u8> {
    assert!(hex.len() % 2 == 0, "{context}: odd-length hex");
    assert!(hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')), "{context}: non-lowercase or non-hex digit in {hex:?}");
    (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect()
}

/// One SPEC §19.1 source record as loaded from the frozen corpus.
pub struct VectorSource {
    pub tag_hex: String,
    pub algo: String,
    pub bytes: Vec<u8>,
}

/// One fully decoded `tests/vectors/frozen/*.json` case (the fields this
/// suite actually needs; see `tests/vectors/SCHEMA.md` for the complete
/// schema).
pub struct VectorCase {
    pub name: String,
    pub sources: Vec<VectorSource>,
    pub bits: i64,
    pub policy_version: u16,
    pub final_entropy: Vec<u8>,
    pub mnemonic_indexes: Vec<u16>,
    pub mnemonic_words: Vec<String>,
    pub bip39_seed: Vec<u8>,
    pub master_fingerprint: Vec<u8>,
    pub addr_bip44: String,
    pub addr_bip49: String,
    pub addr_bip84: String,
    pub addr_bip86: String,
}

/// Absolute path to the frozen vector corpus directory
/// (`tests/vectors/frozen/`, read-only to WP-34 — this function only
/// reads it).
#[must_use]
pub fn frozen_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vectors/frozen")
}

/// Loads and decodes exactly one named case (matched by `sources[].name`,
/// SPEC schema `cases[].name` — file base name is not assumed to match
/// the case name) from the frozen corpus, panicking loudly if the file or
/// case is missing.
#[must_use]
pub fn load_case(file_stem: &str) -> VectorCase {
    let path = frozen_dir().join(format!("{file_stem}.json"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: unreadable: {e}"));
    let doc = Parser::parse_document(&text);
    assert_eq!(doc.get("schema").str(), SCHEMA_ID, "{path:?}: bad schema field");

    let cases = doc.get("cases").arr();
    assert_eq!(cases.len(), 1, "{path:?}: expected exactly one case");
    let case = &cases[0];
    let ctx = format!("{path:?}");

    let sources = case
        .get("sources")
        .arr()
        .iter()
        .map(|s| VectorSource {
            tag_hex: s.get("tag").str().to_string(),
            algo: s.get("algo").str().to_string(),
            bytes: hex_to_bytes(s.get("bytes_hex").str(), &ctx),
        })
        .collect();

    VectorCase {
        name: case.get("name").str().to_string(),
        sources,
        bits: case.get("bits").num(),
        policy_version: u16::try_from(case.get("policy_version").num()).expect("policy_version fits u16"),
        final_entropy: hex_to_bytes(case.get("final_entropy_hex").str(), &ctx),
        mnemonic_indexes: case
            .get("mnemonic_indexes")
            .arr()
            .iter()
            .map(|n| {
                let v = n.num();
                assert!((0..2048).contains(&v), "{ctx}: index {v} out of range");
                v as u16
            })
            .collect(),
        mnemonic_words: case.get("mnemonic_words").arr().iter().map(|w| w.str().to_string()).collect(),
        bip39_seed: hex_to_bytes(case.get("bip39_seed_hex").str(), &ctx),
        master_fingerprint: hex_to_bytes(case.get("master_fingerprint_hex").str(), &ctx),
        addr_bip44: case.get("addresses").get("bip44").str().to_string(),
        addr_bip49: case.get("addresses").get("bip49").str().to_string(),
        addr_bip84: case.get("addresses").get("bip84").str().to_string(),
        addr_bip86: case.get("addresses").get("bip86").str().to_string(),
    }
}

// ============================================================================
// Source-tree scanning primitives (check b: no full-mnemonic string)
// ============================================================================

/// Absolute path to the repository root (two levels up from this crate's
/// own manifest directory, `tests/leakage/`).
#[must_use]
pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Recursively collects every `*.rs` file under `dir` (relative to the
/// repo root), skipping `target/` build-output directories.
#[must_use]
pub fn rust_files_under(dir: &str) -> Vec<PathBuf> {
    let root = repo_root().join(dir);
    let mut out = Vec::new();
    collect_rust_files(&root, &mut out);
    out.sort();
    out
}

fn collect_rust_files(dir: &PathBuf, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{dir:?}: unreadable: {e}"));
    for entry in entries {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().and_then(|n| n.to_str()) == Some("target") {
                continue;
            }
            collect_rust_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// Splits `source` into `(non_test_code, test_code)` at the first
/// `#[cfg(test)]` marker. Every file scanned by this suite follows this
/// codebase's established, universal convention of a single trailing
/// `#[cfg(test)] mod tests { ... }` block as the last item in the file
/// (verified across every `flow_secret`/`seed-core` file read while
/// building this suite) — so "before the first `#[cfg(test)]`" is a sound
/// proxy for "production code" without needing a real Rust parser. A file
/// with no `#[cfg(test)]` marker at all is entirely production code.
///
/// # Known limitation: a doc comment that quotes the attribute
///
/// This is a textual `str::find`, not a real parser, so it cannot tell a
/// live `#[cfg(test)]` attribute from the same eleven characters sitting
/// inside a `///`/`//!` doc comment (e.g. a module doc explaining "the
/// `#[cfg(test)]` fit audit below" some real code). If a file's doc
/// comment quotes the literal attribute text ABOVE its real trailing
/// `#[cfg(test)] mod tests` block, this function truncates
/// `non_test_code` at that doc-comment mention instead — silently
/// excluding everything between the quote and the real test module
/// (real production code) from whatever scan `non_test_code` feeds
/// (Task 19 found this in `crates/seed-flow/src/edu/mod.rs`'s module
/// doc, since fixed by rewording that comment to avoid the literal
/// string). Not fixed here: a real Rust-aware split is out of scope for
/// this helper, and rewording the handful of doc comments that happen to
/// quote the attribute is cheaper and just as correct. If a new
/// production-half leakage gap ever appears, grep every scanned file for
/// `` `#[cfg(test)]` `` (backtick-quoted, i.e. inside a doc comment) —
/// any hit before that file's real test module is this same collision.
#[must_use]
pub fn split_non_test_code(source: &str) -> (&str, &str) {
    match source.find("#[cfg(test)]") {
        Some(idx) => (&source[..idx], &source[idx..]),
        None => (source, ""),
    }
}
