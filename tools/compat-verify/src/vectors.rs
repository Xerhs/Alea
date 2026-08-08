//! Vector-generation mode (SPEC_COMPAT §10.1; IMPLEMENTATION_MAP_COMPAT.md
//! §4 WP-C4: "Also the vector generator mode writing
//! `tests/vectors/compat/`").
//!
//! Writes a single-case `alea-compat-vectors-v1` file (SPEC_COMPAT
//! §10.1 schema) for one profile/events/word-count combination, using the
//! exact same `derive::run` pipeline the CLI's `run` subcommand uses --
//! this mode can never emit a case whose `mnemonic_indexes`/addresses
//! disagree with what `compat-verify run` would show for the same input,
//! because both paths go through the identical function.
//!
//! This module only ever *writes new files at a caller-specified path*; it
//! never reads or overwrites `tests/vectors/compat/frozen/` (frozen vectors
//! are read-only per IMPLEMENTATION_MAP_COMPAT.md §1 rule 2/§6) and never
//! writes anywhere without an explicit `--out` path from the caller (no
//! default that reaches into another WP's owned corpus directory).

use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::Path;

use seed_compat::CompatProfile;

use crate::derive::{Outcome, Success};

/// JSON-escape a string for embedding in a generated vector file (SPEC
/// _COMPAT §10.1: hand-rolled, no third-party JSON dependency in the
/// approved set, matching `seed-compat-vectors`' own reader). Escapes the
/// minimum required by the JSON grammar plus non-ASCII as `\uXXXX` so the
/// output is always valid regardless of vendor-name punctuation (e.g. an
/// em dash in a `reason` string).
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

fn json_str(s: &str) -> String {
    format!("\"{}\"", json_escape(s))
}

fn success_case_json(
    name: &str,
    profile: &CompatProfile,
    events: &str,
    success: &Success,
    oracle_kind: &str,
    ground_truth: &[&str],
) -> String {
    let n = success.word_count_n();
    let words: Vec<String> = success.words_slice().iter().map(|w| json_str(w)).collect();
    let gt: Vec<String> = ground_truth.iter().map(|g| json_str(g)).collect();

    // BIP39 seed hex (SPEC_COMPAT §10.1 `bip39_seed_hex`) is not carried on
    // `Success` today (only entropy + derivation outputs are, per this
    // crate's own `derive::Success` doc comment); the corpus schema treats
    // it as informative, not load-bearing for the frozen-freeze assertion
    // (`seed-compat-vectors` recomputes it from `mnemonic_indexes` itself),
    // so it is intentionally omitted here rather than duplicating PBKDF2
    // work the crate does not otherwise need.
    format!(
        "    {{\n      \"name\": {name},\n      \"profile\": {profile_id},\n      \"method\": \"Sha256AsciiDigest\",\n      \"events\": {events},\n      \"event_count\": {event_count},\n      \"expected\": \"mnemonic\",\n      \"word_count\": {word_count},\n      \"mnemonic_words\": [{words}],\n      \"master_fingerprint_hex\": {fp},\n      \"addresses\": {{\"bip44\": {a44}, \"bip49\": {a49}, \"bip84\": {a84}, \"bip86\": {a86}}},\n      \"oracle_kind\": {oracle_kind},\n      \"ground_truth\": [{gt}]\n    }}",
        name = json_str(name),
        profile_id = json_str(profile.id),
        events = json_str(events),
        event_count = success.used_len,
        word_count = n,
        words = words.join(", "),
        fp = json_str(&success.master_fingerprint_hex()),
        a44 = json_str(success.addresses[0].as_str()),
        a49 = json_str(success.addresses[1].as_str()),
        a84 = json_str(success.addresses[2].as_str()),
        a86 = json_str(success.addresses[3].as_str()),
        oracle_kind = json_str(oracle_kind),
        gt = gt.join(", "),
    )
}

fn refusal_case_json(
    name: &str,
    profile: &CompatProfile,
    events: &str,
    entered: u16,
    reason: &str,
    requested_word_count: Option<u16>,
    oracle_kind: &str,
    ground_truth: &[&str],
) -> String {
    let gt: Vec<String> = ground_truth.iter().map(|g| json_str(g)).collect();
    let req_line = match requested_word_count {
        Some(w) => format!(",\n      \"requested_word_count\": {w}"),
        None => String::new(),
    };
    format!(
        "    {{\n      \"name\": {name},\n      \"profile\": {profile_id},\n      \"method\": \"Sha256AsciiDigest\",\n      \"events\": {events},\n      \"event_count\": {entered},\n      \"expected\": \"refusal\",\n      \"error_kind\": \"Refused\",\n      \"reason\": {reason}{req_line},\n      \"oracle_kind\": {oracle_kind},\n      \"ground_truth\": [{gt}]\n    }}",
        name = json_str(name),
        profile_id = json_str(profile.id),
        events = json_str(events),
        entered = entered,
        reason = json_str(reason),
        oracle_kind = json_str(oracle_kind),
        gt = gt.join(", "),
    )
}

/// Errors this module's vector generation can raise -- always a caller
/// input problem (bad alphabet / empty events), not a `compat_derive`
/// arithmetic failure (there is none for a well-formed profile).
#[derive(Debug)]
pub enum VectorError {
    BadAlphabet { at: usize },
    Empty,
}

impl std::fmt::Display for VectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VectorError::BadAlphabet { at } => write!(f, "bad alphabet at byte {at}"),
            VectorError::Empty => write!(f, "empty events string"),
        }
    }
}

/// Build one case's JSON body (SPEC_COMPAT §10.1 schema) for `events`
/// against `profile`, running the same `derive::run` pipeline
/// `compat-verify run` uses. Returns `Err` only for a `BadAlphabet`/`Empty`
/// input (a refused `DerivedFromLength` count is a *valid* case -- it
/// generates a `"refusal"` case, not an error).
pub fn build_case(
    name: &str,
    profile: &'static CompatProfile,
    events: &str,
    requested: Option<seed_compat::WordCount>,
    oracle_kind: &str,
    ground_truth: &[&str],
) -> Result<String, VectorError> {
    match crate::derive::run(profile, events, requested) {
        Outcome::Success(success) => Ok(success_case_json(name, profile, events, &success, oracle_kind, ground_truth)),
        Outcome::Refused { entered, reason } => {
            let requested_word_count = requested.map(|w| match w {
                seed_compat::WordCount::W12 => 12,
                seed_compat::WordCount::W24 => 24,
            });
            Ok(refusal_case_json(
                name,
                profile,
                events,
                entered,
                reason,
                requested_word_count,
                oracle_kind,
                ground_truth,
            ))
        }
        Outcome::BadAlphabet { at } => Err(VectorError::BadAlphabet { at }),
        Outcome::Empty => Err(VectorError::Empty),
    }
}

/// Write a complete single-case corpus file (SPEC_COMPAT §10.1 schema
/// wrapper: `{"schema": ..., "cases": [ ... ]}`) to `out_path`. Creates
/// parent directories if needed but never touches an existing file's
/// sibling frozen/candidate content -- it only ever writes the one path
/// the caller names.
pub fn write_case_file(out_path: &Path, case_json: &str) -> io::Result<()> {
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let doc = format!(
        "{{\n  \"schema\": \"alea-compat-vectors-v1\",\n  \"cases\": [\n{case_json}\n  ]\n}}\n"
    );
    fs::write(out_path, doc)
}
