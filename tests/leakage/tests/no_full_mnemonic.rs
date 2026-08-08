//! WP-34 check class (b) — SPEC §12.2 ("The application MUST render words
//! individually from fixed word indexes. It MUST NOT create one
//! concatenated mnemonic string.") and the module doc comment in
//! `crates/seed-flow/src/flow_secret/mod.rs` ("No function in
//! this module tree ever holds, builds or formats a concatenated
//! mnemonic phrase ... The only two places a mnemonic word is ever
//! touched are `display::render_mnemonic_display` ... and
//! `reentry::read_and_check_one_word` ...").
//!
//! This file turns both of those prose claims into an executable,
//! grep-based source-tree scan, so a future change that reintroduces
//! string concatenation of mnemonic words fails `cargo test` instead of
//! only a doc comment going stale.
//!
//! Scope (SPEC §29.6 "secret-bearing debug symbols and logs" is a source-
//! level property, not a runtime one, so this check class is necessarily
//! static/source-scanning rather than driven by frozen vectors):
//! `crates/seed-flow/src/flow_secret/` and
//! `crates/seed-uefi-test/src/flow_secret/` (the ceremony's own UI flow —
//! "flow_secret"), `crates/seed-core/src/` (WP-34's other named scope,
//! "core" — includes `bip39/`, where the one documented, reviewed,
//! scrubbed exception lives, and `pipeline/`), and
//! `crates/seed-gop-ui/src/font/` (the rendering path SPEC §12.2 itself
//! is about, included as direct bonus coverage), and
//! `crates/seed-flow/src/screens/` (the redesign's ceremony screens —
//! see [`STRICT_SCAN_DIRS`] for why that directory joined the strict
//! scope once one of its modules began staging mnemonic indexes).

mod support;

use support::{repo_root, rust_files_under, split_non_test_code};

const STRICT_SCAN_DIRS: &[&str] = &[
    "crates/seed-flow/src/flow_secret",
    "crates/seed-uefi-test/src/flow_secret",
    "crates/seed-core/src",
    "crates/seed-gop-ui/src/font",
    // The redesign's ceremony screen modules. Originally outside this
    // scan because `screens/` was pure presentation over already-derived
    // public values; `screens/export.rs` changed that by staging the
    // resident mnemonic index array to re-derive the account key for the
    // opt-in export — the same commit-then-derive relaxation
    // `flow_secret/custom_path` already carries, and exactly the kind of
    // code this scan exists to watch.
    "crates/seed-flow/src/screens",
];

/// Literal substrings that would indicate a full mnemonic phrase (or any
/// other secret-bearing multi-word list) is being concatenated into one
/// string/buffer. `.join(`/`concat!(`/`.concat(` are the three ordinary
/// Rust idioms for turning a slice of pieces into one joined value; SPEC
/// §12.2's own wording (`IMPLEMENTATION_MAP.md` §5 WP-34) calls out
/// `.join(` by name as the canonical example.
const FORBIDDEN_CONCAT_PATTERNS: &[&str] = &[".join(", "concat!(", ".concat("];

/// Scans `text` (assumed already restricted to non-test code via
/// [`split_non_test_code`]) for every forbidden pattern, returning
/// `(pattern, line_number)` for each hit found (1-based line numbers, for
/// a readable failure message).
fn find_forbidden_patterns(text: &str) -> Vec<(&'static str, usize)> {
    let mut hits = Vec::new();
    for &pat in FORBIDDEN_CONCAT_PATTERNS {
        for (line_no, line) in text.lines().enumerate() {
            if line.contains(pat) {
                hits.push((pat, line_no + 1));
            }
        }
    }
    hits
}

#[test]
fn no_string_concatenation_idiom_in_non_test_flow_secret_or_core_code() {
    let mut violations = Vec::new();
    for dir in STRICT_SCAN_DIRS {
        for path in rust_files_under(dir) {
            let content = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: unreadable: {e}"));
            let (non_test, _test) = split_non_test_code(&content);
            for (pat, line) in find_forbidden_patterns(non_test) {
                violations.push(format!("{}:{line}: forbidden pattern {pat:?}", path.strip_prefix(repo_root()).unwrap_or(&path).display()));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "found string-concatenation idioms in non-test flow_secret/core/font source \
         (possible full-mnemonic-string construction, SPEC §12.2):\n{}",
        violations.join("\n")
    );
}

/// Meta-test: proves [`find_forbidden_patterns`] actually detects a
/// violation when one exists, so the all-clear result above is not simply
/// because the scanner itself is broken (a scanner that always returns
/// `[]` would otherwise make the previous test vacuously green forever).
#[test]
fn forbidden_pattern_scanner_actually_detects_a_synthetic_violation() {
    let synthetic = "let words: [&str; 3] = [\"abandon\", \"ability\", \"able\"];\nlet phrase = words.join(\" \");\n";
    let hits = find_forbidden_patterns(synthetic);
    assert_eq!(hits, vec![(".join(", 2)], "scanner failed to flag a synthetic `.join(` violation");

    let clean = "let phrase_word_count = 12;\n";
    assert!(find_forbidden_patterns(clean).is_empty(), "scanner false-positived on non-matching source");
}

/// Meta-test: proves [`split_non_test_code`] actually excludes test-only
/// code, so files whose *tests* legitimately build word lists (KAT
/// helpers, e.g. `crates/seed-core/src/bip39/mod.rs`'s own `words_for`
/// test helper) do not spuriously fail the strict scan above, without
/// the strict scan silently exempting production code that merely
/// follows a `#[cfg(test)]` marker elsewhere in the same file.
#[test]
fn split_non_test_code_excludes_everything_from_the_first_cfg_test_marker() {
    let synthetic = "pub fn real() {}\n#[cfg(test)]\nmod tests {\n    fn helper() { let p = [\"a\"].join(\" \"); }\n}\n";
    let (non_test, test) = split_non_test_code(synthetic);
    assert!(non_test.contains("pub fn real"));
    assert!(!non_test.contains(".join("), "test-only content leaked into the non-test half");
    assert!(test.contains(".join("));

    let no_marker = "pub fn only_production() {}\n";
    let (non_test2, test2) = split_non_test_code(no_marker);
    assert_eq!(non_test2, no_marker);
    assert_eq!(test2, "");
}

// ============================================================================
// The stronger, whole-repository invariant: `seed_core::bip39::word(...)`
// (the only function that ever turns an index back into word text) is
// called from non-test code in exactly the two sites
// `crates/seed-flow/src/flow_secret/mod.rs`'s own doc comment
// names, and nowhere else in the entire `crates/` tree.
// ============================================================================

/// `true` if `haystack[at..]` starts with `needle` AND the character
/// immediately before `at` (if any) is not a Rust identifier character —
/// a minimal word-boundary check so e.g. `mnemonic_word(` or
/// `draw_word(` (both real, legitimate identifiers in this codebase) are
/// never confused with a bare call to `word(`/`::word(`.
fn is_boundary_match(haystack: &[u8], at: usize, needle: &str) -> bool {
    if !haystack[at..].starts_with(needle.as_bytes()) {
        return false;
    }
    if at == 0 {
        return true;
    }
    let prev = haystack[at - 1];
    !(prev.is_ascii_alphanumeric() || prev == b'_')
}

/// `true` if the `word(` match found at byte offset `at` is the function
/// *definition* (`... fn word(`) rather than a call site.
fn is_definition_site(haystack: &[u8], at: usize) -> bool {
    at >= 3 && &haystack[at - 3..at] == b"fn "
}

/// Finds every non-test, non-definition, word-boundary-matched call to
/// `word(` (covering both `bip39::word(idx)` and a local `word(idx)`
/// after a `use ... word;` import) in `text`.
fn find_word_call_sites(text: &str) -> Vec<usize> {
    let bytes = text.as_bytes();
    let mut hits = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if is_boundary_match(bytes, i, "word(") && !is_definition_site(bytes, i) {
            hits.push(i);
        }
        i += 1;
    }
    hits
}

fn line_of(text: &str, byte_offset: usize) -> usize {
    text[..byte_offset].matches('\n').count() + 1
}

/// Scans `dirs` for non-test `word(...)` call sites, returning
/// `"path:line"` strings, sorted.
fn scan_word_call_sites(dirs: &[&str]) -> Vec<String> {
    let mut call_sites: Vec<String> = Vec::new();
    for dir in dirs {
        for entry in rust_files_under(dir) {
            let content = std::fs::read_to_string(&entry).unwrap_or_else(|e| panic!("{entry:?}: unreadable: {e}"));
            let (non_test, _test) = split_non_test_code(&content);
            for offset in find_word_call_sites(non_test) {
                let rel = entry.strip_prefix(repo_root()).unwrap_or(&entry).display().to_string();
                call_sites.push(format!("{rel}:{}", line_of(non_test, offset)));
            }
        }
    }
    call_sites.sort();
    call_sites
}

#[test]
fn word_is_only_ever_called_from_the_two_documented_sites() {
    // Scope matches `crates/seed-flow/src/flow_secret/mod.rs`'s
    // own doc-comment claim, which is itself scoped to "this module
    // tree" (flow_secret) -- plus `seed-core` ("core", this WP's other
    // named scope) and `seed-gop-ui/src/font` (the rendering path the
    // claim is actually about).
    let call_sites = scan_word_call_sites(STRICT_SCAN_DIRS);

    // The two sites the doc comment names: `display::
    // render_mnemonic_display` (draws one word directly, per SPEC §12.2)
    // and `seed_core::bip39::mnemonic_to_seed`'s single documented,
    // reviewed, immediately-scrubbed exception (`IMPLEMENTATION_MAP.md`
    // WP-05 pitfalls).
    let expected_files = ["crates/seed-core/src/bip39/mod.rs", "crates/seed-gop-ui/src/font/mod.rs"];
    let matched_files: Vec<&str> = call_sites.iter().map(|s| s.split(':').next().unwrap()).collect();
    for f in &matched_files {
        assert!(
            expected_files.contains(f),
            "unexpected non-test call to bip39::word(...) outside the two documented sites: {call_sites:?}"
        );
    }
    assert_eq!(
        call_sites.len(),
        2,
        "expected exactly 2 non-test word(...) call sites (one render call, one documented \
         scrubbed phrase-buffer exception), found {}: {call_sites:?}",
        call_sites.len()
    );
}

/// Whole-`crates/`-tree version of the check above: broader than the
/// flow_secret/core/font scope WP-34 owns, kept as an explicit,
/// allowlisted regression detector rather than silently ignored, because
/// running it while building this suite found a real THIRD non-test call
/// site this project's own doc comments do not mention:
/// `crates/seed-desktop-test/src/pipeline.rs` (WP-28's desktop-test-
/// edition `--check` comparison tool) builds a `Vec<String>` of
/// individual words (never one joined phrase) purely to diff against
/// `tests/vectors/frozen/*.json`'s own `mnemonic_words` field, and only
/// ever operates on the desktop test edition's fixed PUBLIC vector
/// entropy (SPEC §4.3: "fixed public entropy only") -- never the secret
/// arena, never the GOP secret-display path, never a real user's
/// mnemonic. This is reported as a WP-34 finding (see task report), not
/// silently fixed here (`crates/seed-desktop-test/` is WP-28's owned
/// path, not WP-34's, `IMPLEMENTATION_MAP.md` §6).
#[test]
fn word_call_sites_across_the_whole_crates_tree_are_fully_accounted_for() {
    let call_sites = scan_word_call_sites(&["crates"]);
    let allowed = [
        "crates/seed-core/src/bip39/mod.rs",
        "crates/seed-gop-ui/src/font/mod.rs",
        // WP-34 finding (informational/low, not a real-secret leak --
        // see this test's own doc comment above): builds a `Vec<String>`
        // of individual words for a public-vector-only debug comparison
        // tool, never a joined phrase, never touching real secret
        // material or the GOP display path.
        "crates/seed-desktop-test/src/pipeline.rs",
        // SPEC §11.6 aggregate cryptographic self-test (`seed_selftest::
        // bip39_kat`, `crates/seed-selftest/src/lib.rs` -- moved out of
        // `seed-flow` by STEP C; see that crate's own doc comment for
        // why): four `bip39::word(idx) == "abandon"`/`"buyer"`/`"art"`
        // equality checks against the standard, widely-published
        // fixed/all-zero-entropy BIP39 known-answer-test vectors (never
        // real secret entropy, never a joined phrase -- each call
        // compares exactly one word at a time against a hardcoded
        // literal, the same shape SPEC §12.2 requires of the real
        // display/re-entry paths).
        "crates/seed-selftest/src/lib.rs",
        // SPEC_MAIN_MENU.md §17.4 / Option-B (2026-08-07): the SEPARATE
        // `alea-verify.efi` cross-device verifier (never linked into the
        // production generator -- binary isolation, SPEC_COMPAT §9). Two
        // sites (`finish`/`finish_entropy`, verify.rs), each an identical
        // `for idx in ..out.mnemonic_indexes[..n] { words.push(word(idx)) }`
        // loop building a `Vec<&'static str>` of individual words for the
        // word-by-word display of a FOREIGN reproduced mnemonic (rendered
        // one word at a time at `verify.rs:593`, `for (i, w) in
        // success.words.iter().enumerate()`). Never a joined phrase (this
        // crate contains no `.join(` in non-test code), never real
        // generation -- the same word-by-word shape SPEC §12.2 requires,
        // reviewed identically to the `pipeline.rs` entry above.
        "crates/alea-verify/src/verify.rs",
    ];
    let unexpected: Vec<&String> = call_sites.iter().filter(|s| !allowed.iter().any(|a| s.starts_with(a))).collect();
    assert!(unexpected.is_empty(), "found word(...) call site(s) not on the reviewed allowlist: {unexpected:?}\nfull list: {call_sites:?}");
    assert_eq!(call_sites.len(), 9, "expected exactly the 9 known, reviewed call sites; found {}: {call_sites:?}", call_sites.len());
}

/// SPEC §13/§20.3: the one documented exception in `bip39::
/// mnemonic_to_seed_with_passphrase_bytes` (the single seed-derivation
/// implementation since SPEC_PASSPHRASE §2.2 — `mnemonic_to_seed` is now a
/// thin empty-passphrase wrapper over it): a fixed-size stack buffer that
/// briefly holds the space-joined phrase for a one-shot PBKDF2 call, plus
/// the secret-adjacent salt buffer that holds the passphrase, must both be
/// immediately, explicitly scrubbed in the same function -- checked here at
/// the source-text level as a belt-and-braces companion to
/// `crates/seed-core/src/bip39/mod.rs`'s own runtime scrub tests (which
/// this WP does not own and must not weaken/duplicate, only corroborate
/// independently).
#[test]
fn the_one_documented_phrase_buffer_exception_is_immediately_scrubbed() {
    let path = repo_root().join("crates/seed-core/src/bip39/mod.rs");
    let content = std::fs::read_to_string(&path).unwrap();
    let (non_test, _test) = split_non_test_code(&content);

    let fn_start = non_test.find("pub fn mnemonic_to_seed_with_passphrase_bytes").expect("mnemonic_to_seed_with_passphrase_bytes must exist in non-test code");
    // Bound the function body at the next top-level `pub fn `/`fn ` after
    // its own signature (the next item in the file).
    let after_sig = fn_start + "pub fn mnemonic_to_seed_with_passphrase_bytes".len();
    let next_item_offset = non_test[after_sig..].find("\npub fn ").or_else(|| non_test[after_sig..].find("\nfn ")).unwrap_or(non_test.len() - after_sig);
    let body = &non_test[fn_start..after_sig + next_item_offset];

    assert!(body.contains("word(idx)"), "expected the documented word-accumulation loop inside mnemonic_to_seed_with_passphrase_bytes");
    assert!(body.contains("scrub_phrase"), "the materialized phrase buffer must be scrubbed before mnemonic_to_seed_with_passphrase_bytes returns");
    assert!(body.contains("scrub_bytes(&mut salt)"), "the secret-adjacent salt buffer (it holds the passphrase, SPEC_PASSPHRASE \u{a7}2.2) must be scrubbed before mnemonic_to_seed_with_passphrase_bytes returns");

    // And it must be the ONLY function in the file with this shape --
    // `word_call_sites` above already proves there is exactly one
    // non-test call to `word(` in this file; this test additionally
    // proves that single call is the one inside `mnemonic_to_seed`
    // specifically (not, say, a second, unscrubbed accumulation
    // elsewhere that this bounding logic accidentally walked past).
    let word_call_offset = non_test.find("word(idx)").unwrap();
    assert!(word_call_offset >= fn_start && word_call_offset < fn_start + body.len(), "the word( call must be inside mnemonic_to_seed's own body");
}
