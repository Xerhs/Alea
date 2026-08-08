//! WP-34 check class (d), extended for the opt-in wallet-export feature
//! (`docs/superpowers/specs/2026-08-07-wallet-export-design.md` §6,
//! "Negative tests updated, not weakened").
//!
//! SPEC §24.3 used to ban the literal `xpub` from every rendered line in
//! the product. The export feature scopes — but does not weaken — that
//! ban:
//!
//! * `xpub`/`ypub`/`zpub` may appear in a string literal **only** in the
//!   two export-branch screen modules, which is where the user asked for
//!   an extended public key and was warned about it. Every other module
//!   in `seed-flow` keeps the ban verbatim.
//! * `xprv`, `private key`, `chain code`, `pubkey`, `seed phrase` and
//!   `mnemonic word` stay banned **everywhere, with an empty allowlist** —
//!   including in the export modules. [`xprv_class_allowlist_is_empty`]
//!   asserts that emptiness explicitly, so a future edit cannot quietly
//!   add an exemption for one of them the way this file adds one for
//!   `xpub`.
//!
//! # What is scanned
//!
//! Every `.rs` file under `crates/seed-flow/src`, restricted to the
//! **production** half of each file (everything before the first
//! `#[cfg(test)]`) and to the contents of its **string literals**. That
//! is deliberately narrower than "the file text":
//!
//! * Doc comments legitimately discuss what must not be shown — this very
//!   sentence would trip a naive text scan.
//! * Test code legitimately names the artifacts it forbids (every screen
//!   module has a `never_mentions_...` test whose ban list spells them
//!   out), and test code does not ship.
//!
//! A string literal in production code, by contrast, is the only thing
//! that can *become* a drawn line: every screen in this crate draws
//! `&'static str` constants and values, never text assembled from
//! comments. The per-screen `never_mentions_...` unit tests cover the
//! rendered-row path from the other side (they walk each screen's real
//! `build_rows` output); this file is the crate-wide backstop that
//! catches a new module before anyone writes a row-walking test for it.

use std::fs;
use std::path::{Path, PathBuf};

/// Literals that are banned everywhere *except* in the allowlisted
/// modules below — the extended-public-key prefixes the export screens
/// exist to display.
const SCOPED_LITERALS: &[&str] = &["xpub", "ypub", "zpub"];

/// Literals banned in every module with **no exemption whatsoever**.
/// This list must never intersect [`ALLOWLIST`]; the intersection is
/// asserted empty by [`xprv_class_allowlist_is_empty`].
const ZERO_ALLOWLIST_LITERALS: &[&str] =
    &["xprv", "private key", "chain code", "pubkey", "seed phrase", "mnemonic word"];

/// The complete set of (module, literal) exemptions, relative to
/// `crates/seed-flow/src`. Exhaustive: any string literal containing a
/// [`SCOPED_LITERALS`] entry in a module not paired with it here fails
/// [`scoped_literals_appear_only_in_the_export_screens`].
const ALLOWLIST: &[(&str, &str)] = &[
    ("screens/export.rs", "xpub"),
    ("screens/export.rs", "ypub"),
    ("screens/export.rs", "zpub"),
    ("screens/export_warning.rs", "xpub"),
];

/// The `seed-flow` source tree, resolved from this suite's own manifest
/// so the test works from any invocation directory.
fn flow_src() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../crates/seed-flow/src")
}

/// Everything in `src` before the first `#[cfg(test)]` — the half that
/// actually ships.
fn production_half(src: &str) -> &str {
    src.split("#[cfg(test)]").next().unwrap_or("")
}

/// Extract the contents of every string literal in `src`, skipping line
/// comments (which may contain quotes) and honouring backslash escapes.
///
/// Deliberately simple, and deliberately over-inclusive rather than
/// under-inclusive: a construct it mis-parses can only cause it to scan
/// *more* text, never less, so it cannot silently miss a banned literal.
/// Raw strings (`r"..."`) are not special-cased — their contents are
/// still captured, because the opening `"` starts a literal either way.
fn string_literals(src: &str) -> Vec<String> {
    let bytes = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            // Line comment: skip to end of line.
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            // Char literal: skip it, so `'"'` cannot open a string.
            b'\'' if bytes.get(i + 1) == Some(&b'"') && bytes.get(i + 2) == Some(&b'\'') => {
                i += 3;
            }
            b'"' => {
                i += 1;
                let start = i;
                while i < bytes.len() {
                    if bytes[i] == b'\\' {
                        i += 2;
                        continue;
                    }
                    if bytes[i] == b'"' {
                        break;
                    }
                    i += 1;
                }
                let end = i.min(bytes.len());
                if let Some(text) = src.get(start..end) {
                    out.push(text.to_string());
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    out
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Every scanned file as `(module path relative to src/, production
/// string literals)`.
fn scanned_modules() -> Vec<(String, Vec<String>)> {
    let root = flow_src();
    let mut files = Vec::new();
    collect_rs_files(&root, &mut files);
    assert!(
        files.len() > 15,
        "source scan found only {} files under {root:?} — the scanner is broken, not the code",
        files.len()
    );

    files
        .into_iter()
        .map(|path| {
            let rel = path
                .strip_prefix(&root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            let text = fs::read_to_string(&path).expect("read source file");
            (rel, string_literals(production_half(&text)))
        })
        .collect()
}

// ============================================================================

/// The scoped ban: `xpub`/`ypub`/`zpub` may be drawn only by the export
/// branch's own two screens.
#[test]
fn scoped_literals_appear_only_in_the_export_screens() {
    let mut hits = 0usize;
    for (module, literals) in scanned_modules() {
        for literal in &literals {
            let lower = literal.to_lowercase();
            for &banned in SCOPED_LITERALS {
                if !lower.contains(banned) {
                    continue;
                }
                hits += 1;
                // (No word-boundary relaxation here: `xpub`/`ypub`/`zpub`
                // as a *substring* of a longer token is exactly as
                // disclosing as the bare word, so any occurrence counts.)
                assert!(
                    ALLOWLIST.contains(&(module.as_str(), banned)),
                    "{module} has a string literal containing {banned:?} ({literal:?}), and \
                     ({module:?}, {banned:?}) is not in the export-screen allowlist. \
                     SPEC §24.3: extended public keys may be named only on the opt-in \
                     export screens, behind their warning screen."
                );
            }
        }
    }
    // The scan must actually be finding things, or it proves nothing.
    assert!(hits >= 4, "the scoped-literal scan found only {hits} hits — is it still working?");
}

/// The unscoped ban: no module, export screens included, may name an
/// xprv-class artifact in a string literal.
///
/// The single documented exception is a *denial* — the export screen's
/// `Watch-only export - contains no private key` caption and the warning
/// screen's `They contain no private key.` — which is checked here to be
/// exactly that: the phrase must be immediately preceded by `no `.
#[test]
fn xprv_class_literals_are_banned_in_every_module() {
    let mut scanned = 0usize;
    for (module, literals) in scanned_modules() {
        scanned += 1;
        for literal in &literals {
            let lower = literal.to_lowercase();
            for &banned in ZERO_ALLOWLIST_LITERALS {
                // EVERY occurrence, not just the first: a literal whose
                // first `private key` is a denial and whose second is not
                // would otherwise sail through.
                let mut from = 0usize;
                while let Some(rel) = lower[from..].find(banned) {
                    let at = from + rel;
                    assert!(
                        banned == "private key" && lower[..at].ends_with("no "),
                        "{module} has a string literal containing {banned:?} at byte {at} \
                         ({literal:?}). SPEC §24.3: this ban has no allowlist anywhere in \
                         the product."
                    );
                    from = at + banned.len();
                }
            }
        }
    }
    assert!(scanned > 15, "only {scanned} modules scanned");
}

/// The explicit statement the wallet-export design asks for: the
/// xprv-class ban's allowlist is **empty**. Scoping `xpub` must never
/// have been a precedent for scoping these.
#[test]
fn xprv_class_allowlist_is_empty() {
    for (module, literal) in ALLOWLIST {
        assert!(
            !ZERO_ALLOWLIST_LITERALS.contains(literal),
            "({module:?}, {literal:?}) exempts an xprv-class literal; that allowlist must \
             stay empty (wallet-export design §6)"
        );
    }
    // Stated the other way round too, so the assertion survives a
    // refactor of either list.
    let exempted: Vec<&str> =
        ZERO_ALLOWLIST_LITERALS.iter().copied().filter(|l| ALLOWLIST.iter().any(|(_, a)| a == l)).collect();
    assert!(exempted.is_empty(), "xprv-class literals with an allowlist entry: {exempted:?}");
}

/// The allowlist itself must not rot: every entry must name a module that
/// exists and must actually be exercised by that module. An allowlist
/// entry nobody needs is an exemption waiting to be misused.
#[test]
fn every_allowlist_entry_is_real_and_used() {
    let modules = scanned_modules();
    for (module, literal) in ALLOWLIST {
        let found = modules
            .iter()
            .find(|(name, _)| name == module)
            .unwrap_or_else(|| panic!("allowlisted module {module:?} does not exist"));
        assert!(
            found.1.iter().any(|l| l.to_lowercase().contains(literal)),
            "allowlist entry ({module:?}, {literal:?}) is unused — remove it"
        );
    }
}

/// Sanity check on the scanner itself: it must see through a doc comment
/// (not scan it), see into a string literal, and not be fooled by an
/// escaped quote.
#[test]
fn the_string_literal_scanner_behaves() {
    let src = r#"
/// This doc comment says xprv and must NOT be scanned.
// Nor this line comment, which says xpub.
const A: &str = "visible xpub";
const B: &str = "escaped \" quote, still one literal";
const C: char = '"';
const D: &str = "after the char literal";
"#;
    let literals = string_literals(src);
    assert!(literals.iter().any(|l| l == "visible xpub"), "{literals:?}");
    assert!(literals.iter().any(|l| l.contains("still one literal")), "{literals:?}");
    assert!(literals.iter().any(|l| l == "after the char literal"), "{literals:?}");
    assert!(
        !literals.iter().any(|l| l.contains("must NOT be scanned")),
        "doc comments must not be scanned: {literals:?}"
    );

    // And the production-half split really drops the test module.
    let split = production_half("const A: &str = \"ok\";\n#[cfg(test)]\nmod t { const B: &str = \"xprv\"; }");
    assert!(!split.contains("xprv"));
}
