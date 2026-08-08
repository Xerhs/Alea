//! Enforces SPEC §3.1 (role palette): "Every drawn color is a named
//! role. Callers never pass raw pixel values." Concretely: no
//! `0x00RR_GGBB`-shaped color literal may appear on a color-bearing line
//! (one mentioning `fg:`/`bg:`/`Style`/`color`) anywhere in this
//! workspace's rendering crates except inside `theme.rs` itself.
//!
//! Host-only (uses `std::fs`); this file is a `tests/` integration
//! binary, always compiled with `std` regardless of the library crate's
//! `#![no_std]`. Walks `seed-gop-ui`, `seed-flow` and `seed-desktop-test`
//! source trees relative to `CARGO_MANIFEST_DIR` so it works from any
//! invocation directory, not just the workspace root.

use std::fs;
use std::path::{Path, PathBuf};

/// Files exempt by name: `theme.rs` *is* the palette (the literals live
/// there by construction) and `glyphs.rs` holds the embedded bitmap font
/// (2-hex-digit byte literals, e.g. `0x3e`) — never the 6-hex-digit
/// `0x00RR_GGBB` shape this check looks for, but named here defensively
/// per the task brief in case the glyph table's format ever changes.
const EXEMPT_FILENAMES: &[&str] = &["theme.rs", "glyphs.rs"];

/// Scan `line` for a `0x00` + 2 hex digits + `_` + 4 hex digits literal
/// (e.g. `0x00FF_FFFF`), by hand rather than pulling in the `regex`
/// crate for one pattern.
fn line_has_color_literal(line: &str) -> bool {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i + 4 <= bytes.len() {
        if &bytes[i..i + 4] == b"0x00" {
            let rest = &bytes[i + 4..];
            if rest.len() >= 7
                && rest[0..2].iter().all(u8::is_ascii_hexdigit)
                && rest[2] == b'_'
                && rest[3..7].iter().all(u8::is_ascii_hexdigit)
            {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Is this a "color-bearing" line per the brief's filter — one that
/// plausibly assigns a color, not e.g. a bitmap byte row or a pixel-mask
/// constant?
fn line_is_color_bearing(line: &str) -> bool {
    line.contains("fg:") || line.contains("bg:") || line.contains("Style") || line.contains("color")
}

/// Recursively collect every `.rs` file under `dir` (no-op if `dir`
/// doesn't exist, so a missing sibling crate fails loudly via an empty
/// scan rather than panicking the harness).
fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_raw_color_literals_outside_theme() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let roots = [
        Path::new(manifest_dir).join("src"),
        Path::new(manifest_dir).join("../seed-flow/src"),
        Path::new(manifest_dir).join("../seed-desktop-test/src"),
    ];

    let mut files = Vec::new();
    for root in &roots {
        assert!(root.is_dir(), "expected source dir at {}", root.display());
        collect_rs_files(root, &mut files);
    }

    let mut violations = Vec::new();
    for file in &files {
        let filename = file.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if EXEMPT_FILENAMES.contains(&filename) {
            continue;
        }
        let contents = fs::read_to_string(file).unwrap_or_default();
        for (lineno, line) in contents.lines().enumerate() {
            if line_is_color_bearing(line) && line_has_color_literal(line) {
                violations.push(format!("{}:{}: {}", file.display(), lineno + 1, line.trim()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "raw color literal(s) found outside seed_gop_ui::theme (SPEC §3.1 role palette):\n{}",
        violations.join("\n")
    );
}
