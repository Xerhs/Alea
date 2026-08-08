//! Launcher item (5) — About / audit-status (SPEC_MAIN_MENU.md §4.1 item
//! 5): version, immutable build id, edition string (`Alea Test
//! (desktop)`), the watermark meaning (SPEC §4.3), and pointers to
//! `REPRODUCING.md` / `SECURITY.md` / the audit-status of the isolation
//! scanners (SPEC §28, SPEC_COMPAT §9). Read-only; no secret, no network
//! (SPEC §25). Returns to the launcher on `Esc` (§4.5).
//!
//! # Version + build id
//!
//! Mirrors the pattern `seed-uefi-production::release` already uses for
//! the same SPEC §4.1 "release version + immutable build identifier"
//! display, scoped to this crate's own `Cargo.toml`/build environment
//! rather than importing that (production-owned, read-only from here)
//! module: [`RELEASE_VERSION`] is this crate's own `CARGO_PKG_VERSION`
//! (always set by Cargo, so a plain `env!` is correct), and
//! [`BUILD_ID`] reads the same `ALEA_BUILD_ID` build-time environment
//! variable the release pipeline is expected to set
//! (`IMPLEMENTATION_MAP.md` WP-32), falling back to a fixed, unmistakable
//! placeholder so an ordinary local `cargo build` still succeeds and
//! stays reproducible build-to-build.

use seed_flow::chrome::{self, KeyHint};
use seed_flow::output::{FbTextOutput, TextOutput};
use seed_gop_ui::font::scrub_fill;

use crate::channel_keys::ChannelKeys;
use crate::shared_screen::SharedFramebuffer;

/// This screen's single footer hint (SPEC_MAIN_MENU.md §4.1 item 5's "any
/// key returns" convention, mirrored by [`run`]'s own `keys.recv()`).
const RETURN_HINT: [KeyHint; 1] = [KeyHint { key: "any key", label: "Return to the menu", enabled: true, danger: false }];

/// SPEC §4.1 "release version" — this crate's own `Cargo.toml` `version`
/// field. Always present at compile time.
pub const RELEASE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Fixed value substituted when the release pipeline has not injected a
/// real build identifier (see [`BUILD_ID`]). Fixed length and an
/// unmistakable `UNSET` prefix so it can never be confused with a
/// genuine pipeline-issued identifier.
pub const UNSET_BUILD_ID_PLACEHOLDER: &str = "UNSET-LOCAL-BUILD-0000000000000000";

/// SPEC §4.1 "immutable build identifier". Reads `ALEA_BUILD_ID` at
/// build time via `option_env!` (never a bare `env!`, so a build outside
/// the release pipeline — including this work package's own DoD check —
/// still compiles); falls back to [`UNSET_BUILD_ID_PLACEHOLDER`], which
/// is fixed and identical across every unofficial build and therefore
/// never itself breaks build reproducibility.
pub const BUILD_ID: &str = match option_env!("ALEA_BUILD_ID") {
    Some(id) => id,
    None => UNSET_BUILD_ID_PLACEHOLDER,
};

/// SPEC §4.3 edition string, matching `crate::window`'s own OS-window
/// title (`"Alea Test (desktop rehearsal)"`) and `crate::ceremony`'s
/// welcome line ("desktop rehearsal edition").
pub const EDITION: &str = "Alea Test (desktop)";

/// Entry point for launcher item (5) (SPEC_MAIN_MENU.md §6.2 routing:
/// `launcher::about::run(fb, keys, ...)`). Takes the same
/// [`SharedFramebuffer`]/[`TextOutput`] backend and the same
/// [`ChannelKeys`] key source the ceremony and every other launcher tool
/// use — no new thread, no new channel (§4.5).
///
/// Renders the info screen once and returns to the launcher on any key
/// (mirroring `crate::check::run`'s own "any key returns" convention);
/// `Esc` is one of the keys that returns, per §4.5.
pub fn run(fb: &mut SharedFramebuffer, keys: &mut ChannelKeys) {
    scrub_fill(fb, 0);
    chrome::draw_header_plain(fb, "ALEA -- About / audit-status", BUILD_ID);
    {
        let mut out = FbTextOutput::at(fb, chrome::content_top());
        render_about(&mut out);
    }
    chrome::draw_footer(fb, &RETURN_HINT);
    let _ = keys.recv();
}

/// Render the About / audit-status screen's content (SPEC_MAIN_MENU.md
/// §4.1 item 5's exact content list: version, immutable build id,
/// edition, watermark meaning, audit-doc pointers) -- chrome (header,
/// footer, screen clear) is [`run`]'s job, not this function's, so it is
/// also directly host-testable against any [`TextOutput`] double (§6.3)
/// with no `Framebuffer` involved.
fn render_about(out: &mut dyn TextOutput) {
    out.write_line("About / audit-status");
    out.write_line("");
    out.write_line(&format!("Release version:  {RELEASE_VERSION}"));
    out.write_line(&format!("Build identifier: {BUILD_ID}"));
    out.write_line(&format!("Edition:          {EDITION}"));
    out.write_line("");
    out.write_line("What the watermark means (SPEC \u{a7}4.3):");
    out.write_line("  Every screen in this edition -- the menu, every tool, every");
    out.write_line("  rehearsal phrase -- carries a permanent on-screen watermark");
    out.write_line("  stating that generated phrases come from a fixed public test");
    out.write_line("  transcript and are never real keys. It is drawn fresh every");
    out.write_line("  frame by the window compositor, on top of whatever this menu");
    out.write_line("  or any tool renders, so it cannot be scrolled away or covered.");
    out.write_line("");
    out.write_line("Audit / reproducibility docs:");
    out.write_line("  REPRODUCING.md -- how to rebuild this binary and compare it");
    out.write_line("    bit-for-bit against a published release.");
    out.write_line("  SECURITY.md -- the security model, threat boundaries, and how");
    out.write_line("    to report a finding.");
    out.write_line("  SPEC.md \u{a7}28 / SPEC_COMPAT.md \u{a7}9 -- the production/test and");
    out.write_line("    seed-compat isolation rules this desktop edition operates");
    out.write_line("    under, and the binary-policy scanners that enforce them.");
    out.write_line("");
    out.write_line("Press any key (or Esc) to return to the menu.");
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RecordingOutput {
        lines: Vec<String>,
    }
    impl RecordingOutput {
        fn new() -> Self {
            Self { lines: Vec::new() }
        }
    }
    impl TextOutput for RecordingOutput {
        fn write_line(&mut self, line: &str) {
            self.lines.push(line.to_string());
        }
        fn clear(&mut self) {
            self.lines.clear();
        }
    }

    #[test]
    fn screen_identifies_the_edition() {
        let mut out = RecordingOutput::new();
        render_about(&mut out);
        let joined = out.lines.join("\n");
        assert!(joined.contains("Alea Test (desktop)"));
    }

    #[test]
    fn screen_shows_release_version_and_build_id() {
        let mut out = RecordingOutput::new();
        render_about(&mut out);
        let joined = out.lines.join("\n");
        assert!(joined.contains(RELEASE_VERSION));
        assert!(joined.contains(BUILD_ID));
    }

    #[test]
    fn build_id_is_never_empty_even_without_the_pipeline_env_var() {
        // Whatever `ALEA_BUILD_ID` resolved to at compile time (real
        // pipeline value or the fixed placeholder), it is never empty --
        // an empty build id would be indistinguishable from "not shown".
        assert!(!BUILD_ID.is_empty());
    }

    #[test]
    fn screen_explains_the_watermark_meaning() {
        let mut out = RecordingOutput::new();
        render_about(&mut out);
        let joined = out.lines.join("\n");
        assert!(joined.to_lowercase().contains("watermark"));
        assert!(joined.contains("fixed public test"));
    }

    #[test]
    fn screen_points_to_the_audit_docs() {
        let mut out = RecordingOutput::new();
        render_about(&mut out);
        let joined = out.lines.join("\n");
        assert!(joined.contains("REPRODUCING.md"));
        assert!(joined.contains("SECURITY.md"));
    }

    #[test]
    fn any_key_including_escape_returns() {
        use std::sync::mpsc::channel;
        let (tx, rx) = channel();
        tx.send(crate::channel_keys::KeyMsg::Escape).unwrap();
        let mut keys = ChannelKeys::new(rx);
        let fb = SharedFramebuffer::new(64, 64);
        let mut fb = fb;
        // `run` blocks for exactly one key then returns; this must not
        // hang the test.
        run(&mut fb, &mut keys);
    }
}
