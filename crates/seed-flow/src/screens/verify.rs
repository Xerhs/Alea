//! Stage-7 Verify screen (design doc §4 "Stage 7 — VERIFY & FINISH").
//!
//! Replaces the SPEC §24.1 verification *offer* screen: rather than
//! asking "view or skip" on a screen of its own, this screen always shows
//! the `RE-ENTRY MATCHED` verdict and the master fingerprint, and reveals
//! the four first receive addresses **only after `[V]`** — an inline
//! toggle that preserves §24.1's "optional and skippable" privacy
//! property at zero extra screens (SPEC amendment §24.1/§24.5).
//!
//! # Leak posture
//!
//! Structurally identical to [`crate::flow_secret::verification`]'s: the
//! only value input this module can reach is a public
//! [`VerificationValues`] (master fingerprint + four first receive
//! addresses). There is no code path from which a BIP39 seed, an extended
//! private key, a raw chain code or a bare public key could reach a drawn
//! line, and every static string is scanned by
//! [`tests::never_mentions_xpub_xprv_or_seed`] in *both* toggle states.
//! Copy is reused by reference from `flow_secret::verification` — the
//! fingerprint gloss, the passphrase-aware address intro and the caveat
//! block — so this screen and the module it will replace can never drift
//! apart in wording.
//!
//! All copy here is plain ASCII: the embedded 8x16 font covers
//! `0x20..=0x7E` only, so a typographic dash would render as a blank
//! cell. The design doc's `RE-ENTRY MATCHED -- every word you typed
//! matched the generated phrase.` verdict is therefore rendered as a 2x
//! [`VERDICT_HEADING`] plus a 1x [`VERDICT_GLOSS`] row, which is also how
//! the design doc's own layout sketch shows it (verdict in `OK`, 2x).

use core::fmt::Write as _;

use seed_core::contracts::{Framebuffer, PathStandard};
use seed_core::pipeline::VerificationValues;
use seed_gop_ui::font::{draw_text, draw_text_scaled, GLYPH_HEIGHT, GLYPH_WIDTH};
use seed_gop_ui::layout::{LINE_PITCH, MARGIN_X, MAX_COLS_AT_FLOOR};
use seed_gop_ui::theme;
use seed_platform_x86::input::InputEvent;

use crate::chrome::{self, Chrome, KeyHint};
use crate::flow_secret::verification::{
    hex8, wallet_label, ADDRESS_INTRO, ADDRESS_INTRO_PP, CAVEAT_LINE_1, CAVEAT_LINE_2,
    CAVEAT_LINE_2_PP, CAVEAT_LINE_3, CAVEAT_LINE_4, FINGERPRINT_GLOSS, FINGERPRINT_LABEL,
    LABEL_FIELD,
};
use crate::output::LineBuf;

// ============================================================================
// Copy
// ============================================================================

/// The design doc §4 verdict, drawn 2x in [`theme::OK`].
pub const VERDICT_HEADING: &str = "RE-ENTRY MATCHED";

/// The verdict's own gloss row (see the module doc comment for why the
/// design doc's single em-dashed sentence is split in two here).
pub const VERDICT_GLOSS: &str = "Every word you typed matched the generated phrase.";

// FINGERPRINT_LABEL ("Master fingerprint", the caption preceding the 2x
// chunked master fingerprint below) is imported from
// `crate::flow_secret::verification` above — see that module's doc
// comment (Task 19 fingerprint-label unification) for why the one
// spelling lives there instead of being redefined per screen.

/// Design doc §4: the reveal caption, "stating why" the addresses are on
/// screen. Split across two rows to fit the 800x600 floor's 96 columns.
pub const REVEAL_CAPTION_1: &str =
    "Addresses are public - but anyone who sees them can watch your balance.";
/// Second row of the reveal caption — see [`REVEAL_CAPTION_1`].
pub const REVEAL_CAPTION_2: &str = "Shown because you pressed [V].";

/// Shown in place of the address block while the reveal toggle is off.
/// Deliberately carries no `[K]` hint of its own: the footer key bar is
/// the only place key hints live (design doc §3.3).
pub const HIDDEN_LINE: &str = "Addresses stay hidden until you ask for them.";

/// 1-based ceremony stage this screen belongs to (design doc §4).
pub const STAGE: u8 = 7;

/// The Stage-7 footer key set (design doc §4).
///
/// The `[X]` label is `Export watch-only`, per the design doc's amended
/// §4 footer line: it names the *user outcome* (a wallet that can watch
/// but never spend) rather than the artifact, which reads better for a
/// first-time user and keeps the literal `xpub` out of anything this
/// screen draws — this screen is held to a leak-string ban that forbids
/// it (see [`tests::never_mentions_xpub_xprv_or_seed`]). The export
/// branch's own screens name what they export.
pub const HINTS: [KeyHint; 5] = [
    KeyHint { key: "Enter", label: "Finish", enabled: true, danger: false },
    KeyHint { key: "V", label: "Show/Hide addresses", enabled: true, danger: false },
    KeyHint { key: "M", label: "Grid", enabled: true, danger: false },
    KeyHint { key: "B", label: "Custom path", enabled: true, danger: false },
    KeyHint { key: "X", label: "Export watch-only", enabled: true, danger: false },
];

// ============================================================================
// State
// ============================================================================

/// Which of the Stage-7 footer actions the user took.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// `[Enter]` — done verifying; advance to the Finish screen.
    Finish,
    /// `[M]` — open the bounded-grid "more derivation options" menu.
    Grid,
    /// `[B]` — open the structured custom-path builder.
    CustomPath,
    /// `[X]` — open the opt-in wallet-export branch.
    Export,
}

/// The Verify screen's entire mutable state: whether the inline address
/// reveal is currently on. Not secret-bearing (a single public boolean),
/// so the ordinary derives apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VerifyState {
    /// `true` once the user has pressed `[V]`; toggled by every later
    /// `[V]`. Starts `false` — addresses are hidden by default (design
    /// doc §4: "Addresses render **only after `[V]`**").
    pub show_addresses: bool,
}

impl VerifyState {
    /// A fresh screen state: addresses hidden.
    #[must_use]
    pub const fn new() -> Self {
        Self { show_addresses: false }
    }

    /// Fold one keystroke into the screen. Returns `Some(outcome)` when
    /// the key leaves this screen, `None` when it was handled in place
    /// (the `[V]` toggle) or ignored. Case-insensitive on letters, like
    /// every other key handler in this crate.
    pub fn handle_key(&mut self, k: InputEvent) -> Option<VerifyOutcome> {
        match k {
            InputEvent::Enter => Some(VerifyOutcome::Finish),
            InputEvent::Char(c) if c.eq_ignore_ascii_case(&'v') => {
                self.show_addresses = !self.show_addresses;
                None
            }
            InputEvent::Char(c) if c.eq_ignore_ascii_case(&'m') => Some(VerifyOutcome::Grid),
            InputEvent::Char(c) if c.eq_ignore_ascii_case(&'b') => Some(VerifyOutcome::CustomPath),
            InputEvent::Char(c) if c.eq_ignore_ascii_case(&'x') => Some(VerifyOutcome::Export),
            _ => None,
        }
    }
}

// ============================================================================
// Value chunking (design doc §3.3 "Value chunking")
// ============================================================================

/// Fixed capacity of a chunked-value scratch buffer: an
/// [`seed_core::contracts::AddressBuf`]-sized value (92 bytes) plus its
/// worst-case 22 inserted spaces, rounded up.
pub const CHUNK_CAP: usize = 128;

/// Copy `src` into `out`, inserting one space after every 4 source bytes
/// (`"73c5da0a"` -> `"73c5 da0a"`), and return the number of bytes
/// written. Display-only: the underlying value is unchanged, and the
/// caller keeps the original.
///
/// # PUBLIC VALUES ONLY
///
/// This function MUST only ever be handed a *public* value — a master
/// fingerprint's hex digits or a receive address. It must never touch a
/// secret-bearing buffer (a BIP39 seed, entropy, an extended private key,
/// a chain code, a mnemonic word or any accumulated re-entry input):
/// chunking rewrites a value into a second buffer that the caller then
/// keeps alive across a draw, which is exactly the copy discipline SPEC
/// §20 forbids for secret material. The design doc states the same rule
/// (§8: "chunking applies only to values from the public-value set"), and
/// [`tests::chunk4_call_sites_are_public_values_only`] enforces it by
/// scanning this crate's source for every call site.
///
/// Never panics: writing stops at `out`'s length, so an undersized `out`
/// truncates rather than indexing out of bounds.
///
/// Crate-visible rather than fully `pub`: every caller the design
/// anticipates — this screen and the `[X]` export branch
/// ([`crate::screens::export`], which chunks the same master
/// fingerprint) — lives in this crate, and the narrower visibility keeps
/// the call-site scan above a complete account of who can reach it.
/// Widen it only when a real out-of-crate caller appears.
pub(crate) fn chunk4(src: &[u8], out: &mut [u8]) -> usize {
    let mut n = 0usize;
    for (i, &b) in src.iter().enumerate() {
        if i > 0 && i % 4 == 0 {
            if n >= out.len() {
                return n;
            }
            out[n] = b' ';
            n += 1;
        }
        if n >= out.len() {
            return n;
        }
        out[n] = b;
        n += 1;
    }
    n
}

// ============================================================================
// Layout
// ============================================================================

/// Height of one 1x content row.
const ROW_1X: u32 = LINE_PITCH;

/// Height of one 2x content row: the 2x glyph box plus the same leading
/// [`LINE_PITCH`] adds to a 1x row, so both scales share one rhythm.
const ROW_2X: u32 = GLYPH_HEIGHT * 2 + (LINE_PITCH - GLYPH_HEIGHT);

/// Height of a blank separator row (half a line pitch).
const GAP: u32 = LINE_PITCH / 2;

/// Gap, in 1x glyph cells, between the fingerprint row's three runs.
const FP_RUN_GAP_CELLS: u32 = 2;

/// Upper bound on the rows either toggle state emits (the reveal state
/// draws 17). Fixed, so [`build_rows`] allocates nothing.
const MAX_ROWS: usize = 20;

/// One content row. Every drawable string this screen owns is reachable
/// from a `Row`, so the fit audit and the leak scan both walk exactly
/// what [`draw_rows`] draws — there is no second, drift-prone copy of the
/// screen's text.
#[derive(Clone, Copy)]
enum Row<'a> {
    /// A blank separator.
    Gap,
    /// A single left-aligned text run.
    Line { text: &'a str, scale: u32, color: u32 },
    /// The composite fingerprint row: [`FINGERPRINT_LABEL`] (1x,
    /// `CAPTION`), the chunked fingerprint (2x, `TEXT`) and
    /// [`FINGERPRINT_GLOSS`] (1x, `CAPTION`), all on one row.
    Fingerprint { value: &'a str },
}

impl Row<'_> {
    /// The vertical advance this row consumes.
    const fn height(self) -> u32 {
        match self {
            Row::Gap => GAP,
            Row::Line { scale, .. } => {
                if scale >= 2 {
                    ROW_2X
                } else {
                    ROW_1X
                }
            }
            Row::Fingerprint { .. } => ROW_2X,
        }
    }
}

/// Fill `fp` with the chunked master fingerprint and `addr_lines` with
/// the four `wallet_label` + chunked-address rows, then return this
/// screen's row list for `st`.
///
/// Presentation-only: reads nothing but the public `values`, performs no
/// derivation. Shared by [`render`] and every test, so what ships is
/// exactly what the tests measure (the same discipline
/// `flow_secret::verification::build_preview` already follows).
fn build_rows<'a>(
    st: &VerifyState,
    values: &VerificationValues,
    passphrase_set: bool,
    fp: &'a mut LineBuf,
    addr_lines: &'a mut [LineBuf; 4],
) -> ([Row<'a>; MAX_ROWS], usize) {
    let fp_hex = hex8(values.master_fingerprint);
    let mut fp_chunked = [0u8; CHUNK_CAP];
    let n = chunk4(&fp_hex, &mut fp_chunked);
    let _ = fp.write_str(core::str::from_utf8(&fp_chunked[..n]).unwrap_or("????????"));

    // Ascending display order (SPEC_WALLET_PREVIEW OQ-2):
    // Legacy -> Nested -> Native -> Taproot.
    const ORDER: [PathStandard; 4] =
        [PathStandard::Bip44, PathStandard::Bip49, PathStandard::Bip84, PathStandard::Bip86];
    for (slot, standard) in addr_lines.iter_mut().zip(ORDER.iter()) {
        let addr = values
            .addresses
            .iter()
            .find(|a| a.standard == *standard)
            .map(|a| a.address.as_str().unwrap_or("?"))
            .unwrap_or("?");
        let mut chunked = [0u8; CHUNK_CAP];
        let n = chunk4(addr.as_bytes(), &mut chunked);
        let chunked = core::str::from_utf8(&chunked[..n]).unwrap_or("?");
        let label = wallet_label(*standard);
        // Pad the label into the shared 32-column field, except where a
        // chunked address is long enough (taproot) that the padded row
        // would clip at the floor's 96 columns — then a single space
        // separates the two. Deterministic per standard; asserted by
        // `address_rows_fit_the_floor`.
        if label.len().max(LABEL_FIELD) + chunked.len() <= MAX_COLS_AT_FLOOR {
            let _ = write!(slot, "{label:<width$}{chunked}", width = LABEL_FIELD);
        } else {
            let _ = write!(slot, "{label} {chunked}");
        }
    }

    let mut rows = [Row::Gap; MAX_ROWS];
    let mut n = 0usize;
    let mut push = |row: Row<'a>| {
        if n < MAX_ROWS {
            rows[n] = row;
            n += 1;
        }
    };

    push(Row::Line { text: VERDICT_HEADING, scale: 2, color: theme::OK });
    push(Row::Line { text: VERDICT_GLOSS, scale: 1, color: theme::TEXT });
    push(Row::Gap);
    push(Row::Fingerprint { value: fp.as_str() });
    push(Row::Gap);

    if st.show_addresses {
        push(Row::Line {
            text: if passphrase_set { ADDRESS_INTRO_PP } else { ADDRESS_INTRO },
            scale: 1,
            color: theme::TEXT,
        });
        for line in addr_lines.iter() {
            push(Row::Line { text: line.as_str(), scale: 1, color: theme::TEXT });
        }
        push(Row::Line { text: REVEAL_CAPTION_1, scale: 1, color: theme::CAPTION });
        push(Row::Line { text: REVEAL_CAPTION_2, scale: 1, color: theme::CAPTION });
    } else {
        push(Row::Line { text: HIDDEN_LINE, scale: 1, color: theme::CAPTION });
    }

    push(Row::Gap);
    for line in [
        CAVEAT_LINE_1,
        if passphrase_set { CAVEAT_LINE_2_PP } else { CAVEAT_LINE_2 },
        CAVEAT_LINE_3,
        CAVEAT_LINE_4,
    ] {
        push(Row::Line { text: line, scale: 1, color: theme::CAPTION });
    }

    (rows, n)
}

/// x origin of the fingerprint row's 2x value run.
const fn fp_value_x() -> u32 {
    MARGIN_X + (FINGERPRINT_LABEL.len() as u32 + FP_RUN_GAP_CELLS) * GLYPH_WIDTH
}

/// x origin of the fingerprint row's trailing gloss run, given the
/// chunked value's length in characters.
const fn fp_gloss_x(value_len: u32) -> u32 {
    fp_value_x() + (value_len + FP_RUN_GAP_CELLS) * GLYPH_WIDTH * 2
}

/// Draw `rows` from [`chrome::content_top`] downwards.
fn draw_rows(fb: &mut dyn Framebuffer, rows: &[Row<'_>]) {
    let mut y = chrome::content_top();
    for row in rows {
        match *row {
            Row::Gap => {}
            Row::Line { text, scale, color } => {
                draw_text_scaled(fb, MARGIN_X, y, text, theme::on_bg(color), scale);
            }
            Row::Fingerprint { value } => {
                // The two 1x runs sit half a glyph lower so they read as
                // centered against the 2x value between them.
                let inset = y + GLYPH_HEIGHT / 2;
                draw_text(fb, MARGIN_X, inset, FINGERPRINT_LABEL, theme::on_bg(theme::CAPTION));
                draw_text_scaled(fb, fp_value_x(), y, value, theme::on_bg(theme::TEXT), 2);
                draw_text(
                    fb,
                    fp_gloss_x(value.len() as u32),
                    inset,
                    FINGERPRINT_GLOSS,
                    theme::on_bg(theme::CAPTION),
                );
            }
        }
        y += row.height();
    }
}

/// Render the Stage-7 Verify screen: chrome shell, verdict, fingerprint,
/// the address block if `st.show_addresses`, the caveats, and the
/// five-hint footer.
///
/// Clears the framebuffer first (SPEC §12.2 "Fixed layouts"): this screen
/// follows the hidden re-entry screen, whose content would otherwise show
/// through.
pub fn render(
    fb: &mut dyn Framebuffer,
    st: &VerifyState,
    v: &VerificationValues,
    passphrase_set: bool,
    build: &'static str,
) {
    seed_gop_ui::font::scrub_fill(fb, theme::BG);
    chrome::draw_header(fb, &Chrome { stage: STAGE, sub: None, build });

    let mut fp = LineBuf::new();
    let mut addr_lines: [LineBuf; 4] = core::array::from_fn(|_| LineBuf::new());
    let (rows, n) = build_rows(st, v, passphrase_set, &mut fp, &mut addr_lines);
    draw_rows(fb, &rows[..n]);

    chrome::draw_footer(fb, &HINTS);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    use std::path::{Path, PathBuf};
    use std::string::{String, ToString};
    use std::vec::Vec;

    use seed_core::contracts::AddressBuf;
    use seed_core::pipeline::StandardAddress;
    use seed_gop_ui::gop::mode::{MIN_HEIGHT, MIN_WIDTH};

    const BUILD: &str = "test-build";

    struct VecFb {
        w: u32,
        h: u32,
        buf: Vec<u32>,
    }
    impl VecFb {
        fn new(w: u32, h: u32) -> Self {
            Self { w, h, buf: std::vec![0u32; (w as usize) * (h as usize)] }
        }
        fn contains(&self, color: u32) -> bool {
            self.buf.iter().any(|&p| p == color)
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

    fn addr(standard: PathStandard, s: &str) -> StandardAddress {
        let mut bytes = [0u8; AddressBuf::CAPACITY];
        bytes[..s.len()].copy_from_slice(s.as_bytes());
        StandardAddress { standard, address: AddressBuf::new(bytes, s.len()) }
    }

    /// The pinned vector values the sibling `verification.rs` tests use,
    /// so both screens are asserted against the same fixed addresses.
    fn sample_values() -> VerificationValues {
        VerificationValues {
            master_fingerprint: [0xa1, 0xb2, 0xc3, 0xd4],
            addresses: [
                addr(PathStandard::Bip44, "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"),
                addr(PathStandard::Bip49, "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"),
                addr(PathStandard::Bip84, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"),
                addr(
                    PathStandard::Bip86,
                    "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
                ),
            ],
        }
    }

    /// Every string this screen draws, in draw order, for the given
    /// toggle state — built from the same [`build_rows`] the renderer
    /// uses, so a test can never assert against stale copy.
    fn screen_lines(st: &VerifyState, passphrase_set: bool) -> Vec<String> {
        let values = sample_values();
        let mut fp = LineBuf::new();
        let mut addr_lines: [LineBuf; 4] = core::array::from_fn(|_| LineBuf::new());
        let (rows, n) = build_rows(st, &values, passphrase_set, &mut fp, &mut addr_lines);
        let mut out = Vec::new();
        for row in &rows[..n] {
            match *row {
                Row::Gap => {}
                Row::Line { text, .. } => out.push(text.to_string()),
                Row::Fingerprint { value } => {
                    out.push(FINGERPRINT_LABEL.to_string());
                    out.push(value.to_string());
                    out.push(FINGERPRINT_GLOSS.to_string());
                }
            }
        }
        out
    }

    fn hidden() -> VerifyState {
        VerifyState::new()
    }

    fn revealed() -> VerifyState {
        VerifyState { show_addresses: true }
    }

    // -- chunk4 --------------------------------------------------------

    #[test]
    fn chunk4_inserts_a_space_every_four_characters() {
        let mut out = [0u8; CHUNK_CAP];
        let n = chunk4(b"73c5da0a", &mut out);
        assert_eq!(&out[..n], b"73c5 da0a");

        // Exactly-4 input gets no trailing separator.
        let n = chunk4(b"abcd", &mut out);
        assert_eq!(&out[..n], b"abcd");

        // Partial trailing group is emitted as-is.
        let n = chunk4(b"1LqBGSKuX5", &mut out);
        assert_eq!(&out[..n], b"1LqB GSKu X5");

        // Empty input.
        assert_eq!(chunk4(b"", &mut out), 0);
    }

    #[test]
    fn chunk4_truncates_instead_of_panicking_on_a_short_out() {
        let mut out = [0u8; 6];
        let n = chunk4(b"73c5da0a", &mut out);
        assert!(n <= out.len());
        assert_eq!(&out[..n], b"73c5 d");
    }

    /// The leak posture demands [`chunk4`] never touch a secret-bearing
    /// buffer. Source-scan (the repo's existing string-level test shape,
    /// cf. `seed-gop-ui/tests/no_raw_colors.rs`): every `chunk4` call
    /// site in this crate must live in one of the two screens the design
    /// anticipates — this one and the `[X]` export branch — and must pass
    /// one of the two public-value expressions: the master-fingerprint
    /// hex digits or a receive address's bytes.
    #[test]
    fn chunk4_call_sites_are_public_values_only() {
        const ALLOWED_ARGS: &[&str] = &["&fp_hex", "addr.as_bytes()"];
        /// The only files permitted to chunk a value, relative to `src/`.
        const ALLOWED_FILES: &[&str] = &["screens/verify.rs", "screens/export.rs"];

        let src_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        collect_rs_files(&src_root, &mut files);
        assert!(files.len() > 5, "source scan found only {} files", files.len());

        let allowed: Vec<PathBuf> = ALLOWED_FILES
            .iter()
            .map(|rel| {
                let mut p = src_root.clone();
                for part in rel.split('/') {
                    p.push(part);
                }
                p
            })
            .collect();
        for path in &allowed {
            assert!(path.exists(), "allowlisted file {path:?} does not exist");
        }
        let mut seen_args = Vec::new();

        for path in &files {
            let text = std::fs::read_to_string(path).expect("read source file");
            // Only the non-test half of a file is production code.
            let prod = match text.find("#[cfg(test)]") {
                Some(i) => &text[..i],
                None => &text[..],
            };
            for line in prod.lines() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with('*') {
                    continue;
                }
                let Some(idx) = line.find("chunk4(") else { continue };
                // The definition itself, whatever its visibility.
                if trimmed.contains("fn chunk4(") {
                    continue;
                }
                assert!(
                    allowed.contains(path),
                    "chunk4 may only be called from {ALLOWED_FILES:?} (found in {path:?})"
                );
                let rest = &line[idx + "chunk4(".len()..];
                let arg = rest.split(',').next().unwrap_or("").trim();
                assert!(
                    ALLOWED_ARGS.contains(&arg),
                    "chunk4 called with {arg:?}; only public values {ALLOWED_ARGS:?} are allowed"
                );
                seen_args.push(arg.to_string());
            }
        }

        for want in ALLOWED_ARGS {
            assert!(
                seen_args.iter().any(|a| a == want),
                "expected a chunk4 call site for the public value {want:?}"
            );
        }
        // Every allowlisted *file* must actually chunk something, too: an
        // allowlist entry nobody needs is an exemption waiting to be
        // misused, and one that silently stops applying is a scan that
        // has quietly narrowed.
        for path in &allowed {
            let text = std::fs::read_to_string(path).expect("read allowlisted file");
            let prod = match text.find("#[cfg(test)]") {
                Some(i) => &text[..i],
                None => &text[..],
            };
            assert!(
                prod.lines().any(|l| {
                    let t = l.trim_start();
                    !t.starts_with("//") && !t.starts_with('*') && l.contains("chunk4(")
                }),
                "allowlisted file {path:?} contains no chunk4 call site -- remove it from \
                 ALLOWED_FILES"
            );
        }
    }

    fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_rs_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    /// Structural half of the same guarantee: this module's production
    /// code names no secret-bearing type at all, so no secret value can
    /// reach [`chunk4`] (or any draw call) however the code is edited.
    #[test]
    fn module_never_names_a_secret_bearing_type() {
        let this_file =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src").join("screens").join("verify.rs");
        let text = std::fs::read_to_string(&this_file).expect("read own source");
        let prod = &text[..text.find("#[cfg(test)]").expect("test module marker")];
        for banned in ["SecretArena", "WordCount", "mnemonic_indexes", "derive_final_entropy"] {
            assert!(
                !prod.contains(banned),
                "verify.rs production code must never reference {banned}"
            );
        }
    }

    // -- key handling --------------------------------------------------

    #[test]
    fn addresses_are_hidden_by_default() {
        assert!(!VerifyState::new().show_addresses);
        assert_eq!(VerifyState::default(), VerifyState::new());
    }

    #[test]
    fn v_toggles_the_address_reveal_without_leaving_the_screen() {
        let mut st = VerifyState::new();
        assert_eq!(st.handle_key(InputEvent::Char('v')), None);
        assert!(st.show_addresses);
        assert_eq!(st.handle_key(InputEvent::Char('V')), None);
        assert!(!st.show_addresses);
    }

    #[test]
    fn footer_keys_map_to_their_outcomes() {
        let mut st = VerifyState::new();
        assert_eq!(st.handle_key(InputEvent::Enter), Some(VerifyOutcome::Finish));
        assert_eq!(st.handle_key(InputEvent::Char('m')), Some(VerifyOutcome::Grid));
        assert_eq!(st.handle_key(InputEvent::Char('M')), Some(VerifyOutcome::Grid));
        assert_eq!(st.handle_key(InputEvent::Char('b')), Some(VerifyOutcome::CustomPath));
        assert_eq!(st.handle_key(InputEvent::Char('B')), Some(VerifyOutcome::CustomPath));
        assert_eq!(st.handle_key(InputEvent::Char('x')), Some(VerifyOutcome::Export));
        assert_eq!(st.handle_key(InputEvent::Char('X')), Some(VerifyOutcome::Export));
    }

    #[test]
    fn unhandled_keys_are_ignored_and_do_not_toggle() {
        let mut st = VerifyState::new();
        for k in [
            InputEvent::Other,
            InputEvent::Escape,
            InputEvent::Backspace,
            InputEvent::Char('q'),
        ] {
            assert_eq!(st.handle_key(k), None, "{k:?} must not leave the screen");
            assert!(!st.show_addresses, "{k:?} must not toggle the reveal");
        }
    }

    // -- default (hidden) state ----------------------------------------

    #[test]
    fn default_state_shows_the_fingerprint_and_hides_the_addresses() {
        let lines = screen_lines(&hidden(), false);
        let joined = lines.join("\n");

        assert!(joined.contains("a1b2 c3d4"), "chunked fingerprint missing: {joined}");
        assert!(joined.contains(VERDICT_HEADING), "verdict missing");
        assert!(!joined.contains("1LqB"), "an address leaked into the default state: {joined}");
        assert!(!joined.contains("bc1q"), "an address leaked into the default state");
        assert!(!joined.contains("bc1p"), "an address leaked into the default state");
        assert!(joined.contains(HIDDEN_LINE), "hidden-state explainer missing");
    }

    // -- revealed state -------------------------------------------------

    #[test]
    fn v_reveals_the_four_pinned_addresses_chunked() {
        let lines = screen_lines(&revealed(), false);
        let joined = lines.join("\n");

        assert!(joined.contains("1LqB GSKu X5yY Uonj xT5q GfpU sXKY YWea bA"), "{joined}");
        assert!(joined.contains("37Vu cYSa XLCA sxYy APfb Si9e h4iE cbSh gf"), "{joined}");
        assert!(
            joined.contains("bc1q cr8t e4kr 609g cawu tmrz a0j4 xv80 jy8z 306f yu"),
            "{joined}"
        );
        assert!(
            joined.contains(
                "bc1p 5cyx nuxm euwu vkwf em96 lqzs zd02 n6xd cjrs 20ca c6yq jjwu dpxq kedr cr"
            ),
            "{joined}"
        );

        // Each label sits on its address's own row, ascending order.
        let pos = |needle: &str| lines.iter().position(|l| l.contains(needle)).expect(needle);
        assert!(pos("Legacy (BIP44)") < pos("Nested SegWit (BIP49)"));
        assert!(pos("Nested SegWit (BIP49)") < pos("Native SegWit / bech32 (BIP84)"));
        assert!(pos("Native SegWit / bech32 (BIP84)") < pos("Taproot (BIP86)"));
        assert_eq!(pos("Legacy (BIP44)"), pos("1LqB GSKu"), "label and address share a row");

        // The reveal caption states why the addresses are on screen.
        assert!(joined.contains(REVEAL_CAPTION_1));
        assert!(joined.contains(REVEAL_CAPTION_2));
        assert!(REVEAL_CAPTION_2.contains("[V]"), "caption must say it was [V]-requested");
    }

    #[test]
    fn passphrase_state_flips_the_intro_and_caveat() {
        let empty = screen_lines(&revealed(), false).join("\n");
        assert!(empty.contains("no passphrase"));
        assert!(empty.contains("EMPTY passphrase"));

        let set = screen_lines(&revealed(), true).join("\n");
        assert!(set.contains("with your passphrase"), "ADDRESS_INTRO must flip");
        assert!(set.contains("passphrase you entered"), "CAVEAT_LINE_2 must flip");
        assert!(!set.contains("EMPTY passphrase"));
    }

    // -- leak bans ------------------------------------------------------

    /// The screen's whole drawable string set — both toggle states, both
    /// passphrase states, plus the footer — may never name a secret
    /// artifact (same bar as `flow_secret::verification`'s own
    /// `never_mentions_xpub_xprv_or_seed`).
    #[test]
    fn never_mentions_xpub_xprv_or_seed() {
        let forbidden = ["xpub", "xprv", "private key", "chain code", "pubkey"];
        let mut all: Vec<String> = Vec::new();
        for st in [hidden(), revealed()] {
            for pp in [false, true] {
                all.extend(screen_lines(&st, pp));
            }
        }
        for hint in &HINTS {
            all.push(hint.key.to_string());
            all.push(hint.label.to_string());
        }
        for line in &all {
            let lower = line.to_lowercase();
            for bad in forbidden {
                assert!(!lower.contains(bad), "line {line:?} must never mention {bad:?}");
            }
        }
    }

    /// The embedded font covers ASCII `0x20..=0x7E`; anything outside it
    /// renders as a blank cell, so every string this screen owns must be
    /// printable ASCII.
    #[test]
    fn all_copy_is_printable_ascii() {
        let mut all: Vec<String> = Vec::new();
        for st in [hidden(), revealed()] {
            for pp in [false, true] {
                all.extend(screen_lines(&st, pp));
            }
        }
        for hint in &HINTS {
            all.push(hint.key.to_string());
            all.push(hint.label.to_string());
        }
        for line in &all {
            for ch in line.chars() {
                assert!(
                    (' '..='~').contains(&ch),
                    "line {line:?} has non-renderable character {ch:?}"
                );
            }
        }
    }

    // -- fit audit ------------------------------------------------------

    /// Every 1x/2x content row fits the 800x600 floor's 96 columns.
    /// `draw_glyph` clips silently past the right edge, so this is a hard
    /// correctness bound.
    #[test]
    fn address_rows_fit_the_floor() {
        for st in [hidden(), revealed()] {
            for pp in [false, true] {
                let values = sample_values();
                let mut fp = LineBuf::new();
                let mut addr_lines: [LineBuf; 4] = core::array::from_fn(|_| LineBuf::new());
                let (rows, n) = build_rows(&st, &values, pp, &mut fp, &mut addr_lines);
                for row in &rows[..n] {
                    match *row {
                        Row::Gap => {}
                        Row::Line { text, scale, .. } => {
                            let cols = text.chars().count() * (scale as usize);
                            assert!(
                                cols <= MAX_COLS_AT_FLOOR,
                                "row {text:?} is {cols} cols at {scale}x, budget {MAX_COLS_AT_FLOOR}"
                            );
                        }
                        Row::Fingerprint { value } => {
                            let right = fp_gloss_x(value.len() as u32)
                                + (FINGERPRINT_GLOSS.len() as u32) * GLYPH_WIDTH;
                            assert!(
                                right <= MIN_WIDTH - MARGIN_X,
                                "fingerprint row ends at x={right}, budget {}",
                                MIN_WIDTH - MARGIN_X
                            );
                        }
                    }
                }
            }
        }
    }

    /// Width-guard for [`build_rows`]'s *fallback* address-row branch.
    ///
    /// The padded-field branch is bounds-checked inline (it is chosen
    /// only when it fits), but the single-space fallback it falls through
    /// to is not — nothing in the code stops a longer address from
    /// clipping there. Pinned here as a host test rather than a
    /// `debug_assert`, so the bound is enforced without introducing a
    /// debug-build panic path into a firmware render routine: every
    /// standard's fallback form is measured, whether or not that branch
    /// is the one actually taken for it today.
    #[test]
    fn address_row_fallback_branch_fits_the_floor() {
        let values = sample_values();
        for standard in
            [PathStandard::Bip44, PathStandard::Bip49, PathStandard::Bip84, PathStandard::Bip86]
        {
            let addr = values
                .addresses
                .iter()
                .find(|a| a.standard == standard)
                .map(|a| a.address.as_str().unwrap())
                .unwrap();
            let mut chunked = [0u8; CHUNK_CAP];
            let n = chunk4(addr.as_bytes(), &mut chunked);
            let label = wallet_label(standard);
            // The fallback form: label, one space, chunked address.
            let fallback_cols = label.len() + 1 + n;
            assert!(
                fallback_cols <= MAX_COLS_AT_FLOOR,
                "{label:?} fallback row is {fallback_cols} cols, budget {MAX_COLS_AT_FLOOR}"
            );
            // And exactly one branch is taken, by a rule that fits either way.
            let padded_cols = label.len().max(LABEL_FIELD) + n;
            let taken = if padded_cols <= MAX_COLS_AT_FLOOR { padded_cols } else { fallback_cols };
            assert!(taken <= MAX_COLS_AT_FLOOR);
        }
    }

    /// The tallest state (addresses revealed) still ends above the footer
    /// band at the resolution floor.
    #[test]
    fn tallest_state_fits_between_the_chrome_bands() {
        let values = sample_values();
        let mut fp = LineBuf::new();
        let mut addr_lines: [LineBuf; 4] = core::array::from_fn(|_| LineBuf::new());
        let (rows, n) = build_rows(&revealed(), &values, false, &mut fp, &mut addr_lines);
        let mut y = chrome::content_top();
        for row in &rows[..n] {
            y += row.height();
        }
        assert!(
            y <= chrome::content_bottom(),
            "content ends at y={y}, footer starts at {}",
            chrome::content_bottom()
        );
    }

    /// [`build_rows`]'s fixed array silently drops anything past
    /// [`MAX_ROWS`], so both states' exact row counts are pinned here: a
    /// future edit that grows a screen past the bound fails loudly rather
    /// than losing its last rows off-screen.
    #[test]
    fn both_states_stay_within_the_fixed_row_bound() {
        let values = sample_values();
        for (st, want) in [(hidden(), 11usize), (revealed(), 17usize)] {
            let mut fp = LineBuf::new();
            let mut addr_lines: [LineBuf; 4] = core::array::from_fn(|_| LineBuf::new());
            let (_rows, n) = build_rows(&st, &values, false, &mut fp, &mut addr_lines);
            assert_eq!(n, want, "row count changed for show_addresses={}", st.show_addresses);
            assert!(n < MAX_ROWS, "row count {n} leaves no headroom under MAX_ROWS={MAX_ROWS}");
        }
    }

    /// Column width [`chrome::draw_footer`] actually consumes for `hints`
    /// — an exact mirror of its `x`-advance arithmetic, so this tracks
    /// the real rendering budget rather than a hand-maintained estimate.
    /// `draw_footer` clips silently, and Stage 7's five-hint set is the
    /// widest in the product.
    fn footer_cols(hints: &[KeyHint]) -> usize {
        const HINT_SEP_LEN: usize = 3; // " | "
        let mut cols = 0usize;
        for (i, hint) in hints.iter().enumerate() {
            if i > 0 {
                cols += HINT_SEP_LEN;
            }
            cols += hint.key.len() + 2; // "[" + key + "]"
            cols += 1; // space
            cols += hint.label.len();
        }
        cols
    }

    #[test]
    fn stage_7_footer_hint_set_fits_the_floor() {
        assert_eq!(HINTS.len(), 5);
        let cols = footer_cols(&HINTS);
        assert!(
            cols <= MAX_COLS_AT_FLOOR,
            "Stage-7 footer is {cols} columns, budget is {MAX_COLS_AT_FLOOR}"
        );
        // Pinned, not just bounded: Stage 7 is the widest hint set in the
        // product, so any label edit that eats the remaining headroom
        // should surface here as an explicit decision rather than drift
        // silently towards `draw_footer`'s silent clip.
        assert_eq!(cols, 93, "Stage-7 footer width changed; re-check the {MAX_COLS_AT_FLOOR}-col budget");
    }

    // -- rendering ------------------------------------------------------

    #[test]
    fn render_draws_the_shell_and_the_verdict_in_ok() {
        let mut fb = VecFb::new(MIN_WIDTH, MIN_HEIGHT);
        render(&mut fb, &hidden(), &sample_values(), false, BUILD);
        assert!(fb.contains(theme::OK), "verdict must render in the OK role");
        assert!(fb.contains(theme::PANEL), "chrome bands must render");
        assert!(fb.contains(theme::ACCENT), "footer key glyphs must render");
    }

    #[test]
    fn render_clears_prior_screen_content_first() {
        let mut fb = VecFb::new(MIN_WIDTH, MIN_HEIGHT);
        let residue: Vec<u32> = std::vec![theme::WATERMARK.fg; 40];
        let mid = MIN_HEIGHT / 2;
        fb.put_row(MIN_WIDTH - 40, mid, &residue);
        assert!(fb.contains(theme::WATERMARK.fg), "sanity: residue present");

        render(&mut fb, &revealed(), &sample_values(), false, BUILD);
        for x in (MIN_WIDTH - 40)..MIN_WIDTH {
            assert_eq!(
                fb.buf[(mid as usize) * (MIN_WIDTH as usize) + (x as usize)],
                theme::BG,
                "residual pixel at x={x} was not cleared"
            );
        }
    }

    #[test]
    fn render_is_stable_across_both_toggle_states() {
        let mut a = VecFb::new(MIN_WIDTH, MIN_HEIGHT);
        render(&mut a, &hidden(), &sample_values(), false, BUILD);
        let mut b = VecFb::new(MIN_WIDTH, MIN_HEIGHT);
        render(&mut b, &revealed(), &sample_values(), false, BUILD);
        assert_ne!(a.buf, b.buf, "the reveal must change what is drawn");
    }
}
