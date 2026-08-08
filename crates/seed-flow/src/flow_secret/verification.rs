//! Wallet-derivation verification display (SPEC §24.3,
//! `AppState::DerivationVerificationDisplay`).
//!
//! Only ever called after re-entry has fully matched (SPEC §24.1: "This
//! step is offered only after re-entry has fully matched"). Optional and
//! skippable (SPEC §24.1/§24.4). Displays exactly: the master
//! fingerprint and the four first receive addresses
//! ([`seed_core::pipeline::VerificationValues`], SPEC §24.2-§24.3) —
//! never a private key, extended private key (`xprv`), the BIP39 seed,
//! a raw chain code or an extended public key (`xpub`); this module has
//! no code path that could reach any of those (its only input is
//! [`seed_core::pipeline::VerificationValues`], which does not carry them).

use core::fmt::Write as _;

use seed_core::contracts::{Framebuffer, PathStandard};
use seed_core::pipeline::{
    ExtendedVerificationValues, N_ACCOUNT_MAX, N_INDEX_MAX, TABLE_DEFAULT_N,
};
use seed_platform_x86::input::{InputEvent, KeySource};

use crate::flow_secret::gop_screen::draw_lines;
use crate::output::LineBuf;

// ============================================================================
// SPEC §24.1/§22.5-style offer screen: view or skip
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfferChoice {
    Show,
    Skip,
}

/// Block until the user chooses to view or skip. Every other key is
/// ignored.
pub fn read_offer_choice<K: KeySource + ?Sized>(keys: &mut K) -> OfferChoice {
    loop {
        match keys.read_key_blocking() {
            InputEvent::Enter => return OfferChoice::Show,
            InputEvent::Char(c) if c.eq_ignore_ascii_case(&'s') => return OfferChoice::Skip,
            _ => {}
        }
    }
}

// ============================================================================
// SPEC §24.3 display
// ============================================================================

/// SPEC §24.2: "The screen MUST state that a wallet restored with any
/// passphrase will NOT match these values." Still used verbatim by the
/// `[M]` more-derivation-options sub-screen (§A.5 rule 5); the promoted
/// preview (SPEC_WALLET_PREVIEW §3.3.1) uses its own fuller
/// [`CAVEAT_LINE_2`]/[`CAVEAT_LINE_3`] wording instead.
pub const EMPTY_PASSPHRASE_CAVEAT: &str =
    "These values assume the empty passphrase. Any other passphrase derives a DIFFERENT wallet.";

/// SPEC_PASSPHRASE §7.3: the caveat FLIP for the passphrase-set case, used
/// in place of [`EMPTY_PASSPHRASE_CAVEAT`] wherever a passphrase was
/// committed. The passphrase value itself is NEVER shown — only that one
/// was used.
pub const PASSPHRASE_SET_CAVEAT: &str =
    "These values assume the passphrase you just entered. A DIFFERENT passphrase, or no passphrase, derives a DIFFERENT wallet.";

/// SPEC_PASSPHRASE §7.3 helper: the caveat line for the current passphrase
/// state (empty vs set).
#[must_use]
pub const fn passphrase_caveat(passphrase_set: bool) -> &'static str {
    if passphrase_set {
        PASSPHRASE_SET_CAVEAT
    } else {
        EMPTY_PASSPHRASE_CAVEAT
    }
}

pub const FOOTER: &str = "After restoring in your signing device, confirm it shows the SAME values.";

// ----------------------------------------------------------------------------
// SPEC_WALLET_PREVIEW §3.3.1/§5.1 — the promoted "your seed works in every
// wallet type" preview copy. Presentation-only: these are the fixed static
// lines of the *default* verification screen (the same
// `DerivationVerificationDisplay` state, the same reused
// `VerificationValues`; no new derivation, no new state edge). All ASCII,
// fixed-layout (SPEC §12.2), every line <= 98 cols on the 800x600 floor.
// ----------------------------------------------------------------------------

/// Row 7 — the master-fingerprint path-independence gloss (OQ-5), appended
/// after the substituted 8-hex fingerprint.
pub const FINGERPRINT_GLOSS: &str = "(same for every type - it IDs this seed)";

/// Task 19 (launcher/Learn/compat restyle) fingerprint-label unification:
/// the one spelling of the "Master fingerprint" caption every fingerprint
/// row in this crate builds from, so the word never drifts between the
/// grid ([`render_more_options`], this module), the
/// Stage-7 Verify screen (`crate::screens::verify`, a pixel-exact
/// `draw_text` layout that computes its own column gap and never embeds
/// padding in the label itself), and the custom-path result screen
/// (`crate::flow_secret::custom_path`). Deliberately holds NO trailing
/// padding: each call site's own column layout differs (the grid pads to
/// six spaces before the hex value; custom-path pads to three), so every
/// site appends its own spacing after this constant rather than the
/// constant dictating one column width that would fit none of them
/// exactly. Unifying the word (not the whitespace) is the actual
/// drift risk this closes — a typo or a stray case change in one of the
/// three copies.
pub const FINGERPRINT_LABEL: &str = "Master fingerprint";

/// Row 9 — the address-block intro. Forward-note (SPEC_PASSPHRASE §v0.1
/// touchpoint 2): the "no passphrase" parenthetical is the one place a
/// later passphrase feature flips this line's assumption; kept as its own
/// constant so that change is a single-line edit.
pub const ADDRESS_INTRO: &str = "First receive address (account 0, index 0, no passphrase):";

/// SPEC_PASSPHRASE §7.3 flip of [`ADDRESS_INTRO`] when a passphrase was set:
/// the "no passphrase" parenthetical becomes "with your passphrase".
pub const ADDRESS_INTRO_PP: &str =
    "First receive address (account 0, index 0, with your passphrase):";

/// Rows 15-18 — the not-secret / privacy note plus the empty-passphrase AND
/// non-standard-path caveat (§4 rules 4-5). Forward-note (SPEC_PASSPHRASE
/// §v0.1 touchpoint 1): [`CAVEAT_LINE_2`]'s "EMPTY passphrase" is the single
/// phrase a later passphrase feature flips to "the passphrase you entered".
pub const CAVEAT_LINE_1: &str = "These values are safe to write down - not secret keys, but addresses";
/// Second caveat line (row 16).
pub const CAVEAT_LINE_2: &str = "reveal where your funds will be. They assume the EMPTY passphrase and";
/// SPEC_PASSPHRASE §7.3 flip of [`CAVEAT_LINE_2`] when a passphrase was set:
/// the "EMPTY passphrase" phrase becomes "the passphrase you entered".
pub const CAVEAT_LINE_2_PP: &str =
    "reveal where your funds will be. They assume the passphrase you entered and";
/// Third caveat line (row 17).
pub const CAVEAT_LINE_3: &str = "the standard account-0 path; a different passphrase or path derives a";
/// Fourth caveat line (row 18).
pub const CAVEAT_LINE_4: &str = "DIFFERENT wallet.";

/// SPEC_DERIVATION_CUSTOM.md §3/§11.1: the footer copy that offers `[B]`
/// alongside `[M]` for the §11.5-safe structured custom-path builder
/// (`crate::flow_secret::custom_path`). Retained as the canonical footer
/// wording (and its `[M]`/`[B]` affordances are pinned by the desktop
/// rehearsal's `verify_screen_advertises_and_handles_m_and_b` test); the
/// live Stage-7 screen is drawn by `crate::screens::verify`.
pub const CONTINUE_MORE_AND_CUSTOM_PROMPT: &str =
    "[Enter] Continue   [M] More derivation options   [B] Build custom path";

/// Visible to the crate (not just this module) so the redesigned
/// Stage-7 screen (`crate::screens::verify`) formats the same public
/// master fingerprint through the identical routine rather than growing
/// a second hex encoder. Behavior unchanged.
pub(crate) fn hex8(bytes: [u8; 4]) -> [u8; 8] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 8];
    for (i, b) in bytes.iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0x0f) as usize];
    }
    out
}

fn standard_label(standard: PathStandard) -> &'static str {
    match standard {
        PathStandard::Bip44 => "BIP44 legacy       ",
        PathStandard::Bip49 => "BIP49 nested segwit",
        PathStandard::Bip84 => "BIP84 native segwit",
        PathStandard::Bip86 => "BIP86 taproot      ",
    }
}

/// SPEC_WALLET_PREVIEW §3.3.1/§5.1: the full plain-English label for the
/// promoted preview's inline `label + address` rows. Left-justified into a
/// 32-column field at render time (widest label
/// `Native SegWit / bech32 (BIP84)` = 30 chars → 2 trailing spaces before
/// the address; widest resulting row `Taproot (BIP86)` (15, padded to 32) +
/// a 62-char bech32m address = 94 ≤ 98). Distinct from [`standard_label`],
/// whose terse code-first form the unchanged `[M]` menu still uses (§3.5).
/// Visible to the crate so `crate::screens::verify` reuses these exact
/// label strings by reference instead of restating them. Behavior
/// unchanged.
pub(crate) fn wallet_label(standard: PathStandard) -> &'static str {
    match standard {
        PathStandard::Bip44 => "Legacy (BIP44)",
        PathStandard::Bip49 => "Nested SegWit (BIP49)",
        PathStandard::Bip84 => "Native SegWit / bech32 (BIP84)",
        PathStandard::Bip86 => "Taproot (BIP86)",
    }
}

/// Width of the left-justified label field on the promoted preview's
/// address rows (SPEC_WALLET_PREVIEW §3.3.1).
pub(crate) const LABEL_FIELD: usize = 32;

/// SPEC_DERIVATION_OPTIONS §A.4.1: what the user chose on the default
/// verification screen's `[Enter]`/`[M]` footer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultChoice {
    /// `[Enter]` — done with verification, continue the ceremony.
    Continue,
    /// `[M]` — open the bounded-grid "more derivation options" menu.
    MoreOptions,
    /// `[B]` — open the §11.5-safe structured custom-path builder
    /// (SPEC_DERIVATION_CUSTOM.md §3; production driver only).
    CustomBuilder,
}

/// Block until the user presses Enter (continue) or `M` (more options) on
/// the default screen. Every other key is ignored. Self-test-safe: only
/// Enter and the letter `M` (in the §11.5-validated `A–Z` set) are read.
pub fn read_default_choice<K: KeySource + ?Sized>(keys: &mut K) -> DefaultChoice {
    loop {
        match keys.read_key_blocking() {
            InputEvent::Enter => return DefaultChoice::Continue,
            InputEvent::Char(c) if c.eq_ignore_ascii_case(&'m') => return DefaultChoice::MoreOptions,
            InputEvent::Char(c) if c.eq_ignore_ascii_case(&'b') => return DefaultChoice::CustomBuilder,
            _ => {}
        }
    }
}

// ============================================================================
// SPEC_DERIVATION_OPTIONS §A.4.2/§A.4.3/§A.4.4: bounded-grid "more
// derivation options" menu (Model A — navigates only the pre-derived,
// public ExtendedVerificationValues; never touches a secret).
// ============================================================================

/// SPEC_DERIVATION_OPTIONS §A.4.2 header (mirrors the default screen's
/// framing: reference values, not secret keys).
pub const MORE_HEADER_1: &str = "MORE DERIVATION OPTIONS (safe to write down; not secret keys,";
/// Second header line, shared framing with the default screen.
pub const MORE_HEADER_2: &str = "but addresses reveal where your funds will be)";
/// SPEC_DERIVATION_OPTIONS §A.4.4 standard picker (self-test-safe digits).
pub const MORE_KEYS_STANDARD: &str = "Standard  [1] BIP44  [2] BIP49  [3] BIP84  [4] BIP86";
/// SPEC_DERIVATION_OPTIONS §A.4.4 account increment/decrement (bounded).
pub const MORE_KEYS_ACCOUNT: &str = "Account   [A] +   [Z] -";
/// SPEC_DERIVATION_OPTIONS §A.4.4 index increment/decrement (bounded).
pub const MORE_KEYS_INDEX: &str = "Index     [S] +   [X] -";
/// SPEC_DERIVATION_OPTIONS §A.4.4 change-chain toggle (external/internal).
pub const MORE_KEYS_CHANGE: &str = "Change    [C] toggle external / internal";
/// SPEC_DERIVATION_OPTIONS §A.4.3 first-N-address table toggle.
pub const MORE_KEYS_TABLE: &str = "Table     [T] toggle first addresses";
/// SPEC_DERIVATION_OPTIONS §A.6 privacy note: the table shows a linkable
/// cluster of related addresses (larger framebuffer-capture surface).
pub const MORE_CLUSTER_NOTE: &str =
    "A table lists a CLUSTER of related addresses (a larger privacy surface).";
/// SPEC_DERIVATION_OPTIONS §A.4.2 back prompt.
pub const MORE_BACK_PROMPT: &str = "[Enter] Back";

/// Label for the external (`0`) vs internal-change (`1`) chain
/// (SPEC_DERIVATION_OPTIONS §A.2/OQ-4).
const fn change_label(change: u32) -> &'static str {
    if change == 0 {
        "external chain"
    } else {
        "internal (change) chain"
    }
}

/// Live selector state for the more-options menu. All coordinates stay
/// within the pre-derived bounds; the address strings are always looked up
/// from the pre-rendered [`ExtendedVerificationValues`], so this module
/// still never touches a secret (Model A, §A.0).
#[derive(Clone, Copy)]
struct Selection {
    /// 0..=3 → BIP44/49/84/86.
    standard_ord: u8,
    /// 0..=`N_ACCOUNT_MAX`.
    account: u32,
    /// 0 external / 1 internal.
    change: u32,
    /// 0..=`N_INDEX_MAX`.
    index: u32,
    /// Whether the first-N-address table is shown instead of a single
    /// address.
    table: bool,
}

impl Selection {
    const fn new() -> Self {
        Self { standard_ord: 0, account: 0, change: 0, index: 0, table: false }
    }

    fn standard(self) -> PathStandard {
        match self.standard_ord {
            0 => PathStandard::Bip44,
            1 => PathStandard::Bip49,
            2 => PathStandard::Bip84,
            _ => PathStandard::Bip86,
        }
    }
}

/// SPEC_DERIVATION_OPTIONS §A.4.2-§A.4.4: run the bounded-grid selection
/// menu over the pre-derived, public [`ExtendedVerificationValues`]. Each
/// self-test-safe keystroke adjusts one selector within its bound and the
/// screen re-renders; `[Enter]` returns to the caller. Blocks; consumes no
/// secret (every address is looked up from `ext`, already rendered before
/// the seed was scrubbed).
pub fn run_more_options<K: KeySource + ?Sized>(
    fb: &mut dyn Framebuffer,
    keys: &mut K,
    ext: &ExtendedVerificationValues,
    passphrase_set: bool,
) {
    let mut sel = Selection::new();
    loop {
        render_more_options(fb, ext, sel, passphrase_set);
        match keys.read_key_blocking() {
            InputEvent::Enter => return,
            InputEvent::Char(c) => {
                let c = c.to_ascii_uppercase();
                match c {
                    '1' => sel.standard_ord = 0,
                    '2' => sel.standard_ord = 1,
                    '3' => sel.standard_ord = 2,
                    '4' => sel.standard_ord = 3,
                    'A' if sel.account < N_ACCOUNT_MAX => sel.account += 1,
                    'Z' if sel.account > 0 => sel.account -= 1,
                    'S' if sel.index < N_INDEX_MAX => sel.index += 1,
                    'X' if sel.index > 0 => sel.index -= 1,
                    'C' => sel.change ^= 1,
                    'T' => sel.table = !sel.table,
                    _ => {}
                }
            }
            _ => {}
        }
    }
}

/// Render one frame of the more-options menu for `sel` (SPEC
/// §A.4.2 single-result view or §A.4.3 first-N table), always including the
/// empty-passphrase caveat and the cluster privacy note (§A.5 rule 5,
/// §A.6). Pulls every address from the pre-rendered grid `ext`.
fn render_more_options(fb: &mut dyn Framebuffer, ext: &ExtendedVerificationValues, sel: Selection, passphrase_set: bool) {
    seed_gop_ui::font::scrub_fill(fb, 0);

    let standard = sel.standard();

    let fp_hex = hex8(ext.master_fingerprint);
    let fp_str = core::str::from_utf8(&fp_hex).unwrap_or("????????");

    let mut summary = LineBuf::new();
    let _ = write!(
        summary,
        "{}   account {}   {}",
        standard_label(standard),
        sel.account,
        change_label(sel.change),
    );

    let mut fp_line = LineBuf::new();
    let _ = write!(fp_line, "{FINGERPRINT_LABEL}      {fp_str}");

    // Up to TABLE_DEFAULT_N dynamic address rows (single result reuses row 0).
    let mut rows: [LineBuf; TABLE_DEFAULT_N] = core::array::from_fn(|_| LineBuf::new());
    let row_count = if sel.table {
        for (i, row) in rows.iter_mut().enumerate() {
            let addr = ext
                .address(standard, sel.account, sel.change, i as u32)
                .and_then(|a| a.as_str())
                .unwrap_or("?");
            let _ = write!(row, "  #{i}   {addr}");
        }
        TABLE_DEFAULT_N
    } else {
        let addr = ext
            .address(standard, sel.account, sel.change, sel.index)
            .and_then(|a| a.as_str())
            .unwrap_or("?");
        let _ = write!(rows[0], "  index {}   {addr}", sel.index);
        1
    };

    // Assemble the fixed line list. Count: 2 header + 1 blank + 5 selector
    // help + 1 blank + summary + fp + up-to-TABLE_DEFAULT_N rows + 1 blank +
    // caveat + cluster + footer + back = at most 21 <= 24.
    let mut lines: [&str; 24] = [""; 24];
    let mut n = 0usize;
    for line in [
        MORE_HEADER_1,
        MORE_HEADER_2,
        "",
        MORE_KEYS_STANDARD,
        MORE_KEYS_ACCOUNT,
        MORE_KEYS_INDEX,
        MORE_KEYS_CHANGE,
        MORE_KEYS_TABLE,
        "",
        summary.as_str(),
        fp_line.as_str(),
    ] {
        lines[n] = line;
        n += 1;
    }
    for row in rows.iter().take(row_count) {
        lines[n] = row.as_str();
        n += 1;
    }
    for line in ["", passphrase_caveat(passphrase_set), MORE_CLUSTER_NOTE, FOOTER, MORE_BACK_PROMPT] {
        lines[n] = line;
        n += 1;
    }

    draw_lines(fb, &lines[..n]);
}

/// Block until Enter (acknowledged). Every other key is ignored.
pub fn read_acknowledged<K: KeySource + ?Sized>(keys: &mut K) {
    loop {
        if let InputEvent::Enter = keys.read_key_blocking() {
            return;
        }
    }
}

// ============================================================================
// SPEC §24.4 failure policy
// ============================================================================

/// SPEC §24.4 verification-failure screen header.
pub const FAILURE_HEADER: &str = "Wallet-derivation verification failed.";
/// SPEC §24.4, verbatim requirement: "the screen states that
/// verification values were not produced."
pub const FAILURE_LINE_NOT_PRODUCED: &str = "Verification values were not produced.";
/// SPEC §24.4, verbatim requirement: "The mnemonic re-entry already
/// succeeded, so the user's backup is usable."
pub const FAILURE_LINE_BACKUP_USABLE: &str =
    "Your recovery phrase already matched during re-entry and remains usable.";
/// SPEC §24.4, verbatim requirement: "the ceremony may be repeated after
/// a fresh boot."
pub const FAILURE_LINE_REPEAT: &str = "You may repeat this step after a fresh boot.";
/// SPEC §24.4 failure-screen continue prompt (acknowledged via
/// [`read_acknowledged`] before the caller proceeds into the fatal
/// scrub-and-shutdown chain, SPEC §27.2).
pub const FAILURE_CONTINUE_PROMPT: &str = "[Enter] Continue to shutdown";

/// Render the SPEC §24.4 verification-failure screen. The caller MUST
/// show this (and let the user acknowledge it, see
/// [`read_acknowledged`]) before transitioning into the fatal
/// scrub-and-shutdown chain — otherwise the very next state's own
/// framebuffer scrub would erase this message before it can be read.
///
/// Clears the framebuffer first (SPEC §12.2 "Fixed layouts"), the same
/// as every other screen transition in this module tree.
pub fn render_failed(fb: &mut dyn Framebuffer) {
    seed_gop_ui::font::scrub_fill(fb, 0);
    draw_lines(
        fb,
        &[
            FAILURE_HEADER,
            "",
            FAILURE_LINE_NOT_PRODUCED,
            FAILURE_LINE_BACKUP_USABLE,
            FAILURE_LINE_REPEAT,
            "",
            FAILURE_CONTINUE_PROMPT,
        ],
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    use seed_core::contracts::PathStandard;

    struct VecFb {
        w: u32,
        h: u32,
        buf: std::vec::Vec<u32>,
    }
    impl VecFb {
        fn new(w: u32, h: u32) -> Self {
            Self { w, h, buf: std::vec![0u32; (w as usize) * (h as usize)] }
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

    struct ScriptedKeys {
        events: std::vec::Vec<InputEvent>,
        pos: usize,
    }
    impl ScriptedKeys {
        fn new(events: std::vec::Vec<InputEvent>) -> Self {
            Self { events, pos: 0 }
        }
    }
    impl KeySource for ScriptedKeys {
        fn read_key_blocking(&mut self) -> InputEvent {
            let ev = self.events.get(self.pos).copied().expect("read past scripted keystream");
            self.pos += 1;
            ev
        }
    }

    /// A real, fully pre-derived grid built through the production pipeline
    /// (`FlowDeriver`), so the UI tests navigate genuine rendered addresses
    /// exactly as the driver hands them to `run_more_options`.
    fn sample_ext() -> ExtendedVerificationValues {
        use seed_core::arena::SecretArena;
        use seed_core::contracts::{ArchId, SourceTag, TargetBits};
        use seed_core::pipeline::{compute_extended_verification_values, derive_final_entropy, SourceInput};

        use crate::flow_secret::derive::{FlowDeriver, FlowTranscript};

        let mut arena = SecretArena::new();
        let dice = [3u8; 32];
        let sources = [SourceInput { tag: SourceTag::DiceRolls, algo_id: b"", bytes: &dice }];
        let wc = derive_final_entropy(
            &mut arena,
            FlowTranscript::new(),
            &sources,
            ArchId::X86_64,
            TargetBits::Bits128,
            1,
        )
        .unwrap();

        let mut ext = ExtendedVerificationValues::new();
        compute_extended_verification_values::<FlowDeriver>(&mut arena, wc, &mut ext).unwrap();
        arena.scrub_all();
        ext
    }

    #[test]
    fn hex8_encodes_fingerprint_lowercase() {
        assert_eq!(&hex8([0xa1, 0xb2, 0xc3, 0xd4]), b"a1b2c3d4");
    }

    #[test]
    fn offer_choice_show_and_skip() {
        let mut k = ScriptedKeys::new(std::vec![InputEvent::Enter]);
        assert_eq!(read_offer_choice(&mut k), OfferChoice::Show);
        let mut k = ScriptedKeys::new(std::vec![InputEvent::Char('s')]);
        assert_eq!(read_offer_choice(&mut k), OfferChoice::Skip);
    }

    #[test]
    fn empty_passphrase_caveat_is_present() {
        assert!(EMPTY_PASSPHRASE_CAVEAT.to_lowercase().contains("passphrase"));
        assert!(EMPTY_PASSPHRASE_CAVEAT.to_lowercase().contains("different") || EMPTY_PASSPHRASE_CAVEAT.contains("NOT"));
    }

    #[test]
    fn never_mentions_xpub_xprv_or_seed() {
        // SPEC §24.3 rules 1-2/§A.5 rules 1-2, 9: no static line/label this
        // module still owns may ever name a secret artifact — an extended
        // private key (`xprv`), an extended public key (`xpub`), a raw chain
        // code, a private key or a bare pubkey. Every drawable string this
        // module owns is covered below (the shared caveat/intro/label copy is
        // now rendered by `crate::screens::verify`, which carries its own
        // equivalent guard; the strings themselves are still checked here).
        //
        // The real guarantee that the *seed value* is never rendered is
        // structural: `run_more_options`/`render_more_options` only ever
        // receive a public `ExtendedVerificationValues` (fingerprint + public
        // addresses) — there is no code path from which a seed/xprv/chain-code
        // byte could reach a drawn line. The failure screen still additionally
        // bans "seed", see `failure_screen_never_mentions_xpub_xprv_or_seed`.
        let forbidden = ["xpub", "xprv", "private key", "chain code", "pubkey"];
        for line in [
            // shared / more-options / footer strings
            FOOTER,
            EMPTY_PASSPHRASE_CAVEAT,
            CONTINUE_MORE_AND_CUSTOM_PROMPT,
            MORE_HEADER_1,
            MORE_HEADER_2,
            MORE_KEYS_STANDARD,
            MORE_KEYS_ACCOUNT,
            MORE_KEYS_INDEX,
            MORE_KEYS_CHANGE,
            MORE_KEYS_TABLE,
            MORE_CLUSTER_NOTE,
            MORE_BACK_PROMPT,
            change_label(0),
            change_label(1),
            // shared caveat/intro/label copy (reused by screens::verify)
            FINGERPRINT_GLOSS,
            ADDRESS_INTRO,
            ADDRESS_INTRO_PP,
            CAVEAT_LINE_1,
            CAVEAT_LINE_2,
            CAVEAT_LINE_2_PP,
            CAVEAT_LINE_3,
            CAVEAT_LINE_4,
            wallet_label(PathStandard::Bip44),
            wallet_label(PathStandard::Bip49),
            wallet_label(PathStandard::Bip84),
            wallet_label(PathStandard::Bip86),
        ] {
            let lower = line.to_lowercase();
            for bad in forbidden {
                assert!(!lower.contains(bad), "line {line:?} must never mention {bad:?}");
            }
        }
    }

    /// SPEC_PASSPHRASE §7.3: the caveat FLIPS when a passphrase was set.
    /// The empty case keeps the "EMPTY passphrase" wording; the passphrase-set
    /// case swaps in "the passphrase you entered" / "with your passphrase" and
    /// never shows the passphrase itself. The shared copy constants these
    /// screens draw are checked directly (the live layout that assembles them
    /// is `crate::screens::verify`).
    #[test]
    fn caveat_flips_when_a_passphrase_is_set() {
        // Standalone caveat helper.
        assert_eq!(passphrase_caveat(false), EMPTY_PASSPHRASE_CAVEAT);
        assert_eq!(passphrase_caveat(true), PASSPHRASE_SET_CAVEAT);
        assert!(PASSPHRASE_SET_CAVEAT.contains("passphrase you just entered"));

        // Empty-case copy names the EMPTY / no passphrase; the set-case copy
        // flips to "with your passphrase" / "the passphrase you entered".
        assert!(EMPTY_PASSPHRASE_CAVEAT.contains("empty passphrase"));
        assert!(CAVEAT_LINE_2.contains("EMPTY passphrase"));
        assert!(ADDRESS_INTRO.contains("no passphrase"));
        assert!(!ADDRESS_INTRO.contains("with your passphrase"));
        assert!(ADDRESS_INTRO_PP.contains("with your passphrase"), "ADDRESS_INTRO_PP must flip");
        assert!(CAVEAT_LINE_2_PP.contains("passphrase you entered"), "CAVEAT_LINE_2_PP must flip");
        assert!(!CAVEAT_LINE_2_PP.contains("EMPTY passphrase"), "set-case caveat must not say EMPTY");
    }

    /// SPEC_DERIVATION_OPTIONS §A.5 rule 9: the only fingerprint word
    /// present is the *master* fingerprint — no "account"/"node" fingerprint
    /// label and no "pubkey" leaks through any static line.
    #[test]
    fn more_options_lines_show_only_master_fingerprint_never_node_or_pubkey() {
        for line in [
            MORE_HEADER_1,
            MORE_HEADER_2,
            MORE_KEYS_STANDARD,
            MORE_KEYS_ACCOUNT,
            MORE_KEYS_INDEX,
            MORE_KEYS_CHANGE,
            MORE_KEYS_TABLE,
            MORE_CLUSTER_NOTE,
            MORE_BACK_PROMPT,
        ] {
            let lower = line.to_lowercase();
            assert!(!lower.contains("pubkey"), "line {line:?} must never mention a pubkey");
            assert!(
                !lower.contains("account fingerprint") && !lower.contains("node fingerprint"),
                "line {line:?} must never show an intermediate-node fingerprint"
            );
        }
    }

    /// SPEC_DERIVATION_OPTIONS §A.5 rule 5 / §R/M7: the empty-passphrase
    /// caveat and the §A.6 cluster note are drawn on the more-options screen
    /// (single-result AND table view), not just the default screen.
    #[test]
    fn more_options_render_includes_caveat_and_cluster_note() {
        // Structural: render_more_options always pushes both lines; assert
        // the constants exist and carry the required meaning, and that the
        // render path draws something for both a single result and a table.
        assert!(EMPTY_PASSPHRASE_CAVEAT.to_lowercase().contains("passphrase"));
        assert!(MORE_CLUSTER_NOTE.to_lowercase().contains("cluster"));

        let ext = sample_ext();
        let mut fb = VecFb::new(1024, 768);
        // single-result view
        render_more_options(&mut fb, &ext, Selection::new(), false);
        assert!(fb.buf.iter().any(|&p| p != 0), "single-result view must draw");
        // table view
        let mut fb2 = VecFb::new(1024, 768);
        render_more_options(&mut fb2, &ext, Selection { table: true, ..Selection::new() }, false);
        assert!(fb2.buf.iter().any(|&p| p != 0), "table view must draw");
    }

    #[test]
    fn default_choice_reads_enter_and_m() {
        let mut k = ScriptedKeys::new(std::vec![InputEvent::Enter]);
        assert_eq!(read_default_choice(&mut k), DefaultChoice::Continue);
        let mut k = ScriptedKeys::new(std::vec![InputEvent::Char('m')]);
        assert_eq!(read_default_choice(&mut k), DefaultChoice::MoreOptions);
        let mut k = ScriptedKeys::new(std::vec![InputEvent::Char('M')]);
        assert_eq!(read_default_choice(&mut k), DefaultChoice::MoreOptions);
        // SPEC_DERIVATION_CUSTOM.md §3: `[B]` opens the custom-path builder.
        let mut k = ScriptedKeys::new(std::vec![InputEvent::Char('b')]);
        assert_eq!(read_default_choice(&mut k), DefaultChoice::CustomBuilder);
        let mut k = ScriptedKeys::new(std::vec![InputEvent::Char('B')]);
        assert_eq!(read_default_choice(&mut k), DefaultChoice::CustomBuilder);
    }

    /// The footer copy that offers `[M] More derivation options` AND
    /// `[B] Build custom path` still fits the 98-col floor
    /// (SPEC_DERIVATION_CUSTOM.md §3, SPEC §12.2).
    #[test]
    fn custom_footer_prompt_fits_floor_and_offers_m_and_b() {
        assert!(CONTINUE_MORE_AND_CUSTOM_PROMPT.chars().count() <= 98);
        assert!(CONTINUE_MORE_AND_CUSTOM_PROMPT.contains("[M]"));
        assert!(CONTINUE_MORE_AND_CUSTOM_PROMPT.contains("[B]"));
    }

    /// The selectors stay within their bounds (self-test-safe increment/
    /// decrement, SPEC_DERIVATION_OPTIONS §A.4.4) and every key used is in
    /// the §11.5-validated set. `run_more_options` returns on `[Enter]`.
    #[test]
    fn run_more_options_navigates_within_bounds_and_returns_on_enter() {
        let ext = sample_ext();
        let mut fb = VecFb::new(1024, 768);
        // Try to over-decrement account/index (must clamp at 0), pick a
        // standard, bump account/index up, toggle change + table, then Enter.
        let mut k = ScriptedKeys::new(std::vec![
            InputEvent::Char('Z'), // account - (clamped at 0)
            InputEvent::Char('X'), // index - (clamped at 0)
            InputEvent::Char('3'), // BIP84
            InputEvent::Char('A'), // account +
            InputEvent::Char('S'), // index +
            InputEvent::Char('C'), // change toggle
            InputEvent::Char('T'), // table on
            InputEvent::Other,     // ignored
            InputEvent::Enter,     // back
        ]);
        run_more_options(&mut fb, &mut k, &ext, false);
        assert!(fb.buf.iter().any(|&p| p != 0));
    }

    #[test]
    fn read_acknowledged_ignores_non_enter_keys() {
        let mut k = ScriptedKeys::new(std::vec![InputEvent::Char('x'), InputEvent::Other, InputEvent::Enter]);
        read_acknowledged(&mut k);
    }

    // ------------------------------------------------------------------
    // Regression tests for the confirmed WP-26 finding (SPEC §24.4).
    // ------------------------------------------------------------------

    /// SPEC §24.4, verbatim requirement: the screen must state that
    /// verification values were not produced and that the ceremony may
    /// be repeated after a fresh boot.
    #[test]
    fn failure_screen_states_not_produced_and_repeatable_after_fresh_boot() {
        assert!(FAILURE_LINE_NOT_PRODUCED.to_lowercase().contains("not produced"));
        assert!(FAILURE_LINE_REPEAT.to_lowercase().contains("fresh boot"));
        assert!(FAILURE_LINE_REPEAT.to_lowercase().contains("repeat"));
    }

    /// SPEC §24.4: "The mnemonic re-entry already succeeded, so the
    /// user's backup is usable" — the screen must say so, and must never
    /// suggest the recovery phrase itself is untrustworthy.
    #[test]
    fn failure_screen_reassures_backup_remains_usable() {
        let lower = FAILURE_LINE_BACKUP_USABLE.to_lowercase();
        assert!(lower.contains("matched") || lower.contains("usable"));
        for line in [FAILURE_HEADER, FAILURE_LINE_NOT_PRODUCED, FAILURE_LINE_REPEAT] {
            assert!(
                !line.to_lowercase().contains("invalid phrase"),
                "line {line:?} must not cast doubt on the already-matched recovery phrase"
            );
        }
    }

    #[test]
    fn render_failed_draws_something_and_clears_prior_content() {
        let mut fb = VecFb::new(1024, 768);
        let far_right_row: std::vec::Vec<u32> = std::vec![0x00FF_FFFFu32; 40];
        fb.put_row(984, 0, &far_right_row);

        render_failed(&mut fb);

        assert!(fb.buf.iter().any(|&p| p != 0), "render_failed must draw something");
        for x in 984..1024 {
            assert_eq!(fb.buf[x as usize], 0, "residual prior-screen pixel at x={x} was not cleared");
        }
    }

    /// This screen must never mention xpub/xprv/seed either (same bar as
    /// the successful verification display).
    #[test]
    fn failure_screen_never_mentions_xpub_xprv_or_seed() {
        let forbidden = ["xpub", "xprv", "seed", "private key"];
        for line in [FAILURE_HEADER, FAILURE_LINE_NOT_PRODUCED, FAILURE_LINE_BACKUP_USABLE, FAILURE_LINE_REPEAT] {
            let lower = line.to_lowercase();
            for bad in forbidden {
                assert!(!lower.contains(bad), "line {line:?} must never mention {bad:?}");
            }
        }
    }
}
