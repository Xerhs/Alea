//! SPEC_DERIVATION_CUSTOM.md §3/§4 — the §11.5-safe STRUCTURED custom
//! derivation-path builder (PRIMARY surface, production UEFI).
//!
//! Reachable from the SPEC §24 verification display footer (alongside `[M]
//! More derivation options`). It lets the user **assemble** an arbitrary
//! bounded BIP32 path and pick a script type using **only** §11.5-validated
//! keys — `{A-Z, 1-6, H, T, Backspace, Enter}` — with no `/`, `'`, `0`,
//! `7`, `8`, `9` ever typed (those characters appear only in the rendered
//! read-back, which is output, never input; SPEC_DERIVATION_CUSTOM §2.2).
//! The assembled path is a bounded `[u32; MAX_DEPTH]`, each entry a child
//! number with `HARDENED_OFFSET` applied where the per-level hardened flag
//! is set (§3.2); it is fed verbatim to the already-implemented,
//! `&[u32]`-general `address_at`/`derive_path` (NO crypto-core change).
//!
//! # Secret lifecycle (SPEC_DERIVATION_CUSTOM §4, the deliberate relaxation)
//!
//! BUILD (this module's interactive loop) is **pure public arithmetic** —
//! it manipulates only public path integers and touches no seed/master key,
//! exactly like navigating the existing `run_more_options` grid. COMMIT
//! (`[Enter]`) makes a **single**, non-interactive
//! [`crate::flow_secret::derive::compute_custom_address`] call, which
//! re-derives the seed from the resident mnemonic, renders the one leaf, and
//! scrubs the derived seed IMMEDIATELY (see that function's own doc
//! comment). This module therefore DOES touch the secret at commit — a
//! documented, bounded relaxation of `verification.rs`'s "never touches a
//! secret" property (SPEC_DERIVATION_CUSTOM §4/§14). It stays post-secret
//! and linear (SPEC §26: never returns to a boot/app menu); OQ-7 allows
//! MULTIPLE commits within one builder session (the mnemonic stays resident
//! across the whole verification phase; each commit derives-and-scrubs the
//! seed independently). The mnemonic buffer is arena-resident and is covered
//! by the SPEC §26/§27 whole-arena shutdown scrub and the panic handler
//! (`SecretArena::register_for_panic_scrub`) — NOT merely `Drop`, which
//! `panic = "abort"` skips.
//!
//! # Safety screens (SPEC_DERIVATION_CUSTOM §5-§8)
//!
//! Before any address is produced the purpose (first path element) is
//! classified; `45'`/`47'` are **BLOCKED** with their own message and
//! never reach a derive, and `48'` returns
//! [`BuilderOutcome::CosignerExport`] so the caller can open the export
//! screen's cosigner view instead of a dead end (wallet-export design D6)
//! — either way this module derives no address for a multisig purpose. On a
//! rendered result the non-blocking short-path (§6), unconventional
//! script-type combination (§7.2) and `coin_type != 0'` fork-false-match
//! (§8) advisories fire in the conditions the spec defines. §24.3 hard
//! rules hold: address + master fingerprint only, never an
//! xprv/xpub/seed/chain-code/pubkey, no export/QR/persistence, the
//! empty-passphrase caveat on every result screen.

use core::fmt::Write as _;

use seed_core::arena::SecretArena;
use seed_core::contracts::{Framebuffer, PathStandard, WordCount};
use seed_derive::address::ScriptType;
use seed_derive::bip32::{HARDENED_OFFSET, MAX_DEPTH};
use seed_platform_x86::input::{InputEvent, KeySource};

use crate::flow_secret::derive;
use crate::flow_secret::gop_screen::draw_lines;
use crate::flow_secret::verification::{passphrase_caveat, read_acknowledged, FINGERPRINT_LABEL};
use crate::output::LineBuf;

/// Largest plain (non-hardened) child number the builder lets a level hold:
/// `2^31 - 1`. Values `>= 2^31` are the hardened index space (applied via
/// the per-level hardened flag), so the base value must stay below it
/// (SPEC_DERIVATION_CUSTOM §3.2, mirroring the §9.3 R12 parser bound).
pub const MAX_LEVEL_VALUE: u32 = HARDENED_OFFSET - 1;

/// The conventional single-sig receive-leaf depth
/// (`purpose'/coin_type'/account'/change/index`), below which a
/// known-purpose path gets the §6 account/change-node warning.
pub const CONVENTIONAL_LEAF_DEPTH: usize = 5;

// ============================================================================
// Purpose classification (SPEC_DERIVATION_CUSTOM §5)
// ============================================================================

/// A recognized non-single-sig purpose that MUST block single-sig rendering
/// (SPEC_DERIVATION_CUSTOM §5), each with its own reason/message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockKind {
    /// `48'` — BIP48 multisig cosigner path (P2WSH of all cosigner keys).
    Bip48Multisig,
    /// `45'` — BIP45 P2SH multisig structure path.
    Bip45Multisig,
    /// `47'` — BIP47 reusable payment codes (ECDH, not one-seed derivable).
    Bip47PaymentCode,
}

/// Classification of a path's first element (SPEC_DERIVATION_CUSTOM §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// A known single-sig purpose `{44',49',84',86'}` and its conventional
    /// script type / standard.
    SingleSigOk(PathStandard),
    /// A known non-single-sig purpose — BLOCK rendering.
    MultisigBlock(BlockKind),
    /// Any other purpose — rendered with an "unrecognized purpose" note
    /// (not blocked; it may be a legitimate bespoke single-sig path).
    Unknown,
}

/// Classify the purpose from the first level's `(base value, hardened)`.
/// Only a hardened first level is treated as a BIP-purpose; an unhardened
/// or absent first level is [`Purpose::Unknown`] (no convention to apply).
#[must_use]
pub fn classify_purpose(first_value: u32, first_hardened: bool) -> Purpose {
    if !first_hardened {
        return Purpose::Unknown;
    }
    match first_value {
        44 => Purpose::SingleSigOk(PathStandard::Bip44),
        49 => Purpose::SingleSigOk(PathStandard::Bip49),
        84 => Purpose::SingleSigOk(PathStandard::Bip84),
        86 => Purpose::SingleSigOk(PathStandard::Bip86),
        45 => Purpose::MultisigBlock(BlockKind::Bip45Multisig),
        47 => Purpose::MultisigBlock(BlockKind::Bip47PaymentCode),
        48 => Purpose::MultisigBlock(BlockKind::Bip48Multisig),
        _ => Purpose::Unknown,
    }
}

/// Classify the purpose of an already-assembled first child number (the
/// hardened bit baked in), the form the §9 free-form PARSER produces. Thin
/// decomposition wrapper over [`classify_purpose`] so both custom-path
/// surfaces — the structured builder (which holds `(value, hardened)`) and
/// the desktop free-form parser (which holds a bounded `[u32]`) — share one
/// classifier (SPEC_DERIVATION_CUSTOM §5, §12.1).
#[must_use]
pub fn classify_purpose_child(first_child: u32) -> Purpose {
    let hardened = first_child >= HARDENED_OFFSET;
    let value = if hardened { first_child - HARDENED_OFFSET } else { first_child };
    classify_purpose(value, hardened)
}

// ============================================================================
// Pure block/warn predicates over a parsed path (SPEC_DERIVATION_CUSTOM
// §6/§7.2/§8) — the single source of truth shared verbatim by the
// structured builder's own methods below AND the §9 desktop free-form
// surface (which passes the parser's bounded `[u32]` output straight in).
// ============================================================================

/// SPEC_DERIVATION_CUSTOM §6: a known single-sig purpose at a depth shorter
/// than the conventional receive leaf (i.e. an account/change node).
#[must_use]
pub fn is_short_path_for(purpose: Purpose, depth: usize) -> bool {
    matches!(purpose, Purpose::SingleSigOk(_)) && depth < CONVENTIONAL_LEAF_DEPTH
}

/// SPEC_DERIVATION_CUSTOM §7.2: a known purpose rendered with a script type
/// other than that purpose's conventional form.
#[must_use]
pub fn is_unconventional_combo_for(purpose: Purpose, script: ScriptType) -> bool {
    match purpose {
        Purpose::SingleSigOk(standard) => script != ScriptType::for_standard(standard),
        _ => false,
    }
}

/// SPEC_DERIVATION_CUSTOM §8: a known-purpose path whose `coin_type` level
/// (the second child) is not `0'` (Bitcoin mainnet). `path` is the assembled
/// child array (hardened bit applied), so `0'` is exactly `HARDENED_OFFSET`.
#[must_use]
pub fn is_nonzero_coin_type_for(purpose: Purpose, path: &[u32]) -> bool {
    matches!(purpose, Purpose::SingleSigOk(_)) && path.len() >= 2 && path[1] != HARDENED_OFFSET
}

// ============================================================================
// The builder state (public arithmetic only — no secret)
// ============================================================================

/// The live BUILD state: a bounded `[u32; MAX_DEPTH]` assembled as
/// `(base value, hardened flag)` per level, plus the chosen script type and
/// UI cursor. Deliberately `Copy` — it carries **no secret**, only public
/// path integers (SPEC_DERIVATION_CUSTOM §4.2).
#[derive(Debug, Clone, Copy)]
pub struct PathBuilder {
    /// Per-level base child number (hardened bit NOT applied), `< 2^31`.
    values: [u32; MAX_DEPTH],
    /// Per-level hardened marker.
    hardened: [bool; MAX_DEPTH],
    /// Number of active levels, `1..=MAX_DEPTH`.
    depth: usize,
    /// Edit cursor: which level `[A]/[Z]/[H]` act on, `0..depth`.
    cursor: usize,
    /// Chosen address form (SPEC_DERIVATION_CUSTOM §7).
    script: ScriptType,
    /// `[T]` read-back detail toggle (per-level breakdown vs. one line).
    detail: bool,
}

impl Default for PathBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PathBuilder {
    /// A sensible starting scaffold: `m/84'/0'/0'/0/0` as native segwit —
    /// a valid BIP84 first receive leaf the user tweaks from. Every result
    /// screen still carries the full §24.3 caveats so this default is never
    /// mistaken for "your wallet's address".
    #[must_use]
    pub fn new() -> Self {
        let mut values = [0u32; MAX_DEPTH];
        let mut hardened = [false; MAX_DEPTH];
        values[0] = 84;
        hardened[0] = true; // 84'
        hardened[1] = true; // 0'
        hardened[2] = true; // 0'
        // levels 3,4 (change, index) stay 0, non-hardened.
        Self { values, hardened, depth: CONVENTIONAL_LEAF_DEPTH, cursor: 0, script: ScriptType::P2wpkh, detail: false }
    }

    /// Active depth (`1..=MAX_DEPTH`).
    #[must_use]
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// The edit cursor level.
    #[must_use]
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// The chosen script type.
    #[must_use]
    pub fn script(&self) -> ScriptType {
        self.script
    }

    /// `[A]` — increment the selected level's base value (clamped at
    /// [`MAX_LEVEL_VALUE`]). Reaches `0`/`7`/`8`/`9` and larger without any
    /// digit key (SPEC_DERIVATION_CUSTOM §3.1).
    pub fn inc_value(&mut self) {
        let v = &mut self.values[self.cursor];
        if *v < MAX_LEVEL_VALUE {
            *v += 1;
        }
    }

    /// `[Z]` — decrement the selected level's base value (clamped at 0).
    pub fn dec_value(&mut self) {
        let v = &mut self.values[self.cursor];
        if *v > 0 {
            *v -= 1;
        }
    }

    /// `[H]` — toggle the selected level's hardened marker.
    pub fn toggle_hardened(&mut self) {
        self.hardened[self.cursor] = !self.hardened[self.cursor];
    }

    /// `[S]` — append a level (deeper), up to [`MAX_DEPTH`]. New level
    /// defaults to `0` (non-hardened) and the cursor moves onto it.
    pub fn grow(&mut self) {
        if self.depth < MAX_DEPTH {
            self.values[self.depth] = 0;
            self.hardened[self.depth] = false;
            self.depth += 1;
            self.cursor = self.depth - 1;
        }
    }

    /// `[X]` / Backspace — remove the last level (shallower), keeping at
    /// least one. The cursor is clamped back into range.
    pub fn shrink(&mut self) {
        if self.depth > 1 {
            self.depth -= 1;
            // Clear the retired slot so a later regrow starts clean.
            self.values[self.depth] = 0;
            self.hardened[self.depth] = false;
            if self.cursor >= self.depth {
                self.cursor = self.depth - 1;
            }
        }
    }

    /// `[C]` — move the edit cursor to the next level (wraps within depth).
    pub fn move_cursor(&mut self) {
        self.cursor = (self.cursor + 1) % self.depth;
    }

    /// `[1]`-`[4]` — pick the script type (SPEC_DERIVATION_CUSTOM §7.1).
    pub fn set_script(&mut self, script: ScriptType) {
        self.script = script;
    }

    /// `[T]` — toggle the read-back detail view.
    pub fn toggle_detail(&mut self) {
        self.detail = !self.detail;
    }

    /// Build the bounded child-number array + length: each entry is the base
    /// value with `HARDENED_OFFSET` added where the level is hardened
    /// (SPEC_DERIVATION_CUSTOM §3.2). This is exactly the `&[u32]`
    /// `address_at`/`derive_path` already accept.
    #[must_use]
    pub fn build_path(&self) -> ([u32; MAX_DEPTH], usize) {
        let mut out = [0u32; MAX_DEPTH];
        for i in 0..self.depth {
            out[i] = self.values[i] + if self.hardened[i] { HARDENED_OFFSET } else { 0 };
        }
        (out, self.depth)
    }

    /// Classify the first level's purpose (SPEC_DERIVATION_CUSTOM §5).
    #[must_use]
    pub fn purpose(&self) -> Purpose {
        classify_purpose(self.values[0], self.hardened[0])
    }

    /// SPEC_DERIVATION_CUSTOM §6: a known purpose at a depth shorter than
    /// the conventional receive leaf (an account/change node). Delegates to
    /// the shared [`is_short_path_for`] predicate.
    #[must_use]
    pub fn is_short_path(&self) -> bool {
        is_short_path_for(self.purpose(), self.depth)
    }

    /// SPEC_DERIVATION_CUSTOM §7.2: a known purpose rendered with a script
    /// type other than that purpose's conventional form. Delegates to the
    /// shared [`is_unconventional_combo_for`] predicate.
    #[must_use]
    pub fn is_unconventional_combo(&self) -> bool {
        is_unconventional_combo_for(self.purpose(), self.script)
    }

    /// SPEC_DERIVATION_CUSTOM §8: a BIP44-shaped known-purpose path whose
    /// `coin_type` level (second element) is not `0'` (Bitcoin mainnet).
    /// Delegates to the shared [`is_nonzero_coin_type_for`] predicate over
    /// this builder's assembled child array.
    #[must_use]
    pub fn is_nonzero_coin_type(&self) -> bool {
        let (path, len) = self.build_path();
        is_nonzero_coin_type_for(self.purpose(), &path[..len])
    }
}

// ============================================================================
// Static screen copy (SPEC_DERIVATION_CUSTOM §5-§8, §10; §24.3 hard rules)
// ============================================================================

/// BUILD-screen title.
pub const BUILD_TITLE: &str = "CUSTOM DERIVATION PATH BUILDER (air-gapped; assembled with self-test-safe keys)";
/// BUILD-screen key help, line 1.
pub const BUILD_KEYS_1: &str =
    "[1-4] script   [A]/[Z] value +/-   [H] hardened   [S]/[X] depth +/-   [C] cursor";
/// BUILD-screen key help, line 2.
pub const BUILD_KEYS_2: &str = "[T] detail read-back      [Enter] preview address      [Esc] back";

/// SPEC_DERIVATION_CUSTOM §7: the path AND script type together define the
/// address — a wrong script type is a silent mismatch, like a wrong
/// passphrase.
pub const SCRIPT_HAZARD_1: &str =
    "The path AND the script type TOGETHER define the address. A wrong script type gives a";
/// Second line of the §7 script-type hazard note.
pub const SCRIPT_HAZARD_2: &str =
    "valid-looking but WRONG address with no error - the same silent hazard as a wrong passphrase.";

/// SPEC_DERIVATION_CUSTOM §5, `48'` block message (line 1).
pub const BLOCK_BIP48_1: &str =
    "BLOCKED: multisig cosigner path (48'). Its receive address is a P2WSH of a witnessScript";
/// `48'` block message (line 2).
pub const BLOCK_BIP48_2: &str =
    "containing ALL cosigners' public keys (BIP67-sorted) and CANNOT be derived from one seed.";
/// `48'` block message (line 3).
pub const BLOCK_BIP48_3: &str =
    "This tool shows single-key addresses only. (Multisig verification is out of scope.)";

/// SPEC_DERIVATION_CUSTOM §5, `45'` block message (line 1).
pub const BLOCK_BIP45_1: &str =
    "BLOCKED: P2SH multisig structure path (45'). The address is a P2SH of a multisig script";
/// `45'` block message (line 2).
pub const BLOCK_BIP45_2: &str =
    "over ALL cosigners' keys - the same one-seed-insufficient property as 48'; a single-sig";
/// `45'` block message (line 3).
pub const BLOCK_BIP45_3: &str =
    "render would be guaranteed wrong. (Multisig verification is out of scope.)";

/// SPEC_DERIVATION_CUSTOM §5, `47'` block message (line 1) — its OWN
/// wording (payment codes / ECDH, not P2WSH multisig).
pub const BLOCK_BIP47_1: &str =
    "BLOCKED: BIP47 reusable-payment-code path (47'). Addresses come from ECDH between your";
/// `47'` block message (line 2).
pub const BLOCK_BIP47_2: &str =
    "payment code and a COUNTERPARTY's payment code, not from your seed alone; there is no";
/// `47'` block message (line 3).
pub const BLOCK_BIP47_3: &str =
    "single-key receive address to show. (Payment-code verification is out of scope.)";

/// Appended to the `45'`/`47'` block screens (wallet-export design D6).
///
/// A user who reaches one of those purposes is usually after a cosigner
/// key, and a cosigner key *is* available — on the export branch, for the
/// BIP48 path that these two obsolete purposes are almost always a
/// mistaken attempt at reaching.
pub const BLOCK_EXPORT_POINTER: &str = "See [X] Export on the verify screen.";

/// Block-screen acknowledge prompt.
pub const BLOCK_BACK_PROMPT: &str = "[Enter] Back to builder";

/// SPEC_DERIVATION_CUSTOM §6 short/account-level warning (line 1).
pub const SHORT_PATH_WARN_1: &str =
    "NOTE: this looks like an account/change node, not a receive leaf. Wallets show addresses";
/// §6 short/account-level warning (line 2).
pub const SHORT_PATH_WARN_2: &str =
    "at .../change/index (depth 5); this shorter path is valid but is NOT an address a wallet lists.";

/// SPEC_DERIVATION_CUSTOM §7.2 unconventional-combination warning (line 1).
pub const COMBO_WARN_1: &str =
    "NOTE: this purpose's conventional address type differs from the script type you chose. The";
/// §7.2 combination warning (line 2).
pub const COMBO_WARN_2: &str =
    "address is valid but will NOT match a wallet that follows the purpose's usual convention.";

/// SPEC_DERIVATION_CUSTOM §8 coin_type warning (line 1).
pub const COIN_TYPE_WARN_1: &str =
    "NOTE: coin_type is not 0' (Bitcoin mainnet); mainnet-BTC encoding is applied regardless. A";
/// §8 coin_type warning (line 2) — differing HRP is visibly different.
pub const COIN_TYPE_WARN_2: &str =
    "different-prefix coin (Litecoin ltc1.../testnet tb1...) is VISIBLY different, so no false match;";
/// §8 coin_type warning (line 3) — the shared-encoding fork false match.
pub const COIN_TYPE_WARN_3: &str =
    "but a shared-encoding fork (BCH legacy 1..., coin_type 145') renders IDENTICALLY - a false match.";

/// SPEC_DERIVATION_CUSTOM §5 unknown-purpose (non-blocking) note.
pub const UNKNOWN_PURPOSE_NOTE: &str =
    "NOTE: unrecognized purpose - verify your wallet actually uses this exact path.";

/// Result-screen title (SPEC_DERIVATION_CUSTOM §10, §24.3 framing).
pub const RESULT_TITLE: &str =
    "CUSTOM PATH PREVIEW (reference value - not secret keys, but an address reveals privacy)";
/// Result-screen "not authoritative" framing (line 1, §10.1).
pub const RESULT_FRAMING_1: &str =
    "This is your wallet's address ONLY if it uses this exact path, script type, coin and the";
/// Result-screen "not authoritative" framing (line 2, §10.1) — empty-
/// passphrase case.
pub const RESULT_FRAMING_2: &str =
    "empty passphrase. Cross-check it against your wallet; do not assume it is authoritative.";
/// SPEC_PASSPHRASE §7.3 flip of [`RESULT_FRAMING_2`] when a passphrase was
/// set.
pub const RESULT_FRAMING_2_PP: &str =
    "passphrase you entered. Cross-check it against your wallet; do not assume it is authoritative.";
/// Result-screen acknowledge prompt.
pub const RESULT_BACK_PROMPT: &str = "[Enter] Back to builder";

// ============================================================================
// Rendering helpers (output only; punctuation `/ '` appears here, never as
// a typed key — SPEC_DERIVATION_CUSTOM §2.2)
// ============================================================================

fn hex8(bytes: [u8; 4]) -> [u8; 8] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 8];
    for (i, b) in bytes.iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0x0f) as usize];
    }
    out
}

/// The human label for a script type (SPEC_DERIVATION_CUSTOM §7.1).
#[must_use]
pub fn script_label(script: ScriptType) -> &'static str {
    match script {
        ScriptType::P2pkh => "P2PKH  (legacy, 1...)",
        ScriptType::P2shP2wpkh => "P2SH-P2WPKH  (nested segwit, 3...)",
        ScriptType::P2wpkh => "P2WPKH  (native segwit, bc1q...)",
        ScriptType::P2tr => "P2TR  (taproot, bc1p...)",
    }
}

/// Write the assembled path read-back (`m/84'/0'/0'/0/0`) into `line`.
/// Output-only: `/` and `'` are rendered here, never typed
/// (SPEC_DERIVATION_CUSTOM §2.2).
fn write_path(line: &mut LineBuf, b: &PathBuilder) {
    let _ = line.write_str("m");
    for i in 0..b.depth {
        let _ = write!(line, "/{}", b.values[i]);
        if b.hardened[i] {
            let _ = line.write_str("'");
        }
    }
}

/// The purpose advisory shown live on the BUILD screen so the user sees the
/// block/convention status before committing.
fn purpose_line(b: &PathBuilder) -> &'static str {
    match b.purpose() {
        Purpose::MultisigBlock(BlockKind::Bip48Multisig) => {
            "Purpose: BIP48 cosigner - [Enter] opens the watch-only export instead."
        }
        Purpose::MultisigBlock(_) => {
            "Purpose: BLOCKED (multisig / payment-code) - preview will be refused."
        }
        Purpose::SingleSigOk(_) => "Purpose: recognized single-sig.",
        Purpose::Unknown => "Purpose: unrecognized - allowed, but verify your wallet uses it.",
    }
}

/// Render the BUILD screen (SPEC_DERIVATION_CUSTOM §3.1/§11.1). Presentation
/// only; touches no secret.
pub fn render_build(fb: &mut dyn Framebuffer, b: &PathBuilder) {
    seed_gop_ui::font::scrub_fill(fb, 0);

    let mut path_line = LineBuf::new();
    let _ = path_line.write_str("Path:   ");
    write_path(&mut path_line, b);

    let mut cursor_line = LineBuf::new();
    let _ = write!(
        cursor_line,
        "Cursor: level {} of {}   value {}{}",
        b.cursor + 1,
        b.depth,
        b.values[b.cursor],
        if b.hardened[b.cursor] { "  (hardened ')" } else { "  (normal)" },
    );

    let mut script_line = LineBuf::new();
    let _ = write!(script_line, "Script: {}", script_label(b.script));

    // Up to MAX_DEPTH per-level detail rows when [T] detail is on.
    let mut detail_rows: [LineBuf; MAX_DEPTH] = core::array::from_fn(|_| LineBuf::new());
    if b.detail {
        for (i, row) in detail_rows.iter_mut().enumerate().take(b.depth) {
            let mark = if i == b.cursor { ">" } else { " " };
            let _ = write!(
                row,
                "{mark} level {}: {}{}",
                i + 1,
                b.values[i],
                if b.hardened[i] { "'" } else { "" },
            );
        }
    }

    // Fixed line list (at most 24; see `build_screen_fits_floor`). Every
    // borrowed `&str` below (the `LineBuf`s, the detail rows) is declared
    // above and outlives this `draw_lines` call.
    let mut lines: [&str; 24] = [""; 24];
    let mut n = 0usize;
    for line in [
        BUILD_TITLE,
        "",
        BUILD_KEYS_1,
        BUILD_KEYS_2,
        "",
        path_line.as_str(),
        cursor_line.as_str(),
        script_line.as_str(),
    ] {
        lines[n] = line;
        n += 1;
    }
    if b.detail {
        lines[n] = "";
        n += 1;
        for row in detail_rows.iter().take(b.depth) {
            lines[n] = row.as_str();
            n += 1;
        }
    }
    for line in ["", purpose_line(b), "", SCRIPT_HAZARD_1, SCRIPT_HAZARD_2] {
        lines[n] = line;
        n += 1;
    }

    draw_lines(fb, &lines[..n]);
}

/// Render the block screen for `kind` (SPEC_DERIVATION_CUSTOM §5). No
/// address is produced.
pub fn render_block(fb: &mut dyn Framebuffer, kind: BlockKind) {
    seed_gop_ui::font::scrub_fill(fb, 0);
    let body: [&str; 3] = match kind {
        BlockKind::Bip48Multisig => [BLOCK_BIP48_1, BLOCK_BIP48_2, BLOCK_BIP48_3],
        BlockKind::Bip45Multisig => [BLOCK_BIP45_1, BLOCK_BIP45_2, BLOCK_BIP45_3],
        BlockKind::Bip47PaymentCode => [BLOCK_BIP47_1, BLOCK_BIP47_2, BLOCK_BIP47_3],
    };
    // `45'`/`47'` point the user at the export branch, which does have
    // something honest to show for a multisig setup (design D6). `48'`
    // does not need the pointer: it no longer reaches this screen from
    // the builder at all (see `run_custom_builder`), and this arm is kept
    // only so this function stays total over `BlockKind`.
    let pointer = match kind {
        BlockKind::Bip45Multisig | BlockKind::Bip47PaymentCode => BLOCK_EXPORT_POINTER,
        BlockKind::Bip48Multisig => "",
    };
    // A blank row before the pointer and before the prompt — but not two
    // in a row when `pointer` is itself empty (the `48'` arm), which
    // would leave a ragged gap on that screen.
    if pointer.is_empty() {
        draw_lines(fb, &[body[0], body[1], body[2], "", BLOCK_BACK_PROMPT]);
    } else {
        draw_lines(fb, &[body[0], body[1], body[2], "", pointer, "", BLOCK_BACK_PROMPT]);
    }
}

/// Render the browse-only result screen for one committed leaf
/// (SPEC_DERIVATION_CUSTOM §4.2 step 5 / §11.1 step 2). Shows the master
/// fingerprint, the assembled path, the script type, the address, the
/// empty-passphrase caveat, and every applicable §6/§7.2/§8 advisory. No
/// key on this screen triggers another derivation (the caller returns to
/// BUILD on acknowledge).
pub fn render_result(fb: &mut dyn Framebuffer, b: &PathBuilder, result: &derive::CustomAddress, passphrase_set: bool) {
    seed_gop_ui::font::scrub_fill(fb, 0);

    let fp_hex = hex8(result.master_fingerprint);
    let fp_str = core::str::from_utf8(&fp_hex).unwrap_or("????????");
    let mut fp_line = LineBuf::new();
    let _ = write!(fp_line, "{FINGERPRINT_LABEL}   {fp_str}");

    let mut path_line = LineBuf::new();
    let _ = path_line.write_str("Path     ");
    write_path(&mut path_line, b);

    let mut script_line = LineBuf::new();
    let _ = write!(script_line, "Script   {}", script_label(b.script));

    let mut addr_line = LineBuf::new();
    let _ = write!(addr_line, "Address  {}", result.address.as_str().unwrap_or("?"));

    // Fixed line list. Header(2) + fp/path/script/addr(4) + blank + caveat
    // + up to 8 advisory lines + framing(4) + back = at most 21 <= 24.
    let mut lines: [&str; 24] = [""; 24];
    let mut n = 0usize;
    for line in [
        RESULT_TITLE,
        "",
        fp_line.as_str(),
        path_line.as_str(),
        script_line.as_str(),
        addr_line.as_str(),
        "",
        passphrase_caveat(passphrase_set),
    ] {
        lines[n] = line;
        n += 1;
    }
    // Applicable advisories (SPEC_DERIVATION_CUSTOM §5/§6/§7.2/§8).
    if matches!(b.purpose(), Purpose::Unknown) {
        lines[n] = UNKNOWN_PURPOSE_NOTE;
        n += 1;
    }
    if b.is_short_path() {
        for line in [SHORT_PATH_WARN_1, SHORT_PATH_WARN_2] {
            lines[n] = line;
            n += 1;
        }
    }
    if b.is_unconventional_combo() {
        for line in [COMBO_WARN_1, COMBO_WARN_2] {
            lines[n] = line;
            n += 1;
        }
    }
    if b.is_nonzero_coin_type() {
        for line in [COIN_TYPE_WARN_1, COIN_TYPE_WARN_2, COIN_TYPE_WARN_3] {
            lines[n] = line;
            n += 1;
        }
    }
    let framing_2 = if passphrase_set { RESULT_FRAMING_2_PP } else { RESULT_FRAMING_2 };
    for line in ["", RESULT_FRAMING_1, framing_2, "", RESULT_BACK_PROMPT] {
        lines[n] = line;
        n += 1;
    }

    draw_lines(fb, &lines[..n]);
}

// ============================================================================
// The interactive driver (SPEC_DERIVATION_CUSTOM §4.2/§11.1)
// ============================================================================

/// How [`run_custom_builder`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuilderOutcome {
    /// The user backed out (`[Esc]`); return to the verification screen.
    Back,
    /// The user committed a `48'` (BIP48 multisig cosigner) path.
    ///
    /// Wallet-export design D6 replaced this purpose's dead-end block
    /// screen with the cosigner view on the `[X]` export screen: the one
    /// thing this device *can* honestly show for a multisig path is the
    /// cosigner's own account key, which is exactly what a coordinator
    /// asks for. The builder itself derives nothing here — it hands the
    /// decision back, and the caller opens
    /// [`crate::screens::export`] with
    /// [`crate::screens::export::ExportKind::Bip48Cosigner`] (behind that
    /// branch's own warning screen, which is never bypassed).
    CosignerExport,
    /// SPEC_DERIVATION_CUSTOM §4.4: a commit-phase `address_at`
    /// [`seed_core::contracts::DeriveError`] (cryptographically unreachable
    /// for a real seed). The caller routes this into the production §24.4
    /// failure screen + the fatal scrub-and-shutdown chain (SPEC §27.2).
    DeriveFailed,
}

/// Run the structured custom-path builder (PRIMARY,
/// SPEC_DERIVATION_CUSTOM §3/§4). Blocks. BUILD is pure public arithmetic;
/// each `[Enter]` COMMIT makes a single [`derive::compute_custom_address`]
/// call (which scrubs the derived seed immediately) unless the purpose is
/// blocked (§5), in which case the block screen is shown and no derive
/// happens. OQ-7: multiple commits are allowed within one session (the
/// mnemonic stays resident); the loop returns only on `[Esc]`
/// ([`BuilderOutcome::Back`]) or a commit-phase derive error
/// ([`BuilderOutcome::DeriveFailed`]).
pub fn run_custom_builder<K: KeySource + ?Sized>(
    fb: &mut dyn Framebuffer,
    keys: &mut K,
    arena: &mut SecretArena,
    word_count: WordCount,
    passphrase_set: bool,
) -> BuilderOutcome {
    let mut b = PathBuilder::new();
    loop {
        render_build(fb, &b);
        match keys.read_key_blocking() {
            InputEvent::Enter => {
                // COMMIT. Refuse to derive a blocked purpose (§5).
                if let Purpose::MultisigBlock(kind) = b.purpose() {
                    // `48'` is no longer a dead end (wallet-export design
                    // D6): hand it to the caller, which opens the export
                    // screen's cosigner view. `45'`/`47'` keep their block
                    // screens — neither is derivable from one seed, and
                    // neither has a cosigner artifact to show.
                    if kind == BlockKind::Bip48Multisig {
                        return BuilderOutcome::CosignerExport;
                    }
                    render_block(fb, kind);
                    read_acknowledged(keys);
                    continue;
                }
                let (path, len) = b.build_path();
                match derive::compute_custom_address(arena, word_count, b.script, &path[..len]) {
                    Ok(result) => {
                        render_result(fb, &b, &result, passphrase_set);
                        read_acknowledged(keys);
                        // OQ-7: stay in the session for another commit.
                    }
                    Err(_) => return BuilderOutcome::DeriveFailed,
                }
            }
            InputEvent::Escape => return BuilderOutcome::Back,
            InputEvent::Backspace => b.shrink(),
            InputEvent::Char(c) => {
                match c.to_ascii_uppercase() {
                    '1' => b.set_script(ScriptType::P2pkh),
                    '2' => b.set_script(ScriptType::P2shP2wpkh),
                    '3' => b.set_script(ScriptType::P2wpkh),
                    '4' => b.set_script(ScriptType::P2tr),
                    'A' => b.inc_value(),
                    'Z' => b.dec_value(),
                    'H' => b.toggle_hardened(),
                    'S' => b.grow(),
                    'X' => b.shrink(),
                    'C' => b.move_cursor(),
                    'T' => b.toggle_detail(),
                    _ => {}
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    use seed_core::arena::SecretArena;
    use seed_derive::bip32::{preset_path, PATH_BIP44, PATH_BIP84};

    // ------------------------------------------------------------------
    // Test doubles (mirroring verification.rs's own).
    // ------------------------------------------------------------------

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

    fn ch(c: char) -> InputEvent {
        InputEvent::Char(c)
    }

    // ------------------------------------------------------------------
    // Builder navigation: keys assemble the expected [u32; N].
    // ------------------------------------------------------------------

    /// The default scaffold is exactly `m/84'/0'/0'/0/0` = `PATH_BIP84`.
    #[test]
    fn default_builder_assembles_bip84_first_leaf() {
        let b = PathBuilder::new();
        let (path, len) = b.build_path();
        assert_eq!(len, 5);
        assert_eq!(&path[..len], &PATH_BIP84);
    }

    /// Navigation keys build the expected array: change purpose 84'->44'
    /// via [Z] x40, pick P2PKH, and confirm it equals `PATH_BIP44` (which
    /// is `m/44'/0'/0'/0/0`).
    #[test]
    fn navigation_builds_bip44_path_with_only_safe_keys() {
        let mut b = PathBuilder::new();
        // cursor starts at level 0 (value 84, hardened). Decrement to 44.
        for _ in 0..40 {
            b.dec_value();
        }
        let (path, len) = b.build_path();
        assert_eq!(&path[..len], &PATH_BIP44, "84' decremented 40x must be 44'");
    }

    /// Increment/decrement reach values whose digit keys (0,7,8,9) are NOT
    /// in the §11.5 set, without ever typing them; hardened toggle and the
    /// depth axis assemble an arbitrary bounded path.
    #[test]
    fn builder_reaches_forbidden_digit_values_and_bounds() {
        let mut b = PathBuilder::new();
        b.grow(); // depth 6, cursor at new level 5 (value 0)
        assert_eq!(b.depth(), 6);
        for _ in 0..9 {
            b.inc_value(); // reach 9 (a forbidden digit) with [A] only
        }
        let (path, len) = b.build_path();
        assert_eq!(len, 6);
        assert_eq!(path[5], 9);

        // Depth clamps at MAX_DEPTH.
        for _ in 0..20 {
            b.grow();
        }
        assert_eq!(b.depth(), MAX_DEPTH);
        // ...and never below 1.
        for _ in 0..50 {
            b.shrink();
        }
        assert_eq!(b.depth(), 1);
    }

    /// Hardened toggle flips exactly the cursor level's `HARDENED_OFFSET`.
    #[test]
    fn hardened_toggle_applies_offset_on_cursor_level() {
        let mut b = PathBuilder::new();
        b.move_cursor(); // level 1 (0', hardened)
        b.toggle_hardened(); // now normal 0
        let (path, _) = b.build_path();
        assert_eq!(path[1], 0, "un-hardened level 1 must drop HARDENED_OFFSET");
        b.toggle_hardened();
        let (path2, _) = b.build_path();
        assert_eq!(path2[1], HARDENED_OFFSET, "re-hardened level 1 must re-add HARDENED_OFFSET");
    }

    /// The base value stays within `0 ..= MAX_LEVEL_VALUE` (< 2^31). Level 0
    /// starts hardened, so once its base value clamps at 0 the assembled
    /// child number is exactly `HARDENED_OFFSET` (base 0 + hardened bit).
    #[test]
    fn value_clamps_at_zero_and_below_hardened_boundary() {
        let mut b = PathBuilder::new();
        for _ in 0..100 {
            b.dec_value();
        }
        assert_eq!(b.build_path().0[0], HARDENED_OFFSET, "base value clamps at 0 (level 0 stays hardened)");
        // Un-harden the level and the same base value renders as plain 0.
        b.toggle_hardened();
        assert_eq!(b.build_path().0[0], 0, "un-hardened, the clamped base value is 0");
    }

    /// Script-type picks map `[1]`-`[4]` to the four `ScriptType`s.
    #[test]
    fn script_picker_maps_1_to_4() {
        let mut b = PathBuilder::new();
        b.set_script(ScriptType::P2pkh);
        assert_eq!(b.script(), ScriptType::P2pkh);
        b.set_script(ScriptType::P2tr);
        assert_eq!(b.script(), ScriptType::P2tr);
    }

    // ------------------------------------------------------------------
    // Purpose classification / block / warnings (§5-§8).
    // ------------------------------------------------------------------

    #[test]
    fn classify_purpose_single_sig_multisig_and_unknown() {
        assert_eq!(classify_purpose(44, true), Purpose::SingleSigOk(PathStandard::Bip44));
        assert_eq!(classify_purpose(84, true), Purpose::SingleSigOk(PathStandard::Bip84));
        assert_eq!(classify_purpose(45, true), Purpose::MultisigBlock(BlockKind::Bip45Multisig));
        assert_eq!(classify_purpose(47, true), Purpose::MultisigBlock(BlockKind::Bip47PaymentCode));
        assert_eq!(classify_purpose(48, true), Purpose::MultisigBlock(BlockKind::Bip48Multisig));
        assert_eq!(classify_purpose(1234, true), Purpose::Unknown);
        // A non-hardened first level is never a BIP purpose.
        assert_eq!(classify_purpose(84, false), Purpose::Unknown);
    }

    /// Each blocked purpose has a DISTINCT message and 47' is not worded as
    /// P2WSH multisig (SPEC_DERIVATION_CUSTOM §5).
    #[test]
    fn block_messages_are_distinct_and_47_has_its_own_wording() {
        let all = [BLOCK_BIP48_1, BLOCK_BIP45_1, BLOCK_BIP47_1];
        assert_ne!(all[0], all[1]);
        assert_ne!(all[1], all[2]);
        assert_ne!(all[0], all[2]);
        let bip47 = [BLOCK_BIP47_1, BLOCK_BIP47_2, BLOCK_BIP47_3].join(" ");
        assert!(bip47.contains("ECDH") && bip47.to_lowercase().contains("payment"));
        assert!(!bip47.to_lowercase().contains("p2wsh"), "47' must not be worded as P2WSH multisig");
        let bip48 = [BLOCK_BIP48_1, BLOCK_BIP48_2, BLOCK_BIP48_3].join(" ");
        assert!(bip48.contains("P2WSH") && bip48.to_lowercase().contains("cosigner"));
        let bip45 = [BLOCK_BIP45_1, BLOCK_BIP45_2, BLOCK_BIP45_3].join(" ");
        assert!(bip45.contains("P2SH") && bip45.to_lowercase().contains("multisig"));
    }

    #[test]
    fn short_path_warning_fires_below_depth_5_for_known_purpose() {
        let mut b = PathBuilder::new(); // 84', depth 5
        assert!(!b.is_short_path());
        b.shrink(); // depth 4
        assert!(b.is_short_path(), "depth 4 known purpose is an account/change node");
        // An unknown purpose never fires the short-path warning.
        let mut u = PathBuilder::new();
        u.dec_value(); // 83' -> unknown purpose
        while u.depth() > 3 {
            u.shrink();
        }
        assert!(!u.is_short_path());
    }

    #[test]
    fn combo_warning_fires_on_purpose_script_mismatch_only() {
        let mut b = PathBuilder::new(); // 84' + P2WPKH: conventional
        assert!(!b.is_unconventional_combo());
        b.set_script(ScriptType::P2tr); // 84' + taproot: unconventional
        assert!(b.is_unconventional_combo());
        // Unknown purpose: no convention to violate.
        let mut u = PathBuilder::new();
        u.inc_value(); // 85' unknown
        u.set_script(ScriptType::P2tr);
        assert!(!u.is_unconventional_combo());
    }

    #[test]
    fn coin_type_warning_fires_when_second_level_not_zero_hardened() {
        let mut b = PathBuilder::new(); // 84'/0'/... : coin_type 0'
        assert!(!b.is_nonzero_coin_type());
        b.move_cursor(); // cursor -> level 1 (coin_type)
        b.inc_value(); // coin_type 1'
        assert!(b.is_nonzero_coin_type());
    }

    // ------------------------------------------------------------------
    // §11.5 key-set discipline: the builder never consumes a forbidden key.
    // ------------------------------------------------------------------

    /// Every key the builder acts on is in the §11.5 set
    /// `{A-Z, 1-6, H, T, Backspace, Enter}` and Escape (for back). A digit
    /// outside `1-6` (e.g. '0','7','8','9') and stray punctuation are
    /// ignored, never mutating the build state.
    #[test]
    fn builder_ignores_keys_outside_the_self_test_set() {
        let mut b = PathBuilder::new();
        let before = b.build_path();
        // Forbidden digits and punctuation must be no-ops in char handling.
        for c in ['0', '7', '8', '9', '/', '\'', '.', ' '] {
            match c.to_ascii_uppercase() {
                '1' => b.set_script(ScriptType::P2pkh),
                '2' => b.set_script(ScriptType::P2shP2wpkh),
                '3' => b.set_script(ScriptType::P2wpkh),
                '4' => b.set_script(ScriptType::P2tr),
                'A' => b.inc_value(),
                'Z' => b.dec_value(),
                'H' => b.toggle_hardened(),
                'S' => b.grow(),
                'X' => b.shrink(),
                'C' => b.move_cursor(),
                'T' => b.toggle_detail(),
                _ => {}
            }
        }
        assert_eq!(b.build_path(), before, "forbidden keys must not mutate the build state");
    }

    /// No static builder line ever names a secret artifact (mirrors
    /// verification.rs's `never_mentions_xpub_xprv_or_seed`;
    /// SPEC_DERIVATION_CUSTOM §10 rules 1-2). Note: "seed" as an ordinary
    /// English word is intentionally NOT banned — the §5 block copy uses it
    /// ("cannot be derived from one seed"), exactly as verification.rs's own
    /// promoted-preview copy does. The real guarantee that no seed VALUE is
    /// rendered is structural: `render_result` only ever receives a public
    /// `CustomAddress` (fingerprint + one address).
    #[test]
    fn no_static_line_mentions_xpub_xprv_chaincode_or_pubkey() {
        let forbidden = ["xpub", "xprv", "private key", "chain code", "pubkey"];
        let lines = [
            BUILD_TITLE, BUILD_KEYS_1, BUILD_KEYS_2, SCRIPT_HAZARD_1, SCRIPT_HAZARD_2,
            BLOCK_BIP48_1, BLOCK_BIP48_2, BLOCK_BIP48_3, BLOCK_BIP45_1, BLOCK_BIP45_2, BLOCK_BIP45_3,
            BLOCK_BIP47_1, BLOCK_BIP47_2, BLOCK_BIP47_3, BLOCK_BACK_PROMPT,
            SHORT_PATH_WARN_1, SHORT_PATH_WARN_2, COMBO_WARN_1, COMBO_WARN_2,
            COIN_TYPE_WARN_1, COIN_TYPE_WARN_2, COIN_TYPE_WARN_3, UNKNOWN_PURPOSE_NOTE,
            RESULT_TITLE, RESULT_FRAMING_1, RESULT_FRAMING_2, RESULT_BACK_PROMPT,
            script_label(ScriptType::P2pkh), script_label(ScriptType::P2shP2wpkh),
            script_label(ScriptType::P2wpkh), script_label(ScriptType::P2tr),
            purpose_line(&PathBuilder::new()),
        ];
        for line in lines {
            let lower = line.to_lowercase();
            for bad in forbidden {
                assert!(!lower.contains(bad), "line {line:?} must never mention {bad:?}");
            }
        }
    }

    /// Every builder screen fits the 800x600 console floor (<= 98 cols,
    /// <= 24 rows). `draw_glyph` clips silently past the edges, so this is
    /// a hard correctness bound.
    #[test]
    fn build_screen_fits_floor() {
        for line in [
            BUILD_TITLE, BUILD_KEYS_1, BUILD_KEYS_2, SCRIPT_HAZARD_1, SCRIPT_HAZARD_2,
            BLOCK_BIP48_1, BLOCK_BIP48_2, BLOCK_BIP48_3, BLOCK_BIP45_1, BLOCK_BIP45_2, BLOCK_BIP45_3,
            BLOCK_BIP47_1, BLOCK_BIP47_2, BLOCK_BIP47_3,
            SHORT_PATH_WARN_1, SHORT_PATH_WARN_2, COMBO_WARN_1, COMBO_WARN_2,
            COIN_TYPE_WARN_1, COIN_TYPE_WARN_2, COIN_TYPE_WARN_3, UNKNOWN_PURPOSE_NOTE,
            RESULT_TITLE, RESULT_FRAMING_1, RESULT_FRAMING_2,
        ] {
            assert!(line.chars().count() <= 98, "line exceeds 98-col floor ({}): {line:?}", line.chars().count());
        }
    }

    // ------------------------------------------------------------------
    // COMMIT cross-check against published BIP84 vectors (through the
    // resident-mnemonic derive path) + secret-lifecycle scrub assertions.
    // ------------------------------------------------------------------

    /// BIP32 word index for a BIP39 wordlist entry.
    fn word_index(target: &str) -> u16 {
        (0..2048u16).find(|&i| seed_core::bip39::word(i) == target).expect("word in list")
    }

    /// Load the canonical "abandon abandon ... about" 12-word mnemonic into
    /// an arena's `mnemonic_indexes` (empty passphrase; SPEC §24.2 test
    /// seed), so a commit re-derives the widely-published BIP84 vectors.
    fn arena_with_abandon_mnemonic() -> SecretArena {
        let abandon = word_index("abandon");
        let about = word_index("about");
        let mut arena = SecretArena::new();
        {
            let idx = arena.mnemonic_indexes();
            for slot in idx.iter_mut().take(11) {
                *slot = abandon;
            }
            idx[11] = about;
        }
        arena
    }

    // BIP84 mediawiki published vectors for "abandon abandon ... about",
    // empty passphrase:
    //   m/84'/0'/0'/0/0 = first receive
    //   m/84'/0'/0'/0/1 = second receive
    const BIP84_RECEIVE_0: &str = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
    const BIP84_RECEIVE_1: &str = "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g";

    #[test]
    fn commit_reproduces_published_bip84_receive_addresses() {
        let mut arena = arena_with_abandon_mnemonic();

        let r0 = derive::compute_custom_address(
            &mut arena,
            WordCount::Twelve,
            ScriptType::P2wpkh,
            &preset_path(PathStandard::Bip84, 0, 0, 0),
        )
        .unwrap();
        assert_eq!(r0.address.as_str().unwrap(), BIP84_RECEIVE_0);
        // BIP84 mediawiki also pins this mnemonic's master fingerprint.
        assert_eq!(r0.master_fingerprint, [0x73, 0xc5, 0xda, 0x0a]);

        let r1 = derive::compute_custom_address(
            &mut arena,
            WordCount::Twelve,
            ScriptType::P2wpkh,
            &preset_path(PathStandard::Bip84, 0, 0, 1),
        )
        .unwrap();
        assert_eq!(r1.address.as_str().unwrap(), BIP84_RECEIVE_1);
    }

    /// SECRET LIFECYCLE (SPEC_DERIVATION_CUSTOM §4.2): after a commit, the
    /// derived seed / master-key arena fields are zeroed, but the mnemonic
    /// indexes stay RESIDENT (OQ-7: multiple commits per session). A second
    /// commit still succeeds against the resident mnemonic.
    #[test]
    fn commit_scrubs_derived_seed_but_retains_resident_mnemonic() {
        let mut arena = arena_with_abandon_mnemonic();
        let indexes_before = *arena.mnemonic_indexes();

        let _ = derive::compute_custom_address(
            &mut arena,
            WordCount::Twelve,
            ScriptType::P2wpkh,
            &preset_path(PathStandard::Bip84, 0, 0, 0),
        )
        .unwrap();

        // Derived seed scrubbed immediately (per-commit).
        assert!(arena.bip39_seed().iter().all(|&b| b == 0), "bip39 seed must be scrubbed after commit");
        assert!(arena.master_key().iter().all(|&b| b == 0), "master key must be scrubbed after commit");
        assert!(arena.master_chain_code().iter().all(|&b| b == 0), "chain code must be scrubbed after commit");
        // Mnemonic still resident for a further commit (OQ-7).
        assert_eq!(*arena.mnemonic_indexes(), indexes_before, "mnemonic must stay resident across a commit");

        // A second commit still works (proves residency is usable).
        let r2 = derive::compute_custom_address(
            &mut arena,
            WordCount::Twelve,
            ScriptType::P2wpkh,
            &preset_path(PathStandard::Bip84, 0, 0, 1),
        )
        .unwrap();
        assert_eq!(r2.address.as_str().unwrap(), BIP84_RECEIVE_1);
        assert!(arena.bip39_seed().iter().all(|&b| b == 0), "seed re-scrubbed after the second commit");

        // The whole-arena scrub (SPEC §26 / fatal / panic path) then wipes
        // the still-resident mnemonic too.
        arena.scrub_all();
        assert!(arena.mnemonic_indexes().iter().all(|&w| w == 0), "shutdown scrub must clear the mnemonic");
    }

    // ------------------------------------------------------------------
    // End-to-end driver: block screen refuses to derive; result screen
    // draws; [Esc] returns Back.
    // ------------------------------------------------------------------

    #[test]
    fn run_builder_blocks_multisig_then_commits_then_backs_out() {
        let mut arena = arena_with_abandon_mnemonic();
        let mut fb = VecFb::new(1024, 768);
        // From the 84' default: [Z]x39 -> 45' (blocked). Enter -> block
        // screen -> Enter ack. Then [A]x39 back to 84'. Enter -> commit
        // (result screen) -> Enter ack. Then Esc -> Back.
        let mut keys = std::vec::Vec::new();
        for _ in 0..39 {
            keys.push(ch('Z'));
        }
        keys.push(InputEvent::Enter); // commit attempt on 45' -> blocked
        keys.push(InputEvent::Enter); // ack block screen
        for _ in 0..39 {
            keys.push(ch('A')); // back to 84'
        }
        keys.push(InputEvent::Enter); // commit 84' path -> result screen
        keys.push(InputEvent::Enter); // ack result screen
        keys.push(InputEvent::Escape); // back out
        let mut sk = ScriptedKeys::new(keys);

        let outcome = run_custom_builder(&mut fb, &mut sk, &mut arena, WordCount::Twelve, false);
        assert_eq!(outcome, BuilderOutcome::Back);
        assert!(fb.buf.iter().any(|&p| p != 0), "the builder must have drawn something");
        // The commit that ran scrubbed the seed.
        assert!(arena.bip39_seed().iter().all(|&b| b == 0));
    }

    /// Wallet-export design D6: committing a `48'` path no longer dead-ends
    /// on a block screen — it leaves the builder with
    /// [`BuilderOutcome::CosignerExport`], and derives nothing on the way
    /// out.
    #[test]
    fn run_builder_routes_a_committed_bip48_path_to_the_cosigner_export() {
        let mut arena = arena_with_abandon_mnemonic();
        let mut fb = VecFb::new(1024, 768);
        // From the 84' default: [Z]x36 -> 48'. Enter -> CosignerExport.
        let mut keys = std::vec::Vec::new();
        for _ in 0..36 {
            keys.push(ch('Z'));
        }
        keys.push(InputEvent::Enter);
        // A trailing Esc that must never be consumed: the builder has to
        // return on the Enter above, not fall through to another screen.
        keys.push(InputEvent::Escape);
        let mut sk = ScriptedKeys::new(keys);

        let outcome = run_custom_builder(&mut fb, &mut sk, &mut arena, WordCount::Twelve, false);
        assert_eq!(outcome, BuilderOutcome::CosignerExport);
        // No derivation happened on this path.
        assert!(arena.bip39_seed().iter().all(|&b| b == 0));
    }

    /// The `45'`/`47'` block screens point the user at the export branch;
    /// the (now builder-unreachable) `48'` screen does not need to.
    #[test]
    fn block_copy_points_45_and_47_at_the_export_screen() {
        assert!(BLOCK_EXPORT_POINTER.contains("[X] Export"));
        assert_eq!(BLOCK_EXPORT_POINTER, "See [X] Export on the verify screen.");
        assert_eq!(classify_purpose(48, true), Purpose::MultisigBlock(BlockKind::Bip48Multisig));
        // The BUILD-screen advisory tells the user what `[Enter]` will do
        // on a `48'` path, rather than promising a refusal.
        let mut b = PathBuilder::new();
        for _ in 0..36 {
            b.dec_value(); // 84' -> 48'
        }
        assert_eq!(b.purpose(), Purpose::MultisigBlock(BlockKind::Bip48Multisig));
        let line = purpose_line(&b);
        assert!(line.contains("BIP48 cosigner"), "{line}");
        assert!(!line.contains("BLOCKED"), "{line}");
        // …while 45' still promises a refusal.
        for _ in 0..3 {
            b.dec_value(); // 48' -> 45'
        }
        assert_eq!(b.purpose(), Purpose::MultisigBlock(BlockKind::Bip45Multisig));
        assert!(purpose_line(&b).contains("BLOCKED"));
    }

    #[test]
    fn render_block_and_result_draw_without_panicking() {
        let mut arena = arena_with_abandon_mnemonic();
        let mut fb = VecFb::new(1024, 768);
        for kind in [BlockKind::Bip48Multisig, BlockKind::Bip45Multisig, BlockKind::Bip47PaymentCode] {
            render_block(&mut fb, kind);
            assert!(fb.buf.iter().any(|&p| p != 0));
        }
        // A result screen with all advisories active (44' as taproot,
        // short depth, nonzero coin_type).
        let mut b = PathBuilder::new();
        for _ in 0..40 {
            b.dec_value(); // 84' -> 44'
        }
        b.set_script(ScriptType::P2tr); // unconventional combo
        b.move_cursor();
        b.inc_value(); // coin_type 1'
        while b.depth() > 3 {
            b.shrink(); // short path (depth 3)
        }
        let (path, len) = b.build_path();
        let result = derive::compute_custom_address(&mut arena, WordCount::Twelve, b.script(), &path[..len]).unwrap();
        render_result(&mut fb, &b, &result, false);
        assert!(fb.buf.iter().any(|&p| p != 0));
    }
}
