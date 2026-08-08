//! The Stage-7 `[X]` export screen: the opt-in, warning-gated display of
//! an account extended **public** key, the output descriptor built from
//! it, and a QR of whichever of the two a wallet consumes
//! (`docs/superpowers/specs/2026-08-07-wallet-export-design.md` §3 step 3,
//! D2/D3/D4/D6/D7).
//!
//! Reached only through [`crate::screens::export_warning`], which is
//! reached only through `[X]` on [`crate::screens::verify`]. Nothing here
//! is ambient: no other screen in the product derives, holds or draws an
//! extended key.
//!
//! # What is on screen
//!
//! * `[1]`-`[4]` — the four single-signature account kinds. The screen
//!   shows the account path, the master fingerprint, the account xpub and
//!   the descriptor (`pkh`/`sh(wpkh)`/`wpkh`/`tr`) that a watch-only
//!   wallet imports verbatim.
//! * `[5]` — the BIP48 multisig **cosigner** view (design D6). It shows
//!   fingerprint + BIP48 path + account xpub, and deliberately renders
//!   **no address and no descriptor**: a cosigner's receive address is a
//!   P2WSH of *all* cosigners' keys, so any single-sig address this
//!   device could compute would be wrong. What it shows and encodes
//!   instead is the BIP-380 key expression
//!   `[<fingerprint>/48h/0h/<account>h/2h]<xpub>` — key origin plus
//!   account key, the exact string a coordinator ingests.
//!   Repeated `[5]` steps the
//!   account index within [`BIP48_ACCOUNT_MAX`] (design §8 OQ-A: 0..=3,
//!   matching the grid's `N_ACCOUNT_MAX`).
//! * `[T]` — SLIP-132 display encoding (design D7). Only BIP49 and BIP84
//!   have SLIP-132 forms (`ypub`/`zpub`); for every other kind the toggle
//!   is inert *by design*, and the Encoding row says so rather than
//!   leaving the user wondering whether the key changed.
//! * `[Enter]` — back to Verify.
//!
//! # Leak posture
//!
//! [`ExportValues`] holds public data only — a fingerprint, a serialized
//! extended *public* key, a descriptor, and a QR matrix of one of the
//! latter two. There is no extended-private-key type anywhere in the
//! workspace to hold (`seed_derive::bip32::serialize`'s own negative
//! tests), and this module never names one.
//!
//! Public is not the same as harmless: an account xpub links every
//! address in that account forever. So the buffers are scrubbed on the
//! way out ([`ExportValues::scrub`]) under the same policy as address
//! buffers, and the literal `xpub`/`ypub`/`zpub` is permitted in a
//! rendered line *only* in this module and
//! [`crate::screens::export_warning`] — an allowlist enumerated by the
//! `tests/leakage` scope test. `xprv`, `private key` and `chain code`
//! keep their global ban with an empty allowlist, here included.
//!
//! [`compute_export`] is the one function in this module that touches the
//! arena. It follows `flow_secret::derive::compute_custom_address`'s
//! scrub discipline exactly — see its own doc comment for the walk.
//!
//! All copy is plain ASCII (the embedded 8x16 font covers `0x20..=0x7E`).

use core::fmt::Write as _;

use seed_core::arena::SecretArena;
use seed_core::contracts::{DeriveError, Framebuffer, PathStandard, WordCount};
use seed_derive::bip32::serialize::{serialize_xpub, XpubVersion, XPUB_MAX_LEN};
use seed_derive::bip32::{account_public, path_bip48_native, HARDENED_OFFSET};
use seed_derive::descriptor::{build_descriptor, DescriptorKind, DESCRIPTOR_MAX_LEN};
use seed_gop_ui::font::{draw_text, GLYPH_WIDTH};
use seed_gop_ui::gop::mode::MIN_WIDTH;
use seed_gop_ui::layout::{LINE_PITCH, MARGIN_X};
use seed_gop_ui::{panel, qr, theme};
use seed_platform_x86::input::InputEvent;

use crate::chrome::{self, Chrome, KeyHint};
use crate::flow_secret::derive::scrub_after_verification;
use crate::flow_secret::verification::{hex8, wallet_label};
use crate::output::LineBuf;
use crate::screens::verify::{chunk4, CHUNK_CAP};

// ============================================================================
// Copy
// ============================================================================

/// 1-based ceremony stage this screen belongs to.
pub const STAGE: u8 = 7;

/// Header sub-label for the export branch.
pub const SUB: &str = "EXPORT";

/// First caption under the QR: what the whole screen is. Deliberately the
/// most prominent statement in the left column, so a photograph of the
/// screen is self-describing and can never be mistaken for a seed backup
/// (design §3 step 3: "Caption under the QR states exactly what is
/// encoded").
pub const QR_CAPTION_PUBLIC: &str = "Watch-only export - contains no private key";

/// Second caption under the QR when a descriptor is on screen.
pub const QR_CAPTION_DESCRIPTOR: &str = "QR = the descriptor shown on the right";

/// Second caption under the QR in the cosigner view, which has no
/// descriptor to encode (see the module doc comment).
pub const QR_CAPTION_COSIGNER_KEY: &str = "QR = the cosigner key shown on the right";

/// Caption over the account extended public key.
pub const XPUB_LABEL: &str = "Account extended public key:";

/// Caption over the cosigner view's key-origin-annotated account key —
/// the exact string a coordinator ingests (see [`build_origin_key`]).
pub const COSIGNER_KEY_LABEL: &str = "Cosigner key (origin + account key):";

/// Caption over the descriptor.
pub const DESCRIPTOR_LABEL: &str = "Descriptor - import this into a watch-only wallet:";

/// The cosigner view's static explanation of what a coordinator does with
/// the key on screen (design D6). Split across three rows to fit the
/// text column at the 800x600 floor; [`COSIGNER_CAPTION`] is the single
/// normative sentence they must reassemble to, pinned by
/// [`tests::cosigner_caption_rows_reassemble_the_normative_sentence`].
pub const COSIGNER_CAPTION_1: &str = "Your coordinator combines cosigner keys into";
/// Second row of the cosigner caption — see [`COSIGNER_CAPTION_1`].
pub const COSIGNER_CAPTION_2: &str = "wsh(sortedmulti(...)) - Alea shows only YOUR";
/// Third row of the cosigner caption — see [`COSIGNER_CAPTION_1`].
pub const COSIGNER_CAPTION_3: &str = "key material.";

/// The normative cosigner caption, as one sentence.
pub const COSIGNER_CAPTION: &str = "Your coordinator combines cosigner keys into wsh(sortedmulti(...)) - Alea shows only YOUR key material.";

/// Label for the cosigner view's kind row (the single-sig kinds reuse
/// `flow_secret::verification::wallet_label`, so this screen and the
/// verification screens can never name the same standard differently).
pub const COSIGNER_KIND_LABEL: &str = "Multisig cosigner (BIP48)";

/// Encoding row value: canonical BIP32 version bytes.
pub const ENCODING_STANDARD: &str = "xpub (standard)";
/// Encoding row value: SLIP-132 BIP49 form.
pub const ENCODING_YPUB: &str = "ypub (SLIP-132)";
/// Encoding row value: SLIP-132 BIP84 form.
pub const ENCODING_ZPUB: &str = "zpub (SLIP-132)";
/// Encoding row value shown when `[T]` is on for a kind that has no
/// SLIP-132 form — the toggle is inert here, and saying so is better
/// than a silently unchanged screen.
pub const ENCODING_NO_SLIP132: &str = "xpub (no SLIP-132 form)";

/// Row captions in the left-hand label field.
const LABEL_KIND: &str = "Script type";
/// Row caption for the cosigner view, whose "script type" is not a
/// single-sig script at all.
const LABEL_KIND_COSIGNER: &str = "Key type";
/// Row caption for the account derivation path.
const LABEL_PATH: &str = "Account path";
/// Row caption for the master fingerprint.
const LABEL_FINGERPRINT: &str = "Fingerprint";
/// Row caption for the display encoding.
const LABEL_ENCODING: &str = "Encoding";

/// First line of the persistent privacy panel (design §3 step 3: "the
/// `WARN` panel restating the privacy line").
pub const PRIVACY_LINE_1: &str =
    "This links every address in this account: anyone who scans or photographs it can";
/// Second line of the persistent privacy panel.
pub const PRIVACY_LINE_2: &str =
    "watch your balance and history forever. Share it only with wallets you control.";

/// This screen's footer key set.
pub const HINTS: [KeyHint; 4] = [
    KeyHint { key: "1-4", label: "Script type", enabled: true, danger: false },
    KeyHint { key: "5", label: "Cosigner (BIP48)", enabled: true, danger: false },
    KeyHint { key: "T", label: "SLIP-132 (ypub/zpub)", enabled: true, danger: false },
    KeyHint { key: "Enter", label: "Back", enabled: true, danger: false },
];

// ============================================================================
// State
// ============================================================================

/// Which artifact the screen is currently showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportKind {
    /// `m/44'/0'/0'` + `pkh(...)`.
    Bip44,
    /// `m/49'/0'/0'` + `sh(wpkh(...))`.
    Bip49,
    /// `m/84'/0'/0'` + `wpkh(...)`.
    Bip84,
    /// `m/86'/0'/0'` + `tr(...)`.
    Bip86,
    /// `m/48'/0'/account'/2'` — the multisig cosigner view. No
    /// descriptor, no address (see the module doc comment).
    Bip48Cosigner,
}

impl ExportKind {
    /// The `PathStandard` this kind corresponds to, or `None` for the
    /// cosigner view (which is not a single-sig standard at all).
    #[must_use]
    pub const fn standard(self) -> Option<PathStandard> {
        match self {
            ExportKind::Bip44 => Some(PathStandard::Bip44),
            ExportKind::Bip49 => Some(PathStandard::Bip49),
            ExportKind::Bip84 => Some(PathStandard::Bip84),
            ExportKind::Bip86 => Some(PathStandard::Bip86),
            ExportKind::Bip48Cosigner => None,
        }
    }

    /// The descriptor template for this kind, or `None` for the cosigner
    /// view — Alea never assembles a multisig descriptor, which would
    /// need the other cosigners' keys this device deliberately never
    /// sees (design D6).
    #[must_use]
    pub const fn descriptor_kind(self) -> Option<DescriptorKind> {
        match self {
            ExportKind::Bip44 => Some(DescriptorKind::Pkh),
            ExportKind::Bip49 => Some(DescriptorKind::ShWpkh),
            ExportKind::Bip84 => Some(DescriptorKind::Wpkh),
            ExportKind::Bip86 => Some(DescriptorKind::Tr),
            ExportKind::Bip48Cosigner => None,
        }
    }

    /// The SLIP-132 version this kind is displayed under when `[T]` is
    /// on, or `None` when no SLIP-132 form is defined for it — BIP44,
    /// BIP86 and the BIP48 cosigner branch all fall in the latter class,
    /// which is what makes `[T]` inert there (design D7).
    #[must_use]
    pub const fn slip132_version(self) -> Option<XpubVersion> {
        match self {
            ExportKind::Bip49 => Some(XpubVersion::Ypub),
            ExportKind::Bip84 => Some(XpubVersion::Zpub),
            ExportKind::Bip44 | ExportKind::Bip86 | ExportKind::Bip48Cosigner => None,
        }
    }

    /// The human-readable name of this kind.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self.standard() {
            Some(standard) => wallet_label(standard),
            None => COSIGNER_KIND_LABEL,
        }
    }
}

/// Largest BIP48 account index the cosigner view will step to (design §8
/// OQ-A; matches `seed_core::pipeline::N_ACCOUNT_MAX`).
pub const BIP48_ACCOUNT_MAX: u32 = 3;

/// Which of the footer actions the user took.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportOutcome {
    /// `[Enter]` — leave the export branch and return to Verify. The
    /// caller MUST call [`ExportValues::scrub`] on this edge.
    Back,
}

/// The export screen's entire mutable state. Not secret-bearing (a kind,
/// a boolean and a bounded index), so the ordinary derives apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportState {
    /// Which artifact is showing.
    pub kind: ExportKind,
    /// Whether `[T]` selected the SLIP-132 display encoding. Inert for
    /// kinds whose [`ExportKind::slip132_version`] is `None`.
    pub slip132: bool,
    /// BIP48 account index for the cosigner view, always
    /// `0..=BIP48_ACCOUNT_MAX`.
    pub cosigner_account: u32,
}

impl Default for ExportState {
    fn default() -> Self {
        Self::new()
    }
}

impl ExportState {
    /// A fresh screen: native segwit (the default a modern wallet wants),
    /// canonical `xpub` encoding, cosigner account 0.
    #[must_use]
    pub const fn new() -> Self {
        Self { kind: ExportKind::Bip84, slip132: false, cosigner_account: 0 }
    }

    /// Fold one keystroke into the screen. Returns `Some(outcome)` when
    /// the key leaves the screen and `None` when it was handled in place
    /// or ignored. Case-insensitive on letters, like every other key
    /// handler in this crate.
    ///
    /// A key that changes what is displayed returns `None`; the caller
    /// re-derives via [`compute_export`] and re-renders. Nothing here
    /// derives anything itself.
    #[must_use = "an ignored ExportOutcome leaves the user stuck on the export screen"]
    pub fn handle_key(&mut self, k: InputEvent) -> Option<ExportOutcome> {
        match k {
            InputEvent::Enter => Some(ExportOutcome::Back),
            InputEvent::Char('1') => {
                self.kind = ExportKind::Bip44;
                None
            }
            InputEvent::Char('2') => {
                self.kind = ExportKind::Bip49;
                None
            }
            InputEvent::Char('3') => {
                self.kind = ExportKind::Bip84;
                None
            }
            InputEvent::Char('4') => {
                self.kind = ExportKind::Bip86;
                None
            }
            InputEvent::Char('5') => {
                // First `[5]` enters the cosigner view; each further
                // `[5]` steps the account index, wrapping at the design's
                // 0..=3 bound so the whole reachable set is walkable from
                // one key without adding another.
                if self.kind == ExportKind::Bip48Cosigner {
                    self.cosigner_account = if self.cosigner_account >= BIP48_ACCOUNT_MAX {
                        0
                    } else {
                        self.cosigner_account + 1
                    };
                } else {
                    self.kind = ExportKind::Bip48Cosigner;
                    self.cosigner_account = 0;
                }
                None
            }
            InputEvent::Char(c) if c.eq_ignore_ascii_case(&'t') => {
                self.slip132 = !self.slip132;
                None
            }
            _ => None,
        }
    }

    /// The account-level derivation path this state exports, as
    /// `(levels, len)`.
    #[must_use]
    pub fn account_path(&self) -> ([u32; 4], usize) {
        let purpose = match self.kind {
            ExportKind::Bip44 => 44,
            ExportKind::Bip49 => 49,
            ExportKind::Bip84 => 84,
            ExportKind::Bip86 => 86,
            ExportKind::Bip48Cosigner => {
                // Native-segwit (`2'`) multisig: the branch every current
                // coordinator asks a cosigner for. The nested (`1'`)
                // branch exists in `seed_derive` but is deliberately not
                // exposed on this screen in v1.
                return (path_bip48_native(self.cosigner_account.min(BIP48_ACCOUNT_MAX)), 4);
            }
        };
        (
            [
                HARDENED_OFFSET + purpose,
                HARDENED_OFFSET,
                HARDENED_OFFSET,
                0,
            ],
            3,
        )
    }

    /// The BIP32 version bytes the account key is displayed under.
    #[must_use]
    pub fn xpub_version(&self) -> XpubVersion {
        match (self.slip132, self.kind.slip132_version()) {
            (true, Some(version)) => version,
            _ => XpubVersion::Xpub,
        }
    }

    /// The Encoding row's value string.
    #[must_use]
    pub fn encoding_label(&self) -> &'static str {
        match (self.slip132, self.kind.slip132_version()) {
            (true, Some(XpubVersion::Ypub)) => ENCODING_YPUB,
            (true, Some(XpubVersion::Zpub)) => ENCODING_ZPUB,
            (true, Some(XpubVersion::Xpub)) | (false, _) => ENCODING_STANDARD,
            (true, None) => ENCODING_NO_SLIP132,
        }
    }
}

// ============================================================================
// Values
// ============================================================================

/// The public artifacts one [`compute_export`] produced, plus the QR of
/// whichever of them a wallet consumes.
///
/// Every field is public data. It is nonetheless scrubbed on the way out
/// ([`Self::scrub`]) under the same policy `AddressBuf`s follow: an
/// account key is an account-linking artifact, and nothing that
/// privacy-sensitive stays resident past the screen that showed it.
pub struct ExportValues {
    /// SPEC §24.3 master-key fingerprint (path-independent).
    master_fingerprint: [u8; 4],
    /// Base58Check account extended public key, `xpub_len` bytes valid.
    xpub: [u8; XPUB_MAX_LEN],
    /// Valid prefix length of [`Self::xpub`].
    xpub_len: usize,
    /// Rendered descriptor, `descriptor_len` bytes valid. `descriptor_len
    /// == 0` means "this kind has no descriptor" (the cosigner view) —
    /// never "the descriptor is empty": [`build_descriptor`] refuses
    /// rather than truncating, and [`compute_export`] turns a refusal
    /// into an error rather than a blank line.
    descriptor: [u8; DESCRIPTOR_MAX_LEN],
    /// Valid prefix length of [`Self::descriptor`].
    descriptor_len: usize,
    /// Key-origin-annotated account key for the cosigner view,
    /// `origin_key_len` bytes valid; empty for every single-sig kind
    /// (which has a descriptor instead). See [`build_origin_key`].
    origin_key: [u8; ORIGIN_KEY_MAX_LEN],
    /// Valid prefix length of [`Self::origin_key`].
    origin_key_len: usize,
    /// QR of [`Self::qr_payload`].
    qr: seed_qr::Matrix,
}

impl Default for ExportValues {
    fn default() -> Self {
        Self::new()
    }
}

impl ExportValues {
    /// An empty value set — nothing derived yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            master_fingerprint: [0u8; 4],
            xpub: [0u8; XPUB_MAX_LEN],
            xpub_len: 0,
            descriptor: [0u8; DESCRIPTOR_MAX_LEN],
            descriptor_len: 0,
            origin_key: [0u8; ORIGIN_KEY_MAX_LEN],
            origin_key_len: 0,
            qr: seed_qr::Matrix::new(),
        }
    }

    /// The master fingerprint.
    #[must_use]
    pub const fn master_fingerprint(&self) -> [u8; 4] {
        self.master_fingerprint
    }

    /// The account extended public key, as ASCII bytes.
    #[must_use]
    pub fn xpub(&self) -> &[u8] {
        self.xpub.get(..self.xpub_len).unwrap_or(&[])
    }

    /// The descriptor, as ASCII bytes; empty when this kind has none.
    #[must_use]
    pub fn descriptor(&self) -> &[u8] {
        self.descriptor.get(..self.descriptor_len).unwrap_or(&[])
    }

    /// The key-origin-annotated account key shown in the cosigner view,
    /// as ASCII bytes; empty for every single-sig kind.
    #[must_use]
    pub fn origin_key(&self) -> &[u8] {
        self.origin_key.get(..self.origin_key_len).unwrap_or(&[])
    }

    /// The rendered QR symbol.
    #[must_use]
    pub const fn qr(&self) -> &seed_qr::Matrix {
        &self.qr
    }

    /// Exactly what the QR encodes: the descriptor for a single-sig
    /// kind, the key-origin-annotated account key in the cosigner view.
    ///
    /// It is always the string *also printed on the screen* beside it —
    /// never a third, invisible payload, and never anything secret
    /// (wallet-export design D5: no QR of any secret, ever).
    /// [`tests::qr_encodes_exactly_the_descriptor_shown`] and
    /// [`tests::qr_payload_is_always_a_printed_value`] pin both halves of
    /// that claim.
    ///
    /// Empty when nothing has been derived (or after [`Self::scrub`]), so
    /// a caller can never encode or draw a stale symbol.
    #[must_use]
    pub fn qr_payload(&self) -> &[u8] {
        if self.descriptor_len > 0 {
            self.descriptor()
        } else {
            self.origin_key()
        }
    }

    /// Zeroize every buffer. Called when the export branch is left
    /// (`[Enter]`/`[Esc]`), same policy as address buffers.
    ///
    /// The byte buffers go through the arena's reviewed
    /// volatile+fence+verify primitive so the writes cannot be optimized
    /// away. The QR bitmap is private to `seed-qr`, so it is wiped by
    /// that crate's own [`seed_qr::Matrix::clear`], which applies the
    /// same discipline (and is *not* a plain `= Matrix::new()` store,
    /// which the optimizer would be free to elide);
    /// [`seed_qr::Matrix::bitmap_is_zero`] lets the test below assert the
    /// bytes rather than infer them from `side`.
    pub fn scrub(&mut self) {
        seed_core::arena::scrub_slice(&mut self.master_fingerprint);
        seed_core::arena::scrub_slice(&mut self.xpub);
        seed_core::arena::scrub_slice(&mut self.descriptor);
        seed_core::arena::scrub_slice(&mut self.origin_key);
        self.xpub_len = 0;
        self.descriptor_len = 0;
        self.origin_key_len = 0;
        self.qr.clear();
    }
}

// ============================================================================
// Derivation
// ============================================================================

/// Maximum length of a key-origin-annotated account key,
/// `[<fingerprint>/48h/0h/<account>h/2h]<xpub>`.
///
/// Size proof: `[` 1 + fingerprint 8 + four path levels at their absolute
/// worst case (`/` + 10 decimal digits + `h` = 12 each) 48 + `]` 1 +
/// [`XPUB_MAX_LEN`] 112 = 170. 176 leaves headroom without changing the
/// buffer type. The paths this screen actually produces are far shorter
/// (`/48h/0h/0h/2h` is 13), so the real length is 134.
pub const ORIGIN_KEY_MAX_LEN: usize = 176;

/// Render `[<fingerprint>/<path>]<xpub_b58>` into `out`, returning the
/// number of bytes written, or **`0` on refusal**.
///
/// This is the BIP-380 *key expression* — key origin plus extended public
/// key, with no script wrapper and therefore no checksum. It is exactly
/// what a multisig coordinator asks each cosigner for, which is why the
/// cosigner view shows and encodes this rather than a bare `xpub` the
/// user would then have to pair with a hand-transcribed fingerprint and
/// path.
///
/// No checksum is appended, deliberately: a BIP-380 checksum covers a
/// whole descriptor, and inventing one for a bare key expression would
/// produce a string no wallet verifies and some would reject.
/// `seed-derive` owns every checksummed form; this function must never
/// grow one.
///
/// Refuses (returns 0) rather than truncating, on the same reasoning
/// [`build_descriptor`] does: a key expression that is missing or
/// truncated but still *looks* right is a funds-loss hazard. The
/// `xpub_b58` shape check mirrors `seed-derive`'s own — length, plus the
/// `pub` tag every extended *public* key prefix shares — so an empty key
/// can never render as a plausible-looking origin string with no key
/// material in it.
///
/// Panic-free: every write goes through a bounds-checked helper and every
/// index is `get`-guarded.
fn build_origin_key(
    master_fingerprint: [u8; 4],
    path: &[u32],
    xpub_b58: &[u8],
    out: &mut [u8; ORIGIN_KEY_MAX_LEN],
) -> usize {
    /// Shortest plausible Base58Check extended key (mirrors
    /// `seed_derive::descriptor`'s own conservative floor).
    const XPUB_MIN_LEN: usize = 100;
    if xpub_b58.len() < XPUB_MIN_LEN
        || xpub_b58.len() > XPUB_MAX_LEN
        || xpub_b58.get(1..4) != Some(b"pub".as_slice())
    {
        return 0;
    }

    /// Lowercase hex digits for the key-origin fingerprint.
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut n = 0usize;
    if !push_bytes(out, &mut n, b"[") {
        return 0;
    }
    for byte in master_fingerprint {
        let (hi, lo) = match (HEX.get((byte >> 4) as usize), HEX.get((byte & 0x0f) as usize)) {
            (Some(hi), Some(lo)) => (*hi, *lo),
            _ => return 0,
        };
        if !push_bytes(out, &mut n, &[hi, lo]) {
            return 0;
        }
    }
    for &level in path {
        let hardened = level >= HARDENED_OFFSET;
        let child = if hardened { level - HARDENED_OFFSET } else { level };
        if !push_bytes(out, &mut n, b"/") || !push_u32_dec(out, &mut n, child) {
            return 0;
        }
        if hardened && !push_bytes(out, &mut n, b"h") {
            return 0;
        }
    }
    if !push_bytes(out, &mut n, b"]") || !push_bytes(out, &mut n, xpub_b58) {
        return 0;
    }
    n
}

/// Append `bytes` at `*n`, or report that they would not fit. Never
/// panics: the destination range is taken with `get_mut`, not indexed.
fn push_bytes(out: &mut [u8; ORIGIN_KEY_MAX_LEN], n: &mut usize, bytes: &[u8]) -> bool {
    let end = match n.checked_add(bytes.len()) {
        Some(end) => end,
        None => return false,
    };
    match out.get_mut(*n..end) {
        Some(dst) => {
            dst.copy_from_slice(bytes);
            *n = end;
            true
        }
        None => false,
    }
}

/// Append `v` in decimal (no leading zeros; `0` renders as `"0"`).
fn push_u32_dec(out: &mut [u8; ORIGIN_KEY_MAX_LEN], n: &mut usize, mut v: u32) -> bool {
    // `u32::MAX` is 10 digits, so the scratch can never be exhausted;
    // `checked_sub` keeps that a fact rather than an assumption.
    let mut digits = [0u8; 10];
    let mut i = digits.len();
    loop {
        let digit = b'0' + (v % 10) as u8;
        v /= 10;
        i = match i.checked_sub(1) {
            Some(i) => i,
            None => return false,
        };
        match digits.get_mut(i) {
            Some(slot) => *slot = digit,
            None => return false,
        }
        if v == 0 {
            break;
        }
    }
    match digits.get(i..) {
        Some(rendered) => push_bytes(out, n, rendered),
        None => false,
    }
}

/// Derive the account extended public key for `st`, render its descriptor
/// (single-sig kinds only) and encode the QR — writing all three into
/// `out`.
///
/// # Scrub walk (SPEC §19.4, §20.1, §20.3)
///
/// Modelled line-for-line on
/// [`crate::flow_secret::derive::compute_custom_address`], which is this
/// crate's reviewed pattern for "re-derive from the resident mnemonic for
/// exactly one public result, then wipe":
///
/// 1. The resident mnemonic indexes and committed passphrase are staged
///    into locals (the same simultaneous-borrow reason
///    `compute_verification_values` has), the BIP39 seed is derived into
///    the arena, and **both locals are scrubbed immediately**.
/// 2. The seed is copied to a local, the master key/chain code are
///    derived for the fingerprint, and **both are scrubbed immediately**.
/// 3. [`account_public`] performs the hardened CKD chain; it scrubs every
///    private intermediate it creates internally, on every return path,
///    and returns public data only.
/// 4. The local seed copy and the arena's derivation-stage fields are
///    scrubbed **before** this function's first `return`, on the error
///    path as well as the success path — nothing between step 4 and the
///    end of this function touches a private value at all.
/// 5. The returned [`seed_derive::bip32::AccountPublic`]'s chain code and
///    public key are public (they are what the xpub encodes) but
///    account-linking, so they are zeroized once serialized, under the
///    same policy as [`ExportValues::scrub`] — leaving no unscrubbed copy
///    of information the value set itself wipes on exit.
///
/// The mnemonic indexes stay resident, exactly as they do across `[M]`
/// and `[B]`, so switching script type with `[1]`-`[5]` simply re-derives.
///
/// # Errors
///
/// * Any [`DeriveError`] from [`account_public`] (cryptographically
///   unreachable for a real seed).
/// * [`DeriveError::BufferTooSmall`] if [`build_descriptor`] refuses (it
///   returns `0` rather than emitting a truncated or key-less descriptor)
///   or if the payload will not fit a version-13 QR symbol. Both are
///   "the artifact could not be produced correctly"; refusing is the
///   whole point, since a plausible-looking but wrong descriptor is a
///   funds-loss hazard. `out` is left scrubbed on every error path, so a
///   caller that ignores the error still renders nothing rather than a
///   stale artifact.
pub fn compute_export(
    arena: &mut SecretArena,
    word_count: WordCount,
    st: &ExportState,
    out: &mut ExportValues,
) -> Result<(), DeriveError> {
    out.scrub();

    // (1) Stage the resident mnemonic indexes AND the resident committed
    // passphrase locally, derive the BIP39 seed, scrub both locals.
    let mut indexes_local = [0u16; 24];
    indexes_local.copy_from_slice(arena.mnemonic_indexes());

    let mut pp_local = [0u8; seed_core::passphrase::MAX_PASSPHRASE_LEN];
    let pp_len = arena.passphrase().len();
    pp_local[..pp_len].copy_from_slice(arena.passphrase().as_bytes());

    seed_core::bip39::mnemonic_to_seed_with_passphrase_bytes(
        &indexes_local,
        word_count,
        &pp_local[..pp_len],
        arena.bip39_seed(),
    );
    scrub_u16_local(&mut indexes_local);
    seed_core::arena::scrub_slice(&mut pp_local);

    let mut seed_local = [0u8; 64];
    seed_local.copy_from_slice(arena.bip39_seed());

    // (2) Master fingerprint (path-independent, §24.3), then scrub the
    // key/chain-code copies immediately.
    let mut key = [0u8; 32];
    let mut cc = [0u8; 32];
    seed_derive::bip32::master_from_seed(&seed_local, &mut key, &mut cc);
    let master_fingerprint = seed_derive::bip32::master_fingerprint(&key);
    seed_core::arena::scrub_slice(&mut key);
    seed_core::arena::scrub_slice(&mut cc);

    // (3) The account node's public data. `account_public` scrubs every
    // private intermediate it creates, on every return path.
    let (path, path_len) = st.account_path();
    let path = path.get(..path_len).unwrap_or(&[]);
    let account = account_public(&seed_local, path);

    // (4) Scrub before any `?`: the derived seed never outlives this call
    // on ANY path, success or failure.
    seed_core::arena::scrub_slice(&mut seed_local);
    scrub_after_verification(arena);

    let mut account = match account {
        Ok(account) => account,
        Err(e) => return Err(e),
    };

    // ---- public data only from here on ----------------------------------

    out.master_fingerprint = master_fingerprint;
    out.xpub_len = serialize_xpub(&account, st.xpub_version(), &mut out.xpub);

    // (5) The account node's chain code and public key are, by
    // construction, exactly the bytes the xpub just serialized encodes:
    // public, but account-linking. `ExportValues` scrubs its own copy on
    // the way out, so this stack copy is zeroized here too rather than
    // left as the one unscrubbed instance of the same information.
    seed_core::arena::scrub_slice(&mut account.chain_code);
    seed_core::arena::scrub_slice(&mut account.pubkey);

    match st.kind.descriptor_kind() {
        Some(kind) => {
            let n = build_descriptor(
                kind,
                master_fingerprint,
                path,
                out.xpub.get(..out.xpub_len).unwrap_or(&[]),
                &mut out.descriptor,
            );
            if n == 0 {
                // Refusal (never truncation). Leave nothing partial behind.
                out.scrub();
                return Err(DeriveError::BufferTooSmall);
            }
            out.descriptor_len = n;
        }
        // Cosigner view: no descriptor exists (design D6), so the
        // exported artifact is the key-origin-annotated account key a
        // coordinator ingests directly.
        None => {
            let n = build_origin_key(
                master_fingerprint,
                path,
                out.xpub.get(..out.xpub_len).unwrap_or(&[]),
                &mut out.origin_key,
            );
            if n == 0 {
                out.scrub();
                return Err(DeriveError::BufferTooSmall);
            }
            out.origin_key_len = n;
        }
    }

    // Encode the QR from whichever artifact is on screen. The fields are
    // destructured so the payload borrow and the matrix borrow are
    // disjoint; [`tests::qr_encodes_exactly_the_descriptor_shown`] pins
    // that this selection stays identical to [`ExportValues::qr_payload`],
    // which is what the screen prints.
    let encoded = {
        let ExportValues { descriptor, descriptor_len, origin_key, origin_key_len, qr, .. } =
            &mut *out;
        let payload: &[u8] = if *descriptor_len > 0 {
            descriptor.get(..*descriptor_len).unwrap_or(&[])
        } else {
            origin_key.get(..*origin_key_len).unwrap_or(&[])
        };
        seed_qr::encode(payload, qr)
    };
    if encoded.is_err() {
        out.scrub();
        return Err(DeriveError::BufferTooSmall);
    }

    Ok(())
}

/// Scrubs a `[u16]` mnemonic-index staging buffer through the arena's
/// reviewed volatile+fence+verify primitive (SPEC §20.3) — the same
/// helper `flow_secret::derive` uses, duplicated here rather than widened
/// to `pub(crate)` in that module so this module's scrub walk is
/// self-contained and reviewable in one file.
fn scrub_u16_local(buf: &mut [u16]) {
    // SAFETY: reinterpreting a `[u16]` as `2*len` bytes through a `u8`
    // pointer is always valid (`u8` has no alignment/padding constraint
    // and every byte of a `u16` is part of its object representation);
    // the slice stays within the exclusively-borrowed buffer.
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(buf.as_mut_ptr().cast::<u8>(), core::mem::size_of_val(buf))
    };
    seed_core::arena::scrub_slice(bytes);
}

// ============================================================================
// Layout
// ============================================================================

/// Height of one 1x content row.
const ROW_1X: u32 = LINE_PITCH;

/// Height of a blank separator row.
const GAP: u32 = LINE_PITCH / 2;

/// Width of the fixed box the QR block is drawn into, in pixels. The
/// symbol's version varies with the payload, so [`qr::module_px_for_width`]
/// picks the largest integer module size that fits this box — the layout
/// stays put whatever the encoder chose.
const QR_BLOCK_W: u32 = GLYPH_WIDTH * 44;

/// Columns available to the captions under the QR block. A budget the
/// fit audit measures against, not a value production code reads (the
/// captions are `const`s, checked once here rather than truncated at
/// draw time).
#[cfg_attr(not(test), allow(dead_code))]
const QR_CAPTION_COLS: usize = (QR_BLOCK_W / GLYPH_WIDTH) as usize;

/// x origin of the right-hand text column.
const TEXT_X: u32 = MARGIN_X + QR_BLOCK_W + MARGIN_X;

/// Columns available in the right-hand text column at the resolution
/// floor.
const TEXT_COLS: usize = ((MIN_WIDTH - TEXT_X - MARGIN_X) / GLYPH_WIDTH) as usize;

/// Width of the left-hand label field in the info rows.
const LABEL_FIELD: usize = 15;

/// Padding inside the privacy panel.
const PANEL_PAD: u32 = LINE_PITCH / 2;

/// Height of the privacy panel: padding, two rows, padding.
const PANEL_H: u32 = PANEL_PAD * 2 + ROW_1X * 2;

/// Columns available inside the privacy panel at the resolution floor —
/// a fit-audit budget, like [`QR_CAPTION_COLS`].
#[cfg_attr(not(test), allow(dead_code))]
const PANEL_COLS: usize = ((MIN_WIDTH - 2 * MARGIN_X - 2 * PANEL_PAD) / GLYPH_WIDTH) as usize;

/// Maximum wrapped segments any one value is split into. The longest
/// artifact this screen can show is a `sh(wpkh(...))` descriptor (156
/// characters), which needs four rows at [`TEXT_COLS`].
const MAX_WRAP_LINES: usize = 4;

/// Number of fixed info rows (kind, path, fingerprint, encoding).
const INFO_ROWS: usize = 4;

/// Upper bound on the rows [`build_rows`] emits. The tallest state (a
/// single-sig kind: 4 info + gap + label + 3 key rows + gap + label + 4
/// descriptor rows) is 15.
const MAX_ROWS: usize = 18;

/// One content row in the right-hand column. Every drawable string this
/// column owns is reachable from a `Row`, so the fit audit and the leak
/// scan walk exactly what [`draw_rows`] draws.
#[derive(Clone, Copy)]
enum Row<'a> {
    /// A blank separator.
    Gap,
    /// A left-aligned 1x text run.
    Line { text: &'a str, color: u32 },
}

impl Row<'_> {
    /// The vertical advance this row consumes.
    const fn height(self) -> u32 {
        match self {
            Row::Gap => GAP,
            Row::Line { .. } => ROW_1X,
        }
    }
}

/// Split `s` into at most [`MAX_WRAP_LINES`] runs of at most `cols`
/// characters, writing them into `out` and returning how many were
/// written.
///
/// Hard wrap, not word wrap: the values are unbroken base58/descriptor
/// text with no spaces to break at. Panic-free (`get` everywhere) and
/// lossless up to the bound — a value that would need more than
/// [`MAX_WRAP_LINES`] runs is impossible for the artifacts this screen
/// produces and is pinned as such by
/// [`tests::the_longest_artifact_still_fits_the_wrap_bound`].
fn wrap<'a>(s: &'a str, cols: usize, out: &mut [&'a str; MAX_WRAP_LINES]) -> usize {
    if cols == 0 {
        return 0;
    }
    let mut n = 0usize;
    let mut start = 0usize;
    while start < s.len() && n < out.len() {
        let end = core::cmp::min(start + cols, s.len());
        match (s.get(start..end), out.get_mut(n)) {
            (Some(run), Some(slot)) => {
                *slot = run;
                n += 1;
            }
            _ => break,
        }
        start = end;
    }
    n
}

/// Interpret `bytes` as the ASCII text it is, or a placeholder if it
/// somehow is not valid UTF-8 (impossible for Base58/descriptor output,
/// but this screen never panics on data).
fn as_text(bytes: &[u8]) -> &str {
    match core::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => "?",
    }
}

/// Write the account path read-back, e.g. `m/84h/0h/0h` — the same `h`
/// hardened marker the descriptor uses, so the two agree on screen.
fn write_account_path(line: &mut LineBuf, st: &ExportState) {
    let (path, len) = st.account_path();
    let _ = line.write_str("m");
    for level in path.iter().take(len) {
        let hardened = *level >= HARDENED_OFFSET;
        let child = if hardened { *level - HARDENED_OFFSET } else { *level };
        let _ = write!(line, "/{child}");
        if hardened {
            let _ = line.write_str("h");
        }
    }
}

/// The two captions drawn under the QR block, in draw order.
fn qr_captions(st: &ExportState) -> [&'static str; 2] {
    let content = match st.kind.descriptor_kind() {
        Some(_) => QR_CAPTION_DESCRIPTOR,
        None => QR_CAPTION_COSIGNER_KEY,
    };
    [QR_CAPTION_PUBLIC, content]
}

/// Fill `info` with the four fixed rows and return the right-hand
/// column's row list.
///
/// Presentation-only: reads nothing but the public `e`, performs no
/// derivation. Shared by [`render`] and every test, so what ships is
/// exactly what the tests measure.
fn build_rows<'a>(
    st: &ExportState,
    e: &'a ExportValues,
    info: &'a mut [LineBuf; INFO_ROWS],
) -> ([Row<'a>; MAX_ROWS], usize) {
    let kind_caption =
        if st.kind == ExportKind::Bip48Cosigner { LABEL_KIND_COSIGNER } else { LABEL_KIND };
    let _ = write!(
        info[0],
        "{caption:<width$}{value}",
        caption = kind_caption,
        width = LABEL_FIELD,
        value = st.kind.label()
    );

    let _ = write!(info[1], "{caption:<width$}", caption = LABEL_PATH, width = LABEL_FIELD);
    write_account_path(&mut info[1], st);

    let fp_hex = hex8(e.master_fingerprint());
    let mut fp_chunked = [0u8; CHUNK_CAP];
    let n = chunk4(&fp_hex, &mut fp_chunked);
    let _ = write!(
        info[2],
        "{caption:<width$}{value}",
        caption = LABEL_FINGERPRINT,
        width = LABEL_FIELD,
        value = as_text(fp_chunked.get(..n).unwrap_or(&[]))
    );

    let _ = write!(
        info[3],
        "{caption:<width$}{value}",
        caption = LABEL_ENCODING,
        width = LABEL_FIELD,
        value = st.encoding_label()
    );

    let info: &'a [LineBuf; INFO_ROWS] = &*info;

    let mut rows = [Row::Gap; MAX_ROWS];
    let mut n = 0usize;
    let mut push = |row: Row<'a>| {
        if n < MAX_ROWS {
            rows[n] = row;
            n += 1;
        }
    };

    for line in info.iter() {
        push(Row::Line { text: line.as_str(), color: theme::TEXT });
    }

    // Which block follows is a property of the *state*, never of whether
    // a value happens to be populated: keying off `descriptor().is_empty()`
    // would make a scrubbed or failed single-sig state render the multisig
    // coordinator caption while `qr_captions` (which reads the kind) said
    // "descriptor" — contradictory copy on the one screen whose whole job
    // is telling the user exactly what they are looking at.
    let cosigner = st.kind.descriptor_kind().is_none();

    push(Row::Gap);
    let (key_label, key_text) = if cosigner {
        (COSIGNER_KEY_LABEL, as_text(e.origin_key()))
    } else {
        (XPUB_LABEL, as_text(e.xpub()))
    };
    push(Row::Line { text: key_label, color: theme::CAPTION });
    let mut key_runs = [""; MAX_WRAP_LINES];
    let key_n = wrap(key_text, TEXT_COLS, &mut key_runs);
    for run in key_runs.iter().take(key_n) {
        push(Row::Line { text: run, color: theme::TEXT });
    }

    push(Row::Gap);
    if cosigner {
        // No descriptor, and — deliberately — no address line either
        // (design D6).
        for line in [COSIGNER_CAPTION_1, COSIGNER_CAPTION_2, COSIGNER_CAPTION_3] {
            push(Row::Line { text: line, color: theme::CAPTION });
        }
    } else {
        push(Row::Line { text: DESCRIPTOR_LABEL, color: theme::CAPTION });
        let mut desc_runs = [""; MAX_WRAP_LINES];
        let desc_n = wrap(as_text(e.descriptor()), TEXT_COLS, &mut desc_runs);
        for run in desc_runs.iter().take(desc_n) {
            push(Row::Line { text: run, color: theme::TEXT });
        }
    }

    (rows, n)
}

/// Draw `rows` down the right-hand column from `y`.
fn draw_rows(fb: &mut dyn Framebuffer, mut y: u32, rows: &[Row<'_>]) {
    for row in rows {
        if let Row::Line { text, color } = *row {
            draw_text(fb, TEXT_X, y, text, theme::on_bg(color));
        }
        y += row.height();
    }
}

/// y origin of the privacy panel: flush to the bottom of the content
/// area, above the footer band.
fn panel_y() -> u32 {
    chrome::content_bottom().saturating_sub(PANEL_H)
}

/// Baseline for the in-place export-refusal line (drawn by the driver on a
/// `BufferTooSmall` refusal): one line-pitch ABOVE the privacy panel, so it
/// never overlaps the panel that owns the bottom of the content area. Owned
/// here because this module owns the panel geometry the refusal must clear.
#[must_use]
pub fn refusal_line_y() -> u32 {
    panel_y().saturating_sub(LINE_PITCH)
}

/// Draw the persistent privacy panel across the bottom of the content
/// area.
fn draw_privacy_panel(fb: &mut dyn Framebuffer) {
    let (fb_w, _) = fb.dims();
    let w = fb_w.saturating_sub(MARGIN_X * 2);
    let y = panel_y();
    panel::warn_panel(fb, MARGIN_X, y, w, PANEL_H);
    let x = MARGIN_X + PANEL_PAD;
    draw_text(fb, x, y + PANEL_PAD, PRIVACY_LINE_1, theme::on_panel(theme::WARN));
    draw_text(fb, x, y + PANEL_PAD + ROW_1X, PRIVACY_LINE_2, theme::on_panel(theme::WARN));
}

/// Render the export screen: chrome shell, QR block + captions on the
/// left, values on the right, the persistent privacy panel across the
/// bottom, and the four-hint footer.
///
/// Clears the framebuffer first (SPEC §12.2 "Fixed layouts").
pub fn render(fb: &mut dyn Framebuffer, st: &ExportState, e: &ExportValues, build: &'static str) {
    seed_gop_ui::font::scrub_fill(fb, theme::BG);
    chrome::draw_header(fb, &Chrome { stage: STAGE, sub: Some(SUB), build });

    let top = chrome::content_top();

    let module_px = qr::module_px_for_width(e.qr().side(), QR_BLOCK_W);
    qr::draw_qr(fb, MARGIN_X, top, e.qr(), module_px);

    let mut caption_y = top + qr::block_px(e.qr().side(), module_px) + GAP;
    for caption in qr_captions(st) {
        draw_text(fb, MARGIN_X, caption_y, caption, theme::on_bg(theme::CAPTION));
        caption_y += ROW_1X;
    }

    let mut info: [LineBuf; INFO_ROWS] = core::array::from_fn(|_| LineBuf::new());
    let (rows, n) = build_rows(st, e, &mut info);
    draw_rows(fb, top, rows.get(..n).unwrap_or(&[]));

    draw_privacy_panel(fb);
    chrome::draw_footer(fb, &HINTS);
}

/// Test-only constructor for [`ExportValues`], deliberately placed at the
/// very end of this module's production section: `screens::verify`'s
/// `chunk4_call_sites_are_public_values_only` scan treats the FIRST
/// `#[cfg(test)]` in a file as the end of its production code, and this
/// module's own `chunk4` call site must stay on the production side of
/// that cut.
#[cfg(test)]
impl ExportValues {
    /// Assemble a value set from raw parts, bypassing
    /// [`compute_export`]'s derivation entirely.
    ///
    /// Exists so a fit-audit can render this screen at payload sizes no
    /// *reachable* seed can produce — in particular a symbol at the
    /// version-13 boundary [`seed_qr::encode`] refuses past. Those sizes
    /// are the layout's true worst cases, and measuring them must not
    /// depend on finding a mnemonic that happens to derive them.
    ///
    /// `qr_payload` is encoded into the symbol independently of
    /// `descriptor`, so a caller can maximize the SYMBOL without also
    /// having to represent an unrepresentable descriptor. That
    /// deliberately breaks this type's "the QR encodes exactly the
    /// printed value" invariant, which is why this is a geometry fixture
    /// only: the invariant itself is pinned, on real derived values, by
    /// [`tests::qr_encodes_exactly_the_descriptor_shown`] and
    /// [`tests::qr_payload_is_always_a_printed_value`].
    ///
    /// Every input is truncated to its field's capacity rather than
    /// asserted, so a caller cannot make this panic.
    #[cfg(test)]
    pub(crate) fn synthetic(
        master_fingerprint: [u8; 4],
        xpub: &[u8],
        descriptor: &[u8],
        qr_payload: &[u8],
    ) -> Self {
        let mut out = Self::new();
        out.master_fingerprint = master_fingerprint;
        out.xpub_len = xpub.len().min(XPUB_MAX_LEN);
        out.xpub[..out.xpub_len].copy_from_slice(&xpub[..out.xpub_len]);
        out.descriptor_len = descriptor.len().min(DESCRIPTOR_MAX_LEN);
        out.descriptor[..out.descriptor_len].copy_from_slice(&descriptor[..out.descriptor_len]);
        seed_qr::encode(qr_payload, &mut out.qr).expect("synthetic QR payload must be encodable");
        out
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    use std::path::PathBuf;
    use std::string::{String, ToString};
    use std::vec::Vec;

    use seed_gop_ui::gop::mode::{MIN_HEIGHT, MIN_WIDTH};
    use seed_gop_ui::layout::MAX_COLS_AT_FLOOR;

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

    // -- fixtures --------------------------------------------------------

    fn word_index(target: &str) -> u16 {
        (0..2048u16).find(|&i| seed_core::bip39::word(i) == target).expect("word in list")
    }

    /// A fresh arena holding the canonical ceremony mnemonic
    /// ("abandon abandon ... about"), the same fixture
    /// `flow_secret::derive`'s own tests use.
    fn ceremony_arena() -> SecretArena {
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

    fn compute(st: &ExportState) -> ExportValues {
        let mut arena = ceremony_arena();
        let mut values = ExportValues::new();
        compute_export(&mut arena, WordCount::Twelve, st, &mut values).expect("derives");
        values
    }

    fn state(kind: ExportKind) -> ExportState {
        ExportState { kind, ..ExportState::new() }
    }

    /// The ceremony seed's master fingerprint, pinned by BIP84's own
    /// published test vectors (and by `seed-derive`'s address tests).
    const CEREMONY_FINGERPRINT: [u8; 4] = [0x73, 0xc5, 0xda, 0x0a];

    /// `m/84'/0'/0'` account xpub for the ceremony mnemonic — copied from
    /// `seed_derive::bip32::serialize`'s own pinned vector, which is
    /// cross-checked there against the independent Python reference stack
    /// (and, for the `zpub` form, against BIP84's published vector).
    const CEREMONY_BIP84_XPUB: &str = "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V";
    /// The BIP48 native-segwit cosigner account key for the ceremony
    /// mnemonic at `m/48'/0'/0'/2'`, and the key expression the cosigner
    /// view shows and encodes for it. Derived by this crate; pinned here
    /// so the QR payload's exact bytes are a fixed, reviewable string.
    const CEREMONY_BIP48_ORIGIN_PREFIX: &str = "[73c5da0a/48h/0h/0h/2h]";

    /// Same account, SLIP-132 `zpub` form — BIP84 "Test vectors",
    /// Account 0 extended public key.
    const CEREMONY_BIP84_ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

    /// The descriptor body (everything before `#checksum`) that
    /// `[3]` must produce for the ceremony seed: template, key origin
    /// (pinned fingerprint + account path), the pinned account xpub, and
    /// the `/0/*` wildcard. Assembled here from independently-pinned
    /// parts, so this expectation does not simply restate the code under
    /// test.
    fn ceremony_bip84_descriptor_body() -> String {
        std::format!("wpkh([73c5da0a/84h/0h/0h]{CEREMONY_BIP84_XPUB}/0/*)")
    }

    /// Just the right-hand value column, in draw order — built from the
    /// same [`build_rows`] the renderer uses, so a test can never assert
    /// against stale copy.
    fn column_lines(st: &ExportState, e: &ExportValues) -> Vec<String> {
        let mut info: [LineBuf; INFO_ROWS] = core::array::from_fn(|_| LineBuf::new());
        let (rows, n) = build_rows(st, e, &mut info);
        let mut out = Vec::new();
        for row in &rows[..n] {
            if let Row::Line { text, .. } = *row {
                out.push(text.to_string());
            }
        }
        out
    }

    /// Every string the screen draws, in draw order (right column, then
    /// the QR captions, then the privacy panel).
    fn screen_lines(st: &ExportState, e: &ExportValues) -> Vec<String> {
        let mut out = column_lines(st, e);
        for caption in qr_captions(st) {
            out.push(caption.to_string());
        }
        out.push(PRIVACY_LINE_1.to_string());
        out.push(PRIVACY_LINE_2.to_string());
        out
    }

    // -- key handling ----------------------------------------------------

    #[test]
    fn default_state_is_native_segwit_with_the_canonical_encoding() {
        let st = ExportState::new();
        assert_eq!(st.kind, ExportKind::Bip84);
        assert!(!st.slip132);
        assert_eq!(st.cosigner_account, 0);
        assert_eq!(ExportState::default(), st);
    }

    #[test]
    fn number_keys_select_the_script_type_without_leaving_the_screen() {
        let mut st = ExportState::new();
        for (key, want) in [
            ('1', ExportKind::Bip44),
            ('2', ExportKind::Bip49),
            ('3', ExportKind::Bip84),
            ('4', ExportKind::Bip86),
            ('5', ExportKind::Bip48Cosigner),
        ] {
            assert_eq!(st.handle_key(InputEvent::Char(key)), None);
            assert_eq!(st.kind, want, "[{key}] must select {want:?}");
        }
    }

    #[test]
    fn repeated_five_steps_the_cosigner_account_within_its_bound() {
        let mut st = ExportState::new();
        assert_eq!(st.handle_key(InputEvent::Char('5')), None);
        assert_eq!(st.cosigner_account, 0, "entering the view must start at account 0");
        for want in [1, 2, 3, 0, 1] {
            assert_eq!(st.handle_key(InputEvent::Char('5')), None);
            assert_eq!(st.cosigner_account, want);
            assert!(st.cosigner_account <= BIP48_ACCOUNT_MAX);
        }
        // Leaving and re-entering resets to account 0.
        assert_eq!(st.handle_key(InputEvent::Char('3')), None);
        assert_eq!(st.handle_key(InputEvent::Char('5')), None);
        assert_eq!(st.cosigner_account, 0);
    }

    #[test]
    fn t_toggles_slip132_and_enter_leaves() {
        let mut st = ExportState::new();
        assert_eq!(st.handle_key(InputEvent::Char('t')), None);
        assert!(st.slip132);
        assert_eq!(st.handle_key(InputEvent::Char('T')), None);
        assert!(!st.slip132);
        assert_eq!(st.handle_key(InputEvent::Enter), Some(ExportOutcome::Back));
    }

    #[test]
    fn unhandled_keys_change_nothing() {
        let mut st = ExportState::new();
        for k in [
            InputEvent::Escape,
            InputEvent::Backspace,
            InputEvent::Other,
            InputEvent::Char('6'),
            InputEvent::Char('0'),
            InputEvent::Char('q'),
        ] {
            assert_eq!(st.handle_key(k), None, "{k:?} must not leave the screen");
            assert_eq!(st, ExportState::new(), "{k:?} must not change the state");
        }
    }

    // -- derivation ------------------------------------------------------

    #[test]
    fn account_paths_match_their_standards() {
        for (kind, want) in [
            (ExportKind::Bip44, &[0x8000_002C, 0x8000_0000, 0x8000_0000][..]),
            (ExportKind::Bip49, &[0x8000_0031, 0x8000_0000, 0x8000_0000][..]),
            (ExportKind::Bip84, &[0x8000_0054, 0x8000_0000, 0x8000_0000][..]),
            (ExportKind::Bip86, &[0x8000_0056, 0x8000_0000, 0x8000_0000][..]),
        ] {
            let (path, len) = state(kind).account_path();
            assert_eq!(&path[..len], want, "{kind:?} account path");
        }

        // BIP48 native-segwit cosigner branch, per account index.
        for account in 0..=BIP48_ACCOUNT_MAX {
            let st = ExportState {
                kind: ExportKind::Bip48Cosigner,
                cosigner_account: account,
                ..ExportState::new()
            };
            let (path, len) = st.account_path();
            assert_eq!(
                &path[..len],
                &[0x8000_0030, 0x8000_0000, 0x8000_0000 + account, 0x8000_0002][..],
                "BIP48 account {account}"
            );
        }
    }

    /// The screen's central vector: `[3]` on the ceremony seed produces
    /// the descriptor built from the independently-pinned account xpub
    /// and the BIP84-pinned master fingerprint, plus a BIP-380 checksum
    /// (whose algorithm is itself pinned against Bitcoin Core's published
    /// vector in `seed_derive::descriptor`).
    #[test]
    fn bip84_descriptor_matches_the_pinned_ceremony_vector() {
        let values = compute(&state(ExportKind::Bip84));
        assert_eq!(values.master_fingerprint(), CEREMONY_FINGERPRINT);
        assert_eq!(as_text(values.xpub()), CEREMONY_BIP84_XPUB);

        let body = ceremony_bip84_descriptor_body();
        let rendered = as_text(values.descriptor());
        assert!(rendered.starts_with(&body), "descriptor body mismatch:\n{rendered}\n{body}");

        let checksum = seed_derive::descriptor::descriptor_checksum(body.as_bytes());
        let want = std::format!("{body}#{}", as_text(&checksum));
        assert_eq!(rendered, want);
        // Pinned in full, so a change to any of the three sources shows
        // up here as one explicit diff.
        assert_eq!(
            rendered,
            "wpkh([73c5da0a/84h/0h/0h]xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V/0/*)#afwvtk2s"
        );
    }

    #[test]
    fn every_single_sig_kind_produces_its_own_template_and_path() {
        for (kind, prefix, origin) in [
            (ExportKind::Bip44, "pkh([73c5da0a/44h/0h/0h]", "44h"),
            (ExportKind::Bip49, "sh(wpkh([73c5da0a/49h/0h/0h]", "49h"),
            (ExportKind::Bip84, "wpkh([73c5da0a/84h/0h/0h]", "84h"),
            (ExportKind::Bip86, "tr([73c5da0a/86h/0h/0h]", "86h"),
        ] {
            let values = compute(&state(kind));
            let rendered = as_text(values.descriptor()).to_string();
            assert!(rendered.starts_with(prefix), "{kind:?}: {rendered}");
            assert!(rendered.contains(origin));
            assert!(rendered.contains("/0/*"), "{kind:?} must carry the derivation wildcard");
            // Every descriptor ends in a real 8-character checksum.
            let (_, checksum) = rendered.rsplit_once('#').expect("checksum present");
            assert_eq!(checksum.len(), 8, "{kind:?} checksum length");
            assert!(!checksum.contains('#'), "{kind:?} got the invalid-checksum sentinel");
        }
    }

    #[test]
    fn slip132_toggle_changes_the_bip84_key_prefix_and_the_descriptor() {
        let plain = compute(&state(ExportKind::Bip84));
        let toggled = compute(&ExportState { slip132: true, ..state(ExportKind::Bip84) });

        assert_eq!(as_text(plain.xpub()), CEREMONY_BIP84_XPUB);
        assert_eq!(as_text(toggled.xpub()), CEREMONY_BIP84_ZPUB);
        assert!(as_text(toggled.descriptor()).contains(CEREMONY_BIP84_ZPUB));
        assert_ne!(plain.descriptor(), toggled.descriptor());

        // BIP49 gets the `ypub` form; BIP44/86 and the cosigner view have
        // no SLIP-132 form, so the toggle is inert for them.
        let y = compute(&ExportState { slip132: true, ..state(ExportKind::Bip49) });
        assert!(as_text(y.xpub()).starts_with("ypub"));
        for kind in [ExportKind::Bip44, ExportKind::Bip86, ExportKind::Bip48Cosigner] {
            let toggled = ExportState { slip132: true, ..state(kind) };
            let off = compute(&state(kind));
            let on = compute(&toggled);
            assert_eq!(off.xpub(), on.xpub(), "{kind:?}: [T] must be inert");
            assert_eq!(toggled.encoding_label(), ENCODING_NO_SLIP132);
        }
    }

    #[test]
    fn cosigner_view_derives_the_bip48_account_key_and_no_descriptor() {
        for account in 0..=BIP48_ACCOUNT_MAX {
            let st = ExportState {
                kind: ExportKind::Bip48Cosigner,
                cosigner_account: account,
                ..ExportState::new()
            };
            let values = compute(&st);
            assert!(as_text(values.xpub()).starts_with("xpub"));
            assert_eq!(values.xpub().len(), 111);
            assert!(
                values.descriptor().is_empty(),
                "the cosigner view must never build a descriptor"
            );
            assert_eq!(values.master_fingerprint(), CEREMONY_FINGERPRINT);

            // The key expression: `[fp/48h/0h/<account>h/2h]xpub...`,
            // with the account key embedded verbatim and no checksum.
            let origin = as_text(values.origin_key()).to_string();
            let want_prefix = std::format!("[73c5da0a/48h/0h/{account}h/2h]");
            assert!(origin.starts_with(&want_prefix), "account {account}: {origin}");
            assert!(origin.ends_with(as_text(values.xpub())), "account {account}: {origin}");
            assert_eq!(origin.len(), want_prefix.len() + 111);
            assert!(!origin.contains('#'), "a key expression carries no checksum");
        }

        // Different accounts really are different keys.
        let a0 = compute(&ExportState {
            kind: ExportKind::Bip48Cosigner,
            cosigner_account: 0,
            ..ExportState::new()
        });
        let a1 = compute(&ExportState {
            kind: ExportKind::Bip48Cosigner,
            cosigner_account: 1,
            ..ExportState::new()
        });
        assert_ne!(a0.xpub(), a1.xpub());
    }

    /// A committed passphrase must change the exported key — otherwise
    /// the user would export a watch-only wallet for a different seed
    /// than the one they backed up (SPEC_PASSPHRASE §M2).
    #[test]
    fn a_committed_passphrase_changes_the_exported_key() {
        let plain = compute(&state(ExportKind::Bip84));

        let mut arena = ceremony_arena();
        for &b in b"Correct Horse 42!" {
            arena.passphrase().push_ascii(b).unwrap();
        }
        let mut with_pp = ExportValues::new();
        compute_export(&mut arena, WordCount::Twelve, &state(ExportKind::Bip84), &mut with_pp)
            .unwrap();

        assert_ne!(plain.xpub(), with_pp.xpub());
        assert_ne!(plain.master_fingerprint(), with_pp.master_fingerprint());
    }

    // -- scrub discipline -------------------------------------------------

    /// SPEC §19.4/§20.1: the derived seed and the arena's whole
    /// derivation stage are gone by the time `compute_export` returns,
    /// while the mnemonic stays resident for the next `[1]`-`[5]`.
    #[test]
    fn compute_export_scrubs_the_derivation_stage_and_keeps_the_mnemonic() {
        let mut arena = ceremony_arena();
        let mut values = ExportValues::new();
        compute_export(&mut arena, WordCount::Twelve, &state(ExportKind::Bip84), &mut values)
            .unwrap();

        assert!(arena.bip39_seed().iter().all(|&b| b == 0), "BIP39 seed must be scrubbed");
        assert!(arena.master_key().iter().all(|&b| b == 0), "master key must be scrubbed");
        assert!(
            arena.master_chain_code().iter().all(|&b| b == 0),
            "master chain code must be scrubbed"
        );
        assert!(
            arena.mnemonic_indexes().iter().any(|&w| w != 0),
            "the mnemonic must stay resident for a further export"
        );

        // A second derivation in the same session works and re-scrubs.
        compute_export(&mut arena, WordCount::Twelve, &state(ExportKind::Bip44), &mut values)
            .unwrap();
        assert!(arena.bip39_seed().iter().all(|&b| b == 0));

        // The whole-arena scrub then wipes the still-resident mnemonic.
        arena.scrub_all();
        assert!(arena.mnemonic_indexes().iter().all(|&w| w == 0));
    }

    #[test]
    fn scrub_zeroizes_every_buffer_and_empties_the_qr() {
        let mut values = compute(&state(ExportKind::Bip84));
        assert!(!values.xpub().is_empty() && !values.descriptor().is_empty());
        assert!(values.qr().side() > 0);
        assert!(!values.qr().bitmap_is_zero(), "sanity: the encoded symbol sets bits");

        values.scrub();

        assert!(values.xpub().is_empty());
        assert!(values.descriptor().is_empty());
        assert!(values.origin_key().is_empty());
        assert_eq!(values.master_fingerprint(), [0u8; 4]);
        assert!(values.qr_payload().is_empty());
        // The backing arrays themselves, not just the length prefixes.
        assert!(values.xpub.iter().all(|&b| b == 0));
        assert!(values.descriptor.iter().all(|&b| b == 0));
        assert!(values.origin_key.iter().all(|&b| b == 0));
        // …and the QR *bitmap bytes*, not merely `side == 0` — the whole
        // point of `Matrix::clear` over a plain `= Matrix::new()` store.
        assert_eq!(values.qr().side(), 0);
        assert!(values.qr().bitmap_is_zero(), "the QR bitmap bytes must be zeroized");

        // Idempotent, and a scrubbed value set stays scrubbed.
        values.scrub();
        assert!(values.qr_payload().is_empty());
        assert!(values.qr().bitmap_is_zero());
    }

    /// The cosigner view's buffers are scrubbed on the same terms — it is
    /// the branch with the *most* account-linking material on screen.
    #[test]
    fn scrub_zeroizes_the_cosigner_origin_key_and_bitmap() {
        let mut values = compute(&state(ExportKind::Bip48Cosigner));
        assert!(!values.origin_key().is_empty());
        assert!(!values.qr().bitmap_is_zero());

        values.scrub();

        assert!(values.origin_key().is_empty());
        assert!(values.origin_key.iter().all(|&b| b == 0));
        assert!(values.qr().bitmap_is_zero());
        assert!(values.qr_payload().is_empty());
    }

    /// Structural leak guard: this module's production code names no
    /// extended-private-key type, no raw entropy field and no
    /// re-entry/mnemonic buffer — the only arena fields it may reach are
    /// the ones `compute_export`'s documented walk names.
    #[test]
    fn module_never_names_a_forbidden_secret_field() {
        let this_file =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src").join("screens").join("export.rs");
        let text = std::fs::read_to_string(&this_file).expect("read own source");
        let prod = &text[..text.find("#[cfg(test)]").expect("test module marker")];
        for banned in [
            "final_entropy",
            "reentry_buffer",
            "machine_sources",
            "transcript(",
            "ckd_priv",
            "privkey",
        ] {
            assert!(!prod.contains(banned), "export.rs production code must never name {banned}");
        }
        // And the arena's derivation stage is scrubbed on the way out.
        assert!(prod.contains("scrub_after_verification"));
    }

    // -- QR ---------------------------------------------------------------

    /// The QR encodes **exactly** the descriptor the screen prints beside
    /// it — never a different, invisible payload, and never anything
    /// secret (design D5).
    #[test]
    fn qr_encodes_exactly_the_descriptor_shown() {
        let values = compute(&state(ExportKind::Bip84));
        assert_eq!(values.qr_payload(), values.descriptor());
        assert_eq!(as_text(values.qr_payload()), as_text(values.descriptor()));

        // Re-encoding the descriptor reproduces the same matrix, so the
        // symbol on screen really is this string and not a stale one.
        let mut expected = seed_qr::Matrix::new();
        seed_qr::encode(values.descriptor(), &mut expected).unwrap();
        assert_eq!(expected.side(), values.qr().side());
        for y in 0..expected.side() {
            for x in 0..expected.side() {
                assert_eq!(expected.get(x, y), values.qr().get(x, y), "module ({x},{y})");
            }
        }
    }

    /// In the cosigner view there is no descriptor, so the QR carries the
    /// key-origin-annotated account key — fingerprint, BIP48 path and
    /// account key in the one string a coordinator ingests, printed
    /// verbatim on the same screen, and still entirely public.
    #[test]
    fn cosigner_qr_encodes_the_origin_annotated_key_shown() {
        let st = state(ExportKind::Bip48Cosigner);
        let values = compute(&st);
        assert!(values.descriptor().is_empty());
        assert_eq!(values.qr_payload(), values.origin_key());
        assert_ne!(values.qr_payload(), values.xpub(), "the bare key is not what is encoded");

        let payload = as_text(values.qr_payload()).to_string();
        assert!(payload.starts_with(CEREMONY_BIP48_ORIGIN_PREFIX), "{payload}");
        assert!(payload.contains(as_text(values.xpub())), "the account key must be embedded");

        // Printed verbatim on screen, across its wrapped rows.
        let printed = column_lines(&st, &values).join("");
        assert!(printed.contains(&payload), "the QR payload is not printed on screen");

        // …and the encoded matrix really is that string.
        let mut expected = seed_qr::Matrix::new();
        seed_qr::encode(values.origin_key(), &mut expected).unwrap();
        assert_eq!(expected.side(), values.qr().side());
        for y in 0..expected.side() {
            for x in 0..expected.side() {
                assert_eq!(expected.get(x, y), values.qr().get(x, y), "module ({x},{y})");
            }
        }
    }

    /// `build_origin_key` refuses rather than emitting a key-less or
    /// truncated expression — the same rule `build_descriptor` follows.
    #[test]
    fn build_origin_key_refuses_implausible_key_material() {
        let mut out = [0u8; ORIGIN_KEY_MAX_LEN];
        let path = [0x8000_0030u32, 0x8000_0000, 0x8000_0000, 0x8000_0002];
        let good = compute(&state(ExportKind::Bip48Cosigner));
        let good_key = good.xpub().to_vec();

        assert!(build_origin_key(CEREMONY_FINGERPRINT, &path, &good_key, &mut out) > 0);
        // Empty, truncated, over-long, and not-an-extended-key inputs.
        assert_eq!(build_origin_key(CEREMONY_FINGERPRINT, &path, b"", &mut out), 0);
        assert_eq!(build_origin_key(CEREMONY_FINGERPRINT, &path, &good_key[..80], &mut out), 0);
        let mut over_long = good_key.clone();
        over_long.extend_from_slice(b"aaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(build_origin_key(CEREMONY_FINGERPRINT, &path, &over_long, &mut out), 0);
        let mut mangled = good_key.clone();
        mangled[1] = b'X';
        assert_eq!(build_origin_key(CEREMONY_FINGERPRINT, &path, &mangled, &mut out), 0);

        // An absurdly deep/large origin path overflows the buffer and is
        // refused, not truncated.
        let deep = [u32::MAX; 20];
        assert_eq!(build_origin_key(CEREMONY_FINGERPRINT, &deep, &good_key, &mut out), 0);

        // Non-hardened levels render without the `h` marker.
        let n = build_origin_key(CEREMONY_FINGERPRINT, &[1u32, 0x8000_0002], &good_key, &mut out);
        let rendered = as_text(out.get(..n).unwrap()).to_string();
        assert!(rendered.starts_with("[73c5da0a/1/2h]"), "{rendered}");
    }

    /// Whatever the kind, the QR payload is byte-identical to a value
    /// that is also *printed* — nothing is ever encoded that a user
    /// cannot read on the same screen.
    #[test]
    fn qr_payload_is_always_a_printed_value() {
        for kind in [
            ExportKind::Bip44,
            ExportKind::Bip49,
            ExportKind::Bip84,
            ExportKind::Bip86,
            ExportKind::Bip48Cosigner,
        ] {
            for slip132 in [false, true] {
                let st = ExportState { slip132, ..state(kind) };
                let values = compute(&st);
                let payload = as_text(values.qr_payload()).to_string();
                assert!(!payload.is_empty());
                let printed = screen_lines(&st, &values).join("");
                assert!(
                    printed.contains(&payload),
                    "{kind:?}/{slip132}: the QR payload is not printed on screen"
                );
            }
        }
    }

    #[test]
    fn every_kind_fits_a_supported_qr_version() {
        for kind in [
            ExportKind::Bip44,
            ExportKind::Bip49,
            ExportKind::Bip84,
            ExportKind::Bip86,
            ExportKind::Bip48Cosigner,
        ] {
            let values = compute(&state(kind));
            assert!(values.qr().side() > 0 && values.qr().side() <= seed_qr::MAX_SIDE);
            assert!(values.qr_payload().len() <= seed_qr::max_payload_bytes(seed_qr::MAX_VERSION));
        }
    }

    // -- screen content ---------------------------------------------------

    #[test]
    fn single_sig_screen_shows_path_fingerprint_key_and_descriptor() {
        let st = state(ExportKind::Bip84);
        let values = compute(&st);
        let lines = screen_lines(&st, &values);
        let joined = lines.join("\n");

        assert!(joined.contains("m/84h/0h/0h"), "account path missing:\n{joined}");
        assert!(joined.contains("73c5 da0a"), "chunked fingerprint missing");
        assert!(joined.contains("Native SegWit"), "script-type name missing");
        assert!(joined.contains(ENCODING_STANDARD));
        assert!(joined.contains(XPUB_LABEL));
        assert!(joined.contains(DESCRIPTOR_LABEL));
        assert!(joined.contains(QR_CAPTION_PUBLIC));
        assert!(joined.contains(QR_CAPTION_DESCRIPTOR));
        assert!(!joined.contains(QR_CAPTION_COSIGNER_KEY));
    }

    /// Design D6: the cosigner view shows fingerprint + BIP48 path +
    /// account key + the static coordinator caption, and renders **no
    /// address** — a single-sig address for a multisig path would be
    /// guaranteed wrong.
    #[test]
    fn cosigner_view_shows_the_caption_and_no_address_line() {
        let st = state(ExportKind::Bip48Cosigner);
        let values = compute(&st);
        let joined = screen_lines(&st, &values).join("\n");

        assert!(joined.contains("m/48h/0h/0h/2h"), "BIP48 path missing:\n{joined}");
        assert!(joined.contains("73c5 da0a"), "chunked fingerprint missing");
        assert!(joined.contains(COSIGNER_KIND_LABEL));
        assert!(joined.contains(COSIGNER_CAPTION_1));
        assert!(joined.contains(COSIGNER_CAPTION_2));
        assert!(joined.contains(COSIGNER_CAPTION_3));
        assert!(joined.contains(QR_CAPTION_COSIGNER_KEY));
        assert!(joined.contains(COSIGNER_KEY_LABEL));
        assert!(joined.contains(CEREMONY_BIP48_ORIGIN_PREFIX), "the key origin must be on screen");
        assert!(!joined.contains(DESCRIPTOR_LABEL), "the cosigner view has no descriptor");
        assert!(!joined.contains(XPUB_LABEL), "the bare-key label belongs to single-sig kinds");

        // No address, in any form, on the value column — for every
        // account index. (The privacy panel legitimately says the word
        // "address"; the *value* column must never show one.)
        for account in 0..=BIP48_ACCOUNT_MAX {
            let st = ExportState { cosigner_account: account, ..state(ExportKind::Bip48Cosigner) };
            let values = compute(&st);
            let column = column_lines(&st, &values).join("\n");
            assert!(
                !column.to_lowercase().contains("address"),
                "account {account}: the cosigner column must not label an address"
            );
            for prefix in ["bc1q", "bc1p"] {
                assert!(!column.contains(prefix), "account {account}: {prefix:?} on screen");
            }
            assert!(values.descriptor().is_empty(), "account {account}: no descriptor");
        }
    }

    #[test]
    fn cosigner_caption_rows_reassemble_the_normative_sentence() {
        let joined = std::format!(
            "{COSIGNER_CAPTION_1} {COSIGNER_CAPTION_2} {COSIGNER_CAPTION_3}"
        );
        assert_eq!(joined, COSIGNER_CAPTION);
        assert!(COSIGNER_CAPTION.contains("wsh(sortedmulti(...))"));
        assert!(COSIGNER_CAPTION.contains("only YOUR key material"));
    }

    #[test]
    fn the_encoding_row_names_the_active_encoding() {
        for (kind, slip132, want) in [
            (ExportKind::Bip84, false, ENCODING_STANDARD),
            (ExportKind::Bip84, true, ENCODING_ZPUB),
            (ExportKind::Bip49, true, ENCODING_YPUB),
            (ExportKind::Bip44, true, ENCODING_NO_SLIP132),
            (ExportKind::Bip86, true, ENCODING_NO_SLIP132),
            (ExportKind::Bip48Cosigner, true, ENCODING_NO_SLIP132),
        ] {
            let st = ExportState { slip132, ..state(kind) };
            assert_eq!(st.encoding_label(), want, "{kind:?}/{slip132}");
            let values = compute(&st);
            assert!(screen_lines(&st, &values).join("\n").contains(want));
        }
    }

    // -- leak bans ---------------------------------------------------------

    /// The screen's whole drawable string set may name an extended
    /// *public* key — that is the feature — but never an xprv-class
    /// artifact. Same bar as every other screen, minus exactly the
    /// `xpub`/`ypub`/`zpub` allowlist the leak-scope test enumerates.
    #[test]
    fn never_mentions_xprv_private_key_or_chain_code() {
        let forbidden = ["xprv", "chain code", "pubkey", "seed word", "mnemonic"];
        let mut all: Vec<String> = Vec::new();
        for kind in [
            ExportKind::Bip44,
            ExportKind::Bip49,
            ExportKind::Bip84,
            ExportKind::Bip86,
            ExportKind::Bip48Cosigner,
        ] {
            for slip132 in [false, true] {
                let st = ExportState { slip132, ..state(kind) };
                let values = compute(&st);
                all.extend(screen_lines(&st, &values));
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
            // `private key` is permitted only as a denial ("... no
            // private key"), never as a label for something on screen.
            if let Some(at) = lower.find("private key") {
                assert!(
                    lower[..at].ends_with("no "),
                    "line {line:?} mentions a private key other than to deny one"
                );
            }
        }
        // And that denial really is on the caption a photograph captures.
        assert!(QR_CAPTION_PUBLIC.contains("no private key"));
    }

    #[test]
    fn all_copy_is_printable_ascii() {
        let st = state(ExportKind::Bip84);
        let values = compute(&st);
        let mut all = screen_lines(&st, &values);
        let cos = state(ExportKind::Bip48Cosigner);
        all.extend(screen_lines(&cos, &compute(&cos)));
        for hint in &HINTS {
            all.push(hint.key.to_string());
            all.push(hint.label.to_string());
        }
        for line in &all {
            for ch in line.chars() {
                assert!((' '..='~').contains(&ch), "line {line:?} has non-renderable {ch:?}");
            }
        }
    }

    // -- fit audit ----------------------------------------------------------

    #[test]
    fn the_longest_artifact_still_fits_the_wrap_bound() {
        // The longest descriptor this screen can emit is the BIP49
        // `sh(wpkh(...))` form.
        let longest = compute(&state(ExportKind::Bip49));
        let n = longest.descriptor().len();
        assert!(n <= TEXT_COLS * MAX_WRAP_LINES, "{n}-char descriptor needs more than {MAX_WRAP_LINES} rows");

        let mut runs = [""; MAX_WRAP_LINES];
        let count = wrap(as_text(longest.descriptor()), TEXT_COLS, &mut runs);
        assert!(count <= MAX_WRAP_LINES);
        let rejoined: String = runs[..count].concat();
        assert_eq!(rejoined, as_text(longest.descriptor()), "wrapping must be lossless");

        // The cosigner key expression wraps losslessly within the same
        // bound, and fits its own buffer with headroom.
        let cosigner = compute(&state(ExportKind::Bip48Cosigner));
        assert!(cosigner.origin_key().len() <= ORIGIN_KEY_MAX_LEN);
        assert!(cosigner.origin_key().len() <= TEXT_COLS * MAX_WRAP_LINES);
        let count = wrap(as_text(cosigner.origin_key()), TEXT_COLS, &mut runs);
        let rejoined: String = runs[..count].concat();
        assert_eq!(rejoined, as_text(cosigner.origin_key()), "wrapping must be lossless");
    }

    #[test]
    fn wrap_is_total_on_degenerate_input() {
        let mut runs = [""; MAX_WRAP_LINES];
        assert_eq!(wrap("", 10, &mut runs), 0);
        assert_eq!(wrap("abc", 0, &mut runs), 0);
        assert_eq!(wrap("abc", 100, &mut runs), 1);
        // Over-long input truncates at the bound rather than panicking.
        let long = "x".repeat(TEXT_COLS * (MAX_WRAP_LINES + 3));
        assert_eq!(wrap(&long, TEXT_COLS, &mut runs), MAX_WRAP_LINES);
    }

    #[test]
    fn every_row_and_caption_fits_its_column_at_the_floor() {
        for kind in [
            ExportKind::Bip44,
            ExportKind::Bip49,
            ExportKind::Bip84,
            ExportKind::Bip86,
            ExportKind::Bip48Cosigner,
        ] {
            for slip132 in [false, true] {
                let st = ExportState { slip132, ..state(kind) };
                let values = compute(&st);
                let mut info: [LineBuf; INFO_ROWS] = core::array::from_fn(|_| LineBuf::new());
                let (rows, n) = build_rows(&st, &values, &mut info);
                for row in &rows[..n] {
                    if let Row::Line { text, .. } = *row {
                        assert!(
                            text.chars().count() <= TEXT_COLS,
                            "{kind:?} row {text:?} is {} cols, budget {TEXT_COLS}",
                            text.chars().count()
                        );
                    }
                }
                for caption in qr_captions(&st) {
                    assert!(
                        caption.len() <= QR_CAPTION_COLS,
                        "caption {caption:?} is {} cols, budget {QR_CAPTION_COLS}",
                        caption.len()
                    );
                }
            }
        }

        for line in [PRIVACY_LINE_1, PRIVACY_LINE_2] {
            assert!(line.len() <= PANEL_COLS, "privacy line {line:?} is {} cols", line.len());
        }
    }

    #[test]
    fn both_columns_end_above_the_privacy_panel() {
        let top = chrome::content_top();
        for kind in [
            ExportKind::Bip44,
            ExportKind::Bip49,
            ExportKind::Bip84,
            ExportKind::Bip86,
            ExportKind::Bip48Cosigner,
        ] {
            let st = state(kind);
            let values = compute(&st);

            let mut info: [LineBuf; INFO_ROWS] = core::array::from_fn(|_| LineBuf::new());
            let (rows, n) = build_rows(&st, &values, &mut info);
            // Pinned, not merely bounded: `build_rows`'s fixed array
            // silently drops anything past `MAX_ROWS`, so a future edit
            // that grows a state past the bound must fail loudly here
            // rather than lose its last rows off-screen.
            let want = match kind {
                // 4 info + gap + key label + 3 key rows + gap + the
                // cosigner caption's 3 rows.
                ExportKind::Bip48Cosigner => 13,
                // …or, for a single-sig kind, the descriptor label plus
                // its wrapped rows: 3 for every template except BIP49's
                // `sh(wpkh(...))`, whose 154 characters need a fourth.
                ExportKind::Bip49 => 15,
                _ => 14,
            };
            assert_eq!(n, want, "{kind:?} row count changed");
            assert!(n < MAX_ROWS, "{kind:?} emitted {n} rows, bound is {MAX_ROWS}");
            let text_bottom = top + rows[..n].iter().map(|r| r.height()).sum::<u32>();
            assert!(
                text_bottom <= panel_y(),
                "{kind:?} text column ends at {text_bottom}, panel starts at {}",
                panel_y()
            );

            let module_px = qr::module_px_for_width(values.qr().side(), QR_BLOCK_W);
            assert!(module_px >= 3, "{kind:?} QR would render at {module_px}px/module");
            let qr_bottom =
                top + qr::block_px(values.qr().side(), module_px) + GAP + ROW_1X * 2;
            assert!(
                qr_bottom <= panel_y(),
                "{kind:?} QR block ends at {qr_bottom}, panel starts at {}",
                panel_y()
            );
        }

        assert!(panel_y() + PANEL_H <= chrome::content_bottom());
    }

    #[test]
    fn the_qr_block_and_text_column_do_not_overlap() {
        assert!(MARGIN_X + QR_BLOCK_W <= TEXT_X);
        assert!(TEXT_X + (TEXT_COLS as u32) * GLYPH_WIDTH <= MIN_WIDTH - MARGIN_X);
    }

    /// The in-place export-refusal line (drawn by the driver on a
    /// `BufferTooSmall` refusal) sits entirely ABOVE the privacy panel: its
    /// baseline plus a full line of glyph height must still clear `panel_y()`,
    /// so the refusal never overlaps the panel that owns the bottom of the
    /// content area.
    #[test]
    fn the_refusal_line_sits_above_the_privacy_panel() {
        let y = refusal_line_y();
        assert!(
            y + LINE_PITCH <= panel_y(),
            "refusal baseline {y} + one line pitch {LINE_PITCH} overlaps the panel at {}",
            panel_y()
        );
        assert!(y >= chrome::content_top(), "refusal line {y} is above the content area");
    }

    // -- synthetic maxima ------------------------------------------------
    //
    // `both_columns_end_above_the_privacy_panel` above measures the five
    // artifacts a real seed derives; the longest of them is BIP49's
    // 154-character `sh(wpkh(...))` descriptor, which encodes to a
    // mid-range QR version. The three tests below take the layout to the
    // sizes it can never be *derived* into but must still survive: the
    // longest descriptor this type can hold at all, and a symbol at
    // `seed_qr`'s version-13 ceiling.

    /// A descriptor-shaped payload of exactly `len` bytes: a real
    /// template and origin prefix, padded through the base58 alphabet so
    /// the QR encoder sees byte-mode data of realistic entropy rather
    /// than a run of one repeated character (which compresses through the
    /// mask-penalty scoring differently and would understate the symbol).
    fn descriptor_shaped(len: usize) -> Vec<u8> {
        const B58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        let head = b"wpkh([73c5da0a/84h/0h/0h]xpub";
        let tail = b"/0/*)#abcdefgh";
        let mut out = Vec::with_capacity(len);
        out.extend_from_slice(head);
        while out.len() + tail.len() < len {
            out.push(B58[out.len() % B58.len()]);
        }
        out.extend_from_slice(tail);
        out.truncate(len);
        out
    }

    /// The screen's own buffer is the binding constraint on payload size,
    /// not the QR encoder — and it is comfortably inside the wrapped
    /// text column's capacity, so no value this screen can hold is ever
    /// silently truncated on its way to the display.
    ///
    /// Pinned as three explicit inequalities because the fit audit below
    /// leans on all of them: `DESCRIPTOR_MAX_LEN` (180) < the wrap budget
    /// (`MAX_WRAP_LINES` x `TEXT_COLS` = 200) < `seed_qr`'s 331-byte
    /// version-13 ceiling.
    #[test]
    fn the_wrap_budget_covers_every_payload_this_screen_can_hold() {
        const WRAP_BUDGET: usize = MAX_WRAP_LINES * TEXT_COLS;
        assert_eq!(TEXT_COLS, 50);
        assert_eq!(WRAP_BUDGET, 200);
        assert!(
            DESCRIPTOR_MAX_LEN <= WRAP_BUDGET,
            "a {DESCRIPTOR_MAX_LEN}-byte descriptor would be truncated by the {WRAP_BUDGET}-char \
             wrap budget while the QR still encoded all of it"
        );
        assert!(
            ORIGIN_KEY_MAX_LEN <= WRAP_BUDGET,
            "the cosigner key expression would be truncated on screen"
        );
        // The QR ceiling is far above anything this screen can hold, so
        // `compute_export`'s QR refusal can only ever fire on a payload
        // the buffers already rejected.
        assert!(DESCRIPTOR_MAX_LEN < 331, "seed_qr's version-13 payload ceiling");
    }

    /// The longest descriptor `ExportValues` can hold (`DESCRIPTOR_MAX_LEN`
    /// = 180 bytes — 26 longer than the longest derivable one) rendered
    /// through the real `render` at the SPEC §11.4 floor: the QR stays at
    /// a scannable module size with its full ISO quiet zone inside the
    /// left column, the wrapped text is lossless, and both columns still
    /// clear the privacy panel.
    #[test]
    fn the_longest_holdable_descriptor_renders_inside_the_layout_at_the_floor() {
        let payload = descriptor_shaped(DESCRIPTOR_MAX_LEN);
        assert_eq!(payload.len(), DESCRIPTOR_MAX_LEN);
        let xpub = std::vec![b'x'; XPUB_MAX_LEN];
        let values = ExportValues::synthetic([0xff; 4], &xpub, &payload, &payload);
        let st = state(ExportKind::Bip84);

        // (a) The symbol is scannable and its quiet zone is inside the box.
        let module_px = qr::module_px_for_width(values.qr().side(), QR_BLOCK_W);
        assert!(module_px >= 3, "QR would render at {module_px}px/module");
        let block = qr::block_px(values.qr().side(), module_px);
        assert!(
            block <= QR_BLOCK_W,
            "the {}-module symbol plus its {}-module quiet zone is {block}px, box is {QR_BLOCK_W}px",
            values.qr().side(),
            qr::QUIET_MODULES * 2
        );
        assert_eq!(
            qr::block_modules(values.qr().side()),
            values.qr().side() as u32 + qr::QUIET_MODULES * 2,
            "the drawn block must include a full 4-module quiet zone on each side"
        );

        // (c) The wrapped payload is complete — no silent truncation.
        let mut runs = [""; MAX_WRAP_LINES];
        let n = wrap(as_text(values.descriptor()), TEXT_COLS, &mut runs);
        let rejoined: String = runs[..n].concat();
        assert_eq!(rejoined.as_bytes(), values.descriptor(), "the wrap dropped payload bytes");

        // (b) Nothing crosses the privacy panel or the chrome bands. The
        // band check itself is the central sweep's
        // (`crate::output::screens_fit_audit`, which audits this same
        // synthetic case through its recording framebuffer); here it is
        // the layout arithmetic.
        let top = chrome::content_top();
        let mut info: [LineBuf; INFO_ROWS] = core::array::from_fn(|_| LineBuf::new());
        let (rows, n) = build_rows(&st, &values, &mut info);
        let text_bottom = top + rows[..n].iter().map(|r| r.height()).sum::<u32>();
        assert!(text_bottom <= panel_y(), "text column ends at {text_bottom}, panel at {}", panel_y());
        let qr_bottom = top + block + GAP + ROW_1X * 2;
        assert!(qr_bottom <= panel_y(), "QR block ends at {qr_bottom}, panel at {}", panel_y());
        assert!(panel_y() + PANEL_H <= chrome::content_bottom());

        // And it actually draws, at the floor, without panicking.
        let mut fb = VecFb::new(MIN_WIDTH, MIN_HEIGHT);
        render(&mut fb, &st, &values, BUILD);
        assert!(fb.contains(theme::QR_LIGHT), "the QR must be on screen");
    }

    /// The brief's literal worst case: a symbol at `seed_qr`'s
    /// version-13 ceiling (331 payload bytes, 69 modules a side) drawn in
    /// the real export-screen QR box at the floor.
    ///
    /// No seed can produce a 331-byte artifact — `ExportValues`'s own
    /// descriptor buffer stops at 180
    /// ([`the_wrap_budget_covers_every_payload_this_screen_can_hold`]) —
    /// so the symbol is built through [`ExportValues::synthetic`] while
    /// the printed text stays the longest holdable descriptor. This test
    /// therefore asserts GEOMETRY only, never copy.
    #[test]
    fn a_version_13_symbol_still_fits_the_qr_block_at_the_floor() {
        const V13_PAYLOAD_BYTES: usize = 331;
        let printed = descriptor_shaped(DESCRIPTOR_MAX_LEN);
        let symbol_payload = descriptor_shaped(V13_PAYLOAD_BYTES);
        let xpub = std::vec![b'x'; XPUB_MAX_LEN];
        let values = ExportValues::synthetic([0xff; 4], &xpub, &printed, &symbol_payload);
        let st = state(ExportKind::Bip84);

        assert_eq!(
            values.qr().side(),
            seed_qr::MAX_SIDE,
            "a {V13_PAYLOAD_BYTES}-byte payload must land on the version-13 symbol"
        );

        let module_px = qr::module_px_for_width(values.qr().side(), QR_BLOCK_W);
        assert!(
            module_px >= 3,
            "the largest supported symbol would render at {module_px}px/module in a \
             {QR_BLOCK_W}px box"
        );
        let block = qr::block_px(values.qr().side(), module_px);
        assert!(
            block <= QR_BLOCK_W,
            "version-13 block is {block}px including its quiet zone, box is {QR_BLOCK_W}px"
        );
        let qr_bottom = chrome::content_top() + block + GAP + ROW_1X * 2;
        assert!(
            qr_bottom <= panel_y(),
            "version-13 QR block + captions end at {qr_bottom}, privacy panel starts at {}",
            panel_y()
        );

        let mut fb = VecFb::new(MIN_WIDTH, MIN_HEIGHT);
        render(&mut fb, &st, &values, BUILD);
        assert!(fb.contains(theme::QR_LIGHT), "the quiet zone must be drawn");
        assert!(fb.contains(theme::QR_DARK), "dark modules must be drawn");
    }

    #[test]
    fn footer_fits_the_floor() {
        const HINT_SEP_LEN: usize = 3; // " | "
        let mut cols = 0usize;
        for (i, hint) in HINTS.iter().enumerate() {
            if i > 0 {
                cols += HINT_SEP_LEN;
            }
            cols += hint.key.len() + 2 + 1 + hint.label.len();
        }
        assert!(cols <= MAX_COLS_AT_FLOOR, "export footer is {cols} columns");
    }

    // -- rendering ----------------------------------------------------------

    #[test]
    fn render_draws_the_shell_the_qr_and_the_privacy_panel() {
        let st = state(ExportKind::Bip84);
        let values = compute(&st);
        let mut fb = VecFb::new(MIN_WIDTH, MIN_HEIGHT);
        render(&mut fb, &st, &values, BUILD);

        assert!(fb.contains(theme::QR_LIGHT), "the QR quiet zone must render");
        assert!(fb.contains(theme::WARN), "the privacy panel must render");
        assert!(fb.contains(theme::PANEL), "chrome bands must render");
        assert!(fb.contains(theme::ACCENT), "footer key glyphs must render");
        assert!(fb.contains(theme::TEXT), "values must render");
    }

    #[test]
    fn render_clears_prior_screen_content_first() {
        let st = state(ExportKind::Bip84);
        let values = compute(&st);
        let mut fb = VecFb::new(MIN_WIDTH, MIN_HEIGHT);
        let residue: Vec<u32> = std::vec![theme::WATERMARK.fg; 40];
        let mid = MIN_HEIGHT / 2;
        fb.put_row(MIN_WIDTH - 40, mid, &residue);
        render(&mut fb, &st, &values, BUILD);
        for x in (MIN_WIDTH - 40)..MIN_WIDTH {
            assert_ne!(
                fb.buf[(mid as usize) * (MIN_WIDTH as usize) + (x as usize)],
                theme::WATERMARK.fg,
                "residual pixel at x={x} was not cleared"
            );
        }
    }

    #[test]
    fn render_differs_between_kinds_and_encodings() {
        let mut a = VecFb::new(MIN_WIDTH, MIN_HEIGHT);
        let st_a = state(ExportKind::Bip84);
        render(&mut a, &st_a, &compute(&st_a), BUILD);

        let mut b = VecFb::new(MIN_WIDTH, MIN_HEIGHT);
        let st_b = state(ExportKind::Bip48Cosigner);
        render(&mut b, &st_b, &compute(&st_b), BUILD);
        assert_ne!(a.buf, b.buf, "the cosigner view must look different");

        let mut c = VecFb::new(MIN_WIDTH, MIN_HEIGHT);
        let st_c = ExportState { slip132: true, ..state(ExportKind::Bip84) };
        render(&mut c, &st_c, &compute(&st_c), BUILD);
        assert_ne!(a.buf, c.buf, "the SLIP-132 toggle must change what is drawn");
    }

    /// A scrubbed value set renders the shell but no artifact — the
    /// "leaving the screen" state must never leave a stale QR on screen.
    #[test]
    fn a_scrubbed_value_set_renders_no_qr() {
        let st = state(ExportKind::Bip84);
        let mut values = compute(&st);
        values.scrub();
        let mut fb = VecFb::new(MIN_WIDTH, MIN_HEIGHT);
        render(&mut fb, &st, &values, BUILD);
        assert!(!fb.contains(theme::QR_LIGHT), "a scrubbed value set must draw no QR");
        assert!(fb.contains(theme::PANEL), "the shell still renders");
    }

    /// A scrubbed (or failed) *single-sig* state must keep single-sig
    /// copy: the block that follows the key is chosen by the state's
    /// kind, not by whether a value happens to be populated, so an empty
    /// descriptor can never make the screen claim to be a multisig
    /// cosigner view while the QR caption still says "descriptor".
    #[test]
    fn a_scrubbed_single_sig_state_never_shows_cosigner_copy() {
        for kind in [ExportKind::Bip44, ExportKind::Bip49, ExportKind::Bip84, ExportKind::Bip86] {
            let st = state(kind);
            let mut values = compute(&st);
            values.scrub();
            let joined = screen_lines(&st, &values).join("\n");

            for caption in [COSIGNER_CAPTION_1, COSIGNER_CAPTION_2, COSIGNER_CAPTION_3] {
                assert!(!joined.contains(caption), "{kind:?}: cosigner caption on a single-sig state");
            }
            assert!(!joined.contains(COSIGNER_KIND_LABEL), "{kind:?}");
            assert!(!joined.contains(COSIGNER_KEY_LABEL), "{kind:?}");
            assert!(!joined.contains(QR_CAPTION_COSIGNER_KEY), "{kind:?}");
            // The single-sig copy is what stays, captions included, so
            // the two columns never contradict each other.
            assert!(joined.contains(XPUB_LABEL), "{kind:?}");
            assert!(joined.contains(DESCRIPTOR_LABEL), "{kind:?}");
            assert!(joined.contains(QR_CAPTION_DESCRIPTOR), "{kind:?}");
        }

        // Symmetrically: an empty cosigner state keeps cosigner copy.
        let st = state(ExportKind::Bip48Cosigner);
        let empty = ExportValues::new();
        let joined = screen_lines(&st, &empty).join("\n");
        assert!(joined.contains(COSIGNER_CAPTION_1));
        assert!(joined.contains(COSIGNER_KEY_LABEL));
        assert!(joined.contains(QR_CAPTION_COSIGNER_KEY));
        assert!(!joined.contains(DESCRIPTOR_LABEL));
    }
}
