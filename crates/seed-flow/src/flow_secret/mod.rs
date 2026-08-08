//! WP-26 — the secret-phase UI flow (SPEC §12, §17.4, §21, §22.6-§24,
//! §25-§26). The security-critical seam of the whole product.
//!
//! # Architecture
//!
//! Follows the exact same provider-trait, host-testable-first pattern
//! `crate::driver`/WP-25 already established for the pre-secret flow —
//! every screen and branch is a pure function/struct taking provider
//! traits, driven by `seed_protocol::state::StateMachine` (WP-23, reused
//! verbatim, never re-implemented). Each UI edition wires every trait
//! against its own real backend in its own `src/flow_secret/`
//! (`crates/seed-uefi-production/src/flow_secret/` and
//! `crates/seed-uefi-test/src/flow_secret/` against real firmware, real
//! GOP framebuffer and real WP-24 machine-entropy drivers;
//! `crates/seed-desktop-test/src/` against a desktop window), verified
//! only by cross-compilation (UEFI editions) or ordinary host build
//! (desktop edition); every byte of *testable logic* lives here,
//! exercised by ordinary host `cargo test`.
//!
//! - [`physical`] — SPEC §17.4 physical-entry screen: dice/coin
//!   collection, live integer bit-progress, undo, clear-with-
//!   confirmation, the SPEC §17.2 budget gate.
//! - [`machine`] — SPEC §15-§16/§18 machine-source acquisition, reusing
//!   WP-24's drivers via [`machine::MachineSourceGate`].
//! - [`derive`] — SPEC §19 transcript build + final-entropy derivation
//!   in the arena, with the immediate SPEC §19.4 scrubs.
//! - [`display`] — SPEC §22.7 mnemonic display: GOP-only, per-word
//!   `draw_word` by index (never a concatenated phrase string), `[H]`
//!   hide / `[D]` destroy with its second confirmation.
//! - [`reentry`] — SPEC §23.1-§23.2 complete hidden re-entry:
//!   Enter-terminated, no-echo, retry/reveal/destroy.
//! - [`verification`] — SPEC §24.3 wallet-derivation verification
//!   display: fingerprint + four addresses only, skippable, empty-
//!   passphrase caveat, never an `xpub`/`xprv`/seed.
//! - [`education`] — SPEC §23.3 completion education, exact required
//!   wording.
//! - [`shutdown`] — SPEC §26 scrub-and-shutdown: the full ordered scrub
//!   list, `EfiResetShutdown` via [`shutdown::ShutdownProvider`],
//!   retry-once, the exact failure text, non-returning halt, and
//!   [`shutdown::FaultHook`] for the future WP-33 fault-injection suite.
//! - [`gop_screen`] — the shared fixed-layout text-line helper every
//!   post-secret screen above uses to draw its own (never the
//!   mnemonic's) fixed UI copy.
//! - [`driver`] — [`driver::run_secret_flow`], the single entry point
//!   tying every module above together, driven state-by-state by
//!   `StateMachine`.
//!
//! # No full-mnemonic string, anywhere
//!
//! No function in this module tree ever holds, builds or formats a
//! concatenated mnemonic phrase (SPEC §12.2). The only two places a
//! mnemonic word is ever touched are [`display::render_mnemonic_display`]
//! (which calls `seed_gop_ui::font::draw_word` once per slot, by index)
//! and [`reentry::read_and_check_one_word`] (which compares one resolved
//! index at a time and never stores more than the current position's
//! result). `seed_core::bip39::mnemonic_to_seed`'s own single, explicitly
//! scrubbed, controlled exception (WP-05's documented stack buffer) is
//! the only place any project code ever materializes word text next to
//! other word text, and it lives entirely inside `seed-core`, outside
//! this crate.

/// SPEC_DERIVATION_CUSTOM.md §3/§4: the §11.5-safe structured custom
/// derivation-path builder (PRIMARY surface), reachable from the §24
/// verification screen. Commit-then-derive against the resident mnemonic.
pub mod custom_path;
/// SPEC_DERIVATION_CUSTOM.md §9: the SECONDARY desktop free-form BIP32
/// path parser (`no_std`, no-`alloc`, no-panic; string -> bounded
/// `[u32; MAX_DEPTH]`). Desktop / compat surface only — never wired into a
/// production UEFI input path (which keeps the structured builder only).
pub mod path_parse;
pub mod derive;
pub mod display;
pub mod driver;
pub mod education;
pub mod gop_screen;
pub mod machine;
/// SPEC_PASSPHRASE §4/§6/§9: the post-secret optional-passphrase
/// offer/entry/confirm screens (masked entry, warnings, ASCII validation,
/// constant-time re-entry compare, extended-charset keyboard gating).
pub mod passphrase;
pub mod physical;
pub mod reentry;
pub mod shutdown;
pub mod verification;

/// SPEC_EDU_UI §4-§6: the counted-vs-claimed composition panel (WP-E3/E4).
pub mod composition;

/// SPEC_DICE_COIN_ART.md §3/§8: dice/coin text-art (dice/coin WP).
pub mod dice_coin_art;

pub use driver::{
    export_error_disposition, run_export_branch, run_secret_flow, ExportBranchOutcome,
    SecretFlowOutcome, SecretProviders,
};
