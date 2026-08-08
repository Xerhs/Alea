//! Stage-specific ceremony screens (design doc §4,
//! `docs/superpowers/specs/2026-08-07-ceremony-ux-redesign-design.md`):
//! one module per stage screen, each a pure state struct + render fn over
//! `&mut dyn seed_core::contracts::Framebuffer`, composed on top of the
//! shared [`crate::chrome`] header/footer.
//!
//! Screens live here rather than under [`crate::flow_secret`] because the
//! shell is phase-agnostic: the same header band, stage rail and footer
//! key bar wrap pre-secret and post-secret screens alike. A screen module
//! in here owns *rendering and key handling only* — the drivers
//! ([`crate::driver`], [`crate::flow_secret::driver`]) keep sole ownership
//! of state-machine wiring.
//!
//! # What these modules may touch
//!
//! Every screen state struct in this tree holds non-secret UI state only
//! (a checkbox triple, a selected row, a reveal toggle, a script kind), and
//! every renderer draws either `&'static str` copy or values a driver hands
//! it. Nothing here builds, stores or scrubs a mnemonic, a BIP39 seed, an
//! extended private key, a chain code or accumulated re-entry input.
//!
//! [`export`] is the one module that reaches into the
//! [`SecretArena`](seed_core::arena::SecretArena) at all, and only through
//! a single function: [`export::compute_export`] re-derives ONE account's
//! public data (fingerprint, account xpub, descriptor, QR) from the
//! resident mnemonic, following
//! [`crate::flow_secret::derive::compute_custom_address`]'s reviewed
//! commit-then-derive discipline — every private intermediate it creates is
//! zeroized before the function returns, on the error path as well as the
//! success path, and the arena's derivation stage is scrubbed before its
//! first `return`. What it leaves behind in
//! [`export::ExportValues`](export::ExportValues) is public but
//! account-linking, so the driver scrubs that too on every exit from the
//! export screen. No other module in this tree takes a `SecretArena` at
//! all.
//!
//! PARALLEL-MERGE NOTE: this file is intentionally minimal (doc comment
//! + `pub mod` lines only) — several Wave-4 tasks add a screen module
//! here independently; the controller union-merges each task's own
//! `pub mod` line rather than any one task owning the whole file.

pub mod device;
pub mod export;
pub mod export_warning;
pub mod finish;
pub mod gates;
pub mod generate;
pub mod prepare;
pub mod setup;
pub mod verify;
