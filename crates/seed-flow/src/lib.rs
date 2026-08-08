//! `seed-flow` — the whole UI flow, pre-secret AND secret-phase (WP-25/
//! 26, SPEC §11, §12, §17.4, §21, §22-§24, §26, §8.4), factored into a
//! standalone, `no_std`, host-testable library crate shared verbatim by
//! all three UI editions (`seed-uefi-production`, `seed-uefi-test`,
//! `seed-desktop-test`).
//!
//! # Why this crate exists
//!
//! Every UI-edition binary crate is either `#![no_std] #![no_main]`
//! (`seed-uefi-production`, `seed-uefi-test`) or otherwise unsuited to
//! host-testing its own UI logic in place. `cargo test -p seed-uefi-test`
//! on the host, for example, would try to link a `std`-based test
//! harness against a crate that unconditionally declares
//! `#![no_std]`/`#[panic_handler]`, which fails with duplicate lang-item
//! errors — there is no way to make a `no_main` UEFI binary crate itself
//! host-testable. So every byte of *testable logic* for the whole flow
//! lives here instead, in a library crate with an ordinary host test
//! harness (`#[cfg(test)] extern crate std;`, the same pattern every
//! other crate in this workspace already uses for its own host tests).
//! Each edition's own `src/flow_pre/` and `src/flow_secret/` are reduced
//! to thin real-firmware/real-desktop-window provider implementations
//! plus their own `#[entry]`/`main` wiring — see each one's own doc
//! comment.
//!
//! This crate lives at the workspace top level (`crates/seed-flow/`) —
//! not nested inside any one edition's directory — precisely so that no
//! edition's dependency graph, least of all `seed-uefi-production`'s,
//! ever has a `path = "..."` dependency that physically crosses into
//! another edition's own directory tree (see this crate's `Cargo.toml`
//! for the history of why that mattered).
//!
//! # Architecture: two phases, two different secret-handling regimes
//!
//! This crate is organized into exactly two phases, and the SPEC §13/
//! §20 secret-bearing-type restrictions apply to one of them and not the
//! other — readers must not assume a blanket rule either way:
//!
//! - **Pre-secret** ([`output`], [`keys`], [`text`], [`diagnostics`],
//!   [`entropy_avail`], [`driver`]): every screen and every branch is a
//!   pure function/struct taking provider traits, and
//!   no entropy, mnemonic or key material is ever constructed, read or
//!   displayed anywhere in this half of the module tree (SPEC §12.1
//!   scope) — every type defined in these modules may freely derive
//!   `Debug`/`Clone`/`Copy`/`PartialEq`, because none of them is ever
//!   secret-bearing. [`driver::run_pre_secret_flow`] is this phase's
//!   single entry point: it drives `seed_protocol::state::StateMachine`
//!   (WP-23, reused verbatim — this crate never invents its own control
//!   flow) from `AppState::Start` through `AppState::
//!   SetupSelection` (the merged setup screen) and hands off
//!   a still-live [`seed_protocol::state::StateMachine`] to the caller
//!   once an entropy mode has been chosen.
//! - **Secret phase** ([`flow_secret`], starting at `AppState::
//!   MachineEntropyAcquisition`/`AppState::PhysicalCollection`): physical/
//!   machine entropy acquisition, final confirmation, mnemonic display,
//!   hidden re-entry, derivation-verification display, completion
//!   education and scrub-and-shutdown. This half of the crate builds and
//!   holds real secret material inside a `seed_core::arena::SecretArena`
//!   (`flow_secret::driver::run_secret_flow`'s own `arena` parameter) and
//!   the resolved-word-index type `flow_secret::reentry` scrubs on every
//!   path — the SPEC §13/§20.2/§20.3 restrictions apply in full here:
//!   no secret-bearing type in this half may derive `Debug`/`Display`/
//!   `Clone`/`Copy`, buffers are fixed-size, and every scrub site uses a
//!   volatile write (see `flow_secret`'s own module doc for the full
//!   architecture and each module's specific SPEC citation).
#![no_std]

#[cfg(test)]
extern crate std;

/// Narrow line-oriented output trait (SPEC §12.1) plus a fixed-capacity
/// `core::fmt::Write` line builder for interpolated diagnostic text.
pub mod output;

/// Menu-level keystroke trait, distinguishing Escape (SPEC §22.1) from
/// every other special key — see the module doc for why this is not
/// simply `seed_platform_x86::input::KeySource`.
pub mod keys;

/// Fixed/verbatim screen text (SPEC §22.1, §22.2 label, §22.4, §22.5,
/// §8.4, §18.2, §18.3).
pub mod text;

/// SPEC_MAIN_MENU.md §17.3 item 3 (Learn) + SPEC §34: shared,
/// backend-neutral, allocation-free education page content for the
/// read-only Learn screen (ported from `seed-desktop-test`'s
/// `launcher/learn.rs`, without any desktop dependency).
pub mod edu;

/// SPEC §22.3 platform-diagnostics gate: provider traits for the four
/// mandatory startup checks, "not proof"/spoofable wording, and the
/// combined diagnostics screen.
pub mod diagnostics;

/// Shared screen chrome (design doc §3.3/§3.4,
/// `docs/superpowers/specs/2026-08-07-ceremony-ux-redesign-design.md`):
/// the header band (product name, build ID, stage rail) and footer key
/// bar every ceremony screen composes on top of.
pub mod chrome;

/// The ceremony stage screens (design doc §4): one module per stage
/// screen, each a pure state struct + render fn over `&mut dyn
/// seed_core::contracts::Framebuffer`, composed on [`chrome`]'s shared
/// header/footer — see `screens`' own module doc comment.
pub mod screens;

/// SPEC §22.5 entropy-mode gating: which of the three modes are
/// available, with a specific reason for each disabled one, plus the
/// §18.2 sole-source rule.
pub mod entropy_avail;

/// The pre-secret flow driver: [`driver::run_pre_secret_flow`].
pub mod driver;

pub use driver::{run_pre_secret_flow, FlowResult, Gates, PreSecretOutcome};

/// WP-26 (SPEC §12, §17.4, §22.6-24, §26): the secret-phase UI flow —
/// physical/machine entropy acquisition, final confirmation, mnemonic
/// display, hidden re-entry, derivation-verification display, completion
/// education and scrub-and-shutdown. Picks up exactly where
/// [`driver::run_pre_secret_flow`] hands off (`AppState::
/// MachineEntropyAcquisition` / `AppState::PhysicalCollection`) and never
/// returns to firmware except through the fatal/shutdown chain (SPEC
/// §21, §27.2). See that module's own doc comment for the full
/// architecture; it follows the identical provider-trait,
/// host-testable-first pattern this crate's pre-secret modules already
/// established.
pub mod flow_secret;

/// Shared real-firmware provider wiring (STEP B dedup): the
/// `FirmwareMenuKeys`/`ProdConsoleGate`/`console_handles()`/gate-wiring
/// code every UEFI edition used to copy-paste into its own
/// `src/flow_pre/`, `src/flow_secret/`, parameterized by a single
/// `production_marker: Option<fn() -> bool>` (see this module's own doc
/// comment for the full rationale and the isolation guarantee it
/// preserves). Only compiled for the real `x86_64-unknown-uefi` target —
/// the `uefi` crate dependency it needs is itself gated to that target in
/// this crate's `Cargo.toml`, so this `#[cfg]` (not merely the
/// dependency's own absence) is what keeps `cargo test -p seed-flow` on
/// the host from ever compiling it.
#[cfg(target_os = "uefi")]
pub mod firmware_wiring;
