//! `alea-verify`'s library half: the host-testable screen/dispatch logic
//! (`verify`, `custom_path`, `markers`), split out of `main.rs` so it can be
//! exercised by ordinary `cargo test -p alea-verify` on the host, exactly
//! like `seed-flow` (the workspace's other shared `no_std`-but-
//! host-testable crate — see that crate's own lib.rs doc comment for the
//! same rationale) instead of only via `cargo check --target
//! x86_64-unknown-uefi`.
//!
//! # Why this split was necessary (Task 19 review fix)
//!
//! `main.rs` is `#![no_std] #![no_main]` with its own `#[panic_handler]`,
//! which cannot coexist with `cargo test`'s host test harness (the harness
//! links `std`, whose own `#[panic_handler]` collides with a second one
//! defined in the same binary crate — `error[E0152]: found duplicate lang
//! item`). A binary crate's own `src/main.rs` is therefore structurally
//! untestable on the host here, same as `seed-uefi-production`'s
//! `launcher.rs` (see that module's own doc comment: "no pre-existing unit
//! tests... verified only via `cargo check --target x86_64-unknown-uefi`").
//! Moving the actual screen-rendering/dispatch logic into this library
//! target fixes that: `main.rs` still owns the `#[entry]`/`#[panic_handler]`
//! UEFI-only wiring and is still `#![no_std] #![no_main]`, but everything
//! it calls now lives in a crate that only conditionally goes `no_std`
//! (`#[cfg(not(test))]` below — the same idiom `seed-flow`'s own
//! `#[cfg(test)] extern crate std;` test modules rely on, just applied at
//! the crate root instead of per-module since every module here needs
//! `alloc` unconditionally, unlike `seed-flow`).
//!
//! `extern crate alloc;` is unconditional (needed under `no_std`; a no-op
//! under `std`, where `alloc` is still directly nameable) so `verify.rs`/
//! `custom_path.rs`'s `use alloc::string::{String, ToString};` etc. resolve
//! identically on both the UEFI target and the host test target.
#![cfg_attr(not(test), no_std)]

#[macro_use]
extern crate alloc;

/// SPEC §28-style positive edition marker (this binary is NOT scanned by
/// `tools/binary-policy-scanner`, which runs only against
/// `seed-uefi-production.efi`; the marker is here so a future verify-aware
/// tool can positively identify this artifact).
pub mod markers;

/// The cross-device verification screen/dispatch flow (Method A dice/coin
/// profiles + Method C iancoleman raw-entropy encodings), ported from
/// `seed-desktop-test`'s `launcher::compat` to this no_std+alloc, GOP-
/// rendered edition.
pub mod verify;

/// The `[P]` free-form custom derivation-path sub-tool reached from a
/// verification result screen, ported from `seed-desktop-test`'s
/// `launcher::custom_path` (reuses `seed_flow::flow_secret::custom_path`'s
/// block/warn logic verbatim).
pub mod custom_path;
