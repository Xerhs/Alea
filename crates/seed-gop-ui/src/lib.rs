//! `seed-gop-ui` — embedded bitmap font + text rendering, and the UEFI GOP
//! framebuffer backend (SPEC §11.4, §12.2, §12.4).
//!
//! `#![no_std]` always: the font/text module has no platform dependency
//! and is reused as-is by the `std` desktop test edition
//! (`seed-desktop-test` implements its own `Framebuffer` over
//! `winit`+`softbuffer` and calls into `font` for glyph rendering). The
//! `gop` module is UEFI-specific and its `uefi` dependency is gated behind
//! the `uefi-backend` feature (off by default) so enabling this crate does
//! not pull UEFI protocol code into non-UEFI consumers.
#![no_std]

/// 8×16 bitmap font + `draw_text`/`draw_word`/`scrub_fill` against the
/// `Framebuffer` trait (WP-10, SPEC §12.2).
pub mod font;

/// UEFI GOP mode selection, `PixelBltOnly` refusal, linear-framebuffer
/// `Framebuffer` implementation and scrub sequence (WP-21, SPEC §11.4,
/// §12.2, §12.4). Requires the `uefi-backend` feature.
pub mod gop;

/// Shared screen-layout constants (margin, line pitch, style) every
/// GOP-rendered text screen in this workspace agrees on (SPEC.md
/// amendment 2026-08-06) — see the module doc comment.
pub mod layout;

/// Panel/rule/checkbox rendering primitives (SPEC §3.1 role-palette
/// layout building blocks) — `fill_rect`, `hrule`, `panel`, `warn_panel`,
/// `checkbox`, all built on `Framebuffer::put_row`.
pub mod panel;

/// QR symbol rendering for the opt-in wallet-export screen: integer
/// module scaling onto a white quiet-zone panel (wallet-export design
/// §4.1). Public export values only — see the module doc comment.
pub mod qr;

/// The role palette (SPEC §3.1): every drawn color, named. The only
/// module in this crate — or in `seed-flow`/`seed-desktop-test` — where a
/// raw color literal may appear (enforced by the `no_raw_colors` host
/// test).
pub mod theme;
