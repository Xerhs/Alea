//! Owned by WP-21 (SPEC §11.4, §12.2, §12.4).
//!
//! GOP mode selection with a named `PixelBltOnly` refusal
//! ([`mode::select_mode`]), a pixel-format-aware linear-framebuffer
//! [`seed_core::contracts::Framebuffer`] implementation
//! ([`framebuffer::LinearFramebuffer`], RGB/BGR/BitMask via
//! [`pixel::PixelLayout`]), the resolution floor
//! ([`mode::MIN_WIDTH`]/[`mode::MIN_HEIGHT`]), the SPEC §12.4 scrub
//! sequence ([`scrub::scrub_sequence`]: pattern → blank → fence), and a
//! fixed-buffer device-path display string
//! ([`device_path::DevicePathText`]).
//!
//! Module split, by design, to keep as much logic as possible
//! host-testable without the `uefi-backend` feature:
//!
//! - [`pixel`], [`mode`], [`framebuffer`], [`device_path`]: pure/raw-
//!   pointer logic, no UEFI protocol calls, always compiled, unit-tested
//!   on the host against a fake mode list ([`mode`] tests) and an
//!   in-memory framebuffer ([`framebuffer`] tests).
//! - [`backend`]: the only module that calls into the real `uefi` crate's
//!   `GraphicsOutput`/`DevicePathToText` protocols. Gated behind the
//!   `uefi-backend` feature (see crate root doc); verified by
//!   cross-compilation to `x86_64-unknown-uefi` only, since there is no
//!   real GOP protocol to exercise on the host.

pub mod device_path;
pub mod framebuffer;
pub mod mode;
pub mod pixel;
mod scrub;

#[cfg(feature = "uefi-backend")]
pub mod backend;

pub use device_path::{ascii_from_utf16, DevicePathText, MAX_DEVICE_PATH_TEXT, NO_DEVICE_PATH_TEXT};
pub use framebuffer::LinearFramebuffer;
pub use mode::{
    select_mode, ModeFormat, ModeInfo, ModeSelectError, BELOW_RESOLUTION_FLOOR_REASON, MAX_GOP_MODES, MIN_HEIGHT,
    MIN_WIDTH, PIXEL_BLT_ONLY_REFUSAL_REASON,
};
pub use pixel::{pack_pixel, PixelLayout};
pub use scrub::{scrub_sequence, NEUTRAL_SCRUB_PATTERN};

#[cfg(feature = "uefi-backend")]
pub use backend::{device_path_text, open_selected_gop, GopOpenError};
