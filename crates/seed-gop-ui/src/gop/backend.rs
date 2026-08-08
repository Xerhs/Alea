//! Real UEFI GOP glue (SPEC §11.4). Owned by WP-21. Feature `uefi-backend`
//! only.
//!
//! This is the sole place in `gop/` that touches the `uefi` crate: it
//! locates the `GraphicsOutput` protocol, converts its reported modes into
//! the project-owned [`super::mode::ModeInfo`] so [`super::mode::select_mode`]
//! (pure, host-tested) can pick one, sets that mode, and hands back a
//! [`super::framebuffer::LinearFramebuffer`] wrapping the real memory-mapped
//! framebuffer plus a [`super::device_path::DevicePathText`] for the
//! confirmation screen (SPEC §11.4: "Display its resolution and device
//! path before generation. Require user confirmation.").
//!
//! Cannot be exercised by host tests (no real GOP protocol on the host);
//! verified by cross-compilation to `x86_64-unknown-uefi` only, per the
//! WP-21 task instructions. All host-testable logic lives in
//! `pixel`/`mode`/`framebuffer`/`device_path` and is exercised there.
//!
//! ## Why every open in this file is non-exclusive (security-reviewed)
//!
//! Every protocol this file opens (`GraphicsOutput`, `DevicePath`,
//! `DevicePathToText`) is opened with [`OpenProtocolAttributes::GetProtocol`]
//! via [`open_shared`], never `boot::open_protocol_exclusive`/
//! `OpenProtocolAttributes::Exclusive`. This was a real-hardware field
//! failure, not a style preference: on a Phoenix-class OEM laptop (OEM laptop,
//! Fedora/UEFI), an exclusive open of `GraphicsOutput` triggers UEFI
//! `DisconnectController` against the handle's `ByDriver` opener -- the
//! firmware's own console driver (`ConPlatformDxe`/`ConSplitterDxe`,
//! whichever composites `SimpleTextOut` text onto the GOP). Disconnecting
//! it tears down the firmware text console *permanently for the rest of
//! boot*, not just for the duration of the open. Both `seed-flow`
//! callers of [`open_selected_gop`] run while the firmware console is
//! still needed: the pre-secret `ProdGraphicsGate` (SPEC §11.4
//! validation) runs mid firmware-console UI, and the secret-phase GOP
//! open (`run_secret_phase`) is followed by several
//! firmware-console-rendered screens (machine-entropy acquisition,
//! physical dice/coin entry, entropy-mode selection, the composition
//! panel and final confirmation) before the flow ever becomes
//! framebuffer-only at `MnemonicDisplay`. An exclusive open at either
//! site black-screens everything after it on this firmware class, with
//! no error -- confirmed by a step-by-step hardware probe: a marker
//! printed after an exclusive open never appears; the same marker after
//! a `GetProtocol` open plus `set_mode` survives.
//!
//! Exclusive access buys no confidentiality here to trade against that
//! cost: `GraphicsOutput`/console drivers only *write* toward the GOP
//! (compositing text into the framebuffer); nothing in the UEFI console
//! model lets a `ByDriver` opener read back or capture framebuffer
//! contents, so detaching it protects no secret. Its only real benefit
//! -- preventing firmware text from being composited *over* already-drawn
//! secret pixels during mnemonic display -- is a pure integrity/
//! availability property, and this codebase never issues a
//! `SimpleTextOut` write while any secret is on the framebuffer (nothing
//! under `flow_secret/` touches `text_out` from `MnemonicDisplay` onward
//! -- see the regression test in `seed-flow`'s `driver.rs` that pins this
//! ordering permanently); a hypothetical firmware-initiated overlay is
//! caught fail-safe by SPEC §23's complete hidden re-entry as a mismatch,
//! not a silent leak.
//!
//! If exclusive access is ever reintroduced, it must be staged at the
//! `MnemonicDisplay` boundary (the one point the flow is provably
//! framebuffer-only for the rest of the ceremony), held concurrently
//! with a still-live shared open for framebuffer-pointer validity, be
//! best-effort on failure (entropy is already committed by then), and be
//! validated on real Phoenix-class firmware first -- see `ci.sh`'s
//! `open_protocol_exclusive` source scanner, which exists to force this
//! conversation rather than let the symbol silently creep back in.
//!
//! ## Never open a second `GraphicsOutput` `ScopedProtocol` while the
//! ## session one is held (SPEC.md amendment 2026-08-06)
//!
//! `crate::gop::backend` (this module) used to expose a
//! `current_mode_dims()` helper that re-opened `GraphicsOutput` via
//! [`open_shared`] to cheaply read the *current* mode without touching
//! `set_mode` again, for the SPEC §11.4 mid-flow re-check. That was
//! removed: per UEFI's own `CloseProtocol` semantics (mirrored by EDK2's
//! `CoreCloseProtocol`), `CloseProtocol` removes *every* open-list entry
//! matching the same `(agent, controller)` pair regardless of how many
//! opens are outstanding on it -- on EDK2-derived firmware, an identical
//! `GetProtocol` open from the same agent dedups into the session's own
//! already-open entry (`OpenCount` incremented, not a second entry), so
//! the transient's `Drop` (`CloseProtocol`) tears down *the session's*
//! registration outright. The session's own later `Drop` then observes
//! `EFI_NOT_FOUND` from firmware, which the `uefi` crate's
//! `ScopedProtocol::drop` asserts is `Status::SUCCESS` -- a panic on any
//! exit-to-firmware path taken after the mid-flow re-check ran, not just
//! the happy path (which never drops the session at all). The fix:
//! `crate::firmware_wiring::HeldGopGraphicsGate` reads the current mode
//! straight off the already-open session `ScopedProtocol` it borrows (its
//! `current_mode_info()`/`Deref`), never opening a second handle. Do not
//! reintroduce a `current_mode_dims`-shaped helper that opens
//! `GraphicsOutput` again for as long as any caller might still be
//! holding `SessionGop`'s own open.

use uefi::boot;
use uefi::boot::{OpenProtocolAttributes, OpenProtocolParams};
use uefi::proto::console::gop::{GraphicsOutput, PixelFormat};
use uefi::proto::device_path::text::{AllowShortcuts, DevicePathToText, DisplayOnly};
use uefi::proto::device_path::DevicePath;
use uefi::Handle;

use super::device_path::{ascii_from_utf16, DevicePathText};
use super::framebuffer::LinearFramebuffer;
use super::mode::{select_mode, ModeFormat, ModeInfo, ModeSelectError, MAX_GOP_MODES};
use super::pixel::PixelLayout;

/// Errors from [`open_selected_gop`] beyond [`ModeSelectError`] (SPEC
/// §11.4).
#[derive(Debug)]
pub enum GopOpenError {
    /// No handle on the system implements `GraphicsOutput`, or it could
    /// not be opened.
    NoGraphicsOutput,
    /// A mode was selected but `GraphicsOutput::set_mode` failed.
    SetModeFailed,
    /// Mode selection itself refused every reported mode (SPEC §11.4).
    ModeSelect(ModeSelectError),
}

/// Open `handle`'s `P` protocol non-exclusively
/// ([`OpenProtocolAttributes::GetProtocol`]), as this agent
/// (`boot::image_handle()`), with no controller association.
///
/// Deliberately never `boot::open_protocol_exclusive`/
/// `OpenProtocolAttributes::Exclusive` -- see the module doc for why:
/// on real (Phoenix-class) firmware, an exclusive open of the GOP
/// handle's protocols disconnects the firmware's own console driver and
/// black-screens every console-rendered screen for the rest of boot.
/// `GetProtocol` has no such side effect on other agents and is what
/// every caller in this file uses.
fn open_shared<P: uefi::proto::ProtocolPointer + ?Sized>(handle: Handle) -> uefi::Result<boot::ScopedProtocol<P>> {
    let params = OpenProtocolParams { handle, agent: boot::image_handle(), controller: None };
    // SAFETY: this UEFI application is single-threaded and runs at
    // TPL_APPLICATION; the returned `ScopedProtocol` is used only
    // synchronously by its caller (never stored past this call stack in
    // a way that could alias a concurrent reentrant open), and closing
    // it on `Drop` (`CloseProtocol`) is always valid for a `GetProtocol`
    // entry opened by this same agent/handle pair. Sharing access with
    // the still-attached firmware console driver is the deliberate
    // point of this open, not an oversight -- see the module doc.
    unsafe { boot::open_protocol::<P>(params, OpenProtocolAttributes::GetProtocol) }
}

fn convert_format(info: &uefi::proto::console::gop::ModeInfo) -> ModeFormat {
    match info.pixel_format() {
        PixelFormat::Rgb => ModeFormat::Linear(PixelLayout::Rgb),
        PixelFormat::Bgr => ModeFormat::Linear(PixelLayout::Bgr),
        PixelFormat::Bitmask => {
            if let Some(mask) = info.pixel_bitmask() {
                ModeFormat::Linear(PixelLayout::Bitmask {
                    red_mask: mask.red,
                    green_mask: mask.green,
                    blue_mask: mask.blue,
                })
            } else {
                // Spec-impossible (Bitmask format always carries a mask),
                // but fail closed rather than assume a layout: treat as
                // refusable exactly like BltOnly.
                ModeFormat::BltOnly
            }
        }
        PixelFormat::BltOnly => ModeFormat::BltOnly,
    }
}

/// Locate the `GraphicsOutput` protocol, enumerate its modes into our
/// fixed [`ModeInfo`] representation (SPEC §13: no `alloc`, fixed
/// buffers), run [`select_mode`], set that mode, and return an opened
/// protocol handle plus the linear framebuffer over it.
///
/// # Errors
///
/// Returns [`GopOpenError::ModeSelect`] with the SPEC §11.4-mandated
/// named reason (`ModeSelectError::reason()`) when no eligible mode
/// exists — in particular, this is the `PixelBltOnly` refusal path.
pub fn open_selected_gop() -> Result<(uefi::boot::ScopedProtocol<GraphicsOutput>, LinearFramebuffer), GopOpenError> {
    let handle = boot::get_handle_for_protocol::<GraphicsOutput>().map_err(|_| GopOpenError::NoGraphicsOutput)?;
    let mut gop = open_shared::<GraphicsOutput>(handle).map_err(|_| GopOpenError::NoGraphicsOutput)?;

    let mut modes = [ModeInfo {
        index: 0,
        width: 0,
        height: 0,
        stride_px: 0,
        format: ModeFormat::BltOnly,
    }; MAX_GOP_MODES];
    let mut count = 0usize;
    for mode in gop.modes() {
        if count >= MAX_GOP_MODES {
            break;
        }
        let info = mode.info();
        let (width, height) = info.resolution();
        modes[count] = ModeInfo {
            index: count as u32,
            width: width as u32,
            height: height as u32,
            stride_px: info.stride() as u32,
            format: convert_format(info),
        };
        count += 1;
    }

    let chosen = select_mode(&modes[..count]).map_err(GopOpenError::ModeSelect)?;

    // Re-resolve the concrete `uefi::proto::console::gop::Mode` for
    // `chosen.index` (our fixed array only kept the derived summary) and
    // apply it.
    let real_mode = gop
        .modes()
        .nth(chosen.index as usize)
        .ok_or(GopOpenError::SetModeFailed)?;
    gop.set_mode(&real_mode).map_err(|_| GopOpenError::SetModeFailed)?;

    let layout = match chosen.format {
        ModeFormat::Linear(l) => l,
        // Unreachable: select_mode never returns a BltOnly mode as
        // `chosen`, but fail closed instead of unwrap/panic on secret
        // display setup code.
        ModeFormat::BltOnly => return Err(GopOpenError::ModeSelect(ModeSelectError::OnlyPixelBltOnly)),
    };

    let info = gop.current_mode_info();
    let (width, height) = info.resolution();
    let stride = info.stride();
    let mut fb = gop.frame_buffer();
    // SAFETY: `fb` is the memory-mapped linear framebuffer for the mode
    // just set; `current_mode_info()` reports the matching geometry, and
    // `frame_buffer()` itself asserts the mode is not `BltOnly` (checked
    // again above). `fb` (and therefore the memory) outlives this
    // function's returned `LinearFramebuffer` only as long as the caller
    // keeps the returned `ScopedProtocol<GraphicsOutput>` alive, which is
    // why both are returned together.
    let linear = unsafe { LinearFramebuffer::new(fb.as_mut_ptr(), width as u32, height as u32, stride as u32, layout) };

    Ok((gop, linear))
}

/// Best-effort device-path display string for `handle` (SPEC §11.4:
/// "Display ... device path before generation"). Returns
/// [`DevicePathText::unavailable`] rather than an error if the
/// `DevicePathToText` protocol is missing or the handle has no device
/// path — the confirmation screen must still show something rather than
/// failing generation over a diagnostic-only string.
#[must_use]
pub fn device_path_text(handle: uefi::Handle) -> DevicePathText {
    let Ok(dp) = open_shared::<DevicePath>(handle) else {
        return DevicePathText::unavailable();
    };
    let Ok(dp2t_handle) = boot::get_handle_for_protocol::<DevicePathToText>() else {
        return DevicePathText::unavailable();
    };
    let Ok(dp2t) = open_shared::<DevicePathToText>(dp2t_handle) else {
        return DevicePathText::unavailable();
    };
    match dp2t.convert_device_path_to_text(&dp, DisplayOnly(true), AllowShortcuts(true)) {
        Ok(text) => ascii_from_utf16(text.as_slice().iter().map(|&c| u16::from(c))),
        Err(_) => DevicePathText::unavailable(),
    }
}
