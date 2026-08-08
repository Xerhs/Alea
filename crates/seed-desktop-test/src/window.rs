//! The real desktop window (SPEC §4.3): `winit` for the OS window +
//! keyboard events, `softbuffer` for presenting pixels, both added to
//! *this* crate's `Cargo.toml` only (never to `seed-flow`/`seed-gop-ui`/
//! any shared crate — see this crate's own `Cargo.toml` doc comment).
//!
//! # Why this module is never reachable from `cargo test` or `check`
//!
//! [`run`] is called from exactly one place: `main()`'s default (no
//! subcommand) branch. `crate::check::run` and every `#[cfg(test)]` test
//! in this crate call into `crate::ceremony`/`crate::pipeline`/
//! `crate::vectors`/`crate::fixed_entropy` directly and never reference
//! this module at all — so a host with no display server (this sandbox
//! included) can `cargo build`/`cargo test`/`cargo run -- check` this
//! crate successfully; only actually launching the GUI (`cargo run` with
//! no arguments, on a machine with a real display) exercises this file's
//! `EventLoop::run` call. The DoD for this module is therefore "compiles
//! cleanly", not "runs headless" (this sandbox has no display server —
//! `which qemu-system-x86_64`-style detection doesn't apply here since
//! this is a native desktop window, not a QEMU boot; there is simply no
//! way to open a window at all in this environment).
//!
//! # Threading model
//!
//! `crate::ceremony::run` blocks synchronously key-by-key for the
//! duration of the whole rehearsal (mirroring every `seed-flow` provider
//! trait's own blocking contract) and must not run on the same thread as
//! `winit`'s event loop (which owns the window and must keep pumping
//! events to stay responsive and to actually deliver those keystrokes in
//! the first place). So: the main thread owns the `winit`
//! `EventLoop`/`Window`/`softbuffer` `Surface` and does nothing but (a)
//! forward keyboard events into an `mpsc` channel and (b) copy the
//! shared pixel buffer onto the surface and present it, every tick
//! (`ControlFlow::Poll`); a second, spawned thread runs the entire
//! ceremony against a [`crate::shared_screen::SharedFramebuffer`] handle
//! and the receiving half of that same channel. The two threads share
//! pixels only through that `Arc<Mutex<..>>`-backed handle — see
//! `crate::shared_screen`'s own doc comment.
//!
//! # The permanent SPEC §4.3 watermark
//!
//! [`present_frame`] draws the two watermark bands directly onto the
//! surface buffer *after* copying the ceremony's own canvas into it,
//! every single tick — never into the shared canvas the ceremony code
//! writes to. This guarantees the watermark survives every
//! `scrub_fill`/`clear()` any reused `seed-flow` screen performs (none of
//! that code needs to know the watermark exists at all) and is present
//! on literally every frame ever displayed, satisfying "visible on every
//! screen, unmissable" without touching a single line of reused
//! `seed-flow` rendering code.

use std::num::NonZeroU32;
use std::sync::mpsc;
use std::thread;

use softbuffer::{Context, Surface};
use winit::event::{ElementState, Event as WinitEvent, KeyEvent, WindowEvent};
use winit::event_loop::{ControlFlow, EventLoop};
use winit::keyboard::{Key, NamedKey};
use winit::window::{Window, WindowBuilder};

use seed_core::contracts::{Framebuffer, Style};

use crate::channel_keys::KeyMsg;
use crate::launcher;
use crate::shared_screen::{SharedFramebuffer, CANVAS_HEIGHT, CANVAS_WIDTH};

/// SPEC §4.3 permanent watermark band height (pixels), reserved above and
/// below the ceremony's own logical canvas so no reused `seed-flow`
/// screen can ever draw over it (see module doc comment).
const WATERMARK_BAND_HEIGHT: u32 = seed_gop_ui::font::GLYPH_HEIGHT * 2 + 8;

/// SPEC §4.3: "Display a permanent watermark stating that generated
/// phrases are public and unsafe." Reuses the exact SPEC §4.2 test-edition
/// wording for brand/message consistency across editions (SPEC §4.3 does
/// not mandate a specific string for the desktop edition, only that one
/// exist and be permanent).
const WATERMARK_TOP: &str = "ALEA TEST (DESKTOP) -- PUBLIC TEST PHRASE, NEVER USE WITH FUNDS";
/// SPEC §4.3 on-screen clarity requirement (task brief): make the fixed-
/// entropy substitution unmissable on every single screen, not just the
/// dedicated rehearsal-notice screen `crate::ceremony` shows once per
/// physical-entry attempt.
const WATERMARK_BOTTOM: &str = "Every phrase here comes from a FIXED PUBLIC test transcript -- your keys never change it.";

const WATERMARK_STYLE: Style = seed_gop_ui::theme::WATERMARK;

/// Launch the real OS window and run the ceremony on a background thread.
/// Never returns while the window stays open; returns once the user
/// closes the window (`WindowEvent::CloseRequested`).
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let event_loop = EventLoop::new()?;

    let window_width = CANVAS_WIDTH;
    let window_height = CANVAS_HEIGHT + WATERMARK_BAND_HEIGHT * 2;

    let window = WindowBuilder::new()
        .with_title("Alea Test (desktop rehearsal)")
        .with_inner_size(winit::dpi::LogicalSize::new(window_width as f64, window_height as f64))
        .with_resizable(false)
        .build(&event_loop)?;

    let context = Context::new(&window)?;
    let mut surface = Surface::new(&context, &window)?;
    surface.resize(NonZeroU32::new(window_width).expect("nonzero"), NonZeroU32::new(window_height).expect("nonzero"))?;

    let fb = SharedFramebuffer::new(CANVAS_WIDTH, CANVAS_HEIGHT);
    let (tx, rx) = mpsc::channel::<KeyMsg>();

    {
        let worker_fb = fb.clone();
        thread::Builder::new()
            .name("seed-desktop-test-ceremony".to_string())
            .spawn(move || {
                // SPEC_MAIN_MENU.md §6.2: the worker thread now starts in
                // the landing menu (`crate::launcher`) instead of jumping
                // straight into the rehearsal ceremony; item (1) on that
                // menu still routes to `crate::ceremony::run`.
                launcher::run(worker_fb, rx, CANVAS_WIDTH, CANVAS_HEIGHT);
            })
            .expect("failed to spawn ceremony worker thread");
    }

    event_loop.set_control_flow(ControlFlow::Poll);
    event_loop.run(move |event, elwt| match event {
        WinitEvent::WindowEvent { event: WindowEvent::CloseRequested, .. } => {
            elwt.exit();
        }
        WinitEvent::WindowEvent {
            event:
                WindowEvent::KeyboardInput {
                    event: KeyEvent { state: ElementState::Pressed, logical_key, text, .. },
                    ..
                },
            ..
        } => {
            if let Some(msg) = translate_key(&logical_key, text.as_deref()) {
                // Best-effort: once the ceremony worker thread has ended
                // (idle-looping post-shutdown), the receiver is still
                // alive (it never drops until the process exits), so
                // this send essentially always succeeds; a closed
                // channel is ignored rather than panicking.
                let _ = tx.send(msg);
            }
        }
        WinitEvent::AboutToWait => {
            present_frame(&fb, &mut surface, window_width, window_height);
        }
        _ => {}
    })?;

    Ok(())
}

/// Smooth keyboard mapping (task brief): 1-6, H/T, A-Z, Enter, Backspace,
/// Esc all map onto exactly the [`KeyMsg`] variants every `seed-flow`
/// screen already understands; anything else becomes [`KeyMsg::Other`],
/// which every menu/hidden-entry read loop in this ceremony already
/// ignores.
///
/// `ArrowUp`/`ArrowDown` map onto [`KeyMsg::Up`]/[`KeyMsg::Down`]
/// (SPEC_MAIN_MENU.md §4.2, §6.3, OQ2 — resolved §15: desktop-local arrow
/// navigation for `crate::launcher` only). This is the one desktop-local
/// extension of the smooth key mapping; every other arrow/function/
/// modifier-only key still falls through to [`KeyMsg::Other`] exactly as
/// before, and the shared `seed_platform_x86::input::InputEvent` enum is
/// untouched (`crate::channel_keys::ChannelKeys`'s `KeySource` impl folds
/// `Up`/`Down` back into `InputEvent::Other` for every arrow-unaware
/// `seed-flow` consumer — see that module's doc comment).
fn translate_key(logical_key: &Key, text: Option<&str>) -> Option<KeyMsg> {
    match logical_key {
        Key::Named(NamedKey::Enter) => Some(KeyMsg::Enter),
        Key::Named(NamedKey::Escape) => Some(KeyMsg::Escape),
        Key::Named(NamedKey::Backspace) => Some(KeyMsg::Backspace),
        Key::Named(NamedKey::ArrowUp) => Some(KeyMsg::Up),
        Key::Named(NamedKey::ArrowDown) => Some(KeyMsg::Down),
        Key::Character(s) => s.chars().next().map(KeyMsg::Char),
        _ => match text.and_then(|t| t.chars().next()) {
            Some(c) => Some(KeyMsg::Char(c)),
            None => Some(KeyMsg::Other),
        },
    }
}

/// Composite one frame: fill both watermark bands, copy the ceremony's
/// shared canvas into the middle, redraw the watermark *text* on top
/// (never onto the shared canvas — see module doc comment), then
/// present.
///
/// Takes the `softbuffer` `Surface` only to obtain its `Buffer` and
/// immediately reborrows that as a plain `&mut [u32]` for every helper
/// below — this sidesteps threading `softbuffer`'s own `D`/`W` generic
/// parameters (and their lifetime, invariant under `&mut`) through any
/// function signature in this module.
fn present_frame(fb: &SharedFramebuffer, surface: &mut Surface<&Window, &Window>, width: u32, height: u32) {
    let Ok(mut buffer) = surface.buffer_mut() else { return };
    let canvas = fb.snapshot();

    fill_rows(&mut buffer, width, 0, WATERMARK_BAND_HEIGHT, WATERMARK_STYLE.bg);

    let canvas_h = height.saturating_sub(WATERMARK_BAND_HEIGHT * 2).min(CANVAS_HEIGHT);
    let copy_w = core::cmp::min(CANVAS_WIDTH, width) as usize;
    for y in 0..canvas_h {
        let dst_y = y + WATERMARK_BAND_HEIGHT;
        let src_start = (y as usize) * (CANVAS_WIDTH as usize);
        let dst_start = (dst_y as usize) * (width as usize);
        buffer[dst_start..dst_start + copy_w].copy_from_slice(&canvas[src_start..src_start + copy_w]);
    }

    let bottom_y = height.saturating_sub(WATERMARK_BAND_HEIGHT);
    fill_rows(&mut buffer, width, bottom_y, WATERMARK_BAND_HEIGHT, WATERMARK_STYLE.bg);

    {
        let mut top_row = BandRow { pixels: &mut buffer, width, y_offset: 8 };
        seed_gop_ui::font::draw_text(&mut top_row, seed_gop_ui::font::GLYPH_WIDTH, 0, WATERMARK_TOP, WATERMARK_STYLE);
    }
    {
        let mut bottom_row = BandRow { pixels: &mut buffer, width, y_offset: bottom_y + 8 };
        seed_gop_ui::font::draw_text(&mut bottom_row, seed_gop_ui::font::GLYPH_WIDTH, 0, WATERMARK_BOTTOM, WATERMARK_STYLE);
    }

    let _ = buffer.present();
}

fn fill_rows(pixels: &mut [u32], width: u32, y0: u32, band_h: u32, color: u32) {
    for y in y0..y0 + band_h {
        let start = (y as usize) * (width as usize);
        let end = start + width as usize;
        if end > pixels.len() {
            break;
        }
        for px in &mut pixels[start..end] {
            *px = color;
        }
    }
}

/// Adapter so `seed_gop_ui::font::draw_text` (which only knows about
/// `seed_core::contracts::Framebuffer`) can draw directly into a plain
/// `&mut [u32]` presentation-buffer slice at a fixed `y_offset`, without
/// this module needing its own glyph-rendering code for the watermark
/// bands.
struct BandRow<'a> {
    pixels: &'a mut [u32],
    width: u32,
    y_offset: u32,
}

impl Framebuffer for BandRow<'_> {
    fn dims(&self) -> (u32, u32) {
        (self.width, WATERMARK_BAND_HEIGHT)
    }

    fn put_row(&mut self, x: u32, y: u32, px: &[u32]) {
        let dst_y = self.y_offset + y;
        let start = (dst_y as usize) * (self.width as usize) + (x as usize);
        let n = core::cmp::min(px.len(), self.width.saturating_sub(x) as usize);
        if n == 0 || start + n > self.pixels.len() {
            return;
        }
        self.pixels[start..start + n].copy_from_slice(&px[..n]);
    }
}
