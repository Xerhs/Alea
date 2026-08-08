//! SPEC_MAIN_MENU.md §17 (2026-08-07 amendment): the production UEFI
//! landing launcher.
//!
//! Read with **number-key + Esc only** (§17.2 input discipline — the
//! desktop launcher's arrow navigation is deliberately NOT ported, only
//! its item *set* is). Strictly pre-secret (§17.2): this screen is shown
//! once at boot, before any mandatory gate or secret exists, and only the
//! `Generate` choice falls through into the unchanged SPEC §11/§21/§22
//! flow.
//!
//! # Rendering (Task 19: launcher restyle onto the shared visual system)
//!
//! Every screen here draws directly on the session
//! [`seed_core::contracts::Framebuffer`] (never a long-lived
//! `TextOutput` held across the whole landing loop): a full
//! [`seed_gop_ui::font::scrub_fill`], then
//! [`seed_flow::chrome::draw_header_plain`] (no ceremony stage rail —
//! stages begin at Generate, §17.3/design doc §5), then this screen's own
//! content through a fresh, LOCALLY-scoped
//! [`seed_flow::output::FbTextOutput::at`] positioned at
//! [`seed_flow::chrome::content_top`], then
//! [`seed_flow::chrome::draw_footer`] with this screen's real key hints
//! (the *only* place key hints live, design doc §3.3) — the same
//! "clear, redraw chrome, fresh content cursor" sequence
//! `FbTextOutput::at`'s own doc comment describes. A caller-owned
//! `FbTextOutput` is deliberately never reused across two different
//! screens/frames: each render function below constructs its own,
//! scoped to just its content block, so the chrome bands it draws before
//! and after are never clobbered by a stray `clear()`.
//!
//! Alloc-free (the crate is `#![no_std]`, UEFI target): every fixed row is
//! a `&'static str`, and the few places a runtime value is interpolated —
//! the About release/build lines, the Self-check PASS/FAIL rows, and the
//! Learn position counter — are built through a stack
//! [`seed_flow::output::LineBuf`] (`core::fmt::Write`), never
//! `format!`/`String` (SPEC §13: fixed buffers, no `alloc`), mirroring
//! `crates/seed-flow/src/flow_secret/composition.rs`'s `write_line_fmt`.

use core::fmt::Write as _;

use seed_core::contracts::Framebuffer;
use seed_flow::chrome::{self, KeyHint};
use seed_flow::keys::{read_menu_choice, MenuChoice, MenuKeySource};
use seed_flow::output::{FbTextOutput, LineBuf, TextOutput};
use seed_flow::text::{wrap_words, PROSE_WRAP_COLS};
use seed_gop_ui::font::scrub_fill;

use crate::{markers, release};

/// Clear `fb` and draw the shared "plain" header band (no stage rail,
/// design doc §5) with `title` on the left and this build's identifier
/// on the right — the first step of every screen in this module (see
/// the module doc comment's rendering section).
fn begin_screen(fb: &mut dyn Framebuffer, title: &str) {
    scrub_fill(fb, 0);
    chrome::draw_header_plain(fb, title, release::BUILD_ID);
}

/// A single `[Esc] Return to the menu` footer — every read-only
/// informational screen in this module (Learn's per-category pages
/// excepted, which additionally offer `[1-9] Next`) ends this way.
const RETURN_HINT: [KeyHint; 1] = [KeyHint { key: "Esc", label: "Return to the menu", enabled: true, danger: false }];

/// One landing-menu selection (SPEC_MAIN_MENU.md §17.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LandingChoice {
    /// Item 1 — fall through into the unchanged pre-secret gate flow.
    Generate,
    /// Item 2 — chain-load the separate `alea-verify.efi` (§17.4).
    Verify,
    /// Item 3 — read-only safety/education screens.
    Learn,
    /// Item 4 — surface the SPEC §11.6 crypto KAT result.
    SelfCheck,
    /// Item 5 — version / build-id / audit status.
    About,
    /// Item 6 / Esc — exit to firmware (legal only pre-secret, §22.1).
    Exit,
}

const TITLE: &str = "ALEA UEFI  --  offline recovery-phrase generator  (production)";
const ITEM_1: &str = "  [1] Generate a recovery phrase";
const ITEM_2: &str = "  [2] Verify a seed from another device   (loads the separate verifier)";
const ITEM_3: &str = "  [3] Learn  (safety & how the ceremony works)";
const ITEM_4: &str = "  [4] Self-check  (this build's cryptographic self-test)";
const ITEM_5: &str = "  [5] About / audit status";
const ITEM_6: &str = "  [6] Exit  (power off / return to firmware)";

/// The landing screen's footer key hints (design doc §3.3: key hints are
/// numbers here, §17.2 -- no arrows, no per-item highlight state to mark
/// `ACCENT`, since this menu is read purely by digit, unlike the desktop
/// edition's arrow-navigated menu).
const LANDING_HINTS: [KeyHint; 2] = [
    KeyHint { key: "1-6", label: "Select", enabled: true, danger: false },
    KeyHint { key: "Esc", label: "Exit", enabled: true, danger: false },
];

/// Render the landing screen (SPEC_MAIN_MENU.md §17.3) on `fb`.
pub fn render_landing(fb: &mut dyn Framebuffer) {
    begin_screen(fb, TITLE);
    {
        let mut out = FbTextOutput::at(fb, chrome::content_top());
        out.write_line(release::RELEASE_VERSION);
        out.write_line("");
        out.write_line(ITEM_1);
        out.write_line(ITEM_2);
        out.write_line(ITEM_3);
        out.write_line(ITEM_4);
        out.write_line(ITEM_5);
        out.write_line(ITEM_6);
    }
    chrome::draw_footer(fb, &LANDING_HINTS);
}

/// Render the landing screen and block for a valid choice
/// (SPEC_MAIN_MENU.md §17.3). Esc maps to [`LandingChoice::Exit`].
pub fn read_landing_choice(fb: &mut dyn Framebuffer, keys: &mut dyn MenuKeySource) -> LandingChoice {
    render_landing(fb);
    match read_menu_choice(keys, &['1', '2', '3', '4', '5', '6'], true) {
        MenuChoice::Picked('1') => LandingChoice::Generate,
        MenuChoice::Picked('2') => LandingChoice::Verify,
        MenuChoice::Picked('3') => LandingChoice::Learn,
        MenuChoice::Picked('4') => LandingChoice::SelfCheck,
        MenuChoice::Picked('5') => LandingChoice::About,
        // Item 6, Escape, and (unreachable) any other char all exit.
        MenuChoice::Picked(_) | MenuChoice::Escape => LandingChoice::Exit,
    }
}

// ============================================================================
// SPEC_MAIN_MENU.md §17.3 item 3 (Learn): the read-only, category-landing
// education screen (design doc §5: "category landing (Topics / Features /
// Technical), 'page 3/12' counters"). Category/page content + the
// backend-neutral per-page emitters live in the shared `seed_flow::edu`
// module (host-testable, allocation-free); this function owns only the
// production launcher's chrome, the interpolated position counter, and
// the number-key/Esc navigation (§17.2 input discipline -- no arrows, no
// Enter) at both the category-landing and per-page level.
// ============================================================================

/// The category-landing screen's footer key hints.
const LEARN_LANDING_HINTS: [KeyHint; 2] = [
    KeyHint { key: "1-3", label: "Select a category", enabled: true, danger: false },
    KeyHint { key: "Esc", label: "Return to the menu", enabled: true, danger: false },
];

/// A category's own page-reader footer key hints: any digit advances one
/// page (§17.2 number-key discipline, matching the flat reader this
/// replaces), Esc returns to the category landing (NOT the top-level
/// launcher menu -- that is now one level further back, reachable by
/// pressing Esc again from the landing).
const LEARN_PAGE_HINTS: [KeyHint; 2] = [
    KeyHint { key: "1-9", label: "Next page", enabled: true, danger: false },
    KeyHint { key: "Esc", label: "Back to categories", enabled: true, danger: false },
];

/// One navigation decision on the category-landing screen. Number-key +
/// Esc only (SPEC_MAIN_MENU.md §17.2): `CATEGORIES` is always exactly the
/// three `seed_flow::edu::Category` variants, so `[1]`/`[2]`/`[3]` map
/// directly to them.
enum LearnCategoryNav {
    /// A category was picked.
    Chosen(seed_flow::edu::Category),
    /// Esc was pressed: return to the top-level landing menu.
    Return,
}

/// Block for a category-landing key through the sanctioned
/// [`read_menu_choice`] seam. `read_menu_choice` only ever surfaces
/// `Picked`/`Escape` and silently ignores every other key, so no
/// non-listed key can leak a navigation action.
fn read_learn_category_nav(keys: &mut dyn MenuKeySource) -> LearnCategoryNav {
    match read_menu_choice(keys, &['1', '2', '3'], true) {
        MenuChoice::Picked('1') => LearnCategoryNav::Chosen(seed_flow::edu::Category::Topics),
        MenuChoice::Picked('2') => LearnCategoryNav::Chosen(seed_flow::edu::Category::Features),
        MenuChoice::Picked('3') => LearnCategoryNav::Chosen(seed_flow::edu::Category::Technical),
        MenuChoice::Picked(_) | MenuChoice::Escape => LearnCategoryNav::Return,
    }
}

/// One navigation decision on a page within an open category. Number-key
/// + Esc only (SPEC_MAIN_MENU.md §17.2): no arrows, no per-page "back" --
/// Esc returns to the category landing, exactly as the composition panel
/// and every other read-only screen here return to their own caller.
enum LearnPageNav {
    /// A number key was pressed: advance to the next page.
    Next,
    /// Esc was pressed: return to the category landing.
    Return,
}

/// Block for a page-navigation key -- same digit/Esc shape as
/// [`read_learn_category_nav`], see that function's own doc comment.
fn read_learn_page_nav(keys: &mut dyn MenuKeySource) -> LearnPageNav {
    match read_menu_choice(
        keys,
        &['1', '2', '3', '4', '5', '6', '7', '8', '9', '0'],
        true,
    ) {
        MenuChoice::Picked(_) => LearnPageNav::Next,
        MenuChoice::Escape => LearnPageNav::Return,
    }
}

/// Emit the Learn position counter (`Page N/M`) via [`LineBuf`] +
/// `core::fmt::Write` -- alloc-free (no `format!`/`String` in this
/// `#![no_std]`, no-`alloc` crate). The `[1-9] Next`/`[Esc] ...` controls
/// this line used to carry now live in the real footer key bar
/// ([`LEARN_PAGE_HINTS`]) instead of this content line, design doc §3.3:
/// "the *only* place key hints live".
fn write_learn_page_counter(out: &mut dyn TextOutput, page_1based: usize, total: usize) {
    let mut buf = LineBuf::new();
    let _ = write!(buf, "Page {page_1based}/{total}");
    out.write_line(buf.as_str());
}

/// SPEC_MAIN_MENU.md §17.3 item 3: render the category-landing screen and
/// loop until the user returns to the top-level landing menu.
///
/// Two navigation levels (§17.2 number-key + Esc, no arrows, no Enter, at
/// either level): `[1]`/`[2]`/`[3]` on the landing opens a category (see
/// [`render_learn_category`]); Esc on the landing returns to the
/// top-level launcher menu (this function returns). Each screen is fully
/// redrawn (`begin_screen`'s `scrub_fill` + chrome) before rendering, so
/// no stale frame content survives a level change.
pub fn render_learn(fb: &mut dyn Framebuffer, keys: &mut dyn MenuKeySource) {
    loop {
        begin_screen(fb, "ALEA -- Learn");
        {
            let mut out = FbTextOutput::at(fb, chrome::content_top());
            seed_flow::edu::render_category_landing(&mut out);
        }
        chrome::draw_footer(fb, &LEARN_LANDING_HINTS);
        match read_learn_category_nav(keys) {
            LearnCategoryNav::Return => return,
            LearnCategoryNav::Chosen(category) => render_learn_category(fb, keys, category),
        }
    }
}

/// Page through one open `category` (see [`render_learn`]) and return to
/// the category landing once the user backs out or advances past the
/// last page.
///
/// Forward-only reader (§17.2 number-key + Esc, no arrows, no Enter): a
/// number key advances one page; advancing past the last page returns to
/// the landing (natural completion); Esc returns to the landing from any
/// page. Every page fits the SPEC §11.4 800x600 floor as a single screen
/// -- no in-page scrolling (pinned by `seed_flow::edu`'s own fit-audit
/// tests).
fn render_learn_category(fb: &mut dyn Framebuffer, keys: &mut dyn MenuKeySource, category: seed_flow::edu::Category) {
    let total = seed_flow::edu::category_page_count(category);
    if total == 0 {
        return;
    }
    let mut index = 0usize;
    loop {
        begin_screen(fb, category.label());
        {
            let mut out = FbTextOutput::at(fb, chrome::content_top());
            seed_flow::edu::render_category_page(&mut out, category, index);
            out.write_line("");
            write_learn_page_counter(&mut out, index + 1, total);
        }
        chrome::draw_footer(fb, &LEARN_PAGE_HINTS);
        match read_learn_page_nav(keys) {
            LearnPageNav::Return => return,
            LearnPageNav::Next => {
                if index + 1 < total {
                    index += 1;
                } else {
                    // Advancing past the final page completes the read and
                    // returns to the category landing.
                    return;
                }
            }
        }
    }
}

// ============================================================================
// Item 4 — Self-check (SPEC_MAIN_MENU.md §17.3 item 4; SPEC §11.6)
// ============================================================================

const SELFCHECK_TITLE: &str = "SELF-CHECK  --  SPEC §11.6 cryptographic known-answer self-test";
const SELFCHECK_OK: &str = "  RESULT:  PASS  --  all cryptographic self-tests matched.";
const SELFCHECK_FAIL: &str =
    "  RESULT:  FAIL  --  a self-test did not match; generation is disabled.";

// One fixed label per SPEC §11.6 bullet, in the spec's own listed order —
// mirroring `seed_selftest::AggregateSelfTestReport`'s field order.
const B1: &str = "SHA-256 known-answer test";
const B2: &str = "SHA-512 / HMAC-SHA512 known-answer tests";
const B3: &str = "PBKDF2 known-answer test";
const B4: &str = "secp256k1 public-key derivation";
const B5: &str = "RIPEMD-160 / Base58Check / Bech32(m)";
const B6: &str = "BIP39 12-word and 24-word";
const B7: &str = "BIP32 derivation";
const B8: &str = "entropy-transcript test";
const B9: &str = "dice and coin session test";
const B10: &str = "wordlist integrity";
const B11: &str = "fixed-buffer bounds";
const B12: &str = "state-machine invariants";
const B13: &str = "production-build policy marker";

// SPEC §5.3: this screen surfaces ONLY the built-in known-answer result —
// it never reproduces the foreign/reference vectors those tests compare
// against.
const SELFCHECK_NOTE_1: &str =
    "  This surfaces only whether this build's built-in self-tests matched.";
const SELFCHECK_NOTE_2: &str =
    "  No reference/expected values are displayed (SPEC §5.3).";

/// Item 4 (SPEC_MAIN_MENU.md §17.3): run the SPEC §11.6 aggregate
/// cryptographic known-answer self-test *now* and display a PASS/FAIL
/// summary, returning to the landing loop on Esc.
///
/// The KAT is invoked directly — [`seed_selftest::run_aggregate_self_test`],
/// the exact same entry point
/// `seed_flow::firmware_wiring::ProdCryptoSelfTestGate` drives for the
/// mandatory startup gate — threaded with this edition's own
/// [`crate::flow_pre::PRODUCTION_MARKER`] so bullet 13 (the SPEC §28
/// production-build policy marker) reflects the real production claim, not a
/// vacuous pass. Every bullet is surfaced individually so a `FAIL` names
/// which primitive regressed. Alloc-free: the fixed rows are `&'static str`
/// and the per-bullet rows are built through [`LineBuf`] (no `alloc`).
pub fn render_selfcheck(fb: &mut dyn Framebuffer, keys: &mut dyn MenuKeySource) {
    // Run the full thirteen-bullet SPEC §11.6 self-test once, with this
    // edition's production policy marker (bullet 13).
    let report = seed_selftest::run_aggregate_self_test(crate::flow_pre::PRODUCTION_MARKER);

    begin_screen(fb, SELFCHECK_TITLE);
    {
        let mut out = FbTextOutput::at(fb, chrome::content_top());
        if report.all_clean() {
            out.write_line(SELFCHECK_OK);
        } else {
            out.write_line(SELFCHECK_FAIL);
        }
        out.write_line("");

        write_check_row(&mut out, report.sha256_kat, B1);
        write_check_row(&mut out, report.sha512_hmac_sha512_kat, B2);
        write_check_row(&mut out, report.pbkdf2_kat, B3);
        write_check_row(&mut out, report.secp256k1_kat, B4);
        write_check_row(&mut out, report.ripemd160_base58check_bech32_kat, B5);
        write_check_row(&mut out, report.bip39_kat, B6);
        write_check_row(&mut out, report.bip32_kat, B7);
        write_check_row(&mut out, report.entropy_transcript_kat, B8);
        write_check_row(&mut out, report.dice_coin_session_kat, B9);
        write_check_row(&mut out, report.wordlist_integrity, B10);
        write_check_row(&mut out, report.fixed_buffer_bounds_kat, B11);
        write_check_row(&mut out, report.state_machine_invariant_kat, B12);
        write_check_row(&mut out, report.production_build_policy_marker, B13);

        out.write_line("");
        out.write_line(SELFCHECK_NOTE_1);
        out.write_line(SELFCHECK_NOTE_2);
    }
    chrome::draw_footer(fb, &RETURN_HINT);
    // Only Esc returns; every other key is ignored (no listed choices) —
    // the §17.2 read discipline shared by every read-only screen here.
    let _ = read_menu_choice(keys, &[], true);
}

/// Write one `  [PASS] <label>` / `  [FAIL] <label>` self-check row through
/// `out`, built without `alloc` via [`LineBuf`] (the
/// `flow_secret::composition::write_line_fmt` idiom). `LINE_CAPACITY`
/// (160) far exceeds any label above, so truncation never occurs here.
fn write_check_row(out: &mut dyn TextOutput, ok: bool, label: &str) {
    let mut line = LineBuf::new();
    let _ = write!(line, "  [{}] {}", if ok { "PASS" } else { "FAIL" }, label);
    out.write_line(line.as_str());
}

// ============================================================================
// SPEC_MAIN_MENU.md §17.3 item (5) — About / audit-status.
// ============================================================================
//
// Unlike the desktop edition's About screen
// (`seed-desktop-test/src/launcher/about.rs`), production is UNwatermarked
// (SPEC §4.1): there is no permanent on-screen watermark, so its
// "what the watermark means (SPEC §4.3)" paragraph is deliberately NOT
// ported here. In its place this screen carries the SPEC §2
// "EXPERIMENTAL -- not externally audited" honesty line, so an operator
// who opens About mid-ceremony sees the same stable-release caveat the
// boot banner (`crate::print_banner`) already showed.

const ABOUT_TITLE: &str = "ABOUT / AUDIT STATUS";
const ABOUT_EDITION: &str = "Alea -- production UEFI edition (unwatermarked)";
/// Reflects [`markers::self_check`] (SPEC §28 / §22.3) — an actual
/// runtime comparison of the compiled-in production marker, not an
/// unconditional claim.
const ABOUT_MARKER_OK: &str = "Edition marker:    verified";
const ABOUT_MARKER_BAD: &str = "Edition marker:    NOT VERIFIED -- build integrity check failed";
/// SPEC §2 experimental-software honesty, plus the "not externally
/// audited" fact the boot banner does not state. Prose — word-wrapped
/// through [`wrap_words`] at [`PROSE_WRAP_COLS`], exactly like
/// `crate::print_banner`'s banner body, so it never clips the right edge
/// of the 800x600 GOP floor.
const ABOUT_HONESTY: &str = "EXPERIMENTAL -- not externally audited. This build has not completed the \
stable-release security gates (SPEC section 2). Do not use it to protect \
substantial funds.";
const ABOUT_DOCS_HEADING: &str = "Audit and reproducibility documents:";
const ABOUT_DOC_REPRODUCING_1: &str = "  REPRODUCING.md -- rebuild this binary and compare it bit-for-bit";
const ABOUT_DOC_REPRODUCING_2: &str = "    against a published release.";
const ABOUT_DOC_SECURITY_1: &str = "  SECURITY.md -- the security model, threat boundaries, and how to";
const ABOUT_DOC_SECURITY_2: &str = "    report a finding.";
const ABOUT_DOC_SPEC_1: &str = "  SPEC.md section 28 -- the isolation rules this edition is built";
const ABOUT_DOC_SPEC_2: &str = "    under, and the binary-policy scanner that enforces them.";

/// Build one display line as `label` immediately followed by `value`
/// (both always non-secret) through a fixed stack [`LineBuf`] — the
/// crate's alloc-free interpolation idiom (mirrors
/// `seed_flow::flow_secret::composition`'s own `write_line_fmt`). No
/// `format!`, no `String`.
fn write_labeled(out: &mut dyn TextOutput, label: &str, value: &str) {
    let mut line = LineBuf::new();
    let _ = line.write_str(label);
    let _ = line.write_str(value);
    out.write_line(line.as_str());
}

/// Render the About / audit-status screen (SPEC_MAIN_MENU.md §17.3 item
/// 5) through `out` and block until Esc returns to the landing loop.
///
/// Shows the SPEC §4.1 release version + immutable build identifier
/// (reused here pre-secret from [`release`]), the edition string, the
/// SPEC §28 edition-marker self-check ([`markers::self_check`]), the SPEC
/// §2 "EXPERIMENTAL -- not externally audited" honesty line, and pointers
/// to the audit / reproducibility docs. Production is UNwatermarked, so
/// no watermark-meaning paragraph is rendered (see the section comment
/// above). Read-only, no secret, no network (SPEC §25). Alloc-free.
pub fn render_about(fb: &mut dyn Framebuffer, keys: &mut dyn MenuKeySource) {
    begin_screen(fb, ABOUT_TITLE);
    {
        let mut out = FbTextOutput::at(fb, chrome::content_top());
        out.write_line(ABOUT_EDITION);
        write_labeled(&mut out, "Release version:   ", release::RELEASE_VERSION);
        write_labeled(&mut out, "Build identifier:  ", release::BUILD_ID);
        out.write_line(if markers::self_check() {
            ABOUT_MARKER_OK
        } else {
            ABOUT_MARKER_BAD
        });
        out.write_line("");
        for line in wrap_words(ABOUT_HONESTY, PROSE_WRAP_COLS) {
            out.write_line(line);
        }
        out.write_line("");
        out.write_line(ABOUT_DOCS_HEADING);
        out.write_line(ABOUT_DOC_REPRODUCING_1);
        out.write_line(ABOUT_DOC_REPRODUCING_2);
        out.write_line(ABOUT_DOC_SECURITY_1);
        out.write_line(ABOUT_DOC_SECURITY_2);
        out.write_line(ABOUT_DOC_SPEC_1);
        out.write_line(ABOUT_DOC_SPEC_2);
    }
    chrome::draw_footer(fb, &RETURN_HINT);
    // Only Esc returns; every other key is ignored (no listed choices) —
    // the §17.2 return discipline shared by every read-only screen here.
    let _ = read_menu_choice(keys, &[], true);
}

// ============================================================================
// Item 2 — chain-load the separate `alea-verify.efi` (SPEC_MAIN_MENU.md §17.4)
// ============================================================================

/// Operator-facing failure title (both targets).
const CHAIN_ERR_TITLE: &str = "VERIFY -- could not start the separate verifier";
const CHAIN_ERR_HINT_1: &str = "The verifier (\\EFI\\ALEA\\VERIFY.EFI) may be missing from this";
const CHAIN_ERR_HINT_2: &str = "boot medium, or the firmware declined to load it.";

/// Host-build reason (the UEFI target is the only one that can chain-load).
#[cfg(not(target_os = "uefi"))]
const CHAIN_ERR_HOST: &str = "reason: chain-loading is only available on the UEFI target.";

/// Item 2 — chain-load the separate `alea-verify.efi` (SPEC_MAIN_MENU.md
/// §17.4).
///
/// Reaches the verifier exactly as §17.4 mandates: it derives the full
/// device path of `\EFI\ALEA\VERIFY.EFI` on the SAME EFI System Partition
/// this production image booted from, then calls [`uefi::boot::load_image`]
/// with a **device-path** source ([`uefi::boot::LoadImageSource::FromDevicePath`])
/// so *firmware* performs the file I/O — the launcher never opens
/// `EFI_SIMPLE_FILE_SYSTEM_PROTOCOL`, keeping the SPEC §29.6
/// forbidden-interface leakage test
/// (`tests/leakage/tests/forbidden_uefi_interfaces.rs`) green — and then
/// [`uefi::boot::start_image`]. On the verifier's return (or on any
/// failure) control comes back here and then to the landing loop, matching
/// §17.3 item 2 ("on its return, control comes back to this landing
/// screen").
///
/// Allocation-free: the composed device path is built into a fixed stack
/// buffer via `DevicePathBuilder::with_buf` (no `alloc`), and every
/// operator-facing line is a fixed `&'static str`.
pub fn chain_load_verify(fb: &mut dyn Framebuffer, keys: &mut dyn MenuKeySource) {
    #[cfg(target_os = "uefi")]
    {
        render_loading_verifier(fb);
        if let Err(reason) = try_chain_load_verify() {
            render_chain_load_error(fb, keys, reason);
        }
        // On success the verifier ran in its own image and has since
        // exited; simply return to the landing loop.
    }
    #[cfg(not(target_os = "uefi"))]
    {
        // Host builds have no firmware boot services to chain-load
        // through; only the UEFI target ever reaches a real verifier.
        render_chain_load_error(fb, keys, CHAIN_ERR_HOST);
    }
}

/// Render the failure screen and block until Esc returns to the menu.
/// Present on both targets (uses only the `Framebuffer`/keys seam).
fn render_chain_load_error(fb: &mut dyn Framebuffer, keys: &mut dyn MenuKeySource, reason: &str) {
    begin_screen(fb, CHAIN_ERR_TITLE);
    {
        let mut out = FbTextOutput::at(fb, chrome::content_top());
        out.write_line(reason);
        out.write_line("");
        out.write_line(CHAIN_ERR_HINT_1);
        out.write_line(CHAIN_ERR_HINT_2);
    }
    chrome::draw_footer(fb, &RETURN_HINT);
    // Only Esc returns; every other key is ignored (no listed choices).
    let _ = read_menu_choice(keys, &[], true);
}

/// Brief notice shown before control is handed to firmware. On success the
/// verifier clears the screen with its own GOP; on failure the error
/// screen replaces this.
#[cfg(target_os = "uefi")]
fn render_loading_verifier(fb: &mut dyn Framebuffer) {
    begin_screen(fb, "VERIFY");
    let mut out = FbTextOutput::at(fb, chrome::content_top());
    out.write_line("Loading the separate verifier (\\EFI\\ALEA\\VERIFY.EFI) ...");
}

/// The verifier's fixed ESP path (SPEC_MAIN_MENU.md §17.4). Cross-slice
/// contract: the `alea-verify` build (see `scripts/build-release.sh` /
/// `.github/workflows/release.yml`) is placed here by `image-builder`'s
/// dual-file layout.
#[cfg(target_os = "uefi")]
const VERIFY_EFI_PATH: &uefi::CStr16 = uefi::cstr16!("\\EFI\\ALEA\\VERIFY.EFI");

/// Stack buffer size for the composed device path. A boot device path
/// (PciRoot/Pci/Sata/HD nodes, ~100-200 bytes) plus the ~44-byte file-path
/// node and the end node fit comfortably; `BufferTooSmall` degrades to a
/// graceful on-screen error rather than any allocation.
#[cfg(target_os = "uefi")]
const DEVICE_PATH_BUF_LEN: usize = 512;

// Named failure reasons (kept as fixed `&'static str`, alloc-free).
#[cfg(target_os = "uefi")]
const ERR_LOADED_IMAGE: &str = "reason: cannot read this image's own load information.";
#[cfg(target_os = "uefi")]
const ERR_NO_DEVICE: &str = "reason: this image reports no originating boot device.";
#[cfg(target_os = "uefi")]
const ERR_DEVICE_PATH: &str = "reason: cannot read the boot device's path.";
#[cfg(target_os = "uefi")]
const ERR_PATH_BUILD: &str = "reason: could not compose the verifier's file path.";
#[cfg(target_os = "uefi")]
const ERR_LOAD_IMAGE: &str = "reason: firmware could not load \\EFI\\ALEA\\VERIFY.EFI.";
#[cfg(target_os = "uefi")]
const ERR_START_IMAGE: &str = "reason: firmware loaded but could not start the verifier.";

/// The real chain-load. Returns `Ok(())` after the verifier exits (control
/// returns here on its exit), or a fixed reason string on any failure.
/// Never opens `EFI_SIMPLE_FILE_SYSTEM_PROTOCOL` (SPEC §17.4 / §29.6): only
/// `LOADED_IMAGE` (this image's own handle) and `DEVICE_PATH` (the boot
/// device, opened read-only via `GetProtocol`) are opened, and firmware
/// performs the file I/O for the `FromDevicePath` load.
#[cfg(target_os = "uefi")]
fn try_chain_load_verify() -> Result<(), &'static str> {
    use core::mem::MaybeUninit;
    use uefi::boot::{
        self, LoadImageSource, OpenProtocolAttributes, OpenProtocolParams,
    };
    use uefi::proto::device_path::build::{self, DevicePathBuilder};
    use uefi::proto::device_path::DevicePath;
    use uefi::proto::loaded_image::LoadedImage;
    use uefi::proto::BootPolicy;

    let image_handle = boot::image_handle();

    // This image's own load information -> the device (EFI System Partition)
    // it booted from. Opened READ-ONLY with `GetProtocol` (NOT exclusive):
    // the production edition bans exclusive protocol opens entirely on the
    // normal boot path (ci.sh SPEC §28 gate; see `seed-gop-ui`'s
    // `gop/backend.rs` module doc for why -- an exclusive open triggers
    // DisconnectController and can kill the firmware console driver on real
    // hardware). We only READ `device()`, so a shared open is correct.
    //
    // SAFETY: `boot::open_protocol` is `unsafe` because the caller must not
    // retain the returned interface past a change to the handle's protocol
    // set. We read `device()` immediately and drop `loaded` before
    // `load_image`; `agent = image_handle` (this application) and
    // `controller = None` are the correct arguments for a UEFI application,
    // and `GetProtocol` neither installs nor removes anything.
    let device_handle = {
        let loaded = unsafe {
            boot::open_protocol::<LoadedImage>(
                OpenProtocolParams {
                    handle: image_handle,
                    agent: image_handle,
                    controller: None,
                },
                OpenProtocolAttributes::GetProtocol,
            )
            .map_err(|_| ERR_LOADED_IMAGE)?
        };
        loaded.device().ok_or(ERR_NO_DEVICE)?
    };

    // The boot device's own device path (ends before any file node). Opened
    // READ-ONLY with `GetProtocol` (NOT exclusive), so no other agent is
    // disconnected from the boot device — we only need to READ its path.
    // This opens DEVICE_PATH, never SIMPLE_FILE_SYSTEM (SPEC §29.6):
    // SIMPLE_FILE_SYSTEM is only reached by `get_image_file_system`, which
    // this code never calls, so LTO drops that GUID from the shipped binary.
    //
    // SAFETY: `boot::open_protocol` is `unsafe` because the caller must not
    // retain the returned interface past a change to the handle's protocol
    // set. We hold `device_path` only briefly to read the boot node chain
    // into `buf`, then drop it before `load_image`; `agent = image_handle`
    // (this application) and `controller = None` are the correct arguments
    // for a UEFI application (not a driver), and `GetProtocol` neither
    // installs nor removes anything.
    let device_path = unsafe {
        boot::open_protocol::<DevicePath>(
            OpenProtocolParams {
                handle: device_handle,
                agent: image_handle,
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    }
    .map_err(|_| ERR_DEVICE_PATH)?;

    // Compose <boot-device-path> + \EFI\ALEA\VERIFY.EFI into a fixed stack
    // buffer (allocation-free). `node_iter()` yields every node up to but
    // excluding the END_ENTIRE node; `finalize()` re-appends END.
    let mut buf = [MaybeUninit::<u8>::uninit(); DEVICE_PATH_BUF_LEN];
    let mut builder = DevicePathBuilder::with_buf(&mut buf);
    for node in device_path.node_iter() {
        builder = builder.push(&node).map_err(|_| ERR_PATH_BUILD)?;
    }
    let full_path = builder
        .push(&build::media::FilePath { path_name: VERIFY_EFI_PATH })
        .map_err(|_| ERR_PATH_BUILD)?
        .finalize()
        .map_err(|_| ERR_PATH_BUILD)?;

    // Release the device-path open before handing control to firmware / the
    // verifier. (The `LoadedImage` open was already released when its inner
    // block ended above.) `full_path` lives in `buf` on this stack frame,
    // independent of this handle.
    drop(device_path);

    // Firmware does the file I/O for FromDevicePath -- the launcher never
    // touches SIMPLE_FILE_SYSTEM (SPEC §17.4 / §29.6). `BootPolicy::BootSelection`
    // is the uefi-0.39 encoding of the historical `from_boot_manager: true`
    // (Boolean TRUE) load policy.
    let verify_image = boot::load_image(
        image_handle,
        LoadImageSource::FromDevicePath {
            device_path: full_path,
            boot_policy: BootPolicy::BootSelection,
        },
    )
    .map_err(|_| ERR_LOAD_IMAGE)?;

    boot::start_image(verify_image).map_err(|_| ERR_START_IMAGE)?;
    Ok(())
}
