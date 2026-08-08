//! Shared real-firmware provider wiring (SPEC §11, §12, §15-§16, §17.4,
//! §22.1-§22.5, §26, §28).
//!
//! # Why this module exists
//!
//! Before this module existed, `crates/seed-uefi-production/src/
//! {flow_pre,flow_secret}/mod.rs` and `crates/seed-uefi-test/src/
//! {flow_pre,flow_secret}/mod.rs` were four separate files (~475 lines
//! combined) that implemented the exact same real-firmware provider
//! traits against the exact same `uefi`/`seed-platform-x86`/`seed-gop-ui`
//! calls, copy-pasted between editions. The only genuine functional delta
//! anywhere in all four files was whether [`ProdPolicyGates::info`]'s
//! `production_markers_verified` field and [`CryptoSelfTestGate`] bullet
//! 13 (SPEC §11.6) reflect a real production-build check or vacuously
//! pass — everything else (Escape-preserving menu-key reads, console-
//! topology handle resolution, GOP mode selection, machine-source
//! acquisition, shutdown, fault-hook wiring) was byte-for-byte identical
//! logic maintained in two (soon to be three, with `seed-desktop-test`'s
//! own analogous but not-UEFI wiring) places at once.
//!
//! That one delta is now the single `production_marker: Option<fn() ->
//! bool>` parameter every constructor below takes. Each UEFI edition's
//! own `flow_pre`/`flow_secret` module is now a thin file that re-exports
//! the types below and supplies exactly one edition-specific constant:
//! production's own thin wrapper passes `Some(markers::self_check)`
//! (SPEC §28: a genuine, real check that this is the verified production
//! build); the test edition passes `None` (by definition not the
//! production build, so there is no marker to assert — see
//! [`seed_selftest::run_aggregate_self_test`]'s own doc comment for why
//! `None` is treated as vacuously passing that one bullet rather than as
//! a failure).
//!
//! # Isolation (SPEC §4.1/§4.2/§9/§28) — read before editing this file
//!
//! This module is reused, unmodified, by `seed-uefi-production` itself
//! (a normal dependency edge via `seed-flow`, already reviewed — see
//! `crates/seed-uefi-production/Cargo.toml`'s own doc comment). It
//! therefore MUST contain no watermark, no `"PUBLIC TEST PHRASE"`, no
//! `"test"`/`"demo"`/`"development"` wording, and no other test-edition
//! identity text anywhere in this file — that text stays exactly where
//! it always has, in each edition's own `main.rs` banner constants (see
//! `crates/seed-uefi-test/src/main.rs`'s `BANNER_LINE_1`/`BANNER_LINE_2`),
//! which this module neither defines nor reads. Every observable
//! behavioral difference between editions is expressed through the
//! `production_marker` parameter alone; adding any other edition-
//! conditional branch here (a hardcoded string, a `cfg` on edition name,
//! etc.) would silently reintroduce the exact copy-paste coupling this
//! dedup was meant to remove. This is enforced structurally, not just by
//! convention: `ci.sh`'s binary-policy scan of the compiled
//! `seed-uefi-production.efi` artifact and its `cargo tree
//! -p seed-uefi-production` isolation check both still pass with this
//! module linked into that binary (it lives in `seed-flow`, already a
//! normal, reviewed dependency of every edition).
//!
//! # Host-testability is unaffected
//!
//! Compiled only for the real `x86_64-unknown-uefi` target
//! (`#[cfg(target_os = "uefi")]` on this module's declaration in
//! `lib.rs`); the `uefi` crate this module needs is itself a
//! target-conditional dependency in this crate's own `Cargo.toml`
//! (`[target.'cfg(target_os = "uefi")'.dependencies]`), so `cargo test -p
//! seed-flow` on the host neither compiles this module nor links `uefi`
//! — the crate's host-testability (see the crate-level doc comment) is
//! completely unaffected by this module's existence. None of the code in
//! this file is exercised by `cargo test` for the same reason every
//! edition's own former copy of it never was; it is verified by
//! cross-compilation to `x86_64-unknown-uefi` only (`ci.sh`).

use crate::diagnostics::{
    CheckOutcome, ConsoleCheckResult, ConsoleGate, CryptoCheckResult, CryptoSelfTestGate,
    GraphicsCheckResult, GraphicsGate, GraphicsInfo, PlatformCheckResult, PlatformGate,
    PlatformInfo, PlatformInfoGate, SecureBootStatus,
};
use crate::entropy_avail::{MachineAvailabilityGate, SourceAvailability};
use crate::flow_secret::machine::{
    AcquiredSource, AcquiredSources, MachineAcquisitionError, MachineSourceGate,
};
use crate::flow_secret::shutdown::{FaultHook, ShutdownFailure, ShutdownProvider};
use crate::flow_secret::SecretFlowOutcome;
use crate::output::TextOutput;
use seed_platform_x86::boot::{print_banner_line, TextSink};
use seed_platform_x86::input::uefi_backend::FirmwareKeySource;
use seed_platform_x86::watchdog::{UefiWatchdog, Watchdog};
use seed_platform_x86::{console, virt};
use seed_protocol::policy::Policy;
use seed_protocol::state::ErrorClass;
use uefi::proto::console::text::{Input, Output};

/// Repository-root entropy policy, embedded at compile time (SPEC §31
/// permits shipping it as part of the signed release; signature
/// verification is out of scope for this module — see `IMPLEMENTATION_MAP
/// .md` WP-29/30). Embedded exactly once here (every edition used to
/// embed its own byte-identical copy at its own call site).
const POLICY_TOML: &str = include_str!("../../../entropy-policy.toml");

// ============================================================================
// TextOutput: firmware SIMPLE_TEXT_OUTPUT_PROTOCOL
// ============================================================================

/// [`TextOutput`] backed by the firmware's `SIMPLE_TEXT_OUTPUT_PROTOCOL`
/// (SPEC §12.1).
///
/// SPEC.md amendment (2026-08-06): no longer constructed anywhere on the
/// normal boot path — both UEFI editions render the entire ceremony
/// through [`crate::output::FbTextOutput`] over the GOP framebuffer
/// instead (see [`open_session_gop`]'s own doc comment). This type stays
/// defined only because [`crate::output::TextOutput`] itself is a plain
/// trait any `SIMPLE_TEXT_OUTPUT_PROTOCOL`-backed adapter could implement
/// (kept for completeness / any future reviewed refusal-path use); a
/// `ci.sh` scanner fails the build on any construction call site of this
/// type (its `new` constructor) anywhere in the production-reachable
/// source tree, so it cannot silently come back into the normal path.
/// (Written without the literal call syntax here on purpose — that exact
/// text would trip the scanner's own blunt source-text grep.)
pub struct FirmwareTextOutput<'a> {
    output: &'a mut Output,
}

impl<'a> FirmwareTextOutput<'a> {
    #[must_use]
    pub fn new(output: &'a mut Output) -> Self {
        Self { output }
    }
}

impl TextOutput for FirmwareTextOutput<'_> {
    fn write_line(&mut self, line: &str) {
        let mut sink = OutputSink { output: self.output };
        // A single over-length/failed line must not crash the flow (SPEC
        // §20.4); best-effort only.
        let _ = print_banner_line(&mut sink, line);
        // Terminate the line. `write_screen()` emits one `write_line` per
        // logical line, and firmware SimpleTextOutput does NOT insert
        // newlines — without this, consecutive lines concatenate onto one
        // row and the mandated warning wording (SPEC §22.1/§22.2) renders
        // garbled ("...your normal" + "operating..." -> "normaloperating").
        // UEFI newline is CR+LF; the mock terminal already treats each
        // write_line as its own line, so this only affects real firmware.
        let _ = print_banner_line(&mut sink, "\r\n");
    }

    fn clear(&mut self) {
        let _ = self.output.clear();
    }

    /// Real-hardware slow-RDSEED fix: unlike `write_line`, this does NOT
    /// emit the trailing CR+LF, so consecutive progress ticks accumulate
    /// on one console row instead of each starting a fresh line — the
    /// visual "dots filling in" effect the acquiring screen's duration
    /// line promises. Counts-only content only (see
    /// `crate::output::TextOutput::write_progress`'s own doc comment);
    /// no secret bytes ever reach this call.
    fn write_progress(&mut self, s: &str) {
        let mut sink = OutputSink { output: self.output };
        let _ = print_banner_line(&mut sink, s);
    }
}

/// Adapts `Output` to `seed_platform_x86::boot::TextSink` so this module
/// can reuse [`print_banner_line`]'s bounds-checked UTF-16 conversion
/// instead of re-implementing it.
struct OutputSink<'a> {
    output: &'a mut Output,
}

impl TextSink for OutputSink<'_> {
    fn write_line(&mut self, line: &str) -> Result<(), seed_platform_x86::boot::BannerError> {
        let mut buf = [0u16; seed_platform_x86::boot::MAX_BANNER_LINE_UNITS];
        let cstr = uefi::CStr16::from_str_with_buf(line, &mut buf)
            .map_err(|_| seed_platform_x86::boot::BannerError::LineTooLong)?;
        self.output
            .output_string(cstr)
            .map_err(|_| seed_platform_x86::boot::BannerError::OutputFailed)
    }
}

// ============================================================================
// MenuKeySource: firmware keystrokes, Escape preserved
// ============================================================================
//
// STEP D dedup: this module used to define its own `FirmwareMenuKeys`
// type here, hand-duplicating `seed_platform_x86::input::uefi_backend::
// FirmwareKeySource`'s exact UEFI `SIMPLE_TEXT_INPUT_PROTOCOL` scan-code
// mapping (including the same `ScanCode::ESCAPE` -> `MenuKey::Escape`
// case, now that Phase 1 added that variant to `InputEvent`). Since
// `crate::keys::MenuKey` is exactly `seed_platform_x86::input::
// InputEvent` and `crate::keys::MenuKeySource` has a blanket impl for any
// real `seed_platform_x86::input::KeySource` (see that module's own doc
// comment), `seed_platform_x86::input::uefi_backend::FirmwareKeySource`
// already *is* a `MenuKeySource` — every construction site below uses it
// directly instead of a second, redundant wrapper type.

// ============================================================================
// PlatformGate: architecture + virtualization (SPEC §11.2)
// ============================================================================

/// Real-firmware [`PlatformGate`]: always reports `x86-64` (the only
/// architecture any of these binaries is ever built for) plus a real
/// CPUID + firmware-string virtualization check.
pub struct ProdPlatformGate;

impl PlatformGate for ProdPlatformGate {
    fn check(&mut self) -> PlatformCheckResult {
        let cpuid = virt::cpuid::RealCpuid;
        let firmware = virt::firmware::uefi_backend::SystemTableFirmwareStrings;
        let report = virt::report::evaluate(&cpuid, &firmware);
        PlatformCheckResult {
            outcome: if report.suspected() {
                CheckOutcome::Failed
            } else {
                CheckOutcome::Clean
            },
            error_class: ErrorClass::Virtualization,
            architecture_line: "x86-64",
            virt_summary: report.summary(),
        }
    }
}

// ============================================================================
// ConsoleGate: ConIn/ConOut/ErrOut topology (SPEC §11.3)
// ============================================================================

/// Real-firmware [`ConsoleGate`].
///
/// # How the active console handles are resolved (SPEC §11.3/§28)
///
/// Each role (`ConIn`/`ConOut`/`ErrOut`) is resolved from an ordered list
/// of sweep stages via `console::resolve_role` — see
/// `seed_platform_x86::console`'s own module-level and
/// `console::uefi_backend`'s doc comments for the full portable-resolver
/// design this implements. In order:
///
/// - **OUTPUT**: the `ConOut` EDK2 tag sweep, then `SimpleTextOutput`
///   protocol enumeration, then `GraphicsOutput` protocol enumeration
///   (last resort, consulted only if `SimpleTextOutput` resolved zero
///   path-bearing handles — the two are never merged, since on every
///   surveyed firmware they share the same real display handle/path).
/// - **INPUT**: the `ConIn` EDK2 tag sweep, then `SimpleTextInput`
///   protocol enumeration.
/// - **ERROUT**: the `StdErr` EDK2 tag sweep only — ErrOut has no
///   dedicated UEFI protocol to enumerate (every ErrOut-capable device
///   already carries `SimpleTextOutput`, gated by the OUTPUT role's own
///   enumeration stage); an empty ErrOut resolution stays non-fatal
///   (SPEC §11.3: "its absence alone is not fatal").
///
/// This never performs a runtime UEFI variable read (SPEC §28):
/// `console::resolve_role`'s tag stage reads EDK2 `ConPlatformDxe`'s own
/// boot-time mirror of console membership (a device-handle tag, not a
/// variable), and the protocol-enumeration stages are plain
/// `LocateHandle(ByProtocol)` sweeps over UEFI-spec-mandated console
/// protocols — the same boot-services pattern already used by
/// `crate::virt::devpath`'s PCI sweep. This is read-only topology
/// inspection: it can only ever cause a *refusal*, never select or
/// influence any entropy source, so it is not a hidden entropy vector
/// even in principle.
///
/// **Two different semantics by design** (see `console::uefi_backend`'s
/// doc comment for the full rationale): the tag stage uses
/// *active-membership* semantics (a present-but-inactive serial/network
/// device does not refuse — the tag mirrors exactly SPEC §11.3's object
/// of inspection), while the enumeration stages use a *conservative
/// closure* (any path-bearing serial/network/BMC/vendor-unclassifiable
/// handle refuses, since activity is unknowable without a banned
/// variable read). Documented consequence: **a machine with
/// serial-console (COM/SOL) redirection enabled, on firmware that does
/// not implement EDK2 tagging, is correctly refused** even while that
/// redirection is idle; the remediation is disabling redirection in
/// firmware setup.
pub struct ProdConsoleGate;

impl ConsoleGate for ProdConsoleGate {
    fn check(&mut self) -> ConsoleCheckResult {
        let out_stages: [console::SweepOutcome; 3] = [
            console::uefi_backend::sweep_by_guid(
                &console::uefi_backend::CONSOLE_OUT_DEVICE_GUID,
                console::ConsoleRole::ConOut,
                console::ConsoleRole::ExtraOut,
            ),
            console::uefi_backend::sweep_simple_text_output(
                console::ConsoleRole::ConOut,
                console::ConsoleRole::ExtraOut,
            ),
            console::uefi_backend::sweep_graphics_output(
                console::ConsoleRole::ConOut,
                console::ConsoleRole::ExtraOut,
            ),
        ];
        let in_stages: [console::SweepOutcome; 2] = [
            console::uefi_backend::sweep_by_guid(
                &console::uefi_backend::CONSOLE_IN_DEVICE_GUID,
                console::ConsoleRole::ConIn,
                console::ConsoleRole::ConIn,
            ),
            console::uefi_backend::sweep_simple_text_input(
                console::ConsoleRole::ConIn,
                console::ConsoleRole::ConIn,
            ),
        ];
        let err_stages: [console::SweepOutcome; 1] = [console::uefi_backend::sweep_by_guid(
            &console::uefi_backend::STANDARD_ERROR_DEVICE_GUID,
            console::ConsoleRole::ErrOut,
            console::ConsoleRole::ErrOut,
        )];

        let out = console::resolve_role(&out_stages);
        let in_ = console::resolve_role(&in_stages);
        let err = console::resolve_role(&err_stages);

        let truncated = out.truncated || in_.truncated || err.truncated;

        let verdict = console::aggregate_topology(&console::TopologySets {
            con_in: &in_.reports[..in_.len],
            con_out: &out.reports[..out.len],
            err_out: &err.reports[..err.len],
            truncated,
        });

        let con_in_accepted = in_.reports[..in_.len].iter().filter(|r| r.is_accepted()).count();
        let con_out_accepted = out.reports[..out.len].iter().filter(|r| r.is_accepted()).count();

        match verdict {
            Ok(()) => ConsoleCheckResult {
                outcome: CheckOutcome::Clean,
                error_class: ErrorClass::ConsoleTopology,
                con_out_paths: u8::try_from(con_out_accepted).unwrap_or(u8::MAX),
                con_in_paths: u8::try_from(con_in_accepted).unwrap_or(u8::MAX),
                summary_line: "Remote/serial paths      None detected -- not proof",
            },
            Err(reason) => {
                let inconclusive = matches!(
                    reason,
                    console::RefuseReason::VendorUnclassifiable
                        | console::RefuseReason::ParseFailure
                        | console::RefuseReason::MultipleOutputPaths
                        | console::RefuseReason::RemoteCapableInput
                );
                ConsoleCheckResult {
                    outcome: if inconclusive {
                        CheckOutcome::Inconclusive
                    } else {
                        CheckOutcome::Failed
                    },
                    error_class: ErrorClass::ConsoleTopology,
                    con_out_paths: u8::try_from(con_out_accepted).unwrap_or(u8::MAX),
                    con_in_paths: u8::try_from(con_in_accepted).unwrap_or(u8::MAX),
                    summary_line: reason.describe(),
                }
            }
        }
    }
}

// ============================================================================
// Session GOP: opened once at process start (SPEC.md amendment 2026-08-06)
// ============================================================================

/// The GOP session opened exactly once, at process start (SPEC.md
/// amendment 2026-08-06 / SPEC §11.4, §12.1, §12.2): captured strictly
/// before [`crate::driver::run_pre_secret_flow`] begins, reused unchanged
/// by [`HeldGopGraphicsGate`] (the SPEC §11.4 mandatory gate) and by
/// [`run_secret_phase`] (every screen from `AppState::
/// MachineEntropyAcquisition` onward) -- never re-opened and never
/// `set_mode` a second time, because a second mode-set mid-ceremony would
/// blank the display and any handle churn risks the exact real-hardware
/// firmware-console disconnect `seed_gop_ui::gop::backend`'s own module
/// doc documents. `gop` is kept alive for the ceremony's entire duration
/// both to keep `fb`'s underlying memory-mapped pointer valid (see
/// `seed_gop_ui::gop::backend::open_selected_gop`'s own doc comment for
/// why both are always returned/held together) AND because
/// [`HeldGopGraphicsGate`] borrows it directly (`pub`) to re-read the
/// *current* mode at the SPEC §11.4 gate -- see that type's own doc
/// comment for why it must never open a second `ScopedProtocol` on this
/// handle instead of borrowing this one.
pub struct SessionGop {
    pub gop: uefi::boot::ScopedProtocol<uefi::proto::console::gop::GraphicsOutput>,
    pub fb: seed_gop_ui::gop::framebuffer::LinearFramebuffer,
    pub info: GraphicsInfo,
}

/// Open the GOP exactly once, non-exclusively (SPEC §11.4; see
/// `seed_gop_ui::gop::backend`'s module doc for why every open in this
/// crate is `GetProtocol`, never exclusive), before any other startup
/// work begins. Callers print the returned refusal reason via the
/// firmware text console before exiting to firmware -- the ONE surviving
/// use of firmware text output on the normal (non-refusal-before-any-
/// framebuffer-exists) boot path, because there is no framebuffer to draw
/// onto yet when this fails.
///
/// # Errors
///
/// The SPEC §11.4-mandated named reason: `PixelBltOnly` wording when no
/// linear-framebuffer-capable mode exists at all, or `ModeSelectError`'s
/// own reason for any other mode-selection refusal (below the resolution
/// floor, etc.).
pub fn open_session_gop() -> Result<SessionGop, &'static str> {
    use seed_core::contracts::Framebuffer as _;
    use seed_gop_ui::gop::backend::{device_path_text, open_selected_gop, GopOpenError};

    let (gop, fb) = open_selected_gop().map_err(|e| match e {
        GopOpenError::ModeSelect(err) => err.reason(),
        GopOpenError::NoGraphicsOutput | GopOpenError::SetModeFailed => {
            seed_gop_ui::gop::mode::PIXEL_BLT_ONLY_REFUSAL_REASON
        }
    })?;

    let (width, height) = fb.dims();
    // `open_selected_gop` returns the opened `ScopedProtocol` handle;
    // re-resolve the underlying `Handle` for the device-path text (SPEC
    // §11.4: "Display ... device path before generation") -- mirrors
    // `ProdGraphicsGate::check`'s own identical re-resolution exactly.
    let device_path = uefi::boot::get_handle_for_protocol::<uefi::proto::console::gop::GraphicsOutput>()
        .map_or_else(
            |_| seed_gop_ui::gop::device_path::DevicePathText::unavailable(),
            device_path_text,
        );

    Ok(SessionGop {
        gop,
        fb,
        info: GraphicsInfo { width, height, device_path },
    })
}

// ============================================================================
// GraphicsGate: GOP mode selection (SPEC §11.4)
// ============================================================================

/// Real-firmware [`GraphicsGate`] that opens its OWN `GraphicsOutput`
/// handle inside `check()` (via `open_selected_gop`, including a real
/// `set_mode`).
///
/// SPEC.md amendment (2026-08-06): NOT constructed by either UEFI
/// edition's `main.rs` on the normal boot path -- both now use
/// [`HeldGopGraphicsGate`] over the single [`SessionGop`] opened once at
/// process start by [`open_session_gop`], never this type. This one is
/// kept defined (not deleted) only for completeness/any future reviewed
/// use, exactly like [`FirmwareTextOutput`] above -- but unlike that type,
/// there is currently no `ci.sh` scanner preventing this one from being
/// wired back into the `Gates` bundle.
///
/// **Do not construct this alongside an open [`SessionGop`].** Calling
/// `check()` here while `SessionGop` is also held opens a SECOND
/// `ScopedProtocol<GraphicsOutput>` on the same handle from the same
/// agent -- per UEFI's `CloseProtocol` semantics (mirrored by EDK2's
/// `CoreCloseProtocol`), that transient's `Drop` removes *every*
/// open-list entry matching the same `(agent, controller)` pair, which on
/// EDK2-derived firmware tears down the session's own registration and
/// panics on the session's later `Drop` (`ScopedProtocol::drop` asserts
/// `Status::SUCCESS`) -- see `seed_gop_ui::gop::backend`'s module doc and
/// [`HeldGopGraphicsGate`]'s own doc comment for the full incident
/// writeup this exact hazard produced when it briefly lived at a
/// different call site. A mid-flow `set_mode` here would also blank the
/// display over whatever [`open_session_gop`] already rendered.
///
/// Runs mid pre-secret firmware-console UI (called from between the
/// keyboard self-test and the word-count screen, all of which render via
/// `SimpleTextOut`): `open_selected_gop` (`seed_gop_ui::gop::backend`)
/// MUST open the GOP non-exclusively. An exclusive open disconnects the
/// firmware's own console driver on real (Phoenix-class) hardware and
/// black-screens every console screen that follows this gate, with no
/// error -- a confirmed real-hardware field failure, not a hypothetical.
/// See that module's doc comment for the full rationale; this is not
/// re-litigated here, only flagged so nobody "fixes" this call site back
/// to exclusive without reading that doc first.
pub struct ProdGraphicsGate;

impl GraphicsGate for ProdGraphicsGate {
    fn check(&mut self) -> GraphicsCheckResult {
        use seed_core::contracts::Framebuffer as _;
        use seed_gop_ui::gop::backend::{device_path_text, open_selected_gop, GopOpenError};

        match open_selected_gop() {
            Ok((gop, fb)) => {
                let (width, height) = fb.dims();
                // `open_selected_gop` returns the opened `ScopedProtocol`
                // handle; re-resolve the underlying `Handle` for the
                // device-path text (SPEC §11.4: "Display ... device path
                // before generation").
                let device_path = uefi::boot::get_handle_for_protocol::<
                    uefi::proto::console::gop::GraphicsOutput,
                >()
                .map_or_else(
                    |_| seed_gop_ui::gop::device_path::DevicePathText::unavailable(),
                    device_path_text,
                );
                drop(gop);
                GraphicsCheckResult::Available(GraphicsInfo { width, height, device_path })
            }
            Err(GopOpenError::ModeSelect(e)) => GraphicsCheckResult::Refused(e.reason()),
            Err(GopOpenError::NoGraphicsOutput) => {
                GraphicsCheckResult::Refused(seed_gop_ui::gop::mode::PIXEL_BLT_ONLY_REFUSAL_REASON)
            }
            Err(GopOpenError::SetModeFailed) => {
                GraphicsCheckResult::Refused(seed_gop_ui::gop::mode::PIXEL_BLT_ONLY_REFUSAL_REASON)
            }
        }
    }
}

/// Real-firmware [`GraphicsGate`] over an already-opened [`SessionGop`]
/// (SPEC.md amendment 2026-08-06 / SPEC §11.4): replaces
/// [`ProdGraphicsGate`] in the `Gates` bundle both UEFI editions'
/// `main.rs` construct now that [`open_session_gop`] captures the GOP
/// once, strictly before `run_pre_secret_flow` even starts, rather than
/// this gate opening it itself mid-flow. The SPEC §11.4 state still runs
/// in its frozen §21 order, still renders resolution + device path, and
/// still requires the local-physical-display user confirmation and
/// keyboard self-test exactly as before (`run_graphics_and_keyboard_gate`
/// in `crate::driver` is unchanged) -- only the moment of GOP
/// *acquisition* moved earlier, never the gate's own semantics.
///
/// # Never a second `ScopedProtocol` open (fixed 2026-08-06 review)
///
/// `check()` borrows [`SessionGop::gop`] directly (`&'a`) and reads its
/// `current_mode_info()` -- it does NOT re-open `GraphicsOutput` a second
/// time. An earlier version called a `current_mode_dims()` helper that
/// opened a second `ScopedProtocol` on the same handle; per UEFI's
/// `CloseProtocol` semantics (mirrored by EDK2's `CoreCloseProtocol`),
/// `CloseProtocol` removes *every* open-list entry matching the same
/// `(agent, controller)` pair, so on EDK2-derived firmware that transient
/// open deduped into the session's own entry and its `Drop` tore down the
/// *session's* registration outright -- the session's own later `Drop`
/// then observed `EFI_NOT_FOUND` from firmware, which the `uefi` crate's
/// `ScopedProtocol::drop` asserts is `Status::SUCCESS`, panicking on any
/// exit-to-firmware path taken after this gate ran. See
/// `seed_gop_ui::gop::backend`'s own module doc for the full incident
/// writeup. Do not reintroduce a second open here.
///
/// Compares the current mode's resolution AND pixel format against the
/// [`GraphicsInfo`] captured at session-open time (the pixel-format check
/// re-asserts the same "still a linear framebuffer, not `PixelBltOnly`"
/// property `open_session_gop` enforced at open time, not just
/// dimensions -- SPEC §11.4 defense-in-depth), returning
/// [`GraphicsCheckResult::Available`] only on an exact dimension match on
/// a still-linear mode, [`GraphicsCheckResult::Refused`] otherwise. The
/// actual Available/Refused mapping is delegated to
/// [`crate::diagnostics::classify_held_graphics_check`] (host-tested
/// there, since this module itself never compiles on the host) -- this
/// type's own `check()` is reduced to reading the two real values off the
/// held protocol and handing them to that pure function, fail-closed the
/// same way whether or not this specific arm has ever fired on real
/// firmware.
pub struct HeldGopGraphicsGate<'a> {
    gop: &'a uefi::boot::ScopedProtocol<uefi::proto::console::gop::GraphicsOutput>,
    info: GraphicsInfo,
}

impl<'a> HeldGopGraphicsGate<'a> {
    /// `gop` is [`SessionGop::gop`] (borrowed, never a fresh open); `info`
    /// is [`SessionGop::info`], captured once by [`open_session_gop`] at
    /// process start.
    #[must_use]
    pub fn new(gop: &'a uefi::boot::ScopedProtocol<uefi::proto::console::gop::GraphicsOutput>, info: GraphicsInfo) -> Self {
        Self { gop, info }
    }
}

impl GraphicsGate for HeldGopGraphicsGate<'_> {
    fn check(&mut self) -> GraphicsCheckResult {
        let mode_info = self.gop.current_mode_info();
        let (width, height) = mode_info.resolution();
        let is_linear = !matches!(mode_info.pixel_format(), uefi::proto::console::gop::PixelFormat::BltOnly);
        crate::diagnostics::classify_held_graphics_check(Some((width as u32, height as u32, is_linear)), self.info)
    }
}

// ============================================================================
// CryptoSelfTestGate: full SPEC §11.6 aggregate self-test
// ============================================================================

/// Real-firmware [`CryptoSelfTestGate`]: a thin adapter over
/// [`seed_selftest::run_aggregate_self_test`] (STEP C: moved out of this
/// crate into its own tiny crate — see that crate's own doc comment for
/// why it isn't `seed_core::self_test`, the more natural home, and for
/// the full bullet list and KAT sources), which runs every one of the
/// thirteen SPEC §11.6 self-test bullets.
///
/// `production_marker` is threaded straight through to
/// `run_aggregate_self_test` for bullet 13 (production-build policy
/// marker): production's own thin wrapper constructs this with
/// `Some(markers::self_check)` — unlike every other edition, that binary
/// genuinely claims to be the verified production build (see
/// [`ProdPolicyGates::info`]'s own `production_markers_verified` field, fed
/// by the same parameter), so the startup gate itself verifies that claim
/// before generation is enabled, not only the SPEC §22.3 diagnostics
/// screen. Every other edition constructs this with `None`.
pub struct ProdCryptoSelfTestGate {
    production_marker: Option<fn() -> bool>,
}

impl ProdCryptoSelfTestGate {
    #[must_use]
    pub fn new(production_marker: Option<fn() -> bool>) -> Self {
        Self { production_marker }
    }
}

impl CryptoSelfTestGate for ProdCryptoSelfTestGate {
    fn check(&mut self) -> CryptoCheckResult {
        let ok = seed_selftest::run_aggregate_self_test(self.production_marker).all_clean();
        CryptoCheckResult {
            outcome: if ok { CheckOutcome::Clean } else { CheckOutcome::Failed },
        }
    }
}

// ============================================================================
// ProdPolicyGates: entropy policy (SPEC §15, §22.3, §22.5, §28)
// ============================================================================

/// Loads (once) and shares the embedded entropy policy between
/// [`PlatformInfoGate`] and [`MachineAvailabilityGate`], plus carries the
/// `production_marker` this edition was constructed with (SPEC §31
/// permits shipping the policy as part of the signed release; signature
/// verification itself is out of scope here — see this module's own doc
/// comment).
pub struct ProdPolicyGates {
    policy: Option<Policy>,
    production_marker: Option<fn() -> bool>,
}

impl ProdPolicyGates {
    #[must_use]
    pub fn new(production_marker: Option<fn() -> bool>) -> Self {
        Self {
            policy: seed_protocol::policy::parse(POLICY_TOML).ok(),
            production_marker,
        }
    }
}

impl PlatformInfoGate for ProdPolicyGates {
    fn info(&mut self) -> PlatformInfo {
        PlatformInfo {
            // SPEC §22.3 explicitly lists "Unknown" as a valid displayed
            // state; reading the real `SecureBoot` UEFI variable is a
            // small, separate piece of work no WP currently owns.
            secure_boot: SecureBootStatus::Unknown,
            entropy_policy_version: self.policy.map(|p| p.version),
            // `None` (every non-production edition) reports `false` — by
            // definition not the verified production build (SPEC §4.2).
            // `Some(f)` (production only) reports the real check's
            // result, so this field means the same thing in every
            // edition: "was the production-build marker actually
            // verified", never a hardcoded claim.
            production_markers_verified: self.production_marker.is_some_and(|f| f()),
        }
    }
}

impl MachineAvailabilityGate for ProdPolicyGates {
    fn efi_rng(&mut self) -> SourceAvailability {
        // The shipped v1 policy ships EFI RNG unapproved
        // (`entropy-policy.toml`'s `[efi_rng] approved = false`); since
        // policy approval is required either way, an unapproved policy
        // makes runtime protocol detection unable to change the answer.
        // A future policy that approves EFI RNG would need this gate
        // extended with real `EFI_RNG_PROTOCOL` location.
        match self.policy {
            Some(p) if p.efi_rng.approved => SourceAvailability {
                approved: true,
                sole_source_allowed: p.efi_rng.sole_source_allowed,
            },
            _ => SourceAvailability::default(),
        }
    }

    fn rdseed(&mut self) -> SourceAvailability {
        let Some(policy) = self.policy else {
            return SourceAvailability::default();
        };
        if !policy.rdseed.approved {
            return SourceAvailability::default();
        }
        let cpuid = virt::cpuid::RealCpuid;
        if !seed_platform_x86::rng::cpu::rdseed_supported(&cpuid) {
            return SourceAvailability::default();
        }
        let raw_vendor = seed_platform_x86::rng::cpu::vendor_string(&cpuid);
        let mut vendor_buf = [0u8; 12];
        vendor_buf.copy_from_slice(&raw_vendor);
        let vendor = core::str::from_utf8(&vendor_buf).unwrap_or("");
        let (family, model, stepping) = seed_platform_x86::rng::cpu::family_model_stepping(&cpuid);
        let approved = policy.rdseed.is_cpu_allowed(vendor, family, model, stepping);
        SourceAvailability {
            approved,
            sole_source_allowed: approved && policy.rdseed.sole_source_allowed,
        }
    }

    /// SPEC §18.2's required machine-only disclosure. Real computation
    /// (not the trait's `None` default): reuses [`Self::efi_rng`]/
    /// [`Self::rdseed`] to find whichever source is currently
    /// sole-source-eligible, then fills in the algorithm identifier /
    /// CPU-microcode-result specific to that source class.
    fn machine_only_disclosure(&mut self) -> Option<crate::entropy_avail::MachineOnlyDisclosure> {
        let policy = self.policy?;

        if self.efi_rng().sole_source_allowed {
            let algo = policy
                .efi_rng
                .allowed_algorithms()
                .first()
                .copied()
                .unwrap_or_else(|| {
                    seed_protocol::policy::AlgoId::from_str("(no approved algorithm listed)")
                        .expect("fits MAX_ALGO_ID_LEN")
                });
            return Some(crate::entropy_avail::MachineOnlyDisclosure {
                source_class: "EFI RNG",
                algorithm_identifier: algo,
                // SPEC §15.1 approval is protocol/algorithm-based, not
                // CPU-identity-based — no CPU/microcode result applies.
                cpu_microcode_result: None,
                policy_version: policy.version,
            });
        }

        if self.rdseed().sole_source_allowed {
            let cpuid = virt::cpuid::RealCpuid;
            let raw_vendor = seed_platform_x86::rng::cpu::vendor_string(&cpuid);
            let mut vendor_buf = [0u8; 12];
            vendor_buf.copy_from_slice(&raw_vendor);
            let vendor = core::str::from_utf8(&vendor_buf).unwrap_or("");
            let (family, model, stepping) = seed_platform_x86::rng::cpu::family_model_stepping(&cpuid);
            // No microcode-revision read exists anywhere in this project
            // yet; `None` is honest about that and fails safe per
            // `is_cpu_allowed_with_microcode`'s own doc comment whenever a
            // policy rule declares a minimum revision, and is a no-op
            // whenever it does not.
            let cpu_result =
                policy.rdseed.is_cpu_allowed_with_microcode(vendor, family, model, stepping, None);
            return Some(crate::entropy_avail::MachineOnlyDisclosure {
                source_class: "RDSEED64",
                algorithm_identifier: seed_protocol::policy::AlgoId::from_str("RDSEED64 (CPU instruction)")
                    .expect("fits MAX_ALGO_ID_LEN"),
                cpu_microcode_result: Some(cpu_result),
                policy_version: policy.version,
            });
        }

        None
    }
}

// ============================================================================
// Watchdog
// ============================================================================

/// Build the real [`Watchdog`] wrapper every edition uses.
#[must_use]
pub fn production_watchdog() -> Watchdog<UefiWatchdog> {
    Watchdog::new(UefiWatchdog::new())
}

// ============================================================================
// MachineSourceGate: real machine-source acquisition (SPEC §15-§16)
// ============================================================================

/// Real machine-source acquisition (SPEC §15-§16), reusing the
/// `efi_rng`/`rdseed`/`rdrand` drivers directly — these drivers ARE the
/// real production entropy-acquisition code in every edition, not a
/// test-only substitute.
///
/// # Real-hardware slow-RDSEED fix (wall-clock acquisition budget)
///
/// Confirmed on real hardware: an old CPU with no `EFI_RNG_PROTOCOL` and
/// an approved sole-source RDSEED policy hung the "acquiring machine
/// entropy" screen for 2+ minutes with no error — the software's
/// per-instruction retry COUNTS were already fully bounded, but a
/// degraded RDSEED reseed pool made each individual instruction slow
/// enough that the bounded count of slow instructions still accumulated
/// to minutes, with no bound on wall-clock TIME anywhere in the old
/// acquisition path. `clock` (calibrated once at construction — see
/// [`Self::new`]) and [`MACHINE_ACQUISITION_BUDGET_MS`] fix this: one
/// shared [`seed_platform_x86::time::Deadline`] covers all three
/// mechanisms for the whole `acquire` call, checked before every single
/// raw instruction attempt (the tightest bound software can give — see
/// `seed_platform_x86::rng::raw`'s module doc for why block- or
/// call-level checks would still allow many slow instructions through).
/// A deadline expiry is a hard failure indistinguishable from an
/// exhausted-retry refusal to every downstream caller
/// (`assemble_acquired_sources` sees `None` either way); the only
/// difference is `timed_out` below, used solely to pick the failure
/// screen's wording.
pub struct ProdMachineSourceGate {
    policy: Option<Policy>,
    /// `None` when TSC calibration itself failed (fail closed — zero
    /// entropy instructions are ever executed in that case; see
    /// [`Self::acquire`]'s early return) or when this is not compiled for
    /// the real UEFI target's clock. Always `Some` in a real production
    /// boot once calibration succeeds.
    clock: Option<seed_platform_x86::time::CalibratedTsc>,
}

/// Wall-clock budget for the whole [`ProdMachineSourceGate::acquire`]
/// call — see [`seed_platform_x86::time::MACHINE_ACQUISITION_BUDGET_MS`]
/// for the exact value and its rationale. Re-exported at this call site
/// under its own name so this module's own doc comments can reference it
/// directly.
pub use seed_platform_x86::time::MACHINE_ACQUISITION_BUDGET_MS;

impl ProdMachineSourceGate {
    #[must_use]
    pub fn new() -> Self {
        Self {
            policy: seed_protocol::policy::parse(POLICY_TOML).ok(),
            clock: seed_platform_x86::time::CalibratedTsc::calibrate(),
        }
    }
}

impl Default for ProdMachineSourceGate {
    fn default() -> Self {
        Self::new()
    }
}

impl MachineSourceGate for ProdMachineSourceGate {
    /// SPEC §15.3/§18.2 ("RDRAND alone never enables this mode in version
    /// 1"): each mechanism is sampled independently into its own local
    /// `Option<AcquiredSource>` and the pass/fail decision is delegated to
    /// [`crate::flow_secret::machine::assemble_acquired_sources`]
    /// (host-tested there), rather than an inline `acquired_any`
    /// OR-of-three-booleans that could not tell "RDRAND alone" apart from
    /// "EFI RNG or RDSEED succeeded" — see that function's own doc
    /// comment for the full rationale.
    ///
    /// See this struct's own doc comment for the wall-clock deadline this
    /// call now enforces across all three mechanisms.
    fn acquire(
        &mut self,
        into: &mut AcquiredSources,
        observer: &mut dyn seed_platform_x86::rng::progress::AcquisitionObserver,
    ) -> Result<(), MachineAcquisitionError> {
        let Some(policy) = &self.policy else {
            return Err(MachineAcquisitionError::NoSourceAvailable);
        };
        // Fail closed on a broken/implausible clock: zero entropy
        // instructions are ever executed rather than trusting an
        // uncalibrated deadline (see `CalibratedTsc::calibrate`'s own
        // doc comment for the plausibility window this already enforced).
        let Some(clock) = self.clock.as_mut() else {
            return Err(MachineAcquisitionError::NoSourceAvailable);
        };
        let mut deadline =
            seed_platform_x86::time::Deadline::start(clock, MACHINE_ACQUISITION_BUDGET_MS);

        // Tracks whether any *primary* (non-supplementary) mechanism's
        // failure was specifically a deadline expiry, for the SPEC §21
        // failure-screen wording only — never for control flow (see this
        // struct's own doc comment).
        let mut primary_timed_out = false;

        // EFI RNG (SPEC §15.1).
        let efi_rng_source = if policy.efi_rng.approved {
            seed_platform_x86::rng::efi_rng::uefi_backend::locate().ok().and_then(|mut rng_protocol| {
                let mut provider =
                    seed_platform_x86::rng::efi_rng::uefi_backend::RealEfiRng::new(&mut rng_protocol);
                match seed_platform_x86::rng::efi_rng::sample(
                    &mut provider,
                    &policy.efi_rng,
                    // The EFI final read is pinned to its own block size, NOT
                    // the shared machine-source cap: L2 raised that cap to 64,
                    // and inheriting it here would grow the EFI record to 64 and
                    // silently disable the L1 repeat-check (32-byte diagnostic
                    // vs 64-byte read never compare equal). See
                    // `efi_rng::EFI_RNG_REQUEST_BYTES`.
                    seed_platform_x86::rng::efi_rng::EFI_RNG_REQUEST_BYTES,
                    &mut deadline,
                ) {
                    Ok(record) => AcquiredSource::new(record.tag(), record.algo_id(), record.bytes()),
                    Err(seed_platform_x86::rng::efi_rng::EfiRngError::DeadlineExceeded) => {
                        primary_timed_out = true;
                        None
                    }
                    Err(_) => None,
                }
            })
        } else {
            None
        };

        // RDSEED64 (SPEC §15.2).
        let rdseed_source = if policy.rdseed.approved {
            let cpuid = virt::cpuid::RealCpuid;
            let mut raw = seed_platform_x86::rng::raw::RealRdseed64;
            match seed_platform_x86::rng::rdseed::sample(&cpuid, &mut raw, policy, &mut deadline, observer) {
                Ok(record) => AcquiredSource::new(record.tag(), record.algo_id(), record.bytes()),
                Err(seed_platform_x86::rng::rdseed::Rdseed64Error::DeadlineExceeded) => {
                    primary_timed_out = true;
                    None
                }
                Err(_) => None,
            }
        } else {
            None
        };

        // RDRAND (SPEC §15.3, supplementary only). Its result is only
        // ever *counted* by `assemble_acquired_sources` below, never
        // treated as sufficient by itself — including when it times out:
        // RDRAND is never a primary mechanism, so its own deadline expiry
        // never sets `primary_timed_out` (a deadline that expires after a
        // primary already succeeded simply omits RDRAND, per SPEC
        // §15.3's supplementary-only contract).
        let rdrand_source = if policy.rdrand.approved {
            let cpuid = virt::cpuid::RealCpuid;
            let mut raw = seed_platform_x86::rng::raw::RealRdrand64;
            seed_platform_x86::rng::rdrand::sample(&cpuid, &mut raw, &policy.rdrand, &mut deadline, observer)
                .ok()
                .and_then(|record| AcquiredSource::new(record.tag(), record.algo_id(), record.bytes()))
        } else {
            None
        };

        crate::flow_secret::machine::assemble_acquired_sources(
            efi_rng_source,
            rdseed_source,
            rdrand_source,
            into,
        )
        .map_err(|e| {
            if primary_timed_out {
                MachineAcquisitionError::SourceTimedOut
            } else {
                e
            }
        })
    }
}

// ============================================================================
// Shutdown / fault hook
// ============================================================================

/// Real `EfiResetShutdown` request (SPEC §26 step 7).
///
/// `uefi::runtime::reset` is typed `-> !` (the crate's binding assumes
/// the firmware call never returns control) — on real hardware a
/// successful shutdown never does. This adapter's `request_shutdown`
/// still returns a `Result` so [`crate::flow_secret::shutdown::
/// scrub_and_shutdown`]'s host-testable retry-once/halt logic (already
/// exhaustively tested against a mock, `seed-flow`'s own test suite) can
/// drive it uniformly; in the never-actually-observed case that control
/// somehow returns anyway, that is itself the SPEC §26 failure
/// condition, which the caller's halt loop (`ProdFaultHook::halt`,
/// below) still terminates safely.
pub struct ProdShutdown;

impl ShutdownProvider for ProdShutdown {
    fn request_shutdown(&mut self) -> Result<(), ShutdownFailure> {
        uefi::runtime::reset(uefi::runtime::ResetType::SHUTDOWN, uefi::Status::SUCCESS, None)
    }
}

/// Real [`FaultHook`]: every `before_*` step is a no-op (no fault
/// injection in production), and `halt` uses the real
/// `seed_platform_x86::boot::halt_forever` (`hlt`-loop) instead of the
/// trait's spin-loop default.
pub struct ProdFaultHook;

impl FaultHook for ProdFaultHook {
    fn halt(&mut self) -> ! {
        seed_platform_x86::boot::halt_forever()
    }
}

// ============================================================================
// AliasedInput + run_secret_phase
// ============================================================================

/// A single UEFI `SIMPLE_TEXT_INPUT_PROTOCOL` handle, aliased between two
/// stateless wrapper roles (SPEC §22.1-style `MenuKeySource` pre-secret,
/// SPEC §12.3 no-echo `KeySource` post-secret) that this ceremony never
/// invokes concurrently.
///
/// [`crate::flow_secret::SecretProviders`] needs both a `menu_keys` and a
/// `secret_keys` field alive for the *entire* [`run_secret_phase`] call
/// (the state-machine-driven dispatch inside `run_secret_flow` switches
/// between them at different points in that one call, never holding both
/// borrows "in use" at once, but the Rust borrow checker only sees that
/// both fields exist for the whole call and would otherwise reject two
/// simultaneous `&mut Input` borrows of the same object).
/// [`FirmwareKeySource`] is a stateless wrapper holding nothing but the
/// borrowed reference, so reconstructing a fresh, immediately-dropped
/// wrapper instance on every single key read (rather than holding one
/// persistently) is behaviorally identical to holding it persistently,
/// and lets this type store only a raw pointer plus reborrow it
/// transiently per call instead.
///
/// STEP D dedup: this type needs only the one explicit
/// `seed_platform_x86::input::KeySource` impl below (the SPEC §12.3
/// no-echo role) — `crate::keys::MenuKeySource`'s blanket impl for any
/// `KeySource` (see that module's own doc comment) supplies the SPEC
/// §22.1-style menu-key role automatically, so there is no second,
/// hand-written impl to keep in sync with it.
struct AliasedInput(*mut Input);

// SAFETY: `AliasedInput` is constructed once in `run_secret_phase` from a
// `&mut Input` that outlives the whole ceremony. Each method call below
// materializes exactly one `&mut Input` reborrow, uses it for the
// duration of one blocking key read, and drops it before returning --
// never two live reborrows at once, and this application is
// single-threaded with no reentrant interrupt handling of this code
// path, so the `menu_keys`/`secret_keys` roles (used at different,
// non-overlapping points of the same sequential state-machine dispatch,
// both ultimately calling this same impl -- see this type's own doc
// comment for why one impl now serves both) never actually alias a
// *live* `&mut Input` at the same instant despite both being reachable
// through the same `SecretProviders` value.
impl seed_platform_x86::input::KeySource for AliasedInput {
    fn read_key_blocking(&mut self) -> seed_platform_x86::input::InputEvent {
        let input = unsafe { &mut *self.0 };
        FirmwareKeySource::new(input).read_key_blocking()
    }
}

/// A single GOP linear framebuffer, aliased between two roles
/// [`crate::flow_secret::SecretProviders`] needs alive simultaneously
/// (SPEC.md amendment 2026-08-06): the pre-`MnemonicDisplay`
/// [`crate::output::FbTextOutput`] text role (`p.text_out`) and the
/// [`seed_core::contracts::Framebuffer`] role every screen from
/// `AppState::MnemonicDisplay` onward uses directly (`p.fb`). Mirrors
/// [`AliasedInput`]'s exact precedent and safety argument above, applied
/// to the framebuffer instead of the keystroke source: both roles are
/// stateless wrappers around nothing but the pointer, and this crate's
/// own driver never renders through both roles within the same screen (see
/// [`run_secret_phase`]'s own doc comment for the exact boundary), each
/// screen beginning with its own `clear`/scrub of the framebuffer it
/// touches.
struct AliasedFb(*mut seed_gop_ui::gop::framebuffer::LinearFramebuffer);

// SAFETY: `AliasedFb` is constructed twice in `run_secret_phase`, both
// times from the one `&mut LinearFramebuffer` (the session framebuffer,
// `SessionGop::fb`) that outlives the whole ceremony. Each method call
// below materializes exactly one `&mut LinearFramebuffer` reborrow, uses
// it for the duration of one draw/scrub call, and drops it before
// returning -- never two live reborrows at once, and (see
// `AliasedInput`'s own safety comment for the identical argument in
// full) this application is single-threaded with no reentrant dispatch
// of this code path, so the `text_out`/`fb` roles -- used at different,
// non-overlapping points of the same sequential state-machine dispatch
// (`text_out` only strictly before `AppState::MnemonicDisplay`, `fb`
// only from `AppState::MnemonicDisplay` onward) -- never actually alias
// a *live* `&mut LinearFramebuffer` at the same instant despite both
// being reachable through the same `SecretProviders` value.
impl seed_core::contracts::Framebuffer for AliasedFb {
    fn dims(&self) -> (u32, u32) {
        let fb = unsafe { &*self.0 };
        fb.dims()
    }

    fn put_row(&mut self, x: u32, y: u32, px: &[u32]) {
        let fb = unsafe { &mut *self.0 };
        fb.put_row(x, y, px);
    }
}

/// Run the complete secret-phase ceremony (SPEC §17.4 onward) with real
/// firmware providers, starting from the state machine
/// `run_pre_secret_flow` handed off (`AppState::MachineEntropyAcquisition`
/// / `AppState::PhysicalCollection`).
///
/// `production_marker` is threaded into this call's own [`ProdPolicyGates`]
/// instance (used here only for [`MachineAvailabilityGate`]'s SPEC §18.2
/// disclosure — the same instance's `production_markers_verified` field
/// is never read during the secret phase) purely so every construction
/// of [`ProdPolicyGates`] anywhere in a given edition agrees on the same
/// marker, matching the parameter every other constructor in this module
/// takes.
///
/// SPEC.md amendment 2026-08-06: `fb` is the SAME session framebuffer
/// [`open_session_gop`] opened once at process start, threaded straight
/// through by the caller (`main.rs`) — this function no longer opens (or
/// re-opens) the GOP itself. A second `set_mode` mid-ceremony would blank
/// the display, and re-opening risks the exact real-hardware
/// firmware-console disconnect `seed_gop_ui::gop::backend`'s own module
/// doc documents; both risks are structurally impossible now that there
/// is only ever one open, held for the whole ceremony. Never returns
/// except in the one narrow pre-secret case
/// [`crate::flow_secret::run_secret_flow`] itself documents
/// (`SecretFlowOutcome::ExitedToFirmwareBeforeSecret`) -- every other
/// path ends in `EfiResetShutdown` or a non-returning halt.
///
/// The secret phase is NOT framebuffer-only from the start: the
/// state-machine dispatch in `flow_secret::driver` renders every screen
/// from `AppState::MachineEntropyAcquisition` through
/// `AppState::FinalGenerationConfirmation` -- machine-entropy
/// acquisition, physical dice/coin entry, entropy-mode + instrument
/// selection, the composition panel, and the final confirmation prompt
/// -- through `p.text_out`, a [`crate::output::FbTextOutput`] over an
/// [`AliasedFb`] reborrow of this very `fb` (SPEC.md amendment
/// 2026-08-06: no longer firmware text output — see that type's own doc
/// comment), and the two pre-secret returns (`AppState::
/// SetupSelection`, `AppState::ExitToFirmware`) hand control back to
/// `main.rs`'s own GOP-rendered firmware-exit path. Only `AppState::
/// MnemonicDisplay` onward (mnemonic display, destroy confirmation,
/// scrub, hidden re-entry, passphrase, derivation verification incl. the
/// custom-path builder, completion education, and shutdown) draws
/// through `p.fb`, a second [`AliasedFb`] reborrow of the same
/// framebuffer. Both reborrows alias the identical pixels -- see
/// [`AliasedFb`]'s own doc comment for why that is sound here.
pub fn run_secret_phase(
    mut sm: seed_protocol::state::StateMachine,
    stdin: &mut Input,
    fb: &mut seed_gop_ui::gop::framebuffer::LinearFramebuffer,
    production_marker: Option<fn() -> bool>,
    instrument: crate::flow_secret::physical::Instrument,
    build_id: &'static str,
    recap: crate::diagnostics::DiagRecap,
) -> SecretFlowOutcome {
    let fb_ptr: *mut seed_gop_ui::gop::framebuffer::LinearFramebuffer = fb;
    let mut text_out_fb = AliasedFb(fb_ptr);
    let mut output = crate::output::FbTextOutput::new(&mut text_out_fb);
    let mut post_secret_fb = AliasedFb(fb_ptr);
    let input_ptr: *mut Input = stdin;
    let mut menu_keys = AliasedInput(input_ptr);
    let mut secret_keys = AliasedInput(input_ptr);
    let mut watchdog = production_watchdog();
    let mut machine_availability = ProdPolicyGates::new(production_marker);
    let mut machine_gate = ProdMachineSourceGate::new();
    let mut shutdown = ProdShutdown;
    let mut fault_hook = ProdFaultHook;

    let policy_ver = seed_protocol::policy::parse(POLICY_TOML).map(|p| p.version).unwrap_or(0);

    let mut arena = seed_core::arena::SecretArena::new();
    // SHOULD-FIX #5 (SPEC §20.4/§27.3): register this ceremony's one live
    // arena so a `#[panic_handler]` (which cannot receive arbitrary
    // extra parameters -- see `seed_core::arena`'s own doc comment on
    // `PANIC_SCRUB_ARENA`) has a best-effort chance to scrub it if a
    // panic ever fires while it is live.
    //
    // SAFETY: `arena` is never moved after this call -- every use below
    // is through `&mut arena`/`providers` borrows, and this function's
    // own body is the entirety of `arena`'s lexical scope -- and this
    // function unregisters it immediately below before that scope ends
    // on every path that returns normally (the only path that does:
    // every other path ends in `shutdown::scrub_and_shutdown`, itself
    // non-returning, so this registration intentionally stays live for
    // the rest of the program's execution on those paths).
    unsafe {
        arena.register_for_panic_scrub();
    }
    let mut providers = crate::flow_secret::SecretProviders {
        text_out: &mut output,
        menu_keys: &mut menu_keys,
        fb: &mut post_secret_fb,
        secret_keys: &mut secret_keys,
        machine_availability: &mut machine_availability,
        machine_gate: &mut machine_gate,
        shutdown: &mut shutdown,
        fault_hook: &mut fault_hook,
        // SPEC_DICE_COIN_VISUAL.md §22.5a: the pre-secret instrument
        // sub-selection, threaded from `FlowResult::instrument`.
        instrument,
        // SPEC_PASSPHRASE §8.2: bootable UEFI (both the production and test
        // editions share this wiring) requires the fail-closed extended
        // printable-ASCII keyboard self-test before passphrase entry.
        passphrase_policy: crate::flow_secret::passphrase::PassphraseKeyboardPolicy::RequireExtendedSelfTest,
        // 2026-08-07 ceremony redesign: the edition's SPEC §4.1 build
        // identifier (chrome header band) and the SPEC §22.3 recap the
        // Stage-3 Setup screen folds in, both threaded from the pre-secret
        // flow's `FlowResult` so backing into `AppState::SetupSelection`
        // re-renders the identical screen.
        build_id,
        recap,
    };

    let outcome = crate::flow_secret::run_secret_flow(
        &mut sm,
        &mut arena,
        &mut watchdog,
        seed_core::contracts::ArchId::X86_64,
        policy_ver,
        &mut providers,
    );
    // Reached on the three returning outcomes: the two pre-secret exits
    // (`ExitedToFirmwareBeforeSecret`, `BackBeforeSecret`) and the SPEC §26
    // amendment (2026-08-08) `DestroyedReturnToMenu` — on the last, the
    // full scrub has already run inside `run_secret_flow`, so `arena` is
    // already zeroed here (its own `Drop` re-scrub is idempotent). Every
    // other post-secret path is non-returning (`scrub_and_shutdown`).
    // Unregister before `arena` goes out of scope so no stale pointer
    // outlives this function.
    seed_core::arena::SecretArena::unregister_for_panic_scrub();
    outcome
}
