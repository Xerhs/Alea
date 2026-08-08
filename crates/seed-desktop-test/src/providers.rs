//! Desktop implementations of every `seed-flow` provider trait this crate
//! needs (SPEC §4.3): the four SPEC §11 mandatory-gate traits, the SPEC
//! §22.5 machine-availability gate, a no-op watchdog timer, the SPEC §26
//! shutdown provider and fault hook, and the (never-reachable, see
//! [`NeverCalledMachineGate`]) machine-source acquisition gate.
//!
//! None of these perform a real security check: there is no UEFI firmware,
//! no real virtualization/console/graphics/crypto self-test environment
//! and no real machine entropy source on a desktop OS. Every gate here is
//! either an honest "not applicable in this rehearsal" `Clean` result or,
//! for machine-source availability, an honest permanent "unavailable" —
//! which is precisely what SPEC §4.3 requires ("no operating-system RNG
//! mode"): with both [`SourceAvailability`] queries always `false`,
//! `seed_flow::entropy_avail::compute_mode_availability` disables both
//! `Combined` and `MachineOnly`, leaving dice/coin entry ([`EntropyMode::
//! DiceOnly`]) as the only mode ever offered, so
//! `AppState::MachineEntropyAcquisition` is structurally unreachable —
//! [`NeverCalledMachineGate::acquire`] panics if this crate's own contract
//! is ever violated.

use seed_flow::diagnostics::{
    CheckOutcome, ConsoleCheckResult, ConsoleGate, CryptoCheckResult, CryptoSelfTestGate, GraphicsCheckResult,
    GraphicsGate, GraphicsInfo, PlatformCheckResult, PlatformGate, PlatformInfo, PlatformInfoGate, SecureBootStatus,
};
use seed_flow::entropy_avail::{MachineAvailabilityGate, SourceAvailability};
use seed_flow::flow_secret::machine::{AcquiredSources, MachineAcquisitionError, MachineSourceGate};
use seed_flow::flow_secret::shutdown::{FaultHook, ShutdownFailure, ShutdownProvider};
use seed_platform_x86::watchdog::WatchdogTimer;
use seed_protocol::state::ErrorClass;

/// SPEC §4.3: this rehearsal edition performs no real firmware/hardware
/// checks at all — every SPEC §11 mandatory gate reports `Clean`
/// unconditionally, with wording that says so plainly rather than
/// implying a real check ran (the same "not proof"/honesty discipline
/// SPEC §22.3 requires of the real checks, applied here to the fact that
/// no check happens at all).
#[derive(Debug, Clone, Copy)]
pub struct DesktopGates {
    pub window_width: u32,
    pub window_height: u32,
}

impl PlatformGate for DesktopGates {
    fn check(&mut self) -> PlatformCheckResult {
        PlatformCheckResult {
            outcome: CheckOutcome::Clean,
            error_class: ErrorClass::Platform,
            architecture_line: "desktop rehearsal (not a UEFI platform)",
            virt_summary: "Desktop rehearsal: no real virtualization check is performed -- this is not a security determination.",
        }
    }
}

impl ConsoleGate for DesktopGates {
    fn check(&mut self) -> ConsoleCheckResult {
        ConsoleCheckResult {
            outcome: CheckOutcome::Clean,
            error_class: ErrorClass::ConsoleTopology,
            con_out_paths: 1,
            con_in_paths: 1,
            summary_line: "Desktop rehearsal: this window is the only input/output path -- not a UEFI console check.",
        }
    }
}

impl GraphicsGate for DesktopGates {
    fn check(&mut self) -> GraphicsCheckResult {
        GraphicsCheckResult::Available(GraphicsInfo {
            width: self.window_width,
            height: self.window_height,
            device_path: seed_gop_ui::gop::device_path::DevicePathText::unavailable(),
        })
    }
}

impl CryptoSelfTestGate for DesktopGates {
    fn check(&mut self) -> CryptoCheckResult {
        // SPEC §11.6 describes a firmware-environment known-answer test;
        // there is no equivalent boundary to certify on a desktop OS, and
        // this rehearsal edition does not claim to perform one (SPEC
        // §4.3 is explicit that no desktop build is a production seed
        // generator). Always `Clean` so the rehearsal can proceed.
        CryptoCheckResult { outcome: CheckOutcome::Clean }
    }
}

impl PlatformInfoGate for DesktopGates {
    fn info(&mut self) -> PlatformInfo {
        PlatformInfo {
            // Secure Boot is a UEFI-only concept; honestly `Unknown`
            // rather than fabricating Enabled/Disabled.
            secure_boot: SecureBootStatus::Unknown,
            // No TPM path exists in the desktop rehearsal (SPEC §4.3).
            tpm_status: "n/a",
            // No entropy policy is ever loaded on desktop (no machine
            // source is ever offered -- see the module doc comment).
            entropy_policy_version: None,
            // This is never a production build (SPEC §4.3, §28).
            production_markers_verified: false,
        }
    }
}

impl MachineAvailabilityGate for DesktopGates {
    fn efi_rng(&mut self) -> SourceAvailability {
        SourceAvailability::default()
    }
    fn rdseed(&mut self) -> SourceAvailability {
        SourceAvailability::default()
    }
}

/// Structural proof that this crate never acquires machine entropy (SPEC
/// §4.3): [`DesktopGates::efi_rng`]/[`DesktopGates::rdseed`] always report
/// unavailable, so `AppState::MachineEntropyAcquisition` can never be
/// reached (`seed_flow::entropy_avail::compute_mode_availability` disables
/// both modes that would lead there). If this invariant is ever violated
/// by a future change, this panics loudly instead of silently acquiring
/// anything.
///
/// `crate::ceremony` therefore never constructs a live
/// `dyn MachineSourceGate` at all (there is no state that would ever call
/// one) — this type exists purely as a structural/documentation artifact
/// exercised by its own unit test below, hence `#[allow(dead_code)]` in
/// ordinary (non-test) builds.
#[allow(dead_code)]
pub struct NeverCalledMachineGate;

impl MachineSourceGate for NeverCalledMachineGate {
    fn acquire(
        &mut self,
        _extras: seed_flow::flow_secret::machine::MachineExtras,
        _into: &mut AcquiredSources,
        _observer: &mut dyn seed_platform_x86::rng::progress::AcquisitionObserver,
    ) -> Result<(), MachineAcquisitionError> {
        panic!(
            "seed-desktop-test: MachineSourceGate::acquire was called, but this edition's \
             MachineAvailabilityGate always reports every machine source unavailable (SPEC \
             §4.3: no operating-system RNG mode) -- this indicates the DesktopGates contract \
             was violated elsewhere, not a real acquisition attempt."
        );
    }
}

/// SPEC §11.1 describes a real UEFI firmware call; there is no such call
/// on a desktop OS, and no watchdog to disable. This adapter always
/// succeeds so `seed_flow::run_pre_secret_flow`'s own (unmodified, WP-25-
/// owned) watchdog-ordering logic runs unchanged.
pub struct DesktopWatchdogTimer;

impl WatchdogTimer for DesktopWatchdogTimer {
    fn set_watchdog_timer(&mut self, _timeout_seconds: usize, _watchdog_code: u64) -> Result<(), u64> {
        Ok(())
    }
}

/// SPEC §26 step 7 describes `EfiResetShutdown`; there is no such firmware
/// call on desktop. This provider always reports success — the actual
/// "close the rehearsal" behavior lives in [`FaultHook::halt`] below,
/// which draws a final screen and idles rather than returning control
/// anywhere (SPEC §26 step 8: "never return").
pub struct DesktopShutdown;

impl ShutdownProvider for DesktopShutdown {
    fn request_shutdown(&mut self) -> Result<(), ShutdownFailure> {
        Ok(())
    }
}

/// No-op [`FaultHook`] whose `halt()` spins forever (mirrors
/// `seed_flow::flow_secret::shutdown::NoFaultHook`'s own default) rather
/// than drawing a final screen — used only where a caller already drew
/// its own terminal screen immediately beforehand (see `crate::ceremony`).
pub struct DesktopFaultHook;

impl FaultHook for DesktopFaultHook {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_gates_are_always_clean_and_never_block_generation() {
        let mut g = DesktopGates { window_width: 1024, window_height: 768 };
        assert_eq!(PlatformGate::check(&mut g).outcome, CheckOutcome::Clean);
        assert_eq!(ConsoleGate::check(&mut g).outcome, CheckOutcome::Clean);
        assert_eq!(CryptoSelfTestGate::check(&mut g).outcome, CheckOutcome::Clean);
        match GraphicsGate::check(&mut g) {
            GraphicsCheckResult::Available(info) => {
                assert_eq!(info.width, 1024);
                assert_eq!(info.height, 768);
            }
            GraphicsCheckResult::Refused(r) => panic!("unexpected refusal: {r}"),
        }
    }

    #[test]
    fn machine_availability_is_always_unavailable() {
        let mut g = DesktopGates { window_width: 800, window_height: 600 };
        let rng = MachineAvailabilityGate::efi_rng(&mut g);
        let seed = MachineAvailabilityGate::rdseed(&mut g);
        assert!(!rng.approved);
        assert!(!rng.sole_source_allowed);
        assert!(!seed.approved);
        assert!(!seed.sole_source_allowed);
    }

    #[test]
    #[should_panic(expected = "MachineSourceGate::acquire was called")]
    fn never_called_machine_gate_panics_if_ever_invoked() {
        let mut gate = NeverCalledMachineGate;
        let mut into = AcquiredSources::new();
        let mut obs = seed_platform_x86::rng::progress::NullObserver;
        let _ = gate.acquire(seed_flow::flow_secret::machine::MachineExtras::default(), &mut into, &mut obs);
    }

    #[test]
    fn desktop_watchdog_timer_always_succeeds() {
        let mut t = DesktopWatchdogTimer;
        assert!(t.set_watchdog_timer(0, 0).is_ok());
    }

    #[test]
    fn desktop_shutdown_always_succeeds() {
        let mut s = DesktopShutdown;
        assert!(s.request_shutdown().is_ok());
    }
}
