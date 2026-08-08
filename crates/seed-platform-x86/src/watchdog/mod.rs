//! Owned by WP-18 (SPEC §11.1). UEFI watchdog disablement and per-transition
//! re-assertion.
//!
//! SPEC §11.1 requires the application to disable the UEFI watchdog
//! immediately after startup by calling `SetWatchdogTimer` with a zero
//! timeout and confirming the returned status is success, and — because
//! UEFI provides no watchdog-state getter — to re-assert the zero timeout
//! at every major state transition (§21), treating any re-assertion
//! failure after final entropy exists as fatal (routed to scrub-and-
//! shutdown). Generation MUST be refused if the initial disablement call
//! fails.
//!
//! This module is host-testable via [`WatchdogTimer`], a trait over the
//! single firmware call it needs. Production code wires [`UefiWatchdog`]
//! (SPEC §31 permits direct UEFI protocol access from platform code);
//! tests use a mock that can be programmed to fail on demand.

#![allow(clippy::module_name_repetitions)]

/// Abstraction over the single UEFI firmware call this module depends on
/// (`EFI_BOOT_SERVICES.SetWatchdogTimer`, SPEC §11.1).
///
/// Implemented for the real firmware call by [`UefiWatchdog`] and, in
/// host tests, by a mock double so `disable()`/`reassert()` logic is
/// verifiable without a UEFI environment.
pub trait WatchdogTimer {
    /// Set the watchdog timer.
    ///
    /// `timeout_seconds == 0` disables the watchdog (SPEC §11.1). A
    /// non-zero `watchdog_code` is reserved for future use by callers
    /// that want to distinguish log entries; this module always passes
    /// `0` since it never expects the timer to actually fire.
    ///
    /// Returns `Ok(())` on firmware success, `Err(raw_status)` otherwise,
    /// where `raw_status` is the platform-specific status code (mirrors
    /// `uefi::Status`'s numeric representation without depending on the
    /// `uefi` crate at the trait boundary, keeping this module host-
    /// testable without a UEFI target).
    fn set_watchdog_timer(&mut self, timeout_seconds: usize, watchdog_code: u64) -> Result<(), u64>;
}

/// Failure classification for watchdog operations (SPEC §11.1).
///
/// The two call sites carry different consequences: an initial-disable
/// failure means generation must never start; a re-assertion failure
/// after final entropy exists is fatal and must route to scrub-and-
/// shutdown. This type lets a caller (the state machine, WP-23) select
/// the correct response without re-deriving that distinction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogFailure {
    /// The initial post-startup disablement call did not return success.
    /// SPEC §11.1: "Refuse generation if the initial disablement call
    /// fails."
    InitialDisableFailed {
        /// Raw firmware status code returned by the failed call.
        status: u64,
    },
    /// A re-assertion call at a state transition did not return success.
    /// SPEC §11.1: treated as fatal once final entropy exists; callers
    /// earlier in the flow may still choose to refuse/abort rather than
    /// continue with an unconfirmed watchdog state.
    ReassertFailed {
        /// Raw firmware status code returned by the failed call.
        status: u64,
    },
}

impl WatchdogFailure {
    /// The raw firmware status code carried by this failure, regardless
    /// of which call site produced it.
    #[must_use]
    pub const fn status(&self) -> u64 {
        match self {
            Self::InitialDisableFailed { status } | Self::ReassertFailed { status } => *status,
        }
    }
}

/// Watchdog code Alea passes to `SetWatchdogTimer`. Values 0..=0xffff
/// are reserved for internal firmware use (SPEC-adjacent UEFI spec note
/// reproduced in the `uefi` crate); Alea never expects the timer to
/// fire, so any value outside that reserved range is fine. Chosen
/// arbitrarily and stable so log entries (if the firmware ever did log
/// one) are identifiable.
const WATCHDOG_CODE: u64 = 0x5EED_0000;

/// Watchdog controller: disables the firmware watchdog at startup and
/// re-asserts that disablement at every major state transition (SPEC
/// §11.1).
///
/// Generic over [`WatchdogTimer`] so production code can plug in the real
/// `EFI_BOOT_SERVICES.SetWatchdogTimer` call while host tests plug in a
/// mock.
pub struct Watchdog<T: WatchdogTimer> {
    timer: T,
    /// Set once `disable()` has returned successfully. `reassert()`
    /// refuses to run until this is true, since re-asserting before the
    /// initial disable makes no sense and SPEC §11.1 orders the two
    /// calls strictly (initial disable, then per-transition re-assert).
    disabled: bool,
}

impl<T: WatchdogTimer> Watchdog<T> {
    /// Build a new controller around `timer`, not yet disabled.
    #[must_use]
    pub const fn new(timer: T) -> Self {
        Self {
            timer,
            disabled: false,
        }
    }

    /// Immediately-after-startup watchdog disablement (SPEC §11.1).
    ///
    /// Calls `SetWatchdogTimer` with a zero timeout and status-checks the
    /// result. On success, marks this controller disabled so subsequent
    /// `reassert()` calls are permitted. On failure, returns
    /// [`WatchdogFailure::InitialDisableFailed`] and the caller MUST
    /// refuse generation (SPEC §11.1) — this function does not enforce
    /// that itself, since the "refuse generation" response belongs to
    /// the state machine (WP-23), not this platform module.
    pub fn disable(&mut self) -> Result<(), WatchdogFailure> {
        match self.timer.set_watchdog_timer(0, WATCHDOG_CODE) {
            Ok(()) => {
                self.disabled = true;
                Ok(())
            }
            Err(status) => Err(WatchdogFailure::InitialDisableFailed { status }),
        }
    }

    /// Per-major-state-transition re-assertion (SPEC §21, §11.1).
    ///
    /// UEFI provides no watchdog-state getter, so "remains disabled"
    /// cannot be tested directly; instead the application re-asserts the
    /// zero timeout at every major state transition. This function
    /// status-checks that re-assertion call.
    ///
    /// Returns [`WatchdogFailure::ReassertFailed`] on firmware failure —
    /// the caller (state machine) is responsible for treating this as
    /// fatal once final entropy exists, routing to scrub-and-shutdown
    /// per SPEC §11.1.
    ///
    /// # Panics
    ///
    /// Panics if called before [`disable`](Self::disable) has succeeded
    /// once. The state machine must never reach a transition point
    /// without having disabled the watchdog first; a call here in that
    /// state indicates a caller ordering bug, not a runtime/firmware
    /// condition, so it is not modeled as a recoverable `Result` variant.
    pub fn reassert(&mut self) -> Result<(), WatchdogFailure> {
        assert!(
            self.disabled,
            "watchdog reassert() called before disable() succeeded"
        );
        match self.timer.set_watchdog_timer(0, WATCHDOG_CODE) {
            Ok(()) => Ok(()),
            Err(status) => Err(WatchdogFailure::ReassertFailed { status }),
        }
    }

    /// Whether the initial disablement has succeeded at least once.
    #[must_use]
    pub const fn is_disabled(&self) -> bool {
        self.disabled
    }
}

/// Production [`WatchdogTimer`] implementation wrapping
/// `uefi::boot::set_watchdog_timer` (SPEC §31: platform code may call
/// UEFI protocols directly).
///
/// Zero-sized: the underlying call is a free function against the global
/// boot-services table, so this type carries no state of its own.
#[cfg(target_os = "uefi")]
pub struct UefiWatchdog;

#[cfg(target_os = "uefi")]
impl UefiWatchdog {
    /// Construct the production watchdog-timer adapter.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[cfg(target_os = "uefi")]
impl Default for UefiWatchdog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "uefi")]
impl WatchdogTimer for UefiWatchdog {
    fn set_watchdog_timer(&mut self, timeout_seconds: usize, watchdog_code: u64) -> Result<(), u64> {
        uefi::boot::set_watchdog_timer(timeout_seconds, watchdog_code, None)
            .map_err(|e| e.status().0 as u64)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    /// Mock [`WatchdogTimer`] for host tests: records every call and can
    /// be programmed to fail on a specific call index (1-based) or
    /// always fail from a threshold onward.
    struct MockTimer {
        calls: std::vec::Vec<(usize, u64)>,
        /// If `Some(n)`, the nth call (1-based) fails with the given
        /// status; all other calls succeed.
        fail_on_call: Option<(usize, u64)>,
    }

    impl MockTimer {
        fn new() -> Self {
            Self {
                calls: std::vec::Vec::new(),
                fail_on_call: None,
            }
        }

        fn failing_on(call_index: usize, status: u64) -> Self {
            Self {
                calls: std::vec::Vec::new(),
                fail_on_call: Some((call_index, status)),
            }
        }
    }

    impl WatchdogTimer for MockTimer {
        fn set_watchdog_timer(
            &mut self,
            timeout_seconds: usize,
            watchdog_code: u64,
        ) -> Result<(), u64> {
            self.calls.push((timeout_seconds, watchdog_code));
            let call_index = self.calls.len();
            if let Some((fail_at, status)) = self.fail_on_call {
                if call_index == fail_at {
                    return Err(status);
                }
            }
            Ok(())
        }
    }

    #[test]
    fn disable_succeeds_and_marks_controller_disabled() {
        let mut wd = Watchdog::new(MockTimer::new());
        assert!(!wd.is_disabled());
        assert!(wd.disable().is_ok());
        assert!(wd.is_disabled());
    }

    #[test]
    fn disable_passes_zero_timeout() {
        let mut wd = Watchdog::new(MockTimer::new());
        wd.disable().unwrap();
        assert_eq!(wd.timer.calls, std::vec![(0usize, WATCHDOG_CODE)]);
    }

    #[test]
    fn disable_failure_is_classified_as_initial_disable_failed() {
        let mut wd = Watchdog::new(MockTimer::failing_on(1, 0xDEAD));
        let err = wd.disable().unwrap_err();
        assert_eq!(err, WatchdogFailure::InitialDisableFailed { status: 0xDEAD });
        assert_eq!(err.status(), 0xDEAD);
        assert!(!wd.is_disabled(), "failed disable must not mark disabled");
    }

    #[test]
    fn reassert_succeeds_after_disable() {
        let mut wd = Watchdog::new(MockTimer::new());
        wd.disable().unwrap();
        assert!(wd.reassert().is_ok());
        assert!(wd.reassert().is_ok());
        assert_eq!(wd.timer.calls.len(), 3); // 1 disable + 2 reassert
    }

    #[test]
    fn reassert_passes_zero_timeout_every_time() {
        let mut wd = Watchdog::new(MockTimer::new());
        wd.disable().unwrap();
        wd.reassert().unwrap();
        for (timeout, code) in &wd.timer.calls {
            assert_eq!(*timeout, 0);
            assert_eq!(*code, WATCHDOG_CODE);
        }
    }

    #[test]
    fn reassert_failure_is_classified_as_reassert_failed() {
        // Call 1 (disable) succeeds, call 2 (first reassert) fails.
        let mut wd = Watchdog::new(MockTimer::failing_on(2, 0xBEEF));
        wd.disable().unwrap();
        let err = wd.reassert().unwrap_err();
        assert_eq!(err, WatchdogFailure::ReassertFailed { status: 0xBEEF });
        assert_eq!(err.status(), 0xBEEF);
    }

    #[test]
    fn reassert_continues_to_be_callable_after_a_failure() {
        // Only call 2 fails; a later reassert (call 3) should succeed,
        // demonstrating the controller doesn't wedge itself after one
        // failed re-assertion (the fatal-routing decision belongs to the
        // caller, not this module).
        let mut wd = Watchdog::new(MockTimer::failing_on(2, 0xBEEF));
        wd.disable().unwrap();
        assert!(wd.reassert().is_err());
        assert!(wd.reassert().is_ok());
    }

    #[test]
    #[should_panic(expected = "reassert() called before disable() succeeded")]
    fn reassert_before_disable_panics() {
        let mut wd = Watchdog::new(MockTimer::new());
        let _ = wd.reassert();
    }

    #[test]
    #[should_panic(expected = "reassert() called before disable() succeeded")]
    fn reassert_after_failed_disable_still_panics() {
        // A failed disable() must NOT flip `disabled`, so reassert()
        // should still refuse to run.
        let mut wd = Watchdog::new(MockTimer::failing_on(1, 1));
        let _ = wd.disable();
        let _ = wd.reassert();
    }

    #[test]
    fn watchdog_failure_is_not_copy_of_secret_data() {
        // Sanity check: this type carries only a status code, never
        // secret material, so Debug/Clone/Copy/PartialEq/Eq are fine
        // here (unlike secret-bearing types, SPEC §13/§20).
        let f = WatchdogFailure::InitialDisableFailed { status: 5 };
        let g = f;
        assert_eq!(f, g);
    }
}
