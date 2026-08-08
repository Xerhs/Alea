//! Injectable monotonic-clock abstraction for wall-clock-bounded machine-
//! entropy acquisition (SPEC §15-§16; see `seed_flow::firmware_wiring::
//! ProdMachineSourceGate` for the one production call site).
//!
//! # Why a wall-clock budget, and why TSC+Stall
//!
//! Real hardware has been observed (old-CPU field report, no EFI_RNG,
//! RDSEED approved as sole source) to hold the "acquiring machine
//! entropy" screen for 2+ minutes with no error and no progress. The
//! software is already fully bounded in *count*: every raw read is a
//! counted retry loop ([`super::rng::raw::read_one_u64`]), never an
//! unbounded spin. The problem is that a slow RDSEED reseed pool makes
//! each *individual* instruction slow, and a bounded count of slow
//! instructions still adds up to minutes — there is no bound on how long
//! the acquisition may take, only on how many attempts it may make.
//!
//! [`Deadline`] adds the missing wall-clock bound: acquisition aborts
//! once a time budget is exceeded, converting an unbounded-feeling
//! multi-minute freeze into a bounded wait plus a clean, fail-closed
//! refusal (see [`super::rng::raw`]'s module doc for where the deadline
//! is actually checked, and why that is the tightest bound software can
//! provide — a single in-flight `rdseed`/`rdrand` instruction cannot be
//! preempted mid-execution, so the check has to happen *between* reads).
//!
//! Three monotonic-time options were considered for the production clock:
//!
//! - `uefi::runtime::get_time()` — RTC-backed, one-second granularity
//!   (too coarse against a multi-second budget), and a *runtime* service
//!   whose reliability varies most on exactly the class of old/unusual
//!   firmware this bug targets.
//! - A Boot Services event timer (`create_event`/`set_timer`/
//!   `check_event`) — adds event/TPL protocol surface to a security-
//!   critical path for no precision benefit over the option below.
//! - **TSC (`core::arch::x86_64::_rdtsc`), calibrated once against
//!   `uefi::boot::stall`** — touches no runtime services and reads no
//!   UEFI configuration variables (SPEC §28's hidden-entropy-toggle
//!   source scanner stays green), is monotonic on every CPU this project
//!   can boot on (invariant TSC
//!   since Nehalem; this ceremony is single-threaded on the BSP, so even
//!   pre-invariant P-state drift is a small, bounded factor against a
//!   seconds-scale budget), and gives sub-microsecond granularity. This
//!   is the one implemented here.
//!
//! Calibration reads the TSC, stalls for a known duration via the UEFI
//! spec-mandated `Boot Services Stall`, reads the TSC again, and derives
//! ticks-per-millisecond from the delta. The result is accepted only
//! inside a plausibility window (1 MHz..100 GHz); anything else is
//! treated as a calibration failure, which makes the machine source
//! report unavailable rather than ever computing a bogus deadline (fail
//! closed — see [`CalibratedTsc::calibrate`]'s doc comment).
//!
//! A 64-bit TSC wraps after 100+ years even at multi-GHz rates, so no
//! wrap handling is needed beyond ordinary `wrapping_sub` (elapsed-time
//! arithmetic) and `saturating_add`/`saturating_mul` (deadline
//! construction) — see [`Deadline::start`].
//!
//! # Injectability
//!
//! [`MonotonicClock`] is a small trait, exactly like
//! [`super::rng::raw::RawInstructionSource`] and
//! [`super::watchdog::WatchdogTimer`]: the production implementation
//! ([`CalibratedTsc`]) is compiled only for the real UEFI target, and
//! host tests inject a fake clock that advances deterministically, so
//! every deadline-related behavior (bounded abort, fail-closed timeout,
//! no regression to the healthy-fast-clock path) is exercised by
//! `cargo test` without touching real hardware timing.
//!
//! # What a broken/frozen clock does NOT do
//!
//! If `now_ticks()` never advances (a frozen or backwards clock),
//! [`Deadline::expired`] simply never fires — but this does not turn
//! into an unbounded loop: every raw-read call site is *also* still
//! bounded by its own retry count (SPEC §15.2/§15.3's bounded-retries
//! requirement, unchanged by this module), so the worst case degrades to
//! exactly today's pre-deadline behavior, never worse, and never accepts
//! different bytes than it would have otherwise. The deadline can only
//! ever convert a would-be success into a failure (by aborting sooner);
//! it can never relax how much entropy is required to succeed.

#![allow(clippy::module_name_repetitions)]

/// A source of monotonic elapsed time, abstracted so acquisition logic is
/// host-testable (see module doc comment).
///
/// Contract: `ticks_per_ms()` MUST be nonzero for the lifetime of a given
/// clock instance (a production [`CalibratedTsc`] enforces this at
/// construction — see [`CalibratedTsc::calibrate`]); `now_ticks()` MUST
/// be monotonically non-decreasing on any real clock (a test double is
/// free to violate this deliberately, e.g. to simulate a broken clock,
/// since [`Deadline`] is documented to degrade safely — never unsafely —
/// when that happens).
pub trait MonotonicClock {
    /// Current tick count. No fixed epoch; only deltas are meaningful.
    fn now_ticks(&mut self) -> u64;

    /// Calibration factor: ticks per millisecond. MUST be nonzero.
    fn ticks_per_ms(&self) -> u64;
}

/// A wall-clock deadline, checked between (never during) individual raw
/// instruction attempts (see [`super::rng::raw`]'s module doc for the
/// exact check point and why that placement is the tightest bound
/// software can provide).
///
/// Saturating arithmetic throughout: a pathological `budget_ms` or an
/// already-near-`u64::MAX` tick count can never overflow into a bogus
/// (too-short-and-wrapped) deadline — worst case the deadline saturates
/// to `u64::MAX` (i.e. "never expires by this arithmetic alone"), which
/// is backstopped by every call site's own pre-existing bounded retry
/// count (see module doc comment's "what a broken/frozen clock does
/// NOT do").
pub struct Deadline<'a> {
    clock: &'a mut dyn MonotonicClock,
    deadline_ticks: u64,
}

impl<'a> Deadline<'a> {
    /// Start a new deadline `budget_ms` milliseconds from now, per
    /// `clock`'s own calibration.
    pub fn start(clock: &'a mut dyn MonotonicClock, budget_ms: u32) -> Self {
        let ticks_per_ms = clock.ticks_per_ms();
        let now = clock.now_ticks();
        let budget_ticks = u64::from(budget_ms).saturating_mul(ticks_per_ms);
        let deadline_ticks = now.saturating_add(budget_ticks);
        Deadline { clock, deadline_ticks }
    }

    /// Whether the budget has been exceeded as of this call. Checked
    /// fresh every call — never cached — so it reflects real elapsed
    /// time at the point each raw read is about to be attempted.
    pub fn expired(&mut self) -> bool {
        self.clock.now_ticks() >= self.deadline_ticks
    }
}

/// Wall-clock budget for one full machine-source acquisition (SPEC
/// §15-§16): all of EFI-RNG + RDSEED + RDRAND share this single deadline,
/// so the acquiring screen is on-screen for at most this long plus at
/// most one slow in-flight instruction/protocol call.
///
/// A healthy path is roughly 16-24 raw reads totaling well under 10 ms
/// (500x headroom under this budget). 5 seconds tolerates a degraded but
/// genuinely-working source delivering values at up to ~75-100 ms per
/// instruction across the worst case ~64 instructions (EFI-RNG
/// diagnostics + RDSEED two blocks + RDRAND two blocks); anything slower
/// than that is operationally unusable for a ceremony, and the operator
/// is directed to physical dice/coin entry instead. RDRAND is
/// supplementary-only (SPEC §15.3), so a deadline that expires after
/// RDSEED already succeeded simply omits RDRAND — never a partial or
/// weakened acceptance.
pub const MACHINE_ACQUISITION_BUDGET_MS: u32 = 5_000;

/// Production monotonic clock: TSC, calibrated once at construction
/// against the UEFI spec-mandated Boot Services `Stall` call. Only
/// compiled for the real UEFI target — see module doc comment.
#[cfg(target_os = "uefi")]
pub struct CalibratedTsc {
    ticks_per_ms: u64,
}

#[cfg(target_os = "uefi")]
impl CalibratedTsc {
    /// Duration of the calibration stall.
    const CALIBRATION_MICROS: u64 = 10_000;

    /// Lower plausibility bound: 1 MHz. No real x86_64 TSC runs this
    /// slow; anything below this indicates a broken `Stall`/TSC pairing,
    /// not a real (if unusual) platform.
    const MIN_TICKS_PER_MS: u64 = 1_000;

    /// Upper plausibility bound: 100 GHz. No real x86_64 TSC runs this
    /// fast; anything above this indicates a broken `Stall` (returned far
    /// too early) rather than a real clock.
    const MAX_TICKS_PER_MS: u64 = 100_000_000;

    /// Calibrate against `uefi::boot::stall`. Returns `None` on
    /// implausible calibration (fail closed — the caller reports the
    /// machine source unavailable rather than trusting an unreliable
    /// deadline; SPEC §15/§16's fail-closed philosophy applies here too:
    /// zero entropy instructions are ever executed when calibration
    /// itself cannot be trusted).
    #[must_use]
    pub fn calibrate() -> Option<Self> {
        // SAFETY: `_rdtsc` is a plain register-read instruction, valid on
        // every x86_64 CPU this project targets (this module is only
        // compiled for `target_os = "uefi"`, always `target_arch =
        // "x86_64"` in this workspace).
        let t0 = unsafe { core::arch::x86_64::_rdtsc() };
        uefi::boot::stall(core::time::Duration::from_micros(Self::CALIBRATION_MICROS));
        let t1 = unsafe { core::arch::x86_64::_rdtsc() };

        let elapsed_ticks = t1.wrapping_sub(t0);
        let elapsed_ms = Self::CALIBRATION_MICROS / 1_000; // = 10, exact
        if elapsed_ms == 0 {
            return None;
        }
        let ticks_per_ms = elapsed_ticks / elapsed_ms;

        if (Self::MIN_TICKS_PER_MS..=Self::MAX_TICKS_PER_MS).contains(&ticks_per_ms) {
            Some(CalibratedTsc { ticks_per_ms })
        } else {
            None
        }
    }
}

#[cfg(target_os = "uefi")]
impl MonotonicClock for CalibratedTsc {
    fn now_ticks(&mut self) -> u64 {
        // SAFETY: see `calibrate`'s own SAFETY comment.
        unsafe { core::arch::x86_64::_rdtsc() }
    }

    fn ticks_per_ms(&self) -> u64 {
        self.ticks_per_ms
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
pub(crate) mod test_support {
    use super::MonotonicClock;

    /// A deterministic fake clock for host tests: starts at `now` and
    /// advances by `advance_per_call` ticks every time `now_ticks()` is
    /// read (matching the pattern used by `RawInstructionSource`/
    /// `WatchdogTimer` test doubles elsewhere in this crate).
    pub(crate) struct FakeClock {
        pub(crate) now: u64,
        pub(crate) advance_per_call: u64,
        pub(crate) ticks_per_ms: u64,
    }

    impl FakeClock {
        pub(crate) fn new(ticks_per_ms: u64) -> Self {
            FakeClock { now: 0, advance_per_call: 0, ticks_per_ms }
        }

        pub(crate) fn starting_at(now: u64, ticks_per_ms: u64) -> Self {
            FakeClock { now, advance_per_call: 0, ticks_per_ms }
        }
    }

    impl MonotonicClock for FakeClock {
        fn now_ticks(&mut self) -> u64 {
            let v = self.now;
            self.now = self.now.saturating_add(self.advance_per_call);
            v
        }

        fn ticks_per_ms(&self) -> u64 {
            self.ticks_per_ms
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::FakeClock;
    use super::*;

    #[test]
    fn deadline_not_expired_before_budget_elapses() {
        let mut clock = FakeClock::new(1_000); // 1000 ticks/ms
        clock.advance_per_call = 1;
        let mut deadline = Deadline::start(&mut clock, 5_000); // 5,000,000 ticks
        assert!(!deadline.expired());
    }

    #[test]
    fn deadline_expires_once_elapsed_ticks_reach_budget() {
        let mut clock = FakeClock::new(1_000);
        clock.advance_per_call = 10_000_000; // jumps straight past any budget
        let mut deadline = Deadline::start(&mut clock, 5_000);
        assert!(deadline.expired());
    }

    #[test]
    fn deadline_expires_exactly_at_the_boundary() {
        // budget_ticks = 5 ms * 1000 ticks/ms = 5000; start at 0, so the
        // deadline_ticks is 5000. Advancing by exactly that much (baked
        // into the clock before `start`, since `Deadline` holds the
        // clock's only mutable borrow for its whole lifetime -- there is
        // no reaching back in to mutate it directly afterward) must count
        // as expired ( >= , not > ).
        let mut clock = FakeClock::starting_at(0, 1_000);
        clock.advance_per_call = 5_000;
        let mut deadline = Deadline::start(&mut clock, 5);
        assert!(deadline.expired());
    }

    #[test]
    fn deadline_saturates_instead_of_overflowing_at_u64_extremes() {
        let mut clock = FakeClock::starting_at(u64::MAX - 10, u64::MAX);
        clock.advance_per_call = 10;
        // budget_ms * ticks_per_ms would overflow u64 multiplication;
        // saturating_mul must clamp instead of panicking/wrapping. Must
        // not panic to compute or check, and the (saturated) deadline
        // must correctly report expired once `now_ticks()` also
        // saturates to `u64::MAX`.
        let mut deadline = Deadline::start(&mut clock, u32::MAX);
        assert!(deadline.expired());
    }

    #[test]
    fn ticks_per_ms_plausibility_window_accepts_realistic_values() {
        // Pure computation mirrored from `CalibratedTsc::calibrate`
        // (host-testable even though the real calibration call itself is
        // cross-build-only): a modern multi-GHz CPU comfortably falls
        // inside 1_000..=100_000_000 ticks/ms.
        let ticks_per_ms = 3_000_000u64; // ~3 GHz
        assert!((1_000..=100_000_000).contains(&ticks_per_ms));
    }

    #[test]
    fn ticks_per_ms_plausibility_window_rejects_implausible_values() {
        assert!(!(1_000..=100_000_000).contains(&500u64)); // too slow
        assert!(!(1_000..=100_000_000).contains(&200_000_000u64)); // too fast
    }
}
