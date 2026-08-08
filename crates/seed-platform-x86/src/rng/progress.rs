//! Progress observation for machine-source acquisition (SPEC §21's
//! "acquiring machine entropy" screen): a counts-only callback so a
//! legitimately slow-but-working source can show visible progress instead
//! of looking frozen, with zero risk of leaking secret bytes through the
//! channel — see [`AcquisitionObserver`]'s own doc comment.

/// Notified once per successfully collected raw 64-bit value (i.e. once
/// per accepted [`super::raw::RawSample`] with `success: true`), by
/// [`super::raw::collect_block`].
///
/// Carries no data beyond the bare fact that one more value was
/// collected — never the value itself, never a byte count, never timing
/// beyond what a caller can already observe by watching wall-clock time
/// pass between calls. A rendered "progress dot" per tick reveals only
/// that *a* DRBG round completed, not any output bit.
pub trait AcquisitionObserver {
    /// One more raw value was successfully collected.
    fn value_collected(&mut self);
}

/// An [`AcquisitionObserver`] that does nothing — the default for every
/// call site (existing tests, `RDRAND`/`RDSEED`/`EFI-RNG` unit tests) that
/// does not care about progress ticks.
pub struct NullObserver;

impl AcquisitionObserver for NullObserver {
    fn value_collected(&mut self) {}
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;

    struct CountingObserver {
        ticks: usize,
    }
    impl AcquisitionObserver for CountingObserver {
        fn value_collected(&mut self) {
            self.ticks += 1;
        }
    }

    #[test]
    fn null_observer_is_a_no_op() {
        // Only demonstrates it compiles and can be called freely; there
        // is no state to assert on a deliberate no-op.
        let mut obs = NullObserver;
        obs.value_collected();
        obs.value_collected();
    }

    #[test]
    fn counting_observer_counts_every_tick() {
        let mut obs = CountingObserver { ticks: 0 };
        obs.value_collected();
        obs.value_collected();
        obs.value_collected();
        assert_eq!(obs.ticks, 3);
    }
}
