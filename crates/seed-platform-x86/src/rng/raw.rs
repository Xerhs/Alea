//! Raw `RDSEED`/`RDRAND` instruction execution (WP-24, SPEC §15.2, §15.3).
//!
//! The instructions themselves are abstracted behind [`RawInstructionSource`]
//! so [`super::rdseed`]/[`super::rdrand`]'s retry/collection/health-check
//! logic is host-testable with injected success/failure sequences, exactly
//! like [`crate::virt::CpuidSource`] does for `cpuid` (see that module's
//! header for the same rationale). The real instructions
//! ([`RealRdseed64`], [`RealRdrand64`]) are only reachable on `x86_64` and
//! MUST NOT be invoked unless the caller has already confirmed CPUID
//! support (`crate::rng::cpu::rdseed_supported`/`rdrand_supported`) —
//! executing either instruction on a processor that does not support it
//! raises `#UD`.
//!
//! SPEC §15.2/§15.3: "check the carry flag after every instruction". Both
//! real backends read `CF` via `setc` in the *same* inline-asm block as
//! the instruction itself, with no intervening instruction that could
//! clobber flags — this is what "per instruction" means in practice, and
//! it is why the two operations are one `asm!` call, not two.
//!
//! # Wall-clock deadline check point (real-hardware slow-RDSEED fix)
//!
//! [`read_one_u64`] additionally takes a [`crate::time::Deadline`] and
//! checks [`crate::time::Deadline::expired`] at the *top* of every retry
//! iteration, before the instruction is executed. This is deliberately
//! the tightest layer available: a single in-flight `rdseed`/`rdrand`
//! cannot be preempted mid-execution (it either returns quickly or it
//! doesn't — there is no way to interrupt it from software), so checking
//! only between whole 256-bit blocks (4 values) would still allow up to
//! ~4 slow instructions to run past the budget per block, and checking
//! only once per `sample()` call would allow the full ~8-16 instructions
//! of a diagnostic pair. Checking before every single read bounds the
//! overshoot to at most one (possibly slow) instruction — see
//! `crate::time`'s module doc for the full rationale and the fail-closed
//! guarantee this gives.

/// The outcome of one raw instruction attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawSample {
    /// The 64-bit value the instruction wrote to its destination
    /// register. Only meaningful when `success` is `true` (SPEC §15.2:
    /// "reject failed values rather than substituting zero" — callers
    /// MUST NOT read `value` when `success` is `false`).
    pub value: u64,
    /// The carry flag (`CF`) the instruction set: `true` means the
    /// hardware reports a valid random/seed value was produced.
    pub success: bool,
}

/// One raw `RDSEED`/`RDRAND`-shaped 64-bit instruction, injectable for
/// host tests.
pub trait RawInstructionSource {
    /// Executes (or simulates) one instruction attempt.
    fn sample(&mut self) -> RawSample;
}

/// Number of 64-bit values that make up one 256-bit source/diagnostic
/// block (SPEC §15.2: "at least four successful 64-bit values"; 4 × 8 = 32
/// bytes per block). A `SourceRecord` can hold up to
/// `seed_core::contracts::MAX_MACHINE_SOURCE_BYTES` = 64 bytes — two such
/// blocks, since RDSEED now feeds both its production and diagnostic block
/// into the record for a 2× entropy margin (2026-08-08 L2 change).
pub const VALUES_PER_BLOCK: usize = 4;

/// Bytes in one block (`VALUES_PER_BLOCK` 64-bit values).
pub const BLOCK_BYTES: usize = VALUES_PER_BLOCK * 8;

/// Why a raw read never produced a successful value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawReadError {
    /// Every attempt within `retry_limit` reported `CF = 0` (SPEC §15.2:
    /// "reject failed values rather than substituting zero").
    RetryExhausted,
    /// The wall-clock [`crate::time::Deadline`] expired before a
    /// successful value was obtained — real-hardware slow-RDSEED fix
    /// (see this module's doc comment). Indistinguishable from
    /// `RetryExhausted` to every caller's control flow; the distinction
    /// exists only so the UI can show different wording.
    DeadlineExceeded,
}

/// Reads one successful 64-bit value, retrying on `CF = 0` up to
/// `retry_limit` *additional* attempts after the first (SPEC §15.2: "use
/// bounded retries"), checking `deadline` before every attempt (see
/// module doc comment). Returns `Err` — never a substituted zero (SPEC
/// §15.2: "reject failed values rather than substituting zero") — if
/// every attempt fails or the deadline expires first.
pub(crate) fn read_one_u64(
    src: &mut dyn RawInstructionSource,
    retry_limit: u16,
    deadline: &mut crate::time::Deadline<'_>,
) -> Result<u64, RawReadError> {
    let attempts = u32::from(retry_limit) + 1;
    for _ in 0..attempts {
        if deadline.expired() {
            return Err(RawReadError::DeadlineExceeded);
        }
        let sample = src.sample();
        if sample.success {
            return Ok(sample.value);
        }
    }
    Err(RawReadError::RetryExhausted)
}

/// Collects `count` (`<= VALUES_PER_BLOCK`) successful 64-bit values,
/// little-endian, into a fixed 256-bit block, notifying `observer` after
/// each one. `count` is a caller invariant (checked by both
/// `rdseed::sample` and `rdrand::sample` against policy before this is
/// called), not re-validated here beyond a debug assertion, so this stays
/// a thin, allocation-free loop.
///
/// On `Err` (retry exhaustion or deadline expiry), the partially-filled
/// `out` buffer is scrubbed before returning — never left holding a
/// partial, unaccounted-for fragment of real entropy bytes in a dropped
/// local (SPEC §13, §20.3).
pub(crate) fn collect_block(
    src: &mut dyn RawInstructionSource,
    retry_limit: u16,
    count: usize,
    deadline: &mut crate::time::Deadline<'_>,
    observer: &mut dyn super::progress::AcquisitionObserver,
) -> Result<[u8; BLOCK_BYTES], RawReadError> {
    debug_assert!(count <= VALUES_PER_BLOCK);
    let mut out = [0u8; BLOCK_BYTES];
    for i in 0..count {
        match read_one_u64(src, retry_limit, deadline) {
            Ok(value) => {
                out[i * 8..(i + 1) * 8].copy_from_slice(&value.to_le_bytes());
                observer.value_collected();
            }
            Err(e) => {
                super::util::scrub(&mut out);
                return Err(e);
            }
        }
    }
    Ok(out)
}

/// Real `RDSEED` (64-bit form) backend (SPEC §15.2: "the production
/// implementation MAY use only the 64-bit form of RDSEED"). Caller MUST
/// have confirmed `cpu::rdseed_supported` first — see module doc.
#[cfg(target_arch = "x86_64")]
pub struct RealRdseed64;

#[cfg(target_arch = "x86_64")]
impl RawInstructionSource for RealRdseed64 {
    fn sample(&mut self) -> RawSample {
        let value: u64;
        let cf: u8;
        // SAFETY: `rdseed` is a plain register-to-register instruction
        // with no memory access; `setc` immediately follows in the same
        // asm block so no intervening instruction can alter `CF` before
        // it is captured (SPEC §15.2: "check the carry flag after every
        // instruction"). Caller contract (module doc) requires CPUID
        // support already confirmed, which is what makes this safe to
        // execute at all (an unsupported CPU would raise `#UD`, an
        // execution fault this `unsafe` block cannot itself prevent).
        unsafe {
            core::arch::asm!(
                "rdseed {val}",
                "setc {cf}",
                val = out(reg) value,
                cf = out(reg_byte) cf,
                options(nomem, nostack),
            );
        }
        RawSample { value, success: cf != 0 }
    }
}

/// Real `RDRAND` (64-bit form) backend (SPEC §15.3: supplementary only —
/// enforced by `super::rdrand`, not here). Caller MUST have confirmed
/// `cpu::rdrand_supported` first — see module doc.
#[cfg(target_arch = "x86_64")]
pub struct RealRdrand64;

#[cfg(target_arch = "x86_64")]
impl RawInstructionSource for RealRdrand64 {
    fn sample(&mut self) -> RawSample {
        let value: u64;
        let cf: u8;
        // SAFETY: see `RealRdseed64::sample` — identical reasoning,
        // `rdrand` in place of `rdseed`.
        unsafe {
            core::arch::asm!(
                "rdrand {val}",
                "setc {cf}",
                val = out(reg) value,
                cf = out(reg_byte) cf,
                options(nomem, nostack),
            );
        }
        RawSample { value, success: cf != 0 }
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::progress::NullObserver;
    use crate::time::test_support::FakeClock;
    use crate::time::Deadline;

    /// A never-expiring clock: a huge `ticks_per_ms` and zero advance per
    /// call, so `Deadline::start(&mut clock, ANY_BUDGET_MS).expired()` is
    /// always `false` within one test. Every pre-existing test in this
    /// module (predating the wall-clock deadline) uses this, so their
    /// original assertions are otherwise unchanged.
    fn never_expiring() -> FakeClock {
        FakeClock::new(1_000)
    }

    /// A scripted [`RawInstructionSource`]: replays a fixed sequence of
    /// samples, then panics if asked for more than were scripted (a test
    /// bug, not a production concern).
    struct Scripted {
        samples: std::vec::Vec<RawSample>,
        next: usize,
        calls: usize,
    }

    impl Scripted {
        fn new(samples: std::vec::Vec<RawSample>) -> Self {
            Scripted { samples, next: 0, calls: 0 }
        }
    }

    impl RawInstructionSource for Scripted {
        fn sample(&mut self) -> RawSample {
            self.calls += 1;
            let s = self.samples[self.next];
            self.next += 1;
            s
        }
    }

    /// A source that always fails (`CF = 0`) — used for the bounded-
    /// iteration deadline tests, where the source must never succeed no
    /// matter how many times it's polled.
    struct AlwaysFail {
        calls: usize,
    }
    impl RawInstructionSource for AlwaysFail {
        fn sample(&mut self) -> RawSample {
            self.calls += 1;
            RawSample { value: 0, success: false }
        }
    }

    #[test]
    fn read_one_u64_returns_first_success() {
        let mut src = Scripted::new(std::vec![RawSample { value: 0x42, success: true }]);
        let mut clock = never_expiring();
        let mut deadline = Deadline::start(&mut clock, 5_000);
        assert_eq!(read_one_u64(&mut src, 5, &mut deadline), Ok(0x42));
        assert_eq!(src.calls, 1);
    }

    #[test]
    fn read_one_u64_retries_within_bound() {
        let mut src = Scripted::new(std::vec![
            RawSample { value: 0, success: false },
            RawSample { value: 0, success: false },
            RawSample { value: 0x99, success: true },
        ]);
        let mut clock = never_expiring();
        let mut deadline = Deadline::start(&mut clock, 5_000);
        assert_eq!(read_one_u64(&mut src, 5, &mut deadline), Ok(0x99));
        assert_eq!(src.calls, 3);
    }

    #[test]
    fn read_one_u64_exhausts_retry_budget_without_substituting_zero() {
        // retry_limit = 2 means 3 total attempts (1 + 2 retries); all
        // fail, so the result must be an error, never a fabricated 0.
        let mut src = Scripted::new(std::vec![
            RawSample { value: 0, success: false },
            RawSample { value: 0, success: false },
            RawSample { value: 0, success: false },
        ]);
        let mut clock = never_expiring();
        let mut deadline = Deadline::start(&mut clock, 5_000);
        assert_eq!(read_one_u64(&mut src, 2, &mut deadline), Err(RawReadError::RetryExhausted));
        assert_eq!(src.calls, 3);
    }

    #[test]
    fn collect_block_assembles_little_endian_values_in_order() {
        let mut src = Scripted::new(std::vec![
            RawSample { value: 0x0102030405060708, success: true },
            RawSample { value: 0x1112131415161718, success: true },
            RawSample { value: 0x2122232425262728, success: true },
            RawSample { value: 0x3132333435363738, success: true },
        ]);
        let mut clock = never_expiring();
        let mut deadline = Deadline::start(&mut clock, 5_000);
        let mut obs = NullObserver;
        let block = collect_block(&mut src, 0, VALUES_PER_BLOCK, &mut deadline, &mut obs)
            .expect("all four succeed");
        let mut expected = [0u8; BLOCK_BYTES];
        expected[0..8].copy_from_slice(&0x0102030405060708u64.to_le_bytes());
        expected[8..16].copy_from_slice(&0x1112131415161718u64.to_le_bytes());
        expected[16..24].copy_from_slice(&0x2122232425262728u64.to_le_bytes());
        expected[24..32].copy_from_slice(&0x3132333435363738u64.to_le_bytes());
        assert_eq!(block, expected);
    }

    #[test]
    fn read_one_u64_rejects_on_carry_flag_not_on_zero_value() {
        // SPEC §15.2: "reject failed values rather than substituting
        // zero" — the rejection test MUST be `success` (the carry flag),
        // never `value != 0`. A naive `value != 0` check would treat
        // this failed-but-nonzero sample as a success and return the
        // bogus value; the correct carry-flag check rejects it and
        // retries onto the real success below.
        let mut src = Scripted::new(std::vec![
            RawSample { value: 0xDEAD_BEEF_0000_0001, success: false },
            RawSample { value: 0x77, success: true },
        ]);
        let mut clock = never_expiring();
        let mut deadline = Deadline::start(&mut clock, 5_000);
        assert_eq!(read_one_u64(&mut src, 5, &mut deadline), Ok(0x77));
        assert_eq!(src.calls, 2);
    }

    #[test]
    fn read_one_u64_exhausts_retry_budget_on_nonzero_failed_values() {
        // Same finding, worst case: every attempt is a nonzero value
        // with `success: false`. A `value != 0` substitute-check would
        // wrongly accept the first attempt; the correct behavior is to
        // reject all of them and return an error.
        let mut src = Scripted::new(std::vec![
            RawSample { value: 0x1234_5678_9abc_def0, success: false },
            RawSample { value: 0xffff_ffff_ffff_ffff, success: false },
        ]);
        let mut clock = never_expiring();
        let mut deadline = Deadline::start(&mut clock, 5_000);
        assert_eq!(read_one_u64(&mut src, 1, &mut deadline), Err(RawReadError::RetryExhausted));
        assert_eq!(src.calls, 2);
    }

    #[test]
    fn collect_block_propagates_retry_exhaustion() {
        let mut src = Scripted::new(std::vec![
            RawSample { value: 1, success: true },
            RawSample { value: 0, success: false },
        ]);
        let mut clock = never_expiring();
        let mut deadline = Deadline::start(&mut clock, 5_000);
        let mut obs = NullObserver;
        assert_eq!(
            collect_block(&mut src, 0, 2, &mut deadline, &mut obs),
            Err(RawReadError::RetryExhausted)
        );
    }

    // ------------------------------------------------------------------
    // Wall-clock deadline tests (real-hardware slow-RDSEED fix).
    // ------------------------------------------------------------------

    /// A-class: an always-failing source with a clock that jumps straight
    /// past the budget on every tick must abort in bounded iterations —
    /// not merely "eventually return", but actually touch the source only
    /// a handful of times before the deadline check stops it.
    #[test]
    fn stalling_source_times_out_in_bounded_iterations() {
        let mut src = AlwaysFail { calls: 0 };
        let mut clock = FakeClock::new(1_000);
        clock.advance_per_call = 10_000_000; // jumps far past any budget instantly
        let mut deadline = Deadline::start(&mut clock, 5_000);
        let result = read_one_u64(&mut src, 100, &mut deadline);
        assert_eq!(result, Err(RawReadError::DeadlineExceeded));
        assert!(src.calls <= 3, "expected a small bounded number of instruction attempts, got {}", src.calls);
    }

    /// A pre-expired deadline must abort before the raw source is ever
    /// touched at all (zero instructions executed once the budget is
    /// already gone).
    #[test]
    fn expired_before_first_read_executes_zero_instructions() {
        let mut src = AlwaysFail { calls: 0 };
        // Starting the clock already one tick past a zero-length budget:
        // `Deadline` holds the clock's only mutable borrow for its whole
        // lifetime, so any "time has already passed" state must be baked
        // in before `start`, not mutated in afterward.
        let mut clock = FakeClock::starting_at(1, 1_000);
        let mut deadline = Deadline::start(&mut clock, 0); // budget 0ms: already expired
        let result = read_one_u64(&mut src, 100, &mut deadline);
        assert_eq!(result, Err(RawReadError::DeadlineExceeded));
        assert_eq!(src.calls, 0);
    }

    /// A source that succeeds on every call, paired with a deadline that
    /// expires partway through a block, must return a deadline error and
    /// scrub the partial buffer — never a partially-filled `Ok`.
    #[test]
    fn partial_block_is_never_returned_on_deadline_expiry() {
        struct ExpireAfterTwo {
            calls: usize,
        }
        impl RawInstructionSource for ExpireAfterTwo {
            fn sample(&mut self) -> RawSample {
                self.calls += 1;
                RawSample { value: self.calls as u64, success: true }
            }
        }
        let mut src = ExpireAfterTwo { calls: 0 };
        // ticks_per_ms = 1; budget of 2ms => a small, exactly-computed
        // deadline. Advancing by 1 tick on every `now_ticks()` call means
        // the deadline is reached after only a couple of instructions —
        // well before all `VALUES_PER_BLOCK` values are collected — so
        // `collect_block` must abort with a deadline error and scrub the
        // partial buffer rather than ever returning a short/partial `Ok`.
        let mut clock = FakeClock::new(1);
        clock.advance_per_call = 1;
        let mut deadline = Deadline::start(&mut clock, 2);
        let mut obs = NullObserver;
        let result = collect_block(&mut src, 0, VALUES_PER_BLOCK, &mut deadline, &mut obs);
        assert_eq!(result, Err(RawReadError::DeadlineExceeded));
        assert!(src.calls < VALUES_PER_BLOCK, "must not have collected a full block");
    }

    /// A fast, healthy source with a generously-advancing-but-still-
    /// within-budget clock must succeed exactly as before the deadline
    /// was introduced — no regression to the happy path.
    #[test]
    fn fast_clock_happy_path_unchanged() {
        let mut src = Scripted::new(std::vec![
            RawSample { value: 0x1111, success: true },
            RawSample { value: 0x2222, success: true },
            RawSample { value: 0x3333, success: true },
            RawSample { value: 0x4444, success: true },
        ]);
        let mut clock = FakeClock::new(1_000_000); // 1000 ticks/ms
        clock.advance_per_call = 1; // 1 tick per check; negligible vs a 5s budget
        let mut deadline = Deadline::start(&mut clock, 5_000);
        let mut obs = NullObserver;
        let block = collect_block(&mut src, 5, VALUES_PER_BLOCK, &mut deadline, &mut obs)
            .expect("healthy fast source must still succeed well within budget");
        assert_eq!(&block[0..8], &0x1111u64.to_le_bytes());
        assert_eq!(src.calls, 4);
    }

    /// The progress observer receives exactly one tick per successfully
    /// collected value, never on a failed/retried attempt.
    #[test]
    fn observer_receives_exactly_one_tick_per_collected_value() {
        struct CountingObserver {
            ticks: usize,
        }
        impl crate::rng::progress::AcquisitionObserver for CountingObserver {
            fn value_collected(&mut self) {
                self.ticks += 1;
            }
        }
        let mut src = Scripted::new(std::vec![
            RawSample { value: 0, success: false }, // one retry, no tick
            RawSample { value: 1, success: true },
            RawSample { value: 2, success: true },
        ]);
        let mut clock = never_expiring();
        let mut deadline = Deadline::start(&mut clock, 5_000);
        let mut obs = CountingObserver { ticks: 0 };
        let result = collect_block(&mut src, 2, 2, &mut deadline, &mut obs);
        assert!(result.is_ok());
        assert_eq!(obs.ticks, 2);
    }
}
