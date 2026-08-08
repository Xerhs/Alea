//! `RDRAND` (64-bit) supplementary-only machine-entropy driver (WP-24,
//! SPEC §15.3).
//!
//! SPEC §15.3: "`RDRAND` is supplementary only in version 1." This
//! module never decides *whether* RDRAND output is used to enable any
//! entropy mode — it only ever produces one tagged
//! [`super::record::SourceRecord`] (`SourceTag::X86RdrandSupplementary`)
//! that a caller may add to the transcript alongside other sources. Mode
//! eligibility is decided elsewhere (policy + state machine), never by
//! this driver having successfully sampled something (SPEC §15.3: "MUST
//! NOT... upgrade an otherwise unsupported platform to 'approved'").
//!
//! `RdrandPolicy` carries no CPU vendor/family/model/stepping allow-list
//! (SPEC §15.3 requires only "CPUID support and carry-flag success", not
//! the RDSEED-style per-processor errata review) and no dedicated
//! retry-limit/min-values fields, so this module uses its own fixed,
//! conservative bounded-retry constant (see [`RETRY_LIMIT`]) rather than
//! reading one from policy.

use seed_core::contracts::SourceTag;
use seed_protocol::policy::RdrandPolicy;

use super::cpu;
use super::health::{self, HealthError};
use super::progress::AcquisitionObserver;
use super::raw::{collect_block, RawInstructionSource, RawReadError, VALUES_PER_BLOCK};
use super::record::SourceRecord;
use super::util::scrub;
use crate::time::Deadline;
use crate::virt::CpuidSource;

/// The algorithm identifier this driver stages into every
/// [`SourceRecord`] it produces.
pub const ALGO_ID: &[u8] = b"RDRAND";

/// Bounded retry count per 64-bit value. Intel's Digital Random Number
/// Generator documentation recommends treating 10 consecutive `CF = 0`
/// results from `RDRAND` as exceptional; this driver uses that figure
/// (SPEC §15.3: "multiple values are collected"; §16: "use bounded
/// retries" is stated for RDSEED but the same reasoning applies — a
/// bound must exist and must be small enough to fail fast rather than
/// spin).
pub const RETRY_LIMIT: u16 = 10;

/// Why an RDRAND sample attempt was refused or failed (SPEC §15.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdrandError {
    /// `policy.approved` is `false`.
    NotApproved,
    /// The policy does not hold SPEC §15.3's mandatory invariants
    /// (`supplementary_only = true`, `sole_source_allowed = false`).
    /// `seed_protocol::policy::parse` already refuses to produce a
    /// `Policy` that violates this, so this is a defense-in-depth check
    /// against a caller passing a hand-built value, not a reachable
    /// production state.
    NotSupplementaryOnly,
    /// CPUID does not report `RDRAND` support (SPEC §15.3: "CPUID
    /// support... required").
    CpuidUnsupported,
    /// A 64-bit value never succeeded within [`RETRY_LIMIT`] (SPEC
    /// §15.2's "reject failed values rather than substituting zero"
    /// applies equally here — no RDRAND value is ever fabricated).
    RetryExhausted,
    /// The wall-clock acquisition budget expired before a full block
    /// could be collected (real-hardware slow-RDSEED fix — see
    /// `crate::time`'s module doc; RDRAND shares the same acquisition
    /// deadline as RDSEED/EFI-RNG). Handled identically to
    /// `RetryExhausted` by every caller's control flow.
    DeadlineExceeded,
    /// A sampled block failed a SPEC §16 catastrophic check.
    Health(HealthError),
}

impl From<RawReadError> for RdrandError {
    fn from(e: RawReadError) -> Self {
        match e {
            RawReadError::RetryExhausted => RdrandError::RetryExhausted,
            RawReadError::DeadlineExceeded => RdrandError::DeadlineExceeded,
        }
    }
}

/// Samples one RDRAND [`SourceRecord`] (SPEC §15.3). Two 256-bit blocks
/// are collected and cross-checked (SPEC §16: "identical consecutive
/// 256-bit diagnostic blocks"); the first becomes the record, the second
/// is scrubbed immediately after the comparison.
pub fn sample(
    cpuid: &dyn CpuidSource,
    raw: &mut dyn RawInstructionSource,
    policy: &RdrandPolicy,
    deadline: &mut Deadline<'_>,
    observer: &mut dyn AcquisitionObserver,
) -> Result<SourceRecord, RdrandError> {
    if !policy.approved {
        return Err(RdrandError::NotApproved);
    }
    if !policy.supplementary_only || policy.sole_source_allowed {
        return Err(RdrandError::NotSupplementaryOnly);
    }

    if !cpu::rdrand_supported(cpuid) {
        return Err(RdrandError::CpuidUnsupported);
    }

    let mut block_a = collect_block(raw, RETRY_LIMIT, VALUES_PER_BLOCK, deadline, observer)?;
    if let Err(e) = health::check_not_degenerate(&block_a) {
        scrub(&mut block_a);
        return Err(RdrandError::Health(e));
    }

    let mut block_b = match collect_block(raw, RETRY_LIMIT, VALUES_PER_BLOCK, deadline, observer) {
        Ok(b) => b,
        Err(e) => {
            scrub(&mut block_a);
            return Err(e.into());
        }
    };
    let degenerate = health::check_not_degenerate(&block_b);
    let repeated = health::check_not_repeated(&block_a, &block_b);
    if let Err(e) = degenerate.and(repeated) {
        scrub(&mut block_a);
        scrub(&mut block_b);
        return Err(RdrandError::Health(e));
    }
    scrub(&mut block_b);

    let record = SourceRecord::new(SourceTag::X86RdrandSupplementary, ALGO_ID, &block_a)
        .expect("32-byte block fits MAX_MACHINE_SOURCE_BYTES");
    scrub(&mut block_a);
    Ok(record)
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::progress::NullObserver;
    use crate::time::test_support::FakeClock;
    use crate::virt::CpuidLeaf;
    use seed_protocol::policy::RdrandPolicy;

    /// Mechanical test helper: see `rdseed.rs`'s identical helper doc
    /// comment. Wraps `sample` with a never-expiring `Deadline` and a
    /// `NullObserver` for every pre-existing test in this module.
    fn sample_default(
        cpuid: &dyn CpuidSource,
        raw: &mut dyn RawInstructionSource,
        policy: &RdrandPolicy,
    ) -> Result<SourceRecord, RdrandError> {
        let mut clock = FakeClock::new(1_000);
        let mut deadline = Deadline::start(&mut clock, 5_000);
        let mut obs = NullObserver;
        sample(cpuid, raw, policy, &mut deadline, &mut obs)
    }

    struct FakeCpuid {
        supported: bool,
    }

    impl CpuidSource for FakeCpuid {
        fn leaf(&self, eax: u32) -> CpuidLeaf {
            match eax {
                1 => CpuidLeaf { eax: 0, ebx: 0, ecx: if self.supported { 1 << 30 } else { 0 }, edx: 0 },
                _ => CpuidLeaf { eax: 0, ebx: 0, ecx: 0, edx: 0 },
            }
        }
    }

    const TEST_POLICY_TOML: &str = r#"
policy_version = 1

[efi_rng]
approved = false
sole_source_allowed = false
max_algorithms = 8
allowed_algorithms = []

[rdseed]
approved = false
sole_source_allowed = false
instruction_width_bits = 64
retry_limit = 5
min_successful_values = 4
diagnostic_blocks = 2

[rdrand]
approved = true
sole_source_allowed = false
supplementary_only = true

[usb_trng]
approved = false
sole_source_allowed = false
min_read_bytes = 32
read_timeout_ms = 2000
max_read_retries = 2
"#;

    fn approved_policy() -> RdrandPolicy {
        seed_protocol::policy::parse(TEST_POLICY_TOML).expect("well-formed test policy").rdrand
    }

    struct Counting {
        next: u64,
        calls: usize,
    }

    impl RawInstructionSource for Counting {
        fn sample(&mut self) -> super::super::raw::RawSample {
            self.calls += 1;
            self.next += 1;
            super::super::raw::RawSample { value: self.next, success: true }
        }
    }

    #[test]
    fn happy_path_produces_valid_record() {
        let cpuid = FakeCpuid { supported: true };
        let policy = approved_policy();
        let mut raw = Counting { next: 0, calls: 0 };
        let record = sample_default(&cpuid, &mut raw, &policy).expect("all checks pass");
        assert_eq!(record.tag(), SourceTag::X86RdrandSupplementary);
        assert_eq!(record.algo_id(), ALGO_ID);
        assert_eq!(record.bytes().len(), 32);
        assert_eq!(raw.calls, 8); // 4 for block A + 4 for the comparison block
    }

    #[test]
    fn rejects_when_not_approved() {
        let cpuid = FakeCpuid { supported: true };
        let mut policy = approved_policy();
        policy.approved = false;
        let mut raw = Counting { next: 0, calls: 0 };
        assert_eq!(sample_default(&cpuid, &mut raw, &policy).err(), Some(RdrandError::NotApproved));
        assert_eq!(raw.calls, 0);
    }

    #[test]
    fn rejects_when_not_supplementary_only() {
        let cpuid = FakeCpuid { supported: true };
        let mut policy = approved_policy();
        policy.supplementary_only = false;
        let mut raw = Counting { next: 0, calls: 0 };
        assert_eq!(sample_default(&cpuid, &mut raw, &policy).err(), Some(RdrandError::NotSupplementaryOnly));
    }

    #[test]
    fn rejects_when_sole_source_allowed_is_set() {
        // SPEC §15.3: RDRAND must never enable machine-only generation by
        // itself, even if some future hand-built policy tried to flip
        // this on (the real parser already refuses such a file).
        let cpuid = FakeCpuid { supported: true };
        let mut policy = approved_policy();
        policy.sole_source_allowed = true;
        let mut raw = Counting { next: 0, calls: 0 };
        assert_eq!(sample_default(&cpuid, &mut raw, &policy).err(), Some(RdrandError::NotSupplementaryOnly));
    }

    #[test]
    fn cpuid_gate_blocks_before_any_instruction_executes() {
        let cpuid = FakeCpuid { supported: false };
        let policy = approved_policy();
        let mut raw = Counting { next: 0, calls: 0 };
        assert_eq!(sample_default(&cpuid, &mut raw, &policy).err(), Some(RdrandError::CpuidUnsupported));
        assert_eq!(raw.calls, 0);
    }

    #[test]
    fn retry_exhaustion_never_substitutes_zero() {
        struct AlwaysFail;
        impl RawInstructionSource for AlwaysFail {
            fn sample(&mut self) -> super::super::raw::RawSample {
                super::super::raw::RawSample { value: 0, success: false }
            }
        }
        let cpuid = FakeCpuid { supported: true };
        let policy = approved_policy();
        let mut raw = AlwaysFail;
        assert_eq!(sample_default(&cpuid, &mut raw, &policy).err(), Some(RdrandError::RetryExhausted));
    }

    #[test]
    fn all_zero_block_is_rejected() {
        struct AllZero;
        impl RawInstructionSource for AllZero {
            fn sample(&mut self) -> super::super::raw::RawSample {
                super::super::raw::RawSample { value: 0, success: true }
            }
        }
        let cpuid = FakeCpuid { supported: true };
        let policy = approved_policy();
        let mut raw = AllZero;
        assert_eq!(sample_default(&cpuid, &mut raw, &policy).err(), Some(RdrandError::Health(HealthError::AllZero)));
    }

    #[test]
    fn identical_consecutive_blocks_are_rejected() {
        struct Repeating {
            values: [u64; 4],
            idx: usize,
        }
        impl RawInstructionSource for Repeating {
            fn sample(&mut self) -> super::super::raw::RawSample {
                let v = self.values[self.idx % 4];
                self.idx += 1;
                super::super::raw::RawSample { value: v, success: true }
            }
        }
        let cpuid = FakeCpuid { supported: true };
        let policy = approved_policy();
        let mut raw = Repeating { values: [0xAAAA, 0xBBBB, 0xCCCC, 0xDDDD], idx: 0 };
        assert_eq!(
            sample_default(&cpuid, &mut raw, &policy).err(),
            Some(RdrandError::Health(HealthError::IdenticalConsecutiveBlocks))
        );
    }

    // ------------------------------------------------------------------
    // Wall-clock deadline tests (real-hardware slow-RDSEED fix; RDRAND
    // shares the same acquisition deadline).
    // ------------------------------------------------------------------

    #[test]
    fn stalling_source_times_out_in_bounded_iterations() {
        struct AlwaysFail {
            calls: usize,
        }
        impl RawInstructionSource for AlwaysFail {
            fn sample(&mut self) -> super::super::raw::RawSample {
                self.calls += 1;
                super::super::raw::RawSample { value: 0, success: false }
            }
        }
        let cpuid = FakeCpuid { supported: true };
        let policy = approved_policy();
        let mut raw = AlwaysFail { calls: 0 };
        let mut clock = FakeClock::new(1_000);
        clock.advance_per_call = 10_000_000;
        let mut deadline = Deadline::start(&mut clock, 5_000);
        let mut obs = NullObserver;
        let result = sample(&cpuid, &mut raw, &policy, &mut deadline, &mut obs);
        assert_eq!(result.err(), Some(RdrandError::DeadlineExceeded));
        assert!(raw.calls <= 3, "expected a small bounded number of instruction attempts, got {}", raw.calls);
    }

    #[test]
    fn deadline_between_blocks_never_accepts_block_a() {
        let cpuid = FakeCpuid { supported: true };
        let policy = approved_policy();
        let mut raw = Counting { next: 0, calls: 0 };
        let mut clock = FakeClock::new(1);
        clock.advance_per_call = 1;
        let mut deadline = Deadline::start(&mut clock, 5);
        let mut obs = NullObserver;
        let result = sample(&cpuid, &mut raw, &policy, &mut deadline, &mut obs);
        assert_eq!(result.err(), Some(RdrandError::DeadlineExceeded));
        assert_eq!(
            raw.calls, VALUES_PER_BLOCK,
            "block A must have fully completed via the raw source before the deadline fired for block B"
        );
    }

    #[test]
    fn fast_clock_happy_path_unchanged() {
        let cpuid = FakeCpuid { supported: true };
        let policy = approved_policy();
        let mut raw = Counting { next: 0, calls: 0 };
        let mut clock = FakeClock::new(1_000_000);
        clock.advance_per_call = 1;
        let mut deadline = Deadline::start(&mut clock, 5_000);
        let mut obs = NullObserver;
        let record = sample(&cpuid, &mut raw, &policy, &mut deadline, &mut obs).expect("all checks pass");
        assert_eq!(record.tag(), SourceTag::X86RdrandSupplementary);
        assert_eq!(record.bytes().len(), 32);
        assert_eq!(raw.calls, 8);
    }
}
