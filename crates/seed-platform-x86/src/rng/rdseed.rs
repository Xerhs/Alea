//! `RDSEED` (64-bit) machine-entropy driver (WP-24, SPEC §15.2).
//!
//! Order of operations, each one a documented SPEC §15.2 requirement:
//! 1. Policy says RDSEED is approved at all, and configured for the
//!    64-bit instruction width (version 1 supports no other width).
//! 2. CPUID confirms the processor actually implements `RDSEED` — MUST
//!    happen before the instruction is ever executed (`#UD` otherwise).
//! 3. CPUID vendor/family/model/stepping is checked against the
//!    top-level compiled-in policy's *known-bad denylist*
//!    (`seed_protocol::policy::Policy::is_cpu_denylisted`, SPEC §15:
//!    "Known-bad platform denylist entries") and then against the
//!    `[rdseed]` section's allow-rules (`RdseedPolicy::is_cpu_allowed`,
//!    itself default-deny). Both MUST pass — the denylist is checked
//!    first and wins even if an allow-rule would otherwise match, so a
//!    later broadening of `[[rdseed_cpu_rules]]` can never silently
//!    resurrect a known-bad platform.
//! 4. Two independent 256-bit blocks are sampled (bounded retries, carry
//!    flag checked after every instruction — see [`super::raw`]) and
//!    passed through the SPEC §16 catastrophic checks: neither may be
//!    all-zero/all-`0xFF`, and the two must not be identical.
//! 5. BOTH health-checked blocks become the
//!    [`super::record::SourceRecord`], concatenated `block_a ‖ block_b`
//!    (512 raw bits). Audit finding L2: the diagnostic block used to be
//!    scrubbed immediately after the identical-block comparison, leaving a
//!    single 256-bit block feeding a 256-bit conditioned seed with ZERO
//!    over-collection margin — if RDSEED ran slightly below full entropy,
//!    effective seed entropy dipped below 256 with nothing to spare.
//!    Feeding the already-validated diagnostic block into the record too
//!    carries 2× raw entropy into the transcript → SHA-256; the final seed
//!    width is unchanged (still 128/256-bit after conditioning), only the
//!    raw input behind it grows. Both blocks are still fully health-checked
//!    BEFORE either enters the record — a stuck/degenerate/repeated
//!    diagnostic block fails closed, never yielding a record. If policy
//!    asks for more than two diagnostic blocks, the surplus blocks are
//!    still sampled and health-checked in sequence but do not fit the
//!    fixed 64-byte record, so only the first diagnostic block is carried.

use seed_core::contracts::SourceTag;
use seed_protocol::policy::Policy;

use super::cpu::{self, family_model_stepping, vendor_string};
use super::health::{self, HealthError};
use super::progress::AcquisitionObserver;
use super::raw::{collect_block, RawInstructionSource, RawReadError, BLOCK_BYTES, VALUES_PER_BLOCK};
use super::record::SourceRecord;
use super::util::scrub;
use crate::time::Deadline;
use crate::virt::CpuidSource;

/// The algorithm identifier this driver stages into every
/// [`SourceRecord`] it produces (`contracts.rs`'s `MAX_ALGO_ID` doc
/// comment names this exact literal as the expected RDSEED64 identifier).
pub const ALGO_ID: &[u8] = b"RDSEED64";

/// Why an RDSEED64 sample attempt was refused or failed (SPEC §15.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rdseed64Error {
    /// `policy.rdseed.approved` is `false` (SPEC §15.2: policy-gated).
    NotApproved,
    /// The policy's `instruction_width_bits` is not `64` (SPEC §15.2:
    /// "the production implementation MAY use only the 64-bit form").
    UnsupportedWidth,
    /// The policy's `min_successful_values` is not exactly
    /// [`VALUES_PER_BLOCK`] (SPEC §15.2: "collect at least four
    /// successful 64-bit values for a 256-bit source record" — and this
    /// driver's fixed 256-bit record shape cannot hold *more* than 4
    /// sixty-four-bit values either, so "at least four" and the record's
    /// fixed capacity together pin this to exactly 4; a compiled-in policy
    /// asking for fewer would silently under-fill the mandated 256-bit
    /// record, so it is refused rather than honored).
    PolicyMinValuesInvalid,
    /// CPUID does not report `RDSEED` support (SPEC §15.2: "verify CPUID
    /// support" — checked before any instruction executes).
    CpuidUnsupported,
    /// The CPU's vendor/family/model/stepping matched a known-bad entry
    /// in the top-level compiled-in policy's denylist (SPEC §15: "Known-bad
    /// platform denylist entries"; SPEC §15.2: "apply the compiled-in
    /// errata and denylist policy"). Checked before, and independently of, the
    /// `[rdseed]` allow-rules — a denylist match always wins.
    CpuDenylisted,
    /// The CPU's vendor/family/model/stepping did not match an
    /// allow-rule in the compiled-in policy (SPEC §15.2: "refuse RDSEED
    /// approval on unknown or denylisted processor combinations").
    CpuNotAllowed,
    /// A 64-bit value never succeeded within the policy's bounded retry
    /// limit (SPEC §15.2: "reject failed values rather than substituting
    /// zero").
    RetryExhausted,
    /// The wall-clock acquisition budget expired before a full block
    /// could be collected (real-hardware slow-RDSEED fix — see
    /// `crate::time`'s module doc). Handled identically to
    /// `RetryExhausted` by every caller's control flow; the distinction
    /// exists only so the UI can show different wording.
    DeadlineExceeded,
    /// A sampled block failed a SPEC §16 catastrophic check.
    Health(HealthError),
}

impl From<RawReadError> for Rdseed64Error {
    fn from(e: RawReadError) -> Self {
        match e {
            RawReadError::RetryExhausted => Rdseed64Error::RetryExhausted,
            RawReadError::DeadlineExceeded => Rdseed64Error::DeadlineExceeded,
        }
    }
}

/// Samples one RDSEED64 [`SourceRecord`] (SPEC §15.2). See the module doc
/// for the exact sequence of checks.
///
/// Takes the full top-level [`Policy`] — not just its `[rdseed]`
/// section — because CPU gating needs both the section's allow-rules
/// (`policy.rdseed.is_cpu_allowed`) *and* the policy-wide known-bad
/// denylist (`policy.is_cpu_denylisted`, SPEC §15); the denylist is not
/// reachable from `RdseedPolicy` alone.
pub fn sample(
    cpuid: &dyn CpuidSource,
    raw: &mut dyn RawInstructionSource,
    policy: &Policy,
    deadline: &mut Deadline<'_>,
    observer: &mut dyn AcquisitionObserver,
) -> Result<SourceRecord, Rdseed64Error> {
    let rdseed_policy = &policy.rdseed;
    if !rdseed_policy.approved {
        return Err(Rdseed64Error::NotApproved);
    }
    if rdseed_policy.instruction_width_bits != 64 {
        return Err(Rdseed64Error::UnsupportedWidth);
    }
    let values_needed = rdseed_policy.min_successful_values as usize;
    if values_needed != VALUES_PER_BLOCK {
        return Err(Rdseed64Error::PolicyMinValuesInvalid);
    }

    if !cpu::rdseed_supported(cpuid) {
        return Err(Rdseed64Error::CpuidUnsupported);
    }

    let vendor = vendor_string(cpuid);
    let vendor_str = core::str::from_utf8(&vendor).unwrap_or("");
    let (family, model, stepping) = family_model_stepping(cpuid);
    if policy.is_cpu_denylisted(vendor_str, family, model, stepping) {
        return Err(Rdseed64Error::CpuDenylisted);
    }
    if !rdseed_policy.is_cpu_allowed(vendor_str, family, model, stepping) {
        return Err(Rdseed64Error::CpuNotAllowed);
    }

    // Block A is the source block: the first half of the final record.
    let mut block_a =
        collect_block(raw, rdseed_policy.retry_limit, values_needed, deadline, observer)?;
    if let Err(e) = health::check_not_degenerate(&block_a) {
        scrub(&mut block_a);
        return Err(Rdseed64Error::Health(e));
    }

    // SPEC §15.2/§16: at least one further 256-bit block, rejecting
    // identical consecutive blocks. This first diagnostic block is the
    // one that — once it passes BOTH catastrophic checks — is also
    // concatenated onto block A to form the 512-raw-bit record (audit
    // finding L2: 2× over-collection margin behind the 256-bit conditioned
    // seed; see the module doc). It is health-checked here, before it ever
    // enters the record.
    let mut block_b = match collect_block(
        raw,
        rdseed_policy.retry_limit,
        values_needed,
        deadline,
        observer,
    ) {
        Ok(b) => b,
        Err(e) => {
            scrub(&mut block_a);
            return Err(e.into());
        }
    };
    {
        let degenerate = health::check_not_degenerate(&block_b);
        let repeated = health::check_not_repeated(&block_a, &block_b);
        if let Err(e) = degenerate.and(repeated) {
            scrub(&mut block_a);
            scrub(&mut block_b);
            return Err(Rdseed64Error::Health(e));
        }
    }

    // `diagnostic_blocks` counts the *total* blocks compared (block A plus
    // this many more); a value below 2 still got the one mandatory
    // comparison above. Any blocks beyond the first diagnostic one are
    // still sampled and health-checked against their predecessor, but do
    // not fit the fixed 64-byte (two-block) record, so they are scrubbed
    // after checking rather than carried.
    let extra_blocks = rdseed_policy.diagnostic_blocks.saturating_sub(1).max(1);
    let mut previous = block_b;
    for _ in 1..extra_blocks {
        let mut next = match collect_block(
            raw,
            rdseed_policy.retry_limit,
            values_needed,
            deadline,
            observer,
        ) {
            Ok(b) => b,
            Err(e) => {
                scrub(&mut block_a);
                scrub(&mut block_b);
                scrub(&mut previous);
                return Err(e.into());
            }
        };
        let degenerate = health::check_not_degenerate(&next);
        let repeated = health::check_not_repeated(&previous, &next);
        if let Err(e) = degenerate.and(repeated) {
            scrub(&mut block_a);
            scrub(&mut block_b);
            scrub(&mut previous);
            scrub(&mut next);
            return Err(Rdseed64Error::Health(e));
        }
        scrub(&mut previous);
        previous = next;
        scrub(&mut next); // `next`'s bytes were copied into `previous` above; wipe this now-stale local name too.
    }
    scrub(&mut previous); // `previous` is a copy of `block_b` (or a later surplus block); `block_b` itself is still needed for the record.

    // Audit finding L2: the record is `block_a ‖ block_b` — both
    // health-checked 256-bit blocks, 512 raw bits, conditioned by the
    // transcript's SHA-256 down to the unchanged 128/256-bit seed width.
    // `values_needed == VALUES_PER_BLOCK` (checked above), so each block
    // fills a full `BLOCK_BYTES`.
    let mut record_bytes = [0u8; 2 * BLOCK_BYTES];
    record_bytes[..BLOCK_BYTES].copy_from_slice(&block_a);
    record_bytes[BLOCK_BYTES..].copy_from_slice(&block_b);
    let record = SourceRecord::new(SourceTag::X86Rdseed64, ALGO_ID, &record_bytes)
        .expect("2*BLOCK_BYTES == 64 <= MAX_MACHINE_SOURCE_BYTES");
    scrub(&mut record_bytes);
    scrub(&mut block_a);
    scrub(&mut block_b);
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

    /// Mechanical test helper: every pre-existing test in this module
    /// predates the wall-clock deadline parameter and does not care about
    /// it — this wraps `sample` with a never-expiring `Deadline` and a
    /// `NullObserver` so those call sites are unchanged in every other
    /// respect. New deadline-specific tests below call `sample` directly.
    fn sample_default(
        cpuid: &dyn CpuidSource,
        raw: &mut dyn RawInstructionSource,
        policy: &Policy,
    ) -> Result<SourceRecord, Rdseed64Error> {
        let mut clock = FakeClock::new(1_000);
        let mut deadline = Deadline::start(&mut clock, 5_000);
        let mut obs = NullObserver;
        sample(cpuid, raw, policy, &mut deadline, &mut obs)
    }

    struct FakeCpuid {
        supported: bool,
        vendor: [u8; 12],
        eax_signature: u32,
    }

    impl CpuidSource for FakeCpuid {
        fn leaf(&self, eax: u32) -> CpuidLeaf {
            match eax {
                0 => CpuidLeaf {
                    eax: 0,
                    ebx: u32::from_le_bytes(self.vendor[0..4].try_into().unwrap()),
                    edx: u32::from_le_bytes(self.vendor[4..8].try_into().unwrap()),
                    ecx: u32::from_le_bytes(self.vendor[8..12].try_into().unwrap()),
                },
                1 => CpuidLeaf { eax: self.eax_signature, ebx: 0, ecx: 0, edx: 0 },
                7 => CpuidLeaf {
                    eax: 0,
                    ebx: if self.supported { 1 << 18 } else { 0 },
                    ecx: 0,
                    edx: 0,
                },
                _ => CpuidLeaf { eax: 0, ebx: 0, ecx: 0, edx: 0 },
            }
        }
    }

    fn intel_cpuid(supported: bool) -> FakeCpuid {
        FakeCpuid { supported, vendor: *b"GenuineIntel", eax_signature: 0x000506E3 }
    }

    /// A full policy document, parsed through the real `seed_protocol`
    /// parser (WP-12) rather than hand-built, since `Policy`'s
    /// constructors are `pub(super)` inside that crate — this crate is
    /// only ever meant to *consume* an already-parsed, already-validated
    /// policy, never assemble one from parts.
    const TEST_POLICY_TOML: &str = r#"
policy_version = 1

[efi_rng]
approved = false
sole_source_allowed = false
max_algorithms = 8
allowed_algorithms = []

[rdseed]
approved = true
sole_source_allowed = true
instruction_width_bits = 64
retry_limit = 5
min_successful_values = 4
diagnostic_blocks = 2

[[rdseed_cpu_rules]]
vendor = "GenuineIntel"
family_min = 0
family_max = 65535
model_min = 0
model_max = 255
stepping_min = 0
stepping_max = 255
allow = true

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

    /// Same as [`TEST_POLICY_TOML`] but with every `GenuineIntel` family-6
    /// part — which covers `intel_cpuid`'s `eax_signature = 0x000506E3`
    /// — also present in `[[denylist]]`, so a CPU that the `[rdseed]`
    /// allow-rules would otherwise accept is refused via the denylist.
    const TEST_POLICY_TOML_DENYLISTED: &str = r#"
policy_version = 1

[efi_rng]
approved = false
sole_source_allowed = false
max_algorithms = 8
allowed_algorithms = []

[rdseed]
approved = true
sole_source_allowed = true
instruction_width_bits = 64
retry_limit = 5
min_successful_values = 4
diagnostic_blocks = 2

[[rdseed_cpu_rules]]
vendor = "GenuineIntel"
family_min = 0
family_max = 65535
model_min = 0
model_max = 255
stepping_min = 0
stepping_max = 255
allow = true

[rdrand]
approved = true
sole_source_allowed = false
supplementary_only = true

[[denylist]]
vendor = "GenuineIntel"
family_min = 6
family_max = 6
model_min = 0
model_max = 255
stepping_min = 0
stepping_max = 255
reason = "known-bad microcode"

[usb_trng]
approved = false
sole_source_allowed = false
min_read_bytes = 32
read_timeout_ms = 2000
max_read_retries = 2
"#;

    fn allow_all_policy() -> Policy {
        seed_protocol::policy::parse(TEST_POLICY_TOML).expect("well-formed test policy")
    }

    fn denylisted_policy() -> Policy {
        seed_protocol::policy::parse(TEST_POLICY_TOML_DENYLISTED)
            .expect("well-formed test policy")
    }

    /// Deterministic distinct-block generator: value `n` on call `n`
    /// (0-indexed across the whole sequence), always successful, so two
    /// consecutive 4-value blocks are never accidentally identical.
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
        let cpuid = intel_cpuid(true);
        let policy = allow_all_policy();
        let mut raw = Counting { next: 0, calls: 0 };
        let record = sample_default(&cpuid, &mut raw, &policy).expect("all checks pass");
        assert_eq!(record.tag(), SourceTag::X86Rdseed64);
        assert_eq!(record.algo_id(), ALGO_ID);
        // Audit finding L2: the record now carries BOTH health-checked
        // 256-bit blocks (block_a ‖ block_b) = 2 * BLOCK_BYTES = 64 bytes.
        assert_eq!(record.bytes().len(), 2 * BLOCK_BYTES);
        assert_eq!(record.bytes().len(), 64);
        // 8 values consumed: 4 for block A, 4 for the one diagnostic
        // block (diagnostic_blocks = 2 => extra_blocks = 1) — both now in
        // the record.
        assert_eq!(raw.calls, 8);

        // `Counting` yields 1,2,3,4 for block A and 5,6,7,8 for block B
        // (little-endian u64s). The record must be exactly those two
        // blocks concatenated — proving block_b's bytes are present, not
        // scrubbed away.
        let mut expected = [0u8; 64];
        for (i, v) in [1u64, 2, 3, 4, 5, 6, 7, 8].iter().enumerate() {
            expected[i * 8..(i + 1) * 8].copy_from_slice(&v.to_le_bytes());
        }
        assert_eq!(record.bytes(), &expected[..]);
        // Cross-check the two halves individually: block A is the first
        // 32 bytes, block B the second 32.
        assert_eq!(&record.bytes()[..BLOCK_BYTES], &expected[..BLOCK_BYTES]);
        assert_eq!(&record.bytes()[BLOCK_BYTES..], &expected[BLOCK_BYTES..]);
    }

    #[test]
    fn rejects_when_policy_not_approved() {
        let cpuid = intel_cpuid(true);
        let mut policy = allow_all_policy();
        policy.rdseed.approved = false;
        let mut raw = Counting { next: 0, calls: 0 };
        assert_eq!(sample_default(&cpuid, &mut raw, &policy).err(), Some(Rdseed64Error::NotApproved));
        assert_eq!(raw.calls, 0, "must not touch hardware once policy already refuses");
    }

    #[test]
    fn rejects_non_64_bit_width() {
        let cpuid = intel_cpuid(true);
        let mut policy = allow_all_policy();
        policy.rdseed.instruction_width_bits = 32;
        let mut raw = Counting { next: 0, calls: 0 };
        assert_eq!(sample_default(&cpuid, &mut raw, &policy).err(), Some(Rdseed64Error::UnsupportedWidth));
    }

    #[test]
    fn cpuid_gate_blocks_before_any_instruction_executes() {
        let cpuid = intel_cpuid(false);
        let policy = allow_all_policy();
        let mut raw = Counting { next: 0, calls: 0 };
        assert_eq!(sample_default(&cpuid, &mut raw, &policy).err(), Some(Rdseed64Error::CpuidUnsupported));
        assert_eq!(raw.calls, 0, "CPUID gate must run before touching the instruction");
    }

    #[test]
    fn unknown_vendor_is_refused_default_deny() {
        let mut cpuid = intel_cpuid(true);
        cpuid.vendor = *b"UnknownVendr";
        let policy = allow_all_policy();
        let mut raw = Counting { next: 0, calls: 0 };
        assert_eq!(sample_default(&cpuid, &mut raw, &policy).err(), Some(Rdseed64Error::CpuNotAllowed));
        assert_eq!(raw.calls, 0);
    }

    /// Regression test for the confirmed WP-24 finding: `sample` used to
    /// receive only the `[rdseed]` sub-policy, so
    /// `Policy::is_cpu_denylisted` (SPEC §15: "Known-bad platform
    /// denylist entries") was structurally unreachable — a CPU on the
    /// top-level denylist would still pass because `[[rdseed_cpu_rules]]`
    /// allowed it. `denylisted_policy` denylists the exact CPU
    /// `intel_cpuid` presents while its `[[rdseed_cpu_rules]]` still
    /// allow-lists that same CPU, so this only passes if the denylist
    /// check actually runs (and runs before any instruction executes).
    #[test]
    fn denylisted_cpu_is_refused_even_though_an_allow_rule_matches() {
        let cpuid = intel_cpuid(true);
        let policy = denylisted_policy();
        // Sanity check: the allow-rule alone would have accepted this CPU.
        let (family, model, stepping) = family_model_stepping(&cpuid);
        assert!(policy.rdseed.is_cpu_allowed("GenuineIntel", family, model, stepping));
        assert!(policy.is_cpu_denylisted("GenuineIntel", family, model, stepping));

        let mut raw = Counting { next: 0, calls: 0 };
        assert_eq!(sample_default(&cpuid, &mut raw, &policy).err(), Some(Rdseed64Error::CpuDenylisted));
        assert_eq!(raw.calls, 0, "denylist gate must run before touching the instruction");
    }

    #[test]
    fn retry_exhaustion_never_substitutes_zero() {
        struct AlwaysFail;
        impl RawInstructionSource for AlwaysFail {
            fn sample(&mut self) -> super::super::raw::RawSample {
                super::super::raw::RawSample { value: 0, success: false }
            }
        }
        let cpuid = intel_cpuid(true);
        let policy = allow_all_policy();
        let mut raw = AlwaysFail;
        assert_eq!(sample_default(&cpuid, &mut raw, &policy).err(), Some(Rdseed64Error::RetryExhausted));
    }

    #[test]
    fn all_zero_block_is_rejected() {
        struct AllZero;
        impl RawInstructionSource for AllZero {
            fn sample(&mut self) -> super::super::raw::RawSample {
                super::super::raw::RawSample { value: 0, success: true }
            }
        }
        let cpuid = intel_cpuid(true);
        let policy = allow_all_policy();
        let mut raw = AllZero;
        assert_eq!(
            sample_default(&cpuid, &mut raw, &policy).err(),
            Some(Rdseed64Error::Health(HealthError::AllZero))
        );
    }

    #[test]
    fn all_ff_block_is_rejected() {
        struct AllFf;
        impl RawInstructionSource for AllFf {
            fn sample(&mut self) -> super::super::raw::RawSample {
                super::super::raw::RawSample { value: u64::MAX, success: true }
            }
        }
        let cpuid = intel_cpuid(true);
        let policy = allow_all_policy();
        let mut raw = AllFf;
        assert_eq!(sample_default(&cpuid, &mut raw, &policy).err(), Some(Rdseed64Error::Health(HealthError::AllFf)));
    }

    #[test]
    fn identical_consecutive_blocks_are_rejected() {
        // Repeats the same 4-value cycle for both blocks A and B.
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
        let cpuid = intel_cpuid(true);
        let policy = allow_all_policy();
        let mut raw = Repeating { values: [0x1111, 0x2222, 0x3333, 0x4444], idx: 0 };
        assert_eq!(
            sample_default(&cpuid, &mut raw, &policy).err(),
            Some(Rdseed64Error::Health(HealthError::IdenticalConsecutiveBlocks))
        );
    }

    #[test]
    fn policy_min_values_of_zero_is_rejected() {
        let cpuid = intel_cpuid(true);
        let mut policy = allow_all_policy();
        policy.rdseed.min_successful_values = 0;
        let mut raw = Counting { next: 0, calls: 0 };
        assert_eq!(sample_default(&cpuid, &mut raw, &policy).err(), Some(Rdseed64Error::PolicyMinValuesInvalid));
    }

    #[test]
    fn policy_min_values_over_block_capacity_is_rejected() {
        let cpuid = intel_cpuid(true);
        let mut policy = allow_all_policy();
        policy.rdseed.min_successful_values = 5;
        let mut raw = Counting { next: 0, calls: 0 };
        assert_eq!(sample_default(&cpuid, &mut raw, &policy).err(), Some(Rdseed64Error::PolicyMinValuesInvalid));
    }

    /// Regression test for the confirmed WP-24 finding: the policy-floor
    /// check used to accept any `1..=VALUES_PER_BLOCK` value, so a signed
    /// policy with e.g. `min_successful_values = 1` would pass and
    /// `sample` would then emit an 8-byte record — well below the SPEC
    /// §15.2-mandated 256-bit (32-byte) floor ("collect at least four
    /// successful 64-bit values for a 256-bit source record"). Every
    /// under-4 value in range must now be refused.
    #[test]
    fn policy_min_values_below_four_is_rejected_for_every_under_value() {
        let cpuid = intel_cpuid(true);
        for n in 1..VALUES_PER_BLOCK {
            let mut policy = allow_all_policy();
            policy.rdseed.min_successful_values = n as u8;
            let mut raw = Counting { next: 0, calls: 0 };
            assert_eq!(
                sample_default(&cpuid, &mut raw, &policy).err(),
                Some(Rdseed64Error::PolicyMinValuesInvalid),
                "min_successful_values = {n} must be refused, not silently under-fill the record"
            );
            assert_eq!(raw.calls, 0, "must not touch hardware once policy already refuses");
        }
    }

    /// Regression test for the confirmed WP-24 finding, updated for audit
    /// finding L2: a valid policy must always yield a full record of TWO
    /// 256-bit blocks (64 bytes) — never a shorter one padded with the
    /// collection buffer's structural zero bytes, and never a health check
    /// run against anything but the bytes that end up in the record.
    #[test]
    fn accepted_record_is_always_two_full_256_bit_blocks() {
        let cpuid = intel_cpuid(true);
        let policy = allow_all_policy();
        assert_eq!(policy.rdseed.min_successful_values as usize, VALUES_PER_BLOCK);
        let mut raw = Counting { next: 0, calls: 0 };
        let record = sample_default(&cpuid, &mut raw, &policy).expect("all checks pass");
        assert_eq!(record.bytes().len(), 2 * VALUES_PER_BLOCK * 8);
        assert_eq!(record.bytes().len(), 2 * BLOCK_BYTES);
    }

    /// Audit finding L2 fail-closed regression: a healthy block A followed
    /// by a degenerate (all-zero) diagnostic block B must be REFUSED — the
    /// diagnostic block is health-checked *before* it is concatenated into
    /// the record, so a stuck second source can never yield either a
    /// block_a-only record or a truncated/half-scrubbed one. Mutation
    /// sanity: if the record were reverted to block_a-only (dropping the
    /// block_b health check and concatenation), this returns `Ok` and the
    /// assertion below fails.
    #[test]
    fn healthy_block_a_with_degenerate_block_b_is_refused() {
        // First four samples (block A) are distinct and healthy; every
        // sample from the fifth on is zero, so block B is all-zero.
        struct HealthyThenZero {
            calls: usize,
        }
        impl RawInstructionSource for HealthyThenZero {
            fn sample(&mut self) -> super::super::raw::RawSample {
                self.calls += 1;
                let value = if self.calls <= VALUES_PER_BLOCK { self.calls as u64 } else { 0 };
                super::super::raw::RawSample { value, success: true }
            }
        }
        let cpuid = intel_cpuid(true);
        let policy = allow_all_policy();
        let mut raw = HealthyThenZero { calls: 0 };
        let result = sample_default(&cpuid, &mut raw, &policy);
        assert_eq!(
            result.err(),
            Some(Rdseed64Error::Health(HealthError::AllZero)),
            "a degenerate diagnostic block B must fail closed, never yield a block_a-only record"
        );
        // Block A (4) + block B (4) were both fully sampled before the
        // health check on B rejected the whole attempt.
        assert_eq!(raw.calls, 2 * VALUES_PER_BLOCK);
    }

    // ------------------------------------------------------------------
    // Wall-clock deadline tests (real-hardware slow-RDSEED fix).
    // ------------------------------------------------------------------

    /// A-class: a source that never succeeds, paired with a clock that
    /// jumps far past the budget on every check, must abort in a small,
    /// bounded number of instruction attempts — never spin for the full
    /// (up to ~48-instruction) retry budget while the deadline is
    /// obviously already gone.
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
        let cpuid = intel_cpuid(true);
        let policy = allow_all_policy();
        let mut raw = AlwaysFail { calls: 0 };
        let mut clock = FakeClock::new(1_000);
        clock.advance_per_call = 10_000_000; // instantly past any budget
        let mut deadline = Deadline::start(&mut clock, 5_000);
        let mut obs = NullObserver;
        let result = sample(&cpuid, &mut raw, &policy, &mut deadline, &mut obs);
        assert_eq!(result.err(), Some(Rdseed64Error::DeadlineExceeded));
        assert!(raw.calls <= 3, "expected a small bounded number of instruction attempts, got {}", raw.calls);
    }

    /// A pre-expired deadline aborts before touching the raw source at
    /// all (zero instructions executed).
    #[test]
    fn expired_before_first_read_executes_zero_instructions() {
        let cpuid = intel_cpuid(true);
        let policy = allow_all_policy();
        let mut raw = Counting { next: 0, calls: 0 };
        // `Deadline` holds the clock's only mutable borrow for its whole
        // lifetime, so "time has already passed" must be baked into the
        // clock's starting state, not mutated in after `start`.
        let mut clock = FakeClock::starting_at(1, 1_000);
        let mut deadline = Deadline::start(&mut clock, 0);
        let mut obs = NullObserver;
        let result = sample(&cpuid, &mut raw, &policy, &mut deadline, &mut obs);
        assert_eq!(result.err(), Some(Rdseed64Error::DeadlineExceeded));
        assert_eq!(raw.calls, 0);
    }

    /// B-class fail-closed regression: block A fully succeeds (SPEC §16's
    /// mandatory diagnostic comparison has not run yet), the deadline
    /// then expires exactly as block B's collection starts. The result
    /// MUST be `Err`, never `Ok` with an unaudited block A — a record is
    /// only ever built after the full diagnostic comparison completes.
    #[test]
    fn deadline_between_blocks_never_accepts_block_a() {
        let cpuid = intel_cpuid(true);
        let policy = allow_all_policy();
        let mut raw = Counting { next: 0, calls: 0 };
        let mut clock = FakeClock::new(1);
        clock.advance_per_call = 1;
        // Tuned so all four block-A deadline checks (values 1..=4) pass
        // and the fifth check (block B's first value) is exactly expired.
        let mut deadline = Deadline::start(&mut clock, 5);
        let mut obs = NullObserver;
        let result = sample(&cpuid, &mut raw, &policy, &mut deadline, &mut obs);
        assert_eq!(result.err(), Some(Rdseed64Error::DeadlineExceeded));
        assert_eq!(
            raw.calls, VALUES_PER_BLOCK,
            "block A must have fully completed via the raw source before the deadline fired for block B"
        );
    }

    /// C-class: a fast, healthy clock must not regress the happy path —
    /// exact same record shape/algo id/byte count as before the deadline
    /// was introduced.
    #[test]
    fn fast_clock_happy_path_unchanged() {
        let cpuid = intel_cpuid(true);
        let policy = allow_all_policy();
        let mut raw = Counting { next: 0, calls: 0 };
        let mut clock = FakeClock::new(1_000_000);
        clock.advance_per_call = 1;
        let mut deadline = Deadline::start(&mut clock, 5_000);
        let mut obs = NullObserver;
        let record = sample(&cpuid, &mut raw, &policy, &mut deadline, &mut obs).expect("all checks pass");
        assert_eq!(record.tag(), SourceTag::X86Rdseed64);
        assert_eq!(record.algo_id(), ALGO_ID);
        // Audit finding L2: 64-byte (two-block) record.
        assert_eq!(record.bytes().len(), 2 * BLOCK_BYTES);
        assert_eq!(raw.calls, 8);
    }

    /// D-class: the progress observer receives one tick per collected
    /// value across the full happy path (block A + one diagnostic block).
    #[test]
    fn observer_ticks_once_per_collected_value_across_full_sample() {
        struct CountingObserver {
            ticks: usize,
        }
        impl AcquisitionObserver for CountingObserver {
            fn value_collected(&mut self) {
                self.ticks += 1;
            }
        }
        let cpuid = intel_cpuid(true);
        let policy = allow_all_policy();
        let mut raw = Counting { next: 0, calls: 0 };
        let mut clock = FakeClock::new(1_000_000);
        clock.advance_per_call = 1;
        let mut deadline = Deadline::start(&mut clock, 5_000);
        let mut obs = CountingObserver { ticks: 0 };
        let record = sample(&cpuid, &mut raw, &policy, &mut deadline, &mut obs).expect("all checks pass");
        drop(record);
        assert_eq!(obs.ticks, 8, "4 values for block A + 4 for the one diagnostic block");
    }
}
