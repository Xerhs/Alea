//! `EFI_RNG_PROTOCOL` machine-entropy driver (WP-24, SPEC §15.1).
//!
//! Order of operations, each a documented SPEC §15.1 requirement:
//! 1. The protocol has already been located (SPEC §15.1: "the protocol
//!    can be located reliably") — that step lives in
//!    [`uefi_backend::locate`], since it needs live UEFI boot services
//!    and has nothing to host-test.
//! 2. [`EfiRngProvider::get_info`] enumerates supported algorithms into a
//!    fixed buffer (SPEC §15.1: "enumerate supported algorithms into a
//!    fixed-size buffer"; "reject an algorithm list larger than the
//!    reviewed maximum" — the provider itself must refuse to report more
//!    than [`MAX_ENUMERATED_ALGORITHMS`], never silently truncate).
//! 3. Duplicate or all-zero ("malformed" — `EMPTY_ALGORITHM` is a
//!    firmware-internal sentinel, never a real advertised algorithm)
//!    entries are rejected.
//! 4. Each algorithm is rendered to canonical GUID text ([`super::guid`])
//!    and checked against the compiled-in policy's `allowed_algorithms`
//!    (SPEC §15.1: "an explicit approved algorithm rather than an
//!    ambiguous default"; "unknown and vendor-specific algorithms as
//!    unapproved unless the policy explicitly allows them").
//! 5. Two independent 32-byte diagnostic reads are taken and passed
//!    through the SPEC §16 catastrophic checks (SPEC §15.1: "repeated
//!    diagnostic samples pass catastrophic checks").
//! 6. Exactly `request_len` bytes are read for the final record (SPEC
//!    §15.1: "the exact requested length is returned successfully" —
//!    `get_rng` returning `Ok(())` for a `buf.len() == request_len` call
//!    is this driver's definition of "exact length"; a provider that
//!    silently short-fills a buffer while reporting success is itself
//!    violating its contract, not something this driver can detect from
//!    the byte count alone).
//!
//! SPEC §15.1 also requires never describing this source as TPM-backed
//! without separate verification, and never equating byte count with
//! proven entropy — both are presentation-layer (WP-25/26) obligations;
//! this module never emits or implies either claim.

use seed_core::contracts::{SourceTag, MAX_MACHINE_SOURCE_BYTES};
use seed_protocol::policy::EfiRngPolicy;

/// The EFI-RNG production/diagnostic block size, in bytes (256 bits).
///
/// This is deliberately a dedicated constant, NOT
/// [`MAX_MACHINE_SOURCE_BYTES`]: that shared cap was raised to 64 by the
/// 2026-08-08 RDSEED 2×-margin change (L2), and the EFI path must not inherit
/// that. Two properties depend on the EFI final read being exactly this size:
/// (1) the L1 repeat-check compares the final read against the retained
/// diagnostic block, and [`health::check_not_repeated`] treats
/// different-length slices as never-identical — so a longer production read
/// would silently disable the check; (2) the EFI source record stays 32 bytes,
/// unchanged by L2. The diagnostic blocks below are sized from this same
/// constant so the two can never drift. Both invariants are compile-time
/// asserted below.
pub const EFI_RNG_REQUEST_BYTES: usize = 32;

// The pinned request must fit the shared record buffer/cap, and must stay the
// 32-byte block size the diagnostic reads use (so the L1 repeat-check compares
// equal-length slices — `health::check_not_repeated` treats different-length
// blocks as never identical). A future change that breaks either — e.g. another
// cap bump leaking in — is a compile error, not a silently-disabled check.
const _: () = assert!(EFI_RNG_REQUEST_BYTES <= MAX_MACHINE_SOURCE_BYTES);
const _: () = assert!(EFI_RNG_REQUEST_BYTES == 32);

use super::guid::{format_guid, GUID_TEXT_LEN};
use super::health::{self, HealthError};
use super::record::SourceRecord;
use super::util::scrub;
use crate::time::Deadline;

/// Reviewed maximum count of algorithms this driver will enumerate
/// (SPEC §15.1: "reject an algorithm list larger than the reviewed
/// maximum"). Matches `seed_protocol::policy::types::MAX_ALGORITHMS`
/// (16) — a policy can never approve more algorithms than this driver
/// can even hold, so the two bounds cannot silently drift apart in a way
/// that hides an approved algorithm this driver would refuse to look at.
pub const MAX_ENUMERATED_ALGORITHMS: usize = 16;

/// One raw, wire-order GUID (see [`super::guid`]'s module doc for the
/// byte layout).
pub type RawGuid = [u8; 16];

/// The all-zero GUID (`EFI_RNG_ALGORITHM` sentinel `EMPTY_ALGORITHM`,
/// per `uefi-raw`'s `RngAlgorithmType`): a placeholder value, never a
/// real advertised algorithm (SPEC §15.1: "malformed identifiers").
const EMPTY_ALGORITHM: RawGuid = [0u8; 16];

/// Why an EFI RNG sample attempt was refused or failed (SPEC §15.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EfiRngError {
    /// Locating `EFI_RNG_PROTOCOL` failed (SPEC §15.1: "can be located
    /// reliably").
    LocateFailed,
    /// `GetInfo()` itself failed.
    GetInfoFailed,
    /// The firmware reported more algorithms than
    /// [`MAX_ENUMERATED_ALGORITHMS`] (SPEC §15.1: "reject an algorithm
    /// list larger than the reviewed maximum").
    TooManyAlgorithms,
    /// The same algorithm GUID appeared twice in the enumerated list
    /// (SPEC §15.1: "reject duplicate... identifiers").
    DuplicateAlgorithm,
    /// The all-zero sentinel GUID appeared in the enumerated list (SPEC
    /// §15.1: "reject... malformed identifiers").
    MalformedAlgorithm,
    /// No enumerated algorithm is both policy-`approved` and listed in
    /// `allowed_algorithms` (SPEC §15.1: "explicit approved algorithm
    /// rather than an ambiguous default").
    NoApprovedAlgorithm,
    /// `request_len` was `0` or exceeded `MAX_MACHINE_SOURCE_BYTES`.
    InvalidRequestLength,
    /// `GetRng()` failed for a diagnostic or final read.
    GetRngFailed,
    /// The wall-clock acquisition budget expired before a read could be
    /// attempted (real-hardware slow-RDSEED fix — see `crate::time`'s
    /// module doc; dormant under the shipped v1 policy, which ships EFI
    /// RNG unapproved, but included here for defense in depth since this
    /// mechanism shares the same acquisition deadline as RDSEED/RDRAND).
    DeadlineExceeded,
    /// A sampled block failed a SPEC §16 catastrophic check.
    Health(HealthError),
}

/// Backend abstraction over `EFI_RNG_PROTOCOL`, so the policy-filtering /
/// health-check logic in [`sample`] is host-testable without linking the
/// `uefi` crate (SPEC §15.1's requirements are about *how this driver
/// behaves*, not about the firmware call ABI). [`uefi_backend::RealEfiRng`]
/// is the real adapter, compiled only for the `uefi` target.
pub trait EfiRngProvider {
    /// Enumerates supported algorithm GUIDs into `out`, returning how
    /// many were written. MUST return
    /// `Err(EfiRngError::TooManyAlgorithms)` rather than truncating if
    /// the firmware reports more than `out.len()`
    /// (= [`MAX_ENUMERATED_ALGORITHMS`]) algorithms.
    fn get_info(&mut self, out: &mut [RawGuid; MAX_ENUMERATED_ALGORITHMS]) -> Result<usize, EfiRngError>;

    /// Requests exactly `buf.len()` bytes using `algorithm` (firmware
    /// default if `None`). MUST fail rather than partially fill `buf`
    /// and report success.
    fn get_rng(&mut self, algorithm: Option<RawGuid>, buf: &mut [u8]) -> Result<(), EfiRngError>;
}

fn pick_approved_algorithm(algos: &[RawGuid], policy: &EfiRngPolicy) -> Option<RawGuid> {
    for &algo in algos {
        let text = format_guid(&algo);
        // `format_guid` only ever emits ASCII hex digits and `-`, so this
        // is always valid UTF-8; `unwrap_or("")` is a defensive fallback
        // that simply never matches any policy entry.
        let text_str = core::str::from_utf8(&text).unwrap_or("");
        if policy.is_algorithm_allowed(text_str) {
            return Some(algo);
        }
    }
    None
}

fn diagnostic_read(
    provider: &mut dyn EfiRngProvider,
    algo: RawGuid,
    out: &mut [u8; 32],
    deadline: &mut Deadline<'_>,
) -> Result<(), EfiRngError> {
    if deadline.expired() {
        return Err(EfiRngError::DeadlineExceeded);
    }
    provider.get_rng(Some(algo), out).map_err(|_| EfiRngError::GetRngFailed)
}

/// Samples one EFI RNG [`SourceRecord`] (SPEC §15.1). See the module doc
/// for the exact sequence of checks. `request_len` is the number of
/// final source bytes wanted (`1..=MAX_MACHINE_SOURCE_BYTES`).
///
/// `deadline` is checked before every `get_rng` protocol call (real-
/// hardware slow-RDSEED fix — see `crate::time`'s module doc); dormant
/// under the shipped v1 policy (EFI RNG ships unapproved), included for
/// defense in depth since this mechanism shares the acquisition-wide
/// deadline with RDSEED/RDRAND.
pub fn sample(
    provider: &mut dyn EfiRngProvider,
    policy: &EfiRngPolicy,
    request_len: usize,
    deadline: &mut Deadline<'_>,
) -> Result<SourceRecord, EfiRngError> {
    if request_len == 0 || request_len > MAX_MACHINE_SOURCE_BYTES {
        return Err(EfiRngError::InvalidRequestLength);
    }

    let mut algos = [EMPTY_ALGORITHM; MAX_ENUMERATED_ALGORITHMS];
    let count = provider.get_info(&mut algos)?;
    if count > MAX_ENUMERATED_ALGORITHMS {
        return Err(EfiRngError::TooManyAlgorithms);
    }
    let algos = &algos[..count];

    for &algo in algos {
        if algo == EMPTY_ALGORITHM {
            return Err(EfiRngError::MalformedAlgorithm);
        }
    }
    for i in 0..algos.len() {
        for j in (i + 1)..algos.len() {
            if algos[i] == algos[j] {
                return Err(EfiRngError::DuplicateAlgorithm);
            }
        }
    }

    let algo = pick_approved_algorithm(algos, policy).ok_or(EfiRngError::NoApprovedAlgorithm)?;

    // SPEC §15.1: "repeated diagnostic samples pass catastrophic
    // checks" — two independent 256-bit reads, checked individually and
    // against each other, distinct from the final production read below.
    let mut diag_a = [0u8; EFI_RNG_REQUEST_BYTES];
    let mut diag_b = [0u8; EFI_RNG_REQUEST_BYTES];
    diagnostic_read(provider, algo, &mut diag_a, deadline)?;
    if let Err(e) = health::check_not_degenerate(&diag_a) {
        scrub(&mut diag_a);
        scrub(&mut diag_b);
        return Err(EfiRngError::Health(e));
    }
    diagnostic_read(provider, algo, &mut diag_b, deadline)?;
    let degenerate_b = health::check_not_degenerate(&diag_b);
    let repeated = health::check_not_repeated(&diag_a, &diag_b);
    scrub(&mut diag_a);
    if let Err(e) = degenerate_b.and(repeated) {
        scrub(&mut diag_b);
        return Err(EfiRngError::Health(e));
    }
    // L1 (2026-08-08 RNG-robustness audit): retain the last diagnostic
    // block so the final production read can be repeat-checked against it.
    // A firmware RNG that wedges immediately after the diagnostics and
    // replays this exact block as the production read would otherwise
    // clear the degeneracy check below undetected — the SPEC §15.1
    // identical-consecutive guard already runs between diag_a/diag_b, and
    // is here extended across the diagnostic/production boundary. (Dormant
    // under the shipped v1 policy — EFI RNG is unapproved — but the same
    // defense-in-depth rationale as the rest of this function.) `last_diag`
    // is scrubbed on every exit path below, mirroring the fail-closed
    // scrub idiom the diagnostic reads already use.
    let mut last_diag = diag_b;
    scrub(&mut diag_b);

    if deadline.expired() {
        scrub(&mut last_diag);
        return Err(EfiRngError::DeadlineExceeded);
    }
    let mut buf = [0u8; MAX_MACHINE_SOURCE_BYTES];
    if provider.get_rng(Some(algo), &mut buf[..request_len]).is_err() {
        scrub(&mut last_diag);
        return Err(EfiRngError::GetRngFailed);
    }
    if let Err(e) = health::check_not_degenerate(&buf[..request_len]) {
        scrub(&mut buf);
        scrub(&mut last_diag);
        return Err(EfiRngError::Health(e));
    }
    if let Err(e) = health::check_not_repeated(&last_diag, &buf[..request_len]) {
        scrub(&mut buf);
        scrub(&mut last_diag);
        return Err(EfiRngError::Health(e));
    }
    scrub(&mut last_diag);

    let text = format_guid(&algo);
    let record = SourceRecord::new(SourceTag::ApprovedEfiRng, &text, &buf[..request_len])
        .ok_or(EfiRngError::InvalidRequestLength)?;
    scrub(&mut buf);
    Ok(record)
}

const _: () = assert!(GUID_TEXT_LEN == seed_core::contracts::MAX_ALGO_ID);

/// Real `EFI_RNG_PROTOCOL` adapter. Only compiled for the `uefi` target
/// family, never pulled into host `cargo test` runs.
#[cfg(target_os = "uefi")]
pub mod uefi_backend {
    use super::{EfiRngError, EfiRngProvider, RawGuid, MAX_ENUMERATED_ALGORITHMS};
    use uefi::proto::rng::{Rng, RngAlgorithmType};
    use uefi::Guid;

    /// Adapts `uefi::proto::rng::Rng` to [`EfiRngProvider`].
    pub struct RealEfiRng<'a> {
        rng: &'a mut Rng,
    }

    impl<'a> RealEfiRng<'a> {
        /// Wraps an already-located `Rng` protocol instance.
        pub fn new(rng: &'a mut Rng) -> Self {
            Self { rng }
        }
    }

    impl EfiRngProvider for RealEfiRng<'_> {
        fn get_info(
            &mut self,
            out: &mut [RawGuid; MAX_ENUMERATED_ALGORITHMS],
        ) -> Result<usize, EfiRngError> {
            let mut list = [RngAlgorithmType::EMPTY_ALGORITHM; MAX_ENUMERATED_ALGORITHMS];
            match self.rng.get_info(&mut list) {
                Ok(slice) => {
                    if slice.len() > MAX_ENUMERATED_ALGORITHMS {
                        // Defensive: `list`'s own length already bounds
                        // this, but keep the check explicit and cheap.
                        return Err(EfiRngError::TooManyAlgorithms);
                    }
                    for (i, algo) in slice.iter().enumerate() {
                        out[i] = algo.0.to_bytes();
                    }
                    Ok(slice.len())
                }
                Err(err) => {
                    if err.status() == uefi::Status::BUFFER_TOO_SMALL {
                        Err(EfiRngError::TooManyAlgorithms)
                    } else {
                        Err(EfiRngError::GetInfoFailed)
                    }
                }
            }
        }

        fn get_rng(&mut self, algorithm: Option<RawGuid>, buf: &mut [u8]) -> Result<(), EfiRngError> {
            let algo = algorithm.map(|bytes| RngAlgorithmType(Guid::from_bytes(bytes)));
            self.rng.get_rng(algo, buf).map_err(|_| EfiRngError::GetRngFailed)
        }
    }

    /// Locates `EFI_RNG_PROTOCOL` (SPEC §15.1: "can be located
    /// reliably"), opened exclusively so no other agent can interleave
    /// calls against the same protocol instance mid-sample.
    pub fn locate() -> Result<uefi::boot::ScopedProtocol<Rng>, EfiRngError> {
        let handle =
            uefi::boot::get_handle_for_protocol::<Rng>().map_err(|_| EfiRngError::LocateFailed)?;
        uefi::boot::open_protocol_exclusive::<Rng>(handle).map_err(|_| EfiRngError::LocateFailed)
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::test_support::FakeClock;
    use std::vec::Vec;

    /// Mechanical test helper: see `rdseed.rs`'s identical helper doc
    /// comment. Wraps `sample` with a never-expiring `Deadline` for every
    /// pre-existing test in this module.
    fn sample_default(
        provider: &mut dyn EfiRngProvider,
        policy: &EfiRngPolicy,
        request_len: usize,
    ) -> Result<SourceRecord, EfiRngError> {
        let mut clock = FakeClock::new(1_000);
        let mut deadline = Deadline::start(&mut clock, 5_000);
        sample(provider, policy, request_len, &mut deadline)
    }

    /// A scripted [`EfiRngProvider`]: fixed algorithm list, and a queue
    /// of canned `get_rng` responses consumed in call order.
    struct MockProvider {
        algos: Vec<RawGuid>,
        get_info_err: Option<EfiRngError>,
        rng_responses: Vec<Result<[u8; 32], EfiRngError>>,
        next: usize,
        get_rng_calls: usize,
    }

    impl EfiRngProvider for MockProvider {
        fn get_info(&mut self, out: &mut [RawGuid; MAX_ENUMERATED_ALGORITHMS]) -> Result<usize, EfiRngError> {
            if let Some(e) = self.get_info_err {
                return Err(e);
            }
            for (i, &a) in self.algos.iter().enumerate() {
                out[i] = a;
            }
            Ok(self.algos.len())
        }

        fn get_rng(&mut self, _algorithm: Option<RawGuid>, buf: &mut [u8]) -> Result<(), EfiRngError> {
            self.get_rng_calls += 1;
            let resp = self.rng_responses[self.next];
            self.next += 1;
            match resp {
                Ok(bytes) => {
                    buf.copy_from_slice(&bytes[..buf.len()]);
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
    }

    const APPROVED_GUID: RawGuid = [0x11u8; 16];
    const OTHER_GUID: RawGuid = [0x22u8; 16];

    fn policy_approving(guid: RawGuid) -> EfiRngPolicy {
        let text = format_guid(&guid);
        let text_str = core::str::from_utf8(&text).unwrap();
        let toml = std::format!(
            r#"
policy_version = 1

[efi_rng]
approved = true
sole_source_allowed = false
max_algorithms = 8
allowed_algorithms = ["{text_str}"]

[rdseed]
approved = false
sole_source_allowed = false
instruction_width_bits = 64
retry_limit = 5
min_successful_values = 4
diagnostic_blocks = 2

[rdrand]
approved = false
sole_source_allowed = false
supplementary_only = true

[usb_trng]
approved = false
sole_source_allowed = false
min_read_bytes = 32
read_timeout_ms = 2000
max_read_retries = 2

[tpm2]
approved = false
sole_source_allowed = false
max_bytes_per_call = 32
retry_limit = 3
max_manufacturers = 8
allowed_manufacturers = []

[tpm12]
approved = false
sole_source_allowed = false
max_bytes_per_call = 32
retry_limit = 3
max_read_rounds = 8
max_manufacturers = 8
allowed_manufacturers = []
"#
        );
        seed_protocol::policy::parse(&toml).expect("well-formed test policy").efi_rng
    }

    fn distinct_block(seed: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        for (i, v) in b.iter_mut().enumerate() {
            *v = seed.wrapping_add(i as u8).wrapping_add(1);
        }
        b
    }

    #[test]
    fn happy_path_produces_valid_record() {
        let policy = policy_approving(APPROVED_GUID);
        let mut provider = MockProvider {
            algos: std::vec![APPROVED_GUID],
            get_info_err: None,
            rng_responses: std::vec![Ok(distinct_block(1)), Ok(distinct_block(2)), Ok(distinct_block(3))],
            next: 0,
            get_rng_calls: 0,
        };
        let record = sample_default(&mut provider, &policy, 32).expect("all checks pass");
        assert_eq!(record.tag(), SourceTag::ApprovedEfiRng);
        assert_eq!(record.bytes(), &distinct_block(3));
        assert_eq!(provider.get_rng_calls, 3, "two diagnostic reads + one production read");
    }

    #[test]
    fn record_at_the_pinned_call_site_request_length_stays_one_block() {
        // N1 regression (2026-08-08): the real EFI call site
        // (`firmware_wiring`) passes `EFI_RNG_REQUEST_BYTES`, NOT the shared
        // machine-source cap. When L2 raised that cap 32->64, using it here
        // would have (a) grown the EFI record to 64 and (b) disabled the L1
        // repeat-check (32-byte diag vs 64-byte read never compare equal).
        // Pin that a record built at the pinned request length is exactly one
        // 32-byte block, matching the diagnostic block size.
        let policy = policy_approving(APPROVED_GUID);
        let mut provider = MockProvider {
            algos: std::vec![APPROVED_GUID],
            get_info_err: None,
            rng_responses: std::vec![Ok(distinct_block(1)), Ok(distinct_block(2)), Ok(distinct_block(3))],
            next: 0,
            get_rng_calls: 0,
        };
        let record = sample_default(&mut provider, &policy, EFI_RNG_REQUEST_BYTES)
            .expect("all checks pass");
        assert_eq!(record.bytes().len(), EFI_RNG_REQUEST_BYTES);
        assert_eq!(record.bytes().len(), 32, "one 256-bit block, not two");
    }

    #[test]
    fn request_len_shorter_than_full_block_is_honored_exactly() {
        let policy = policy_approving(APPROVED_GUID);
        let mut provider = MockProvider {
            algos: std::vec![APPROVED_GUID],
            get_info_err: None,
            rng_responses: std::vec![Ok(distinct_block(1)), Ok(distinct_block(2)), Ok(distinct_block(3))],
            next: 0,
            get_rng_calls: 0,
        };
        let record = sample_default(&mut provider, &policy, 16).expect("all checks pass");
        assert_eq!(record.bytes().len(), 16);
        assert_eq!(record.bytes(), &distinct_block(3)[..16]);
    }

    #[test]
    fn no_approved_algorithm_when_policy_disapproves_all() {
        let policy = policy_approving(OTHER_GUID); // approves a different GUID
        let mut provider = MockProvider {
            algos: std::vec![APPROVED_GUID],
            get_info_err: None,
            rng_responses: std::vec![],
            next: 0,
            get_rng_calls: 0,
        };
        assert_eq!(sample_default(&mut provider, &policy, 32).err(), Some(EfiRngError::NoApprovedAlgorithm));
        assert_eq!(provider.get_rng_calls, 0, "never touches get_rng without an approved algorithm");
    }

    #[test]
    fn empty_algorithm_list_is_refused() {
        let policy = policy_approving(APPROVED_GUID);
        let mut provider = MockProvider {
            algos: std::vec![],
            get_info_err: None,
            rng_responses: std::vec![],
            next: 0,
            get_rng_calls: 0,
        };
        assert_eq!(sample_default(&mut provider, &policy, 32).err(), Some(EfiRngError::NoApprovedAlgorithm));
    }

    #[test]
    fn duplicate_algorithm_is_rejected() {
        let policy = policy_approving(APPROVED_GUID);
        let mut provider = MockProvider {
            algos: std::vec![APPROVED_GUID, APPROVED_GUID],
            get_info_err: None,
            rng_responses: std::vec![],
            next: 0,
            get_rng_calls: 0,
        };
        assert_eq!(sample_default(&mut provider, &policy, 32).err(), Some(EfiRngError::DuplicateAlgorithm));
    }

    #[test]
    fn malformed_all_zero_algorithm_is_rejected() {
        let policy = policy_approving(APPROVED_GUID);
        let mut provider = MockProvider {
            algos: std::vec![EMPTY_ALGORITHM],
            get_info_err: None,
            rng_responses: std::vec![],
            next: 0,
            get_rng_calls: 0,
        };
        assert_eq!(sample_default(&mut provider, &policy, 32).err(), Some(EfiRngError::MalformedAlgorithm));
    }

    #[test]
    fn provider_reporting_too_many_algorithms_is_propagated() {
        let policy = policy_approving(APPROVED_GUID);
        let mut provider = MockProvider {
            algos: std::vec![],
            get_info_err: Some(EfiRngError::TooManyAlgorithms),
            rng_responses: std::vec![],
            next: 0,
            get_rng_calls: 0,
        };
        assert_eq!(sample_default(&mut provider, &policy, 32).err(), Some(EfiRngError::TooManyAlgorithms));
    }

    #[test]
    fn all_zero_diagnostic_block_is_rejected() {
        let policy = policy_approving(APPROVED_GUID);
        let mut provider = MockProvider {
            algos: std::vec![APPROVED_GUID],
            get_info_err: None,
            rng_responses: std::vec![Ok([0u8; 32])],
            next: 0,
            get_rng_calls: 0,
        };
        assert_eq!(
            sample_default(&mut provider, &policy, 32).err(),
            Some(EfiRngError::Health(HealthError::AllZero))
        );
    }

    #[test]
    fn identical_diagnostic_blocks_are_rejected() {
        let policy = policy_approving(APPROVED_GUID);
        let block = distinct_block(7);
        let mut provider = MockProvider {
            algos: std::vec![APPROVED_GUID],
            get_info_err: None,
            rng_responses: std::vec![Ok(block), Ok(block)],
            next: 0,
            get_rng_calls: 0,
        };
        assert_eq!(
            sample_default(&mut provider, &policy, 32).err(),
            Some(EfiRngError::Health(HealthError::IdenticalConsecutiveBlocks))
        );
    }

    /// L1 (2026-08-08 RNG-robustness audit): the final production read is
    /// now repeat-checked against the last diagnostic block, not just for
    /// degeneracy. A firmware RNG that wedges right after the diagnostics
    /// and replays diag_b as the production read (distinct diagnostics, so
    /// the diag_a/diag_b guard passes) must be rejected exactly as an
    /// identical diagnostic pair is. Before the fix this replayed block —
    /// non-degenerate — sailed through and became the record's bytes.
    #[test]
    fn production_read_equal_to_last_diagnostic_block_is_rejected() {
        let policy = policy_approving(APPROVED_GUID);
        let diag_b = distinct_block(2);
        let mut provider = MockProvider {
            algos: std::vec![APPROVED_GUID],
            get_info_err: None,
            // diag_a, diag_b (distinct -> diag pair passes), then the
            // production read replays diag_b verbatim.
            rng_responses: std::vec![Ok(distinct_block(1)), Ok(diag_b), Ok(diag_b)],
            next: 0,
            get_rng_calls: 0,
        };
        assert_eq!(
            sample_default(&mut provider, &policy, 32).err(),
            Some(EfiRngError::Health(HealthError::IdenticalConsecutiveBlocks)),
            "a production read replaying the last diagnostic block must fail closed"
        );
        assert_eq!(provider.get_rng_calls, 3, "the production read must actually have been performed and then rejected");
    }

    #[test]
    fn get_rng_failure_on_final_read_is_propagated() {
        let policy = policy_approving(APPROVED_GUID);
        let mut provider = MockProvider {
            algos: std::vec![APPROVED_GUID],
            get_info_err: None,
            rng_responses: std::vec![
                Ok(distinct_block(1)),
                Ok(distinct_block(2)),
                Err(EfiRngError::GetRngFailed),
            ],
            next: 0,
            get_rng_calls: 0,
        };
        assert_eq!(sample_default(&mut provider, &policy, 32).err(), Some(EfiRngError::GetRngFailed));
    }

    #[test]
    fn zero_request_length_is_rejected() {
        let policy = policy_approving(APPROVED_GUID);
        let mut provider = MockProvider {
            algos: std::vec![APPROVED_GUID],
            get_info_err: None,
            rng_responses: std::vec![],
            next: 0,
            get_rng_calls: 0,
        };
        assert_eq!(sample_default(&mut provider, &policy, 0).err(), Some(EfiRngError::InvalidRequestLength));
    }

    #[test]
    fn oversized_request_length_is_rejected() {
        let policy = policy_approving(APPROVED_GUID);
        let mut provider = MockProvider {
            algos: std::vec![APPROVED_GUID],
            get_info_err: None,
            rng_responses: std::vec![],
            next: 0,
            get_rng_calls: 0,
        };
        assert_eq!(
            sample_default(&mut provider, &policy, MAX_MACHINE_SOURCE_BYTES + 1).err(),
            Some(EfiRngError::InvalidRequestLength)
        );
    }

    #[test]
    fn unapproved_policy_never_reads_rng() {
        // efi_rng.approved = false entirely: is_algorithm_allowed always
        // false regardless of allowed_algorithms content.
        let toml = r#"
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
approved = false
sole_source_allowed = false
supplementary_only = true

[usb_trng]
approved = false
sole_source_allowed = false
min_read_bytes = 32
read_timeout_ms = 2000
max_read_retries = 2

[tpm2]
approved = false
sole_source_allowed = false
max_bytes_per_call = 32
retry_limit = 3
max_manufacturers = 8
allowed_manufacturers = []

[tpm12]
approved = false
sole_source_allowed = false
max_bytes_per_call = 32
retry_limit = 3
max_read_rounds = 8
max_manufacturers = 8
allowed_manufacturers = []
"#;
        let policy = seed_protocol::policy::parse(toml).unwrap().efi_rng;
        let mut provider = MockProvider {
            algos: std::vec![APPROVED_GUID],
            get_info_err: None,
            rng_responses: std::vec![],
            next: 0,
            get_rng_calls: 0,
        };
        assert_eq!(sample_default(&mut provider, &policy, 32).err(), Some(EfiRngError::NoApprovedAlgorithm));
        assert_eq!(provider.get_rng_calls, 0);
    }

    // ------------------------------------------------------------------
    // Wall-clock deadline tests (real-hardware slow-RDSEED fix; dormant
    // under the shipped policy, defense in depth).
    // ------------------------------------------------------------------

    #[test]
    fn expired_deadline_is_checked_before_the_first_get_rng_call() {
        let policy = policy_approving(APPROVED_GUID);
        let mut provider = MockProvider {
            algos: std::vec![APPROVED_GUID],
            get_info_err: None,
            rng_responses: std::vec![Ok(distinct_block(1)), Ok(distinct_block(2)), Ok(distinct_block(3))],
            next: 0,
            get_rng_calls: 0,
        };
        // `Deadline` holds the clock's only mutable borrow for its whole
        // lifetime, so "time has already passed" must be baked into the
        // clock's starting state, not mutated in after `start`.
        let mut clock = FakeClock::starting_at(1, 1_000);
        let mut deadline = Deadline::start(&mut clock, 0);
        let result = sample(&mut provider, &policy, 32, &mut deadline);
        assert_eq!(result.err(), Some(EfiRngError::DeadlineExceeded));
        assert_eq!(provider.get_rng_calls, 0, "must not touch the protocol once the deadline is already gone");
    }

    #[test]
    fn deadline_expiring_between_diagnostic_reads_never_completes_the_sample() {
        let policy = policy_approving(APPROVED_GUID);
        let mut provider = MockProvider {
            algos: std::vec![APPROVED_GUID],
            get_info_err: None,
            rng_responses: std::vec![Ok(distinct_block(1)), Ok(distinct_block(2)), Ok(distinct_block(3))],
            next: 0,
            get_rng_calls: 0,
        };
        // ticks_per_ms=1, budget=2ms, advancing 1 tick per `now_ticks()`
        // call: the check before diag_a passes (tick 1 < 2), diag_a is
        // read successfully, then the check before diag_b is exactly
        // expired (tick 2 >= 2) -- proving a completed diag_a is still
        // discarded, never smuggled into an `Ok` result.
        let mut clock = FakeClock::new(1);
        clock.advance_per_call = 1;
        let mut deadline = Deadline::start(&mut clock, 2);
        let result = sample(&mut provider, &policy, 32, &mut deadline);
        assert_eq!(result.err(), Some(EfiRngError::DeadlineExceeded));
        assert_eq!(provider.get_rng_calls, 1, "diag_a must have been read before the deadline fired for diag_b");
    }

    #[test]
    fn fast_clock_happy_path_unchanged() {
        let policy = policy_approving(APPROVED_GUID);
        let mut provider = MockProvider {
            algos: std::vec![APPROVED_GUID],
            get_info_err: None,
            rng_responses: std::vec![Ok(distinct_block(1)), Ok(distinct_block(2)), Ok(distinct_block(3))],
            next: 0,
            get_rng_calls: 0,
        };
        let mut clock = FakeClock::new(1_000_000);
        clock.advance_per_call = 1;
        let mut deadline = Deadline::start(&mut clock, 5_000);
        let record = sample(&mut provider, &policy, 32, &mut deadline).expect("all checks pass");
        assert_eq!(record.tag(), SourceTag::ApprovedEfiRng);
        assert_eq!(record.bytes(), &distinct_block(3));
        assert_eq!(provider.get_rng_calls, 3);
    }
}
