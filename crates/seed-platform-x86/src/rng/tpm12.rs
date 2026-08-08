//! TPM 1.2 `TPM_GetRandom` driver (SPEC_TPM12_ENTROPY.md §1, §4, §5).
//!
//! Sibling of [`super::tpm2`], same byte-level discipline: the
//! [`Tpm12Transport`] trait carries raw command/response blocks, so wire
//! marshalling and response validation are host-tested byte-for-byte
//! (`tests::ScriptedTransport`), and the real backend
//! ([`uefi_backend::RealTpm12`]) is a thin adapter over
//! `uefi::proto::tcg::v1::Tcg::pass_through_to_tpm`.
//!
//! Wire constants (SPEC_TPM12_ENTROPY.md revision log; TPM Main
//! Specification Part 2/Part 3, corroborated by the Linux kernel's
//! `tpm1_get_random` — re-verified at implementation time per the parent
//! spec's discipline): `TPM_TAG_RQU_COMMAND = 0x00C1`,
//! `TPM_TAG_RSP_COMMAND = 0x00C4`, `TPM_ORD_GetRandom = 0x0000_0046`,
//! `bytesRequested`/`randomBytesSize` are **u32** (unlike 2.0's u16),
//! `TPM_SUCCESS = 0`, `TPM_RETRY = 0x800`. All big-endian.
//!
//! The one substantive delta from the 2.0 driver (SPEC_TPM12_ENTROPY §4):
//! a conformant TPM 1.2 part may return FEWER bytes than requested — a
//! legitimate short return, not a protocol violation — so each 32-byte
//! block is an **accumulation loop** bounded by
//! `policy.tpm12.max_read_rounds`, where every round requests exactly the
//! remainder. A zero-byte round and round exhaustion are hard fails
//! (partial blocks scrubbed, never padded, never recorded). Health
//! checks, scrub discipline, and the manufacturer gate mirror the parent.

use seed_core::contracts::{SourceTag, MAX_TPM2_SOURCE_BYTES};
use seed_protocol::policy::Policy;

use super::health::{self, HealthError};
use super::record::SourceRecord;
use super::util::scrub;
use crate::time::Deadline;

/// The fixed ASCII `algo_id` every TPM 1.2 record carries
/// (SPEC_TPM12_ENTROPY.md §1) — never TPM-supplied text, and distinct
/// from the 2.0 family's so the transcript discloses which command set
/// produced the record.
pub const TPM12_ALGO_ID: &[u8] = b"TPM12/GetRandom";

/// `TPM_TAG_RQU_COMMAND` (TPM Main Part 2).
const TPM_TAG_RQU_COMMAND: u16 = 0x00C1;
/// `TPM_TAG_RSP_COMMAND` (TPM Main Part 2).
const TPM_TAG_RSP_COMMAND: u16 = 0x00C4;
/// `TPM_ORD_GetRandom` (TPM Main Part 3).
const TPM_ORD_GET_RANDOM: u32 = 0x0000_0046;
/// `TPM_ORD_GetCapability` (TPM Main Part 3).
const TPM_ORD_GET_CAPABILITY: u32 = 0x0000_0065;
/// `TPM_CAP_PROPERTY` (TPM Main Part 2).
const TPM_CAP_PROPERTY: u32 = 0x0000_0005;
/// `TPM_CAP_PROP_MANUFACTURER` (TPM Main Part 2).
const TPM_CAP_PROP_MANUFACTURER: u32 = 0x0000_0103;
/// `TPM_SUCCESS`.
const TPM_SUCCESS: u32 = 0;
/// `TPM_RETRY` = `TPM_BASE + 0x800` (TPM Main Part 2) — the one
/// retryable return code (SPEC_TPM12_ENTROPY §4).
const TPM_RETRY: u32 = 0x0000_0800;

/// `TPM_GetRandom` request: tag u16 + paramSize u32 + ordinal u32 +
/// bytesRequested u32.
pub const GET_RANDOM_COMMAND_LEN: usize = 14;
/// `TPM_GetRandom` response buffer: tag u16 + paramSize u32 +
/// returnCode u32 + randomBytesSize u32 + up to 32 bytes.
pub const GET_RANDOM_RESPONSE_LEN: usize = 14 + MAX_TPM2_SOURCE_BYTES;
/// `TPM_GetCapability(TPM_CAP_PROPERTY, TPM_CAP_PROP_MANUFACTURER)`
/// request: header (10) + capArea u32 + subCapSize u32 + subCap u32.
pub const GET_CAPABILITY_COMMAND_LEN: usize = 22;
/// Its response: header (10) + respSize u32 + 4 value bytes.
pub const GET_CAPABILITY_RESPONSE_LEN: usize = 10 + 4 + 4;

/// Transport-level failure: the TCG 1.2 protocol call itself did not
/// complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tpm12SubmitError;

/// One backend's TCG 1.2 command primitive. Exactly one real
/// implementation ([`uefi_backend::RealTpm12`]) plus the host-test
/// double (`tests::ScriptedTransport`).
pub trait Tpm12Transport {
    /// Whether a TPM 1.2 is present AND activated per the TCG 1.2
    /// `StatusCheck` capability flags (SPEC_TPM12_ENTROPY §3: a 1.2 part
    /// can be present but deactivated — refusing commands — which MUST
    /// report `false` here; the recap probe names that state
    /// separately). Fail closed on any status error.
    fn is_present_and_activated(&mut self) -> bool;

    /// Submits one raw command block and fills `response`; the
    /// response's own `paramSize` header field states how much is
    /// meaningful, validated by [`sample`]'s parsers.
    fn submit(&mut self, command: &[u8], response: &mut [u8]) -> Result<(), Tpm12SubmitError>;
}

/// Why a TPM 1.2 sample attempt was refused or failed. Carries no
/// secret values (the leakage suite enumerates this).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tpm12Error {
    /// `policy.tpm12.approved` is `false`.
    NotApproved,
    /// No present-and-activated TPM 1.2 (§3) — normal silent absence.
    NotPresent,
    /// The TCG 1.2 protocol call itself failed.
    Unavailable,
    /// Non-empty reviewed manufacturer list, reported id not on it.
    ManufacturerRefused,
    /// A response failed structural validation (§4): wrong tag,
    /// inconsistent sizes, or `randomBytesSize` exceeding the request.
    ResponseMalformed,
    /// The TPM returned a nonzero, non-`TPM_RETRY` return code.
    TpmErrorCode,
    /// `TPM_RETRY` persisted past `policy.tpm12.retry_limit`
    /// resubmissions within one round.
    RetriesExhausted,
    /// A round returned zero bytes (§4: a present, activated TPM that
    /// yields nothing is refusing or broken — never spun on).
    ZeroBytesReturned,
    /// `max_read_rounds` rounds accumulated fewer than 32 bytes (§4).
    RoundsExhausted,
    /// The shared machine-acquisition wall-clock budget expired.
    DeadlineExceeded,
    /// A sampled block failed a SPEC §16 catastrophic check.
    Health(HealthError),
}

fn be_u16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

fn be_u32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// Serializes `TPM_GetRandom(bytesRequested = remaining)`.
fn build_get_random(buf: &mut [u8; GET_RANDOM_COMMAND_LEN], remaining: u32) {
    buf[0..2].copy_from_slice(&TPM_TAG_RQU_COMMAND.to_be_bytes());
    buf[2..6].copy_from_slice(&(GET_RANDOM_COMMAND_LEN as u32).to_be_bytes());
    buf[6..10].copy_from_slice(&TPM_ORD_GET_RANDOM.to_be_bytes());
    buf[10..14].copy_from_slice(&remaining.to_be_bytes());
}

/// Serializes `TPM_GetCapability(TPM_CAP_PROPERTY,
/// TPM_CAP_PROP_MANUFACTURER)`: subCap is a 4-byte payload preceded by
/// its size.
fn build_get_capability_manufacturer(buf: &mut [u8; GET_CAPABILITY_COMMAND_LEN]) {
    buf[0..2].copy_from_slice(&TPM_TAG_RQU_COMMAND.to_be_bytes());
    buf[2..6].copy_from_slice(&(GET_CAPABILITY_COMMAND_LEN as u32).to_be_bytes());
    buf[6..10].copy_from_slice(&TPM_ORD_GET_CAPABILITY.to_be_bytes());
    buf[10..14].copy_from_slice(&TPM_CAP_PROPERTY.to_be_bytes());
    buf[14..18].copy_from_slice(&4u32.to_be_bytes());
    buf[18..22].copy_from_slice(&TPM_CAP_PROP_MANUFACTURER.to_be_bytes());
}

/// One structurally validated `TPM_GetRandom` response (§4).
enum RoundOutcome {
    /// `n` fresh bytes were appended to the block.
    Got(usize),
    /// `TPM_RETRY` — resubmit within the per-round budget.
    Retry,
}

/// Validates one raw response and appends its bytes to
/// `block[*filled..]`. `remaining` is what was requested this round.
fn parse_round(
    resp: &[u8; GET_RANDOM_RESPONSE_LEN],
    remaining: usize,
    block: &mut [u8; MAX_TPM2_SOURCE_BYTES],
    filled: usize,
) -> Result<RoundOutcome, Tpm12Error> {
    let rc = be_u32(resp, 6);
    if rc == TPM_RETRY {
        return Ok(RoundOutcome::Retry);
    }
    if rc != TPM_SUCCESS {
        return Err(Tpm12Error::TpmErrorCode);
    }
    if be_u16(resp, 0) != TPM_TAG_RSP_COMMAND {
        return Err(Tpm12Error::ResponseMalformed);
    }
    let param_size = be_u32(resp, 2) as usize;
    let n = be_u32(resp, 10) as usize;
    // §4: a short return is LEGAL (n < remaining accumulates); a long
    // one, or sizes that disagree, are malformed.
    if n > remaining || param_size != 14 + n || param_size > GET_RANDOM_RESPONSE_LEN {
        return Err(Tpm12Error::ResponseMalformed);
    }
    if n == 0 {
        return Err(Tpm12Error::ZeroBytesReturned);
    }
    block[filled..filled + n].copy_from_slice(&resp[14..14 + n]);
    Ok(RoundOutcome::Got(n))
}

/// Reads one 32-byte block via the §4 accumulation loop.
fn read_block(
    transport: &mut dyn Tpm12Transport,
    retry_limit: u8,
    max_read_rounds: u8,
    deadline: &mut Deadline<'_>,
) -> Result<[u8; MAX_TPM2_SOURCE_BYTES], Tpm12Error> {
    let mut block = [0u8; MAX_TPM2_SOURCE_BYTES];
    let mut filled = 0usize;
    let mut rounds: u16 = 0;
    while filled < MAX_TPM2_SOURCE_BYTES {
        if rounds as u32 >= max_read_rounds as u32 {
            scrub(&mut block);
            return Err(Tpm12Error::RoundsExhausted);
        }
        rounds += 1;
        let remaining = MAX_TPM2_SOURCE_BYTES - filled;
        let mut command = [0u8; GET_RANDOM_COMMAND_LEN];
        build_get_random(&mut command, remaining as u32);

        let mut retries: u16 = 0;
        loop {
            if deadline.expired() {
                scrub(&mut block);
                return Err(Tpm12Error::DeadlineExceeded);
            }
            let mut resp = [0u8; GET_RANDOM_RESPONSE_LEN];
            if transport.submit(&command, &mut resp).is_err() {
                scrub(&mut block);
                return Err(Tpm12Error::Unavailable);
            }
            match parse_round(&resp, remaining, &mut block, filled) {
                Ok(RoundOutcome::Got(n)) => {
                    filled += n;
                    break;
                }
                Ok(RoundOutcome::Retry) => {
                    retries += 1;
                    if retries as u32 > retry_limit as u32 {
                        scrub(&mut block);
                        return Err(Tpm12Error::RetriesExhausted);
                    }
                }
                Err(e) => {
                    scrub(&mut block);
                    return Err(e);
                }
            }
        }
    }
    Ok(block)
}

/// Runs the manufacturer gate (only called when the reviewed list is
/// non-empty). The reported string never leaves this function.
fn manufacturer_gate(transport: &mut dyn Tpm12Transport, policy: &Policy) -> Result<(), Tpm12Error> {
    let mut command = [0u8; GET_CAPABILITY_COMMAND_LEN];
    build_get_capability_manufacturer(&mut command);
    let mut resp = [0u8; GET_CAPABILITY_RESPONSE_LEN];
    transport.submit(&command, &mut resp).map_err(|_| Tpm12Error::Unavailable)?;

    if be_u32(&resp, 6) != TPM_SUCCESS {
        return Err(Tpm12Error::TpmErrorCode);
    }
    if be_u16(&resp, 0) != TPM_TAG_RSP_COMMAND
        || be_u32(&resp, 2) as usize != GET_CAPABILITY_RESPONSE_LEN
        || be_u32(&resp, 10) != 4
    {
        return Err(Tpm12Error::ResponseMalformed);
    }
    let raw = &resp[14..18];
    let trimmed_len = raw.iter().rposition(|&b| b != 0 && b != b' ').map_or(0, |i| i + 1);
    let trimmed = &raw[..trimmed_len];
    let id = core::str::from_utf8(trimmed).map_err(|_| Tpm12Error::ManufacturerRefused)?;
    if !id.is_empty()
        && id.bytes().all(|b| b.is_ascii_graphic())
        && policy.tpm12.is_manufacturer_allowed(id)
    {
        Ok(())
    } else {
        Err(Tpm12Error::ManufacturerRefused)
    }
}

/// Samples one TPM 1.2 [`SourceRecord`] (SPEC_TPM12_ENTROPY §4, §5; the
/// parent spec's §9 health shape).
pub fn sample(
    transport: &mut dyn Tpm12Transport,
    policy: &Policy,
    deadline: &mut Deadline<'_>,
) -> Result<SourceRecord, Tpm12Error> {
    let tpm_policy = &policy.tpm12;
    if !tpm_policy.approved {
        return Err(Tpm12Error::NotApproved);
    }
    if !transport.is_present_and_activated() {
        return Err(Tpm12Error::NotPresent);
    }
    if !tpm_policy.allowed_manufacturers().is_empty() {
        manufacturer_gate(transport, policy)?;
    }

    let mut block_a =
        read_block(transport, tpm_policy.retry_limit, tpm_policy.max_read_rounds, deadline)?;
    if let Err(e) = health::check_not_degenerate(&block_a) {
        scrub(&mut block_a);
        return Err(Tpm12Error::Health(e));
    }

    let mut block_b =
        match read_block(transport, tpm_policy.retry_limit, tpm_policy.max_read_rounds, deadline) {
            Ok(b) => b,
            Err(e) => {
                scrub(&mut block_a);
                return Err(e);
            }
        };
    let degenerate = health::check_not_degenerate(&block_b);
    let repeated = health::check_not_repeated(&block_a, &block_b);
    if let Err(e) = degenerate.and(repeated) {
        scrub(&mut block_a);
        scrub(&mut block_b);
        return Err(Tpm12Error::Health(e));
    }
    scrub(&mut block_b);

    let record = SourceRecord::new(SourceTag::Tpm12GetRandom, TPM12_ALGO_ID, &block_a).ok_or({
        // Unreachable (both lengths compile-time within bounds); kept
        // fail-closed rather than panicking (SPEC §27.3).
        Tpm12Error::ResponseMalformed
    });
    scrub(&mut block_a);
    record
}

/// Real TCG 1.2 protocol adapter. Only compiled for the `uefi` target.
#[cfg(target_os = "uefi")]
pub mod uefi_backend {
    use super::{Tpm12SubmitError, Tpm12Transport};
    use uefi::proto::tcg::v1::Tcg;

    /// Adapts `uefi::proto::tcg::v1::Tcg` to [`Tpm12Transport`].
    pub struct RealTpm12<'a> {
        tcg: &'a mut Tcg,
    }

    impl<'a> RealTpm12<'a> {
        /// Wraps an already-located TCG 1.2 protocol instance.
        pub fn new(tcg: &'a mut Tcg) -> Self {
            Self { tcg }
        }
    }

    impl Tpm12Transport for RealTpm12<'_> {
        fn is_present_and_activated(&mut self) -> bool {
            // Fail closed: a status error reports absent
            // (SPEC_TPM12_ENTROPY §3). `deactivated` is the 1.2-specific
            // present-but-refusing state.
            self.tcg
                .status_check()
                .map(|status| {
                    let flags = status.protocol_capability;
                    flags.tpm_present() && !flags.tpm_deactivated()
                })
                .unwrap_or(false)
        }

        fn submit(&mut self, command: &[u8], response: &mut [u8]) -> Result<(), Tpm12SubmitError> {
            self.tcg
                .pass_through_to_tpm(command, response)
                .map_err(|_| Tpm12SubmitError)
        }
    }

    /// Locates the TCG 1.2 protocol, opened **non-exclusively**
    /// (`GetProtocol`) — same SPEC §11.4 console-survival discipline as
    /// `tpm2::uefi_backend::locate` (see that function's doc comment).
    pub fn locate() -> Result<uefi::boot::ScopedProtocol<Tcg>, super::Tpm12Error> {
        let handle = uefi::boot::get_handle_for_protocol::<Tcg>()
            .map_err(|_| super::Tpm12Error::NotPresent)?;
        let params = uefi::boot::OpenProtocolParams {
            handle,
            agent: uefi::boot::image_handle(),
            controller: None,
        };
        // SAFETY: single-threaded UEFI application at TPL_APPLICATION;
        // used synchronously and dropped within the sampling call stack
        // (the `gop/backend.rs` GetProtocol justification).
        unsafe {
            uefi::boot::open_protocol::<Tcg>(params, uefi::boot::OpenProtocolAttributes::GetProtocol)
        }
        .map_err(|_| super::Tpm12Error::NotPresent)
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::test_support::FakeClock;
    use std::vec::Vec;

    fn policy(tpm12_block: &str) -> Policy {
        let toml = std::format!(
            r#"
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
retry_limit = 75
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
max_read_retries = 3

[tpm2]
approved = false
sole_source_allowed = false
max_bytes_per_call = 32
retry_limit = 3
max_manufacturers = 8
allowed_manufacturers = []

{tpm12_block}
"#
        );
        seed_protocol::policy::parse(&toml).expect("well-formed test policy")
    }

    fn approved_policy() -> Policy {
        policy(
            "[tpm12]\napproved = true\nsole_source_allowed = false\nmax_bytes_per_call = 32\nretry_limit = 3\nmax_read_rounds = 8\nmax_manufacturers = 8\nallowed_manufacturers = []",
        )
    }

    fn approved_policy_with_manufacturers() -> Policy {
        policy(
            "[tpm12]\napproved = true\nsole_source_allowed = false\nmax_bytes_per_call = 32\nretry_limit = 3\nmax_read_rounds = 8\nmax_manufacturers = 8\nallowed_manufacturers = [\"ATML\"]",
        )
    }

    fn unapproved_policy() -> Policy {
        policy(
            "[tpm12]\napproved = false\nsole_source_allowed = false\nmax_bytes_per_call = 32\nretry_limit = 3\nmax_read_rounds = 8\nmax_manufacturers = 8\nallowed_manufacturers = []",
        )
    }

    /// A well-formed `TPM_GetRandom` response carrying `data`.
    fn get_random_response(rc: u32, data: &[u8]) -> Vec<u8> {
        let mut r = std::vec![0u8; 14 + data.len()];
        r[0..2].copy_from_slice(&TPM_TAG_RSP_COMMAND.to_be_bytes());
        r[2..6].copy_from_slice(&((14 + data.len()) as u32).to_be_bytes());
        r[6..10].copy_from_slice(&rc.to_be_bytes());
        r[10..14].copy_from_slice(&(data.len() as u32).to_be_bytes());
        r[14..].copy_from_slice(data);
        r
    }

    fn counter_bytes(base: u8, n: usize) -> Vec<u8> {
        (0..n).map(|i| base.wrapping_add(i as u8)).collect()
    }

    fn manufacturer_response(id: &[u8]) -> Vec<u8> {
        let mut r = std::vec![0u8; GET_CAPABILITY_RESPONSE_LEN];
        r[0..2].copy_from_slice(&TPM_TAG_RSP_COMMAND.to_be_bytes());
        r[2..6].copy_from_slice(&(GET_CAPABILITY_RESPONSE_LEN as u32).to_be_bytes());
        r[6..10].copy_from_slice(&TPM_SUCCESS.to_be_bytes());
        r[10..14].copy_from_slice(&4u32.to_be_bytes());
        r[14..14 + id.len()].copy_from_slice(id);
        r
    }

    struct ScriptedTransport {
        present: bool,
        responses: Vec<Vec<u8>>,
        commands: Vec<Vec<u8>>,
    }

    impl ScriptedTransport {
        fn new(present: bool, responses: Vec<Vec<u8>>) -> Self {
            Self { present, responses, commands: Vec::new() }
        }
    }

    impl Tpm12Transport for ScriptedTransport {
        fn is_present_and_activated(&mut self) -> bool {
            self.present
        }
        fn submit(&mut self, command: &[u8], response: &mut [u8]) -> Result<(), Tpm12SubmitError> {
            self.commands.push(command.to_vec());
            if self.responses.is_empty() {
                return Err(Tpm12SubmitError);
            }
            let canned = self.responses.remove(0);
            response[..canned.len()].copy_from_slice(&canned);
            Ok(())
        }
    }

    fn deadline(clock: &mut FakeClock) -> Deadline<'_> {
        Deadline::start(clock, 5_000)
    }

    #[test]
    fn happy_path_single_round_blocks_produce_valid_record() {
        let mut t = ScriptedTransport::new(
            true,
            std::vec![
                get_random_response(TPM_SUCCESS, &counter_bytes(1, 32)),
                get_random_response(TPM_SUCCESS, &counter_bytes(101, 32)),
            ],
        );
        let mut clock = FakeClock::new(1);
        let mut d = deadline(&mut clock);
        let record = sample(&mut t, &approved_policy(), &mut d).expect("happy path");
        assert_eq!(record.tag(), SourceTag::Tpm12GetRandom);
        assert_eq!(record.algo_id(), TPM12_ALGO_ID);
        assert_eq!(record.bytes(), &counter_bytes(1, 32)[..]);
        assert_eq!(t.commands.len(), 2);
    }

    /// SPEC_TPM12_ENTROPY §4 byte-exact marshalling:
    /// `00C1 | 0000000E | 00000046 | 00000020` for a fresh 32-byte round.
    #[test]
    fn get_random_command_marshals_byte_exact() {
        let mut t = ScriptedTransport::new(
            true,
            std::vec![
                get_random_response(TPM_SUCCESS, &counter_bytes(1, 32)),
                get_random_response(TPM_SUCCESS, &counter_bytes(101, 32)),
            ],
        );
        let mut clock = FakeClock::new(1);
        let mut d = deadline(&mut clock);
        sample(&mut t, &approved_policy(), &mut d).unwrap();
        assert_eq!(
            t.commands[0],
            std::vec![
                0x00, 0xC1, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x00, 0x00, 0x46, 0x00, 0x00, 0x00,
                0x20
            ]
        );
    }

    /// §4: the accumulation loop — a part that trickles 8 bytes per
    /// round still assembles a full 32-byte block, and each round
    /// requests exactly the remainder.
    #[test]
    fn short_returns_accumulate_across_rounds() {
        let mut responses = Vec::new();
        for base in [0u8, 8, 16, 24] {
            responses.push(get_random_response(TPM_SUCCESS, &counter_bytes(base, 8)));
        }
        responses.push(get_random_response(TPM_SUCCESS, &counter_bytes(200, 32)));
        let mut t = ScriptedTransport::new(true, responses);
        let mut clock = FakeClock::new(1);
        let mut d = deadline(&mut clock);
        let record = sample(&mut t, &approved_policy(), &mut d).expect("accumulated");
        let expected: Vec<u8> = (0..32u8).collect();
        assert_eq!(record.bytes(), &expected[..]);
        // Rounds 2..4 of block A requested the shrinking remainder.
        assert_eq!(&t.commands[1][10..14], &24u32.to_be_bytes());
        assert_eq!(&t.commands[2][10..14], &16u32.to_be_bytes());
        assert_eq!(&t.commands[3][10..14], &8u32.to_be_bytes());
    }

    /// §4: a zero-byte round is a hard fail, never a spin.
    #[test]
    fn zero_byte_round_fails_hard() {
        let mut t = ScriptedTransport::new(
            true,
            std::vec![get_random_response(TPM_SUCCESS, &[])],
        );
        let mut clock = FakeClock::new(1);
        let mut d = deadline(&mut clock);
        assert_eq!(
            sample(&mut t, &approved_policy(), &mut d).map(|_| ()).unwrap_err(),
            Tpm12Error::ZeroBytesReturned
        );
    }

    /// §4: `max_read_rounds` bounds a trickling part — 8 rounds of 1
    /// byte cannot fill 32, so the block fails with `RoundsExhausted`.
    #[test]
    fn round_exhaustion_fails_hard() {
        let responses = (0..8)
            .map(|i| get_random_response(TPM_SUCCESS, &[i as u8]))
            .collect();
        let mut t = ScriptedTransport::new(true, responses);
        let mut clock = FakeClock::new(1);
        let mut d = deadline(&mut clock);
        assert_eq!(
            sample(&mut t, &approved_policy(), &mut d).map(|_| ()).unwrap_err(),
            Tpm12Error::RoundsExhausted
        );
        assert_eq!(t.commands.len(), 8);
    }

    /// A response claiming MORE bytes than requested is malformed.
    #[test]
    fn overlong_return_is_rejected() {
        // First round returns 31 bytes (fine), second claims 32 when
        // only 1 remains.
        let mut t = ScriptedTransport::new(
            true,
            std::vec![
                get_random_response(TPM_SUCCESS, &counter_bytes(0, 31)),
                get_random_response(TPM_SUCCESS, &counter_bytes(0, 32)),
            ],
        );
        let mut clock = FakeClock::new(1);
        let mut d = deadline(&mut clock);
        assert_eq!(
            sample(&mut t, &approved_policy(), &mut d).map(|_| ()).unwrap_err(),
            Tpm12Error::ResponseMalformed
        );
    }

    #[test]
    fn tpm_retry_within_budget_succeeds_and_exhaustion_fails() {
        let mut t = ScriptedTransport::new(
            true,
            std::vec![
                get_random_response(TPM_RETRY, &[]),
                get_random_response(TPM_SUCCESS, &counter_bytes(1, 32)),
                get_random_response(TPM_SUCCESS, &counter_bytes(101, 32)),
            ],
        );
        let mut clock = FakeClock::new(1);
        let mut d = deadline(&mut clock);
        assert!(sample(&mut t, &approved_policy(), &mut d).is_ok());

        let mut t = ScriptedTransport::new(
            true,
            std::vec![get_random_response(TPM_RETRY, &[]); 5],
        );
        let mut clock = FakeClock::new(1);
        let mut d = deadline(&mut clock);
        assert_eq!(
            sample(&mut t, &approved_policy(), &mut d).map(|_| ()).unwrap_err(),
            Tpm12Error::RetriesExhausted
        );
        assert_eq!(t.commands.len(), 4, "retry_limit = 3 allows 4 submissions");
    }

    #[test]
    fn unapproved_policy_never_touches_the_transport() {
        let mut t = ScriptedTransport::new(true, std::vec![]);
        let mut clock = FakeClock::new(1);
        let mut d = deadline(&mut clock);
        assert_eq!(
            sample(&mut t, &unapproved_policy(), &mut d).map(|_| ()).unwrap_err(),
            Tpm12Error::NotApproved
        );
        assert!(t.commands.is_empty());
    }

    #[test]
    fn absent_or_deactivated_reports_not_present() {
        let mut t = ScriptedTransport::new(false, std::vec![]);
        let mut clock = FakeClock::new(1);
        let mut d = deadline(&mut clock);
        assert_eq!(
            sample(&mut t, &approved_policy(), &mut d).map(|_| ()).unwrap_err(),
            Tpm12Error::NotPresent
        );
        assert!(t.commands.is_empty());
    }

    #[test]
    fn all_zero_block_and_identical_blocks_are_rejected() {
        let mut t = ScriptedTransport::new(
            true,
            std::vec![get_random_response(TPM_SUCCESS, &[0u8; 32])],
        );
        let mut clock = FakeClock::new(1);
        let mut d = deadline(&mut clock);
        assert_eq!(
            sample(&mut t, &approved_policy(), &mut d).map(|_| ()).unwrap_err(),
            Tpm12Error::Health(HealthError::AllZero)
        );

        let mut t = ScriptedTransport::new(
            true,
            std::vec![
                get_random_response(TPM_SUCCESS, &counter_bytes(7, 32)),
                get_random_response(TPM_SUCCESS, &counter_bytes(7, 32)),
            ],
        );
        let mut clock = FakeClock::new(1);
        let mut d = deadline(&mut clock);
        assert_eq!(
            sample(&mut t, &approved_policy(), &mut d).map(|_| ()).unwrap_err(),
            Tpm12Error::Health(HealthError::IdenticalConsecutiveBlocks)
        );
    }

    #[test]
    fn expired_deadline_fails_before_any_submit() {
        let mut t = ScriptedTransport::new(true, std::vec![]);
        let mut clock = FakeClock::new(1);
        clock.advance_per_call = 10_000;
        let mut d = Deadline::start(&mut clock, 1);
        assert_eq!(
            sample(&mut t, &approved_policy(), &mut d).map(|_| ()).unwrap_err(),
            Tpm12Error::DeadlineExceeded
        );
        assert!(t.commands.is_empty());
    }

    // ---- manufacturer gate ----

    #[test]
    fn empty_manufacturer_list_skips_the_capability_round_trip() {
        let mut t = ScriptedTransport::new(
            true,
            std::vec![
                get_random_response(TPM_SUCCESS, &counter_bytes(1, 32)),
                get_random_response(TPM_SUCCESS, &counter_bytes(101, 32)),
            ],
        );
        let mut clock = FakeClock::new(1);
        let mut d = deadline(&mut clock);
        sample(&mut t, &approved_policy(), &mut d).unwrap();
        for cmd in &t.commands {
            assert_eq!(&cmd[6..10], &[0x00, 0x00, 0x00, 0x46]);
        }
    }

    #[test]
    fn listed_manufacturer_passes_unlisted_is_refused() {
        let mut t = ScriptedTransport::new(
            true,
            std::vec![
                manufacturer_response(b"ATML"),
                get_random_response(TPM_SUCCESS, &counter_bytes(1, 32)),
                get_random_response(TPM_SUCCESS, &counter_bytes(101, 32)),
            ],
        );
        let mut clock = FakeClock::new(1);
        let mut d = deadline(&mut clock);
        assert!(sample(&mut t, &approved_policy_with_manufacturers(), &mut d).is_ok());
        // Capability command byte-exact: header + capArea 5 + subCapSize 4
        // + subCap 0x103.
        assert_eq!(
            t.commands[0],
            std::vec![
                0x00, 0xC1, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x65, 0x00, 0x00, 0x00,
                0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x01, 0x03
            ]
        );

        let mut t = ScriptedTransport::new(true, std::vec![manufacturer_response(b"IFX\0")]);
        let mut clock = FakeClock::new(1);
        let mut d = deadline(&mut clock);
        assert_eq!(
            sample(&mut t, &approved_policy_with_manufacturers(), &mut d).map(|_| ()).unwrap_err(),
            Tpm12Error::ManufacturerRefused
        );
        assert_eq!(t.commands.len(), 1);
    }
}
