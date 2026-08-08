//! TPM 2.0 `GetRandom` driver (SPEC_TPM_ENTROPY.md §5, §7, §9).
//!
//! This module produces a tagged (`SourceTag::Tpm2GetRandom` = `0x13`)
//! [`super::record::SourceRecord`] from the platform TPM 2.0's
//! `TPM2_GetRandom` DRBG, read over `EFI_TCG2_PROTOCOL.SubmitCommand`,
//! reusing this crate's existing [`super::health`] catastrophic checks
//! (`check_not_degenerate`, `check_not_repeated`) the same way
//! [`super::usb_trng`] does.
//!
//! Like `usb_trng`, everything testable lives behind a small transport
//! trait: [`Tpm2Transport`] carries raw command/response byte blocks, so
//! the **wire marshalling and response validation in this module are
//! host-tested byte-for-byte** (`tests::ScriptedTransport`) and the real
//! backend ([`uefi_backend`]) is nothing but a thin adapter over
//! `uefi::proto::tcg::v2::Tcg::submit_command` — unlike WP-U4's blocked
//! USB primitive, that adapter is real and shippable today.
//!
//! Wire constants (SPEC_TPM_ENTROPY.md §5, re-verified against edk2
//! `MdePkg/Include/IndustryStandard/Tpm20.h` and the TCG EFI Protocol
//! Specification Family 2.0 at implementation time, per the spec's
//! revision-log requirement): `TPM_ST_NO_SESSIONS = 0x8001`,
//! `TPM_CC_GetRandom = 0x0000_017B`, `TPM_CC_GetCapability =
//! 0x0000_017A`, `TPM_CAP_TPM_PROPERTIES = 6`, `TPM_PT_MANUFACTURER =
//! 0x105`, `TPM_RC_RETRY = 0x922`. All wire integers are big-endian.
//!
//! Order of operations, mirroring [`super::usb_trng::sample`]:
//! 1. `policy.tpm2.approved` gates everything (SPEC_TPM_ENTROPY §8.1) —
//!    an unapproved policy issues **zero** TPM commands.
//! 2. [`Tpm2Transport::is_present`] (TCG2 capability `TPMPresentFlag`,
//!    §7.1) — absent is a normal, silent condition for the caller.
//! 3. If the reviewed manufacturer list is non-empty (§7.1 point 4), one
//!    `TPM2_GetCapability(TPM_PT_MANUFACTURER)` round-trip gates on
//!    [`Tpm2Policy::is_manufacturer_allowed`]. The manufacturer string
//!    never enters the record (§4.2/§6.1: no TPM-supplied text in the
//!    transcript). Spoofability caveat: SPEC_TPM_ENTROPY §4.2.
//! 4. Two 32-byte `TPM2_GetRandom` blocks (§7.2), each retried only on
//!    `TPM_RC_RETRY` up to `policy.tpm2.retry_limit` times (§7.3); the
//!    `TPM2B_DIGEST` size MUST be exactly 32 — a short return is a hard
//!    fail, never zero-padded, never accepted partially (§7.2).
//! 5. Block A must not be degenerate; block B must not be degenerate and
//!    must differ from block A (SPEC §16 via [`super::health`]); block B
//!    is scrubbed; block A becomes the record with fixed `algo_id`
//!    `"TPM2/GetRandom"` (§6.1).

use seed_core::contracts::{SourceTag, MAX_TPM2_SOURCE_BYTES};
use seed_protocol::policy::Policy;

use super::health::{self, HealthError};
use super::record::SourceRecord;
use super::util::scrub;
use crate::time::Deadline;

/// The fixed ASCII `algo_id` every TPM record carries
/// (SPEC_TPM_ENTROPY.md §6.1) — never TPM-supplied text.
pub const TPM2_ALGO_ID: &[u8] = b"TPM2/GetRandom";

/// `TPM_ST_NO_SESSIONS` (TPM 2.0 Library Part 2; edk2 Tpm20.h).
const TPM_ST_NO_SESSIONS: u16 = 0x8001;
/// `TPM_CC_GetRandom` (edk2 Tpm20.h: `0x0000017B`).
const TPM_CC_GET_RANDOM: u32 = 0x0000_017B;
/// `TPM_CC_GetCapability` (edk2 Tpm20.h: `0x0000017A`).
const TPM_CC_GET_CAPABILITY: u32 = 0x0000_017A;
/// `TPM_CAP_TPM_PROPERTIES` (TPM 2.0 Library Part 2).
const TPM_CAP_TPM_PROPERTIES: u32 = 0x0000_0006;
/// `TPM_PT_MANUFACTURER` = `PT_FIXED + 5` (TPM 2.0 Library Part 2).
const TPM_PT_MANUFACTURER: u32 = 0x0000_0105;
/// `TPM_RC_SUCCESS`.
const TPM_RC_SUCCESS: u32 = 0;
/// `TPM_RC_RETRY` = `RC_WARN + 0x022` (TPM 2.0 Library Part 2) — the one
/// response code SPEC_TPM_ENTROPY §7.3 permits resubmission on.
const TPM_RC_RETRY: u32 = 0x0000_0922;

/// `TPM2_GetRandom` request: header (10) + `bytesRequested` u16 (2).
pub const GET_RANDOM_COMMAND_LEN: usize = 12;
/// `TPM2_GetRandom` response at exactly one 32-byte block: header (10) +
/// `TPM2B_DIGEST` size u16 (2) + 32 bytes.
pub const GET_RANDOM_RESPONSE_LEN: usize = 10 + 2 + MAX_TPM2_SOURCE_BYTES;
/// `TPM2_GetCapability(TPM_PT_MANUFACTURER)` request: header (10) +
/// capability u32 + property u32 + propertyCount u32.
pub const GET_CAPABILITY_COMMAND_LEN: usize = 22;
/// Its response: header (10) + moreData u8 + capability u32 +
/// propertyCount u32 + one `TPMS_TAGGED_PROPERTY` (property u32 +
/// value u32).
pub const GET_CAPABILITY_RESPONSE_LEN: usize = 10 + 1 + 4 + 4 + 4 + 4;

/// Transport-level failure: the TCG2 protocol call itself did not
/// complete (protocol vanished, firmware error status). Response-content
/// problems are NOT transport errors — they are parsed and classified
/// here in [`sample`]'s helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tpm2SubmitError;

/// One backend's TCG2 command primitive. Exactly one real implementation
/// ([`uefi_backend::RealTpm2`]) plus the host-test double
/// (`tests::ScriptedTransport`).
pub trait Tpm2Transport {
    /// Whether a TPM 2.0 is present per the TCG2 boot-service capability
    /// (`TPMPresentFlag`, SPEC_TPM_ENTROPY §7.1). A protocol that cannot
    /// be located or a capability call that fails MUST report `false`
    /// (fail closed), never guess `true`.
    fn is_present(&mut self) -> bool;

    /// Submits one raw command block and fills `response` with the raw
    /// response block. The response's own `responseSize` header field —
    /// not a transport return value — states how much of `response` is
    /// meaningful; [`sample`]'s parsers validate it. MUST NOT modify
    /// `response` bytes beyond what the firmware wrote.
    fn submit(&mut self, command: &[u8], response: &mut [u8]) -> Result<(), Tpm2SubmitError>;
}

/// Why a TPM sample attempt was refused or failed (SPEC_TPM_ENTROPY §7,
/// §9). Carries no secret values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tpm2Error {
    /// `policy.tpm2.approved` is `false` (SPEC_TPM_ENTROPY §8.1: ships
    /// unapproved; availability is never approval).
    NotApproved,
    /// No TPM 2.0 present per the TCG2 capability (§7.1) — the normal
    /// silent-absence case.
    NotPresent,
    /// The TCG2 protocol call itself failed (§7.3: hard fail of the TPM
    /// source for this ceremony, never a silent substitution).
    Unavailable,
    /// The reviewed manufacturer list is non-empty and the TPM's reported
    /// `TPM_PT_MANUFACTURER` is not on it (§7.1 point 4). Review
    /// scaffolding, not a security boundary (§4.2).
    ManufacturerRefused,
    /// A response failed structural validation (§7.2): wrong tag,
    /// inconsistent sizes, or a `TPM2B_DIGEST` shorter than the 32 bytes
    /// requested — a short return is a hard failure, never zero-padded.
    ResponseMalformed,
    /// The TPM returned a nonzero, non-`TPM_RC_RETRY` response code.
    TpmErrorCode,
    /// `TPM_RC_RETRY` persisted past `policy.tpm2.retry_limit`
    /// resubmissions (§7.3).
    RetriesExhausted,
    /// The shared machine-acquisition wall-clock budget expired (§7.3;
    /// same fail-closed deadline the other machine sources share).
    DeadlineExceeded,
    /// A sampled block failed a SPEC §16 catastrophic check.
    Health(HealthError),
}

/// Serializes the `TPM2_GetRandom(bytesRequested = 32)` command
/// (SPEC_TPM_ENTROPY §5: big-endian throughout).
fn build_get_random(buf: &mut [u8; GET_RANDOM_COMMAND_LEN]) {
    buf[0..2].copy_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
    buf[2..6].copy_from_slice(&(GET_RANDOM_COMMAND_LEN as u32).to_be_bytes());
    buf[6..10].copy_from_slice(&TPM_CC_GET_RANDOM.to_be_bytes());
    buf[10..12].copy_from_slice(&(MAX_TPM2_SOURCE_BYTES as u16).to_be_bytes());
}

/// Serializes `TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES,
/// TPM_PT_MANUFACTURER, 1)`.
fn build_get_capability_manufacturer(buf: &mut [u8; GET_CAPABILITY_COMMAND_LEN]) {
    buf[0..2].copy_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
    buf[2..6].copy_from_slice(&(GET_CAPABILITY_COMMAND_LEN as u32).to_be_bytes());
    buf[6..10].copy_from_slice(&TPM_CC_GET_CAPABILITY.to_be_bytes());
    buf[10..14].copy_from_slice(&TPM_CAP_TPM_PROPERTIES.to_be_bytes());
    buf[14..18].copy_from_slice(&TPM_PT_MANUFACTURER.to_be_bytes());
    buf[18..22].copy_from_slice(&1u32.to_be_bytes());
}

fn be_u16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

fn be_u32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// One `TPM2_GetRandom` response, structurally validated (§7.2).
enum GetRandomOutcome {
    /// A full 32-byte block.
    Block([u8; MAX_TPM2_SOURCE_BYTES]),
    /// `TPM_RC_RETRY` — the caller may resubmit within its budget.
    Retry,
}

/// Validates one raw `TPM2_GetRandom` response block (§7.2): response tag
/// `TPM_ST_NO_SESSIONS`, `responseSize` exactly [`GET_RANDOM_RESPONSE_LEN`],
/// `responseCode` success (or retry), and `TPM2B_DIGEST.size` exactly 32.
/// Anything else — including a *shorter-than-requested* digest, which a
/// conformant TPM is allowed to send but this driver's 32-byte request is
/// specifically sized to never need — is [`Tpm2Error::ResponseMalformed`].
fn parse_get_random_response(resp: &[u8; GET_RANDOM_RESPONSE_LEN]) -> Result<GetRandomOutcome, Tpm2Error> {
    let rc = be_u32(resp, 6);
    if rc == TPM_RC_RETRY {
        return Ok(GetRandomOutcome::Retry);
    }
    if rc != TPM_RC_SUCCESS {
        return Err(Tpm2Error::TpmErrorCode);
    }
    if be_u16(resp, 0) != TPM_ST_NO_SESSIONS {
        return Err(Tpm2Error::ResponseMalformed);
    }
    if be_u32(resp, 2) as usize != GET_RANDOM_RESPONSE_LEN {
        return Err(Tpm2Error::ResponseMalformed);
    }
    if be_u16(resp, 10) as usize != MAX_TPM2_SOURCE_BYTES {
        return Err(Tpm2Error::ResponseMalformed);
    }
    let mut block = [0u8; MAX_TPM2_SOURCE_BYTES];
    block.copy_from_slice(&resp[12..12 + MAX_TPM2_SOURCE_BYTES]);
    Ok(GetRandomOutcome::Block(block))
}

/// Reads one 32-byte block, resubmitting only on `TPM_RC_RETRY`, at most
/// `retry_limit` resubmissions (§7.3). The deadline is checked before
/// every submit — `SubmitCommand` itself is synchronous and
/// firmware-bounded, so the check brackets calls rather than preempting
/// one (§7.3: the retry limit bounds Alea's part).
fn read_block(
    transport: &mut dyn Tpm2Transport,
    retry_limit: u8,
    deadline: &mut Deadline<'_>,
) -> Result<[u8; MAX_TPM2_SOURCE_BYTES], Tpm2Error> {
    let mut command = [0u8; GET_RANDOM_COMMAND_LEN];
    build_get_random(&mut command);
    let mut submissions: u16 = 0;
    loop {
        if deadline.expired() {
            return Err(Tpm2Error::DeadlineExceeded);
        }
        let mut resp = [0u8; GET_RANDOM_RESPONSE_LEN];
        transport.submit(&command, &mut resp).map_err(|_| Tpm2Error::Unavailable)?;
        match parse_get_random_response(&resp)? {
            GetRandomOutcome::Block(b) => return Ok(b),
            GetRandomOutcome::Retry => {
                submissions += 1;
                if submissions as u32 > retry_limit as u32 {
                    return Err(Tpm2Error::RetriesExhausted);
                }
            }
        }
    }
}

/// Runs the §7.1 point 4 manufacturer gate: one
/// `TPM2_GetCapability(TPM_PT_MANUFACTURER)` round-trip, matched against
/// the reviewed list. Only called when that list is non-empty. The
/// reported string never leaves this function (§4.2/§6.1).
fn manufacturer_gate(
    transport: &mut dyn Tpm2Transport,
    policy: &Policy,
) -> Result<(), Tpm2Error> {
    let mut command = [0u8; GET_CAPABILITY_COMMAND_LEN];
    build_get_capability_manufacturer(&mut command);
    let mut resp = [0u8; GET_CAPABILITY_RESPONSE_LEN];
    transport.submit(&command, &mut resp).map_err(|_| Tpm2Error::Unavailable)?;

    if be_u32(&resp, 6) != TPM_RC_SUCCESS {
        return Err(Tpm2Error::TpmErrorCode);
    }
    if be_u16(&resp, 0) != TPM_ST_NO_SESSIONS
        || be_u32(&resp, 2) as usize != GET_CAPABILITY_RESPONSE_LEN
        || be_u32(&resp, 11) != TPM_CAP_TPM_PROPERTIES
        || be_u32(&resp, 15) != 1
        || be_u32(&resp, 19) != TPM_PT_MANUFACTURER
    {
        return Err(Tpm2Error::ResponseMalformed);
    }
    // The value is a u32 whose big-endian bytes are the vendor's ASCII id
    // (e.g. "IFX\0"); trailing NULs/spaces pad short ids.
    let raw = &resp[23..27];
    let trimmed_len = raw.iter().rposition(|&b| b != 0 && b != b' ').map_or(0, |i| i + 1);
    let trimmed = &raw[..trimmed_len];
    let id = core::str::from_utf8(trimmed).map_err(|_| Tpm2Error::ManufacturerRefused)?;
    if !id.is_empty() && id.bytes().all(|b| b.is_ascii_graphic()) && policy.tpm2.is_manufacturer_allowed(id)
    {
        Ok(())
    } else {
        Err(Tpm2Error::ManufacturerRefused)
    }
}

/// Samples one TPM [`SourceRecord`] (SPEC_TPM_ENTROPY §7, §9). See the
/// module doc for the exact sequence.
pub fn sample(
    transport: &mut dyn Tpm2Transport,
    policy: &Policy,
    deadline: &mut Deadline<'_>,
) -> Result<SourceRecord, Tpm2Error> {
    let tpm_policy = &policy.tpm2;
    if !tpm_policy.approved {
        return Err(Tpm2Error::NotApproved);
    }
    if !transport.is_present() {
        return Err(Tpm2Error::NotPresent);
    }
    if !tpm_policy.allowed_manufacturers().is_empty() {
        manufacturer_gate(transport, policy)?;
    }

    let mut block_a = read_block(transport, tpm_policy.retry_limit, deadline)?;
    if let Err(e) = health::check_not_degenerate(&block_a) {
        scrub(&mut block_a);
        return Err(Tpm2Error::Health(e));
    }

    let mut block_b = match read_block(transport, tpm_policy.retry_limit, deadline) {
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
        return Err(Tpm2Error::Health(e));
    }
    scrub(&mut block_b);

    let record = SourceRecord::new(SourceTag::Tpm2GetRandom, TPM2_ALGO_ID, &block_a).ok_or({
        // Unreachable: both lengths are compile-time within bounds; kept
        // as a fail-closed path rather than a panic (SPEC §27.3).
        Tpm2Error::ResponseMalformed
    });
    scrub(&mut block_a);
    record
}

/// Real `EFI_TCG2_PROTOCOL` adapter. Only compiled for the `uefi` target
/// family, never pulled into host `cargo test` runs.
#[cfg(target_os = "uefi")]
pub mod uefi_backend {
    use super::{Tpm2SubmitError, Tpm2Transport};
    use uefi::proto::tcg::v2::Tcg;

    /// Adapts `uefi::proto::tcg::v2::Tcg` to [`Tpm2Transport`]. The
    /// protocol GUID lives in the `uefi` crate's binding and matches the
    /// TCG EFI Protocol Specification value
    /// `607f766c-7455-42be-930b-e4d76db2720f` (SPEC_TPM_ENTROPY §5).
    pub struct RealTpm2<'a> {
        tcg: &'a mut Tcg,
    }

    impl<'a> RealTpm2<'a> {
        /// Wraps an already-located TCG2 protocol instance.
        pub fn new(tcg: &'a mut Tcg) -> Self {
            Self { tcg }
        }
    }

    impl Tpm2Transport for RealTpm2<'_> {
        fn is_present(&mut self) -> bool {
            // Fail closed: a capability call that errors reports absent
            // (SPEC_TPM_ENTROPY §7.1).
            self.tcg
                .get_capability()
                .map(|cap| cap.tpm_present())
                .unwrap_or(false)
        }

        fn submit(&mut self, command: &[u8], response: &mut [u8]) -> Result<(), Tpm2SubmitError> {
            self.tcg
                .submit_command(command, response)
                .map_err(|_| Tpm2SubmitError)
        }
    }

    /// Locates `EFI_TCG2_PROTOCOL`, opened **non-exclusively**
    /// (`GetProtocol`) — deliberately NOT `open_protocol_exclusive`, per
    /// the SPEC §11.4 firmware-console-survival lesson the ci.sh
    /// exclusive-open gate enforces: an exclusive open fires
    /// `DisconnectController` at the handle's `ByDriver` openers, and the
    /// TCG2 handle belongs to platform firmware whose own components
    /// (measured-boot infrastructure) may be bound to it. Exclusivity
    /// also buys nothing here, unlike `efi_rng::locate`'s reviewed case:
    /// the TCG2 driver serializes TPM command submission itself, and an
    /// interleaved command from another agent between this driver's two
    /// `GetRandom` calls cannot alter the freshness of either DRBG
    /// response (SPEC_TPM_ENTROPY.md §7.2's response validation is
    /// per-command, not session-stateful).
    pub fn locate() -> Result<uefi::boot::ScopedProtocol<Tcg>, super::Tpm2Error> {
        let handle = uefi::boot::get_handle_for_protocol::<Tcg>()
            .map_err(|_| super::Tpm2Error::NotPresent)?;
        let params = uefi::boot::OpenProtocolParams {
            handle,
            agent: uefi::boot::image_handle(),
            controller: None,
        };
        // SAFETY: single-threaded UEFI application at TPL_APPLICATION;
        // the returned `ScopedProtocol` is used synchronously within the
        // sampling call stack and dropped before any other TCG2 use by
        // this agent — the same justification as `seed-gop-ui`'s
        // reviewed `GetProtocol` opens (`gop/backend.rs` module doc).
        unsafe {
            uefi::boot::open_protocol::<Tcg>(params, uefi::boot::OpenProtocolAttributes::GetProtocol)
        }
        .map_err(|_| super::Tpm2Error::NotPresent)
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::test_support::FakeClock;
    use std::vec::Vec;

    /// The full shipped-shape policy, with `[tpm2]` overridable per test.
    fn policy(tpm2_block: &str) -> Policy {
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

[tpm12]
approved = false
sole_source_allowed = false
max_bytes_per_call = 32
retry_limit = 3
max_read_rounds = 8
max_manufacturers = 8
allowed_manufacturers = []

{tpm2_block}
"#
        );
        seed_protocol::policy::parse(&toml).expect("well-formed test policy")
    }

    fn approved_policy() -> Policy {
        policy(
            "[tpm2]\napproved = true\nsole_source_allowed = false\nmax_bytes_per_call = 32\nretry_limit = 3\nmax_manufacturers = 8\nallowed_manufacturers = []",
        )
    }

    fn approved_policy_with_manufacturers() -> Policy {
        policy(
            "[tpm2]\napproved = true\nsole_source_allowed = false\nmax_bytes_per_call = 32\nretry_limit = 3\nmax_manufacturers = 8\nallowed_manufacturers = [\"IFX\"]",
        )
    }

    fn unapproved_policy() -> Policy {
        policy(
            "[tpm2]\napproved = false\nsole_source_allowed = false\nmax_bytes_per_call = 32\nretry_limit = 3\nmax_manufacturers = 8\nallowed_manufacturers = []",
        )
    }

    /// Builds a well-formed `TPM2_GetRandom` response carrying `fill` as
    /// every data byte, with overridable response code.
    fn get_random_response(rc: u32, fill: u8) -> [u8; GET_RANDOM_RESPONSE_LEN] {
        let mut r = [0u8; GET_RANDOM_RESPONSE_LEN];
        r[0..2].copy_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        r[2..6].copy_from_slice(&(GET_RANDOM_RESPONSE_LEN as u32).to_be_bytes());
        r[6..10].copy_from_slice(&rc.to_be_bytes());
        r[10..12].copy_from_slice(&(MAX_TPM2_SOURCE_BYTES as u16).to_be_bytes());
        for b in &mut r[12..] {
            *b = fill;
        }
        r
    }

    /// Distinct, non-degenerate data: `base`, `base+1`, ...
    fn get_random_response_counter(base: u8) -> [u8; GET_RANDOM_RESPONSE_LEN] {
        let mut r = get_random_response(TPM_RC_SUCCESS, 0);
        for (i, b) in r[12..].iter_mut().enumerate() {
            *b = base.wrapping_add(i as u8);
        }
        r
    }

    /// A well-formed manufacturer capability response for `id` (4 ASCII
    /// bytes, NUL-padded).
    fn manufacturer_response(id: &[u8]) -> [u8; GET_CAPABILITY_RESPONSE_LEN] {
        let mut r = [0u8; GET_CAPABILITY_RESPONSE_LEN];
        r[0..2].copy_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        r[2..6].copy_from_slice(&(GET_CAPABILITY_RESPONSE_LEN as u32).to_be_bytes());
        r[6..10].copy_from_slice(&TPM_RC_SUCCESS.to_be_bytes());
        r[10] = 0; // moreData
        r[11..15].copy_from_slice(&TPM_CAP_TPM_PROPERTIES.to_be_bytes());
        r[15..19].copy_from_slice(&1u32.to_be_bytes());
        r[19..23].copy_from_slice(&TPM_PT_MANUFACTURER.to_be_bytes());
        r[23..23 + id.len()].copy_from_slice(id);
        r
    }

    /// Scripted transport: a fixed presence flag plus a queue of canned
    /// responses, recording every submitted command for byte-exact
    /// marshalling assertions.
    struct ScriptedTransport {
        present: bool,
        responses: Vec<Vec<u8>>,
        commands: Vec<Vec<u8>>,
        fail_submit: bool,
    }

    impl ScriptedTransport {
        fn new(present: bool, responses: Vec<Vec<u8>>) -> Self {
            Self { present, responses, commands: Vec::new(), fail_submit: false }
        }
    }

    impl Tpm2Transport for ScriptedTransport {
        fn is_present(&mut self) -> bool {
            self.present
        }
        fn submit(&mut self, command: &[u8], response: &mut [u8]) -> Result<(), Tpm2SubmitError> {
            self.commands.push(command.to_vec());
            if self.fail_submit {
                return Err(Tpm2SubmitError);
            }
            let canned = self.responses.remove(0);
            response[..canned.len()].copy_from_slice(&canned);
            Ok(())
        }
    }

    fn fresh_deadline(clock: &mut FakeClock) -> Deadline<'_> {
        Deadline::start(clock, 5_000)
    }

    #[test]
    fn happy_path_produces_valid_record() {
        let mut t = ScriptedTransport::new(
            true,
            std::vec![
                get_random_response_counter(1).to_vec(),
                get_random_response_counter(101).to_vec(),
            ],
        );
        let mut clock = FakeClock::new(1);
        let mut deadline = fresh_deadline(&mut clock);
        let record = sample(&mut t, &approved_policy(), &mut deadline).expect("happy path");
        assert_eq!(record.tag(), SourceTag::Tpm2GetRandom);
        assert_eq!(record.algo_id(), TPM2_ALGO_ID);
        assert_eq!(record.bytes().len(), MAX_TPM2_SOURCE_BYTES);
        let expected: Vec<u8> = (0..32u8).map(|i| 1 + i).collect();
        assert_eq!(record.bytes(), &expected[..]);
        assert_eq!(t.commands.len(), 2, "exactly two GetRandom submissions");
    }

    /// SPEC_TPM_ENTROPY §5: byte-exact big-endian marshalling of the
    /// GetRandom command — `80 01 | 00 00 00 0C | 00 00 01 7B | 00 20`.
    #[test]
    fn get_random_command_marshals_byte_exact() {
        let mut t = ScriptedTransport::new(
            true,
            std::vec![
                get_random_response_counter(1).to_vec(),
                get_random_response_counter(101).to_vec(),
            ],
        );
        let mut clock = FakeClock::new(1);
        let mut deadline = fresh_deadline(&mut clock);
        sample(&mut t, &approved_policy(), &mut deadline).unwrap();
        assert_eq!(
            t.commands[0],
            std::vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x7B, 0x00, 0x20]
        );
        assert_eq!(t.commands[0], t.commands[1]);
    }

    /// §8.1: an unapproved policy issues zero TPM commands and never even
    /// asks about presence.
    #[test]
    fn unapproved_policy_never_touches_the_transport() {
        let mut t = ScriptedTransport::new(true, std::vec![]);
        let mut clock = FakeClock::new(1);
        let mut deadline = fresh_deadline(&mut clock);
        assert_eq!(
            sample(&mut t, &unapproved_policy(), &mut deadline).map(|_| ()).unwrap_err(),
            Tpm2Error::NotApproved
        );
        assert!(t.commands.is_empty());
    }

    #[test]
    fn absent_tpm_is_reported_not_present_with_zero_commands() {
        let mut t = ScriptedTransport::new(false, std::vec![]);
        let mut clock = FakeClock::new(1);
        let mut deadline = fresh_deadline(&mut clock);
        assert_eq!(
            sample(&mut t, &approved_policy(), &mut deadline).map(|_| ()).unwrap_err(),
            Tpm2Error::NotPresent
        );
        assert!(t.commands.is_empty());
    }

    /// §7.3: `TPM_RC_RETRY` is resubmitted within the policy budget and
    /// the sample still succeeds.
    #[test]
    fn rc_retry_within_budget_succeeds() {
        let mut t = ScriptedTransport::new(
            true,
            std::vec![
                get_random_response(TPM_RC_RETRY, 0).to_vec(),
                get_random_response_counter(1).to_vec(),
                get_random_response(TPM_RC_RETRY, 0).to_vec(),
                get_random_response_counter(101).to_vec(),
            ],
        );
        let mut clock = FakeClock::new(1);
        let mut deadline = fresh_deadline(&mut clock);
        assert!(sample(&mut t, &approved_policy(), &mut deadline).is_ok());
        assert_eq!(t.commands.len(), 4);
    }

    /// §7.3: retry exhaustion is a hard fail (`retry_limit = 3` allows 3
    /// resubmissions = 4 submissions of the first block).
    #[test]
    fn rc_retry_exhaustion_fails_hard() {
        let mut t = ScriptedTransport::new(
            true,
            std::vec![get_random_response(TPM_RC_RETRY, 0).to_vec(); 5],
        );
        let mut clock = FakeClock::new(1);
        let mut deadline = fresh_deadline(&mut clock);
        assert_eq!(
            sample(&mut t, &approved_policy(), &mut deadline).map(|_| ()).unwrap_err(),
            Tpm2Error::RetriesExhausted
        );
        assert_eq!(t.commands.len(), 4);
    }

    #[test]
    fn nonzero_non_retry_response_code_fails() {
        // TPM_RC_FAILURE (0x101).
        let mut t =
            ScriptedTransport::new(true, std::vec![get_random_response(0x101, 0).to_vec()]);
        let mut clock = FakeClock::new(1);
        let mut deadline = fresh_deadline(&mut clock);
        assert_eq!(
            sample(&mut t, &approved_policy(), &mut deadline).map(|_| ()).unwrap_err(),
            Tpm2Error::TpmErrorCode
        );
    }

    /// §7.2: a `TPM2B_DIGEST` shorter than the 32 requested bytes is a
    /// hard structural failure — never zero-padded, never accepted.
    #[test]
    fn short_digest_is_rejected_not_padded() {
        let mut r = get_random_response_counter(1);
        r[10..12].copy_from_slice(&16u16.to_be_bytes());
        // A shorter digest also shrinks responseSize; malformed either
        // way, but model the honest-short-TPM shape.
        r[2..6].copy_from_slice(&((10 + 2 + 16) as u32).to_be_bytes());
        let mut t = ScriptedTransport::new(true, std::vec![r.to_vec()]);
        let mut clock = FakeClock::new(1);
        let mut deadline = fresh_deadline(&mut clock);
        assert_eq!(
            sample(&mut t, &approved_policy(), &mut deadline).map(|_| ()).unwrap_err(),
            Tpm2Error::ResponseMalformed
        );
    }

    #[test]
    fn wrong_response_tag_is_rejected() {
        let mut r = get_random_response_counter(1);
        r[0..2].copy_from_slice(&0x8002u16.to_be_bytes()); // TPM_ST_SESSIONS
        let mut t = ScriptedTransport::new(true, std::vec![r.to_vec()]);
        let mut clock = FakeClock::new(1);
        let mut deadline = fresh_deadline(&mut clock);
        assert_eq!(
            sample(&mut t, &approved_policy(), &mut deadline).map(|_| ()).unwrap_err(),
            Tpm2Error::ResponseMalformed
        );
    }

    /// SPEC §16 catastrophic checks, in the exact usb_trng shape: a
    /// degenerate first block fails the sample.
    #[test]
    fn all_zero_block_a_is_rejected() {
        let mut t = ScriptedTransport::new(
            true,
            std::vec![get_random_response(TPM_RC_SUCCESS, 0x00).to_vec()],
        );
        let mut clock = FakeClock::new(1);
        let mut deadline = fresh_deadline(&mut clock);
        assert_eq!(
            sample(&mut t, &approved_policy(), &mut deadline).map(|_| ()).unwrap_err(),
            Tpm2Error::Health(HealthError::AllZero)
        );
    }

    #[test]
    fn identical_consecutive_blocks_are_rejected() {
        let mut t = ScriptedTransport::new(
            true,
            std::vec![
                get_random_response_counter(7).to_vec(),
                get_random_response_counter(7).to_vec(),
            ],
        );
        let mut clock = FakeClock::new(1);
        let mut deadline = fresh_deadline(&mut clock);
        assert_eq!(
            sample(&mut t, &approved_policy(), &mut deadline).map(|_| ()).unwrap_err(),
            Tpm2Error::Health(HealthError::IdenticalConsecutiveBlocks)
        );
    }

    #[test]
    fn transport_failure_is_unavailable() {
        let mut t = ScriptedTransport::new(true, std::vec![]);
        t.fail_submit = true;
        let mut clock = FakeClock::new(1);
        let mut deadline = fresh_deadline(&mut clock);
        assert_eq!(
            sample(&mut t, &approved_policy(), &mut deadline).map(|_| ()).unwrap_err(),
            Tpm2Error::Unavailable
        );
    }

    /// §7.3: an already-expired deadline fails closed before any TPM
    /// command executes.
    #[test]
    fn expired_deadline_is_checked_before_the_first_submit() {
        let mut t = ScriptedTransport::new(true, std::vec![]);
        let mut clock = FakeClock::new(1);
        clock.advance_per_call = 10_000;
        let mut deadline = Deadline::start(&mut clock, 1);
        assert_eq!(
            sample(&mut t, &approved_policy(), &mut deadline).map(|_| ()).unwrap_err(),
            Tpm2Error::DeadlineExceeded
        );
        assert!(t.commands.is_empty());
    }

    // ---- §7.1 point 4: manufacturer gate ----

    /// An empty reviewed list issues no GetCapability command at all.
    #[test]
    fn empty_manufacturer_list_skips_the_capability_round_trip() {
        let mut t = ScriptedTransport::new(
            true,
            std::vec![
                get_random_response_counter(1).to_vec(),
                get_random_response_counter(101).to_vec(),
            ],
        );
        let mut clock = FakeClock::new(1);
        let mut deadline = fresh_deadline(&mut clock);
        sample(&mut t, &approved_policy(), &mut deadline).unwrap();
        // Both submitted commands are GetRandom (cc 0x17B), no 0x17A.
        for cmd in &t.commands {
            assert_eq!(&cmd[6..10], &[0x00, 0x00, 0x01, 0x7B]);
        }
    }

    #[test]
    fn listed_manufacturer_passes_the_gate() {
        let mut t = ScriptedTransport::new(
            true,
            std::vec![
                manufacturer_response(b"IFX\0").to_vec(),
                get_random_response_counter(1).to_vec(),
                get_random_response_counter(101).to_vec(),
            ],
        );
        let mut clock = FakeClock::new(1);
        let mut deadline = fresh_deadline(&mut clock);
        assert!(sample(&mut t, &approved_policy_with_manufacturers(), &mut deadline).is_ok());
        // First command is GetCapability, byte-exact (§5).
        assert_eq!(
            t.commands[0],
            std::vec![
                0x80, 0x01, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x01, 0x7A, 0x00, 0x00, 0x00,
                0x06, 0x00, 0x00, 0x01, 0x05, 0x00, 0x00, 0x00, 0x01
            ]
        );
    }

    #[test]
    fn unlisted_manufacturer_is_refused_before_any_get_random() {
        let mut t = ScriptedTransport::new(
            true,
            std::vec![manufacturer_response(b"NTC\0").to_vec()],
        );
        let mut clock = FakeClock::new(1);
        let mut deadline = fresh_deadline(&mut clock);
        assert_eq!(
            sample(&mut t, &approved_policy_with_manufacturers(), &mut deadline).map(|_| ()).unwrap_err(),
            Tpm2Error::ManufacturerRefused
        );
        assert_eq!(t.commands.len(), 1, "refused before any GetRandom");
    }
}
