//! USB-TRNG driver (WP-U3, SPEC_USB_TRNG.md v0.6.2 §6, §7, §9).
//!
//! This module produces a tagged (`SourceTag::ApprovedUsbTrng` = `0x12`)
//! [`super::record::SourceRecord`] from an allow-listed, policy-approved USB
//! hardware TRNG, reusing this crate's existing [`super::health`]
//! catastrophic checks (`check_length`, `check_not_degenerate`,
//! `check_not_repeated`) the same way [`super::rdseed`] does, and adding the
//! USB-specific failure modes SPEC_USB_TRNG §9 enumerates: short read,
//! device disappearance/timeout, stall, descriptor/class re-verification
//! failure, and command/echo-handshake failure.
//!
//! **The real USB transfer primitive is out of scope here (WP-U4,
//! §7.4-BLOCKED — see `IMPLEMENTATION_MAP_USB_TRNG.md` §4/§7).** This module
//! defines only the [`UsbTrngTransport`] trait contract (SPEC_USB_TRNG §3.3
//! of the implementation map) that a real backend will implement later, plus
//! a host-test double (`tests::ScriptedTransport`) that lets every health
//! path here be exercised with `cargo test` and no hardware, no firmware
//! protocol, and no `EFI_USB_IO_PROTOCOL` link. Swapping in WP-U4's real
//! implementation is a drop-in: [`sample`] never depends on anything but the
//! trait.
//!
//! Order of operations, mirroring [`super::rdseed::sample`]'s structure:
//! 1. `policy.usb_trng.approved` gates everything (SPEC_USB_TRNG §8.1).
//! 2. [`UsbTrngTransport::enumerate_allowed`] matches the attached device's
//!    identity against the compiled-in allow-list (SPEC_USB_TRNG §7.4 point 1,
//!    §8.1 `is_device_allowed`) — default-deny, exact `(vid, pid, class)`
//!    match.
//! 3. Two diagnostic blocks are read via [`UsbTrngTransport::start_and_read`]
//!    (SPEC_USB_TRNG §9's "two consecutive diagnostic blocks", the same
//!    shape RDSEED already collects). Each read is retried up to
//!    `policy.usb_trng.max_read_retries` times on a *transport* failure
//!    (device gone, timeout, stall, descriptor mismatch, echo failure) —
//!    never on a short read, which fails immediately and is never zero-padded
//!    (SPEC_USB_TRNG §9: "Never zero-pad a short read up to length").
//! 4. Block A must not be degenerate; block B must not be degenerate and
//!    must differ from block A (SPEC §16 via [`super::health`]).
//! 5. Block A becomes the [`super::record::SourceRecord`], tagged `0x12`,
//!    with a fixed, device-supplied-string-free `algo_id` built from the
//!    matched policy entry's `profile` and `init_command` (SPEC_USB_TRNG
//!    §6.1: e.g. `"USB-TRNG/OneRNG/cmd1"` — never raw device text).

use seed_core::contracts::{SourceTag, MAX_ALGO_ID, MAX_MACHINE_SOURCE_BYTES};
use seed_protocol::policy::MAX_USB_TRNG_READ_BYTES;
use seed_protocol::policy::{
    FixedStr, Policy, UsbClass, UsbTrngDevice, UsbTrngPolicy, MAX_INIT_COMMAND_LEN,
    MAX_PROFILE_LEN,
};

use super::health::{self, HealthError};
use super::record::SourceRecord;
use super::util::scrub;

/// The fixed ASCII prefix every USB-TRNG `algo_id` starts with
/// (SPEC_USB_TRNG §6.1).
const ALGO_ID_PREFIX: &[u8] = b"USB-TRNG/";

/// The `(profile, init_command)` separator inside the fixed `algo_id`
/// (SPEC_USB_TRNG §6.1 example: `"USB-TRNG/OneRNG/cmd1"`).
const ALGO_ID_SEP: u8 = b'/';

/// The USB device the policy's allow-list matched (SPEC_USB_TRNG §7.4 point
/// 1), handed from [`UsbTrngTransport::enumerate_allowed`] to
/// [`UsbTrngTransport::start_and_read`]. A plain copy of the matched
/// `[[usb_trng_devices]]` policy entry's identifying fields — never
/// device-supplied text (SPEC_USB_TRNG §6.1) — so a transport backend has
/// everything it needs to address the physical device and re-verify its
/// descriptor at read time (SPEC_USB_TRNG §9 "descriptor / class
/// re-verification") without holding a borrow into the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatchedDevice {
    /// USB vendor id (SPEC_USB_TRNG §8.1).
    pub vendor_id: u16,
    /// USB product id (SPEC_USB_TRNG §8.1).
    pub product_id: u16,
    /// Expected interface class, re-verified at read time (SPEC_USB_TRNG
    /// §7.4 point 2, §9).
    pub usb_class: UsbClass,
    /// Fixed device-profile id (SPEC_USB_TRNG §6.1), copied from the
    /// matched allow-list entry.
    pub profile: FixedStr<MAX_PROFILE_LEN>,
    /// Device init/feed-start command (SPEC_USB_TRNG §5.1, §9), copied from
    /// the matched allow-list entry.
    pub init_command: FixedStr<MAX_INIT_COMMAND_LEN>,
}

impl MatchedDevice {
    /// Copies the identifying fields out of a compiled-in policy allow-list
    /// entry. A real [`UsbTrngTransport::enumerate_allowed`] implementation
    /// (WP-U4) calls this once it has confirmed a physically attached
    /// device's descriptor matches `dev` — never the other way around, so
    /// no device-supplied text ever enters a [`MatchedDevice`].
    pub fn from_policy_entry(dev: &UsbTrngDevice) -> Self {
        MatchedDevice {
            vendor_id: dev.vendor_id,
            product_id: dev.product_id,
            usb_class: dev.usb_class,
            profile: dev.profile,
            init_command: dev.init_command,
        }
    }
}

/// Why a USB bulk read attempt failed at the transport layer
/// (SPEC_USB_TRNG §9). Deliberately does **not** include a short-read
/// variant: a transport that returns fewer than the requested bytes reports
/// that via `start_and_read`'s `Ok(usize)` length, which [`sample`] checks
/// with [`health::check_length`] — never zero-padded, never silently
/// accepted (SPEC_USB_TRNG §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbReadError {
    /// The bulk transfer did not complete within `read_timeout_ms`
    /// (SPEC_USB_TRNG §9: "a bulk transfer timeout").
    Timeout,
    /// The device detached mid-read (SPEC_USB_TRNG §9: "the device
    /// detaching").
    DeviceGone,
    /// The bulk endpoint stalled (SPEC_USB_TRNG §9: "a stall").
    Stalled,
    /// The device's descriptor (VID/PID/interface class) no longer matches
    /// what enumeration observed — including a newly exposed input
    /// interface (SPEC_USB_TRNG §7.4 point 2, §9: "descriptor / class
    /// re-verification... a device that changed descriptors or exposed an
    /// input interface since enumeration → refuse").
    DescriptorMismatch,
    /// The `cmdO`/`cmd1` feed-start handshake did not produce a live feed
    /// (SPEC_USB_TRNG §9: "command/echo sanity... a device that returns
    /// nothing, or returns a constant, fails").
    EchoFailed,
}

/// One backend's USB transfer primitive (`IMPLEMENTATION_MAP_USB_TRNG.md`
/// §3.3). Exactly one implementation per backend is expected in the
/// finished product — the real `EFI_USB_IO_PROTOCOL`-driven implementation
/// is WP-U4, **not implemented here** (§7.4-BLOCKED) — plus a host-test
/// double (`tests::ScriptedTransport`) that lets [`sample`] be exercised
/// with `cargo test` and no hardware.
pub trait UsbTrngTransport {
    /// Matches the currently attached, enumerable USB device(s) against
    /// `pol`'s allow-list (SPEC_USB_TRNG §7.4 point 1, `UsbTrngPolicy::
    /// is_device_allowed`'s default-deny semantics). Returns `None` if no
    /// attached device's `(vendor_id, product_id, usb_class)` matches an
    /// approved entry, or if `pol.approved` is `false`.
    fn enumerate_allowed(&mut self, pol: &UsbTrngPolicy) -> Option<MatchedDevice>;

    /// Issues the device's feed-start command (if not already started) and
    /// reads up to `out.len()` bytes into `out`, returning the number of
    /// bytes actually written. MUST NOT zero-pad: a short read is reported
    /// as its true length, never silently topped up (SPEC_USB_TRNG §9).
    fn start_and_read(
        &mut self,
        dev: &MatchedDevice,
        out: &mut [u8],
    ) -> Result<usize, UsbReadError>;
}

/// Why a USB-TRNG sample attempt was refused or failed (SPEC_USB_TRNG §7,
/// §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbTrngError {
    /// `policy.usb_trng.approved` is `false` (SPEC_USB_TRNG §8.1: policy-
    /// gated, SHIP DEFAULT unapproved).
    NotApproved,
    /// No attached device matched the compiled-in allow-list (SPEC_USB_TRNG
    /// §7.4 point 1: "Availability does not imply approval").
    NoDeviceMatched,
    /// The matched allow-list entry's `algo_id` (prefix + `profile` + `/` +
    /// `init_command`) does not fit `MAX_ALGO_ID` bytes. Defensive: the
    /// policy parser already bounds `profile`/`init_command` so this should
    /// be unreachable for any policy it accepted, but this driver never
    /// assumes an invariant it cannot itself see enforced (SPEC §27.3
    /// fail-closed discipline).
    AlgoIdOverflow,
    /// A bulk transfer timed out (SPEC_USB_TRNG §9), after the policy's
    /// retry budget was exhausted.
    Timeout,
    /// The device detached mid-read (SPEC_USB_TRNG §9), after the policy's
    /// retry budget was exhausted.
    DeviceGone,
    /// The bulk endpoint stalled (SPEC_USB_TRNG §9), after the policy's
    /// retry budget was exhausted.
    Stalled,
    /// The device's descriptor/class no longer matched the allow-list at
    /// read time (SPEC_USB_TRNG §7.4 point 2, §9), after the policy's
    /// retry budget was exhausted.
    DescriptorMismatch,
    /// The `cmdO`/`cmd1` handshake never produced a live feed
    /// (SPEC_USB_TRNG §9), after the policy's retry budget was exhausted.
    EchoFailed,
    /// A sampled block failed a SPEC §16 catastrophic check (short read,
    /// all-zero, all-`0xFF`, or identical consecutive blocks).
    Health(HealthError),
}

impl From<UsbReadError> for UsbTrngError {
    fn from(e: UsbReadError) -> Self {
        match e {
            UsbReadError::Timeout => UsbTrngError::Timeout,
            UsbReadError::DeviceGone => UsbTrngError::DeviceGone,
            UsbReadError::Stalled => UsbTrngError::Stalled,
            UsbReadError::DescriptorMismatch => UsbTrngError::DescriptorMismatch,
            UsbReadError::EchoFailed => UsbTrngError::EchoFailed,
        }
    }
}

/// Builds the fixed `algo_id` bytes (`"USB-TRNG/" + profile + "/" +
/// init_command`, SPEC_USB_TRNG §6.1) for `dev` into `out`, returning the
/// number of bytes written, or `None` if it would overflow `out`
/// (`MAX_ALGO_ID` bytes). Never touches device-supplied text — `dev`'s
/// `profile`/`init_command` are copies of the *compiled-in policy's* allow-list
/// entry (SPEC_USB_TRNG §6.1: "chosen from a fixed table so no untrusted,
/// device-supplied descriptor string is ever mixed into the transcript").
fn build_algo_id(dev: &MatchedDevice, out: &mut [u8; MAX_ALGO_ID]) -> Option<usize> {
    let profile = dev.profile.as_str().as_bytes();
    let init_command = dev.init_command.as_str().as_bytes();
    let total = ALGO_ID_PREFIX.len() + profile.len() + 1 + init_command.len();
    if total > MAX_ALGO_ID {
        return None;
    }
    let mut i = 0;
    out[i..i + ALGO_ID_PREFIX.len()].copy_from_slice(ALGO_ID_PREFIX);
    i += ALGO_ID_PREFIX.len();
    out[i..i + profile.len()].copy_from_slice(profile);
    i += profile.len();
    out[i] = ALGO_ID_SEP;
    i += 1;
    out[i..i + init_command.len()].copy_from_slice(init_command);
    i += init_command.len();
    Some(i)
}

/// Reads one `min_bytes`-length diagnostic block, retrying up to
/// `max_retries` times on a transport-level [`UsbReadError`] (never on a
/// short read, which is an immediate [`HealthError::LengthMismatch`] —
/// SPEC_USB_TRNG §9: "Never zero-pad a short read"). On retry exhaustion,
/// returns the *last observed* transport error, so a caller can tell a
/// timeout apart from a device-gone or descriptor-mismatch failure rather
/// than a single collapsed "retries exhausted" variant.
fn read_block(
    transport: &mut dyn UsbTrngTransport,
    dev: &MatchedDevice,
    min_bytes: usize,
    max_retries: u8,
) -> Result<[u8; MAX_MACHINE_SOURCE_BYTES], UsbTrngError> {
    let mut attempts: u16 = 0;
    loop {
        let mut buf = [0u8; MAX_MACHINE_SOURCE_BYTES];
        match transport.start_and_read(dev, &mut buf[..min_bytes]) {
            Ok(n) => {
                health::check_length(n, min_bytes).map_err(UsbTrngError::Health)?;
                return Ok(buf);
            }
            Err(e) => {
                attempts += 1;
                if attempts as u32 > max_retries as u32 {
                    return Err(UsbTrngError::from(e));
                }
                // else: bounded retry, loop again (SPEC_USB_TRNG §9's
                // `max_read_retries` budget).
            }
        }
    }
}

/// Samples one USB-TRNG [`SourceRecord`] (SPEC_USB_TRNG §7, §9). See the
/// module doc for the exact sequence.
pub fn sample(
    transport: &mut dyn UsbTrngTransport,
    policy: &Policy,
) -> Result<SourceRecord, UsbTrngError> {
    let usb_policy = &policy.usb_trng;
    if !usb_policy.approved {
        return Err(UsbTrngError::NotApproved);
    }

    let matched = transport
        .enumerate_allowed(usb_policy)
        .ok_or(UsbTrngError::NoDeviceMatched)?;

    // Clamp to the USB-TRNG read ceiling (32), NOT the shared machine-source
    // cap: L2 raised that cap to 64 for RDSEED's 2x margin, and USB reads must
    // keep their own reviewed 32-byte bound (SPEC_USB_TRNG §8.2). Behaviourally
    // a no-op — the policy parser already rejects any min_read_bytes > 32 — but
    // this defense-in-depth clamp must match the reviewed USB ceiling, not
    // inherit RDSEED's.
    let min_bytes = (usb_policy.min_read_bytes as usize).min(MAX_USB_TRNG_READ_BYTES as usize);

    let mut block_a = read_block(transport, &matched, min_bytes, usb_policy.max_read_retries)?;
    if let Err(e) = health::check_not_degenerate(&block_a[..min_bytes]) {
        scrub(&mut block_a);
        return Err(UsbTrngError::Health(e));
    }

    let mut block_b = match read_block(transport, &matched, min_bytes, usb_policy.max_read_retries)
    {
        Ok(b) => b,
        Err(e) => {
            scrub(&mut block_a);
            return Err(e);
        }
    };
    let degenerate = health::check_not_degenerate(&block_b[..min_bytes]);
    let repeated = health::check_not_repeated(&block_a[..min_bytes], &block_b[..min_bytes]);
    if let Err(e) = degenerate.and(repeated) {
        scrub(&mut block_a);
        scrub(&mut block_b);
        return Err(UsbTrngError::Health(e));
    }
    scrub(&mut block_b);

    let mut algo_id = [0u8; MAX_ALGO_ID];
    let algo_id_len = match build_algo_id(&matched, &mut algo_id) {
        Some(n) => n,
        None => {
            scrub(&mut block_a);
            return Err(UsbTrngError::AlgoIdOverflow);
        }
    };

    let record = SourceRecord::new(
        SourceTag::ApprovedUsbTrng,
        &algo_id[..algo_id_len],
        &block_a[..min_bytes],
    )
    .ok_or_else(|| {
        // Unreachable for any policy the parser accepted
        // (`min_read_bytes <= MAX_MACHINE_SOURCE_BYTES`, `algo_id_len <=
        // MAX_ALGO_ID` already checked above); kept as a fail-closed path
        // rather than a panic (SPEC §27.3).
        UsbTrngError::AlgoIdOverflow
    });
    scrub(&mut block_a);
    record
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use seed_protocol::policy::Policy;

    /// A canned [`UsbTrngTransport`] double (WP-U3, `IMPLEMENTATION_MAP_
    /// USB_TRNG.md` §4): scripts a fixed sequence of `start_and_read`
    /// results so every SPEC_USB_TRNG §9 health path is testable without
    /// any hardware, firmware protocol, or `EFI_USB_IO_PROTOCOL` link.
    /// `enumerate_allowed` always reports `device` present when the policy
    /// approves it and the fixture's `present` flag is set — real
    /// enumeration (WP-U4) is out of scope here.
    struct ScriptedTransport {
        present: bool,
        device: MatchedDevice,
        /// One scripted outcome per `start_and_read` call, consumed in
        /// order. Running out of scripted reads panics the test — a test
        /// that reaches this has under-scripted its double.
        reads: std::vec::Vec<Result<std::vec::Vec<u8>, UsbReadError>>,
        calls: usize,
    }

    impl UsbTrngTransport for ScriptedTransport {
        fn enumerate_allowed(&mut self, pol: &UsbTrngPolicy) -> Option<MatchedDevice> {
            if !self.present {
                return None;
            }
            pol.is_device_allowed(self.device.vendor_id, self.device.product_id, self.device.usb_class)?;
            Some(self.device)
        }

        fn start_and_read(
            &mut self,
            _dev: &MatchedDevice,
            out: &mut [u8],
        ) -> Result<usize, UsbReadError> {
            let outcome = self
                .reads
                .get(self.calls)
                .cloned()
                .expect("test under-scripted ScriptedTransport reads");
            self.calls += 1;
            match outcome {
                Ok(bytes) => {
                    let n = bytes.len().min(out.len());
                    out[..n].copy_from_slice(&bytes[..n]);
                    Ok(bytes.len())
                }
                Err(e) => Err(e),
            }
        }
    }

    fn one_rng_device() -> MatchedDevice {
        MatchedDevice {
            vendor_id: 0x1d50,
            product_id: 0x6086,
            usb_class: UsbClass::CdcAcm,
            profile: seed_protocol::policy::FixedStr::from_str("OneRNG").unwrap(),
            init_command: seed_protocol::policy::FixedStr::from_str("cmd1").unwrap(),
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
approved = false
sole_source_allowed = false
supplementary_only = true

[usb_trng]
approved = true
sole_source_allowed = false
min_read_bytes = 32
read_timeout_ms = 2000
max_read_retries = 2

[[usb_trng_devices]]
profile = "OneRNG"
vendor_id = 7504
product_id = 24710
usb_class = "cdc-acm"
init_command = "cmd1"
min_firmware = ""
reason_pinned = "raw avalanche; reinforcement only; not sole-source"

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

    const TEST_POLICY_TOML_UNAPPROVED: &str = r#"
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

    fn allow_all_policy() -> Policy {
        seed_protocol::policy::parse(TEST_POLICY_TOML).expect("well-formed test policy")
    }

    fn unapproved_policy() -> Policy {
        seed_protocol::policy::parse(TEST_POLICY_TOML_UNAPPROVED).expect("well-formed test policy")
    }

    fn block(byte: u8) -> std::vec::Vec<u8> {
        std::vec![byte; 32]
    }

    fn distinct_blocks() -> (std::vec::Vec<u8>, std::vec::Vec<u8>) {
        let mut a = std::vec![0x11u8; 32];
        let mut b = std::vec![0x22u8; 32];
        a[0] = 0xAA;
        b[0] = 0xBB;
        (a, b)
    }

    #[test]
    fn good_stream_yields_a_0x12_record() {
        let policy = allow_all_policy();
        let (a, b) = distinct_blocks();
        let mut transport = ScriptedTransport {
            present: true,
            device: one_rng_device(),
            reads: std::vec![Ok(a.clone()), Ok(b)],
            calls: 0,
        };
        let record = sample(&mut transport, &policy).expect("clean scripted stream must succeed");
        assert_eq!(record.tag(), SourceTag::ApprovedUsbTrng);
        assert_eq!(record.algo_id(), b"USB-TRNG/OneRNG/cmd1");
        assert_eq!(record.bytes(), &a[..]);
    }

    #[test]
    fn not_approved_is_refused_without_touching_transport() {
        let policy = unapproved_policy();
        let mut transport = ScriptedTransport {
            present: true,
            device: one_rng_device(),
            reads: std::vec![],
            calls: 0,
        };
        assert_eq!(sample(&mut transport, &policy).err(), Some(UsbTrngError::NotApproved));
        assert_eq!(transport.calls, 0);
    }

    #[test]
    fn no_device_present_is_refused() {
        let policy = allow_all_policy();
        let mut transport =
            ScriptedTransport { present: false, device: one_rng_device(), reads: std::vec![], calls: 0 };
        assert_eq!(sample(&mut transport, &policy).err(), Some(UsbTrngError::NoDeviceMatched));
    }

    #[test]
    fn unlisted_device_is_refused_default_deny() {
        let policy = allow_all_policy();
        let mut unlisted = one_rng_device();
        unlisted.product_id = 0xffff;
        let mut transport =
            ScriptedTransport { present: true, device: unlisted, reads: std::vec![], calls: 0 };
        assert_eq!(sample(&mut transport, &policy).err(), Some(UsbTrngError::NoDeviceMatched));
    }

    #[test]
    fn all_zero_block_is_rejected() {
        let policy = allow_all_policy();
        let mut transport = ScriptedTransport {
            present: true,
            device: one_rng_device(),
            reads: std::vec![Ok(block(0x00))],
            calls: 0,
        };
        assert_eq!(
            sample(&mut transport, &policy).err(),
            Some(UsbTrngError::Health(HealthError::AllZero))
        );
    }

    #[test]
    fn all_ff_block_is_rejected() {
        let policy = allow_all_policy();
        let mut transport = ScriptedTransport {
            present: true,
            device: one_rng_device(),
            reads: std::vec![Ok(block(0xFF))],
            calls: 0,
        };
        assert_eq!(
            sample(&mut transport, &policy).err(),
            Some(UsbTrngError::Health(HealthError::AllFf))
        );
    }

    #[test]
    fn stuck_repeating_blocks_are_rejected() {
        let policy = allow_all_policy();
        let same = block(0x42);
        let mut transport = ScriptedTransport {
            present: true,
            device: one_rng_device(),
            reads: std::vec![Ok(same.clone()), Ok(same)],
            calls: 0,
        };
        assert_eq!(
            sample(&mut transport, &policy).err(),
            Some(UsbTrngError::Health(HealthError::IdenticalConsecutiveBlocks))
        );
    }

    #[test]
    fn short_read_is_rejected_never_zero_padded() {
        let policy = allow_all_policy();
        let mut transport = ScriptedTransport {
            present: true,
            device: one_rng_device(),
            reads: std::vec![Ok(std::vec![0x11u8; 16])], // policy requires 32
            calls: 0,
        };
        assert_eq!(
            sample(&mut transport, &policy).err(),
            Some(UsbTrngError::Health(HealthError::LengthMismatch))
        );
    }

    #[test]
    fn short_read_is_never_retried() {
        // A short read is a health-check failure, not a transport error —
        // it must fail on the very first attempt, never consuming the
        // retry budget (SPEC_USB_TRNG §9: "Never zero-pad a short read").
        let policy = allow_all_policy();
        let mut transport = ScriptedTransport {
            present: true,
            device: one_rng_device(),
            reads: std::vec![Ok(std::vec![0x11u8; 16])],
            calls: 0,
        };
        let _ = sample(&mut transport, &policy);
        assert_eq!(transport.calls, 1, "short read must not be retried");
    }

    #[test]
    fn device_disappearance_mid_read_is_rejected() {
        let policy = allow_all_policy();
        let mut transport = ScriptedTransport {
            present: true,
            device: one_rng_device(),
            reads: std::vec![
                Err(UsbReadError::DeviceGone),
                Err(UsbReadError::DeviceGone),
                Err(UsbReadError::DeviceGone),
            ],
            calls: 0,
        };
        assert_eq!(sample(&mut transport, &policy).err(), Some(UsbTrngError::DeviceGone));
        // policy's max_read_retries = 2 => 1 initial attempt + 2 retries = 3 calls.
        assert_eq!(transport.calls, 3);
    }

    #[test]
    fn timeout_is_rejected_after_retry_budget_exhausted() {
        let policy = allow_all_policy();
        let mut transport = ScriptedTransport {
            present: true,
            device: one_rng_device(),
            reads: std::vec![
                Err(UsbReadError::Timeout),
                Err(UsbReadError::Timeout),
                Err(UsbReadError::Timeout),
            ],
            calls: 0,
        };
        assert_eq!(sample(&mut transport, &policy).err(), Some(UsbTrngError::Timeout));
    }

    #[test]
    fn stall_is_rejected_after_retry_budget_exhausted() {
        let policy = allow_all_policy();
        let mut transport = ScriptedTransport {
            present: true,
            device: one_rng_device(),
            reads: std::vec![Err(UsbReadError::Stalled), Err(UsbReadError::Stalled), Err(UsbReadError::Stalled)],
            calls: 0,
        };
        assert_eq!(sample(&mut transport, &policy).err(), Some(UsbTrngError::Stalled));
    }

    #[test]
    fn descriptor_mismatch_at_read_time_is_rejected() {
        let policy = allow_all_policy();
        let mut transport = ScriptedTransport {
            present: true,
            device: one_rng_device(),
            reads: std::vec![
                Err(UsbReadError::DescriptorMismatch),
                Err(UsbReadError::DescriptorMismatch),
                Err(UsbReadError::DescriptorMismatch),
            ],
            calls: 0,
        };
        assert_eq!(sample(&mut transport, &policy).err(), Some(UsbTrngError::DescriptorMismatch));
    }

    #[test]
    fn echo_handshake_failure_is_rejected() {
        let policy = allow_all_policy();
        let mut transport = ScriptedTransport {
            present: true,
            device: one_rng_device(),
            reads: std::vec![
                Err(UsbReadError::EchoFailed),
                Err(UsbReadError::EchoFailed),
                Err(UsbReadError::EchoFailed),
            ],
            calls: 0,
        };
        assert_eq!(sample(&mut transport, &policy).err(), Some(UsbTrngError::EchoFailed));
    }

    #[test]
    fn transient_failure_recovers_within_retry_budget() {
        // A transport-level failure that clears before the retry budget is
        // exhausted must still yield a good record — retries exist so a
        // single flaky poll does not fail an otherwise-healthy device.
        let policy = allow_all_policy();
        let (a, b) = distinct_blocks();
        let mut transport = ScriptedTransport {
            present: true,
            device: one_rng_device(),
            reads: std::vec![Err(UsbReadError::Timeout), Ok(a.clone()), Ok(b)],
            calls: 0,
        };
        let record = sample(&mut transport, &policy).expect("must recover within retry budget");
        assert_eq!(record.bytes(), &a[..]);
    }

    #[test]
    fn second_block_failure_scrubs_first_block_before_returning() {
        // Not directly observable (SourceRecord/scrub state is private),
        // but this exercises the path where block A succeeds and block B's
        // read fails outright, proving it does not panic and does return
        // the expected error rather than silently mixing a half-read.
        let policy = allow_all_policy();
        let a = block(0x11);
        let mut transport = ScriptedTransport {
            present: true,
            device: one_rng_device(),
            reads: std::vec![
                Ok(a),
                Err(UsbReadError::DeviceGone),
                Err(UsbReadError::DeviceGone),
                Err(UsbReadError::DeviceGone),
            ],
            calls: 0,
        };
        assert_eq!(sample(&mut transport, &policy).err(), Some(UsbTrngError::DeviceGone));
    }

    #[test]
    fn record_bytes_never_exceed_policy_min_read_bytes() {
        let policy = allow_all_policy();
        let (a, b) = distinct_blocks();
        let mut transport = ScriptedTransport {
            present: true,
            device: one_rng_device(),
            reads: std::vec![Ok(a), Ok(b)],
            calls: 0,
        };
        let record = sample(&mut transport, &policy).unwrap();
        assert_eq!(record.bytes().len(), policy.usb_trng.min_read_bytes as usize);
    }
}
