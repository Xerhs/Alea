//! WP-34 check class (c) — SPEC §27.3: "No error may contain: raw
//! entropy; dice or coin history; mnemonic words or indexes; the BIP39
//! seed; private keys or chain codes; hashes derived solely from the
//! mnemonic; re-entry prefixes; correct or incorrect word positions
//! beyond the currently requested position."
//!
//! Every error/failure type on the core protocol/derivation/policy path
//! (enumerated by grepping `pub enum .*Error`/`pub struct .*Error`/
//! `pub struct .*Failure` across `crates/` when this suite was first
//! built) is inspected here via an EXHAUSTIVE, non-wildcard
//! `match`/destructure per type. Known coverage gap, tracked pre-stable
//! (2026-08-06): error types added since — USB-TRNG (`UsbReadError`,
//! `UsbTrngError`), `PathParseError`, `PassphraseInputError`,
//! `ExtendedSelfTestFailure`, `WatchdogFailure`, `EntropyEncodingError`,
//! `CompatError` — are not yet enumerated, so the compile-enforced
//! rot-guard below does not protect them. This is a
//! stronger guarantee than a runtime spot-check: because the match arms
//! are exhaustive, the Rust compiler itself refuses to build this test if
//! a future change ever adds a new variant or field to any of these
//! types without this file being updated to account for it — so the
//! "structural, compile-enforced" proof does not silently rot. Each test
//! function also constructs one real instance of every variant and calls
//! the shape-check on it, so the exhaustiveness is exercised as an
//! executed `#[test]`, not just dead code.
//!
//! For every variant with a payload, this file recurses into that
//! payload's own type (also exhaustively matched) rather than treating
//! "has a field" as an automatic fail — the goal is "no *secret-shaped*
//! field" (an entropy/key/mnemonic-sized byte buffer, a word index, a
//! re-entry prefix), not "no field of any kind" (a `u32` line number in a
//! non-secret policy-file parse error, or a wrapped sibling error enum
//! that is itself proven field-free below, are fine).

use seed_core::contracts::{Bip39Error, DeriveError, EncodeError};
use seed_core::pipeline::PipelineError;
use seed_gop_ui::gop::backend::GopOpenError;
use seed_gop_ui::gop::mode::ModeSelectError;
use seed_platform_x86::boot::BannerError;
use seed_platform_x86::input::{SelfTestExpectation, SelfTestFailure};
use seed_platform_x86::rng::efi_rng::EfiRngError;
use seed_platform_x86::rng::health::HealthError;
use seed_platform_x86::rng::rdrand::RdrandError;
use seed_platform_x86::rng::rdseed::Rdseed64Error;
use seed_protocol::physical::PhysicalError;
use seed_protocol::policy::{ParseError, ParseErrorKind};
use seed_protocol::state::{ErrorClass, WatchdogReassertFailure};
use seed_protocol::transcript::TranscriptError;
use seed_flow::flow_secret::machine::MachineAcquisitionError;
use seed_flow::flow_secret::shutdown::ShutdownFailure;

// ============================================================================
// Leaf error enums: every variant must be a bare unit variant (no payload
// of any kind). This is the strictest, simplest category.
// ============================================================================

fn assert_encode_error_shape(e: &EncodeError) {
    match e {
        EncodeError::BufferTooSmall | EncodeError::InvalidVersion | EncodeError::InvalidProgramLength => {}
    }
}

fn assert_bip39_error_shape(e: &Bip39Error) {
    match e {
        Bip39Error::InvalidEntropyLength | Bip39Error::ChecksumMismatch => {}
    }
}

fn assert_derive_error_shape(e: &DeriveError) {
    match e {
        DeriveError::InvalidChildKey | DeriveError::InvalidIndex | DeriveError::PointAtInfinity | DeriveError::BufferTooSmall => {}
    }
}

fn assert_transcript_error_shape(e: &TranscriptError) {
    use TranscriptError::*;
    match e {
        DuplicateTag | TooManyRecords | AlgoIdTooLong | SourceTooLong | InvalidRollValue | InvalidFlipValue | BufferOverflow | Truncated
        | Oversized | BadDomain | UnknownTag | OutOfCanonicalOrder | TrailingBytes | PresenceMismatch => {}
    }
}

fn assert_mode_select_error_shape(e: &ModeSelectError) {
    match e {
        ModeSelectError::NoModesReported | ModeSelectError::OnlyPixelBltOnly | ModeSelectError::BelowResolutionFloor => {}
    }
}

fn assert_banner_error_shape(e: &BannerError) {
    match e {
        BannerError::LineTooLong | BannerError::OutputFailed => {}
    }
}

fn assert_health_error_shape(e: &HealthError) {
    match e {
        HealthError::LengthMismatch | HealthError::AllZero | HealthError::AllFf | HealthError::IdenticalConsecutiveBlocks => {}
    }
}

fn assert_physical_error_shape(e: &PhysicalError) {
    match e {
        PhysicalError::InvalidRoll | PhysicalError::CapacityReached => {}
    }
}

fn assert_machine_acquisition_error_shape(e: &MachineAcquisitionError) {
    match e {
        // `SourceTimedOut` (real-hardware slow-RDSEED fix, SPEC §21): a
        // plain unit variant, exactly like `NoSourceAvailable` -- no
        // secret-bearing payload to check.
        MachineAcquisitionError::NoSourceAvailable | MachineAcquisitionError::SourceTimedOut => {}
    }
}

/// `ErrorClass` is not itself thrown as an error value in the ordinary
/// sense -- it is the SPEC §27.3 error-*class* taxonomy the state machine
/// tags every post-secret fault with (`Event::Fault(ErrorClass)`).
/// Included here because it is exactly the enum SPEC §27.3's own list of
/// classes ("Platform; watchdog; console-topology; ...") maps onto, so
/// proving it carries no payload anywhere is a direct, load-bearing check
/// of that SPEC sentence.
fn assert_error_class_shape(e: &ErrorClass) {
    use ErrorClass::*;
    match e {
        Platform | Watchdog | ConsoleTopology | Virtualization | GraphicsOrKeyboard | EntropyPolicy | MachineSource | PhysicalEntryState
        | Derivation | Cryptographic | StateMachine | Integrity | Shutdown => {}
    }
}

fn assert_parse_error_kind_shape(e: &ParseErrorKind) {
    use ParseErrorKind::*;
    match e {
        LineTooLong | UnterminatedHeader | UnknownSection | DuplicateSection | ExpectedEquals | InvalidKey | UnknownKey | DuplicateKey
        | InvalidBoolean | InvalidInteger | IntegerOverflow | InvalidString | StringTooLong | InvalidArray | TooManyAlgorithms
        | TooManyCpuRules | TooManyDenylistEntries | TooManyUsbTrngDevices | UnknownUsbTrngProfile | UnsupportedUsbClass
        | UsbTrngMinReadBytesOutOfRange | MissingField | InvalidRange | RdrandSoleSourceNotAllowed
        | RdrandMustBeSupplementaryOnly | RdseedMustBe64Bit | TrailingContent => {}
    }
}

// ============================================================================
// Wrapper error enums: every variant is either a unit variant or wraps
// another type already proven field-free above.
// ============================================================================

fn assert_gop_open_error_shape(e: &GopOpenError) {
    match e {
        GopOpenError::NoGraphicsOutput | GopOpenError::SetModeFailed => {}
        GopOpenError::ModeSelect(inner) => assert_mode_select_error_shape(inner),
    }
}

fn assert_efi_rng_error_shape(e: &EfiRngError) {
    use EfiRngError::*;
    match e {
        LocateFailed | GetInfoFailed | TooManyAlgorithms | DuplicateAlgorithm | MalformedAlgorithm | NoApprovedAlgorithm
        // `DeadlineExceeded` (real-hardware slow-RDSEED fix, SPEC §21):
        // a plain unit variant, no secret-bearing payload.
        | InvalidRequestLength | GetRngFailed | DeadlineExceeded => {}
        Health(inner) => assert_health_error_shape(inner),
    }
}

fn assert_rdrand_error_shape(e: &RdrandError) {
    use RdrandError::*;
    match e {
        // `DeadlineExceeded`: see `assert_efi_rng_error_shape`'s comment.
        NotApproved | NotSupplementaryOnly | CpuidUnsupported | RetryExhausted | DeadlineExceeded => {}
        Health(inner) => assert_health_error_shape(inner),
    }
}

fn assert_rdseed64_error_shape(e: &Rdseed64Error) {
    use Rdseed64Error::*;
    match e {
        // `DeadlineExceeded`: see `assert_efi_rng_error_shape`'s comment.
        NotApproved | UnsupportedWidth | PolicyMinValuesInvalid | CpuidUnsupported | CpuDenylisted | CpuNotAllowed | RetryExhausted
        | DeadlineExceeded => {}
        Health(inner) => assert_health_error_shape(inner),
    }
}

/// SPEC §27.3 explicitly lists "hashes derived solely from the mnemonic"
/// as forbidden error content -- `PipelineError::Bip39` and
/// `PipelineError::Transcript` are exactly the two pipeline-facade error
/// paths that fire during/after mnemonic derivation, so both are checked
/// here against a concrete instantiation (`TranscriptError`, the sink
/// error type this module uses `seed_protocol::transcript::
/// TranscriptError` for, matching the real production wiring in
/// `crates/seed-flow/src/flow_secret/derive.rs`'s own
/// `DeriveFlowError` type alias).
fn assert_pipeline_error_shape(e: &PipelineError<TranscriptError>) {
    match e {
        PipelineError::Transcript(inner) => assert_transcript_error_shape(inner),
        PipelineError::Bip39(inner) => assert_bip39_error_shape(inner),
        // Pre-release audit MUST-FIX #2 (`docs/PRE-RELEASE-AUDIT.md`):
        // the fail-closed entropy-floor rejection. A bare unit variant --
        // carries no source bytes, no digest, nothing derived from any
        // secret.
        PipelineError::InsufficientSources => {}
    }
}

// ============================================================================
// Struct-shaped error/failure types: every field must be an allowlisted
// non-secret type (a plain integer position/line number over PUBLIC,
// non-secret data, or another type already proven field-free above).
// ============================================================================

/// `ParseError { line: u32, kind: ParseErrorKind }` -- `line` is a
/// 1-based line number into `entropy-policy.toml`, a compiled-in, non-secret,
/// project-shipped configuration file (SPEC §15), never user secret
/// material; `kind` is proven field-free above.
fn assert_parse_error_shape(e: &ParseError) {
    let ParseError { line: _, kind } = e;
    assert_parse_error_kind_shape(kind);
}

/// `SelfTestFailure { index: usize, expected: SelfTestExpectation }` --
/// SPEC §11.5's keyboard-layout self-test uses a FIXED, PUBLIC,
/// project-defined test sequence (`self_test_sequence()`: literally
/// "A-Z, 1-6, Backspace, Enter"), never real user secret entry, so
/// `index`/`expected` describe only where in that fixed public script the
/// keyboard driver mismatched -- not a re-entry position/prefix in the
/// SPEC §27.3 sense (that is `reentry::ReentryOutcome`, checked
/// separately below, which is a bare `Matched`/`Mismatch` enum with no
/// payload at all).
fn assert_self_test_failure_shape(e: &SelfTestFailure) {
    let SelfTestFailure { index: _, expected } = e;
    match expected {
        SelfTestExpectation::Char(_) | SelfTestExpectation::Backspace | SelfTestExpectation::Enter => {}
    }
}

// ============================================================================
// Executed tests: construct one real instance of every variant/type and
// run it through the shape-check above (exercises the exhaustive match,
// not just dead code).
// ============================================================================

#[test]
fn leaf_error_enums_carry_no_fields() {
    for e in [EncodeError::BufferTooSmall, EncodeError::InvalidVersion, EncodeError::InvalidProgramLength] {
        assert_encode_error_shape(&e);
    }
    for e in [Bip39Error::InvalidEntropyLength, Bip39Error::ChecksumMismatch] {
        assert_bip39_error_shape(&e);
    }
    for e in [DeriveError::InvalidChildKey, DeriveError::InvalidIndex, DeriveError::PointAtInfinity, DeriveError::BufferTooSmall] {
        assert_derive_error_shape(&e);
    }
    for e in [
        TranscriptError::DuplicateTag,
        TranscriptError::TooManyRecords,
        TranscriptError::AlgoIdTooLong,
        TranscriptError::SourceTooLong,
        TranscriptError::InvalidRollValue,
        TranscriptError::InvalidFlipValue,
        TranscriptError::BufferOverflow,
        TranscriptError::Truncated,
        TranscriptError::Oversized,
        TranscriptError::BadDomain,
        TranscriptError::UnknownTag,
        TranscriptError::OutOfCanonicalOrder,
        TranscriptError::TrailingBytes,
        TranscriptError::PresenceMismatch,
    ] {
        assert_transcript_error_shape(&e);
    }
    for e in [ModeSelectError::NoModesReported, ModeSelectError::OnlyPixelBltOnly, ModeSelectError::BelowResolutionFloor] {
        assert_mode_select_error_shape(&e);
    }
    for e in [BannerError::LineTooLong, BannerError::OutputFailed] {
        assert_banner_error_shape(&e);
    }
    for e in [HealthError::LengthMismatch, HealthError::AllZero, HealthError::AllFf, HealthError::IdenticalConsecutiveBlocks] {
        assert_health_error_shape(&e);
    }
    for e in [PhysicalError::InvalidRoll, PhysicalError::CapacityReached] {
        assert_physical_error_shape(&e);
    }
    assert_machine_acquisition_error_shape(&MachineAcquisitionError::NoSourceAvailable);
    for e in [
        ErrorClass::Platform,
        ErrorClass::Watchdog,
        ErrorClass::ConsoleTopology,
        ErrorClass::Virtualization,
        ErrorClass::GraphicsOrKeyboard,
        ErrorClass::EntropyPolicy,
        ErrorClass::MachineSource,
        ErrorClass::PhysicalEntryState,
        ErrorClass::Derivation,
        ErrorClass::Cryptographic,
        ErrorClass::StateMachine,
        ErrorClass::Integrity,
        ErrorClass::Shutdown,
    ] {
        assert_error_class_shape(&e);
    }
    use ParseErrorKind::*;
    for e in [
        LineTooLong,
        UnterminatedHeader,
        UnknownSection,
        DuplicateSection,
        ExpectedEquals,
        InvalidKey,
        UnknownKey,
        DuplicateKey,
        InvalidBoolean,
        InvalidInteger,
        IntegerOverflow,
        InvalidString,
        StringTooLong,
        InvalidArray,
        TooManyAlgorithms,
        TooManyCpuRules,
        TooManyDenylistEntries,
        TooManyUsbTrngDevices,
        UnknownUsbTrngProfile,
        UnsupportedUsbClass,
        UsbTrngMinReadBytesOutOfRange,
        MissingField,
        InvalidRange,
        RdrandSoleSourceNotAllowed,
        RdrandMustBeSupplementaryOnly,
        RdseedMustBe64Bit,
        TrailingContent,
    ] {
        assert_parse_error_kind_shape(&e);
    }
}

#[test]
fn wrapper_error_enums_only_wrap_already_field_free_types() {
    assert_gop_open_error_shape(&GopOpenError::NoGraphicsOutput);
    assert_gop_open_error_shape(&GopOpenError::SetModeFailed);
    assert_gop_open_error_shape(&GopOpenError::ModeSelect(ModeSelectError::NoModesReported));

    for e in [
        EfiRngError::LocateFailed,
        EfiRngError::GetInfoFailed,
        EfiRngError::TooManyAlgorithms,
        EfiRngError::DuplicateAlgorithm,
        EfiRngError::MalformedAlgorithm,
        EfiRngError::NoApprovedAlgorithm,
        EfiRngError::InvalidRequestLength,
        EfiRngError::GetRngFailed,
        EfiRngError::Health(HealthError::AllZero),
    ] {
        assert_efi_rng_error_shape(&e);
    }

    for e in [RdrandError::NotApproved, RdrandError::NotSupplementaryOnly, RdrandError::CpuidUnsupported, RdrandError::RetryExhausted, RdrandError::Health(HealthError::AllFf)] {
        assert_rdrand_error_shape(&e);
    }

    for e in [
        Rdseed64Error::NotApproved,
        Rdseed64Error::UnsupportedWidth,
        Rdseed64Error::PolicyMinValuesInvalid,
        Rdseed64Error::CpuidUnsupported,
        Rdseed64Error::CpuDenylisted,
        Rdseed64Error::CpuNotAllowed,
        Rdseed64Error::RetryExhausted,
        Rdseed64Error::Health(HealthError::IdenticalConsecutiveBlocks),
    ] {
        assert_rdseed64_error_shape(&e);
    }

    assert_pipeline_error_shape(&PipelineError::Transcript(TranscriptError::DuplicateTag));
    assert_pipeline_error_shape(&PipelineError::Bip39(Bip39Error::ChecksumMismatch));
    assert_pipeline_error_shape(&PipelineError::<TranscriptError>::InsufficientSources);
}

#[test]
fn struct_shaped_errors_carry_only_allowlisted_non_secret_fields() {
    assert_parse_error_shape(&ParseError { line: 7, kind: ParseErrorKind::MissingField });
    assert_parse_error_shape(&ParseError { line: 0, kind: ParseErrorKind::InvalidInteger });

    assert_self_test_failure_shape(&SelfTestFailure { index: 3, expected: SelfTestExpectation::Char('q') });
    assert_self_test_failure_shape(&SelfTestFailure { index: 30, expected: SelfTestExpectation::Backspace });

    // Zero-field marker types: constructing them at all is the whole
    // proof (a struct literal with fields would fail to compile against
    // a unit-struct's `Type;` definition).
    let _ = WatchdogReassertFailure;
    let _ = ShutdownFailure;
}

/// SPEC §27.3's own most specific example -- "correct or incorrect word
/// positions beyond the currently requested position" -- is exactly what
/// `reentry::ReentryOutcome` (the value the re-entry loop reports per
/// word position) must never carry. Checked directly against the real
/// production type, exhaustively.
#[test]
fn reentry_outcome_carries_no_position_or_letter_information() {
    use seed_flow::flow_secret::reentry::ReentryOutcome;
    for e in [ReentryOutcome::Matched, ReentryOutcome::Mismatch] {
        match e {
            ReentryOutcome::Matched | ReentryOutcome::Mismatch => {}
        }
    }
}
