//! Minimal TOML-subset parser for `entropy-policy.toml` (WP-12, SPEC §15).
//!
//! # Grammar (documented here; this is *not* full TOML)
//!
//! ```text
//! file        := line*
//! line        := ws* (comment | table-header | array-header | assignment)? ws* newline
//! comment     := '#' any-char-except-newline*
//! table-header    := '[' ident ']'
//! array-header    := '[[' ident ']]'
//! assignment  := key ws* '=' ws* value
//! key         := ('a'..'z' | 'A'..'Z' | '_') ('a'..'z' | 'A'..'Z' | '0'..'9' | '_')*
//! value       := integer | boolean | string | string-array
//! integer     := '0' | ('1'..'9' digit*)              (unsigned decimal only; no
//!                                                       sign, no leading zeros,
//!                                                       no floats, no underscores)
//! boolean     := 'true' | 'false'
//! string      := '"' printable-ascii-no-quote-no-backslash* '"'
//! string-array := '[' ws* (string (ws* ',' ws* string)*)? ws* ']'   (single line)
//! ```
//!
//! Not supported (any occurrence is a reject, not a best-effort parse):
//! multi-line strings/arrays, string escapes (including `\"`), unicode
//! escapes, floats, signed integers, underscores in numbers, inline
//! tables, dotted keys, nested arrays, non-ASCII or control bytes inside
//! strings, duplicate keys, duplicate sections, unknown keys/sections,
//! lines over [`MAX_LINE_LEN`] bytes.
//!
//! # Schema (fixed, known set of sections/keys — SPEC §15)
//!
//! ```text
//! policy_version = <u16>                       # required, top level
//!
//! [efi_rng]                                     # SPEC §15.1
//! approved = <bool>
//! sole_source_allowed = <bool>
//! max_algorithms = <u8>
//! allowed_algorithms = [<string>, ...]          # up to MAX_ALGORITHMS
//!
//! [rdseed]                                      # SPEC §15.2
//! approved = <bool>
//! sole_source_allowed = <bool>
//! instruction_width_bits = <u16>                # MUST be 64 if approved
//! retry_limit = <u16>
//! min_successful_values = <u8>
//! diagnostic_blocks = <u8>
//!
//! [[rdseed_cpu_rules]]                          # 0 or more, SPEC §15.2
//! vendor = <string>                             # CPUID vendor-ID, <=12 bytes
//! family_min = <u16>
//! family_max = <u16>
//! model_min = <u8>
//! model_max = <u8>
//! stepping_min = <u8>
//! stepping_max = <u8>
//! allow = <bool>
//! min_microcode_revision = <u32>                # optional, SPEC §15: required
//!                                                # microcode/firmware condition
//!                                                # "where known"; absent means
//!                                                # this rule has none
//!
//! [rdrand]                                      # SPEC §15.3
//! approved = <bool>
//! sole_source_allowed = <bool>                  # MUST be false
//! supplementary_only = <bool>                   # MUST be true
//!
//! [[denylist]]                                  # 0 or more, SPEC §15
//! vendor = <string>
//! family_min = <u16>
//! family_max = <u16>
//! model_min = <u8>
//! model_max = <u8>
//! stepping_min = <u8>
//! stepping_max = <u8>
//! reason = <string>                             # <=64 bytes
//!
//! [usb_trng]                                    # SPEC_USB_TRNG §8.1
//! approved = <bool>
//! sole_source_allowed = <bool>                  # plain bool, EFI-modelled
//! min_read_bytes = <u16>                        # bounded [16, 32]
//! read_timeout_ms = <u16>
//! max_read_retries = <u8>
//! # NOTE: there is deliberately no `counts_toward_floor` or
//! # `reviewed_floor_override` key in this schema. Either key appearing in
//! # a `[usb_trng]` section is rejected as UnknownKey — the same mechanism
//! # that rejects any other unrecognized key (SPEC_USB_TRNG §8.2).
//!
//! [[usb_trng_devices]]                          # 0 or more, SPEC_USB_TRNG §8.1
//! profile = <string>                            # MUST be a known fixed profile id
//! vendor_id = <u16>                             # decimal only (this grammar has
//! product_id = <u16>                            # no hex integer form); e.g. USB
//!                                                # VID `0x1d50` is written `7504`
//! usb_class = <string>                          # MUST be "cdc-acm" (v1's only class)
//! init_command = <string>                       # <=16 bytes
//! min_firmware = <string>                       # <=32 bytes; "" = unconstrained
//! reason_pinned = <string>                      # <=64 bytes
//! ```

use super::types::{
    CpuRange, CpuRule, DenylistEntry, Policy, Reason, UsbClass, UsbTrngDevice, Vendor,
    KNOWN_USB_TRNG_PROFILES, MAX_USB_TRNG_READ_BYTES, MIN_USB_TRNG_READ_BYTES,
};

/// Reject any line longer than this (keeps the parser's line handling
/// bounded without needing a heap buffer).
pub const MAX_LINE_LEN: usize = 256;

/// Why a policy file was rejected. Carries the 1-based source line where
/// the problem was detected (SPEC §27.3: no secret values in errors — this
/// type never can, it only describes file syntax).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseError {
    /// 1-based line number of the offending line (0 if not line-specific,
    /// e.g. a missing-required-field error detected at EOF).
    pub line: u32,
    /// The specific rejection reason.
    pub kind: ParseErrorKind,
}

/// Specific reasons a policy file is malformed or fails validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseErrorKind {
    /// A line exceeded [`MAX_LINE_LEN`] bytes.
    LineTooLong,
    /// A `[...]`/`[[...]]` header was missing its closing bracket(s).
    UnterminatedHeader,
    /// A section/array name is not one of the fixed schema names.
    UnknownSection,
    /// The same `[section]` (or top level) appeared more than once.
    DuplicateSection,
    /// A non-header line had no `=`.
    ExpectedEquals,
    /// A key is empty or contains characters outside `[A-Za-z0-9_]`, or
    /// starts with a digit.
    InvalidKey,
    /// A key is not recognized in its current section.
    UnknownKey,
    /// The same key was assigned twice within the same section/record.
    DuplicateKey,
    /// A value that should be `true`/`false` was neither.
    InvalidBoolean,
    /// A value that should be an unsigned integer was malformed (empty,
    /// non-digit, leading zero, signed, or otherwise not a bare decimal
    /// literal).
    InvalidInteger,
    /// An integer literal's value does not fit the target field width.
    IntegerOverflow,
    /// A value that should be a double-quoted string was malformed
    /// (missing quotes, contains a backslash/embedded quote, contains a
    /// non-printable-ASCII byte).
    InvalidString,
    /// A string value exceeded its field's fixed capacity.
    StringTooLong,
    /// A value that should be `[...]` array-of-strings was malformed.
    InvalidArray,
    /// An `allowed_algorithms` array had more entries than
    /// [`super::types::MAX_ALGORITHMS`].
    TooManyAlgorithms,
    /// More than [`super::types::MAX_CPU_RULES`] `[[rdseed_cpu_rules]]`
    /// records were present.
    TooManyCpuRules,
    /// More than [`super::types::MAX_DENYLIST_ENTRIES`] `[[denylist]]`
    /// records were present.
    TooManyDenylistEntries,
    /// More than [`super::types::MAX_USB_TRNG_DEVICES`]
    /// `[[usb_trng_devices]]` records were present (SPEC_USB_TRNG §8.1).
    TooManyUsbTrngDevices,
    /// A `[[usb_trng_devices]]` `profile` value was not one of
    /// [`super::types::KNOWN_USB_TRNG_PROFILES`] (SPEC_USB_TRNG §8.2:
    /// "MUST have a `profile` that resolves to a known fixed profile id").
    UnknownUsbTrngProfile,
    /// A `[[usb_trng_devices]]` `usb_class` value was not a reviewed class
    /// (SPEC_USB_TRNG §8.2: "`hid` and any composite-with-input class are
    /// not representable as an approved class").
    UnsupportedUsbClass,
    /// `[usb_trng] min_read_bytes` was outside
    /// `[MIN_USB_TRNG_READ_BYTES, MAX_USB_TRNG_READ_BYTES]`
    /// (SPEC_USB_TRNG §8.2: "MUST be ≥ the health-check block size and ≤
    /// `MAX_USB_TRNG_READ_BYTES` (32)" — the USB read ceiling, decoupled from
    /// the shared machine-source cap, which the L2 change raised to 64).
    UsbTrngMinReadBytesOutOfRange,
    /// A required field was never set (in a section, or the top-level
    /// `policy_version`). `line` is the header line of the section that
    /// is missing the field (or `0` for top-level).
    MissingField,
    /// A `*_min` value was greater than the corresponding `*_max` value.
    InvalidRange,
    /// `[rdrand] sole_source_allowed = true` (SPEC §15.3 forbids this).
    RdrandSoleSourceNotAllowed,
    /// `[rdrand] supplementary_only = false` (SPEC §15.3 forbids this).
    RdrandMustBeSupplementaryOnly,
    /// `[rdseed] approved = true` with `instruction_width_bits != 64`
    /// (SPEC §15.2: only the 64-bit form).
    RdseedMustBe64Bit,
    /// Trailing, non-whitespace content followed a complete value on the
    /// same line (e.g. `approved = true extra`).
    TrailingContent,
}

/// Parse and fully validate a policy file (SPEC §15). Any malformed or
/// out-of-policy input is rejected with a [`ParseError`]; there is no
/// partial/best-effort success.
pub fn parse(input: &str) -> Result<Policy, ParseError> {
    let mut policy = Policy::empty();

    let mut section = Section::Top;
    let mut seen_version = false;
    let mut seen_efi_rng = false;
    let mut seen_rdseed = false;
    let mut seen_rdrand = false;
    let mut seen_usb_trng = false;

    // Per-section duplicate-key tracking (top-level `policy_version` uses
    // `seen_version` above).
    let mut efi_seen = EfiRngSeen::default();
    let mut rdseed_seen = RdseedSeen::default();
    let mut rdrand_seen = RdrandSeen::default();
    let mut usb_trng_seen = UsbTrngSeen::default();

    let mut cpu_rule: Option<CpuRuleBuilder> = None;
    let mut denylist_entry: Option<DenylistBuilder> = None;
    let mut usb_trng_device: Option<UsbTrngDeviceBuilder> = None;

    for (idx, raw_line) in input.lines().enumerate() {
        let line_no = (idx + 1) as u32;
        if raw_line.len() > MAX_LINE_LEN {
            return Err(ParseError { line: line_no, kind: ParseErrorKind::LineTooLong });
        }
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(rest) = line.strip_prefix("[[") {
            let name = rest
                .strip_suffix("]]")
                .ok_or(ParseError { line: line_no, kind: ParseErrorKind::UnterminatedHeader })?
                .trim();
            finalize_pending(&mut policy, section, &mut cpu_rule, &mut denylist_entry, &mut usb_trng_device, line_no)?;
            match name {
                "rdseed_cpu_rules" => {
                    section = Section::RdseedCpuRule;
                    cpu_rule = Some(CpuRuleBuilder::default());
                }
                "denylist" => {
                    section = Section::Denylist;
                    denylist_entry = Some(DenylistBuilder::default());
                }
                "usb_trng_devices" => {
                    section = Section::UsbTrngDevice;
                    usb_trng_device = Some(UsbTrngDeviceBuilder::default());
                }
                _ => return Err(ParseError { line: line_no, kind: ParseErrorKind::UnknownSection }),
            }
        } else if let Some(rest) = line.strip_prefix('[') {
            let name = rest
                .strip_suffix(']')
                .ok_or(ParseError { line: line_no, kind: ParseErrorKind::UnterminatedHeader })?
                .trim();
            finalize_pending(&mut policy, section, &mut cpu_rule, &mut denylist_entry, &mut usb_trng_device, line_no)?;
            match name {
                "efi_rng" => {
                    if seen_efi_rng {
                        return Err(ParseError { line: line_no, kind: ParseErrorKind::DuplicateSection });
                    }
                    seen_efi_rng = true;
                    section = Section::EfiRng;
                }
                "rdseed" => {
                    if seen_rdseed {
                        return Err(ParseError { line: line_no, kind: ParseErrorKind::DuplicateSection });
                    }
                    seen_rdseed = true;
                    section = Section::Rdseed;
                }
                "rdrand" => {
                    if seen_rdrand {
                        return Err(ParseError { line: line_no, kind: ParseErrorKind::DuplicateSection });
                    }
                    seen_rdrand = true;
                    section = Section::Rdrand;
                }
                "usb_trng" => {
                    if seen_usb_trng {
                        return Err(ParseError { line: line_no, kind: ParseErrorKind::DuplicateSection });
                    }
                    seen_usb_trng = true;
                    section = Section::UsbTrng;
                }
                _ => return Err(ParseError { line: line_no, kind: ParseErrorKind::UnknownSection }),
            }
        } else {
            let eq = line.find('=').ok_or(ParseError { line: line_no, kind: ParseErrorKind::ExpectedEquals })?;
            let key = line[..eq].trim();
            let val = line[eq + 1..].trim();
            validate_key(key).ok_or(ParseError { line: line_no, kind: ParseErrorKind::InvalidKey })?;

            match section {
                Section::Top => {
                    if key != "policy_version" {
                        return Err(ParseError { line: line_no, kind: ParseErrorKind::UnknownKey });
                    }
                    if seen_version {
                        return Err(ParseError { line: line_no, kind: ParseErrorKind::DuplicateKey });
                    }
                    policy.version = parse_u16(val).map_err(|kind| ParseError { line: line_no, kind })?;
                    seen_version = true;
                }
                Section::EfiRng => apply_efi_rng(&mut policy, &mut efi_seen, key, val, line_no)?,
                Section::Rdseed => apply_rdseed(&mut policy, &mut rdseed_seen, key, val, line_no)?,
                Section::Rdrand => apply_rdrand(&mut policy, &mut rdrand_seen, key, val, line_no)?,
                Section::UsbTrng => apply_usb_trng(&mut policy, &mut usb_trng_seen, key, val, line_no)?,
                Section::RdseedCpuRule => {
                    let b = cpu_rule.as_mut().expect("array-header always sets a builder");
                    apply_cpu_rule_field(b, key, val, line_no)?;
                }
                Section::Denylist => {
                    let b = denylist_entry.as_mut().expect("array-header always sets a builder");
                    apply_denylist_field(b, key, val, line_no)?;
                }
                Section::UsbTrngDevice => {
                    let b = usb_trng_device.as_mut().expect("array-header always sets a builder");
                    apply_usb_trng_device_field(b, key, val, line_no)?;
                }
            }
        }
    }

    let eof_line = (input.lines().count() as u32) + 1;
    finalize_pending(&mut policy, section, &mut cpu_rule, &mut denylist_entry, &mut usb_trng_device, eof_line)?;

    if !seen_version {
        return Err(ParseError { line: 0, kind: ParseErrorKind::MissingField });
    }
    if !efi_seen.approved || !efi_seen.sole_source_allowed || !efi_seen.max_algorithms {
        return Err(ParseError { line: 0, kind: ParseErrorKind::MissingField });
    }
    if !rdseed_seen.approved
        || !rdseed_seen.sole_source_allowed
        || !rdseed_seen.instruction_width_bits
        || !rdseed_seen.retry_limit
        || !rdseed_seen.min_successful_values
        || !rdseed_seen.diagnostic_blocks
    {
        return Err(ParseError { line: 0, kind: ParseErrorKind::MissingField });
    }
    if !rdrand_seen.approved || !rdrand_seen.sole_source_allowed || !rdrand_seen.supplementary_only {
        return Err(ParseError { line: 0, kind: ParseErrorKind::MissingField });
    }
    if !usb_trng_seen.approved
        || !usb_trng_seen.sole_source_allowed
        || !usb_trng_seen.min_read_bytes
        || !usb_trng_seen.read_timeout_ms
        || !usb_trng_seen.max_read_retries
    {
        return Err(ParseError { line: 0, kind: ParseErrorKind::MissingField });
    }

    // Cross-field policy validation (SPEC §15.2/§15.3).
    if policy.rdrand.sole_source_allowed {
        return Err(ParseError { line: 0, kind: ParseErrorKind::RdrandSoleSourceNotAllowed });
    }
    if !policy.rdrand.supplementary_only {
        return Err(ParseError { line: 0, kind: ParseErrorKind::RdrandMustBeSupplementaryOnly });
    }
    if policy.rdseed.approved && policy.rdseed.instruction_width_bits != 64 {
        return Err(ParseError { line: 0, kind: ParseErrorKind::RdseedMustBe64Bit });
    }
    // SPEC_USB_TRNG §8.2: "min_read_bytes MUST be >= the health-check block
    // size and <= MAX_USB_TRNG_READ_BYTES (32)" — the USB read ceiling
    // (decoupled from the now-64 shared machine-source cap). Checked
    // unconditionally (not gated on `approved`), matching the RDSEED
    // 64-bit-width guard above being unconditional-on-syntax too.
    if policy.usb_trng.min_read_bytes < MIN_USB_TRNG_READ_BYTES
        || policy.usb_trng.min_read_bytes > MAX_USB_TRNG_READ_BYTES
    {
        return Err(ParseError { line: 0, kind: ParseErrorKind::UsbTrngMinReadBytesOutOfRange });
    }

    Ok(policy)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Top,
    EfiRng,
    Rdseed,
    Rdrand,
    UsbTrng,
    RdseedCpuRule,
    Denylist,
    UsbTrngDevice,
}

#[derive(Default)]
struct EfiRngSeen {
    approved: bool,
    sole_source_allowed: bool,
    max_algorithms: bool,
    allowed_algorithms: bool,
}

#[derive(Default)]
struct RdseedSeen {
    approved: bool,
    sole_source_allowed: bool,
    instruction_width_bits: bool,
    retry_limit: bool,
    min_successful_values: bool,
    diagnostic_blocks: bool,
}

#[derive(Default)]
struct RdrandSeen {
    approved: bool,
    sole_source_allowed: bool,
    supplementary_only: bool,
}

#[derive(Default)]
struct UsbTrngSeen {
    approved: bool,
    sole_source_allowed: bool,
    min_read_bytes: bool,
    read_timeout_ms: bool,
    max_read_retries: bool,
}

#[derive(Default)]
struct CpuRuleBuilder {
    vendor: Option<Vendor>,
    family_min: Option<u16>,
    family_max: Option<u16>,
    model_min: Option<u8>,
    model_max: Option<u8>,
    stepping_min: Option<u8>,
    stepping_max: Option<u8>,
    allow: Option<bool>,
    /// Optional (SPEC §15: "where known") — see grammar doc above.
    min_microcode_revision: Option<u32>,
}

#[derive(Default)]
struct DenylistBuilder {
    vendor: Option<Vendor>,
    family_min: Option<u16>,
    family_max: Option<u16>,
    model_min: Option<u8>,
    model_max: Option<u8>,
    stepping_min: Option<u8>,
    stepping_max: Option<u8>,
    reason: Option<Reason>,
}

#[derive(Default)]
struct UsbTrngDeviceBuilder {
    profile: Option<super::types::FixedStr<{ super::types::MAX_PROFILE_LEN }>>,
    vendor_id: Option<u16>,
    product_id: Option<u16>,
    usb_class: Option<UsbClass>,
    init_command: Option<super::types::FixedStr<{ super::types::MAX_INIT_COMMAND_LEN }>>,
    min_firmware: Option<super::types::FixedStr<{ super::types::MAX_MIN_FIRMWARE_LEN }>>,
    reason: Option<Reason>,
}

fn finalize_pending(
    policy: &mut Policy,
    section: Section,
    cpu_rule: &mut Option<CpuRuleBuilder>,
    denylist_entry: &mut Option<DenylistBuilder>,
    usb_trng_device: &mut Option<UsbTrngDeviceBuilder>,
    line_no: u32,
) -> Result<(), ParseError> {
    match section {
        Section::RdseedCpuRule => {
            if let Some(b) = cpu_rule.take() {
                let range = build_range(
                    b.vendor,
                    b.family_min,
                    b.family_max,
                    b.model_min,
                    b.model_max,
                    b.stepping_min,
                    b.stepping_max,
                    line_no,
                )?;
                let allow = b.allow.ok_or(ParseError { line: line_no, kind: ParseErrorKind::MissingField })?;
                // `min_microcode_revision` is optional (SPEC §15: "where
                // known") — absent stays `None`, no MissingField error.
                policy
                    .rdseed
                    .push_cpu_rule(CpuRule { range, allow, min_microcode_revision: b.min_microcode_revision })
                    .map_err(|_| ParseError { line: line_no, kind: ParseErrorKind::TooManyCpuRules })?;
            }
        }
        Section::Denylist => {
            if let Some(b) = denylist_entry.take() {
                let range = build_range(
                    b.vendor,
                    b.family_min,
                    b.family_max,
                    b.model_min,
                    b.model_max,
                    b.stepping_min,
                    b.stepping_max,
                    line_no,
                )?;
                let reason = b.reason.ok_or(ParseError { line: line_no, kind: ParseErrorKind::MissingField })?;
                policy
                    .push_denylist(DenylistEntry { range, reason })
                    .map_err(|_| ParseError { line: line_no, kind: ParseErrorKind::TooManyDenylistEntries })?;
            }
        }
        Section::UsbTrngDevice => {
            if let Some(b) = usb_trng_device.take() {
                let missing = || ParseError { line: line_no, kind: ParseErrorKind::MissingField };
                let device = UsbTrngDevice {
                    profile: b.profile.ok_or_else(missing)?,
                    vendor_id: b.vendor_id.ok_or_else(missing)?,
                    product_id: b.product_id.ok_or_else(missing)?,
                    usb_class: b.usb_class.ok_or_else(missing)?,
                    init_command: b.init_command.ok_or_else(missing)?,
                    min_firmware: b.min_firmware.ok_or_else(missing)?,
                    reason: b.reason.ok_or_else(missing)?,
                };
                policy
                    .usb_trng
                    .push_device(device)
                    .map_err(|_| ParseError { line: line_no, kind: ParseErrorKind::TooManyUsbTrngDevices })?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_range(
    vendor: Option<Vendor>,
    family_min: Option<u16>,
    family_max: Option<u16>,
    model_min: Option<u8>,
    model_max: Option<u8>,
    stepping_min: Option<u8>,
    stepping_max: Option<u8>,
    line_no: u32,
) -> Result<CpuRange, ParseError> {
    let missing = || ParseError { line: line_no, kind: ParseErrorKind::MissingField };
    let vendor = vendor.ok_or_else(missing)?;
    let family_min = family_min.ok_or_else(missing)?;
    let family_max = family_max.ok_or_else(missing)?;
    let model_min = model_min.ok_or_else(missing)?;
    let model_max = model_max.ok_or_else(missing)?;
    let stepping_min = stepping_min.ok_or_else(missing)?;
    let stepping_max = stepping_max.ok_or_else(missing)?;
    if family_min > family_max || model_min > model_max || stepping_min > stepping_max {
        return Err(ParseError { line: line_no, kind: ParseErrorKind::InvalidRange });
    }
    Ok(CpuRange { vendor, family_min, family_max, model_min, model_max, stepping_min, stepping_max })
}

fn apply_efi_rng(
    policy: &mut Policy,
    seen: &mut EfiRngSeen,
    key: &str,
    val: &str,
    line_no: u32,
) -> Result<(), ParseError> {
    let dup = |k: bool| k;
    match key {
        "approved" => {
            if dup(seen.approved) {
                return Err(ParseError { line: line_no, kind: ParseErrorKind::DuplicateKey });
            }
            policy.efi_rng.approved = parse_bool(val).map_err(|kind| ParseError { line: line_no, kind })?;
            seen.approved = true;
        }
        "sole_source_allowed" => {
            if seen.sole_source_allowed {
                return Err(ParseError { line: line_no, kind: ParseErrorKind::DuplicateKey });
            }
            policy.efi_rng.sole_source_allowed =
                parse_bool(val).map_err(|kind| ParseError { line: line_no, kind })?;
            seen.sole_source_allowed = true;
        }
        "max_algorithms" => {
            if seen.max_algorithms {
                return Err(ParseError { line: line_no, kind: ParseErrorKind::DuplicateKey });
            }
            policy.efi_rng.max_algorithms = parse_u8(val).map_err(|kind| ParseError { line: line_no, kind })?;
            seen.max_algorithms = true;
        }
        "allowed_algorithms" => {
            if seen.allowed_algorithms {
                return Err(ParseError { line: line_no, kind: ParseErrorKind::DuplicateKey });
            }
            for_each_array_string(val, |tok| {
                let id = super::types::AlgoId::from_str(tok).ok_or(ParseErrorKind::StringTooLong)?;
                policy.efi_rng.push_algorithm(id).map_err(|_| ParseErrorKind::TooManyAlgorithms)?;
                Ok(())
            })
            .map_err(|kind| ParseError { line: line_no, kind })?;
            seen.allowed_algorithms = true;
        }
        _ => return Err(ParseError { line: line_no, kind: ParseErrorKind::UnknownKey }),
    }
    Ok(())
}

fn apply_rdseed(
    policy: &mut Policy,
    seen: &mut RdseedSeen,
    key: &str,
    val: &str,
    line_no: u32,
) -> Result<(), ParseError> {
    macro_rules! scalar {
        ($field:ident, $seen_field:ident, $parser:ident) => {{
            if seen.$seen_field {
                return Err(ParseError { line: line_no, kind: ParseErrorKind::DuplicateKey });
            }
            policy.rdseed.$field = $parser(val).map_err(|kind| ParseError { line: line_no, kind })?;
            seen.$seen_field = true;
        }};
    }
    match key {
        "approved" => scalar!(approved, approved, parse_bool),
        "sole_source_allowed" => scalar!(sole_source_allowed, sole_source_allowed, parse_bool),
        "instruction_width_bits" => scalar!(instruction_width_bits, instruction_width_bits, parse_u16),
        "retry_limit" => scalar!(retry_limit, retry_limit, parse_u16),
        "min_successful_values" => scalar!(min_successful_values, min_successful_values, parse_u8),
        "diagnostic_blocks" => scalar!(diagnostic_blocks, diagnostic_blocks, parse_u8),
        _ => return Err(ParseError { line: line_no, kind: ParseErrorKind::UnknownKey }),
    }
    Ok(())
}

fn apply_rdrand(
    policy: &mut Policy,
    seen: &mut RdrandSeen,
    key: &str,
    val: &str,
    line_no: u32,
) -> Result<(), ParseError> {
    macro_rules! scalar {
        ($field:ident, $seen_field:ident) => {{
            if seen.$seen_field {
                return Err(ParseError { line: line_no, kind: ParseErrorKind::DuplicateKey });
            }
            policy.rdrand.$field = parse_bool(val).map_err(|kind| ParseError { line: line_no, kind })?;
            seen.$seen_field = true;
        }};
    }
    match key {
        "approved" => scalar!(approved, approved),
        "sole_source_allowed" => scalar!(sole_source_allowed, sole_source_allowed),
        "supplementary_only" => scalar!(supplementary_only, supplementary_only),
        _ => return Err(ParseError { line: line_no, kind: ParseErrorKind::UnknownKey }),
    }
    Ok(())
}

/// Applies one `key = val` assignment inside `[usb_trng]` (SPEC_USB_TRNG
/// §8.1). Any key not matched below — in particular `counts_toward_floor`
/// and `reviewed_floor_override` — falls through to the `UnknownKey` arm:
/// the floor-override escape hatch is not parseable, not merely unused
/// (SPEC_USB_TRNG §8.2).
fn apply_usb_trng(
    policy: &mut Policy,
    seen: &mut UsbTrngSeen,
    key: &str,
    val: &str,
    line_no: u32,
) -> Result<(), ParseError> {
    macro_rules! scalar {
        ($field:ident, $seen_field:ident, $parser:ident) => {{
            if seen.$seen_field {
                return Err(ParseError { line: line_no, kind: ParseErrorKind::DuplicateKey });
            }
            policy.usb_trng.$field = $parser(val).map_err(|kind| ParseError { line: line_no, kind })?;
            seen.$seen_field = true;
        }};
    }
    match key {
        "approved" => scalar!(approved, approved, parse_bool),
        "sole_source_allowed" => scalar!(sole_source_allowed, sole_source_allowed, parse_bool),
        "min_read_bytes" => scalar!(min_read_bytes, min_read_bytes, parse_u16),
        "read_timeout_ms" => scalar!(read_timeout_ms, read_timeout_ms, parse_u16),
        "max_read_retries" => scalar!(max_read_retries, max_read_retries, parse_u8),
        _ => return Err(ParseError { line: line_no, kind: ParseErrorKind::UnknownKey }),
    }
    Ok(())
}

fn apply_usb_trng_device_field(
    b: &mut UsbTrngDeviceBuilder,
    key: &str,
    val: &str,
    line_no: u32,
) -> Result<(), ParseError> {
    macro_rules! scalar {
        ($field:ident, $parser:expr) => {{
            if b.$field.is_some() {
                return Err(ParseError { line: line_no, kind: ParseErrorKind::DuplicateKey });
            }
            b.$field = Some($parser(val).map_err(|kind| ParseError { line: line_no, kind })?);
        }};
    }
    match key {
        "profile" => scalar!(profile, parse_usb_trng_profile),
        "vendor_id" => scalar!(vendor_id, parse_u16),
        "product_id" => scalar!(product_id, parse_u16),
        "usb_class" => scalar!(usb_class, parse_usb_class),
        "init_command" => scalar!(init_command, parse_init_command),
        "min_firmware" => scalar!(min_firmware, parse_min_firmware),
        "reason_pinned" => scalar!(reason, parse_reason),
        _ => return Err(ParseError { line: line_no, kind: ParseErrorKind::UnknownKey }),
    }
    Ok(())
}

fn apply_cpu_rule_field(b: &mut CpuRuleBuilder, key: &str, val: &str, line_no: u32) -> Result<(), ParseError> {
    macro_rules! scalar {
        ($field:ident, $parser:expr) => {{
            if b.$field.is_some() {
                return Err(ParseError { line: line_no, kind: ParseErrorKind::DuplicateKey });
            }
            b.$field = Some($parser(val).map_err(|kind| ParseError { line: line_no, kind })?);
        }};
    }
    match key {
        "vendor" => scalar!(vendor, parse_vendor),
        "family_min" => scalar!(family_min, parse_u16),
        "family_max" => scalar!(family_max, parse_u16),
        "model_min" => scalar!(model_min, parse_u8),
        "model_max" => scalar!(model_max, parse_u8),
        "stepping_min" => scalar!(stepping_min, parse_u8),
        "stepping_max" => scalar!(stepping_max, parse_u8),
        "allow" => scalar!(allow, parse_bool),
        "min_microcode_revision" => scalar!(min_microcode_revision, parse_u32),
        _ => return Err(ParseError { line: line_no, kind: ParseErrorKind::UnknownKey }),
    }
    Ok(())
}

fn apply_denylist_field(b: &mut DenylistBuilder, key: &str, val: &str, line_no: u32) -> Result<(), ParseError> {
    macro_rules! scalar {
        ($field:ident, $parser:expr) => {{
            if b.$field.is_some() {
                return Err(ParseError { line: line_no, kind: ParseErrorKind::DuplicateKey });
            }
            b.$field = Some($parser(val).map_err(|kind| ParseError { line: line_no, kind })?);
        }};
    }
    match key {
        "vendor" => scalar!(vendor, parse_vendor),
        "family_min" => scalar!(family_min, parse_u16),
        "family_max" => scalar!(family_max, parse_u16),
        "model_min" => scalar!(model_min, parse_u8),
        "model_max" => scalar!(model_max, parse_u8),
        "stepping_min" => scalar!(stepping_min, parse_u8),
        "stepping_max" => scalar!(stepping_max, parse_u8),
        "reason" => scalar!(reason, parse_reason),
        _ => return Err(ParseError { line: line_no, kind: ParseErrorKind::UnknownKey }),
    }
    Ok(())
}

fn validate_key(key: &str) -> Option<()> {
    let mut chars = key.bytes();
    let first = chars.next()?;
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return None;
    }
    if key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        Some(())
    } else {
        None
    }
}

fn parse_bool(s: &str) -> Result<bool, ParseErrorKind> {
    match s {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(ParseErrorKind::InvalidBoolean),
    }
}

fn parse_u64(s: &str) -> Result<u64, ParseErrorKind> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ParseErrorKind::InvalidInteger);
    }
    if s.len() > 1 && s.as_bytes()[0] == b'0' {
        return Err(ParseErrorKind::InvalidInteger);
    }
    let mut v: u64 = 0;
    for b in s.bytes() {
        v = v.checked_mul(10).ok_or(ParseErrorKind::IntegerOverflow)?;
        v = v.checked_add((b - b'0') as u64).ok_or(ParseErrorKind::IntegerOverflow)?;
    }
    Ok(v)
}

fn parse_u16(s: &str) -> Result<u16, ParseErrorKind> {
    let v = parse_u64(s)?;
    u16::try_from(v).map_err(|_| ParseErrorKind::IntegerOverflow)
}

fn parse_u32(s: &str) -> Result<u32, ParseErrorKind> {
    let v = parse_u64(s)?;
    u32::try_from(v).map_err(|_| ParseErrorKind::IntegerOverflow)
}

fn parse_u8(s: &str) -> Result<u8, ParseErrorKind> {
    let v = parse_u64(s)?;
    u8::try_from(v).map_err(|_| ParseErrorKind::IntegerOverflow)
}

fn parse_string(s: &str) -> Result<&str, ParseErrorKind> {
    let b = s.as_bytes();
    if b.len() < 2 || b[0] != b'"' || b[b.len() - 1] != b'"' {
        return Err(ParseErrorKind::InvalidString);
    }
    let inner = &s[1..s.len() - 1];
    if inner.bytes().any(|c| c == b'"' || c == b'\\' || !(0x20..=0x7E).contains(&c)) {
        return Err(ParseErrorKind::InvalidString);
    }
    Ok(inner)
}

fn parse_vendor(s: &str) -> Result<Vendor, ParseErrorKind> {
    let inner = parse_string(s)?;
    Vendor::from_str(inner).ok_or(ParseErrorKind::StringTooLong)
}

fn parse_reason(s: &str) -> Result<Reason, ParseErrorKind> {
    let inner = parse_string(s)?;
    Reason::from_str(inner).ok_or(ParseErrorKind::StringTooLong)
}

/// Parses a `[[usb_trng_devices]]` `profile` value, requiring it to be one
/// of [`KNOWN_USB_TRNG_PROFILES`] (SPEC_USB_TRNG §8.2: "MUST have a
/// `profile` that resolves to a known fixed profile id... never from
/// device-supplied text").
fn parse_usb_trng_profile(s: &str) -> Result<super::types::FixedStr<{ super::types::MAX_PROFILE_LEN }>, ParseErrorKind> {
    let inner = parse_string(s)?;
    if !KNOWN_USB_TRNG_PROFILES.contains(&inner) {
        return Err(ParseErrorKind::UnknownUsbTrngProfile);
    }
    super::types::FixedStr::from_str(inner).ok_or(ParseErrorKind::StringTooLong)
}

/// Parses a `[[usb_trng_devices]]` `usb_class` value, accepting only the
/// reviewed class strings (SPEC_USB_TRNG §8.2: `hid`/input-composite are
/// not representable as an approved class — there is no [`UsbClass`]
/// variant for them, so any string other than `"cdc-acm"` is rejected
/// here, not silently mapped).
fn parse_usb_class(s: &str) -> Result<UsbClass, ParseErrorKind> {
    let inner = parse_string(s)?;
    match inner {
        "cdc-acm" => Ok(UsbClass::CdcAcm),
        _ => Err(ParseErrorKind::UnsupportedUsbClass),
    }
}

/// Parses a `[[usb_trng_devices]]` `init_command` value (SPEC_USB_TRNG
/// §8.1, e.g. `"cmd1"`).
fn parse_init_command(
    s: &str,
) -> Result<super::types::FixedStr<{ super::types::MAX_INIT_COMMAND_LEN }>, ParseErrorKind> {
    let inner = parse_string(s)?;
    super::types::FixedStr::from_str(inner).ok_or(ParseErrorKind::StringTooLong)
}

/// Parses a `[[usb_trng_devices]]` `min_firmware` value (SPEC_USB_TRNG
/// §8.1: `""` means "no constraint verified yet", a valid explicit value,
/// not an absent key).
fn parse_min_firmware(
    s: &str,
) -> Result<super::types::FixedStr<{ super::types::MAX_MIN_FIRMWARE_LEN }>, ParseErrorKind> {
    let inner = parse_string(s)?;
    super::types::FixedStr::from_str(inner).ok_or(ParseErrorKind::StringTooLong)
}

fn for_each_array_string(s: &str, mut f: impl FnMut(&str) -> Result<(), ParseErrorKind>) -> Result<(), ParseErrorKind> {
    let b = s.as_bytes();
    if b.len() < 2 || b[0] != b'[' || b[b.len() - 1] != b']' {
        return Err(ParseErrorKind::InvalidArray);
    }
    let inner = s[1..s.len() - 1].trim();
    if inner.is_empty() {
        return Ok(());
    }
    for tok in inner.split(',') {
        let tok = tok.trim();
        let content = parse_string(tok)?;
        f(content)?;
    }
    Ok(())
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use std::format;
    use std::string::String;

    const MINIMAL_VALID: &str = r#"
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
"#;

    #[test]
    fn parses_minimal_valid_policy() {
        let p = parse(MINIMAL_VALID).expect("minimal valid policy must parse");
        assert_eq!(p.version, 1);
        assert!(!p.efi_rng.approved);
        assert_eq!(p.efi_rng.max_algorithms, 8);
        assert_eq!(p.efi_rng.allowed_algorithms().len(), 0);
        assert!(p.rdseed.approved);
        assert!(p.rdseed.sole_source_allowed);
        assert_eq!(p.rdseed.instruction_width_bits, 64);
        assert_eq!(p.rdseed.retry_limit, 75);
        assert_eq!(p.rdseed.min_successful_values, 4);
        assert_eq!(p.rdseed.diagnostic_blocks, 2);
        assert!(p.rdrand.approved);
        assert!(!p.rdrand.sole_source_allowed);
        assert!(p.rdrand.supplementary_only);
        assert_eq!(p.denylist().len(), 0);
        assert!(!p.usb_trng.approved);
        assert!(!p.usb_trng.sole_source_allowed);
        assert_eq!(p.usb_trng.min_read_bytes, 32);
        assert_eq!(p.usb_trng.read_timeout_ms, 2000);
        assert_eq!(p.usb_trng.max_read_retries, 3);
        assert_eq!(p.usb_trng.devices().len(), 0);
    }

    #[test]
    fn parses_comments_and_blank_lines() {
        let src = format!("# leading comment\n\n{MINIMAL_VALID}\n# trailing comment\n");
        assert!(parse(&src).is_ok());
    }

    #[test]
    fn parses_algorithms_and_cpu_rules_and_denylist() {
        let src = r#"
policy_version = 3

[efi_rng]
approved = true
sole_source_allowed = true
max_algorithms = 4
allowed_algorithms = ["44f7b9-approved-rng", "another-algo"]

[rdseed]
approved = true
sole_source_allowed = true
instruction_width_bits = 64
retry_limit = 75
min_successful_values = 4
diagnostic_blocks = 2

[[rdseed_cpu_rules]]
vendor = "GenuineIntel"
family_min = 6
family_max = 6
model_min = 0
model_max = 255
stepping_min = 0
stepping_max = 255
allow = true

[[rdseed_cpu_rules]]
vendor = "AuthenticAMD"
family_min = 25
family_max = 25
model_min = 0
model_max = 10
stepping_min = 0
stepping_max = 255
allow = false

[rdrand]
approved = true
sole_source_allowed = false
supplementary_only = true

[usb_trng]
approved = true
sole_source_allowed = false
min_read_bytes = 32
read_timeout_ms = 2000
max_read_retries = 3

[[usb_trng_devices]]
profile = "OneRNG"
vendor_id = 7504
product_id = 24710
usb_class = "cdc-acm"
init_command = "cmd1"
min_firmware = ""
reason_pinned = "raw avalanche; reinforcement only; not sole-source"

[[denylist]]
vendor = "GenuineIntel"
family_min = 6
family_max = 6
model_min = 78
model_max = 78
stepping_min = 0
stepping_max = 0
reason = "known-bad microcode"
"#;
        let p = parse(src).expect("full-featured policy must parse");
        assert_eq!(p.version, 3);
        assert_eq!(p.efi_rng.allowed_algorithms().len(), 2);
        assert_eq!(p.efi_rng.allowed_algorithms()[0].as_str(), "44f7b9-approved-rng");
        assert!(p.efi_rng.is_algorithm_allowed("another-algo"));
        assert!(!p.efi_rng.is_algorithm_allowed("unlisted"));
        assert_eq!(p.rdseed.cpu_rules().len(), 2);
        assert!(p.rdseed.is_cpu_allowed("GenuineIntel", 6, 5, 3));
        assert!(!p.rdseed.is_cpu_allowed("AuthenticAMD", 25, 5, 0));
        assert!(!p.rdseed.is_cpu_allowed("UnknownVendor", 6, 5, 3));
        assert_eq!(p.denylist().len(), 1);
        assert!(p.is_cpu_denylisted("GenuineIntel", 6, 78, 0));
        assert!(!p.is_cpu_denylisted("GenuineIntel", 6, 79, 0));
        assert!(p.usb_trng.approved);
        assert_eq!(p.usb_trng.devices().len(), 1);
        assert_eq!(p.usb_trng.devices()[0].profile.as_str(), "OneRNG");
        assert!(p.usb_trng.is_device_allowed(7504, 24710, UsbClass::CdcAcm).is_some());
        assert!(p.usb_trng.is_device_allowed(1, 2, UsbClass::CdcAcm).is_none());
    }

    #[test]
    fn last_matching_cpu_rule_wins() {
        let src = r#"
policy_version = 1

[efi_rng]
approved = false
sole_source_allowed = false
max_algorithms = 0
allowed_algorithms = []

[rdseed]
approved = true
sole_source_allowed = true
instruction_width_bits = 64
retry_limit = 1
min_successful_values = 4
diagnostic_blocks = 2

[[rdseed_cpu_rules]]
vendor = "GenuineIntel"
family_min = 6
family_max = 6
model_min = 0
model_max = 255
stepping_min = 0
stepping_max = 255
allow = true

[[rdseed_cpu_rules]]
vendor = "GenuineIntel"
family_min = 6
family_max = 6
model_min = 78
model_max = 78
stepping_min = 0
stepping_max = 0
allow = false

[rdrand]
approved = false
sole_source_allowed = false
supplementary_only = true

[usb_trng]
approved = false
sole_source_allowed = false
min_read_bytes = 32
read_timeout_ms = 2000
max_read_retries = 3
"#;
        let p = parse(src).unwrap();
        // Broad rule allows family 6; narrower later rule overrides for the
        // specific bad model/stepping combination.
        assert!(p.rdseed.is_cpu_allowed("GenuineIntel", 6, 10, 0));
        assert!(!p.rdseed.is_cpu_allowed("GenuineIntel", 6, 78, 0));
    }

    #[test]
    fn rejects_missing_policy_version() {
        let src = MINIMAL_VALID.replacen("policy_version = 1\n", "", 1);
        let err = parse(&src).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::MissingField);
    }

    #[test]
    fn rejects_unknown_section() {
        let src = "policy_version = 1\n[bogus]\nfoo = true\n";
        let err = parse(src).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::UnknownSection);
    }

    #[test]
    fn rejects_unknown_key() {
        let src = MINIMAL_VALID.replace("max_algorithms = 8", "max_algorithms = 8\nbogus_key = 1");
        let err = parse(&src).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::UnknownKey);
    }

    #[test]
    fn rejects_duplicate_key() {
        let src = MINIMAL_VALID.replace("approved = false\n", "approved = false\napproved = true\n");
        let err = parse(&src).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::DuplicateKey);
    }

    #[test]
    fn rejects_duplicate_section() {
        let src = format!("{MINIMAL_VALID}\n[efi_rng]\napproved = true\n");
        let err = parse(&src).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::DuplicateSection);
    }

    #[test]
    fn rejects_missing_equals() {
        let src = "policy_version 1\n";
        let err = parse(src).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::ExpectedEquals);
    }

    #[test]
    fn rejects_bad_integer_forms() {
        for bad in ["01", "1.0", "-1", "1_000", "", "abc", "1a"] {
            let src = format!("policy_version = {bad}\n");
            let err = parse(&src).unwrap_err();
            assert_eq!(err.kind, ParseErrorKind::InvalidInteger, "input {bad:?} should be rejected");
        }
    }

    #[test]
    fn rejects_integer_overflow() {
        let src = MINIMAL_VALID.replace("max_algorithms = 8", "max_algorithms = 999");
        let err = parse(&src).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::IntegerOverflow);
    }

    #[test]
    fn rejects_bad_boolean() {
        let src = MINIMAL_VALID.replace("approved = false", "approved = yes");
        let err = parse(&src).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::InvalidBoolean);
    }

    #[test]
    fn rejects_string_with_escape() {
        let src = MINIMAL_VALID.replace(r#"allowed_algorithms = []"#, r#"allowed_algorithms = ["a\"b"]"#);
        let err = parse(&src).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::InvalidString);
    }

    #[test]
    fn rejects_unterminated_string_in_array() {
        let src = MINIMAL_VALID.replace(r#"allowed_algorithms = []"#, r#"allowed_algorithms = ["unterminated]"#);
        assert!(parse(&src).is_err());
    }

    #[test]
    fn rejects_trailing_comma_in_array() {
        let src = MINIMAL_VALID.replace(r#"allowed_algorithms = []"#, r#"allowed_algorithms = ["a",]"#);
        let err = parse(&src).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::InvalidString);
    }

    #[test]
    fn rejects_line_too_long() {
        let mut long = String::from("policy_version = 1");
        for _ in 0..300 {
            long.push('1');
        }
        long.push('\n');
        let err = parse(&long).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::LineTooLong);
    }

    #[test]
    fn rejects_rdrand_sole_source_allowed() {
        let src = MINIMAL_VALID.replace(
            "[rdrand]\napproved = true\nsole_source_allowed = false",
            "[rdrand]\napproved = true\nsole_source_allowed = true",
        );
        let err = parse(&src).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::RdrandSoleSourceNotAllowed);
    }

    #[test]
    fn rejects_rdrand_not_supplementary_only() {
        let src = MINIMAL_VALID.replace("supplementary_only = true", "supplementary_only = false");
        let err = parse(&src).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::RdrandMustBeSupplementaryOnly);
    }

    #[test]
    fn rejects_rdseed_non_64_bit_width() {
        let src = MINIMAL_VALID.replace("instruction_width_bits = 64", "instruction_width_bits = 32");
        let err = parse(&src).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::RdseedMustBe64Bit);
    }

    #[test]
    fn rejects_incomplete_cpu_rule_record() {
        let src = r#"
policy_version = 1

[efi_rng]
approved = false
sole_source_allowed = false
max_algorithms = 0
allowed_algorithms = []

[rdseed]
approved = true
sole_source_allowed = true
instruction_width_bits = 64
retry_limit = 1
min_successful_values = 4
diagnostic_blocks = 2

[[rdseed_cpu_rules]]
vendor = "GenuineIntel"
family_min = 6
family_max = 6

[rdrand]
approved = false
sole_source_allowed = false
supplementary_only = true
"#;
        let err = parse(src).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::MissingField);
    }

    #[test]
    fn rejects_inverted_range() {
        let src = r#"
policy_version = 1

[efi_rng]
approved = false
sole_source_allowed = false
max_algorithms = 0
allowed_algorithms = []

[rdseed]
approved = true
sole_source_allowed = true
instruction_width_bits = 64
retry_limit = 1
min_successful_values = 4
diagnostic_blocks = 2

[[rdseed_cpu_rules]]
vendor = "GenuineIntel"
family_min = 10
family_max = 6
model_min = 0
model_max = 0
stepping_min = 0
stepping_max = 0
allow = true

[rdrand]
approved = false
sole_source_allowed = false
supplementary_only = true
"#;
        let err = parse(src).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::InvalidRange);
    }

    #[test]
    fn rejects_too_many_algorithms() {
        let mut list = String::from("[");
        for i in 0..(super::super::types::MAX_ALGORITHMS + 1) {
            if i > 0 {
                list.push(',');
            }
            list.push_str(&format!("\"algo{i}\""));
        }
        list.push(']');
        let src = MINIMAL_VALID.replace("allowed_algorithms = []", &format!("allowed_algorithms = {list}"));
        let err = parse(&src).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::TooManyAlgorithms);
    }

    #[test]
    fn rejects_string_too_long_for_vendor() {
        let src = r#"
policy_version = 1

[efi_rng]
approved = false
sole_source_allowed = false
max_algorithms = 0
allowed_algorithms = []

[rdseed]
approved = true
sole_source_allowed = true
instruction_width_bits = 64
retry_limit = 1
min_successful_values = 4
diagnostic_blocks = 2

[[rdseed_cpu_rules]]
vendor = "ThisVendorStringIsWayTooLongForTheFixedBuffer"
family_min = 0
family_max = 0
model_min = 0
model_max = 0
stepping_min = 0
stepping_max = 0
allow = true

[rdrand]
approved = false
sole_source_allowed = false
supplementary_only = true
"#;
        let err = parse(src).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::StringTooLong);
    }

    /// Regression test (SPEC §15: "Required microcode or firmware
    /// conditions where known"): the optional `min_microcode_revision` key
    /// on `[[rdseed_cpu_rules]]` must parse and be attached to the built
    /// `CpuRule`, and remain `None` when the key is absent from a record.
    #[test]
    fn parses_optional_min_microcode_revision() {
        let src = r#"
policy_version = 1

[efi_rng]
approved = false
sole_source_allowed = false
max_algorithms = 0
allowed_algorithms = []

[rdseed]
approved = true
sole_source_allowed = true
instruction_width_bits = 64
retry_limit = 1
min_successful_values = 4
diagnostic_blocks = 2

[[rdseed_cpu_rules]]
vendor = "GenuineIntel"
family_min = 6
family_max = 6
model_min = 0
model_max = 255
stepping_min = 0
stepping_max = 255
allow = true
min_microcode_revision = 42

[[rdseed_cpu_rules]]
vendor = "AuthenticAMD"
family_min = 25
family_max = 25
model_min = 0
model_max = 255
stepping_min = 0
stepping_max = 255
allow = true

[rdrand]
approved = false
sole_source_allowed = false
supplementary_only = true

[usb_trng]
approved = false
sole_source_allowed = false
min_read_bytes = 32
read_timeout_ms = 2000
max_read_retries = 3
"#;
        let p = parse(src).expect("optional min_microcode_revision must parse");
        assert_eq!(p.rdseed.cpu_rules()[0].min_microcode_revision, Some(42));
        assert_eq!(p.rdseed.cpu_rules()[1].min_microcode_revision, None);
    }

    /// Regression test: `min_microcode_revision` participates in the same
    /// duplicate-key and integer-overflow validation as every other scalar
    /// field, since it reuses the shared field-parsing machinery.
    #[test]
    fn rejects_duplicate_min_microcode_revision() {
        let src = r#"
policy_version = 1

[efi_rng]
approved = false
sole_source_allowed = false
max_algorithms = 0
allowed_algorithms = []

[rdseed]
approved = true
sole_source_allowed = true
instruction_width_bits = 64
retry_limit = 1
min_successful_values = 4
diagnostic_blocks = 2

[[rdseed_cpu_rules]]
vendor = "GenuineIntel"
family_min = 6
family_max = 6
model_min = 0
model_max = 0
stepping_min = 0
stepping_max = 0
allow = true
min_microcode_revision = 1
min_microcode_revision = 2

[rdrand]
approved = false
sole_source_allowed = false
supplementary_only = true
"#;
        let err = parse(src).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::DuplicateKey);
    }

    // -----------------------------------------------------------------------
    // USB TRNG (SPEC_USB_TRNG §8) — adversarial "floor-loophole rejected"
    // tests and the rest of the §8.2 parser hard-rule coverage.
    // -----------------------------------------------------------------------

    /// Adversarial regression (SPEC_USB_TRNG §8.2, §10.2 rule 4 — the
    /// mandatory floor-loophole test): `counts_toward_floor` is not a
    /// recognized key anywhere in this schema. A policy file that sets it
    /// MUST be rejected as `UnknownKey` — the escape hatch from the SPEC
    /// §17.2 witnessed floor is not even expressible, mirroring the
    /// absolute `[rdrand] sole_source_allowed` guard which also has no
    /// override key.
    #[test]
    fn rejects_usb_trng_counts_toward_floor_key() {
        let src = MINIMAL_VALID.replace(
            "[usb_trng]\napproved = false",
            "[usb_trng]\napproved = false\ncounts_toward_floor = true",
        );
        let err = parse(&src).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::UnknownKey);
    }

    /// Adversarial regression (SPEC_USB_TRNG §8.2): `reviewed_floor_override`
    /// — the earlier draft's alternate spelling of the same loophole — is
    /// equally unparseable, and for the same reason (not in the fixed key
    /// set, so it falls to the same `UnknownKey` arm as any other typo).
    #[test]
    fn rejects_usb_trng_reviewed_floor_override_key() {
        let src = MINIMAL_VALID.replace(
            "[usb_trng]\napproved = false",
            "[usb_trng]\napproved = false\nreviewed_floor_override = true",
        );
        let err = parse(&src).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::UnknownKey);
    }

    /// SPEC_USB_TRNG §8.2: "`usb_class` MUST be one of the reviewed class
    /// enum values; `hid`... [is] not representable as an approved class."
    #[test]
    fn rejects_usb_trng_hid_class() {
        let device = r#"
[[usb_trng_devices]]
profile = "OneRNG"
vendor_id = 7504
product_id = 24710
usb_class = "hid"
init_command = "cmd1"
min_firmware = ""
reason_pinned = "test"
"#;
        let src = format!("{MINIMAL_VALID}\n{device}");
        let err = parse(&src).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::UnsupportedUsbClass);
    }

    /// SPEC_USB_TRNG §8.2: "any composite-with-input class" is equally
    /// unrepresentable — there is no enum variant to select regardless of
    /// what string names it.
    #[test]
    fn rejects_usb_trng_composite_input_class() {
        let device = r#"
[[usb_trng_devices]]
profile = "OneRNG"
vendor_id = 7504
product_id = 24710
usb_class = "composite-hid"
init_command = "cmd1"
min_firmware = ""
reason_pinned = "test"
"#;
        let src = format!("{MINIMAL_VALID}\n{device}");
        let err = parse(&src).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::UnsupportedUsbClass);
    }

    /// SPEC_USB_TRNG §8.2: "Every `[[usb_trng_devices]]` entry MUST have a
    /// `profile` that resolves to a known fixed profile id" — an unreviewed
    /// profile string is rejected, never accepted as free text.
    #[test]
    fn rejects_unknown_usb_trng_profile() {
        let device = r#"
[[usb_trng_devices]]
profile = "TotallyUnreviewedDevice"
vendor_id = 1
product_id = 2
usb_class = "cdc-acm"
init_command = "cmd1"
min_firmware = ""
reason_pinned = "test"
"#;
        let src = format!("{MINIMAL_VALID}\n{device}");
        let err = parse(&src).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::UnknownUsbTrngProfile);
    }

    /// SPEC_USB_TRNG §8.3: `sole_source_allowed = true` is a plain bool
    /// modelled on `[efi_rng]`, "not a bespoke double-key override" — it
    /// MUST parse (it is a documented reviewer act, not a syntax error).
    /// This is the positive counterpart to the floor-loophole tests above:
    /// the *floor* has no escape hatch, but sole-source participation is a
    /// legitimate, reviewable flag.
    #[test]
    fn parses_usb_trng_sole_source_allowed_true() {
        let src = MINIMAL_VALID.replace(
            "[usb_trng]\napproved = false\nsole_source_allowed = false",
            "[usb_trng]\napproved = true\nsole_source_allowed = true",
        );
        let p = parse(&src).expect("sole_source_allowed = true is a documented reviewer act, not a parse error");
        assert!(p.usb_trng.approved);
        assert!(p.usb_trng.sole_source_allowed);
    }

    /// SPEC_USB_TRNG §8.2: "`min_read_bytes` MUST be ≥ the health-check
    /// block size" — below the reviewed floor is rejected.
    #[test]
    fn rejects_usb_trng_min_read_bytes_too_small() {
        let src = MINIMAL_VALID.replace("min_read_bytes = 32", "min_read_bytes = 8");
        let err = parse(&src).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::UsbTrngMinReadBytesOutOfRange);
    }

    /// SPEC_USB_TRNG §8.2: "...and ≤ `MAX_USB_TRNG_READ_BYTES` (32)" —
    /// above the USB one-block cap is rejected.
    #[test]
    fn rejects_usb_trng_min_read_bytes_too_large() {
        let src = MINIMAL_VALID.replace("min_read_bytes = 32", "min_read_bytes = 33");
        let err = parse(&src).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::UsbTrngMinReadBytesOutOfRange);
    }

    /// SPEC_USB_TRNG §8.1: the `[[usb_trng_devices]]` allow-list is capacity-
    /// bounded like every other policy array (`MAX_USB_TRNG_DEVICES`).
    #[test]
    fn rejects_too_many_usb_trng_devices() {
        let mut devices = String::new();
        for i in 0..(super::super::types::MAX_USB_TRNG_DEVICES + 1) {
            devices.push_str(&format!(
                "\n[[usb_trng_devices]]\nprofile = \"OneRNG\"\nvendor_id = {i}\nproduct_id = {i}\nusb_class = \"cdc-acm\"\ninit_command = \"cmd1\"\nmin_firmware = \"\"\nreason_pinned = \"test\"\n"
            ));
        }
        let src = format!("{MINIMAL_VALID}\n{devices}");
        let err = parse(&src).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::TooManyUsbTrngDevices);
    }

    /// `[usb_trng]` is a required top-level section, exactly like
    /// `[efi_rng]`/`[rdseed]`/`[rdrand]` — an entropy policy that omits it
    /// entirely is incomplete, not implicitly unapproved.
    #[test]
    fn rejects_missing_usb_trng_section() {
        let src = MINIMAL_VALID.replace(
            "\n[usb_trng]\napproved = false\nsole_source_allowed = false\nmin_read_bytes = 32\nread_timeout_ms = 2000\nmax_read_retries = 3\n",
            "\n",
        );
        assert!(!src.contains("[usb_trng]"), "test setup must actually remove the section");
        let err = parse(&src).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::MissingField);
    }

    /// `[usb_trng]` participates in the same duplicate-section guard as
    /// every other fixed section.
    #[test]
    fn rejects_duplicate_usb_trng_section() {
        let src = format!("{MINIMAL_VALID}\n[usb_trng]\napproved = true\n");
        let err = parse(&src).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::DuplicateSection);
    }

    /// A `[[usb_trng_devices]]` record participates in the same
    /// duplicate-key guard as every other array-record section.
    #[test]
    fn rejects_duplicate_key_in_usb_trng_device() {
        let device = r#"
[[usb_trng_devices]]
profile = "OneRNG"
profile = "OneRNG"
vendor_id = 7504
product_id = 24710
usb_class = "cdc-acm"
init_command = "cmd1"
min_firmware = ""
reason_pinned = "test"
"#;
        let src = format!("{MINIMAL_VALID}\n{device}");
        let err = parse(&src).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::DuplicateKey);
    }

    /// An incomplete `[[usb_trng_devices]]` record (missing a required
    /// field) is rejected as `MissingField`, exactly like an incomplete
    /// `[[rdseed_cpu_rules]]`/`[[denylist]]` record.
    #[test]
    fn rejects_incomplete_usb_trng_device_record() {
        let device = r#"
[[usb_trng_devices]]
profile = "OneRNG"
vendor_id = 7504
"#;
        let src = format!("{MINIMAL_VALID}\n{device}");
        let err = parse(&src).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::MissingField);
    }

    /// SPEC_USB_TRNG §6.1: "no untrusted, device-supplied descriptor string
    /// is ever mixed into the transcript" — `is_device_allowed` is
    /// default-deny (unapproved policy never matches) and exact-match
    /// (no VID/PID prefix or wildcard matching).
    #[test]
    fn usb_trng_is_device_allowed_is_default_deny_and_exact_match() {
        let device = r#"
[[usb_trng_devices]]
profile = "OneRNG"
vendor_id = 7504
product_id = 24710
usb_class = "cdc-acm"
init_command = "cmd1"
min_firmware = ""
reason_pinned = "test"
"#;
        // Unapproved overall: even an exact VID/PID/class match is denied.
        let unapproved = format!("{MINIMAL_VALID}\n{device}");
        let p = parse(&unapproved).expect("valid device record must parse");
        assert!(!p.usb_trng.approved);
        assert!(p.usb_trng.is_device_allowed(7504, 24710, UsbClass::CdcAcm).is_none());

        // Approved, exact match: allowed.
        let approved = unapproved.replace("[usb_trng]\napproved = false", "[usb_trng]\napproved = true");
        let p = parse(&approved).expect("valid device record must parse");
        assert!(p.usb_trng.approved);
        let matched =
            p.usb_trng.is_device_allowed(7504, 24710, UsbClass::CdcAcm).expect("exact VID/PID/class must match");
        assert_eq!(matched.profile.as_str(), "OneRNG");
        // A near-miss VID is not the same device.
        assert!(p.usb_trng.is_device_allowed(7505, 24710, UsbClass::CdcAcm).is_none());
    }

    #[test]
    fn accepts_shipped_v1_policy_file() {
        let src = include_str!("../../../../entropy-policy.toml");
        let p = parse(src).expect("shipped v1 policy must parse and validate");
        assert_eq!(p.version, 1);
        assert!(p.rdseed.approved);
        assert!(p.rdseed.sole_source_allowed);
        assert!(p.rdrand.approved);
        assert!(!p.rdrand.sole_source_allowed);
        assert!(p.rdrand.supplementary_only);
        assert_eq!(p.denylist().len(), 0, "v1 denylist is an empty scaffold");
        assert!(!p.usb_trng.approved, "v1 usb_trng is unapproved by default (SPEC_USB_TRNG §8.1)");
        assert_eq!(p.usb_trng.devices().len(), 0, "v1 usb_trng_devices is an empty scaffold");
    }
}
