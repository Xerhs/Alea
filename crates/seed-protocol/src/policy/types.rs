//! Policy data model (WP-12, SPEC §15).
//!
//! Plain-data, non-secret descriptors produced by [`super::parse`]. None of
//! these types carry secret material, so ordinary derives
//! (`Debug`/`Clone`/`Copy`/`PartialEq`) are fine (SPEC §13/§20 only
//! restrict *secret-bearing* types).

/// Maximum number of `allowed_algorithms` entries under `[efi_rng]`
/// (SPEC §15.1: "reject an algorithm list larger than the reviewed
/// maximum").
pub const MAX_ALGORITHMS: usize = 16;

/// Maximum byte length of one algorithm identifier string (matches
/// `seed_core::contracts::MAX_ALGO_ID`, kept as a local constant so this
/// crate does not need a contract change to stay in sync — both are
/// derived from the same "EFI RNG algorithm GUID rendered as text" bound).
pub const MAX_ALGO_ID_LEN: usize = 32;

/// Maximum byte length of a CPUID vendor-ID string (`"GenuineIntel"`,
/// `"AuthenticAMD"` are both 12 ASCII bytes; this is the fixed CPUID
/// vendor-string length).
pub const MAX_VENDOR_LEN: usize = 12;

/// Maximum byte length of a free-text denylist `reason` field.
pub const MAX_REASON_LEN: usize = 64;

/// Maximum number of `[[rdseed_cpu_rules]]` records.
pub const MAX_CPU_RULES: usize = 16;

/// Maximum number of `[[denylist]]` records.
pub const MAX_DENYLIST_ENTRIES: usize = 16;

/// Maximum number of `[[usb_trng_devices]]` allow-list records
/// (SPEC_USB_TRNG §8.1: "Zero or more explicitly reviewed devices").
/// Sized like [`MAX_DENYLIST_ENTRIES`] — a small, hand-reviewed set, not an
/// open registry.
pub const MAX_USB_TRNG_DEVICES: usize = 16;

/// Maximum byte length of a `[[usb_trng_devices]]` `profile` string
/// (SPEC_USB_TRNG §8.1/§8.2: a fixed profile id, e.g. `"OneRNG"`, drawn from
/// [`KNOWN_USB_TRNG_PROFILES`]).
pub const MAX_PROFILE_LEN: usize = 32;

/// Maximum byte length of a `[[usb_trng_devices]]` `init_command` string
/// (SPEC_USB_TRNG §8.1: e.g. `"cmd1"`).
pub const MAX_INIT_COMMAND_LEN: usize = 16;

/// Maximum byte length of a `[[usb_trng_devices]]` `min_firmware` string
/// (SPEC_USB_TRNG §8.1: `""` = no constraint verified yet).
pub const MAX_MIN_FIRMWARE_LEN: usize = 32;

/// The fixed table of known USB-TRNG device profile ids (SPEC_USB_TRNG
/// §5.1, §8.2: "Every `[[usb_trng_devices]]` entry MUST have a `profile`
/// that resolves to a known fixed profile id"). A `profile` string not in
/// this table is rejected by the parser — there is no free-text/wildcard
/// profile. `"OneRNG"` is the only v1 entry (SPEC_USB_TRNG §5.1: "the most
/// UEFI-tractable target").
pub const KNOWN_USB_TRNG_PROFILES: &[&str] = &["OneRNG"];

/// Lower bound on `[usb_trng] min_read_bytes` (SPEC_USB_TRNG §8.2:
/// "`min_read_bytes` MUST be ≥ the health-check block size"). Reviewed
/// floor below which the catastrophic degenerate/repeated-block checks
/// (SPEC_USB_TRNG §9) are not statistically meaningful. This is a
/// policy-crate-local constant — `seed-platform-x86` (which owns the
/// driver's own block-size constant) depends on `seed-protocol`, not the
/// other way around, so the two are not literally the same `const`, only
/// reviewed to the same value.
pub const MIN_USB_TRNG_READ_BYTES: u16 = 16;

/// Upper bound on `[usb_trng] min_read_bytes` (SPEC_USB_TRNG §8.2: "and ≤
/// 32 bytes"). A USB-TRNG source record is one health-checked 256-bit
/// block = 32 bytes (SPEC_USB_TRNG §6.1). This is deliberately its own
/// reviewed literal rather than a mirror of
/// `seed_core::contracts::MAX_MACHINE_SOURCE_BYTES`: that shared per-record
/// transcript cap rose to 64 for audit finding L2 (the RDSEED64 record now
/// carries two 256-bit blocks), but a USB-TRNG read is still a single
/// block, so its policy ceiling stays pinned at 32 — exactly as
/// `MIN_USB_TRNG_READ_BYTES` above is its own reviewed literal, not a
/// mirror.
pub const MAX_USB_TRNG_READ_BYTES: u16 = 32;

/// A fixed-capacity, stack-allocated ASCII string (no alloc).
///
/// Only `bytes[..len]` is meaningful; `bytes[len..]` is unspecified
/// padding. Content is validated printable-ASCII (`0x20..=0x7E`) by the
/// parser before construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedStr<const N: usize> {
    bytes: [u8; N],
    len: u8,
}

impl<const N: usize> FixedStr<N> {
    /// An empty string.
    pub const fn empty() -> Self {
        Self { bytes: [0u8; N], len: 0 }
    }

    /// Build from a `&str` already known to fit and be printable ASCII.
    /// Returns `None` if `s` does not fit in `N` bytes.
    pub fn from_str(s: &str) -> Option<Self> {
        let b = s.as_bytes();
        if b.len() > N {
            return None;
        }
        let mut bytes = [0u8; N];
        bytes[..b.len()].copy_from_slice(b);
        Some(Self { bytes, len: b.len() as u8 })
    }

    /// The string content.
    pub fn as_str(&self) -> &str {
        // SAFETY-free: constructed only from validated ASCII, `unwrap_or`
        // guards against any future misuse rather than panicking.
        core::str::from_utf8(&self.bytes[..self.len as usize]).unwrap_or("")
    }
}

/// One algorithm identifier (SPEC §15.1).
pub type AlgoId = FixedStr<MAX_ALGO_ID_LEN>;

/// One CPUID vendor-ID string (SPEC §15.2).
pub type Vendor = FixedStr<MAX_VENDOR_LEN>;

/// One denylist free-text reason (SPEC §15).
pub type Reason = FixedStr<MAX_REASON_LEN>;

/// A CPU vendor/family/model/stepping range rule (SPEC §15: "CPU vendor,
/// family, model and stepping rules").
///
/// `family`/`model`/`stepping` are matched as inclusive `[min, max]`
/// ranges so one record can cover a run of steppings/models without a
/// combinatorial explosion of single-value entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuRange {
    /// CPUID vendor-ID string, e.g. `"GenuineIntel"`.
    pub vendor: Vendor,
    /// Inclusive CPU family range, lower bound.
    pub family_min: u16,
    /// Inclusive CPU family range, upper bound.
    pub family_max: u16,
    /// Inclusive CPU model range, lower bound.
    pub model_min: u8,
    /// Inclusive CPU model range, upper bound.
    pub model_max: u8,
    /// Inclusive CPU stepping range, lower bound.
    pub stepping_min: u8,
    /// Inclusive CPU stepping range, upper bound.
    pub stepping_max: u8,
}

impl CpuRange {
    /// Whether `(vendor, family, model, stepping)` falls inside this
    /// range. Vendor comparison is exact-match (SPEC §15.2: "identify CPU
    /// vendor, family, model and stepping").
    pub fn matches(&self, vendor: &str, family: u16, model: u8, stepping: u8) -> bool {
        self.vendor.as_str() == vendor
            && family >= self.family_min
            && family <= self.family_max
            && model >= self.model_min
            && model <= self.model_max
            && stepping >= self.stepping_min
            && stepping <= self.stepping_max
    }
}

/// A CPU allow-rule attached to `[[rdseed_cpu_rules]]` (SPEC §15.2:
/// "apply the compiled-in errata and denylist policy").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuRule {
    /// The vendor/family/model/stepping range this rule covers.
    pub range: CpuRange,
    /// Whether processors in this range are allowed to use RDSEED.
    pub allow: bool,
    /// Required minimum microcode revision for this rule to grant RDSEED
    /// approval, when a required revision is known (SPEC §15: "Required
    /// microcode or firmware conditions where known"; SPEC §15.2: the
    /// RDSEED driver must "record microcode revision where safely
    /// available"). `None` means this rule has no microcode condition
    /// attached. When `Some(min_rev)`, a platform whose current microcode
    /// revision is unknown (not safely readable) or below `min_rev` does
    /// NOT satisfy this rule — see [`RdseedPolicy::is_cpu_allowed_with_microcode`].
    pub min_microcode_revision: Option<u32>,
}

/// A known-bad-platform denylist entry (SPEC §15: "Known-bad platform
/// denylist entries"). Empty in the shipped v1 policy (scaffold only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DenylistEntry {
    /// The vendor/family/model/stepping range being denylisted.
    pub range: CpuRange,
    /// Human-readable reason, never shown as a security proof.
    pub reason: Reason,
}

/// `[efi_rng]` section (SPEC §15.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EfiRngPolicy {
    /// Whether `EFI_RNG_PROTOCOL` may be used at all.
    pub approved: bool,
    /// Whether an approved EFI RNG algorithm may be the sole machine
    /// source (SPEC §15.1: "approved as a sole machine source only when
    /// the compiled-in policy says so").
    pub sole_source_allowed: bool,
    /// Reviewed maximum algorithm-list length (SPEC §15.1: "reject an
    /// algorithm list larger than the reviewed maximum"). Enforced by the
    /// EFI RNG driver (WP-24), recorded here as policy data.
    pub max_algorithms: u8,
    /// Explicitly approved algorithm identifiers (SPEC §15.1: "explicit
    /// approved algorithm rather than an ambiguous default"; "unknown and
    /// vendor-specific algorithms as unapproved unless the policy
    /// explicitly allows them").
    allowed_algorithms: [AlgoId; MAX_ALGORITHMS],
    /// Number of valid entries in `allowed_algorithms`.
    allowed_algorithms_len: u8,
}

impl EfiRngPolicy {
    pub(super) fn empty() -> Self {
        Self {
            approved: false,
            sole_source_allowed: false,
            max_algorithms: 0,
            allowed_algorithms: [AlgoId::empty(); MAX_ALGORITHMS],
            allowed_algorithms_len: 0,
        }
    }

    pub(super) fn push_algorithm(&mut self, id: AlgoId) -> Result<(), ()> {
        let i = self.allowed_algorithms_len as usize;
        if i >= MAX_ALGORITHMS {
            return Err(());
        }
        self.allowed_algorithms[i] = id;
        self.allowed_algorithms_len += 1;
        Ok(())
    }

    /// The approved algorithm identifiers as a slice.
    pub fn allowed_algorithms(&self) -> &[AlgoId] {
        &self.allowed_algorithms[..self.allowed_algorithms_len as usize]
    }

    /// Whether `id` is explicitly present in `allowed_algorithms`
    /// (SPEC §15.1: unknown/unlisted algorithms are unapproved).
    pub fn is_algorithm_allowed(&self, id: &str) -> bool {
        self.approved && self.allowed_algorithms().iter().any(|a| a.as_str() == id)
    }
}

/// `[rdseed]` section (SPEC §15.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RdseedPolicy {
    /// Whether RDSEED64 may be used at all.
    pub approved: bool,
    /// Whether RDSEED may be the sole machine source
    /// (SPEC §15.2/§15: "stand alone or is supplementary only").
    pub sole_source_allowed: bool,
    /// Required instruction width in bits. Version 1 MUST be `64`
    /// (SPEC §15.2: "only the 64-bit form of RDSEED").
    pub instruction_width_bits: u16,
    /// Bounded retry limit per value (SPEC §15.2: "use bounded retries").
    pub retry_limit: u16,
    /// Minimum successful 64-bit values required per 256-bit source
    /// record (SPEC §15.2: "at least four successful 64-bit values").
    pub min_successful_values: u8,
    /// Number of separate 256-bit diagnostic blocks collected for the
    /// catastrophic-repetition check (SPEC §15.2: "two separate 256-bit
    /// diagnostic blocks").
    pub diagnostic_blocks: u8,
    cpu_rules: [CpuRule; MAX_CPU_RULES],
    cpu_rules_len: u8,
}

impl RdseedPolicy {
    pub(super) fn empty() -> Self {
        Self {
            approved: false,
            sole_source_allowed: false,
            instruction_width_bits: 0,
            retry_limit: 0,
            min_successful_values: 0,
            diagnostic_blocks: 0,
            cpu_rules: [CpuRule {
                range: CpuRange {
                    vendor: Vendor::empty(),
                    family_min: 0,
                    family_max: 0,
                    model_min: 0,
                    model_max: 0,
                    stepping_min: 0,
                    stepping_max: 0,
                },
                allow: false,
                min_microcode_revision: None,
            }; MAX_CPU_RULES],
            cpu_rules_len: 0,
        }
    }

    pub(super) fn push_cpu_rule(&mut self, rule: CpuRule) -> Result<(), ()> {
        let i = self.cpu_rules_len as usize;
        if i >= MAX_CPU_RULES {
            return Err(());
        }
        self.cpu_rules[i] = rule;
        self.cpu_rules_len += 1;
        Ok(())
    }

    /// The configured CPU allow-rules as a slice.
    pub fn cpu_rules(&self) -> &[CpuRule] {
        &self.cpu_rules[..self.cpu_rules_len as usize]
    }

    /// Whether `(vendor, family, model, stepping)` is allowed to use
    /// RDSEED under this policy: approved overall, matches at least one
    /// rule, and the *last* matching rule says `allow = true`
    /// (last-match-wins lets a later, narrower rule override an earlier
    /// broad one — SPEC §15.2: "refuse RDSEED approval on unknown or
    /// denylisted processor combinations", i.e. default is deny).
    ///
    /// INFO-3: this mechanism is default-deny, but the SHIPPED v1
    /// `entropy-policy.toml` deliberately supplies an allow-all rule for
    /// any GenuineIntel/AuthenticAMD part with an empty denylist (release
    /// scaffolding, not an oversight). Because CPUID vendor/family/model/
    /// stepping is CPU/hypervisor-reported and spoofable under
    /// virtualization, in v1 this gate constrains little beyond the vendor
    /// string + the RDSEED feature bit; the honest backstop is that RDSEED
    /// is machine-only entropy, gated behind the SPEC §18.2 machine-only
    /// warning. See the note by the allow-rules in `entropy-policy.toml`.
    pub fn is_cpu_allowed(&self, vendor: &str, family: u16, model: u8, stepping: u8) -> bool {
        if !self.approved {
            return false;
        }
        let mut allowed = false;
        let mut matched = false;
        for rule in self.cpu_rules() {
            if rule.range.matches(vendor, family, model, stepping) {
                matched = true;
                allowed = rule.allow;
            }
        }
        matched && allowed
    }

    /// As [`Self::is_cpu_allowed`], but additionally enforces each matching
    /// rule's [`CpuRule::min_microcode_revision`] condition (SPEC §15:
    /// "Required microcode or firmware conditions where known"; SPEC
    /// §15.2: "apply the compiled-in errata and denylist policy" plus "record
    /// microcode revision where safely available").
    ///
    /// `current_microcode_revision` is the platform's actual microcode
    /// revision, or `None` when the driver could not safely read it. A
    /// rule that requires a minimum revision is *not* satisfied when the
    /// current revision is unknown — an unreadable microcode revision
    /// fails safe (denied), it never silently skips the check. Rules
    /// without a microcode condition (`min_microcode_revision: None`)
    /// behave exactly as in [`Self::is_cpu_allowed`]. Last-match-wins, as
    /// in [`Self::is_cpu_allowed`].
    pub fn is_cpu_allowed_with_microcode(
        &self,
        vendor: &str,
        family: u16,
        model: u8,
        stepping: u8,
        current_microcode_revision: Option<u32>,
    ) -> bool {
        if !self.approved {
            return false;
        }
        let mut allowed = false;
        let mut matched = false;
        for rule in self.cpu_rules() {
            if rule.range.matches(vendor, family, model, stepping) {
                matched = true;
                allowed = rule.allow && microcode_requirement_met(rule.min_microcode_revision, current_microcode_revision);
            }
        }
        matched && allowed
    }
}

/// Whether `current` satisfies a rule's `required` minimum microcode
/// revision (SPEC §15, §15.2). `required = None` means the rule has no
/// condition, always satisfied. `required = Some(min_rev)` with an unknown
/// `current` (`None`) fails safe: not satisfied.
fn microcode_requirement_met(required: Option<u32>, current: Option<u32>) -> bool {
    match required {
        None => true,
        Some(min_rev) => matches!(current, Some(rev) if rev >= min_rev),
    }
}

/// `[rdrand]` section (SPEC §15.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RdrandPolicy {
    /// Whether RDRAND may be sampled at all (supplementary tag only).
    pub approved: bool,
    /// MUST be `false` in every valid version-1 policy (SPEC §15.3:
    /// "MUST NOT enable machine-only generation by itself"). The parser
    /// rejects a policy file that sets this `true`.
    pub sole_source_allowed: bool,
    /// MUST be `true` in every valid version-1 policy (SPEC §15.3:
    /// "RDRAND is supplementary only in version 1"). The parser rejects a
    /// policy file that sets this `false`.
    pub supplementary_only: bool,
}

impl RdrandPolicy {
    pub(super) fn empty() -> Self {
        Self { approved: false, sole_source_allowed: false, supplementary_only: true }
    }
}

/// The reviewed USB interface-class values a `[[usb_trng_devices]]` entry
/// may declare (SPEC_USB_TRNG §8.2: "`usb_class` MUST be one of the
/// reviewed class enum values; `hid` and any composite-with-input class are
/// **not** representable as an approved class").
///
/// This enum is deliberately closed to one variant in v1: there is no
/// `Hid`/input-composite variant to select, so a policy file cannot express
/// an approved input-capable USB device no matter what string it spells —
/// the parser maps every recognized `usb_class` string onto a variant of
/// this enum, and an unrecognized or disallowed string is a parse rejection
/// (SPEC_USB_TRNG §7.4, §9: "an input interface since enumeration →
/// refuse").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbClass {
    /// USB CDC-ACM (virtual serial), the OneRNG interface class
    /// (SPEC_USB_TRNG §5.1, §5.5).
    CdcAcm,
}

/// One reviewed `[[usb_trng_devices]]` allow-list entry (SPEC_USB_TRNG
/// §8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsbTrngDevice {
    /// Fixed device-profile id (SPEC_USB_TRNG §6.1: drives the transcript
    /// `algo_id`, e.g. `"USB-TRNG/OneRNG/cmd1"`, never a device-supplied
    /// string). Validated at parse time to be one of
    /// [`KNOWN_USB_TRNG_PROFILES`].
    pub profile: FixedStr<MAX_PROFILE_LEN>,
    /// USB vendor id this entry matches exactly (SPEC_USB_TRNG §8.1:
    /// `vendor_id = 0x1d50` for OneRNG).
    pub vendor_id: u16,
    /// USB product id this entry matches exactly (SPEC_USB_TRNG §8.1:
    /// `product_id = 0x6086` for OneRNG).
    pub product_id: u16,
    /// Expected USB interface class (SPEC_USB_TRNG §7.4, §9: re-verified at
    /// read time, not just at enumeration).
    pub usb_class: UsbClass,
    /// Device init/feed-start command (SPEC_USB_TRNG §5.1, §9: e.g.
    /// `"cmd1"` for raw avalanche).
    pub init_command: FixedStr<MAX_INIT_COMMAND_LEN>,
    /// Minimum reviewed firmware version, or empty for "no constraint
    /// verified yet" (SPEC_USB_TRNG §8.1: an empty string means the device
    /// stays off until a firmware floor is reviewed and recorded).
    pub min_firmware: FixedStr<MAX_MIN_FIRMWARE_LEN>,
    /// Human-readable, non-normative reviewer note (SPEC_USB_TRNG §8.1
    /// `reason_pinned`), never shown as a security proof.
    pub reason: Reason,
}

/// `[usb_trng]` section (SPEC_USB_TRNG §8.1, §8.2).
///
/// There is deliberately **no `counts_toward_floor` field** — a USB TRNG
/// contributes zero counted bits toward the SPEC §17.2 witnessed floor
/// unconditionally, and no compiled-in policy file can express otherwise
/// (SPEC_USB_TRNG §8.2, §10.2 rule 4). This mirrors the absolute
/// `[rdrand] sole_source_allowed` guard in `parser.rs`, which has no
/// override key either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsbTrngPolicy {
    /// Whether a USB TRNG may be used at all (SPEC_USB_TRNG §8.1: SHIP
    /// DEFAULT `false`, like `[efi_rng]`).
    pub approved: bool,
    /// Whether an allow-listed USB TRNG may participate in machine-only
    /// (sole-source) generation. A **plain bool modelled on `[efi_rng]`**
    /// (SPEC_USB_TRNG §8.3) — not a bespoke double-key override. Default
    /// `false`. Even when `true`, SPEC_USB_TRNG §7.1 requires the
    /// substitutable first-phase read path to fail closed for sole-source
    /// regardless of this flag; that gate lives in the driver (WP-U3/U4),
    /// not here.
    pub sole_source_allowed: bool,
    /// Minimum bytes a read must return to pass the length health check
    /// (SPEC_USB_TRNG §8.1, §9: "short read / length mismatch... fail").
    pub min_read_bytes: u16,
    /// Bounded per-read timeout in milliseconds (SPEC_USB_TRNG §8.1, §9:
    /// "a bulk transfer timeout... fail").
    pub read_timeout_ms: u16,
    /// Bounded retry budget; exhaustion is a hard fail, never a silent
    /// substitution (SPEC_USB_TRNG §8.1, §9).
    pub max_read_retries: u8,
    devices: [UsbTrngDevice; MAX_USB_TRNG_DEVICES],
    devices_len: usize,
}

impl UsbTrngPolicy {
    pub(super) fn empty() -> Self {
        Self {
            approved: false,
            sole_source_allowed: false,
            min_read_bytes: 0,
            read_timeout_ms: 0,
            max_read_retries: 0,
            devices: [UsbTrngDevice {
                profile: FixedStr::empty(),
                vendor_id: 0,
                product_id: 0,
                usb_class: UsbClass::CdcAcm,
                init_command: FixedStr::empty(),
                min_firmware: FixedStr::empty(),
                reason: Reason::empty(),
            }; MAX_USB_TRNG_DEVICES],
            devices_len: 0,
        }
    }

    pub(super) fn push_device(&mut self, device: UsbTrngDevice) -> Result<(), ()> {
        let i = self.devices_len;
        if i >= MAX_USB_TRNG_DEVICES {
            return Err(());
        }
        self.devices[i] = device;
        self.devices_len += 1;
        Ok(())
    }

    /// The configured device allow-list entries as a slice.
    pub fn devices(&self) -> &[UsbTrngDevice] {
        &self.devices[..self.devices_len]
    }

    /// Whether `(vendor_id, product_id, usb_class)` matches an allow-listed,
    /// approved device (SPEC_USB_TRNG §8.1: the USB analog of
    /// `RdseedPolicy::is_cpu_allowed` — default-deny, exact match). Returns
    /// the matched entry (its `profile` is what the driver uses to derive
    /// the fixed transcript `algo_id`; SPEC_USB_TRNG §6.1), or `None` when
    /// unapproved overall or no entry matches exactly.
    pub fn is_device_allowed(&self, vendor_id: u16, product_id: u16, usb_class: UsbClass) -> Option<&UsbTrngDevice> {
        if !self.approved {
            return None;
        }
        self.devices()
            .iter()
            .find(|d| d.vendor_id == vendor_id && d.product_id == product_id && d.usb_class == usb_class)
    }
}

/// A fully parsed, validated entropy policy (SPEC §15).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// Policy version, shown by the UI (SPEC §15: "The UI MUST show the
    /// policy version used").
    pub version: u16,
    /// `[efi_rng]` section.
    pub efi_rng: EfiRngPolicy,
    /// `[rdseed]` section.
    pub rdseed: RdseedPolicy,
    /// `[rdrand]` section.
    pub rdrand: RdrandPolicy,
    /// `[usb_trng]` section (SPEC_USB_TRNG §8.1).
    pub usb_trng: UsbTrngPolicy,
    denylist: [DenylistEntry; MAX_DENYLIST_ENTRIES],
    denylist_len: u8,
}

impl Policy {
    pub(super) fn empty() -> Self {
        Self {
            version: 0,
            efi_rng: EfiRngPolicy::empty(),
            rdseed: RdseedPolicy::empty(),
            rdrand: RdrandPolicy::empty(),
            usb_trng: UsbTrngPolicy::empty(),
            denylist: [DenylistEntry {
                range: CpuRange {
                    vendor: Vendor::empty(),
                    family_min: 0,
                    family_max: 0,
                    model_min: 0,
                    model_max: 0,
                    stepping_min: 0,
                    stepping_max: 0,
                },
                reason: Reason::empty(),
            }; MAX_DENYLIST_ENTRIES],
            denylist_len: 0,
        }
    }

    pub(super) fn push_denylist(&mut self, entry: DenylistEntry) -> Result<(), ()> {
        let i = self.denylist_len as usize;
        if i >= MAX_DENYLIST_ENTRIES {
            return Err(());
        }
        self.denylist[i] = entry;
        self.denylist_len += 1;
        Ok(())
    }

    /// The known-bad-platform denylist entries.
    pub fn denylist(&self) -> &[DenylistEntry] {
        &self.denylist[..self.denylist_len as usize]
    }

    /// Whether `(vendor, family, model, stepping)` is explicitly
    /// denylisted (SPEC §15: "Known-bad platform denylist entries").
    pub fn is_cpu_denylisted(&self, vendor: &str, family: u16, model: u8, stepping: u8) -> bool {
        self.denylist().iter().any(|e| e.range.matches(vendor, family, model, stepping))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range_all() -> CpuRange {
        CpuRange {
            vendor: Vendor::from_str("GenuineIntel").unwrap(),
            family_min: 0,
            family_max: 65535,
            model_min: 0,
            model_max: 255,
            stepping_min: 0,
            stepping_max: 255,
        }
    }

    /// Regression test (SPEC §15: "Required microcode or firmware
    /// conditions where known"; SPEC §15.2: "record microcode revision
    /// where safely available"): a rule with no microcode condition
    /// behaves exactly like the plain `is_cpu_allowed` check.
    #[test]
    fn microcode_check_no_condition_behaves_like_plain_check() {
        let mut policy = RdseedPolicy::empty();
        policy.approved = true;
        policy
            .push_cpu_rule(CpuRule { range: range_all(), allow: true, min_microcode_revision: None })
            .unwrap();

        assert!(policy.is_cpu_allowed("GenuineIntel", 6, 10, 0));
        assert!(policy.is_cpu_allowed_with_microcode("GenuineIntel", 6, 10, 0, None));
        assert!(policy.is_cpu_allowed_with_microcode("GenuineIntel", 6, 10, 0, Some(1)));
    }

    /// Regression test: a rule that requires a minimum microcode revision
    /// must be denied when the current revision is unknown (`None`) —
    /// SPEC §15.2's "where safely available" means the read can fail, and
    /// failure must fail safe (deny), not silently skip the check.
    #[test]
    fn microcode_check_denies_when_revision_unknown() {
        let mut policy = RdseedPolicy::empty();
        policy.approved = true;
        policy
            .push_cpu_rule(CpuRule { range: range_all(), allow: true, min_microcode_revision: Some(100) })
            .unwrap();

        assert!(!policy.is_cpu_allowed_with_microcode("GenuineIntel", 6, 10, 0, None));
        // The microcode-unaware check is unaffected by the condition.
        assert!(policy.is_cpu_allowed("GenuineIntel", 6, 10, 0));
    }

    /// Regression test: a rule that requires a minimum microcode revision
    /// denies platforms below that revision and allows platforms at or
    /// above it.
    #[test]
    fn microcode_check_enforces_minimum_revision() {
        let mut policy = RdseedPolicy::empty();
        policy.approved = true;
        policy
            .push_cpu_rule(CpuRule { range: range_all(), allow: true, min_microcode_revision: Some(100) })
            .unwrap();

        assert!(!policy.is_cpu_allowed_with_microcode("GenuineIntel", 6, 10, 0, Some(99)));
        assert!(policy.is_cpu_allowed_with_microcode("GenuineIntel", 6, 10, 0, Some(100)));
        assert!(policy.is_cpu_allowed_with_microcode("GenuineIntel", 6, 10, 0, Some(101)));
    }

    /// Regression test: last-match-wins still applies with microcode
    /// conditions — a later, narrower rule with an unmet microcode
    /// condition overrides an earlier broad allow.
    #[test]
    fn microcode_check_last_match_wins() {
        let mut policy = RdseedPolicy::empty();
        policy.approved = true;
        policy
            .push_cpu_rule(CpuRule { range: range_all(), allow: true, min_microcode_revision: None })
            .unwrap();
        let narrow = CpuRange {
            vendor: Vendor::from_str("GenuineIntel").unwrap(),
            family_min: 6,
            family_max: 6,
            model_min: 78,
            model_max: 78,
            stepping_min: 0,
            stepping_max: 0,
        };
        policy
            .push_cpu_rule(CpuRule { range: narrow, allow: true, min_microcode_revision: Some(500) })
            .unwrap();

        // Outside the narrow rule: only the broad, unconditioned rule
        // matches.
        assert!(policy.is_cpu_allowed_with_microcode("GenuineIntel", 6, 10, 0, None));
        // Inside the narrow rule: its unmet microcode condition denies,
        // even though the broad earlier rule would have allowed it.
        assert!(!policy.is_cpu_allowed_with_microcode("GenuineIntel", 6, 78, 0, Some(499)));
        assert!(policy.is_cpu_allowed_with_microcode("GenuineIntel", 6, 78, 0, Some(500)));
    }
}
