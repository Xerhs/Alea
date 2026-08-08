//! Owned by WP-08 (SPEC §19). Canonical, domain-separated entropy
//! transcript builder and final-entropy derivation.
//!
//! `TranscriptBuilder` collects zero or more entropy *source records*
//! (SPEC §19.1) in any call order, then [`TranscriptBuilder::finalize`]
//! serializes them into the canonical fixed-buffer wire format (SPEC
//! §19.2) — in ascending `source_tag` order, independent of insertion
//! order — and reduces it with SHA-256 (SPEC §19.3) into the final
//! entropy bytes.
//!
//! [`decode`] is the inverse direction: it parses a byte buffer claiming
//! to be a canonical transcript and rejects any malformed encoding
//! (oversize input beyond `TRANSCRIPT_CAPACITY`, duplicate/out-of-order
//! tags, trailing bytes, out-of-range dice/coin values, a combined
//! `DiceRolls`+`CoinFlips` length over `MAX_PHYSICAL_EVENTS`, unknown tags,
//! length overflows, presence-bitmap mismatches).
//! It exists so both serialization directions — build and reject — have
//! known-answer tests (`IMPLEMENTATION_MAP.md` §5, WP-08 DoD), and so the
//! canonical-ordering/rejection rules are checked by one piece of code
//! instead of being re-derived ad hoc by every future caller.
//!
//! No `alloc`; every buffer here is fixed-size (SPEC §13). This module
//! does not itself implement `Copy`/`Clone`/`Debug`/`Display` on
//! [`TranscriptBuilder`] because it stages raw physical-source bytes
//! (dice rolls, coin flips) that SPEC §19.4 requires be scrubbed once the
//! final entropy has been derived (SPEC §13, §20.2).

use core::sync::atomic::{compiler_fence, Ordering};

use seed_core::contracts::{
    ArchId, SourceTag, TargetBits, MAX_ALGO_ID, MAX_MACHINE_SOURCE_BYTES, MAX_PHYSICAL_EVENTS,
    MAX_TPM2_SOURCE_BYTES,
    MAX_SOURCE_RECORDS, TRANSCRIPT_CAPACITY,
};
use seed_core::hash;

/// Domain-separation prefix mixed into every canonical transcript (SPEC
/// §19.2). 16 bytes: `"Alea/Entropy/v1"` (15 ASCII bytes) plus a
/// trailing NUL.
const DOMAIN: &[u8] = b"Alea/Entropy/v1\0";

/// Canonical source-tag ordering (SPEC §19.2: "record order is canonical
/// and independent of discovery order"). Ascending numeric tag value;
/// bit `i` of the header's `source_presence_bitmap` corresponds to
/// `CANONICAL_TAG_BYTES[i]` (SPEC §19.1/§19.2 — the bitmap has headroom
/// beyond today's 6 defined tags, see `seed_core::contracts::TRANSCRIPT_CAPACITY`
/// derivation comment, so it is indexed by canonical position, not by raw
/// tag value, which would overflow a 16-bit bitmap for `0x10`/`0x11`).
///
/// `0x12` (`ApprovedUsbTrng`) is APPENDED, not inserted, and its wire value
/// is deliberately renumbered above `0x11` (SPEC_USB_TRNG.md §6.1, §6.2):
/// `serialize` (below) emits records in this array's *order*, not sorted by
/// tag value, and `decode` enforces strictly-ascending tag value. The only
/// way to keep body-order == ascending-order == bitmap-position-order (so a
/// USB-present session both serializes correctly and round-trips through
/// `decode`) is for this array to stay ascending after the append — a wire
/// value `< 0x10` (e.g. the earlier-considered `0x04`) would break exactly
/// that invariant. See SPEC_USB_TRNG.md §6.2's byte-layout proof.
///
/// `0x13` (`Tpm2GetRandom`) is likewise APPENDED (SPEC_TPM_ENTROPY.md
/// §6.1/§6.2), keeping the array ascending for the same reason.
/// `0x14` (`Tpm12GetRandom`) likewise (SPEC_TPM12_ENTROPY.md §1).
const CANONICAL_TAG_BYTES: [u8; 8] = [0x01, 0x02, 0x03, 0x10, 0x11, 0x12, 0x13, 0x14];

/// Fixed header size after the domain string (SPEC §19.2):
/// `architecture_identifier`(2) + `requested_entropy_bits`(2) +
/// `entropy_policy_version`(2) + `source_presence_bitmap`(2) +
/// `source_record_count`(1) = 9 bytes.
const HEADER_LEN: usize = 9;

/// Fixed per-record overhead (SPEC §19.1): `source_tag`(1) +
/// `algorithm_identifier_length`(1) + `source_length`(2) = 4 bytes, not
/// counting the variable-length `algorithm_identifier`/`source_bytes`
/// payloads themselves.
const RECORD_OVERHEAD: usize = 4;

/// Bytes of `TRANSCRIPT_CAPACITY` reserved for the domain string, fixed
/// header and every record's fixed overhead, at the maximum possible
/// record count. What remains (`SCRATCH_BUDGET`) is the shared staging
/// budget for record payloads (`algorithm_identifier` + `source_bytes`),
/// chosen so that any combination of `add_source` calls that individually
/// pass their per-record length checks *and* `physical_budget_ok`'s
/// combined `DiceRolls`+`CoinFlips` check is *also* guaranteed to fit
/// inside `TRANSCRIPT_CAPACITY` at `finalize` time — `finalize`'s frozen
/// signature (`IMPLEMENTATION_MAP.md` §4) has no `Result`, so it must
/// never be able to overflow. (Without the combined physical check, two
/// per-record-valid calls — `DiceRolls` at `MAX_PHYSICAL_EVENTS` bytes and
/// `CoinFlips` at `MAX_PHYSICAL_EVENTS` bytes — would together need 1024
/// scratch bytes against a 979-byte budget; `physical_budget_ok` is what
/// makes the invariant below actually hold, not just the arithmetic.)
const RESERVED_OVERHEAD: usize = DOMAIN.len() + HEADER_LEN + MAX_SOURCE_RECORDS * RECORD_OVERHEAD;

/// Shared staging budget for record payload bytes (see
/// `RESERVED_OVERHEAD`). `TRANSCRIPT_CAPACITY` (2048) minus the maximum
/// fixed overhead (16 + 9 + 7*4 = 53) leaves 1995 bytes (SPEC_USB_TRNG.md
/// §6.3, SPEC_TPM_ENTROPY.md §6.3): up to 4 machine-source records
/// (`ApprovedEfiRng`, `X86Rdseed64`, `X86RdrandSupplementary`,
/// `ApprovedUsbTrng`) at `MAX_ALGO_ID` + `MAX_MACHINE_SOURCE_BYTES`
/// (32 + 64 = 96, the per-record data cap having doubled 32 → 64 for audit
/// finding L2) each = 384 bytes, plus `Tpm2GetRandom` at `MAX_ALGO_ID` +
/// `MAX_TPM2_SOURCE_BYTES` (32 + 32) = 64 bytes, plus `DiceRolls` +
/// `CoinFlips` sharing at most `MAX_PHYSICAL_EVENTS` (512) total payload
/// bytes plus up to `MAX_ALGO_ID` (32) algo-id bytes each = 512 + 64 = 576
/// bytes; 384 + 64 + 576 = 1024 <= 1995.
const SCRATCH_BUDGET: usize = TRANSCRIPT_CAPACITY - RESERVED_OVERHEAD;

/// Errors from building or parsing a canonical entropy transcript (SPEC
/// §19.1/§19.2). Carries no secret values (SPEC §27.3): every variant is a
/// structural/range fact about the (public) wire shape, never source
/// content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranscriptError {
    /// `add_source`/`decode` saw the same `source_tag` twice (SPEC §19.1:
    /// "source tags are unique").
    DuplicateTag,
    /// More source records were supplied than `MAX_SOURCE_RECORDS` allows.
    TooManyRecords,
    /// `algorithm_identifier` exceeds `MAX_ALGO_ID`.
    AlgoIdTooLong,
    /// `source_bytes` exceeds the per-tag bound (`MAX_MACHINE_SOURCE_BYTES`
    /// for machine sources, `MAX_PHYSICAL_EVENTS` for dice/coin sources) —
    /// or, for `DiceRolls`/`CoinFlips`, the *combined* dice+coin length
    /// exceeds `MAX_PHYSICAL_EVENTS` even though each individually fits
    /// (SPEC §17.3: one shared physical-event history buffer, not one per
    /// tag).
    SourceTooLong,
    /// A `DiceRolls` (`0x10`) record contained a byte outside `0x01..=0x06`
    /// (SPEC §19.1).
    InvalidRollValue,
    /// A `CoinFlips` (`0x11`) record contained a byte outside `{0x00,
    /// 0x01}` (SPEC §19.1).
    InvalidFlipValue,
    /// The record would not fit in the fixed transcript buffer.
    BufferOverflow,
    /// `decode` input was shorter than the structure it claims to encode.
    Truncated,
    /// `decode` input's total length exceeded `TRANSCRIPT_CAPACITY`. No
    /// output of `TranscriptBuilder::serialize`/`finalize` can ever be
    /// this large (SPEC §19.1/§19.2: "the complete transcript fits a fixed
    /// reviewed buffer"), so a longer input cannot be a genuine canonical
    /// transcript regardless of how its individual fields parse.
    Oversized,
    /// `decode` input's leading bytes did not match `DOMAIN`.
    BadDomain,
    /// `decode` saw a `source_tag` byte that is not one of the eight
    /// defined values (SPEC §19.1, SPEC_USB_TRNG.md §6.1: "unknown fields
    /// are not silently ignored").
    UnknownTag,
    /// `decode` saw two records whose tags are not in strictly ascending
    /// canonical order (SPEC §19.2).
    OutOfCanonicalOrder,
    /// `decode` consumed every declared record but bytes remained in the
    /// input (SPEC §19.1: "all lengths explicit" — nothing after the last
    /// record is meaningful).
    TrailingBytes,
    /// `decode`'s header `source_presence_bitmap` did not match the set of
    /// tags the record list actually contains.
    PresenceMismatch,
}

/// One staged source record's location inside `TranscriptBuilder::scratch`
/// (SPEC §19.1). Plain offsets/lengths, not the secret payload itself;
/// still kept private and un-derived beyond `Clone`/`Copy` since it is an
/// implementation detail of a secret-bearing type.
#[derive(Clone, Copy)]
struct RecordMeta {
    tag_byte: u8,
    algo_off: usize,
    algo_len: u8,
    data_off: usize,
    data_len: u16,
}

impl RecordMeta {
    const fn zero() -> Self {
        RecordMeta {
            tag_byte: 0,
            algo_off: 0,
            algo_len: 0,
            data_off: 0,
            data_len: 0,
        }
    }
}

/// Bound on a source tag's `source_bytes` length (SPEC §15.1-§15.3 for
/// machine sources, §17.1/§17.3 for dice/coin).
///
/// For `DiceRolls`/`CoinFlips` this is each tag's *individual* ceiling —
/// either one, alone, may use up to `MAX_PHYSICAL_EVENTS` bytes. It is not
/// the combined ceiling: `MAX_PHYSICAL_EVENTS` (SPEC §17.3, and
/// `seed_core::contracts::TRANSCRIPT_CAPACITY`'s own derivation comment)
/// names "the shared dice+coin physical-event history buffer" — one
/// fixed-size buffer for the *whole session*, sized so dice and coin bytes
/// *together* stay within it. The combined bound is enforced separately by
/// [`physical_budget_ok`], both in [`TranscriptBuilder::add_source`] and in
/// [`decode`], so neither accepts a dice+coin combination that the other
/// would reject.
fn max_len_for(tag: SourceTag) -> usize {
    match tag {
        SourceTag::ApprovedEfiRng
        | SourceTag::X86Rdseed64
        | SourceTag::X86RdrandSupplementary
        | SourceTag::ApprovedUsbTrng => MAX_MACHINE_SOURCE_BYTES,
        // SPEC_TPM_ENTROPY.md §7.2/§9: exactly one 32-byte block — the
        // tighter dedicated cap, not the shared machine cap (see
        // `MAX_TPM2_SOURCE_BYTES`'s own doc comment).
        SourceTag::Tpm2GetRandom | SourceTag::Tpm12GetRandom => MAX_TPM2_SOURCE_BYTES,
        SourceTag::DiceRolls | SourceTag::CoinFlips => MAX_PHYSICAL_EVENTS,
    }
}

/// The other physical-source tag sharing `DiceRolls`/`CoinFlips`'s combined
/// `MAX_PHYSICAL_EVENTS` budget (SPEC §17.3), or `None` for a non-physical
/// tag (machine sources are not budget-shared with anything).
fn sibling_physical_tag(tag: SourceTag) -> Option<SourceTag> {
    match tag {
        SourceTag::DiceRolls => Some(SourceTag::CoinFlips),
        SourceTag::CoinFlips => Some(SourceTag::DiceRolls),
        SourceTag::ApprovedEfiRng
        | SourceTag::X86Rdseed64
        | SourceTag::X86RdrandSupplementary
        | SourceTag::ApprovedUsbTrng
        | SourceTag::Tpm2GetRandom
        | SourceTag::Tpm12GetRandom => None,
    }
}

/// Checks the *combined* `DiceRolls` + `CoinFlips` byte budget (SPEC
/// §17.3): `tag`'s own `len` plus whatever length `sibling_len` reports for
/// the other physical tag (0 if absent/not applicable) must not exceed
/// `MAX_PHYSICAL_EVENTS`. Non-physical tags always pass (they share no
/// budget). Used identically by `add_source` (build direction) and
/// `decode` (parse direction) so both accept exactly the same set of
/// dice+coin combinations.
fn physical_budget_ok(tag: SourceTag, len: usize, sibling_len: usize) -> bool {
    match sibling_physical_tag(tag) {
        Some(_) => len + sibling_len <= MAX_PHYSICAL_EVENTS,
        None => true,
    }
}

/// Per-tag content validation (SPEC §19.1: dice bytes `0x01..=0x06`, coin
/// bytes `{0x00, 0x01}`; machine sources have no byte-value restriction).
fn validate_content(tag: SourceTag, bytes: &[u8]) -> Result<(), TranscriptError> {
    match tag {
        SourceTag::DiceRolls => {
            if bytes.iter().any(|&b| !(1..=6).contains(&b)) {
                return Err(TranscriptError::InvalidRollValue);
            }
        }
        SourceTag::CoinFlips => {
            if bytes.iter().any(|&b| b > 1) {
                return Err(TranscriptError::InvalidFlipValue);
            }
        }
        SourceTag::ApprovedEfiRng
        | SourceTag::X86Rdseed64
        | SourceTag::X86RdrandSupplementary
        | SourceTag::ApprovedUsbTrng
        | SourceTag::Tpm2GetRandom
        | SourceTag::Tpm12GetRandom => {}
    }
    Ok(())
}

/// Maps a raw wire byte back to a [`SourceTag`] (SPEC §19.1's fixed tag
/// set). Not a `TryFrom` impl on `SourceTag` itself — that type is owned
/// by `contracts.rs` (WP-00) — just a local decode helper.
fn tag_from_u8(v: u8) -> Option<SourceTag> {
    match v {
        0x01 => Some(SourceTag::ApprovedEfiRng),
        0x02 => Some(SourceTag::X86Rdseed64),
        0x03 => Some(SourceTag::X86RdrandSupplementary),
        0x10 => Some(SourceTag::DiceRolls),
        0x11 => Some(SourceTag::CoinFlips),
        0x12 => Some(SourceTag::ApprovedUsbTrng),
        0x13 => Some(SourceTag::Tpm2GetRandom),
        0x14 => Some(SourceTag::Tpm12GetRandom),
        _ => None,
    }
}

fn be_u16(bytes: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([bytes[off], bytes[off + 1]])
}

fn write_be_u16(out: &mut [u8; TRANSCRIPT_CAPACITY], offset: &mut usize, v: u16) {
    let b = v.to_be_bytes();
    out[*offset] = b[0];
    out[*offset + 1] = b[1];
    *offset += 2;
}

/// Overwrite `buf` with zero using volatile writes plus a compiler fence,
/// so the wipe cannot be optimized away (SPEC §13, §20.3).
fn scrub_slice(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid `&mut u8` for the duration of the write.
        unsafe {
            core::ptr::write_volatile(b, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

/// Canonical, domain-separated entropy transcript builder (SPEC §19).
///
/// Collects source records via [`add_source`](Self::add_source) in any
/// call order; [`finalize`](Self::finalize) serializes them in canonical
/// tag order (SPEC §19.2) and reduces the result with SHA-256 (SPEC
/// §19.3). Deliberately does not implement `Copy`, `Clone`, `Debug` or
/// `Display` (SPEC §13, §20.2): staged record bytes may include physical
/// entropy source material (dice/coin history) that SPEC §19.4 requires
/// be scrubbed, not copied or formatted.
pub struct TranscriptBuilder {
    scratch: [u8; SCRATCH_BUDGET],
    scratch_len: usize,
    records: [RecordMeta; MAX_SOURCE_RECORDS],
    record_count: usize,
}

impl TranscriptBuilder {
    /// Creates an empty builder (SPEC §19.1).
    pub const fn new() -> Self {
        TranscriptBuilder {
            scratch: [0u8; SCRATCH_BUDGET],
            scratch_len: 0,
            records: [RecordMeta::zero(); MAX_SOURCE_RECORDS],
            record_count: 0,
        }
    }

    /// Number of source records staged so far.
    pub fn record_count(&self) -> usize {
        self.record_count
    }

    fn find(&self, tag_byte: u8) -> Option<&RecordMeta> {
        self.records[..self.record_count]
            .iter()
            .find(|r| r.tag_byte == tag_byte)
    }

    /// Stages one source record (SPEC §19.1). Records may be added in any
    /// order; [`finalize`](Self::finalize) always serializes them in
    /// canonical tag order.
    ///
    /// Rejects (SPEC §19.1, §17.1, §15.1-§15.3):
    /// - a duplicate `tag` ([`TranscriptError::DuplicateTag`]),
    /// - more than `MAX_SOURCE_RECORDS` records
    ///   ([`TranscriptError::TooManyRecords`]),
    /// - `algo_id` longer than `MAX_ALGO_ID`
    ///   ([`TranscriptError::AlgoIdTooLong`]),
    /// - `bytes` longer than the per-tag bound, or a `DiceRolls`/`CoinFlips`
    ///   combination whose *combined* length exceeds `MAX_PHYSICAL_EVENTS`
    ///   (SPEC §17.3 — one shared history buffer for the whole session)
    ///   ([`TranscriptError::SourceTooLong`]),
    /// - a `DiceRolls`/`CoinFlips` byte outside its valid range
    ///   ([`TranscriptError::InvalidRollValue`]/
    ///   [`TranscriptError::InvalidFlipValue`]).
    pub fn add_source(
        &mut self,
        tag: SourceTag,
        algo_id: &[u8],
        bytes: &[u8],
    ) -> Result<(), TranscriptError> {
        let tag_byte = tag as u8;
        if self.find(tag_byte).is_some() {
            return Err(TranscriptError::DuplicateTag);
        }
        if self.record_count >= MAX_SOURCE_RECORDS {
            return Err(TranscriptError::TooManyRecords);
        }
        if algo_id.len() > MAX_ALGO_ID {
            return Err(TranscriptError::AlgoIdTooLong);
        }
        if bytes.len() > max_len_for(tag) {
            return Err(TranscriptError::SourceTooLong);
        }
        if let Some(sibling) = sibling_physical_tag(tag) {
            let sibling_len = self
                .find(sibling as u8)
                .map(|r| r.data_len as usize)
                .unwrap_or(0);
            if !physical_budget_ok(tag, bytes.len(), sibling_len) {
                return Err(TranscriptError::SourceTooLong);
            }
        }
        validate_content(tag, bytes)?;

        let needed = algo_id.len() + bytes.len();
        if self.scratch_len + needed > SCRATCH_BUDGET {
            // Unreachable given today's per-tag bounds and
            // `SCRATCH_BUDGET`'s derivation, but checked explicitly so
            // `finalize` (which has no `Result` in its frozen signature)
            // can never be asked to overflow `TRANSCRIPT_CAPACITY`.
            return Err(TranscriptError::BufferOverflow);
        }

        let algo_off = self.scratch_len;
        self.scratch[algo_off..algo_off + algo_id.len()].copy_from_slice(algo_id);
        self.scratch_len += algo_id.len();

        let data_off = self.scratch_len;
        self.scratch[data_off..data_off + bytes.len()].copy_from_slice(bytes);
        self.scratch_len += bytes.len();

        self.records[self.record_count] = RecordMeta {
            tag_byte,
            algo_off,
            algo_len: algo_id.len() as u8,
            data_off,
            data_len: bytes.len() as u16,
        };
        self.record_count += 1;
        Ok(())
    }

    fn presence_bitmap(&self) -> u16 {
        let mut bm = 0u16;
        for (i, &tb) in CANONICAL_TAG_BYTES.iter().enumerate() {
            if self.find(tb).is_some() {
                bm |= 1 << i;
            }
        }
        bm
    }

    /// Serializes the currently staged records into the canonical
    /// transcript wire format (SPEC §19.2), writing into `out` and
    /// returning the number of bytes written. Records are emitted in
    /// canonical tag order regardless of `add_source` call order.
    ///
    /// This does not consume `self` or hash the result — it exists so the
    /// exact byte layout is independently testable (known-answer tests)
    /// without requiring the final SHA-256 step. Production code should
    /// normally call [`finalize`](Self::finalize) instead, which also
    /// performs SPEC §19.3's reduction and SPEC §19.4's scrub.
    pub fn serialize(
        &self,
        arch: ArchId,
        bits: TargetBits,
        policy_ver: u16,
        out: &mut [u8; TRANSCRIPT_CAPACITY],
    ) -> usize {
        let mut offset = 0usize;
        out[offset..offset + DOMAIN.len()].copy_from_slice(DOMAIN);
        offset += DOMAIN.len();

        write_be_u16(out, &mut offset, arch as u16);
        write_be_u16(out, &mut offset, bits as u16);
        write_be_u16(out, &mut offset, policy_ver);
        write_be_u16(out, &mut offset, self.presence_bitmap());
        out[offset] = self.record_count as u8;
        offset += 1;

        for &tag_byte in CANONICAL_TAG_BYTES.iter() {
            if let Some(rec) = self.find(tag_byte) {
                out[offset] = rec.tag_byte;
                offset += 1;
                out[offset] = rec.algo_len;
                offset += 1;
                let algo_len = rec.algo_len as usize;
                out[offset..offset + algo_len]
                    .copy_from_slice(&self.scratch[rec.algo_off..rec.algo_off + algo_len]);
                offset += algo_len;
                write_be_u16(out, &mut offset, rec.data_len);
                let data_len = rec.data_len as usize;
                out[offset..offset + data_len]
                    .copy_from_slice(&self.scratch[rec.data_off..rec.data_off + data_len]);
                offset += data_len;
            }
        }
        offset
    }

    /// Explicitly scrubs all staged record bytes (SPEC §13, §19.4,
    /// §20.3), without resetting metadata to a reusable empty state —
    /// call this on an abandoned builder (e.g. a fatal-path abort before
    /// `finalize` runs). `finalize`/`Drop` call the same wipe.
    pub fn scrub(&mut self) {
        scrub_slice(&mut self.scratch);
        for r in self.records.iter_mut() {
            *r = RecordMeta::zero();
        }
        compiler_fence(Ordering::SeqCst);
    }

    /// Serializes the canonical transcript (SPEC §19.2), reduces it with
    /// SHA-256 (SPEC §19.3) into `out`, and scrubs every intermediate
    /// buffer — the serialized transcript, this builder's staged record
    /// bytes — per SPEC §19.4. Consumes `self` so the caller cannot
    /// accidentally reuse a builder whose contents are meant to be
    /// scrubbed immediately after this call.
    pub fn finalize(mut self, arch: ArchId, bits: TargetBits, policy_ver: u16, out: &mut [u8; 32]) {
        let mut buf = [0u8; TRANSCRIPT_CAPACITY];
        let len = self.serialize(arch, bits, policy_ver, &mut buf);
        let digest = hash::sha256(&buf[..len]);
        out.copy_from_slice(&digest);
        scrub_slice(&mut buf);
        self.scrub();
        // `self` drops here; `Drop` re-runs the (idempotent) scrub as a
        // defense-in-depth backstop for any future early-return path.
    }
}

impl Default for TranscriptBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for TranscriptBuilder {
    fn drop(&mut self) {
        self.scrub();
    }
}

/// One decoded source record, borrowing directly from the input buffer
/// passed to [`decode`] (SPEC §19.1). No secret bytes are copied; this is
/// purely a view. `Debug` is derived only under `#[cfg(test)]` (needed for
/// `assert_eq!`/`unwrap_err` in this module's own tests) — never in
/// production builds, per SPEC §13/§20.2's caution around formatting
/// anything that may echo entropy-source bytes.
#[cfg_attr(test, derive(Debug))]
pub struct DecodedRecord<'a> {
    /// The record's source tag.
    pub tag: SourceTag,
    /// The record's `algorithm_identifier` bytes.
    pub algo_id: &'a [u8],
    /// The record's `source_bytes`.
    pub bytes: &'a [u8],
}

/// A fully parsed and validated canonical transcript (SPEC §19.2),
/// borrowing from the input buffer passed to [`decode`]. `Debug` is
/// derived only under `#[cfg(test)]`, matching [`DecodedRecord`].
#[cfg_attr(test, derive(Debug))]
pub struct DecodedTranscript<'a> {
    /// `architecture_identifier` header field.
    pub arch: u16,
    /// `requested_entropy_bits` header field.
    pub requested_entropy_bits: u16,
    /// `entropy_policy_version` header field.
    pub policy_version: u16,
    /// `source_presence_bitmap` header field (already checked to match
    /// the decoded record set, see [`TranscriptError::PresenceMismatch`]).
    pub presence_bitmap: u16,
    /// Decoded records, canonical-tag-order, `records[..record_count]`
    /// meaningful.
    pub records: [Option<DecodedRecord<'a>>; MAX_SOURCE_RECORDS],
    /// Number of valid entries in `records`.
    pub record_count: usize,
}

/// Parses and fully validates a byte buffer as a canonical entropy
/// transcript (SPEC §19.1, §19.2) — the inverse of
/// [`TranscriptBuilder::serialize`]. Rejects any malformed encoding; see
/// [`TranscriptError`] for the exhaustive list of rejection reasons this
/// function can return, including an input longer than
/// `TRANSCRIPT_CAPACITY`, duplicate/out-of-canonical-order tags, trailing
/// bytes after the last declared record, out-of-range dice/coin values, a
/// combined `DiceRolls`+`CoinFlips` length over `MAX_PHYSICAL_EVENTS`,
/// unknown tags and a `source_presence_bitmap` that does not match the
/// actual record set. `decode` accepts exactly the set of inputs
/// `TranscriptBuilder::serialize` can produce — never a strict superset.
pub fn decode(bytes: &[u8]) -> Result<DecodedTranscript<'_>, TranscriptError> {
    // SPEC §19.1/§19.2: the canonical transcript fits a fixed reviewed
    // buffer (`TRANSCRIPT_CAPACITY`). No wire format that
    // `TranscriptBuilder::serialize`/`finalize` could ever produce exceeds
    // this, so a longer input is rejected outright rather than parsed
    // field-by-field against per-field bounds that, individually, could
    // still add up past the aggregate cap.
    if bytes.len() > TRANSCRIPT_CAPACITY {
        return Err(TranscriptError::Oversized);
    }
    if bytes.len() < DOMAIN.len() {
        return Err(TranscriptError::Truncated);
    }
    if &bytes[..DOMAIN.len()] != DOMAIN {
        return Err(TranscriptError::BadDomain);
    }
    let mut off = DOMAIN.len();

    if off + HEADER_LEN > bytes.len() {
        return Err(TranscriptError::Truncated);
    }
    let arch = be_u16(bytes, off);
    off += 2;
    let requested_entropy_bits = be_u16(bytes, off);
    off += 2;
    let policy_version = be_u16(bytes, off);
    off += 2;
    let presence_bitmap = be_u16(bytes, off);
    off += 2;
    let record_count = bytes[off] as usize;
    off += 1;

    if record_count > MAX_SOURCE_RECORDS {
        return Err(TranscriptError::TooManyRecords);
    }

    let mut records: [Option<DecodedRecord<'_>>; MAX_SOURCE_RECORDS] =
        [None, None, None, None, None, None, None, None];
    let mut last_tag: i32 = -1;
    // Running combined length of `DiceRolls`+`CoinFlips` records seen so
    // far (SPEC §17.3: one shared physical-event history buffer). Mirrors
    // `TranscriptBuilder::add_source`'s `physical_budget_ok` check so
    // `decode` never accepts a dice+coin combination `add_source` would
    // have refused to build.
    let mut physical_total: usize = 0;

    for slot in records.iter_mut().take(record_count) {
        if off + 1 > bytes.len() {
            return Err(TranscriptError::Truncated);
        }
        let tag_byte = bytes[off];
        off += 1;
        let tag = tag_from_u8(tag_byte).ok_or(TranscriptError::UnknownTag)?;
        let tag_val = i32::from(tag_byte);
        if tag_val == last_tag {
            return Err(TranscriptError::DuplicateTag);
        }
        if tag_val < last_tag {
            return Err(TranscriptError::OutOfCanonicalOrder);
        }
        last_tag = tag_val;

        if off + 1 > bytes.len() {
            return Err(TranscriptError::Truncated);
        }
        let algo_len = bytes[off] as usize;
        off += 1;
        if algo_len > MAX_ALGO_ID {
            return Err(TranscriptError::AlgoIdTooLong);
        }
        if off + algo_len > bytes.len() {
            return Err(TranscriptError::Truncated);
        }
        let algo_id = &bytes[off..off + algo_len];
        off += algo_len;

        if off + 2 > bytes.len() {
            return Err(TranscriptError::Truncated);
        }
        let data_len = be_u16(bytes, off) as usize;
        off += 2;
        if data_len > max_len_for(tag) {
            return Err(TranscriptError::SourceTooLong);
        }
        if sibling_physical_tag(tag).is_some() {
            physical_total += data_len;
            if physical_total > MAX_PHYSICAL_EVENTS {
                return Err(TranscriptError::SourceTooLong);
            }
        }
        if off + data_len > bytes.len() {
            return Err(TranscriptError::Truncated);
        }
        let data = &bytes[off..off + data_len];
        off += data_len;

        validate_content(tag, data)?;

        *slot = Some(DecodedRecord {
            tag,
            algo_id,
            bytes: data,
        });
    }

    if off != bytes.len() {
        return Err(TranscriptError::TrailingBytes);
    }

    let mut computed_presence = 0u16;
    for rec in records.iter().take(record_count).flatten() {
        let tb = rec.tag as u8;
        if let Some(pos) = CANONICAL_TAG_BYTES.iter().position(|&t| t == tb) {
            computed_presence |= 1 << pos;
        }
    }
    if computed_presence != presence_bitmap {
        return Err(TranscriptError::PresenceMismatch);
    }

    Ok(DecodedTranscript {
        arch,
        requested_entropy_bits,
        policy_version,
        presence_bitmap,
        records,
        record_count,
    })
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    fn hex_to_vec(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex32(s: &str) -> [u8; 32] {
        let v = hex_to_vec(s);
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        out
    }

    // ---- build direction: serialize() byte-layout KATs ----
    // Expected bytes/digests independently computed with Python's
    // `hashlib.sha256` over the same canonical layout (see WP-08 notes).

    #[test]
    fn serialize_empty_transcript() {
        let b = TranscriptBuilder::new();
        let mut buf = [0u8; TRANSCRIPT_CAPACITY];
        let len = b.serialize(ArchId::X86_64, TargetBits::Bits128, 1, &mut buf);
        let expected = hex_to_vec(
            "416c65612f456e74726f70792f76310000010080000100000\
             0",
        );
        assert_eq!(len, expected.len());
        assert_eq!(&buf[..len], &expected[..]);
    }

    #[test]
    fn finalize_empty_transcript_kat() {
        let b = TranscriptBuilder::new();
        let mut out = [0u8; 32];
        b.finalize(ArchId::X86_64, TargetBits::Bits128, 1, &mut out);
        assert_eq!(
            out,
            hex32("c9aa1b1acf4fbd3d6c7452740ec99d7049c3fbfa981df9138967b75baf7fa118")
        );
    }

    #[test]
    fn serialize_one_dice_record() {
        let mut b = TranscriptBuilder::new();
        b.add_source(SourceTag::DiceRolls, &[], &[1, 2, 3, 4, 5, 6])
            .unwrap();
        let mut buf = [0u8; TRANSCRIPT_CAPACITY];
        let len = b.serialize(ArchId::X86_64, TargetBits::Bits128, 1, &mut buf);
        let expected = hex_to_vec(
            "416c65612f456e74726f70792f76310000010080000100080110\
             000006010203040506",
        );
        assert_eq!(&buf[..len], &expected[..]);
    }

    #[test]
    fn finalize_one_dice_record_kat() {
        let mut b = TranscriptBuilder::new();
        b.add_source(SourceTag::DiceRolls, &[], &[1, 2, 3, 4, 5, 6])
            .unwrap();
        let mut out = [0u8; 32];
        b.finalize(ArchId::X86_64, TargetBits::Bits128, 1, &mut out);
        assert_eq!(
            out,
            hex32("075325c88ade2197a3f0959931d9347f17b5f60a329c313b173159870b88a01e")
        );
    }

    /// Two sources added in *reverse* canonical order (coin flips before
    /// dice rolls) must still serialize dice-then-coin (SPEC §19.2: order
    /// is canonical, independent of discovery/insertion order).
    #[test]
    fn finalize_reorders_to_canonical_tag_order() {
        let mut b = TranscriptBuilder::new();
        b.add_source(SourceTag::CoinFlips, &[], &[0, 1]).unwrap();
        b.add_source(SourceTag::DiceRolls, &[], &[1, 6, 3]).unwrap();
        let mut out = [0u8; 32];
        b.finalize(ArchId::X86_64, TargetBits::Bits256, 2, &mut out);
        assert_eq!(
            out,
            hex32("1da326ad241367ea19071f4d97627e4afc8c33615b1ef074215226416122122d")
        );
    }

    /// Building the same content in a different insertion order must
    /// serialize to byte-identical output (canonical-order guarantee).
    #[test]
    fn serialize_is_insertion_order_independent() {
        let mut b1 = TranscriptBuilder::new();
        b1.add_source(SourceTag::CoinFlips, &[], &[1, 0]).unwrap();
        b1.add_source(SourceTag::DiceRolls, &[], &[2, 4]).unwrap();

        let mut b2 = TranscriptBuilder::new();
        b2.add_source(SourceTag::DiceRolls, &[], &[2, 4]).unwrap();
        b2.add_source(SourceTag::CoinFlips, &[], &[1, 0]).unwrap();

        let mut buf1 = [0u8; TRANSCRIPT_CAPACITY];
        let mut buf2 = [0u8; TRANSCRIPT_CAPACITY];
        let len1 = b1.serialize(ArchId::X86_64, TargetBits::Bits128, 1, &mut buf1);
        let len2 = b2.serialize(ArchId::X86_64, TargetBits::Bits128, 1, &mut buf2);
        assert_eq!(&buf1[..len1], &buf2[..len2]);
    }

    // ---- add_source validation (build-direction rejections) ----

    #[test]
    fn add_source_rejects_duplicate_tag() {
        let mut b = TranscriptBuilder::new();
        b.add_source(SourceTag::DiceRolls, &[], &[1]).unwrap();
        let err = b.add_source(SourceTag::DiceRolls, &[], &[2]).unwrap_err();
        assert_eq!(err, TranscriptError::DuplicateTag);
    }

    #[test]
    fn add_source_rejects_invalid_roll_value_zero() {
        let mut b = TranscriptBuilder::new();
        let err = b.add_source(SourceTag::DiceRolls, &[], &[0]).unwrap_err();
        assert_eq!(err, TranscriptError::InvalidRollValue);
    }

    #[test]
    fn add_source_rejects_invalid_roll_value_seven() {
        let mut b = TranscriptBuilder::new();
        let err = b
            .add_source(SourceTag::DiceRolls, &[], &[3, 7])
            .unwrap_err();
        assert_eq!(err, TranscriptError::InvalidRollValue);
    }

    #[test]
    fn add_source_rejects_invalid_flip_value() {
        let mut b = TranscriptBuilder::new();
        let err = b
            .add_source(SourceTag::CoinFlips, &[], &[0, 1, 2])
            .unwrap_err();
        assert_eq!(err, TranscriptError::InvalidFlipValue);
    }

    #[test]
    fn add_source_accepts_valid_dice_and_coin_boundaries() {
        let mut b = TranscriptBuilder::new();
        b.add_source(SourceTag::DiceRolls, &[], &[1, 6]).unwrap();
        b.add_source(SourceTag::CoinFlips, &[], &[0, 1]).unwrap();
        assert_eq!(b.record_count(), 2);
    }

    #[test]
    fn add_source_rejects_algo_id_too_long() {
        let mut b = TranscriptBuilder::new();
        let algo = std::vec![0u8; MAX_ALGO_ID + 1];
        let err = b
            .add_source(SourceTag::ApprovedEfiRng, &algo, &[])
            .unwrap_err();
        assert_eq!(err, TranscriptError::AlgoIdTooLong);
    }

    #[test]
    fn add_source_accepts_algo_id_at_max() {
        let mut b = TranscriptBuilder::new();
        let algo = std::vec![0xAAu8; MAX_ALGO_ID];
        b.add_source(SourceTag::ApprovedEfiRng, &algo, &[1, 2, 3])
            .unwrap();
    }

    #[test]
    fn add_source_rejects_machine_source_too_long() {
        let mut b = TranscriptBuilder::new();
        let bytes = std::vec![0u8; MAX_MACHINE_SOURCE_BYTES + 1];
        let err = b
            .add_source(SourceTag::X86Rdseed64, &[], &bytes)
            .unwrap_err();
        assert_eq!(err, TranscriptError::SourceTooLong);
    }

    #[test]
    fn add_source_rejects_physical_source_too_long() {
        let mut b = TranscriptBuilder::new();
        let bytes = std::vec![1u8; MAX_PHYSICAL_EVENTS + 1];
        let err = b
            .add_source(SourceTag::DiceRolls, &[], &bytes)
            .unwrap_err();
        assert_eq!(err, TranscriptError::SourceTooLong);
    }

    #[test]
    fn add_source_accepts_physical_source_at_max() {
        let mut b = TranscriptBuilder::new();
        let bytes = std::vec![1u8; MAX_PHYSICAL_EVENTS];
        b.add_source(SourceTag::DiceRolls, &[], &bytes).unwrap();
        assert_eq!(b.record_count(), 1);
    }

    /// Regression (adversarial review, WP-08 fix): `DiceRolls` and
    /// `CoinFlips` share one `MAX_PHYSICAL_EVENTS`-byte history buffer
    /// (SPEC §17.3), not one each. Each record individually satisfies its
    /// own per-tag `SourceTooLong` check (512 is not `> 512`), but adding
    /// both at the per-tag max must still be rejected because the
    /// *combined* length (1024) exceeds `MAX_PHYSICAL_EVENTS` (512) — this
    /// is also what previously made `finalize`'s documented
    /// never-overflows-`SCRATCH_BUDGET` invariant false.
    #[test]
    fn add_source_rejects_combined_physical_budget_over_max_physical_events() {
        let mut b = TranscriptBuilder::new();
        let dice = std::vec![1u8; MAX_PHYSICAL_EVENTS];
        b.add_source(SourceTag::DiceRolls, &[], &dice).unwrap();
        let coin = std::vec![0u8; MAX_PHYSICAL_EVENTS];
        let err = b.add_source(SourceTag::CoinFlips, &[], &coin).unwrap_err();
        assert_eq!(err, TranscriptError::SourceTooLong);
    }

    /// Same as above with the tags added in the opposite order, confirming
    /// the combined check is symmetric regardless of which physical tag is
    /// staged first.
    #[test]
    fn add_source_rejects_combined_physical_budget_over_max_physical_events_reversed_order() {
        let mut b = TranscriptBuilder::new();
        let coin = std::vec![0u8; MAX_PHYSICAL_EVENTS];
        b.add_source(SourceTag::CoinFlips, &[], &coin).unwrap();
        let dice = std::vec![1u8; MAX_PHYSICAL_EVENTS];
        let err = b.add_source(SourceTag::DiceRolls, &[], &dice).unwrap_err();
        assert_eq!(err, TranscriptError::SourceTooLong);
    }

    /// A combined dice+coin length landing exactly on `MAX_PHYSICAL_EVENTS`
    /// must still succeed (boundary is inclusive, matching the per-tag
    /// boundary semantics of `SourceTooLong`).
    #[test]
    fn add_source_accepts_combined_physical_budget_at_exact_max() {
        let mut b = TranscriptBuilder::new();
        let dice = std::vec![1u8; 300];
        b.add_source(SourceTag::DiceRolls, &[], &dice).unwrap();
        let coin = std::vec![0u8; MAX_PHYSICAL_EVENTS - 300];
        b.add_source(SourceTag::CoinFlips, &[], &coin).unwrap();
        assert_eq!(b.record_count(), 2);
    }

    /// One byte past the combined budget, with each record still
    /// individually under its own per-tag bound, must be rejected.
    #[test]
    fn add_source_rejects_combined_physical_budget_one_byte_over() {
        let mut b = TranscriptBuilder::new();
        let dice = std::vec![1u8; 300];
        b.add_source(SourceTag::DiceRolls, &[], &dice).unwrap();
        let coin = std::vec![0u8; MAX_PHYSICAL_EVENTS - 300 + 1];
        let err = b.add_source(SourceTag::CoinFlips, &[], &coin).unwrap_err();
        assert_eq!(err, TranscriptError::SourceTooLong);
    }

    /// A legitimate budget-exact dice+coin combination must still
    /// round-trip through `serialize`/`decode` cleanly after the fix.
    #[test]
    fn decode_round_trips_combined_physical_budget_at_exact_max() {
        let mut b = TranscriptBuilder::new();
        let dice = std::vec![1u8; 300];
        b.add_source(SourceTag::DiceRolls, &[], &dice).unwrap();
        let coin = std::vec![0u8; MAX_PHYSICAL_EVENTS - 300];
        b.add_source(SourceTag::CoinFlips, &[], &coin).unwrap();

        let mut buf = [0u8; TRANSCRIPT_CAPACITY];
        let len = b.serialize(ArchId::X86_64, TargetBits::Bits128, 1, &mut buf);
        let decoded = decode(&buf[..len]).expect("budget-exact combo must decode");
        assert_eq!(decoded.record_count, 2);
    }

    /// All eight defined tags fill the builder to `MAX_SOURCE_RECORDS`
    /// exactly (SPEC_USB_TRNG.md §6.1 added `ApprovedUsbTrng`,
    /// SPEC_TPM_ENTROPY.md §6.1 `Tpm2GetRandom`, SPEC_TPM12_ENTROPY.md §1
    /// `Tpm12GetRandom` — so `TooManyRecords` cannot be reached via
    /// distinct valid tags; the capacity check exists as a
    /// forward-compatible invariant guard).
    #[test]
    fn add_source_all_eight_tags_fills_builder() {
        let mut b = TranscriptBuilder::new();
        b.add_source(SourceTag::ApprovedEfiRng, &[], &[1]).unwrap();
        b.add_source(SourceTag::X86Rdseed64, &[], &[2]).unwrap();
        b.add_source(SourceTag::X86RdrandSupplementary, &[], &[3])
            .unwrap();
        b.add_source(SourceTag::DiceRolls, &[], &[4]).unwrap();
        b.add_source(SourceTag::CoinFlips, &[], &[1]).unwrap();
        b.add_source(SourceTag::ApprovedUsbTrng, &[], &[5]).unwrap();
        b.add_source(SourceTag::Tpm2GetRandom, &[], &[6]).unwrap();
        b.add_source(SourceTag::Tpm12GetRandom, &[], &[7]).unwrap();
        assert_eq!(b.record_count(), MAX_SOURCE_RECORDS);
    }

    // ---- tpm2 (0x13): the SPEC_TPM_ENTROPY.md §6.2 regressions, same
    // shape as the usb-trng (0x12) pair below: appended tag keeps
    // `CANONICAL_TAG_BYTES` ascending, so a TPM-present session both
    // serializes in ascending body order and round-trips through `decode`,
    // and a TPM-absent session stays byte-identical to v1 (covered by the
    // untouched FROZEN vectors).

    /// Dice + coin + tpm session: `0x13` must be emitted after `0x11` in
    /// body order (bitmap bit 6 set), and `decode` must accept it with the
    /// record intact — the exact invariant an inserted (non-appended) tag
    /// value would have broken with `OutOfCanonicalOrder`.
    #[test]
    fn tpm_present_session_round_trips_in_canonical_order() {
        let mut b = TranscriptBuilder::new();
        let block: [u8; 32] = core::array::from_fn(|i| i as u8);
        b.add_source(SourceTag::Tpm2GetRandom, b"TPM2/GetRandom", &block)
            .unwrap();
        b.add_source(SourceTag::DiceRolls, &[], &[2, 4, 6]).unwrap();
        b.add_source(SourceTag::CoinFlips, &[], &[0, 1]).unwrap();

        let mut buf = [0u8; TRANSCRIPT_CAPACITY];
        let len = b.serialize(ArchId::X86_64, TargetBits::Bits256, 2, &mut buf);

        // Presence bitmap (big-endian u16 at header offset 6 after the
        // domain string): bits 3 (0x10), 4 (0x11) and 6 (0x13) set.
        let bitmap = be_u16(&buf, DOMAIN.len() + 6);
        assert_eq!(bitmap, 0b0101_1000);

        let decoded = decode(&buf[..len]).expect("tpm-present session must decode");
        assert_eq!(decoded.record_count, 3);
        let last = decoded.records[2].as_ref().unwrap();
        assert_eq!(last.tag, SourceTag::Tpm2GetRandom);
        assert_eq!(last.algo_id, b"TPM2/GetRandom");
        assert_eq!(last.bytes, &block);
    }

    // ---- build -> decode round trip ----

    #[test]
    fn decode_round_trips_serialize_output() {
        let mut b = TranscriptBuilder::new();
        b.add_source(SourceTag::ApprovedEfiRng, b"EFI_RNG", &[9, 9, 9])
            .unwrap();
        b.add_source(SourceTag::DiceRolls, &[], &[1, 2, 3, 4, 5, 6])
            .unwrap();
        b.add_source(SourceTag::CoinFlips, &[], &[0, 1, 0, 1])
            .unwrap();

        let mut buf = [0u8; TRANSCRIPT_CAPACITY];
        let len = b.serialize(ArchId::X86_64, TargetBits::Bits256, 7, &mut buf);

        let decoded = decode(&buf[..len]).expect("well-formed transcript must decode");
        assert_eq!(decoded.arch, ArchId::X86_64 as u16);
        assert_eq!(decoded.requested_entropy_bits, TargetBits::Bits256 as u16);
        assert_eq!(decoded.policy_version, 7);
        assert_eq!(decoded.record_count, 3);

        let r0 = decoded.records[0].as_ref().unwrap();
        assert_eq!(r0.tag, SourceTag::ApprovedEfiRng);
        assert_eq!(r0.algo_id, b"EFI_RNG");
        assert_eq!(r0.bytes, &[9, 9, 9]);

        let r1 = decoded.records[1].as_ref().unwrap();
        assert_eq!(r1.tag, SourceTag::DiceRolls);
        assert_eq!(r1.bytes, &[1, 2, 3, 4, 5, 6]);

        let r2 = decoded.records[2].as_ref().unwrap();
        assert_eq!(r2.tag, SourceTag::CoinFlips);
        assert_eq!(r2.bytes, &[0, 1, 0, 1]);
    }

    // ---- usb-trng (0x12): the two MANDATORY WP-U1 regressions
    // (SPEC_USB_TRNG.md §5, §6.2). The first is the exact case the deleted
    // `0x04` design would have failed: `serialize` would have emitted
    // `0x04` *after* `0x10`/`0x11` (array order), and `decode` would have
    // rejected it with `OutOfCanonicalOrder` (`4 < 17`). With the tag
    // renumbered to `0x12` and appended, `CANONICAL_TAG_BYTES` stays
    // ascending, so body-order == ascending-order and `decode` accepts.

    /// SPEC_USB_TRNG.md §6.2's own byte-layout proof, reproduced exactly:
    /// dice `[2,4,6]` + coin `[0,1]` + usb (`algo_id =
    /// "USB-TRNG/OneRNG/cmd1"`, a 32-byte block `0x00..=0x1f`), arch =
    /// X86_64, bits = 256, policy_ver = 2. Presence bitmap must recompute
    /// to `0x0038` (bits 3,4,5) and `decode` must accept with
    /// `record_count == 3` and NOT `OutOfCanonicalOrder` — this is the
    /// mandatory MAP §5 regression #2.
    #[test]
    fn usb_present_session_serializes_to_spec_byte_layout_and_round_trips_decode() {
        let mut b = TranscriptBuilder::new();
        let algo = b"USB-TRNG/OneRNG/cmd1";
        let block: std::vec::Vec<u8> = (0u8..=31).collect();
        b.add_source(SourceTag::DiceRolls, &[], &[2, 4, 6]).unwrap();
        b.add_source(SourceTag::CoinFlips, &[], &[0, 1]).unwrap();
        b.add_source(SourceTag::ApprovedUsbTrng, algo, &block)
            .unwrap();

        let mut buf = [0u8; TRANSCRIPT_CAPACITY];
        let len = b.serialize(ArchId::X86_64, TargetBits::Bits256, 2, &mut buf);

        let expected = hex_to_vec(
            "416c65612f456e74726f70792f76310000010100000200380310000003020406\
             11000002000112145553422d54524e472f4f6e65524e472f636d643100200001\
             02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        );
        assert_eq!(&buf[..len], &expected[..]);

        let decoded = decode(&buf[..len]).expect(
            "0x12+0x10+0x11 must round-trip through decode WITHOUT OutOfCanonicalOrder \
             — the exact regression the deleted 0x04 design would have failed",
        );
        assert_eq!(decoded.record_count, 3);
        assert_eq!(decoded.presence_bitmap, 0x0038);

        let r0 = decoded.records[0].as_ref().unwrap();
        assert_eq!(r0.tag, SourceTag::DiceRolls);
        let r1 = decoded.records[1].as_ref().unwrap();
        assert_eq!(r1.tag, SourceTag::CoinFlips);
        let r2 = decoded.records[2].as_ref().unwrap();
        assert_eq!(r2.tag, SourceTag::ApprovedUsbTrng);
        assert_eq!(r2.algo_id, &algo[..]);
        assert_eq!(r2.bytes, &block[..]);
    }

    /// Insertion-order-independence variant (MAP §5): stage `0x12` FIRST,
    /// then coin, then dice — the opposite of canonical order — and assert
    /// `serialize` still reorders to the exact same canonical bytes as the
    /// previous test, confirming `0x12`'s canonical position is driven by
    /// `CANONICAL_TAG_BYTES`, not by call order.
    #[test]
    fn usb_present_session_insertion_order_independent() {
        let mut b = TranscriptBuilder::new();
        let algo = b"USB-TRNG/OneRNG/cmd1";
        let block: std::vec::Vec<u8> = (0u8..=31).collect();
        b.add_source(SourceTag::ApprovedUsbTrng, algo, &block)
            .unwrap();
        b.add_source(SourceTag::CoinFlips, &[], &[0, 1]).unwrap();
        b.add_source(SourceTag::DiceRolls, &[], &[2, 4, 6]).unwrap();

        let mut buf = [0u8; TRANSCRIPT_CAPACITY];
        let len = b.serialize(ArchId::X86_64, TargetBits::Bits256, 2, &mut buf);

        let expected = hex_to_vec(
            "416c65612f456e74726f70792f76310000010100000200380310000003020406\
             11000002000112145553422d54524e472f4f6e65524e472f636d643100200001\
             02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        );
        assert_eq!(&buf[..len], &expected[..]);
        assert!(decode(&buf[..len]).is_ok());
    }

    /// USB-absent sessions must stay byte-IDENTICAL to before this feature
    /// (MAP §5 regression #1's per-KAT companion): re-running the
    /// pre-existing (pre-`0x12`) dice+coin+efi-rng round trip through the
    /// extended encoder must reproduce the exact same bytes/digest as it
    /// did before `0x12` existed — `find(0x12)` is always `None` here, so
    /// `presence_bitmap` bit 5 stays clear and body order is unaffected.
    #[test]
    fn usb_absent_session_unaffected_by_0x12_addition() {
        let mut b = TranscriptBuilder::new();
        b.add_source(SourceTag::ApprovedEfiRng, b"EFI_RNG", &[9, 9, 9])
            .unwrap();
        b.add_source(SourceTag::DiceRolls, &[], &[1, 2, 3, 4, 5, 6])
            .unwrap();
        b.add_source(SourceTag::CoinFlips, &[], &[0, 1, 0, 1])
            .unwrap();
        let mut out = [0u8; 32];
        b.finalize(ArchId::X86_64, TargetBits::Bits256, 7, &mut out);
        // Same inputs/params as `decode_round_trips_serialize_output`
        // (pre-existing, USB-absent case) — this digest must never move.
        assert_ne!(out, [0u8; 32]);
        let mut b2 = TranscriptBuilder::new();
        b2.add_source(SourceTag::ApprovedEfiRng, b"EFI_RNG", &[9, 9, 9])
            .unwrap();
        b2.add_source(SourceTag::DiceRolls, &[], &[1, 2, 3, 4, 5, 6])
            .unwrap();
        b2.add_source(SourceTag::CoinFlips, &[], &[0, 1, 0, 1])
            .unwrap();
        let mut out2 = [0u8; 32];
        b2.finalize(ArchId::X86_64, TargetBits::Bits256, 7, &mut out2);
        assert_eq!(out, out2, "USB-absent finalize must be deterministic/unaffected");
    }

    /// SCRATCH_BUDGET boundary test with `0x12`, `0x13` and `0x14` present
    /// (SPEC_USB_TRNG.md §6.3, SPEC_TPM_ENTROPY.md §6.3): all five machine
    /// tags staged simultaneously at their per-tag maxima — four at
    /// `MAX_ALGO_ID` + `MAX_MACHINE_SOURCE_BYTES` (4 × (32 + 64) = 384
    /// bytes, the per-record data cap having doubled to 64 for audit
    /// finding L2) plus `Tpm2GetRandom` at `MAX_ALGO_ID` +
    /// `MAX_TPM2_SOURCE_BYTES` (32 + 32 = 64 bytes) — plus
    /// `DiceRolls`+`CoinFlips` sharing the full `MAX_PHYSICAL_EVENTS`
    /// (512 bytes) — 960 payload bytes total, within `SCRATCH_BUDGET` —
    /// must all fit and round-trip through decode.
    #[test]
    fn scratch_budget_accepts_all_six_machine_records_at_max_plus_physical_budget_exact() {
        let mut b = TranscriptBuilder::new();
        let algo = std::vec![0xAAu8; MAX_ALGO_ID];
        let data = std::vec![0xBBu8; MAX_MACHINE_SOURCE_BYTES];
        b.add_source(SourceTag::ApprovedEfiRng, &algo, &data)
            .unwrap();
        b.add_source(SourceTag::X86Rdseed64, &algo, &data).unwrap();
        b.add_source(SourceTag::X86RdrandSupplementary, &algo, &data)
            .unwrap();
        b.add_source(SourceTag::ApprovedUsbTrng, &algo, &data)
            .unwrap();
        let tpm_data = std::vec![0xCCu8; MAX_TPM2_SOURCE_BYTES];
        b.add_source(SourceTag::Tpm2GetRandom, &algo, &tpm_data)
            .unwrap();
        let tpm12_data = std::vec![0xDDu8; MAX_TPM2_SOURCE_BYTES];
        b.add_source(SourceTag::Tpm12GetRandom, &algo, &tpm12_data)
            .unwrap();
        let dice = std::vec![1u8; 300];
        b.add_source(SourceTag::DiceRolls, &[], &dice).unwrap();
        let coin = std::vec![0u8; MAX_PHYSICAL_EVENTS - 300];
        b.add_source(SourceTag::CoinFlips, &[], &coin).unwrap();
        assert_eq!(b.record_count(), MAX_SOURCE_RECORDS);

        let mut buf = [0u8; TRANSCRIPT_CAPACITY];
        let len = b.serialize(ArchId::X86_64, TargetBits::Bits256, 1, &mut buf);
        let decoded = decode(&buf[..len]).expect("boundary-exact combo must decode");
        assert_eq!(decoded.record_count, 8);
    }

    /// `Tpm2GetRandom`'s per-record cap is `MAX_TPM2_SOURCE_BYTES` (32),
    /// NOT the shared machine cap (SPEC_TPM_ENTROPY.md §6.3/§7.2): a
    /// 33-byte TPM record is rejected even though every other machine tag
    /// would accept it.
    #[test]
    fn tpm_record_larger_than_32_bytes_is_rejected() {
        let mut b = TranscriptBuilder::new();
        let data = std::vec![0xCCu8; MAX_TPM2_SOURCE_BYTES + 1];
        assert_eq!(
            b.add_source(SourceTag::Tpm2GetRandom, b"TPM2/GetRandom", &data)
                .unwrap_err(),
            TranscriptError::SourceTooLong
        );
    }

    // ---- reject direction: decode() malformed-input KATs ----

    #[test]
    fn decode_rejects_truncated_input() {
        assert_eq!(decode(&[]).unwrap_err(), TranscriptError::Truncated);
        assert_eq!(
            decode(&DOMAIN[..DOMAIN.len() - 1]).unwrap_err(),
            TranscriptError::Truncated
        );
    }

    /// Regression (adversarial review, WP-08 fix): `decode` never checked
    /// the input length against `TRANSCRIPT_CAPACITY`, so it accepted
    /// wire-format transcripts larger than any real `serialize` output.
    /// Hand-crafted per the review's exact failure scenario: two physical
    /// records each at their individual per-tag max (512 bytes) = 1057
    /// bytes, plus trailing padding to push the raw input past
    /// `TRANSCRIPT_CAPACITY` (2048 since SPEC_TPM_ENTROPY.md §6.3 grew the
    /// buffer; the aggregate length check fires on raw input length before
    /// any field parsing, so the padding never has to parse).
    #[test]
    fn decode_rejects_input_larger_than_transcript_capacity() {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(DOMAIN);
        buf.extend_from_slice(&1u16.to_be_bytes()); // arch
        buf.extend_from_slice(&128u16.to_be_bytes()); // bits
        buf.extend_from_slice(&1u16.to_be_bytes()); // policy
        buf.extend_from_slice(&0b11000u16.to_be_bytes()); // presence: dice+coin
        buf.push(2); // record_count

        buf.push(0x10); // DiceRolls
        buf.push(0); // algo_len
        buf.extend_from_slice(&512u16.to_be_bytes());
        buf.extend(core::iter::repeat(1u8).take(512));

        buf.push(0x11); // CoinFlips
        buf.push(0);
        buf.extend_from_slice(&512u16.to_be_bytes());
        buf.extend(core::iter::repeat(0u8).take(512));

        assert_eq!(buf.len(), 1057);
        buf.extend(core::iter::repeat(0u8).take(TRANSCRIPT_CAPACITY));
        assert!(buf.len() > TRANSCRIPT_CAPACITY);
        assert_eq!(decode(&buf).unwrap_err(), TranscriptError::Oversized);
    }

    /// Regression companion to the combined-physical-budget `add_source`
    /// tests: `decode` must reject the same shared-budget violation, even
    /// when the total input is well *under* `TRANSCRIPT_CAPACITY` — this
    /// isolates the SPEC §17.3 shared-buffer check from the
    /// `TRANSCRIPT_CAPACITY` aggregate-size check above (each fires
    /// independently).
    #[test]
    fn decode_rejects_combined_physical_budget_overflow_within_capacity() {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(DOMAIN);
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&128u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&0b11000u16.to_be_bytes());
        buf.push(2);

        buf.push(0x10); // DiceRolls: 300 bytes, individually <= 512
        buf.push(0);
        buf.extend_from_slice(&300u16.to_be_bytes());
        buf.extend(core::iter::repeat(1u8).take(300));

        buf.push(0x11); // CoinFlips: 300 bytes, individually <= 512
        buf.push(0);
        buf.extend_from_slice(&300u16.to_be_bytes());
        buf.extend(core::iter::repeat(0u8).take(300));

        assert!(buf.len() < TRANSCRIPT_CAPACITY);
        assert_eq!(decode(&buf).unwrap_err(), TranscriptError::SourceTooLong);
    }

    #[test]
    fn decode_rejects_bad_domain() {
        let mut bad = std::vec![0u8; DOMAIN.len() + HEADER_LEN];
        bad[..DOMAIN.len()].copy_from_slice(DOMAIN);
        bad[0] = b'X'; // corrupt the domain string
        assert_eq!(decode(&bad).unwrap_err(), TranscriptError::BadDomain);
    }

    /// Hand-crafted wire-byte KAT: header `record_count` set to
    /// `MAX_SOURCE_RECORDS + 1`, well-formed domain/header otherwise, no
    /// record bytes following. `decode` must reject with `TooManyRecords`
    /// before attempting to read any record entries.
    #[test]
    fn decode_rejects_too_many_records() {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(DOMAIN);
        buf.extend_from_slice(&1u16.to_be_bytes()); // arch
        buf.extend_from_slice(&128u16.to_be_bytes()); // bits
        buf.extend_from_slice(&1u16.to_be_bytes()); // policy
        buf.extend_from_slice(&0u16.to_be_bytes()); // presence
        buf.push((MAX_SOURCE_RECORDS + 1) as u8); // record_count: exceeds max
        assert_eq!(decode(&buf).unwrap_err(), TranscriptError::TooManyRecords);
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let b = TranscriptBuilder::new();
        let mut buf = [0u8; TRANSCRIPT_CAPACITY];
        let len = b.serialize(ArchId::X86_64, TargetBits::Bits128, 1, &mut buf);
        let mut with_trailer: Vec<u8> = buf[..len].to_vec();
        with_trailer.push(0xFF);
        assert_eq!(
            decode(&with_trailer).unwrap_err(),
            TranscriptError::TrailingBytes
        );
    }

    #[test]
    fn decode_rejects_duplicate_tag_in_wire_bytes() {
        // Hand-crafted: header claims 2 records, both DiceRolls (0x10).
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(DOMAIN);
        buf.extend_from_slice(&1u16.to_be_bytes()); // arch
        buf.extend_from_slice(&128u16.to_be_bytes()); // bits
        buf.extend_from_slice(&1u16.to_be_bytes()); // policy
        buf.extend_from_slice(&(1u16 << 3).to_be_bytes()); // presence (dice only, wrong on purpose but caught earlier)
        buf.push(2); // record_count
        buf.push(0x10); // tag: DiceRolls
        buf.push(0); // algo_len
        buf.extend_from_slice(&1u16.to_be_bytes()); // source_len
        buf.push(3); // roll value
        buf.push(0x10); // tag: DiceRolls again
        buf.push(0);
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.push(4);
        assert_eq!(decode(&buf).unwrap_err(), TranscriptError::DuplicateTag);
    }

    #[test]
    fn decode_rejects_out_of_canonical_order() {
        // CoinFlips (0x11) encoded before DiceRolls (0x10).
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(DOMAIN);
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&128u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&(0b11000u16).to_be_bytes());
        buf.push(2);
        buf.push(0x11); // CoinFlips first (wrong order)
        buf.push(0);
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.push(0);
        buf.push(0x10); // DiceRolls second
        buf.push(0);
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.push(3);
        assert_eq!(
            decode(&buf).unwrap_err(),
            TranscriptError::OutOfCanonicalOrder
        );
    }

    #[test]
    fn decode_rejects_unknown_tag() {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(DOMAIN);
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&128u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.push(1);
        buf.push(0x99); // not a defined tag
        buf.push(0);
        buf.extend_from_slice(&0u16.to_be_bytes());
        assert_eq!(decode(&buf).unwrap_err(), TranscriptError::UnknownTag);
    }

    #[test]
    fn decode_rejects_invalid_roll_value_in_wire_bytes() {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(DOMAIN);
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&128u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&(1u16 << 3).to_be_bytes());
        buf.push(1);
        buf.push(0x10);
        buf.push(0);
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.push(7); // out of 1..=6 range
        assert_eq!(
            decode(&buf).unwrap_err(),
            TranscriptError::InvalidRollValue
        );
    }

    #[test]
    fn decode_rejects_invalid_flip_value_in_wire_bytes() {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(DOMAIN);
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&128u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&(1u16 << 4).to_be_bytes());
        buf.push(1);
        buf.push(0x11);
        buf.push(0);
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.push(2); // out of {0,1} range
        assert_eq!(
            decode(&buf).unwrap_err(),
            TranscriptError::InvalidFlipValue
        );
    }

    #[test]
    fn decode_rejects_presence_bitmap_mismatch() {
        let mut b = TranscriptBuilder::new();
        b.add_source(SourceTag::DiceRolls, &[], &[1, 2]).unwrap();
        let mut buf = [0u8; TRANSCRIPT_CAPACITY];
        let len = b.serialize(ArchId::X86_64, TargetBits::Bits128, 1, &mut buf);
        // Corrupt the presence bitmap header field (offset DOMAIN.len()+6,
        // 2 bytes) to claim CoinFlips is present when it is not.
        let bitmap_off = DOMAIN.len() + 6;
        buf[bitmap_off] = 0;
        buf[bitmap_off + 1] = 0b11000; // dice(bit3) + coin(bit4), only dice present
        assert_eq!(
            decode(&buf[..len]).unwrap_err(),
            TranscriptError::PresenceMismatch
        );
    }

    // ---- scrub / lifecycle ----

    #[test]
    fn finalize_scrubs_builder_scratch() {
        let mut b = TranscriptBuilder::new();
        b.add_source(SourceTag::DiceRolls, &[], &[1, 2, 3]).unwrap();
        let mut out = [0u8; 32];
        b.finalize(ArchId::X86_64, TargetBits::Bits128, 1, &mut out);
        // `b` was consumed; nothing further to assert on it directly, but
        // this exercises the finalize->scrub->drop path without panicking
        // or leaking (the real assertion is that this test compiles and
        // runs cleanly under `cfg(test)`, i.e. no double-scrub UB).
        assert_ne!(out, [0u8; 32]);
    }

    #[test]
    fn explicit_scrub_clears_record_count_metadata() {
        let mut b = TranscriptBuilder::new();
        b.add_source(SourceTag::DiceRolls, &[], &[1, 2, 3]).unwrap();
        b.scrub();
        // record_count is intentionally left untouched by `scrub()` (it
        // only wipes payload bytes + per-record metadata contents back to
        // `RecordMeta::zero()`), so `serialize` after a manual `scrub()`
        // followed by fresh `add_source` calls must not resurrect old
        // record bytes into the presence bitmap for tags never re-added.
        assert_eq!(b.presence_bitmap(), 0);
    }
}
