//! Machine-source entropy records (WP-24, SPEC §15, §19.1).
//!
//! [`SourceRecord`] is this module's output shape: exactly the
//! `(tag, algo_id, bytes)` triple `seed_protocol::transcript::
//! TranscriptBuilder::add_source` accepts (SPEC §19.1), packaged so a
//! caller can hold one before it is staged into the transcript.
//!
//! `bytes` is raw machine-entropy output. In machine-only mode (SPEC
//! §18.2) it becomes part of the final mnemonic entropy after nothing
//! more than a domain-separated SHA-256 reduction, so it is treated as
//! secret from the moment it is sampled (SPEC §13, §20.2): no
//! `Copy`/`Clone`/`Debug`/`Display`/serialization, and an explicit,
//! volatile-write [`SourceRecord::scrub`] that also runs on `Drop`.

use seed_core::contracts::{SourceTag, MAX_ALGO_ID, MAX_MACHINE_SOURCE_BYTES};

use super::util::scrub;

/// One machine-entropy source record, ready to hand to
/// `TranscriptBuilder::add_source(record.tag(), record.algo_id(),
/// record.bytes())` (SPEC §19.1).
///
/// Deliberately does not implement `Copy`, `Clone`, `Debug`, `Display` or
/// any serialization trait (SPEC §13, §20.2) — see the module doc.
pub struct SourceRecord {
    tag: SourceTag,
    algo_id: [u8; MAX_ALGO_ID],
    algo_id_len: u8,
    bytes: [u8; MAX_MACHINE_SOURCE_BYTES],
    bytes_len: u8,
}

impl SourceRecord {
    /// Builds a record from caller-owned slices, copying both into fixed
    /// internal buffers. Returns `None` if either slice exceeds this
    /// record's fixed capacity (`MAX_ALGO_ID` / `MAX_MACHINE_SOURCE_BYTES`
    /// — the same bounds `TranscriptBuilder::add_source` itself enforces,
    /// checked again here so a driver bug fails at construction, not
    /// silently at transcript time).
    pub(crate) fn new(tag: SourceTag, algo_id: &[u8], bytes: &[u8]) -> Option<Self> {
        if algo_id.len() > MAX_ALGO_ID || bytes.len() > MAX_MACHINE_SOURCE_BYTES {
            return None;
        }
        let mut record = SourceRecord {
            tag,
            algo_id: [0u8; MAX_ALGO_ID],
            algo_id_len: algo_id.len() as u8,
            bytes: [0u8; MAX_MACHINE_SOURCE_BYTES],
            bytes_len: bytes.len() as u8,
        };
        record.algo_id[..algo_id.len()].copy_from_slice(algo_id);
        record.bytes[..bytes.len()].copy_from_slice(bytes);
        Some(record)
    }

    /// The canonical entropy-source tag (SPEC §19.1) this record must be
    /// staged under.
    pub fn tag(&self) -> SourceTag {
        self.tag
    }

    /// The algorithm-identifier bytes (SPEC §19.1: `algorithm_identifier`
    /// — an EFI RNG GUID rendered as text, or a fixed ASCII literal like
    /// `"RDSEED64"`/`"RDRAND"`). Not secret; identifies the mechanism,
    /// never the sampled value.
    pub fn algo_id(&self) -> &[u8] {
        &self.algo_id[..self.algo_id_len as usize]
    }

    /// The raw sampled entropy bytes (SPEC §19.1: `source_bytes`).
    /// Secret — see the module doc.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.bytes_len as usize]
    }

    /// Explicitly wipes both buffers with volatile writes (SPEC §13,
    /// §20.3). Idempotent; also invoked by `Drop`, so calling it early
    /// (e.g. on an error path that discards the record without staging
    /// it) is always safe and never double-frees anything.
    pub fn scrub(&mut self) {
        scrub(&mut self.algo_id);
        scrub(&mut self.bytes);
        self.algo_id_len = 0;
        self.bytes_len = 0;
    }
}

impl Drop for SourceRecord {
    fn drop(&mut self) {
        self.scrub();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_tag_algo_id_and_bytes() {
        let record = SourceRecord::new(SourceTag::X86Rdseed64, b"RDSEED64", &[0x11u8; 32])
            .expect("fits within fixed capacity");
        assert_eq!(record.tag(), SourceTag::X86Rdseed64);
        assert_eq!(record.algo_id(), b"RDSEED64");
        assert_eq!(record.bytes(), &[0x11u8; 32]);
    }

    #[test]
    fn rejects_algo_id_over_capacity() {
        let too_long = [b'a'; MAX_ALGO_ID + 1];
        assert!(SourceRecord::new(SourceTag::X86Rdseed64, &too_long, &[0u8; 4]).is_none());
    }

    #[test]
    fn rejects_bytes_over_capacity() {
        let too_long = [0u8; MAX_MACHINE_SOURCE_BYTES + 1];
        assert!(SourceRecord::new(SourceTag::X86Rdseed64, b"RDSEED64", &too_long).is_none());
    }

    #[test]
    fn scrub_zeroes_and_empties_both_buffers() {
        let mut record = SourceRecord::new(SourceTag::X86RdrandSupplementary, b"RDRAND", &[0xAAu8; 32])
            .unwrap();
        record.scrub();
        assert_eq!(record.algo_id(), b"");
        assert_eq!(record.bytes(), b"");
        assert_eq!(record.algo_id, [0u8; MAX_ALGO_ID]);
        assert_eq!(record.bytes, [0u8; MAX_MACHINE_SOURCE_BYTES]);
    }

    #[test]
    fn drop_scrubs_without_panicking() {
        // Cannot observe freed memory safely; this only proves Drop runs
        // cleanly (scrub() is idempotent, called again by Drop after the
        // explicit call above in other tests).
        let record = SourceRecord::new(SourceTag::ApprovedEfiRng, b"algo", &[1u8; 4]).unwrap();
        drop(record);
    }
}
