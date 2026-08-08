//! Deterministic GPT + EFI System Partition boot-media image builder.
//!
//! SPEC §10 step 5 ("Write the complete disk image to removable media")
//! and SPEC §32 ("deterministic USB image before external signing
//! effects") require that the published `.img` artifact be reproducible
//! byte-for-byte across independent build machines, AND (real-hardware
//! finding, 2026-08-06 OEM laptop test) be an image real UEFI firmware
//! will actually register as a boot option. This module hand-rolls a
//! minimal FAT16 filesystem containing exactly one file at the standard
//! removable-media boot path `\EFI\BOOT\BOOTX64.EFI` (SPEC §5 "Standard
//! removable-media boot path") — [`build_esp_volume`] — and wraps it in a
//! standard protective-MBR + GPT disk as its sole EFI System Partition —
//! [`build_image`], the crate's public entry point.
//!
//! ## Why GPT+ESP, not a bare FAT16 "superfloppy"
//!
//! An earlier version of this tool emitted `build_esp_volume`'s FAT16
//! bytes directly as the whole-disk image (no partition table at all — a
//! "superfloppy" layout some firmware tolerates). The real OEM laptop
//! used for hardware validation did NOT enumerate that image as a UEFI
//! boot option at all; only a proper protective-MBR + GPT + single EFI
//! System Partition (type GUID `C12A7328-F81F-11D2-BA4B-00A0C93EC93B`)
//! image was accepted ("Boot Option Restored"), and the identical FAT
//! contents booted correctly from inside that layout in both QEMU+OVMF
//! and on that OEM laptop. [`build_image`] now always emits that layout.
//!
//! ## Why a hand-rolled FAT16 writer instead of a crate
//!
//! There is no `no_std`-reviewed, minimal, write-only FAT crate pinned in
//! the SPEC §3 dependency table, and this tool is a release-engineering
//! artifact whose output bytes are part of the security-relevant
//! reproducibility story (SPEC §32) — every byte it emits should be
//! traceable to code in this repository, not to an external crate's
//! internal layout choices (padding, timestamp defaults, cluster-size
//! heuristics) that could silently change between versions and break
//! byte-for-byte reproducibility. The on-disk structure needed is small
//! and fixed (one file, two subdirectories, no long file names, no
//! fragmentation), so a hand-rolled writer is both simpler to review and
//! more directly deterministic than pulling in a general-purpose crate.
//! This is documented per the work-package instructions as the chosen
//! alternative to "a small well-reviewed crate." The same rationale
//! extends to the GPT/MBR wrapper added here: a hand-rolled protective
//! MBR, GPT header/entry-array pair, and CRC32 (~12 lines, IEEE 802.3
//! polynomial) keep every emitted byte traceable to this file rather
//! than to an external partitioning crate's own choices.
//!
//! All timestamps, volume metadata, and padding bytes are fixed constants
//! so that two independent builds from the same input `.efi` file produce
//! byte-identical images (SPEC §32 gate, IMPLEMENTATION_MAP.md Wave 5:
//! "Deterministic image hash ×2 builds"). The two GPT GUIDs that would
//! normally be random (disk GUID, ESP partition GUID) are instead a
//! pure function of the SHA-256 of `payload`'s bytes (see
//! [`guid_from_hash`]) with the RFC 4122 version/variant bits forced —
//! deterministic across two builds of the same input, while distinct
//! releases (distinct loader bytes) still get distinct GUIDs.

pub mod denylist;
pub mod entropy_policy_export;
pub mod license_inventory;
pub mod sbom;

use std::io;

/// Bytes per sector. Fixed at the standard value for maximum firmware
/// compatibility (SPEC §5 boot path support).
const SECTOR_SIZE: usize = 512;
/// Sectors per cluster. `1` keeps the layout simple (cluster == sector)
/// while still yielding a large enough cluster count to be unambiguously
/// classified as FAT16 by any BPB-parsing firmware (see [`FatType`]
/// selection logic in `plan_layout`).
const SECTORS_PER_CLUSTER: u8 = 1;
/// Reserved sectors before the first FAT (just the boot sector itself).
const RESERVED_SECTORS: u16 = 1;
/// Standard two-FAT redundancy.
const NUM_FATS: u8 = 2;
/// Root directory entries. `512` is the conventional FAT16 default and
/// yields a whole number of sectors (512 * 32 / 512 = 32 sectors).
const ROOT_ENTRIES: u16 = 512;
const ROOT_DIR_SECTORS: u16 = (ROOT_ENTRIES as u32 * 32 / SECTOR_SIZE as u32) as u16;
/// Minimum data-region cluster count required for firmware to classify
/// the volume as FAT16 rather than FAT12 (Microsoft FAT spec threshold).
const MIN_FAT16_CLUSTERS: u32 = 4085;
/// Maximum data-region cluster count for FAT16 (exclusive upper bound is
/// FAT32 territory).
const MAX_FAT16_CLUSTERS: u32 = 65524;

/// Fixed FAT directory-entry date: 2026-01-01 (SPEC §32 determinism —
/// every build must emit the same timestamp regardless of build wall
/// clock).
const FIXED_FAT_DATE: u16 = fat_date(2026, 1, 1);
/// Fixed FAT directory-entry time: 00:00:00.
const FIXED_FAT_TIME: u16 = 0;
/// Fixed volume serial number (any constant works; must never vary
/// between builds).
const FIXED_VOLUME_ID: u32 = 0x5EED_F00D;
const VOLUME_LABEL: &[u8; 11] = b"ALEA       ";

const fn fat_date(year: u16, month: u16, day: u16) -> u16 {
    (((year - 1980) & 0x7F) << 9) | ((month & 0x0F) << 5) | (day & 0x1F)
}

/// Cluster index used as the FAT end-of-chain marker (FAT16).
const FAT16_EOC: u16 = 0xFFFF;
/// First two reserved FAT entries (media descriptor + EOC), per spec.
const FAT16_RESERVED0: u16 = 0xFFF8;
const FAT16_RESERVED1: u16 = 0xFFFF;

/// Errors surfaced by [`build_image`].
#[derive(Debug)]
pub enum ImageBuildError {
    /// The input `.efi` payload was empty.
    EmptyPayload,
    /// The input `.efi` payload is too large to address with FAT16
    /// cluster arithmetic used here (would need FAT32).
    PayloadTooLarge,
    Io(io::Error),
}

impl std::fmt::Display for ImageBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImageBuildError::EmptyPayload => write!(f, "input EFI payload is empty"),
            ImageBuildError::PayloadTooLarge => {
                write!(f, "input EFI payload exceeds FAT16 image capacity")
            }
            ImageBuildError::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for ImageBuildError {}

impl From<io::Error> for ImageBuildError {
    fn from(e: io::Error) -> Self {
        ImageBuildError::Io(e)
    }
}

/// Layout parameters derived from the payload size. All derivation is a
/// pure function of `payload_len`, which is what makes the output
/// deterministic (SPEC §32).
struct Layout {
    fat_size_sectors: u32,
    data_clusters: u32,
    total_sectors: u32,
}

fn plan_layout(payload_len: usize) -> Result<Layout, ImageBuildError> {
    let cluster_bytes = SECTOR_SIZE * SECTORS_PER_CLUSTER as usize;
    let file_clusters = (payload_len + cluster_bytes - 1) / cluster_bytes;
    // 2 fixed single-cluster directories (\EFI, \EFI\BOOT) + file clusters.
    let needed = 2u32 + file_clusters as u32;
    let data_clusters = needed.max(MIN_FAT16_CLUSTERS);
    if data_clusters > MAX_FAT16_CLUSTERS {
        return Err(ImageBuildError::PayloadTooLarge);
    }
    // FAT16: 2 bytes/entry, +2 reserved entries (0 and 1).
    let fat_bytes = (data_clusters as u64 + 2) * 2;
    let fat_size_sectors = ((fat_bytes + SECTOR_SIZE as u64 - 1) / SECTOR_SIZE as u64) as u32;
    let total_sectors = RESERVED_SECTORS as u32
        + NUM_FATS as u32 * fat_size_sectors
        + ROOT_DIR_SECTORS as u32
        + data_clusters * SECTORS_PER_CLUSTER as u32;
    Ok(Layout {
        fat_size_sectors,
        data_clusters,
        total_sectors,
    })
}

/// Dual-file variant of [`plan_layout`] (SPEC_MAIN_MENU.md §17.4): the
/// data region holds THREE fixed single-cluster directories (`\EFI`,
/// `\EFI\BOOT`, `\EFI\ALEA`) plus BOTH files' clusters (the boot loader at
/// `\EFI\BOOT\BOOTX64.EFI` and the separate verifier at
/// `\EFI\ALEA\VERIFY.EFI`). The single-file [`plan_layout`] is left
/// untouched so its output — and thus `build_esp_volume`/`build_image`'s
/// frozen bytes — never changes.
///
/// Determinism (SPEC §32) is preserved: every derived value is a pure
/// function of the two payload lengths.
fn plan_layout_dual(boot_len: usize, verify_len: usize) -> Result<Layout, ImageBuildError> {
    let cluster_bytes = SECTOR_SIZE * SECTORS_PER_CLUSTER as usize;
    let boot_clusters = (boot_len + cluster_bytes - 1) / cluster_bytes;
    let verify_clusters = (verify_len + cluster_bytes - 1) / cluster_bytes;
    // 3 fixed single-cluster directories (\EFI, \EFI\BOOT, \EFI\ALEA) +
    // both files' clusters.
    let needed = 3u32 + boot_clusters as u32 + verify_clusters as u32;
    let data_clusters = needed.max(MIN_FAT16_CLUSTERS);
    if data_clusters > MAX_FAT16_CLUSTERS {
        return Err(ImageBuildError::PayloadTooLarge);
    }
    // FAT16: 2 bytes/entry, +2 reserved entries (0 and 1).
    let fat_bytes = (data_clusters as u64 + 2) * 2;
    let fat_size_sectors = ((fat_bytes + SECTOR_SIZE as u64 - 1) / SECTOR_SIZE as u64) as u32;
    let total_sectors = RESERVED_SECTORS as u32
        + NUM_FATS as u32 * fat_size_sectors
        + ROOT_DIR_SECTORS as u32
        + data_clusters * SECTORS_PER_CLUSTER as u32;
    Ok(Layout {
        fat_size_sectors,
        data_clusters,
        total_sectors,
    })
}

/// Formats an 8.3 short filename component (name, extension) into the
/// fixed 11-byte directory-entry field, space-padded.
fn short_name(name: &str, ext: &str) -> [u8; 11] {
    let mut buf = [b' '; 11];
    for (i, b) in name.as_bytes().iter().take(8).enumerate() {
        buf[i] = *b;
    }
    for (i, b) in ext.as_bytes().iter().take(3).enumerate() {
        buf[8 + i] = *b;
    }
    buf
}

/// Writes one 32-byte FAT directory entry.
#[allow(clippy::too_many_arguments)]
fn write_dir_entry(
    out: &mut [u8],
    off: usize,
    name: [u8; 11],
    attr: u8,
    first_cluster: u16,
    file_size: u32,
) {
    out[off..off + 11].copy_from_slice(&name);
    out[off + 11] = attr;
    out[off + 12] = 0; // reserved (NT case flags)
    out[off + 13] = 0; // create time, tenths
    out[off + 14..off + 16].copy_from_slice(&FIXED_FAT_TIME.to_le_bytes());
    out[off + 16..off + 18].copy_from_slice(&FIXED_FAT_DATE.to_le_bytes());
    out[off + 18..off + 20].copy_from_slice(&FIXED_FAT_DATE.to_le_bytes()); // last access date
    out[off + 20..off + 22].copy_from_slice(&0u16.to_le_bytes()); // first cluster hi (FAT16: always 0)
    out[off + 22..off + 24].copy_from_slice(&FIXED_FAT_TIME.to_le_bytes()); // write time
    out[off + 24..off + 26].copy_from_slice(&FIXED_FAT_DATE.to_le_bytes()); // write date
    out[off + 26..off + 28].copy_from_slice(&first_cluster.to_le_bytes());
    out[off + 28..off + 32].copy_from_slice(&file_size.to_le_bytes());
}

const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_ARCHIVE: u8 = 0x20;

/// Builds a deterministic FAT16 volume containing `payload` at
/// `\EFI\BOOT\BOOTX64.EFI` (SPEC §5 standard removable-media boot path),
/// returning the raw volume bytes. This is the sole EFI System Partition
/// contents [`build_image`] wraps in a GPT disk; it is also exposed
/// directly so tests (and any future consumer) can byte-compare it
/// against the ESP slice of a full built image.
///
/// Determinism (SPEC §32): the output is a pure function of `payload`'s
/// bytes and length only — no wall-clock timestamps, random IDs, or
/// filesystem-order-dependent traversal are involved.
pub fn build_esp_volume(payload: &[u8]) -> Result<Vec<u8>, ImageBuildError> {
    if payload.is_empty() {
        return Err(ImageBuildError::EmptyPayload);
    }
    let layout = plan_layout(payload.len())?;
    let total_bytes = layout.total_sectors as usize * SECTOR_SIZE;
    let mut img = vec![0u8; total_bytes];

    write_boot_sector(&mut img, &layout);

    let fat_start = RESERVED_SECTORS as usize * SECTOR_SIZE;
    let fat_size_bytes = layout.fat_size_sectors as usize * SECTOR_SIZE;
    let root_dir_start = fat_start + NUM_FATS as usize * fat_size_bytes;
    let data_start = root_dir_start + ROOT_DIR_SECTORS as usize * SECTOR_SIZE;
    let cluster_bytes = SECTOR_SIZE * SECTORS_PER_CLUSTER as usize;

    // Cluster numbering: data clusters start at 2 (FAT convention).
    let efi_dir_cluster: u16 = 2;
    let boot_dir_cluster: u16 = 3;
    let file_start_cluster: u16 = 4;
    let file_clusters = (payload.len() + cluster_bytes - 1) / cluster_bytes;

    // --- FAT table (write identically into both copies) ---
    let mut fat = vec![0u8; fat_size_bytes];
    write_fat16_entry(&mut fat, 0, FAT16_RESERVED0);
    write_fat16_entry(&mut fat, 1, FAT16_RESERVED1);
    write_fat16_entry(&mut fat, efi_dir_cluster as usize, FAT16_EOC);
    write_fat16_entry(&mut fat, boot_dir_cluster as usize, FAT16_EOC);
    for i in 0..file_clusters {
        let cluster = file_start_cluster as usize + i;
        let next = if i + 1 == file_clusters {
            FAT16_EOC
        } else {
            (cluster + 1) as u16
        };
        write_fat16_entry(&mut fat, cluster, next);
    }
    img[fat_start..fat_start + fat_size_bytes].copy_from_slice(&fat);
    img[fat_start + fat_size_bytes..fat_start + 2 * fat_size_bytes].copy_from_slice(&fat);

    // --- Root directory: single entry "EFI" (directory) ---
    {
        let off = root_dir_start;
        write_dir_entry(
            &mut img,
            off,
            short_name("EFI", ""),
            ATTR_DIRECTORY,
            efi_dir_cluster,
            0,
        );
    }

    // --- \EFI directory cluster: ".", "..", "BOOT" ---
    {
        let cluster_off = data_start + (efi_dir_cluster as usize - 2) * cluster_bytes;
        write_dir_entry(&mut img, cluster_off, short_name(".", ""), ATTR_DIRECTORY, efi_dir_cluster, 0);
        write_dir_entry(&mut img, cluster_off + 32, short_name("..", ""), ATTR_DIRECTORY, 0, 0);
        write_dir_entry(
            &mut img,
            cluster_off + 64,
            short_name("BOOT", ""),
            ATTR_DIRECTORY,
            boot_dir_cluster,
            0,
        );
    }

    // --- \EFI\BOOT directory cluster: ".", "..", "BOOTX64.EFI" ---
    {
        let cluster_off = data_start + (boot_dir_cluster as usize - 2) * cluster_bytes;
        write_dir_entry(&mut img, cluster_off, short_name(".", ""), ATTR_DIRECTORY, boot_dir_cluster, 0);
        write_dir_entry(
            &mut img,
            cluster_off + 32,
            short_name("..", ""),
            ATTR_DIRECTORY,
            efi_dir_cluster,
            0,
        );
        write_dir_entry(
            &mut img,
            cluster_off + 64,
            short_name("BOOTX64", "EFI"),
            ATTR_ARCHIVE,
            file_start_cluster,
            payload.len() as u32,
        );
    }

    // --- File data ---
    {
        let file_data_off = data_start + (file_start_cluster as usize - 2) * cluster_bytes;
        img[file_data_off..file_data_off + payload.len()].copy_from_slice(payload);
        // Remaining bytes in the final cluster are already zero-filled
        // (deterministic padding) from the `vec![0u8; ...]` allocation.
    }

    let _ = layout.data_clusters; // used above via layout fields already
    Ok(img)
}

/// Dual-file variant of [`build_esp_volume`] (SPEC_MAIN_MENU.md §17.4):
/// builds a deterministic FAT16 volume containing BOTH the boot loader at
/// `\EFI\BOOT\BOOTX64.EFI` (SPEC §5 standard removable-media boot path)
/// AND the separate verifier at `\EFI\ALEA\VERIFY.EFI` — the ESP contents
/// [`build_image_with_verify`] wraps in a GPT disk so the production
/// landing launcher's Verify item can chain-load the verifier.
///
/// The single-file [`build_esp_volume`] is deliberately left byte-frozen;
/// this parallel function adds a third single-cluster directory (`\EFI\ALEA`)
/// and the verifier file. Cluster numbering (FAT convention, data clusters
/// start at 2): `\EFI`=2, `\EFI\BOOT`=3, `\EFI\ALEA`=4, the boot file's
/// clusters start at 5, and the verifier file's clusters follow.
///
/// Determinism (SPEC §32): a pure function of the two payloads' bytes and
/// lengths — no wall-clock, no random IDs, fixed traversal order.
pub fn build_esp_volume_with_verify(
    bootx64: &[u8],
    verify: &[u8],
) -> Result<Vec<u8>, ImageBuildError> {
    if bootx64.is_empty() || verify.is_empty() {
        return Err(ImageBuildError::EmptyPayload);
    }
    let layout = plan_layout_dual(bootx64.len(), verify.len())?;
    let total_bytes = layout.total_sectors as usize * SECTOR_SIZE;
    let mut img = vec![0u8; total_bytes];

    write_boot_sector(&mut img, &layout);

    let fat_start = RESERVED_SECTORS as usize * SECTOR_SIZE;
    let fat_size_bytes = layout.fat_size_sectors as usize * SECTOR_SIZE;
    let root_dir_start = fat_start + NUM_FATS as usize * fat_size_bytes;
    let data_start = root_dir_start + ROOT_DIR_SECTORS as usize * SECTOR_SIZE;
    let cluster_bytes = SECTOR_SIZE * SECTORS_PER_CLUSTER as usize;

    // Cluster numbering: data clusters start at 2 (FAT convention).
    let efi_dir_cluster: u16 = 2;
    let boot_dir_cluster: u16 = 3;
    let alea_dir_cluster: u16 = 4;
    let boot_file_start_cluster: u16 = 5;
    let boot_file_clusters = (bootx64.len() + cluster_bytes - 1) / cluster_bytes;
    let verify_file_start_cluster: u16 = boot_file_start_cluster + boot_file_clusters as u16;
    let verify_file_clusters = (verify.len() + cluster_bytes - 1) / cluster_bytes;

    // --- FAT table (write identically into both copies) ---
    let mut fat = vec![0u8; fat_size_bytes];
    write_fat16_entry(&mut fat, 0, FAT16_RESERVED0);
    write_fat16_entry(&mut fat, 1, FAT16_RESERVED1);
    write_fat16_entry(&mut fat, efi_dir_cluster as usize, FAT16_EOC);
    write_fat16_entry(&mut fat, boot_dir_cluster as usize, FAT16_EOC);
    write_fat16_entry(&mut fat, alea_dir_cluster as usize, FAT16_EOC);
    for i in 0..boot_file_clusters {
        let cluster = boot_file_start_cluster as usize + i;
        let next = if i + 1 == boot_file_clusters {
            FAT16_EOC
        } else {
            (cluster + 1) as u16
        };
        write_fat16_entry(&mut fat, cluster, next);
    }
    for i in 0..verify_file_clusters {
        let cluster = verify_file_start_cluster as usize + i;
        let next = if i + 1 == verify_file_clusters {
            FAT16_EOC
        } else {
            (cluster + 1) as u16
        };
        write_fat16_entry(&mut fat, cluster, next);
    }
    img[fat_start..fat_start + fat_size_bytes].copy_from_slice(&fat);
    img[fat_start + fat_size_bytes..fat_start + 2 * fat_size_bytes].copy_from_slice(&fat);

    // --- Root directory: single entry "EFI" (directory) ---
    write_dir_entry(
        &mut img,
        root_dir_start,
        short_name("EFI", ""),
        ATTR_DIRECTORY,
        efi_dir_cluster,
        0,
    );

    // --- \EFI directory cluster: ".", "..", "BOOT", "ALEA" ---
    {
        let cluster_off = data_start + (efi_dir_cluster as usize - 2) * cluster_bytes;
        write_dir_entry(&mut img, cluster_off, short_name(".", ""), ATTR_DIRECTORY, efi_dir_cluster, 0);
        write_dir_entry(&mut img, cluster_off + 32, short_name("..", ""), ATTR_DIRECTORY, 0, 0);
        write_dir_entry(
            &mut img,
            cluster_off + 64,
            short_name("BOOT", ""),
            ATTR_DIRECTORY,
            boot_dir_cluster,
            0,
        );
        write_dir_entry(
            &mut img,
            cluster_off + 96,
            short_name("ALEA", ""),
            ATTR_DIRECTORY,
            alea_dir_cluster,
            0,
        );
    }

    // --- \EFI\BOOT directory cluster: ".", "..", "BOOTX64.EFI" ---
    {
        let cluster_off = data_start + (boot_dir_cluster as usize - 2) * cluster_bytes;
        write_dir_entry(&mut img, cluster_off, short_name(".", ""), ATTR_DIRECTORY, boot_dir_cluster, 0);
        write_dir_entry(
            &mut img,
            cluster_off + 32,
            short_name("..", ""),
            ATTR_DIRECTORY,
            efi_dir_cluster,
            0,
        );
        write_dir_entry(
            &mut img,
            cluster_off + 64,
            short_name("BOOTX64", "EFI"),
            ATTR_ARCHIVE,
            boot_file_start_cluster,
            bootx64.len() as u32,
        );
    }

    // --- \EFI\ALEA directory cluster: ".", "..", "VERIFY.EFI" ---
    {
        let cluster_off = data_start + (alea_dir_cluster as usize - 2) * cluster_bytes;
        write_dir_entry(&mut img, cluster_off, short_name(".", ""), ATTR_DIRECTORY, alea_dir_cluster, 0);
        write_dir_entry(
            &mut img,
            cluster_off + 32,
            short_name("..", ""),
            ATTR_DIRECTORY,
            efi_dir_cluster,
            0,
        );
        write_dir_entry(
            &mut img,
            cluster_off + 64,
            short_name("VERIFY", "EFI"),
            ATTR_ARCHIVE,
            verify_file_start_cluster,
            verify.len() as u32,
        );
    }

    // --- Boot-loader file data ---
    {
        let off = data_start + (boot_file_start_cluster as usize - 2) * cluster_bytes;
        img[off..off + bootx64.len()].copy_from_slice(bootx64);
    }
    // --- Verifier file data ---
    {
        let off = data_start + (verify_file_start_cluster as usize - 2) * cluster_bytes;
        img[off..off + verify.len()].copy_from_slice(verify);
    }

    Ok(img)
}

// ============================================================================
// GPT + protective MBR wrapper (SPEC §5, §10 step 5, §32)
// ============================================================================

/// Bytes per logical block (LBA). Fixed at the standard value, matching
/// [`SECTOR_SIZE`] — the GPT block size and the FAT sector size are the
/// same physical unit on this image.
const LBA_SIZE: usize = SECTOR_SIZE;
/// First LBA of the EFI System Partition. `2048` is the conventional
/// 1 MiB alignment boundary used by virtually every modern partitioning
/// tool, chosen for maximal firmware/OS compatibility.
const ESP_START_LBA: u64 = 2048;
/// Number of entries in the GPT partition entry array (UEFI spec
/// minimum/conventional value).
const GPT_ENTRY_COUNT: u32 = 128;
/// Size in bytes of one GPT partition entry (UEFI spec fixed value).
const GPT_ENTRY_SIZE: u32 = 128;
/// Sectors occupied by the entry array: `128 entries * 128 bytes / 512
/// bytes-per-sector`.
const GPT_ENTRY_ARRAY_LBAS: u64 = (GPT_ENTRY_COUNT as u64 * GPT_ENTRY_SIZE as u64) / LBA_SIZE as u64;
/// GPT header structure size (UEFI spec fixed value; the rest of the LBA
/// it occupies is zero-padded).
const GPT_HEADER_SIZE: u32 = 92;

/// EFI System Partition type GUID `C12A7328-F81F-11D2-BA4B-00A0C93EC93B`,
/// pre-serialized in GPT mixed-endian on-disk byte order (UEFI spec
/// Appendix A).
const ESP_TYPE_GUID_BYTES: [u8; 16] = [
    0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,
];

/// Fixed partition name, UTF-16LE, zero-padded to the GPT entry's 72-byte
/// name field. A constant (not derived from input) keeps the entry
/// bytes deterministic and independent of any external naming choice.
const PARTITION_NAME: &str = "ALEA ESP";

fn partition_name_utf16_bytes() -> [u8; 72] {
    let mut out = [0u8; 72];
    for (i, unit) in PARTITION_NAME.encode_utf16().enumerate() {
        let off = i * 2;
        if off + 2 > out.len() {
            break;
        }
        out[off..off + 2].copy_from_slice(&unit.to_le_bytes());
    }
    out
}

/// IEEE 802.3 CRC-32 (reflected, polynomial `0xEDB8_8320`), computed
/// byte-by-byte with no lookup table — small, simple, and every byte of
/// its behavior is visible in this function rather than delegated to a
/// dependency, matching this module's "every emitted byte traceable to
/// this repository" doctrine (see module doc comment). GPT requires this
/// exact algorithm for its header and partition-entry-array checksums.
#[must_use]
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Derives one on-disk GPT GUID (mixed-endian serialization) from 16
/// bytes of a hash digest, forcing RFC 4122 version 4 / variant bits so
/// the result is a well-formed (if not cryptographically "random") GUID.
/// A pure function of `h16` — the same input always yields the same
/// GUID, which is what keeps two builds of the same payload
/// byte-identical (SPEC §32) while still giving distinct releases
/// distinct GUIDs (`h16` is derived from `payload`'s own SHA-256 by the
/// caller).
#[must_use]
fn guid_from_hash(h16: &[u8; 16]) -> [u8; 16] {
    let d1 = u32::from_be_bytes([h16[0], h16[1], h16[2], h16[3]]);
    let d2 = u16::from_be_bytes([h16[4], h16[5]]);
    let d3 = (u16::from_be_bytes([h16[6], h16[7]]) & 0x0FFF) | 0x4000;
    let mut d4 = [0u8; 8];
    d4[0] = (h16[8] & 0x3F) | 0x80;
    d4[1..8].copy_from_slice(&h16[9..16]);

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&d1.to_le_bytes());
    out[4..6].copy_from_slice(&d2.to_le_bytes());
    out[6..8].copy_from_slice(&d3.to_le_bytes());
    out[8..16].copy_from_slice(&d4);
    out
}

/// Writes one 92-byte GPT header (per UEFI spec layout) into `out[0..92]`
/// with its own `header_crc32` field computed correctly (computed with
/// the field itself zeroed, per spec, then written back in).
#[allow(clippy::too_many_arguments)]
fn write_gpt_header(
    out: &mut [u8],
    my_lba: u64,
    alternate_lba: u64,
    first_usable_lba: u64,
    last_usable_lba: u64,
    disk_guid: &[u8; 16],
    partition_entry_lba: u64,
    entries_crc32: u32,
) {
    out[0..8].copy_from_slice(b"EFI PART");
    out[8..12].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]); // revision 1.0
    out[12..16].copy_from_slice(&GPT_HEADER_SIZE.to_le_bytes());
    out[16..20].copy_from_slice(&0u32.to_le_bytes()); // header_crc32 placeholder (zeroed for the CRC pass)
    out[20..24].copy_from_slice(&0u32.to_le_bytes()); // reserved
    out[24..32].copy_from_slice(&my_lba.to_le_bytes());
    out[32..40].copy_from_slice(&alternate_lba.to_le_bytes());
    out[40..48].copy_from_slice(&first_usable_lba.to_le_bytes());
    out[48..56].copy_from_slice(&last_usable_lba.to_le_bytes());
    out[56..72].copy_from_slice(disk_guid);
    out[72..80].copy_from_slice(&partition_entry_lba.to_le_bytes());
    out[80..84].copy_from_slice(&GPT_ENTRY_COUNT.to_le_bytes());
    out[84..88].copy_from_slice(&GPT_ENTRY_SIZE.to_le_bytes());
    out[88..92].copy_from_slice(&entries_crc32.to_le_bytes());

    let header_crc32 = crc32(&out[0..GPT_HEADER_SIZE as usize]);
    out[16..20].copy_from_slice(&header_crc32.to_le_bytes());
}

/// Writes the 128-byte partition entry at index 0 of a GPT entry array
/// (every other entry in the array stays zero: this disk has exactly one
/// partition).
fn write_gpt_esp_entry(out: &mut [u8], partition_guid: &[u8; 16], first_lba: u64, last_lba: u64) {
    out[0..16].copy_from_slice(&ESP_TYPE_GUID_BYTES);
    out[16..32].copy_from_slice(partition_guid);
    out[32..40].copy_from_slice(&first_lba.to_le_bytes());
    out[40..48].copy_from_slice(&last_lba.to_le_bytes());
    out[48..56].copy_from_slice(&0u64.to_le_bytes()); // attributes
    out[56..128].copy_from_slice(&partition_name_utf16_bytes());
}

/// Writes the protective MBR into `out[0..512]` (LBA0): a single
/// `0xEE`-type entry covering the whole disk (or `0xFFFF_FFFF` sectors
/// if the disk is larger), no boot code, and the standard `0x55AA`
/// signature. Per UEFI spec Appendix A ("Protective MBR").
fn write_protective_mbr(out: &mut [u8], total_lbas: u64) {
    // out[0..440]: boot code, left zero -- this disk is never executed as
    // legacy x86 boot code (SPEC §5: UEFI file-path boot only).
    out[440..444].copy_from_slice(&0u32.to_le_bytes()); // disk signature: fixed 0 (SPEC §32 determinism)
    out[444..446].copy_from_slice(&0u16.to_le_bytes()); // reserved

    let entry_off = 446;
    out[entry_off] = 0x00; // boot indicator: not bootable (BIOS sense)
    out[entry_off + 1..entry_off + 4].copy_from_slice(&[0x00, 0x02, 0x00]); // CHS start (nominal)
    out[entry_off + 4] = 0xEE; // partition type: GPT protective
    out[entry_off + 5..entry_off + 8].copy_from_slice(&[0xFF, 0xFF, 0xFF]); // CHS end (nominal)
    out[entry_off + 8..entry_off + 12].copy_from_slice(&1u32.to_le_bytes()); // starting LBA
    let size_lba = u32::try_from(total_lbas.saturating_sub(1)).unwrap_or(u32::MAX);
    out[entry_off + 12..entry_off + 16].copy_from_slice(&size_lba.to_le_bytes());
    // Partition table entries 2-4 stay zero.

    out[510] = 0x55;
    out[511] = 0xAA;
}

/// Builds a deterministic, bootable disk image: protective MBR + primary
/// GPT + a single EFI System Partition containing `payload` at
/// `\EFI\BOOT\BOOTX64.EFI`, plus the backup GPT at the end of the disk
/// (SPEC §5, §10 step 5, §32). This is the crate's public entry point —
/// every consumer (the CLI, `scripts/build-release.sh`, the media
/// read-back verifier) should call this, not [`build_esp_volume`]
/// directly.
///
/// Determinism (SPEC §32): every byte is a pure function of `payload`'s
/// bytes and length — the FAT volume via [`build_esp_volume`] (already
/// deterministic), and the two on-disk GUIDs (disk GUID, ESP partition
/// GUID) via [`guid_from_hash`] over `payload`'s own SHA-256 digest. Two
/// independent builds from the same input `.efi` file therefore always
/// produce byte-identical images; two different inputs get different
/// (but still internally well-formed) GUIDs.
pub fn build_image(payload: &[u8]) -> Result<Vec<u8>, ImageBuildError> {
    let fat = build_esp_volume(payload)?;
    // The GUID seed is the loader bytes themselves — unchanged from the
    // original inline implementation, so this output stays byte-identical.
    wrap_esp_in_gpt(&fat, payload)
}

/// Dual-file variant of [`build_image`] (SPEC_MAIN_MENU.md §17.4): builds
/// the same protective-MBR + GPT + single-ESP disk, but the ESP now also
/// carries the separate verifier at `\EFI\ALEA\VERIFY.EFI` alongside the
/// standard `\EFI\BOOT\BOOTX64.EFI` boot path (via
/// [`build_esp_volume_with_verify`]). This is what the production release
/// (`scripts/build-release.sh`, `.github/workflows/release.yml`) emits so
/// the landing launcher's Verify item can chain-load the verifier.
///
/// Determinism (SPEC §32): the two on-disk GUIDs are derived from
/// `SHA-256(bootx64 ++ verify)`, so two builds of the same inputs are
/// byte-identical while distinct releases (distinct combined content) still
/// get distinct GUIDs — and distinct from the single-file
/// [`build_image`]'s GUIDs, whose seed is `bootx64` alone.
pub fn build_image_with_verify(bootx64: &[u8], verify: &[u8]) -> Result<Vec<u8>, ImageBuildError> {
    let fat = build_esp_volume_with_verify(bootx64, verify)?;
    // Combined-content GUID seed: SHA-256 of bootx64 || verify. Non-empty
    // `verify` guarantees this differs from `build_image(bootx64)`'s seed.
    let mut seed = Vec::with_capacity(bootx64.len() + verify.len());
    seed.extend_from_slice(bootx64);
    seed.extend_from_slice(verify);
    wrap_esp_in_gpt(&fat, &seed)
}

/// Wraps an already-built FAT16 EFI System Partition volume (`fat`) in a
/// deterministic protective-MBR + primary/backup GPT disk, deriving the
/// disk and partition GUIDs from `SHA-256(guid_seed)` (see
/// [`guid_from_hash`]). Factored out of [`build_image`] so the single- and
/// dual-file entry points share one GPT-wrapping body; [`build_image`]
/// passes the loader bytes as `guid_seed`, keeping its output byte-for-byte
/// identical to the pre-factoring implementation.
fn wrap_esp_in_gpt(fat: &[u8], guid_seed: &[u8]) -> Result<Vec<u8>, ImageBuildError> {
    let fat_lbas = (fat.len() / LBA_SIZE) as u64;

    // total = MBR(1) + primary header(1) + primary entries(32) + gap to
    // ESP_START_LBA + ESP + backup entries(32) + backup header(1).
    let total_lbas = ESP_START_LBA + fat_lbas + GPT_ENTRY_ARRAY_LBAS + 1;

    let digest = sha256_bytes(guid_seed);
    let disk_guid = guid_from_hash(digest[0..16].try_into().expect("16-byte slice"));
    let partition_guid = guid_from_hash(digest[16..32].try_into().expect("16-byte slice"));

    let mut img = vec![0u8; (total_lbas as usize) * LBA_SIZE];

    write_protective_mbr(&mut img[0..LBA_SIZE], total_lbas);

    let first_usable_lba = 34u64; // 1 (MBR) + 1 (primary header) + 32 (primary entries)
    let last_usable_lba = total_lbas - 34; // mirror at the far end

    let mut primary_entries = vec![0u8; (GPT_ENTRY_ARRAY_LBAS as usize) * LBA_SIZE];
    write_gpt_esp_entry(
        &mut primary_entries[0..GPT_ENTRY_SIZE as usize],
        &partition_guid,
        ESP_START_LBA,
        ESP_START_LBA + fat_lbas - 1,
    );
    let entries_crc32 = crc32(&primary_entries);

    let mut primary_header = vec![0u8; LBA_SIZE];
    write_gpt_header(
        &mut primary_header[0..GPT_HEADER_SIZE as usize],
        1,
        total_lbas - 1,
        first_usable_lba,
        last_usable_lba,
        &disk_guid,
        2,
        entries_crc32,
    );

    let primary_entries_start = 2 * LBA_SIZE;
    let backup_entries_lba = total_lbas - 1 - GPT_ENTRY_ARRAY_LBAS;
    let backup_entries_start = (backup_entries_lba as usize) * LBA_SIZE;
    let backup_header_lba = total_lbas - 1;
    let backup_header_start = (backup_header_lba as usize) * LBA_SIZE;
    let esp_start = (ESP_START_LBA as usize) * LBA_SIZE;

    let mut backup_header = vec![0u8; LBA_SIZE];
    write_gpt_header(
        &mut backup_header[0..GPT_HEADER_SIZE as usize],
        backup_header_lba,
        1,
        first_usable_lba,
        last_usable_lba,
        &disk_guid,
        backup_entries_lba,
        entries_crc32,
    );

    img[LBA_SIZE..2 * LBA_SIZE].copy_from_slice(&primary_header);
    img[primary_entries_start..primary_entries_start + primary_entries.len()]
        .copy_from_slice(&primary_entries);
    img[esp_start..esp_start + fat.len()].copy_from_slice(&fat);
    img[backup_entries_start..backup_entries_start + primary_entries.len()]
        .copy_from_slice(&primary_entries);
    img[backup_header_start..backup_header_start + LBA_SIZE].copy_from_slice(&backup_header);

    Ok(img)
}

/// Raw SHA-256 digest bytes of `data` (used internally for deterministic
/// GUID derivation; [`sha256_hex`] below is the public hex-string form
/// used for the published image hash).
fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn write_fat16_entry(fat: &mut [u8], index: usize, value: u16) {
    let off = index * 2;
    fat[off..off + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_boot_sector(img: &mut [u8], layout: &Layout) {
    // Jump instruction + NOP (standard 3-byte x86 short jump over the BPB).
    img[0] = 0xEB;
    img[1] = 0x3C;
    img[2] = 0x90;
    // OEM name, 8 bytes.
    img[3..11].copy_from_slice(b"SEEDFNDY");
    // BPB.
    img[11..13].copy_from_slice(&(SECTOR_SIZE as u16).to_le_bytes());
    img[13] = SECTORS_PER_CLUSTER;
    img[14..16].copy_from_slice(&RESERVED_SECTORS.to_le_bytes());
    img[16] = NUM_FATS;
    img[17..19].copy_from_slice(&ROOT_ENTRIES.to_le_bytes());
    // total_sectors_16: 0 if it doesn't fit in u16, else the value; the
    // 32-bit field is always populated for consistency across readers.
    let total_sectors_16: u16 = if layout.total_sectors <= 0xFFFF {
        layout.total_sectors as u16
    } else {
        0
    };
    img[19..21].copy_from_slice(&total_sectors_16.to_le_bytes());
    img[21] = 0xF8; // media descriptor: fixed disk
    img[22..24].copy_from_slice(&(layout.fat_size_sectors as u16).to_le_bytes());
    img[24..26].copy_from_slice(&32u16.to_le_bytes()); // sectors per track (nominal)
    img[26..28].copy_from_slice(&64u16.to_le_bytes()); // number of heads (nominal)
    img[28..32].copy_from_slice(&0u32.to_le_bytes()); // hidden sectors
    img[32..36].copy_from_slice(&layout.total_sectors.to_le_bytes()); // total_sectors_32
    // Extended BPB (FAT12/16).
    img[36] = 0x80; // drive number
    img[37] = 0; // reserved
    img[38] = 0x29; // extended boot signature
    img[39..43].copy_from_slice(&FIXED_VOLUME_ID.to_le_bytes());
    img[43..54].copy_from_slice(VOLUME_LABEL);
    img[54..62].copy_from_slice(b"FAT16   ");
    // Boot code region (62..510) left zero-filled: this image is never
    // executed as x86 boot code — the platform boots via the UEFI file
    // path `\EFI\BOOT\BOOTX64.EFI` (SPEC §5), not legacy BIOS boot sector
    // execution. Zero bytes keep the image deterministic and inert.
    img[510] = 0x55;
    img[511] = 0xAA;
}

/// Computes the SHA-256 digest of `data`, as required for the published
/// image hash (SPEC §32: "published binary and source hashes"; SPEC §10
/// step 7: read-back hash comparison).
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = sha256_bytes(data);
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_payload(len: usize) -> Vec<u8> {
        // Deterministic pseudo-random-looking payload (not actually
        // random — a fixed function of the index), so both build
        // invocations in the determinism test see byte-identical input.
        (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(7)).collect()
    }

    /// Determinism gate (IMPLEMENTATION_MAP.md Wave 5: "Deterministic
    /// image hash ×2 builds"), now over the full GPT+ESP image.
    #[test]
    fn build_is_byte_identical_across_two_builds() {
        let payload = sample_payload(300_000);
        let img1 = build_image(&payload).expect("build 1");
        let img2 = build_image(&payload).expect("build 2");
        assert_eq!(img1, img2, "two builds from identical input must be byte-identical");
        assert_eq!(sha256_hex(&img1), sha256_hex(&img2));
    }

    #[test]
    fn tiny_payload_round_trips_through_gpt_image() {
        let payload = b"MZ_FAKE_EFI_PAYLOAD_BYTES_FOR_TEST".to_vec();
        let img = build_image(&payload).expect("build");
        let esp = esp_partition_slice(&img);
        let found = read_back_bootx64(esp).expect("BOOTX64.EFI must be found");
        assert_eq!(found, payload);
    }

    #[test]
    fn larger_payload_spanning_many_clusters_round_trips_through_gpt_image() {
        let payload = sample_payload(2_500_000); // spans many 512B clusters
        let img = build_image(&payload).expect("build");
        let esp = esp_partition_slice(&img);
        let found = read_back_bootx64(esp).expect("BOOTX64.EFI must be found");
        assert_eq!(found, payload);
    }

    #[test]
    fn empty_payload_is_rejected() {
        assert!(matches!(build_image(&[]), Err(ImageBuildError::EmptyPayload)));
        assert!(matches!(build_esp_volume(&[]), Err(ImageBuildError::EmptyPayload)));
    }

    // ---- GPT/MBR structure tests ----

    /// Independently re-derives the MBR + primary GPT header + entry 0
    /// fields directly from raw bytes at their spec-fixed offsets (not by
    /// calling the writer's own helper functions), locates and returns
    /// the ESP partition's byte slice within `img`. Panics (via
    /// `expect`/`assert`) if any structural expectation is violated --
    /// appropriate for a test helper.
    fn esp_partition_slice(img: &[u8]) -> &[u8] {
        // --- Protective MBR (LBA0) ---
        assert_eq!(img[510], 0x55, "MBR signature byte 0");
        assert_eq!(img[511], 0xAA, "MBR signature byte 1");
        let entry_off = 446;
        assert_eq!(img[entry_off + 4], 0xEE, "MBR partition type must be 0xEE (GPT protective)");
        let mbr_start_lba = u32::from_le_bytes(img[entry_off + 8..entry_off + 12].try_into().unwrap());
        assert_eq!(mbr_start_lba, 1);

        // --- Primary GPT header (LBA1) ---
        let hdr = &img[LBA_SIZE..LBA_SIZE + GPT_HEADER_SIZE as usize];
        assert_eq!(&hdr[0..8], b"EFI PART");
        let stored_header_crc = u32::from_le_bytes(hdr[16..20].try_into().unwrap());
        let mut hdr_for_crc = hdr.to_vec();
        hdr_for_crc[16..20].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(crc32(&hdr_for_crc), stored_header_crc, "primary header CRC32 must self-verify");

        let my_lba = u64::from_le_bytes(hdr[24..32].try_into().unwrap());
        assert_eq!(my_lba, 1);
        let partition_entry_lba = u64::from_le_bytes(hdr[72..80].try_into().unwrap());
        let num_entries = u32::from_le_bytes(hdr[80..84].try_into().unwrap());
        let entry_size = u32::from_le_bytes(hdr[84..88].try_into().unwrap());
        let stored_entries_crc = u32::from_le_bytes(hdr[88..92].try_into().unwrap());
        assert_eq!(num_entries, GPT_ENTRY_COUNT);
        assert_eq!(entry_size, GPT_ENTRY_SIZE);

        let entries_start = (partition_entry_lba as usize) * LBA_SIZE;
        let entries_bytes = (num_entries * entry_size) as usize;
        let entries = &img[entries_start..entries_start + entries_bytes];
        assert_eq!(crc32(entries), stored_entries_crc, "primary entry array CRC32 must self-verify");

        // --- Entry 0: the ESP ---
        let entry0 = &entries[0..GPT_ENTRY_SIZE as usize];
        assert_eq!(&entry0[0..16], &ESP_TYPE_GUID_BYTES, "entry 0 type GUID must be the ESP type GUID");
        let first_lba = u64::from_le_bytes(entry0[32..40].try_into().unwrap());
        let last_lba = u64::from_le_bytes(entry0[40..48].try_into().unwrap());
        assert_eq!(first_lba, ESP_START_LBA);

        let esp_start = (first_lba as usize) * LBA_SIZE;
        let esp_end = ((last_lba + 1) as usize) * LBA_SIZE;
        &img[esp_start..esp_end]
    }

    #[test]
    fn esp_partition_bytes_equal_esp_volume() {
        let payload = sample_payload(50_000);
        let img = build_image(&payload).expect("build");
        let esp = esp_partition_slice(&img);
        let fat = build_esp_volume(&payload).expect("build esp volume");
        assert_eq!(esp, &fat[..], "ESP partition bytes must exactly equal build_esp_volume's output");
    }

    #[test]
    fn esp_type_guid_bytes_are_exact() {
        // Pin the literal ESP type GUID
        // C12A7328-F81F-11D2-BA4B-00A0C93EC93B in its GPT mixed-endian
        // on-disk serialization.
        assert_eq!(
            ESP_TYPE_GUID_BYTES,
            [
                0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9,
                0x3B,
            ]
        );
    }

    #[test]
    fn backup_gpt_is_consistent() {
        let payload = sample_payload(50_000);
        let img = build_image(&payload).expect("build");
        let total_lbas = (img.len() / LBA_SIZE) as u64;

        // Locate the primary entry array bytes independently (re-derive,
        // not reuse, the primary header's own partition_entry_lba).
        let primary_hdr = &img[LBA_SIZE..LBA_SIZE + GPT_HEADER_SIZE as usize];
        let primary_entries_lba = u64::from_le_bytes(primary_hdr[72..80].try_into().unwrap());
        let primary_entries_start = (primary_entries_lba as usize) * LBA_SIZE;
        let entries_bytes = (GPT_ENTRY_COUNT * GPT_ENTRY_SIZE) as usize;
        let primary_entries = &img[primary_entries_start..primary_entries_start + entries_bytes];

        // Backup header is the last LBA.
        let backup_header_lba = total_lbas - 1;
        let backup_hdr_start = (backup_header_lba as usize) * LBA_SIZE;
        let backup_hdr = &img[backup_hdr_start..backup_hdr_start + GPT_HEADER_SIZE as usize];
        assert_eq!(&backup_hdr[0..8], b"EFI PART");

        let stored_crc = u32::from_le_bytes(backup_hdr[16..20].try_into().unwrap());
        let mut for_crc = backup_hdr.to_vec();
        for_crc[16..20].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(crc32(&for_crc), stored_crc, "backup header CRC32 must self-verify");

        let backup_my_lba = u64::from_le_bytes(backup_hdr[24..32].try_into().unwrap());
        let backup_alt_lba = u64::from_le_bytes(backup_hdr[32..40].try_into().unwrap());
        assert_eq!(backup_my_lba, backup_header_lba, "backup header's my_lba must be its own LBA");
        assert_eq!(backup_alt_lba, 1, "backup header's alternate_lba must point at the primary header");

        let backup_entries_lba = u64::from_le_bytes(backup_hdr[72..80].try_into().unwrap());
        assert_eq!(backup_entries_lba, total_lbas - 1 - GPT_ENTRY_ARRAY_LBAS);
        let backup_entries_start = (backup_entries_lba as usize) * LBA_SIZE;
        let backup_entries = &img[backup_entries_start..backup_entries_start + entries_bytes];
        assert_eq!(backup_entries, primary_entries, "backup entry array must equal the primary one");
    }

    #[test]
    fn guids_are_deterministic_and_well_formed() {
        let payload_a = sample_payload(1_000);
        let payload_b = sample_payload(1_001);

        let img_a1 = build_image(&payload_a).expect("build a1");
        let img_a2 = build_image(&payload_a).expect("build a2");
        let img_b = build_image(&payload_b).expect("build b");

        let disk_guid = |img: &[u8]| -> [u8; 16] {
            img[LBA_SIZE + 56..LBA_SIZE + 72].try_into().unwrap()
        };
        let partition_guid = |img: &[u8]| -> [u8; 16] {
            let hdr = &img[LBA_SIZE..LBA_SIZE + GPT_HEADER_SIZE as usize];
            let entries_lba = u64::from_le_bytes(hdr[72..80].try_into().unwrap());
            let entries_start = (entries_lba as usize) * LBA_SIZE;
            img[entries_start + 16..entries_start + 32].try_into().unwrap()
        };

        assert_eq!(disk_guid(&img_a1), disk_guid(&img_a2), "same payload -> same disk GUID");
        assert_eq!(
            partition_guid(&img_a1),
            partition_guid(&img_a2),
            "same payload -> same partition GUID"
        );
        assert_ne!(disk_guid(&img_a1), disk_guid(&img_b), "different payload -> different disk GUID");

        for guid in [disk_guid(&img_a1), partition_guid(&img_a1)] {
            let version = (guid[7] & 0xF0) >> 4;
            let variant = (guid[8] & 0xC0) >> 6;
            assert_eq!(version, 4, "RFC 4122 version nibble must be 4");
            assert_eq!(variant, 0b10, "RFC 4122 variant bits must be 10");
        }
    }

    #[test]
    fn crc32_known_answer() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn image_length_matches_total_lbas() {
        let payload = sample_payload(50_000);
        let img = build_image(&payload).expect("build");
        let fat = build_esp_volume(&payload).expect("build esp volume");
        let fat_lbas = (fat.len() / LBA_SIZE) as u64;
        let expected_total_lbas = ESP_START_LBA + fat_lbas + GPT_ENTRY_ARRAY_LBAS + 1;
        assert_eq!(img.len(), (expected_total_lbas as usize) * LBA_SIZE);
    }

    /// Minimal FAT16 reader used only by tests, to prove the writer
    /// produces a structurally valid, self-consistent filesystem
    /// (independent re-derivation of offsets from the on-disk BPB, not
    /// reuse of the writer's internal layout constants).
    fn read_back_bootx64(img: &[u8]) -> Option<Vec<u8>> {
        let bytes_per_sector = u16::from_le_bytes([img[11], img[12]]) as usize;
        let sectors_per_cluster = img[13] as usize;
        let reserved_sectors = u16::from_le_bytes([img[14], img[15]]) as usize;
        let num_fats = img[16] as usize;
        let root_entries = u16::from_le_bytes([img[17], img[18]]) as usize;
        let fat_size = u16::from_le_bytes([img[22], img[23]]) as usize;
        let root_dir_sectors = (root_entries * 32 + bytes_per_sector - 1) / bytes_per_sector;
        let root_dir_start = (reserved_sectors + num_fats * fat_size) * bytes_per_sector;
        let data_start = root_dir_start + root_dir_sectors * bytes_per_sector;
        let cluster_bytes = bytes_per_sector * sectors_per_cluster;

        let fat_start = reserved_sectors * bytes_per_sector;
        let fat = &img[fat_start..fat_start + fat_size * bytes_per_sector];

        let read_dir_entry = |base: usize, idx: usize| -> ([u8; 11], u8, u16, u32) {
            let off = base + idx * 32;
            let mut name = [0u8; 11];
            name.copy_from_slice(&img[off..off + 11]);
            let attr = img[off + 11];
            let cluster = u16::from_le_bytes([img[off + 26], img[off + 27]]);
            let size = u32::from_le_bytes([
                img[off + 28],
                img[off + 29],
                img[off + 30],
                img[off + 31],
            ]);
            (name, attr, cluster, size)
        };

        let cluster_offset = |cluster: u16| data_start + (cluster as usize - 2) * cluster_bytes;

        // Walk root dir for "EFI".
        let mut efi_cluster = None;
        for i in 0..root_entries {
            let (name, attr, cluster, _) = read_dir_entry(root_dir_start, i);
            if name[0] == 0 {
                break;
            }
            if attr & ATTR_DIRECTORY != 0 && &name == &short_name("EFI", "") {
                efi_cluster = Some(cluster);
                break;
            }
        }
        let efi_cluster = efi_cluster?;

        // Walk EFI dir for "BOOT".
        let mut boot_cluster = None;
        let efi_base = cluster_offset(efi_cluster);
        for i in 0..(cluster_bytes / 32) {
            let (name, attr, cluster, _) = read_dir_entry(efi_base, i);
            if name[0] == 0 {
                break;
            }
            if attr & ATTR_DIRECTORY != 0 && &name == &short_name("BOOT", "") {
                boot_cluster = Some(cluster);
                break;
            }
        }
        let boot_cluster = boot_cluster?;

        // Walk BOOT dir for "BOOTX64.EFI".
        let mut file_info = None;
        let boot_base = cluster_offset(boot_cluster);
        for i in 0..(cluster_bytes / 32) {
            let (name, attr, cluster, size) = read_dir_entry(boot_base, i);
            if name[0] == 0 {
                break;
            }
            if attr & ATTR_ARCHIVE != 0 && &name == &short_name("BOOTX64", "EFI") {
                file_info = Some((cluster, size));
                break;
            }
        }
        let (mut cluster, size) = file_info?;

        // Follow the FAT chain, collecting file bytes.
        let mut out = Vec::with_capacity(size as usize);
        loop {
            let start = cluster_offset(cluster);
            out.extend_from_slice(&img[start..start + cluster_bytes]);
            let fat_off = cluster as usize * 2;
            let next = u16::from_le_bytes([fat[fat_off], fat[fat_off + 1]]);
            if next >= FAT16_EOC {
                break;
            }
            cluster = next;
        }
        out.truncate(size as usize);
        Some(out)
    }

    /// Test-only generalization of [`read_back_bootx64`]: navigate
    /// `\EFI\<dir>\<name>.<ext>` in a raw FAT16 ESP volume and return the
    /// file's bytes, or `None` if any path component is missing.
    /// Independent re-derivation of BPB offsets (not reuse of the writer's
    /// layout constants), so it structurally proves the 8.3 directory
    /// entries the dual-file writer emitted are actually present and
    /// resolvable.
    fn read_back_efi_file(img: &[u8], dir: &str, name: &str, ext: &str) -> Option<Vec<u8>> {
        let bytes_per_sector = u16::from_le_bytes([img[11], img[12]]) as usize;
        let sectors_per_cluster = img[13] as usize;
        let reserved_sectors = u16::from_le_bytes([img[14], img[15]]) as usize;
        let num_fats = img[16] as usize;
        let root_entries = u16::from_le_bytes([img[17], img[18]]) as usize;
        let fat_size = u16::from_le_bytes([img[22], img[23]]) as usize;
        let root_dir_sectors = (root_entries * 32 + bytes_per_sector - 1) / bytes_per_sector;
        let root_dir_start = (reserved_sectors + num_fats * fat_size) * bytes_per_sector;
        let data_start = root_dir_start + root_dir_sectors * bytes_per_sector;
        let cluster_bytes = bytes_per_sector * sectors_per_cluster;
        let fat_start = reserved_sectors * bytes_per_sector;
        let fat = &img[fat_start..fat_start + fat_size * bytes_per_sector];

        let read_entry = |base: usize, idx: usize| -> ([u8; 11], u16, u32) {
            let off = base + idx * 32;
            let mut n = [0u8; 11];
            n.copy_from_slice(&img[off..off + 11]);
            let cluster = u16::from_le_bytes([img[off + 26], img[off + 27]]);
            let size = u32::from_le_bytes([
                img[off + 28],
                img[off + 29],
                img[off + 30],
                img[off + 31],
            ]);
            (n, cluster, size)
        };
        let cluster_offset = |cluster: u16| data_start + (cluster as usize - 2) * cluster_bytes;
        let find_in_dir = |base: usize, count: usize, target: &[u8; 11]| -> Option<(u16, u32)> {
            for i in 0..count {
                let (n, cluster, size) = read_entry(base, i);
                if n[0] == 0 {
                    break;
                }
                if &n == target {
                    return Some((cluster, size));
                }
            }
            None
        };

        let (efi_cluster, _) = find_in_dir(root_dir_start, root_entries, &short_name("EFI", ""))?;
        let (sub_cluster, _) =
            find_in_dir(cluster_offset(efi_cluster), cluster_bytes / 32, &short_name(dir, ""))?;
        let (mut cluster, size) =
            find_in_dir(cluster_offset(sub_cluster), cluster_bytes / 32, &short_name(name, ext))?;

        let mut out = Vec::with_capacity(size as usize);
        loop {
            let start = cluster_offset(cluster);
            out.extend_from_slice(&img[start..start + cluster_bytes]);
            let fat_off = cluster as usize * 2;
            let next = u16::from_le_bytes([fat[fat_off], fat[fat_off + 1]]);
            if next >= FAT16_EOC {
                break;
            }
            cluster = next;
        }
        out.truncate(size as usize);
        Some(out)
    }

    /// SPEC_MAIN_MENU.md §17.4: the dual-file image must carry BOTH
    /// `\EFI\BOOT\BOOTX64.EFI` and `\EFI\ALEA\VERIFY.EFI`, each reading
    /// back to its exact input bytes (structural proof the 8.3 directory
    /// entries and cluster chains were laid out correctly).
    #[test]
    fn dual_file_image_contains_both_bootx64_and_verify() {
        let boot = sample_payload(40_000);
        let verify = sample_payload(25_000); // distinct length -> distinct content
        let img = build_image_with_verify(&boot, &verify).expect("build dual");
        let esp = esp_partition_slice(&img);

        let got_boot =
            read_back_efi_file(esp, "BOOT", "BOOTX64", "EFI").expect("BOOTX64.EFI must be present");
        let got_verify =
            read_back_efi_file(esp, "ALEA", "VERIFY", "EFI").expect("VERIFY.EFI must be present");
        assert_eq!(got_boot, boot, "BOOTX64.EFI must read back to the boot payload");
        assert_eq!(got_verify, verify, "VERIFY.EFI must read back to the verifier payload");
    }

    /// The dual-file image stays deterministic (SPEC §32): two builds from
    /// identical inputs are byte-identical.
    #[test]
    fn dual_file_image_is_byte_identical_across_two_builds() {
        let boot = sample_payload(40_000);
        let verify = sample_payload(25_000);
        let a = build_image_with_verify(&boot, &verify).expect("build a");
        let b = build_image_with_verify(&boot, &verify).expect("build b");
        assert_eq!(a, b, "two dual builds from identical inputs must be byte-identical");
    }

    /// The single-file [`build_image`] path is unchanged: its ESP still
    /// contains `\EFI\BOOT\BOOTX64.EFI` and NOT `\EFI\ALEA\VERIFY.EFI`, and
    /// its ESP bytes still exactly equal the frozen
    /// [`build_esp_volume`] output.
    #[test]
    fn single_file_build_image_is_unchanged_and_has_no_verifier() {
        let boot = sample_payload(40_000);
        let img = build_image(&boot).expect("build");
        let esp = esp_partition_slice(&img);

        assert_eq!(
            read_back_efi_file(esp, "BOOT", "BOOTX64", "EFI").as_deref(),
            Some(&boot[..]),
            "single-file image must still contain BOOTX64.EFI"
        );
        assert!(
            read_back_efi_file(esp, "ALEA", "VERIFY", "EFI").is_none(),
            "single-file build_image must NOT contain \\EFI\\ALEA\\VERIFY.EFI"
        );

        let fat = build_esp_volume(&boot).expect("esp volume");
        assert_eq!(
            esp,
            &fat[..],
            "build_image's ESP must remain byte-identical to build_esp_volume's frozen output"
        );
    }
}
