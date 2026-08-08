//! Integration test tying WP-29's two tools together, per the
//! work-package's explicit test requirement: "round-trip an image through
//! the readback verifier (match) and a corrupted copy (mismatch
//! detected)".
//!
//! Uses a real deterministic FAT16 image produced by `image-builder`
//! (SPEC §5, §32) as the "written media," then exercises
//! `media-readback-verifier` (SPEC §10 steps 6-7) against a clean copy
//! and a bit-flipped copy.

use media_readback_verifier::{hash_file, to_hex, verify, VerifyResult};
use std::fs;
use std::path::PathBuf;

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("mrv-roundtrip-{tag}-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn readback_of_unmodified_image_matches_published_hash() {
    let payload = b"FAKE_PRODUCTION_EFI_PAYLOAD".repeat(50);
    let image = image_builder::build_image(&payload).expect("build image");
    let published_hash_hex = image_builder::sha256_hex(&image);

    let dir = scratch_dir("match");
    let media_path = dir.join("alea-usb.img");
    fs::write(&media_path, &image).unwrap();

    // Emulate "write to media, then read the media back and hash it"
    // (SPEC §10 steps 5-6) followed by step 7's comparison.
    let actual_digest = hash_file(&media_path).unwrap();
    assert_eq!(to_hex(&actual_digest), published_hash_hex);

    let mut expected = [0u8; 32];
    for (i, b) in expected.iter_mut().enumerate() {
        *b = u8::from_str_radix(&published_hash_hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    let result = verify(&media_path, &expected).unwrap();
    assert_eq!(result, VerifyResult::Match);

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn readback_of_corrupted_copy_is_detected_as_mismatch() {
    let payload = b"FAKE_PRODUCTION_EFI_PAYLOAD".repeat(50);
    let image = image_builder::build_image(&payload).expect("build image");
    let expected = hash_file_of_bytes(&image);

    let dir = scratch_dir("mismatch");
    let media_path = dir.join("alea-usb-corrupted.img");
    let mut corrupted = image.clone();
    // Flip a bit deep inside the file-data region, simulating a bad write
    // or damaged media (SPEC §10's whole reason for step 6-7 existing).
    let idx = corrupted.len() / 2;
    corrupted[idx] ^= 0x01;
    fs::write(&media_path, &corrupted).unwrap();

    let result = verify(&media_path, &expected).unwrap();
    assert_eq!(result, VerifyResult::Mismatch);

    fs::remove_dir_all(&dir).ok();
}

fn hash_file_of_bytes(bytes: &[u8]) -> [u8; 32] {
    let dir = scratch_dir("hashtmp");
    let path = dir.join("tmp.img");
    fs::write(&path, bytes).unwrap();
    let d = hash_file(&path).unwrap();
    fs::remove_dir_all(&dir).ok();
    d
}
