//! Integration test: builds a tiny image twice via the public library API
//! and asserts the two builds are byte-identical (SPEC §32; also exercised
//! at unit level in `src/lib.rs`, repeated here as a black-box crate-API
//! check per the work-package's explicit test requirement).

use image_builder::build_image;

#[test]
fn two_builds_of_a_tiny_efi_are_byte_identical() {
    let payload: Vec<u8> = b"FAKE_EFI_HEADER_BYTES_FOR_DETERMINISM_TEST".to_vec();
    let a = build_image(&payload).expect("build a");
    let b = build_image(&payload).expect("build b");
    assert_eq!(a, b);
    assert_eq!(image_builder::sha256_hex(&a), image_builder::sha256_hex(&b));
}
