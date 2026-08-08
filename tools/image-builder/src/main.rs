//! CLI front-end for the deterministic FAT16 boot-media image builder.
//!
//! SPEC §5 ("Standard removable-media boot path `\EFI\BOOT\BOOTX64.EFI`")
//! and SPEC §32 ("deterministic USB image"). Two forms:
//!
//! ```text
//! image-builder <bootx64.efi> <output.img>
//! image-builder <bootx64.efi> <output.img> <verify.efi>
//! ```
//!
//! The three-argument form ALSO places the separate verifier at
//! `\EFI\ALEA\VERIFY.EFI` (SPEC_MAIN_MENU.md §17.4) alongside the standard
//! `\EFI\BOOT\BOOTX64.EFI` boot path — this is what the production release
//! (`scripts/build-release.sh`, `.github/workflows/release.yml`) uses so the
//! landing launcher's Verify item can chain-load it. The optional verifier is
//! the LAST argument so the historical two-argument form keeps working
//! unchanged for existing callers/tests.
//!
//! Emits `<output.img>` and `<output.img>.sha256` (a `sha256sum`-compatible
//! line: `<hex digest>  <basename>\n`), per SPEC §32's requirement that
//! every release artifact publish its hash.

use std::env;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    // Disambiguated purely by argument count so the historical two-argument
    // form keeps working unchanged for existing callers/tests:
    //   argc 3: <bootx64.efi> <output.img>               (single file)
    //   argc 4: <bootx64.efi> <output.img> <verify.efi>  (dual file)
    let (bootx64_path, output_path, verify_path) = match args.len() {
        3 => (args[1].clone(), args[2].clone(), None),
        4 => (args[1].clone(), args[2].clone(), Some(args[3].clone())),
        _ => {
            eprintln!("usage: image-builder <bootx64.efi> <output.img> [verify.efi]");
            return ExitCode::from(2);
        }
    };

    let bootx64 = match fs::read(&bootx64_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: reading '{bootx64_path}': {e}");
            return ExitCode::from(2);
        }
    };

    let image = match &verify_path {
        Some(vp) => {
            let verify = match fs::read(vp) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("error: reading '{vp}': {e}");
                    return ExitCode::from(2);
                }
            };
            image_builder::build_image_with_verify(&bootx64, &verify)
        }
        None => image_builder::build_image(&bootx64),
    };
    let image = match image {
        Ok(img) => img,
        Err(e) => {
            eprintln!("error: building image: {e}");
            return ExitCode::from(1);
        }
    };

    let digest = image_builder::sha256_hex(&image);

    if let Err(e) = fs::write(&output_path, &image) {
        eprintln!("error: writing '{output_path}': {e}");
        return ExitCode::from(1);
    }

    let basename = Path::new(&output_path)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| output_path.clone());
    let hash_path = format!("{output_path}.sha256");
    let hash_line = format!("{digest}  {basename}\n");
    if let Err(e) = fs::write(&hash_path, hash_line) {
        eprintln!("error: writing '{hash_path}': {e}");
        return ExitCode::from(1);
    }

    println!("wrote {output_path} ({} bytes)", image.len());
    println!("sha256: {digest}");
    ExitCode::SUCCESS
}
