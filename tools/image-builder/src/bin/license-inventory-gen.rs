//! CLI front-end for [`image_builder::license_inventory`] (WP-29,
//! SPEC §31).
//!
//! ```text
//! license-inventory-gen <Cargo.lock> <own-license> <output.md>
//! ```
//!
//! `<own-license>` is this workspace's own declared license (root
//! `Cargo.toml`'s `[workspace.package] license`, e.g. `"MIT OR
//! Apache-2.0"`), attributed to every path/workspace-member package
//! (see [`image_builder::license_inventory`]'s module doc). Registry
//! source directories are discovered automatically via
//! [`image_builder::license_inventory::default_registry_src_dirs`].

use image_builder::license_inventory::{build_license_inventory, default_registry_src_dirs, render_markdown};
use std::env;
use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: license-inventory-gen <Cargo.lock> <own-license> <output.md>");
        return ExitCode::from(2);
    }
    let lock_path = &args[1];
    let own_license = &args[2];
    let output_path = &args[3];

    let contents = match fs::read_to_string(lock_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: reading '{lock_path}': {e}");
            return ExitCode::from(2);
        }
    };

    let dirs = default_registry_src_dirs();
    let entries = match build_license_inventory(&contents, &dirs, own_license) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("error: parsing Cargo.lock: {e}");
            return ExitCode::from(1);
        }
    };

    let unknown_count = entries.iter().filter(|e| matches!(e.license, image_builder::license_inventory::LicenseSource::Unknown)).count();
    if unknown_count > 0 {
        eprintln!("warning: {unknown_count} package(s) have UNKNOWN license (no locally extracted source found)");
    }

    let markdown = render_markdown(&entries);
    if let Err(e) = fs::write(output_path, &markdown) {
        eprintln!("error: writing '{output_path}': {e}");
        return ExitCode::from(1);
    }

    println!("wrote {output_path} ({} packages, {unknown_count} unknown)", entries.len());
    ExitCode::SUCCESS
}
