//! Build script for `seed-desktop-test` only (WP-28's own owned path;
//! does not touch `~/.cargo/config.toml` or any other crate's build).
//!
//! # Why this exists: `-ldl` on `x86_64-unknown-linux-musl`
//!
//! This crate's `winit`/`softbuffer` dependency tree (Linux backend: X11
//! via `x11-dl`, Wayland via `wayland-sys`/`dlib`) unconditionally emits
//! `cargo:rustc-link-lib=dl` on Linux, following the historical glibc
//! convention of a separate `libdl.so`/`.a`. musl folds every `dl*`
//! symbol (`dlopen`, `dlsym`, `dlclose`, `dlerror`) directly into `libc.a`
//! itself and ships no separate `libdl.a` — confirmed against this
//! toolchain's own bundled musl `libc.a`
//! (`$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-musl/lib/
//! self-contained/libc.a` contains all four symbols). The link therefore
//! fails not because a symbol is missing, but because the linker's
//! `-ldl` flag requires *a file named `libdl.a`* to exist somewhere on
//! the search path, and none does.
//!
//! The fix is exactly that missing (and otherwise-empty) file: this
//! script writes a zero-member static archive named `libdl.a` — the
//! minimal valid `ar` archive is its 8-byte global header with no
//! members — into `OUT_DIR` and adds that directory to the link search
//! path, only when targeting `linux`+`musl`. Every real `dl*` symbol
//! still resolves from musl's own `libc.a`, already linked in by rustc
//! itself; this stub only satisfies the linker's file-existence check.
//! On every other target (Windows, other libc, UEFI) this script is a
//! no-op.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();

    if target_os == "linux" && target_env == "musl" {
        let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR set by cargo"));
        let stub_path = out_dir.join("libdl.a");
        // Minimal valid empty `ar` archive: just the global magic, no
        // members -- see module doc comment.
        fs::write(&stub_path, b"!<arch>\n").expect("failed to write libdl.a stub");
        println!("cargo:rustc-link-search=native={}", out_dir.display());
    }
}
