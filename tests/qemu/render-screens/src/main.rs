//! Renders the shipped Stage 7 EXPORT screen to PPM, at its real on-screen
//! geometry, from a PUBLIC frozen test vector.
//!
//! # Why this exists
//!
//! The 2026-08-07 wallet-export feature draws a QR symbol of the account
//! xpub / descriptor / cosigner key. "Does that QR actually scan?" cannot be
//! answered by a unit test that only checks the module matrix — it depends on
//! the module *pixels* the screen finally paints. Nor can it be answered from
//! a QEMU screenshot: SPEC §11.2 refuses to generate at all under a detected
//! hypervisor, so the export screen is unreachable in emulation and this
//! program deliberately does not try to make it reachable.
//!
//! So this host binary calls the SHIPPED renderer — `seed_flow::screens::
//! export::render`, the exact function `seed-uefi-production` calls — against
//! an in-memory [`seed_core::contracts::Framebuffer`], and writes the result
//! out as a PPM that any image decoder (`zbarimg`, ZXing, OpenCV, a phone
//! camera pointed at the displayed file) can be run against.
//!
//! It is a host-only program: it produces no bootable artifact, it is not a
//! workspace member, and its entire input is
//! `tests/vectors/frozen/dice_only_24w_min_budget.json` — a published, public
//! test mnemonic that must never hold funds.
//!
//! Usage:
//!     cargo run --manifest-path tests/qemu/render-screens/Cargo.toml -- \
//!         tests/vectors/frozen/<case>.json <out-dir>

use std::fs;
use std::io::Write;
use std::path::Path;

use seed_core::arena::SecretArena;
use seed_core::contracts::{Framebuffer, WordCount};
use seed_flow::screens::export::{compute_export, ExportKind, ExportState, ExportValues};

/// In-memory framebuffer double: the same shape `seed-gop-ui`'s linear
/// framebuffer presents to the renderers, backed by a `Vec<u32>`.
struct MemFb {
    w: u32,
    h: u32,
    px: Vec<u32>,
}

impl MemFb {
    fn new(w: u32, h: u32) -> Self {
        Self { w, h, px: vec![0u32; (w as usize) * (h as usize)] }
    }

    /// Writes binary P6 PPM. Pixels are `0x00RRGGBB` (the packing every
    /// `seed-gop-ui` backend and every `seed-flow` style constant uses).
    fn write_ppm(&self, path: &Path) -> std::io::Result<()> {
        let mut out = Vec::with_capacity(self.px.len() * 3 + 32);
        out.extend_from_slice(format!("P6\n{} {}\n255\n", self.w, self.h).as_bytes());
        for p in &self.px {
            out.push(((p >> 16) & 0xFF) as u8);
            out.push(((p >> 8) & 0xFF) as u8);
            out.push((p & 0xFF) as u8);
        }
        fs::File::create(path)?.write_all(&out)
    }
}

impl Framebuffer for MemFb {
    fn dims(&self) -> (u32, u32) {
        (self.w, self.h)
    }
    fn put_row(&mut self, x: u32, y: u32, px: &[u32]) {
        if y >= self.h {
            return;
        }
        let start = (y as usize) * (self.w as usize) + (x as usize);
        let end = (start + px.len()).min((y as usize + 1) * self.w as usize);
        if start < end {
            self.px[start..end].copy_from_slice(&px[..end - start]);
        }
    }
}

/// Minimal field extraction from a frozen vector file — the same targeted
/// approach `seed-core`'s and `seed-flow`'s own tests use, so this program
/// needs no JSON dependency (SPEC §31: no new dependencies).
fn extract_u16_list(text: &str, field: &str) -> Vec<u16> {
    let key = format!("\"{field}\"");
    let start = text.find(&key).unwrap_or_else(|| panic!("missing field {field}"));
    let open = text[start..].find('[').expect("list start") + start;
    let close = text[open..].find(']').expect("list end") + open;
    text[open + 1..close]
        .split(',')
        .filter_map(|t| t.trim().parse::<u16>().ok())
        .collect()
}

fn main() {
    let mut args = std::env::args().skip(1);
    let case_path = args.next().expect("usage: alea-render-screens <case.json> <out-dir>");
    let out_dir = args.next().expect("usage: alea-render-screens <case.json> <out-dir>");
    fs::create_dir_all(&out_dir).expect("create out dir");

    let text = fs::read_to_string(&case_path).expect("read frozen case");
    let indexes = extract_u16_list(&text, "mnemonic_indexes");
    let word_count = match indexes.len() {
        12 => WordCount::Twelve,
        24 => WordCount::TwentyFour,
        n => panic!("unexpected mnemonic length {n}"),
    };
    println!("case: {case_path} ({} words)", indexes.len());

    // The screen's real geometry: the GOP mode both UEFI editions select.
    let (w, h) = (1920u32, 1080u32);

    for (name, kind) in [
        ("bip44", ExportKind::Bip44),
        ("bip49", ExportKind::Bip49),
        ("bip84", ExportKind::Bip84),
        ("bip86", ExportKind::Bip86),
        ("cosigner", ExportKind::Bip48Cosigner),
    ] {
        // A fresh arena per artifact, holding only the PUBLIC frozen
        // mnemonic; scrubbed again before it drops.
        let mut arena = SecretArena::new();
        arena.mnemonic_indexes()[..indexes.len()].copy_from_slice(&indexes);

        let st = ExportState { kind, slip132: false, cosigner_account: 0 };
        let mut values = ExportValues::new();
        compute_export(&mut arena, word_count, &st, &mut values)
            .unwrap_or_else(|e| panic!("compute_export failed for {name}: {e:?}"));

        let mut fb = MemFb::new(w, h);
        seed_flow::screens::export::render(&mut fb, &st, &values, "RENDER-HARNESS");
        let path = Path::new(&out_dir).join(format!("export-{name}.ppm"));
        fb.write_ppm(&path).expect("write ppm");
        println!("wrote {}", path.display());

        values.scrub();
        arena.scrub_all();
    }
}
