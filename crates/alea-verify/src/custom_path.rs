//! Free-form custom derivation-path sub-tool (SPEC_DERIVATION_CUSTOM.md §9 /
//! §11.2), reached with `[P]` from a verification result screen. Ported from
//! `seed-desktop-test/src/launcher/custom_path.rs` to this no_std + alloc,
//! GOP-rendered UEFI edition.
//!
//! The typed path string is run through the net-new no_std parser
//! ([`seed_flow::flow_secret::path_parse::parse_path`]) and then the EXACT
//! same block/warn logic the production structured builder uses
//! ([`seed_flow::flow_secret::custom_path`], imported as `cp`) — reused
//! verbatim, never reimplemented (the `48'`/`45'`/`47'` blocks with distinct
//! messages; the short-path / coin_type / unconventional-combo warnings).
//!
//! # Throwaway / foreign seed only (SPEC_DERIVATION_CUSTOM §9.6)
//!
//! This operates only on the compat-derived public/throwaway seed the user
//! just reproduced (SPEC_COMPAT §7/§8's `NOT AN ALEA SEED` banner is carried
//! on every screen). The seed is borrowed for the entry/preview loop and
//! zeroized by its owner (`crate::verify`) on return. The result screen
//! shows the master fingerprint and the single derived address only — never
//! an xprv/xpub/seed/chain-code/pubkey (SPEC_DERIVATION_CUSTOM §10 / §24.3).

use alloc::string::{String, ToString};

use seed_core::contracts::AddressBuf;
use seed_derive::address::{address_at, ScriptType};
use seed_derive::bip32::{master_fingerprint, master_from_seed, MAX_DEPTH};
use seed_flow::flow_secret::custom_path as cp;
use seed_flow::flow_secret::path_parse::parse_path;
use seed_flow::flow_secret::verification::passphrase_caveat;
use seed_flow::output::TextOutput;
use seed_platform_x86::input::InputEvent as Key;
use zeroize::Zeroize;

use crate::verify::{MODE_BANNER_LINE_1, MODE_BANNER_LINE_2, RESULT_WATERMARK};

const ENTRY_TITLE: &str =
    "CUSTOM DERIVATION PATH (free-form) -- type a BIP32 path, e.g. m/84'/0'/0'/0/0";
const DERIVE_FAILED_LINE: &str =
    "could not derive that path (unexpected) -- edit the path and try again";

fn render_banner(out: &mut dyn TextOutput) {
    out.write_line(MODE_BANNER_LINE_1);
    out.write_line(MODE_BANNER_LINE_2);
    out.write_line(RESULT_WATERMARK);
    out.write_line("");
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    use core::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Renders the assembled path read-back (`m/84'/0'/0'/0/0`) for the child
/// array `path` (hardened bit already applied — the parser's output form).
fn path_string(path: &[u32]) -> String {
    let mut s = String::from("m");
    for &child in path {
        let hardened = child >= seed_derive::bip32::HARDENED_OFFSET;
        let value = if hardened {
            child - seed_derive::bip32::HARDENED_OFFSET
        } else {
            child
        };
        s.push('/');
        s.push_str(&value.to_string());
        if hardened {
            s.push('\'');
        }
    }
    s
}

fn render_entry(out: &mut dyn TextOutput, buffer: &str, error: Option<&str>) {
    out.clear();
    render_banner(out);
    out.write_line(ENTRY_TITLE);
    out.write_line("Rehearse the path->address mapping on this PUBLIC/THROWAWAY seed. Full keyboard.");
    out.write_line("");
    out.write_line(&format!("  {buffer}_"));
    out.write_line("");
    if let Some(reason) = error {
        out.write_line(&format!("could not read that path: {reason}"));
        out.write_line("");
    }
    out.write_line("Type the path   Backspace undo   Enter preview   Esc back");
}

fn render_block(out: &mut dyn TextOutput, kind: cp::BlockKind) {
    out.clear();
    render_banner(out);
    let body: [&str; 3] = match kind {
        cp::BlockKind::Bip48Multisig => [cp::BLOCK_BIP48_1, cp::BLOCK_BIP48_2, cp::BLOCK_BIP48_3],
        cp::BlockKind::Bip45Multisig => [cp::BLOCK_BIP45_1, cp::BLOCK_BIP45_2, cp::BLOCK_BIP45_3],
        cp::BlockKind::Bip47PaymentCode => [cp::BLOCK_BIP47_1, cp::BLOCK_BIP47_2, cp::BLOCK_BIP47_3],
    };
    for line in body {
        out.write_line(line);
    }
    out.write_line("");
    out.write_line(cp::BLOCK_BACK_PROMPT);
}

fn script_label_for_key(key: char) -> Option<ScriptType> {
    match key {
        '1' => Some(ScriptType::P2pkh),
        '2' => Some(ScriptType::P2shP2wpkh),
        '3' => Some(ScriptType::P2wpkh),
        '4' => Some(ScriptType::P2tr),
        _ => None,
    }
}

fn render_script_picker(out: &mut dyn TextOutput, path: &[u32]) {
    out.clear();
    render_banner(out);
    out.write_line(&format!("Path:   {}", path_string(path)));
    out.write_line("");
    out.write_line("Choose the address (script) type:");
    out.write_line(&format!("  [1] {}", cp::script_label(ScriptType::P2pkh)));
    out.write_line(&format!("  [2] {}", cp::script_label(ScriptType::P2shP2wpkh)));
    out.write_line(&format!("  [3] {}", cp::script_label(ScriptType::P2wpkh)));
    out.write_line(&format!("  [4] {}", cp::script_label(ScriptType::P2tr)));
    out.write_line("");
    out.write_line(cp::SCRIPT_HAZARD_1);
    out.write_line(cp::SCRIPT_HAZARD_2);
    out.write_line("");
    out.write_line("[1-4] pick   Esc back to path entry");
}

fn render_result(
    out: &mut dyn TextOutput,
    path: &[u32],
    script: ScriptType,
    fingerprint: [u8; 4],
    address: &str,
) {
    out.clear();
    render_banner(out);
    out.write_line(cp::RESULT_TITLE);
    out.write_line("");
    out.write_line(&format!("Master fingerprint   {}", bytes_to_hex(&fingerprint)));
    out.write_line(&format!("Path                 {}", path_string(path)));
    out.write_line(&format!("Script               {}", cp::script_label(script)));
    out.write_line(&format!("Address              {address}"));
    out.write_line("");
    out.write_line(passphrase_caveat(false));

    let purpose = cp::classify_purpose_child(path[0]);
    if matches!(purpose, cp::Purpose::Unknown) {
        out.write_line(cp::UNKNOWN_PURPOSE_NOTE);
    }
    if cp::is_short_path_for(purpose, path.len()) {
        out.write_line(cp::SHORT_PATH_WARN_1);
        out.write_line(cp::SHORT_PATH_WARN_2);
    }
    if cp::is_unconventional_combo_for(purpose, script) {
        out.write_line(cp::COMBO_WARN_1);
        out.write_line(cp::COMBO_WARN_2);
    }
    if cp::is_nonzero_coin_type_for(purpose, path) {
        out.write_line(cp::COIN_TYPE_WARN_1);
        out.write_line(cp::COIN_TYPE_WARN_2);
        out.write_line(cp::COIN_TYPE_WARN_3);
    }
    out.write_line("");
    out.write_line(cp::RESULT_FRAMING_1);
    out.write_line(cp::RESULT_FRAMING_2);
    out.write_line("");
    out.write_line("Any key returns to the path field.");
}

enum Stage {
    Entry {
        buffer: String,
        error: Option<&'static str>,
    },
    Block {
        buffer: String,
        kind: cp::BlockKind,
    },
    Script {
        buffer: String,
        path: [u32; MAX_DEPTH],
        depth: usize,
    },
    Result {
        buffer: String,
        path: [u32; MAX_DEPTH],
        depth: usize,
        script: ScriptType,
    },
    Done,
}

/// The master fingerprint of a seed (SPEC_DERIVATION_CUSTOM §10 rule 2).
/// Scrubs the intermediate master key / chain code (SPEC §13, §20.3).
fn seed_master_fingerprint(seed: &[u8; 64]) -> [u8; 4] {
    let mut key = [0u8; 32];
    let mut cc = [0u8; 32];
    master_from_seed(seed, &mut key, &mut cc);
    let fp = master_fingerprint(&key);
    key.zeroize();
    cc.zeroize();
    fp
}

/// The full free-form custom-path screen/dispatch loop over an injected
/// [`TextOutput`] and blocking key-read closure, operating on the
/// throwaway/foreign `seed`. Returns once the user backs out of the path
/// field (`Esc`). Number-key + Esc + free-form typing only.
pub fn run_over(out: &mut dyn TextOutput, mut next_key: impl FnMut() -> Key, seed: &[u8; 64]) {
    let fingerprint = seed_master_fingerprint(seed);
    let mut stage = Stage::Entry {
        buffer: String::new(),
        error: None,
    };
    loop {
        stage = match stage {
            Stage::Entry { mut buffer, error } => {
                render_entry(out, &buffer, error);
                match next_key() {
                    Key::Char(c) => {
                        buffer.push(c);
                        Stage::Entry {
                            buffer,
                            error: None,
                        }
                    }
                    Key::Backspace => {
                        buffer.pop();
                        Stage::Entry {
                            buffer,
                            error: None,
                        }
                    }
                    Key::Enter => {
                        let mut path = [0u32; MAX_DEPTH];
                        match parse_path(&buffer, &mut path) {
                            // Parse failure touches no seed -> benign re-enter.
                            Err(e) => Stage::Entry {
                                buffer,
                                error: Some(e.reason()),
                            },
                            Ok(depth) => match cp::classify_purpose_child(path[0]) {
                                // Multisig / payment-code purposes are BLOCKED
                                // before any derive, each with its own message.
                                cp::Purpose::MultisigBlock(kind) => Stage::Block { buffer, kind },
                                _ => Stage::Script {
                                    buffer,
                                    path,
                                    depth,
                                },
                            },
                        }
                    }
                    Key::Escape => Stage::Done,
                    _ => Stage::Entry { buffer, error },
                }
            }
            Stage::Block { buffer, kind } => {
                render_block(out, kind);
                let _ = next_key();
                Stage::Entry {
                    buffer,
                    error: None,
                }
            }
            Stage::Script {
                buffer,
                path,
                depth,
            } => {
                render_script_picker(out, &path[..depth]);
                match next_key() {
                    Key::Char(c) => match script_label_for_key(c) {
                        Some(script) => Stage::Result {
                            buffer,
                            path,
                            depth,
                            script,
                        },
                        None => Stage::Script {
                            buffer,
                            path,
                            depth,
                        },
                    },
                    Key::Escape => Stage::Entry {
                        buffer,
                        error: None,
                    },
                    _ => Stage::Script {
                        buffer,
                        path,
                        depth,
                    },
                }
            }
            Stage::Result {
                buffer,
                path,
                depth,
                script,
            } => {
                let mut addr = AddressBuf::empty();
                match address_at(seed, script, &path[..depth], &mut addr) {
                    Ok(()) => {
                        render_result(
                            out,
                            &path[..depth],
                            script,
                            fingerprint,
                            addr.as_str().unwrap_or("?"),
                        );
                        let _ = next_key();
                        Stage::Entry {
                            buffer,
                            error: None,
                        }
                    }
                    // Cryptographically unreachable for a real seed; benign
                    // re-enter (this edition, SPEC_DERIVATION_CUSTOM §9.6),
                    // NOT the production scrub-and-shutdown.
                    Err(_) => Stage::Entry {
                        buffer,
                        error: Some(DERIVE_FAILED_LINE),
                    },
                }
            }
            Stage::Done => return,
        };
    }
}
