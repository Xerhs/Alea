//! SPEC_DERIVATION_CUSTOM.md §9 / §11.2 — the SECONDARY desktop free-form
//! custom derivation-path tool, wired into the cross-device verification
//! launcher (reached with `[P]` from the compat result screen,
//! `crate::launcher::compat`).
//!
//! Unlike the PRIMARY production surface (the §11.5-safe STRUCTURED builder
//! in `seed_flow::flow_secret::custom_path`, air-gapped UEFI), this desktop
//! surface lets the user simply **type** a full path string
//! (`m/48'/0'/0'/2'/0/0`) — a desktop has a full keyboard, so the §11.5
//! constrained-key discipline does not apply here. The typed string is run
//! through the net-new `no_std` parser
//! (`seed_flow::flow_secret::path_parse`, §9.4) and then the EXACT same
//! block/warn logic the production builder uses (`48'`/`45'`/`47'` block
//! with distinct messages; short-path/coin_type/unconventional-combo
//! warnings) — reused verbatim from `seed_flow::flow_secret::custom_path`,
//! not reimplemented.
//!
//! # Throwaway / foreign seed only (SPEC_DERIVATION_CUSTOM §9.6)
//!
//! This tool never touches a real, funded Alea seed. It operates on the
//! **compat-derived public/throwaway seed** the user just reproduced from
//! the dice/coin event string they typed into the cross-device
//! verification tool (`crate::launcher::compat`) — SPEC_COMPAT §7/§8's
//! permanent `NOT AN ALEA SEED` / "public/throwaway" banner is carried on
//! every screen here. Per §9.6 this framing is a **banner/convention, not
//! a construction guarantee** (a user who typed their real dice log could
//! reproduce a funded seed on this hot, networked OS) — which is precisely
//! why the primary custom-path answer is the air-gapped production builder,
//! not this tool. The seed is borrowed for the entry/preview loop and
//! zeroized by its owner (`crate::launcher::compat`) on exit.
//!
//! # §24.3 hard rules (SPEC_DERIVATION_CUSTOM §10), inherited
//!
//! The result screen shows the **master fingerprint** and the single
//! resulting **address** only — never an xprv/xpub/seed/chain-code/pubkey
//! (`address_at` returns an address string only), no QR/export/persistence,
//! with the empty-passphrase caveat and the "reference value, not
//! authoritative" framing on every result (reused from
//! `seed_flow::flow_secret::custom_path`'s own screen copy).
//!
//! # Host-testable without a display (mirrors `crate::launcher::compat`)
//!
//! [`run_over`] is the whole screen/dispatch loop over an injected
//! `&mut dyn TextOutput` and a blocking key-read closure — no
//! `SharedFramebuffer`/`ChannelKeys`/window needed — so the full flow
//! (parse -> block/warn -> derive) is exercised in `#[cfg(test)]` below
//! against a scripted `Vec<KeyMsg>` and a fixed public test seed.

use seed_core::contracts::AddressBuf;
use seed_derive::address::{address_at, ScriptType};
use seed_derive::bip32::{master_fingerprint, master_from_seed, MAX_DEPTH};
use seed_flow::flow_secret::custom_path as cp;
use seed_flow::flow_secret::path_parse::parse_path;
use seed_flow::flow_secret::verification::passphrase_caveat;
use seed_flow::output::TextOutput;
use zeroize::Zeroize;

use crate::channel_keys::KeyMsg;
use crate::launcher::compat::{MODE_BANNER_LINE_1, MODE_BANNER_LINE_2, RESULT_WATERMARK};

/// Screen title for the free-form entry field (SPEC_DERIVATION_CUSTOM §11.2).
const ENTRY_TITLE: &str = "CUSTOM DERIVATION PATH (free-form) -- type a BIP32 path, e.g. m/84'/0'/0'/0/0";
/// The benign "could not derive" line for the (cryptographically
/// unreachable) `DeriveError` case (SPEC_DERIVATION_CUSTOM §9.6): a benign
/// re-enter on this edition, never the production scrub-and-shutdown.
const DERIVE_FAILED_LINE: &str = "could not derive that path (unexpected) -- edit the path and try again";

/// Renders the SPEC_COMPAT §7/§8 `NOT AN ALEA SEED` banner block that opens
/// **every** screen this tool shows (SPEC_DERIVATION_CUSTOM §9.6). Mirrors
/// `crate::launcher::compat::render_common_banner` and reuses its verbatim
/// banner constants.
fn render_banner(out: &mut dyn TextOutput) {
    out.write_line(MODE_BANNER_LINE_1);
    out.write_line(MODE_BANNER_LINE_2);
    out.write_line(RESULT_WATERMARK);
    out.write_line("");
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
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
        let value = if hardened { child - seed_derive::bip32::HARDENED_OFFSET } else { child };
        s.push('/');
        s.push_str(&value.to_string());
        if hardened {
            s.push('\'');
        }
    }
    s
}

// ============================================================================
// Screens
// ============================================================================

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

/// Renders the browse-only result screen for one derived leaf
/// (SPEC_DERIVATION_CUSTOM §11.2 step 3): master fingerprint, path, script
/// type, address, the empty-passphrase caveat, every applicable
/// §5/§6/§7.2/§8 advisory, the "reference value" framing, and (via
/// [`render_banner`]) the permanent `NOT AN ALEA SEED` banner.
fn render_result(out: &mut dyn TextOutput, path: &[u32], script: ScriptType, fingerprint: [u8; 4], address: &str) {
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

// ============================================================================
// The screen/dispatch loop
// ============================================================================

enum Stage {
    Entry { buffer: String, error: Option<&'static str> },
    Block { buffer: String, kind: cp::BlockKind },
    Script { buffer: String, path: [u32; MAX_DEPTH], depth: usize },
    Result { buffer: String, path: [u32; MAX_DEPTH], depth: usize, script: ScriptType },
    Done,
}

/// The master fingerprint of a seed (SPEC_DERIVATION_CUSTOM §10 rule 2:
/// the master fingerprint is the only fingerprint ever shown). Scrubs the
/// intermediate master key / chain code (SPEC §13, §20.3).
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
/// throwaway/foreign `seed` (SPEC_DERIVATION_CUSTOM §9.6). Returns to the
/// caller once the user backs out of the path field (`Esc`). No
/// `SharedFramebuffer`/`ChannelKeys`/window dependency (host-testable).
pub fn run_over(out: &mut dyn TextOutput, mut next_key: impl FnMut() -> KeyMsg, seed: &[u8; 64]) {
    let fingerprint = seed_master_fingerprint(seed);
    let mut stage = Stage::Entry { buffer: String::new(), error: None };
    loop {
        stage = match stage {
            Stage::Entry { mut buffer, error } => {
                render_entry(out, &buffer, error);
                match next_key() {
                    KeyMsg::Char(c) => {
                        buffer.push(c);
                        Stage::Entry { buffer, error: None }
                    }
                    KeyMsg::Backspace => {
                        buffer.pop();
                        Stage::Entry { buffer, error: None }
                    }
                    KeyMsg::Enter => {
                        let mut path = [0u32; MAX_DEPTH];
                        match parse_path(&buffer, &mut path) {
                            // Parse failure touches no seed -> benign re-enter (§9.6).
                            Err(e) => Stage::Entry { buffer, error: Some(e.reason()) },
                            Ok(depth) => match cp::classify_purpose_child(path[0]) {
                                // A multisig / payment-code purpose is BLOCKED before
                                // any derive (§5), each with its distinct message.
                                cp::Purpose::MultisigBlock(kind) => Stage::Block { buffer, kind },
                                _ => Stage::Script { buffer, path, depth },
                            },
                        }
                    }
                    KeyMsg::Escape => Stage::Done,
                    _ => Stage::Entry { buffer, error },
                }
            }
            Stage::Block { buffer, kind } => {
                render_block(out, kind);
                let _ = next_key();
                // Return to the field with the offending path kept for editing.
                Stage::Entry { buffer, error: None }
            }
            Stage::Script { buffer, path, depth } => {
                render_script_picker(out, &path[..depth]);
                match next_key() {
                    KeyMsg::Char(c) => match script_label_for_key(c) {
                        Some(script) => Stage::Result { buffer, path, depth, script },
                        None => Stage::Script { buffer, path, depth },
                    },
                    KeyMsg::Escape => Stage::Entry { buffer, error: None },
                    _ => Stage::Script { buffer, path, depth },
                }
            }
            Stage::Result { buffer, path, depth, script } => {
                let mut addr = AddressBuf::empty();
                match address_at(seed, script, &path[..depth], &mut addr) {
                    Ok(()) => {
                        render_result(out, &path[..depth], script, fingerprint, addr.as_str().unwrap_or("?"));
                        let _ = next_key();
                        Stage::Entry { buffer, error: None }
                    }
                    // Cryptographically unreachable for a real seed; a benign
                    // re-enter here (different edition, different constraints, §9.6),
                    // NOT the production §27.2 scrub-and-shutdown.
                    Err(_) => Stage::Entry { buffer, error: Some(DERIVE_FAILED_LINE) },
                }
            }
            Stage::Done => return,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seed_core::contracts::WordCount;

    /// Keeps the FULL transcript of every screen ever rendered (like
    /// `crate::launcher::compat`'s own test double), so a full-flow test can
    /// assert on an earlier screen's content after later screens redrew.
    struct RecordingOutput {
        lines: Vec<String>,
    }
    impl RecordingOutput {
        fn new() -> Self {
            Self { lines: Vec::new() }
        }
        fn joined(&self) -> String {
            self.lines.join("\n")
        }
    }
    impl TextOutput for RecordingOutput {
        fn write_line(&mut self, line: &str) {
            self.lines.push(line.to_string());
        }
        fn clear(&mut self) {}
    }

    struct ScriptedKeys {
        script: std::vec::IntoIter<KeyMsg>,
    }
    impl ScriptedKeys {
        fn new(keys: Vec<KeyMsg>) -> Self {
            Self { script: keys.into_iter() }
        }
        fn next(&mut self) -> KeyMsg {
            self.script.next().unwrap_or(KeyMsg::Escape)
        }
    }

    fn typed(s: &str) -> Vec<KeyMsg> {
        s.chars().map(KeyMsg::Char).collect()
    }

    /// The canonical BIP39 "abandon abandon ... about" 12-word public test
    /// seed (empty passphrase) — the widely-published BIP84 vector seed,
    /// used purely as a throwaway/foreign seed for these host tests.
    fn abandon_seed() -> [u8; 64] {
        fn word_index(target: &str) -> u16 {
            (0..2048u16).find(|&i| seed_core::bip39::word(i) == target).expect("word in list")
        }
        let mut indexes = [0u16; 24];
        for slot in indexes.iter_mut().take(11) {
            *slot = word_index("abandon");
        }
        indexes[11] = word_index("about");
        let mut seed = [0u8; 64];
        seed_core::bip39::mnemonic_to_seed(&indexes, WordCount::Twelve, &mut seed);
        seed
    }

    fn run(keys: Vec<KeyMsg>) -> String {
        let seed = abandon_seed();
        let mut scripted = ScriptedKeys::new(keys);
        let mut out = RecordingOutput::new();
        run_over(&mut out, || scripted.next(), &seed);
        out.joined()
    }

    /// DERIVE CROSS-CHECK (task DoD): the published BIP84 vector
    /// `m/84'/0'/0'/0/1` on the abandon seed renders exactly
    /// `bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g`, and the master
    /// fingerprint is the BIP84-mediawiki-pinned `73c5da0a`.
    #[test]
    fn derive_cross_check_published_bip84_second_receive() {
        let mut keys = Vec::new();
        keys.extend(typed("m/84'/0'/0'/0/1"));
        keys.push(KeyMsg::Enter); // parse -> script picker
        keys.push(KeyMsg::Char('3')); // P2WPKH -> result
        keys.push(KeyMsg::Escape); // result -> back to entry
        keys.push(KeyMsg::Escape); // entry -> exit
        let joined = run(keys);
        assert!(joined.contains("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"), "missing BIP84 receive #1 in:\n{joined}");
        assert!(joined.contains("Master fingerprint   73c5da0a"));
        assert!(joined.contains(RESULT_WATERMARK), "throwaway banner must be on the result screen");
        assert!(joined.to_lowercase().contains("passphrase"), "empty-passphrase caveat must appear (SPEC §24.3 rule 5)");
    }

    /// First-receive BIP84 leaf also matches its published vector.
    #[test]
    fn derive_cross_check_published_bip84_first_receive() {
        let mut keys = typed("m/84'/0'/0'/0/0");
        keys.push(KeyMsg::Enter);
        keys.push(KeyMsg::Char('3'));
        let joined = run(keys);
        assert!(joined.contains("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"));
    }

    /// The `48'`/`45'`/`47'` multisig / payment-code purposes are BLOCKED
    /// before any derive, each with its own distinct message (§5).
    #[test]
    fn multisig_purposes_are_blocked_with_distinct_messages() {
        for (path, needle) in
            [("m/48'/0'/0'/2'/0/0", "48'"), ("m/45'/0/0/0", "45'"), ("m/47'/0'/0'", "47'")]
        {
            let mut keys = typed(path);
            keys.push(KeyMsg::Enter); // parse -> block
            keys.push(KeyMsg::Enter); // ack block -> entry
            let joined = run(keys);
            assert!(joined.contains("BLOCKED"), "{path}: expected a block screen");
            assert!(joined.contains(needle), "{path}: block screen should name {needle}");
            // A blocked path must NEVER reach a rendered address / script picker.
            assert!(!joined.contains("Choose the address (script) type:"), "{path}: blocked path reached the script picker");
        }
        // The 47' message is its OWN wording (ECDH payment codes, not P2WSH).
        let mut keys = typed("m/47'/0'/0'");
        keys.push(KeyMsg::Enter);
        keys.push(KeyMsg::Enter);
        let joined = run(keys);
        assert!(joined.contains("ECDH"));
        assert!(!joined.to_lowercase().contains("p2wsh"));
    }

    /// §6 short-path warning fires for a known purpose above a receive leaf.
    #[test]
    fn short_path_warning_fires() {
        let mut keys = typed("m/84'/0'"); // depth 2 account node
        keys.push(KeyMsg::Enter);
        keys.push(KeyMsg::Char('3'));
        let joined = run(keys);
        assert!(joined.contains(cp::SHORT_PATH_WARN_1));
    }

    /// §8 coin_type warning fires when the second level is not 0'.
    #[test]
    fn coin_type_warning_fires() {
        let mut keys = typed("m/84'/1'/0'/0/0"); // coin_type 1'
        keys.push(KeyMsg::Enter);
        keys.push(KeyMsg::Char('3'));
        let joined = run(keys);
        assert!(joined.contains(cp::COIN_TYPE_WARN_1));
    }

    /// §7.2 unconventional-combination warning fires when a known purpose is
    /// rendered with a non-conventional script type (84' as legacy P2PKH).
    #[test]
    fn unconventional_combo_warning_fires() {
        let mut keys = typed("m/84'/0'/0'/0/0");
        keys.push(KeyMsg::Enter);
        keys.push(KeyMsg::Char('1')); // P2PKH (not the 84' convention)
        let joined = run(keys);
        assert!(joined.contains(cp::COMBO_WARN_1));
    }

    /// A parse failure stays on the field with a typed reason and never
    /// reaches a script picker or address (§9.6 benign re-enter).
    #[test]
    fn parse_failure_is_a_benign_reenter() {
        let mut keys = typed("m/44''"); // R10 duplicated marker
        keys.push(KeyMsg::Enter);
        let joined = run(keys);
        assert!(joined.contains("could not read that path:"));
        assert!(!joined.contains("Choose the address (script) type:"));
    }

    /// Backspace edits the field; a corrected path then derives.
    #[test]
    fn backspace_edits_then_a_valid_path_derives() {
        let mut keys = typed("m/84'/0'/0'/0/0x"); // trailing junk
        keys.push(KeyMsg::Backspace); // drop the 'x'
        keys.push(KeyMsg::Enter);
        keys.push(KeyMsg::Char('3'));
        let joined = run(keys);
        assert!(joined.contains("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"));
    }

    /// §24.3 rule 1/2: no result screen ever names a secret artifact.
    #[test]
    fn result_never_mentions_secret_artifacts() {
        let mut keys = typed("m/84'/0'/0'/0/0");
        keys.push(KeyMsg::Enter);
        keys.push(KeyMsg::Char('3'));
        let joined = run(keys).to_lowercase();
        for bad in ["xprv", "xpub", "private key", "chain code"] {
            assert!(!joined.contains(bad), "result must never mention {bad}");
        }
    }

    /// Esc at the empty field returns immediately without derive.
    #[test]
    fn escape_at_entry_returns_immediately() {
        let joined = run(std::vec![KeyMsg::Escape]);
        assert!(joined.contains(ENTRY_TITLE));
        assert!(!joined.contains("Master fingerprint"));
    }
}
