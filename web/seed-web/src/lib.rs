//! `seed-web` — Alea Offline Web Edition WASM glue (SPEC_WEB_OFFLINE §7/§8).
//!
//! A `cdylib` for `wasm32-unknown-unknown` exporting a small, auditable,
//! **zero-import** ABI (raw `#[no_mangle] extern "C"` functions over two
//! caller-provided linear-memory buffers) — no `wasm-bindgen`, no `js-sys`,
//! no `web-sys`, no `getrandom`, no `std`. It links ONLY the three Phase-1
//! crates: `seed-core`, `seed-derive`, `seed-compat` (NOT `seed-protocol` —
//! M6/§7). Secrets stay in WASM linear memory and are scrubbed after use; only
//! PUBLIC values (addresses + master fingerprint, plus reproduced
//! mnemonic/entropy for the rehearsal & foreign-compat demos) ever cross to JS.
//!
//! ## ABI (all lengths in bytes; every fn returns i32 = output length written
//! to OUTPUT, or a negative error code)
//!
//! * `io_input_ptr() -> *mut u8`   — start of the input scratch buffer
//! * `io_output_ptr() -> *mut u8`  — start of the output scratch buffer
//! * `io_input_cap() -> usize`     — input capacity
//! * `io_output_cap() -> usize`    — output capacity
//! * `rehearsal() -> i32`          — feature 1: all-zero public vector
//! * `verify(m_len, p_len) -> i32` — feature 2: mnemonic (+opt passphrase)
//! * `verify_grid(m_len, p_len, standard_id, account, change, index_start, n)
//!   -> i32` — feature 2b: "more derivation options" (bounded first-N grid of
//!   receive addresses for one chosen standard/account'/change/index range)
//! * `compat(enc_id, in_len) -> i32` — feature 3: seed-compat Method C
//! * `wasm_sha256(len) -> i32`     — hash INPUT[..len]; 64 hex chars out
//!
//! Output is line-based ASCII: `key\tvalue\n` records. Callers split on `\n`
//! then on the first `\t`. Values never contain `\t`/`\n` (addresses,
//! fingerprints, hex, and space-joined mnemonics are all safe). The first line
//! is always `status\tok` or `status\terror`.

#![no_std]
#![allow(static_mut_refs)]

use core::ptr::addr_of_mut;

use seed_compat::entropy_encoding::{entropy_encoding_derive, Encoding, EntropyEncodingError};
use seed_compat::WordCount as CompatWordCount;
use seed_core::bip39::{entropy_to_indexes, mnemonic_to_seed_with_passphrase_bytes, word};
use seed_core::contracts::{AddressBuf, PathStandard, WordCount};
use seed_core::hash::sha256;
use seed_core::passphrase::MAX_PASSPHRASE_LEN;
use seed_derive::address::{address_at, first_address, ScriptType};
use seed_derive::bip32::{master_fingerprint, master_from_seed, preset_path};

// --------------------------------------------------------------------------
// Panic handler (panic=abort — SPEC_WEB_OFFLINE §5.2). On wasm this traps.
// No secret value is ever placed in a panic message; the core is written to
// avoid panicking on secret paths (SPEC §13/§27.3).
// --------------------------------------------------------------------------
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

// --------------------------------------------------------------------------
// Shared linear-memory scratch buffers. Zeroed statics live in BSS, so their
// size does NOT inflate the .wasm file (only initial memory pages). INPUT is
// sized to hold the whole embedded .wasm for the in-page self-hash (§5.3).
// --------------------------------------------------------------------------
const INPUT_CAP: usize = 640 * 1024;
const OUTPUT_CAP: usize = 8 * 1024;

static mut INPUT: [u8; INPUT_CAP] = [0u8; INPUT_CAP];
static mut OUTPUT: [u8; OUTPUT_CAP] = [0u8; OUTPUT_CAP];

#[no_mangle]
pub extern "C" fn io_input_ptr() -> *mut u8 {
    addr_of_mut!(INPUT) as *mut u8
}

#[no_mangle]
pub extern "C" fn io_output_ptr() -> *mut u8 {
    addr_of_mut!(OUTPUT) as *mut u8
}

#[no_mangle]
pub extern "C" fn io_input_cap() -> usize {
    INPUT_CAP
}

#[no_mangle]
pub extern "C" fn io_output_cap() -> usize {
    OUTPUT_CAP
}

// Negative return codes (distinct from any non-negative length).
const ERR_OUTPUT_OVERFLOW: i32 = -1;
const ERR_BAD_ARGS: i32 = -2;

// --------------------------------------------------------------------------
// A bounded writer over the OUTPUT buffer. Every write is length-checked;
// once overflowed it stays overflowed and the entry point returns
// ERR_OUTPUT_OVERFLOW rather than emitting a truncated record.
// --------------------------------------------------------------------------
struct Writer {
    len: usize,
    overflow: bool,
}

impl Writer {
    fn new() -> Self {
        Writer { len: 0, overflow: false }
    }

    fn raw(&mut self, bytes: &[u8]) {
        if self.overflow {
            return;
        }
        let end = self.len + bytes.len();
        if end > OUTPUT_CAP {
            self.overflow = true;
            return;
        }
        // SAFETY: bounds checked above; exclusive access via &mut self and the
        // single-threaded wasm model.
        let out = unsafe { &mut OUTPUT };
        out[self.len..end].copy_from_slice(bytes);
        self.len = end;
    }

    fn str(&mut self, s: &str) {
        self.raw(s.as_bytes());
    }

    /// Emit one `key\tvalue\n` record whose value is a raw ASCII string.
    fn kv(&mut self, key: &str, value: &str) {
        self.str(key);
        self.raw(b"\t");
        self.str(value);
        self.raw(b"\n");
    }

    fn key(&mut self, key: &str) {
        self.str(key);
        self.raw(b"\t");
    }

    fn hex(&mut self, bytes: &[u8]) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for &b in bytes {
            self.raw(&[HEX[(b >> 4) as usize], HEX[(b & 0x0f) as usize]]);
        }
    }

    /// Emit an unsigned decimal integer (no allocation).
    fn dec(&mut self, mut v: u32) {
        let mut buf = [0u8; 10];
        let mut i = buf.len();
        if v == 0 {
            self.raw(b"0");
            return;
        }
        while v > 0 {
            i -= 1;
            buf[i] = b'0' + (v % 10) as u8;
            v /= 10;
        }
        self.raw(&buf[i..]);
    }

    fn nl(&mut self) {
        self.raw(b"\n");
    }

    fn finish(self) -> i32 {
        if self.overflow {
            ERR_OUTPUT_OVERFLOW
        } else {
            self.len as i32
        }
    }
}

// --------------------------------------------------------------------------
// Shared derivation: from a validated (indexes, count) + passphrase bytes,
// emit the master fingerprint and the four first-receive addresses. Every
// secret intermediate (seed, master key/chain-code) is scrubbed on the way
// out (SPEC §20.3 / SPEC_WEB_OFFLINE §3.4 WASM-side scrub). Only PUBLIC values
// are written to OUTPUT (SPEC §24.3 / §9.4: never a private key/xprv/WIF/seed).
// --------------------------------------------------------------------------
fn emit_public_values(w: &mut Writer, indexes: &[u16; 24], count: WordCount, passphrase: &[u8]) {
    let mut seed = [0u8; 64];
    mnemonic_to_seed_with_passphrase_bytes(indexes, count, passphrase, &mut seed);

    // Master fingerprint (first 4 bytes of hash160(compressed master pubkey)).
    let mut mkey = [0u8; 32];
    let mut mcc = [0u8; 32];
    master_from_seed(&seed, &mut mkey, &mut mcc);
    let fp = master_fingerprint(&mkey);
    // Chain code + master private key are secret; scrub immediately.
    seed_core::arena::scrub_slice(&mut mkey);
    seed_core::arena::scrub_slice(&mut mcc);

    w.key("fingerprint");
    w.hex(&fp);
    w.nl();

    let standards = [
        ("bip44", PathStandard::Bip44),
        ("bip49", PathStandard::Bip49),
        ("bip84", PathStandard::Bip84),
        ("bip86", PathStandard::Bip86),
    ];
    for (label, std) in standards {
        let mut buf = AddressBuf::empty();
        match first_address(&seed, std, &mut buf) {
            Ok(()) => match buf.as_str() {
                Some(s) => w.kv(label, s),
                None => w.kv(label, "?"),
            },
            Err(_) => w.kv(label, "derive-error"),
        }
    }

    // Scrub the 64-byte BIP39 seed (secret) before returning.
    seed_core::arena::scrub_slice(&mut seed);
}

/// Feature 2b shared derivation (SPEC_DERIVATION_OPTIONS Part A / §A.4.3): from
/// a validated (indexes, count) + passphrase, emit the master fingerprint and a
/// bounded first-N table of receive addresses for ONE chosen preset standard,
/// account', change chain, and starting index. Each address is derived on
/// demand via `preset_path` + `address_at(seed, ScriptType::for_standard(..))`
/// — the SAME seed as feature 2, just at additional public derivation paths.
///
/// §24.3 STRICT: emits ONLY the master fingerprint and rendered addresses.
/// Never an xprv/xpub, private key, WIF, seed, or chain code. Every secret
/// intermediate (seed, master key/chain-code) is scrubbed on the way out
/// (SPEC §20.3). Address lines are `addr\t<index> <address>` (the value holds
/// no `\t`/`\n` — index is decimal, the address never contains a space).
#[allow(clippy::too_many_arguments)]
fn emit_grid_values(
    w: &mut Writer,
    indexes: &[u16; 24],
    count: WordCount,
    passphrase: &[u8],
    standard: PathStandard,
    account: u32,
    change: u32,
    index_start: u32,
    n: u32,
) {
    let mut seed = [0u8; 64];
    mnemonic_to_seed_with_passphrase_bytes(indexes, count, passphrase, &mut seed);

    // Master fingerprint (first 4 bytes of hash160(compressed master pubkey)).
    let mut mkey = [0u8; 32];
    let mut mcc = [0u8; 32];
    master_from_seed(&seed, &mut mkey, &mut mcc);
    let fp = master_fingerprint(&mkey);
    seed_core::arena::scrub_slice(&mut mkey);
    seed_core::arena::scrub_slice(&mut mcc);

    w.key("fingerprint");
    w.hex(&fp);
    w.nl();

    let script = ScriptType::for_standard(standard);
    // `index_start + (n - 1)` is bounds-checked by the caller to neither
    // overflow nor exceed INDEX_MAX, so `index_start + i` is always in range.
    for i in 0..n {
        let idx = index_start + i;
        let path = preset_path(standard, account, change, idx);
        let mut buf = AddressBuf::empty();
        w.key("addr");
        w.dec(idx);
        w.raw(b" ");
        match address_at(&seed, script, &path, &mut buf) {
            Ok(()) => match buf.as_str() {
                Some(s) => w.str(s),
                None => w.str("?"),
            },
            Err(_) => w.str("derive-error"),
        }
        w.nl();
    }

    // Scrub the 64-byte BIP39 seed (secret) before returning.
    seed_core::arena::scrub_slice(&mut seed);
}

/// Emit `mnemonic\t<space-joined words>` for the first `count` indexes.
/// Used only for the rehearsal (public test vector) and the foreign-compat
/// reproduction — both explicitly non-secret framings. Verification (feature
/// 2) never echoes the mnemonic back (the user already holds it).
fn emit_mnemonic(w: &mut Writer, indexes: &[u16], count: usize) {
    w.key("mnemonic");
    for (i, &idx) in indexes.iter().take(count).enumerate() {
        if i != 0 {
            w.raw(b" ");
        }
        w.str(word(idx));
    }
    w.nl();
}

// --------------------------------------------------------------------------
// Feature 1 — Fixed public-vector rehearsal (SPEC_WEB_OFFLINE §13.2 item 1).
// all-zero entropy (16 bytes 0x00) -> BIP39 mnemonic -> 4 first-receive
// addresses + master fingerprint. Deterministic byte-parity demo.
// --------------------------------------------------------------------------
#[no_mangle]
pub extern "C" fn rehearsal() -> i32 {
    let entropy = [0u8; 16];
    let mut indexes = [0u16; 24];
    let count = match entropy_to_indexes(&entropy, &mut indexes) {
        Ok(c) => c,
        Err(_) => return ERR_BAD_ARGS,
    };

    let mut w = Writer::new();
    w.kv("status", "ok");
    w.kv("mode", "rehearsal");
    emit_mnemonic(&mut w, &indexes, count as usize);
    emit_public_values(&mut w, &indexes, count, &[]);
    w.finish()
}

// --------------------------------------------------------------------------
// Feature 2 — Verification display (SPEC_WEB_OFFLINE §13.2 item 2 / §9.4).
// INPUT layout: [0..m_len) = mnemonic ASCII, [m_len..m_len+p_len) = passphrase
// ASCII. Validates the mnemonic (words + BIP39 checksum) then emits ONLY the
// master fingerprint + first receive address for BIP44/49/84/86. Never the
// mnemonic, seed, xprv, private key, WIF, or chain code.
// --------------------------------------------------------------------------
#[no_mangle]
pub extern "C" fn verify(m_len: usize, p_len: usize) -> i32 {
    if m_len > INPUT_CAP || p_len > MAX_PASSPHRASE_LEN || m_len + p_len > INPUT_CAP {
        // Lengths are untrusted on this path (a caller/embedder may have written
        // secret bytes into INPUT before passing an over-long or inconsistent
        // length). Scrub the FULL INPUT buffer before returning (SPEC §20.3).
        scrub_input(INPUT_CAP);
        return err_line("bad-input-length");
    }

    // Copy the mnemonic + passphrase out of the shared INPUT buffer into local
    // fixed buffers so we can scrub INPUT afterwards regardless of outcome.
    let inp = unsafe { &INPUT };
    let mnemonic_bytes = &inp[..m_len];
    let passphrase_bytes = &inp[m_len..m_len + p_len];

    // Passphrase must be printable ASCII (SPEC_PASSPHRASE §3.2 discipline).
    for &b in passphrase_bytes {
        if !(0x20..=0x7e).contains(&b) {
            // Scrub the written secret region so verify() scrubs on EVERY
            // outcome, as its doc comment promises (mirrors verify_grid()).
            scrub_input(m_len + p_len);
            return err_line("passphrase-not-printable-ascii");
        }
    }

    let mut indexes = [0u16; 24];
    let count = match parse_and_validate_mnemonic(mnemonic_bytes, &mut indexes) {
        Ok(c) => c,
        Err(msg) => {
            // Scrub secret-bearing scratch before returning.
            scrub_indexes(&mut indexes);
            scrub_input(m_len + p_len);
            return err_line(msg);
        }
    };

    let mut pass_local = [0u8; MAX_PASSPHRASE_LEN];
    pass_local[..p_len].copy_from_slice(passphrase_bytes);

    let mut w = Writer::new();
    w.kv("status", "ok");
    w.kv("mode", "verify");
    emit_public_values(&mut w, &indexes, count, &pass_local[..p_len]);

    // Scrub every secret buffer we touched (SPEC §20.3).
    scrub_indexes(&mut indexes);
    seed_core::arena::scrub_slice(&mut pass_local);
    scrub_input(m_len + p_len);
    w.finish()
}

// --------------------------------------------------------------------------
// Feature 2b — "More derivation options" bounded grid (SPEC_DERIVATION_OPTIONS
// Part A, the desktop [M] menu mirrored for the web). Same INPUT layout as
// `verify`: [0..m_len) mnemonic, [m_len..m_len+p_len) passphrase. Validates the
// mnemonic + passphrase exactly as `verify`, then emits the master fingerprint
// + the first `n` receive addresses of ONE chosen standard (`standard_id`
// 0..3 = BIP44/49/84/86) at account' `account`, change chain `change`
// (0 external / 1 internal), indices `index_start .. index_start + n`.
//
// Bounds (honest + sane for on-demand web derivation): standard 0..=3,
// account 0..=N_ACCOUNT_MAX, change in {0,1}, n in 1..=N_GRID_MAX, and the last
// index (`index_start + n - 1`) must not overflow nor exceed N_INDEX_MAX. Any
// out-of-range parameter is refused with a typed `status\terror` line. §24.3
// STRICT: addresses + fingerprint ONLY (see `emit_grid_values`).
// --------------------------------------------------------------------------
const N_ACCOUNT_MAX: u32 = 100;
// First-N table cap: SPEC_DERIVATION_OPTIONS §A.4.3 caps this at ~10
// ("deliberately not 20") to limit the on-screen address cluster under
// framebuffer/GPU/screen capture — a constraint that binds MORE strongly in a
// hot browser than on the desktop edition it mirrors.
const N_GRID_MAX: u32 = 10;
const N_INDEX_MAX: u32 = 100_000;

#[no_mangle]
pub extern "C" fn verify_grid(
    m_len: usize,
    p_len: usize,
    standard_id: u32,
    account: u32,
    change: u32,
    index_start: u32,
    n: u32,
) -> i32 {
    if m_len > INPUT_CAP || p_len > MAX_PASSPHRASE_LEN || m_len + p_len > INPUT_CAP {
        // Lengths are untrusted on this path (a caller/embedder may have written
        // secret bytes into INPUT before passing an over-long or inconsistent
        // length). Scrub the FULL INPUT buffer before returning (SPEC §20.3).
        scrub_input(INPUT_CAP);
        return err_line("bad-input-length");
    }

    // Parameter bounds (validated before touching any secret material).
    let standard = match standard_id {
        0 => PathStandard::Bip44,
        1 => PathStandard::Bip49,
        2 => PathStandard::Bip84,
        3 => PathStandard::Bip86,
        _ => return err_line("unknown-standard"),
    };
    if account > N_ACCOUNT_MAX {
        return err_line("account-out-of-range");
    }
    if change > 1 {
        return err_line("change-must-be-0-or-1");
    }
    if n < 1 || n > N_GRID_MAX {
        return err_line("count-out-of-range");
    }
    // The highest index we will derive must neither overflow u32 nor exceed the
    // honest on-demand bound.
    match index_start.checked_add(n - 1) {
        Some(last) if last <= N_INDEX_MAX => {}
        _ => return err_line("index-out-of-range"),
    }

    let inp = unsafe { &INPUT };
    let mnemonic_bytes = &inp[..m_len];
    let passphrase_bytes = &inp[m_len..m_len + p_len];

    // Passphrase must be printable ASCII (SPEC_PASSPHRASE §3.2 discipline).
    for &b in passphrase_bytes {
        if !(0x20..=0x7e).contains(&b) {
            scrub_input(m_len + p_len);
            return err_line("passphrase-not-printable-ascii");
        }
    }

    let mut indexes = [0u16; 24];
    let count = match parse_and_validate_mnemonic(mnemonic_bytes, &mut indexes) {
        Ok(c) => c,
        Err(msg) => {
            scrub_indexes(&mut indexes);
            scrub_input(m_len + p_len);
            return err_line(msg);
        }
    };

    let mut pass_local = [0u8; MAX_PASSPHRASE_LEN];
    pass_local[..p_len].copy_from_slice(passphrase_bytes);

    let label = match standard {
        PathStandard::Bip44 => "bip44",
        PathStandard::Bip49 => "bip49",
        PathStandard::Bip84 => "bip84",
        PathStandard::Bip86 => "bip86",
    };

    let mut w = Writer::new();
    w.kv("status", "ok");
    w.kv("mode", "grid");
    w.kv("standard", label);
    w.key("account");
    w.dec(account);
    w.nl();
    w.key("change");
    w.dec(change);
    w.nl();
    emit_grid_values(
        &mut w,
        &indexes,
        count,
        &pass_local[..p_len],
        standard,
        account,
        change,
        index_start,
        n,
    );

    // Scrub every secret buffer we touched (SPEC §20.3).
    scrub_indexes(&mut indexes);
    seed_core::arena::scrub_slice(&mut pass_local);
    scrub_input(m_len + p_len);
    w.finish()
}

// --------------------------------------------------------------------------
// Feature 3 — Entropy-encoding compat (SPEC_WEB_OFFLINE §13.2 item 3 / §6
// feature 5). seed-compat Method C, byte-exact to iancoleman/bip39. INPUT =
// foreign entropy string; `enc_id` selects the encoding (index into
// Encoding::ALL). Reproduces the mnemonic + entropy + first addresses of
// FOREIGN material — carries the "never an Alea seed" framing in the UI.
// --------------------------------------------------------------------------
#[no_mangle]
pub extern "C" fn compat(enc_id: u32, in_len: usize) -> i32 {
    if in_len > INPUT_CAP {
        // `in_len` is untrusted on this path; a caller may have written bytes
        // into INPUT before passing an over-long length. Scrub the FULL INPUT
        // buffer before returning (consistent with the verify* bad-length paths).
        scrub_input(INPUT_CAP);
        return err_line("bad-input-length");
    }
    let encoding = match Encoding::ALL.get(enc_id as usize) {
        Some(&e) => e,
        None => return err_line("unknown-encoding"),
    };

    let inp = unsafe { &INPUT };
    let input_str = match core::str::from_utf8(&inp[..in_len]) {
        Ok(s) => s,
        Err(_) => {
            scrub_input(in_len);
            return err_line("input-not-utf8");
        }
    };

    match entropy_encoding_derive(encoding, input_str) {
        Ok(output) => {
            let count = match output.word_count {
                CompatWordCount::W12 => WordCount::Twelve,
                CompatWordCount::W24 => WordCount::TwentyFour,
            };
            let n = count as usize;

            let mut w = Writer::new();
            w.kv("status", "ok");
            w.kv("mode", "compat");
            w.kv("encoding", encoding.id());
            w.key("accepted");
            w.dec(output.accepted_symbols as u32);
            w.nl();
            w.key("ignored");
            w.dec(output.ignored_chars as u32);
            w.nl();
            w.key("retained_bits");
            w.dec(output.retained_bits as u32);
            w.nl();
            w.key("total_bits");
            w.dec(output.total_bits as u32);
            w.nl();
            w.key("entropy");
            w.hex(&output.entropy[..output.entropy_len]);
            w.nl();
            emit_mnemonic(&mut w, &output.mnemonic_indexes, n);
            emit_public_values(&mut w, &output.mnemonic_indexes, count, &[]);

            scrub_input(in_len);
            // `output` scrubs its own mnemonic_indexes + entropy on Drop.
            w.finish()
        }
        Err(e) => {
            scrub_input(in_len);
            emit_compat_error(e)
        }
    }
}

fn emit_compat_error(e: EntropyEncodingError) -> i32 {
    let mut w = Writer::new();
    w.kv("status", "error");
    match e {
        EntropyEncodingError::NoSymbols { ignored_chars } => {
            w.kv("error", "no-symbols");
            w.key("ignored");
            w.dec(ignored_chars as u32);
            w.nl();
        }
        EntropyEncodingError::TooLong => {
            w.kv("error", "too-long");
        }
        EntropyEncodingError::UnsupportedLength {
            retained_bits,
            total_bits,
            iancoleman_words,
            accepted_symbols,
            ignored_chars,
        } => {
            w.kv("error", "unsupported-length");
            w.key("retained_bits");
            w.dec(retained_bits as u32);
            w.nl();
            w.key("total_bits");
            w.dec(total_bits as u32);
            w.nl();
            w.key("iancoleman_words");
            w.dec(iancoleman_words as u32);
            w.nl();
            w.key("accepted");
            w.dec(accepted_symbols as u32);
            w.nl();
            w.key("ignored");
            w.dec(ignored_chars as u32);
            w.nl();
        }
    }
    w.finish()
}

// --------------------------------------------------------------------------
// In-page WASM self-hash (SPEC_WEB_OFFLINE §5.3): SHA-256 over INPUT[..len],
// written as 64 lowercase hex chars. JS copies the embedded .wasm bytes into
// INPUT and calls this so the user can eyeball-match the value to a published
// hash. Uses the core's OWN SHA-256 — no host crypto, fully self-contained.
// Scope note (enforced by the UI copy): covers ONLY the wasm bytes, not the
// HTML/JS wrapper.
// --------------------------------------------------------------------------
#[no_mangle]
pub extern "C" fn wasm_sha256(len: usize) -> i32 {
    if len > INPUT_CAP {
        return ERR_BAD_ARGS;
    }
    let inp = unsafe { &INPUT };
    let digest = sha256(&inp[..len]);
    let mut w = Writer::new();
    w.hex(&digest);
    w.finish()
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

/// Emit a `status\terror` + `error\t<msg>` record and finish.
fn err_line(msg: &str) -> i32 {
    let mut w = Writer::new();
    w.kv("status", "error");
    w.kv("error", msg);
    w.finish()
}

/// Best-effort scrub of a `[u16; 24]` index array via the core's byte-wise
/// scrub primitive (reinterpret the 24 u16s as their 48 constituent bytes).
fn scrub_indexes(indexes: &mut [u16; 24]) {
    // SAFETY: `[u16; 24]` has no padding; a `u8` view over its 48 bytes is
    // always valid and stays within the exclusively-borrowed array.
    let b = unsafe { core::slice::from_raw_parts_mut(indexes.as_mut_ptr().cast::<u8>(), 48) };
    seed_core::arena::scrub_slice(b);
}

/// Zero the first `n` bytes of the shared INPUT buffer (it held a secret
/// mnemonic/passphrase). Uses the core's reviewed scrub primitive.
fn scrub_input(n: usize) {
    let n = if n > INPUT_CAP { INPUT_CAP } else { n };
    let inp = unsafe { &mut INPUT };
    seed_core::arena::scrub_slice(&mut inp[..n]);
}

/// Parse an ASCII space-separated mnemonic into wordlist indexes and validate
/// both (a) every word is an exact BIP39 English wordlist entry and (b) the
/// BIP39 checksum. Returns the WordCount on success or a static error message.
///
/// Checksum validation reuses the core's own `entropy_to_indexes`: reconstruct
/// the ENT-bit entropy from the packed 11-bit indexes, recompute indexes from
/// it (which recomputes+appends the canonical checksum), and require equality.
fn parse_and_validate_mnemonic(bytes: &[u8], indexes: &mut [u16; 24]) -> Result<WordCount, &'static str> {
    // Tokenize on ASCII spaces; ignore empty tokens (handles runs of spaces
    // and leading/trailing whitespace). Reject non-space ASCII control/upper.
    let mut n = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        // skip spaces
        while i < bytes.len() && bytes[i] == b' ' {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let start = i;
        while i < bytes.len() && bytes[i] != b' ' {
            i += 1;
        }
        let tok = &bytes[start..i];
        if n >= 24 {
            return Err("too-many-words");
        }
        match lookup_word(tok) {
            Some(idx) => {
                indexes[n] = idx;
                n += 1;
            }
            None => return Err("unknown-word"),
        }
    }

    let count = match n {
        12 => WordCount::Twelve,
        24 => WordCount::TwentyFour,
        _ => return Err("word-count-must-be-12-or-24"),
    };

    if !checksum_ok(indexes, count) {
        return Err("bad-checksum");
    }
    Ok(count)
}

/// Exact match of an entered token against the BIP39 English wordlist.
fn lookup_word(tok: &[u8]) -> Option<u16> {
    if tok.is_empty() || tok.len() > 8 {
        return None;
    }
    for idx in 0u16..2048 {
        if word(idx).as_bytes() == tok {
            return Some(idx);
        }
    }
    None
}

/// Validate the BIP39 checksum by round-tripping through the core encoder.
fn checksum_ok(indexes: &[u16; 24], count: WordCount) -> bool {
    let (n, ent_bytes) = match count {
        WordCount::Twelve => (12usize, 16usize),
        WordCount::TwentyFour => (24usize, 32usize),
    };
    // Reconstruct the leading ENT bits (entropy, MSB-first) from the packed
    // 11-bit word values.
    let mut entropy = [0u8; 32];
    let ent_bits = ent_bytes * 8;
    for bitpos in 0..ent_bits {
        let word_i = bitpos / 11;
        let bit_in_word = bitpos % 11;
        let idx = indexes[word_i];
        let bit = ((idx >> (10 - bit_in_word)) & 1) as u8;
        if bit != 0 {
            entropy[bitpos / 8] |= 1 << (7 - (bitpos % 8));
        }
    }

    let mut recomputed = [0u16; 24];
    let ok = match entropy_to_indexes(&entropy[..ent_bytes], &mut recomputed) {
        Ok(_) => recomputed[..n] == indexes[..n],
        Err(_) => false,
    };
    seed_core::arena::scrub_slice(&mut entropy);
    seed_core::arena::scrub_slice(unsafe {
        core::slice::from_raw_parts_mut(recomputed.as_mut_ptr().cast::<u8>(), 48)
    });
    ok
}
