//! Keyboard input (WP-22, SPEC §11.5, §12.3).
//!
//! This module owns three things, all host-testable via the [`KeySource`]
//! abstraction (real firmware only links on `x86_64-unknown-uefi`, see
//! [`uefi_backend`]):
//!
//! - A blocking key-read trait ([`KeySource`]) normalizing UEFI keystrokes
//!   into [`InputEvent`].
//! - The keyboard-layout self-test flow ([`run_self_test`]), SPEC §11.5:
//!   confirms A–Z, 1–6, Backspace and Enter behave as expected before any
//!   secret exists, failing closed on the first mismatch.
//! - The hidden-entry primitive ([`read_hidden`]), SPEC §12.3: reads into a
//!   caller-owned fixed buffer with no echo, calling back on every count
//!   change so the UI layer can render a dot count without ever seeing the
//!   letters.
//!
//! Nothing in this module logs, persists, or `Debug`/`Display`-prints
//! accumulated secret buffer contents. [`InputEvent`] itself derives
//! `Debug`/`Clone`/`Copy` because it only ever carries a single transient
//! keystroke (never an accumulated secret) — the accumulated hidden buffer
//! in [`read_hidden`] is a plain `&mut [u8]` that this module never wraps
//! in a formatting/derive that could leak it.

#[cfg(test)]
extern crate std;

/// A single normalized keystroke, independent of the firmware protocol
/// that produced it (SPEC §11.5, §12.3).
///
/// This type is deliberately not "secret-bearing" in the SPEC §20 sense:
/// it represents exactly one transient keystroke, never an accumulated
/// buffer, so deriving `Debug`/`Clone`/`Copy` here does not create a path
/// to leak accumulated secret text. Callers accumulating keystrokes (e.g.
/// [`read_hidden`]) MUST NOT wrap the accumulated buffer itself in any of
/// those traits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputEvent {
    /// A printable character was typed.
    Char(char),
    /// Backspace: remove one previously-entered character.
    Backspace,
    /// Enter: terminate the current entry.
    Enter,
    /// Escape (`ScanCode::ESCAPE`, SPEC §11.5, §12.3). Distinguished from
    /// [`InputEvent::Other`] so callers can give Escape caller-specific
    /// meaning (e.g. cancel-entry) without it being silently folded into
    /// the generic "ignore this key" bucket. [`read_hidden`] itself still
    /// treats it as "not echoed, not stored" per SPEC §12.3 — same as
    /// `Other` — until a caller opts into different handling.
    Escape,
    /// Any other key (arrows, function keys, etc.) — SPEC §12.3 requires
    /// these to be ignored: not echoed, not stored.
    Other,
}

/// Blocking key-read abstraction (SPEC §11.5: "Blocking key read trait
/// over uefi input").
///
/// Implementations MUST block until exactly one key is available and
/// return its normalized form. The real firmware-backed implementation is
/// [`uefi_backend::FirmwareKeySource`]; host tests use a scripted double
/// (see `tests` below).
pub trait KeySource {
    /// Block until a key is available, then return its normalized event.
    fn read_key_blocking(&mut self) -> InputEvent;
}

// ---------------------------------------------------------------------
// Keyboard-layout self-test (SPEC §11.5)
// ---------------------------------------------------------------------

/// One expected keystroke in the self-test sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfTestExpectation {
    /// Expect the printable character `c` (case-insensitive: firmware
    /// keyboard drivers may report either case depending on shift state,
    /// and SPEC §11.5 only requires the *key* map correctly, not that a
    /// specific case be produced).
    Char(char),
    /// Expect Backspace.
    Backspace,
    /// Expect Enter.
    Enter,
}

/// Number of steps in [`self_test_sequence`]: 26 letters (A–Z, which
/// includes H and T — SPEC §11.5 calls those out separately because they
/// are later used as dedicated single-key coin-flip inputs, but the key
/// itself is exercised once here) + 6 digits (1–6) + Backspace + Enter.
pub const SELF_TEST_LEN: usize = 26 + 6 + 1 + 1;

/// The fixed keyboard self-test sequence (SPEC §11.5): A–Z, 1–6,
/// Backspace, Enter, in that order. Locale-neutral — ASCII letters and
/// digits only, no punctuation (SPEC §11.5: "Avoid locale-sensitive
/// punctuation").
pub const fn self_test_sequence() -> [SelfTestExpectation; SELF_TEST_LEN] {
    let mut seq = [SelfTestExpectation::Enter; SELF_TEST_LEN];
    let mut i = 0;
    let mut c = b'A';
    while c <= b'Z' {
        seq[i] = SelfTestExpectation::Char(c as char);
        i += 1;
        c += 1;
    }
    let mut d = b'1';
    while d <= b'6' {
        seq[i] = SelfTestExpectation::Char(d as char);
        i += 1;
        d += 1;
    }
    seq[i] = SelfTestExpectation::Backspace;
    i += 1;
    seq[i] = SelfTestExpectation::Enter;
    i += 1;
    debug_assert!(i == SELF_TEST_LEN);
    seq
}

/// The self-test failed at `index` (0-based into [`self_test_sequence`]):
/// the key pressed did not match `expected`. SPEC §11.5: "Fail closed if
/// the input mapping is unsuitable" — the caller MUST treat this as
/// generation-disabling, never retry-in-place or fall back to a
/// multiple-choice picker.
///
/// Not secret-bearing (only ever carries self-test scaffolding, never
/// mnemonic/entropy material), so `Debug`/`Clone`/`Copy` are fine here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfTestFailure {
    /// Index into the sequence where the mismatch occurred.
    pub index: usize,
    /// What the sequence expected at that index.
    pub expected: SelfTestExpectation,
}

/// Run the keyboard-layout self-test (SPEC §11.5).
///
/// `on_step(index, total, expected)` is called before each keystroke is
/// awaited, so a caller can render "press <key>" prompts; it carries no
/// secret data. Returns `Ok(())` only if every keystroke in
/// [`self_test_sequence`] matched, in order. On the first mismatch this
/// returns `Err` immediately (fail closed, SPEC §11.5) rather than
/// retrying or skipping.
pub fn run_self_test<K, F>(source: &mut K, mut on_step: F) -> Result<(), SelfTestFailure>
where
    K: KeySource,
    F: FnMut(usize, usize, SelfTestExpectation),
{
    let seq = self_test_sequence();
    for (index, expected) in seq.iter().copied().enumerate() {
        on_step(index, seq.len(), expected);
        let got = source.read_key_blocking();
        let matched = match (expected, got) {
            (SelfTestExpectation::Char(want), InputEvent::Char(got)) => {
                want.eq_ignore_ascii_case(&got)
            }
            (SelfTestExpectation::Backspace, InputEvent::Backspace) => true,
            (SelfTestExpectation::Enter, InputEvent::Enter) => true,
            _ => false,
        };
        if !matched {
            return Err(SelfTestFailure { index, expected });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------
// SPEC_PASSPHRASE §8.2 — extended printable-ASCII keyboard self-test
// ---------------------------------------------------------------------

/// Lowest / highest printable-ASCII code point the passphrase charset needs
/// (SPEC_PASSPHRASE §3.2: `0x20` SPACE .. `0x7E` `~`).
pub const EXT_ASCII_MIN: u8 = 0x20;
/// See [`EXT_ASCII_MIN`].
pub const EXT_ASCII_MAX: u8 = 0x7E;

/// Number of keys in the extended printable-ASCII self-test:
/// `0x7E - 0x20 + 1 = 95`.
pub const EXTENDED_SELF_TEST_LEN: usize = (EXT_ASCII_MAX - EXT_ASCII_MIN + 1) as usize;

/// The extended self-test failed at printable-ASCII byte `expected`: the
/// firmware did not deliver that exact code point. SPEC_PASSPHRASE §8.2
/// fail-closed — the caller MUST disable **passphrase entry only** (NOT
/// generation), never retry-in-place or silently degrade the charset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtendedSelfTestFailure {
    /// The printable-ASCII byte that did not round-trip.
    pub expected: u8,
}

/// SPEC_PASSPHRASE §8.2 extended keyboard self-test: round-trip **every**
/// printable-ASCII code point (`0x20`–`0x7E`) the passphrase charset allows,
/// in ascending order, requiring an **exact** match (case-sensitive, unlike
/// the base [`run_self_test`], because a passphrase's exact bytes ARE its
/// identity). This **explicitly supersedes** SPEC §11.5's
/// "avoid locale-sensitive punctuation" clause (SPEC_PASSPHRASE §8.2/M4):
/// rather than avoiding punctuation, it exercises every punctuation mark and
/// fails closed on anything it cannot verify.
///
/// `on_step(expected)` is called before each keystroke is awaited so a
/// caller can render "press <key>" prompts (no secret data). Returns
/// `Ok(())` only if every code point matched, in order; on the first
/// mismatch it returns `Err` immediately (fail closed). A caller MUST treat
/// `Err` as disabling passphrase entry only.
pub fn run_extended_ascii_self_test<K, F>(
    source: &mut K,
    mut on_step: F,
) -> Result<(), ExtendedSelfTestFailure>
where
    K: KeySource,
    F: FnMut(char),
{
    let mut byte = EXT_ASCII_MIN;
    loop {
        let expected = byte as char;
        on_step(expected);
        let got = source.read_key_blocking();
        let matched = matches!(got, InputEvent::Char(c) if c == expected);
        if !matched {
            return Err(ExtendedSelfTestFailure { expected: byte });
        }
        if byte == EXT_ASCII_MAX {
            return Ok(());
        }
        byte += 1;
    }
}

// ---------------------------------------------------------------------
// Hidden-entry primitive (SPEC §12.3)
// ---------------------------------------------------------------------

/// Read hidden input into `buf` (SPEC §12.3: "no echo of entered
/// letters").
///
/// - Only the first `min(buf.len(), max_len)` accepted characters are
///   stored; characters typed beyond that capacity are rejected — "not
///   echoed, not stored" (SPEC §12.3) — silently, with no error and no
///   partial write.
/// - Backspace removes one previously-entered character and scrubs its
///   old byte with a volatile write (defense in depth: the stale byte
///   must not linger in `buf` after being logically removed).
/// - Enter terminates entry and returns the number of characters
///   currently held (this may be zero; SPEC §12.3 says the caller must
///   re-display the prompt on an empty-buffer Enter — that is a caller
///   concern, not this primitive's).
/// - Only ASCII characters are stored (BIP39 English words are ASCII;
///   non-ASCII printable keys are rejected the same way as
///   capacity-exceeding ones).
/// - `on_count_changed(new_len)` fires every time the held length
///   changes, so the UI can render a dot-count without ever seeing the
///   underlying bytes. It receives a plain `usize`, never buffer
///   contents.
/// - Every other key ([`InputEvent::Other`]) is ignored.
///
/// This function performs no logging or persistence of `buf` beyond the
/// writes described above (SPEC §12.3: "no entered prefix is logged or
/// persisted").
///
/// The caller owns `buf`'s lifetime and MUST scrub it (e.g. via
/// `SecretArena::scrub_all`) once it is no longer needed; this primitive
/// only scrubs bytes it itself invalidates via Backspace.
pub fn read_hidden<K, C>(source: &mut K, buf: &mut [u8], max_len: usize, mut on_count_changed: C) -> usize
where
    K: KeySource,
    C: FnMut(usize),
{
    let cap = core::cmp::min(buf.len(), max_len);
    let mut len = 0usize;
    on_count_changed(len);
    loop {
        match source.read_key_blocking() {
            InputEvent::Enter => return len,
            InputEvent::Backspace => {
                if len > 0 {
                    len -= 1;
                    scrub_byte(&mut buf[len]);
                    on_count_changed(len);
                }
                // Empty buffer + Backspace: no-op, per SPEC §12.3 (only
                // "one hidden character" is ever removed, and there is
                // none to remove).
            }
            InputEvent::Char(c) => {
                if len < cap && c.is_ascii() {
                    buf[len] = c as u8;
                    len += 1;
                    on_count_changed(len);
                }
                // Beyond capacity, or non-ASCII: rejected silently — not
                // echoed, not stored (SPEC §12.3).
            }
            InputEvent::Escape | InputEvent::Other => {}
        }
    }
}

/// Overwrite `*b` with zero via a volatile write, so the compiler cannot
/// elide the store as dead (SPEC §20.3: explicit scrub with volatile
/// writes).
fn scrub_byte(b: &mut u8) {
    // SAFETY: `b` is a valid, exclusively-borrowed `u8` reference for the
    // duration of this call.
    unsafe {
        core::ptr::write_volatile(b as *mut u8, 0);
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

// ---------------------------------------------------------------------
// Real firmware backend (SPEC §11.5, §12.3) — only linked into UEFI
// builds.
// ---------------------------------------------------------------------

/// Real UEFI adapter: wires [`KeySource`] to
/// `uefi::proto::console::text::Input`. Only compiled when targeting the
/// `uefi` OS (`x86_64-unknown-uefi`), never pulled into host `cargo test`
/// runs.
#[cfg(target_os = "uefi")]
pub mod uefi_backend {
    use super::{InputEvent, KeySource};
    use uefi::proto::console::text::{Input, Key, ScanCode};

    /// UTF-16/UEFI carriage-return code point used for the Enter key.
    const CHAR_CARRIAGE_RETURN: u16 = 0x0D;
    /// UTF-16/UEFI backspace code point.
    const CHAR_BACKSPACE: u16 = 0x08;

    /// [`KeySource`] backed by the firmware's `SIMPLE_TEXT_INPUT_PROTOCOL`.
    ///
    /// Blocks on [`uefi::boot::wait_for_event`] against the protocol's
    /// `wait_for_key` event, per the crate's own documented blocking
    /// pattern, then drains exactly one keystroke with `read_key`.
    pub struct FirmwareKeySource<'a> {
        input: &'a mut Input,
    }

    impl<'a> FirmwareKeySource<'a> {
        /// Wrap an already-open `Input` protocol instance.
        pub fn new(input: &'a mut Input) -> Self {
            Self { input }
        }
    }

    impl KeySource for FirmwareKeySource<'_> {
        fn read_key_blocking(&mut self) -> InputEvent {
            loop {
                // Block until the firmware signals a key is ready.
                if let Ok(event) = self.input.wait_for_key_event() {
                    let mut events = [event];
                    // Failure here (e.g. UNSUPPORTED) just falls through
                    // to a `read_key` poll below rather than spinning
                    // forever on an error path.
                    let _ = uefi::boot::wait_for_event(&mut events);
                }
                match self.input.read_key() {
                    Ok(Some(Key::Printable(ch))) => {
                        let code: u16 = ch.into();
                        return match code {
                            CHAR_CARRIAGE_RETURN => InputEvent::Enter,
                            CHAR_BACKSPACE => InputEvent::Backspace,
                            _ => match char::try_from(u32::from(code)) {
                                Ok(c) if c.is_ascii_graphic() => InputEvent::Char(c),
                                _ => InputEvent::Other,
                            },
                        };
                    }
                    Ok(Some(Key::Special(ScanCode::ESCAPE))) => return InputEvent::Escape,
                    Ok(Some(Key::Special(_))) => return InputEvent::Other,
                    Ok(None) => continue, // NOT_READY: loop and wait again
                    Err(_) => continue,   // transient device error: retry blocking wait
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scripted [`KeySource`] double for host tests: replays a fixed
    /// keystream, then panics if read past the end (a test bug, not a
    /// production concern).
    struct ScriptedKeySource {
        events: std::vec::Vec<InputEvent>,
        pos: usize,
    }

    impl ScriptedKeySource {
        fn new(events: std::vec::Vec<InputEvent>) -> Self {
            Self { events, pos: 0 }
        }
    }

    impl KeySource for ScriptedKeySource {
        fn read_key_blocking(&mut self) -> InputEvent {
            let ev = self
                .events
                .get(self.pos)
                .copied()
                .expect("ScriptedKeySource read past scripted keystream");
            self.pos += 1;
            ev
        }
    }

    fn valid_self_test_keystream() -> std::vec::Vec<InputEvent> {
        let mut v = std::vec::Vec::new();
        for c in b'A'..=b'Z' {
            v.push(InputEvent::Char(c as char));
        }
        for d in b'1'..=b'6' {
            v.push(InputEvent::Char(d as char));
        }
        v.push(InputEvent::Backspace);
        v.push(InputEvent::Enter);
        v
    }

    // ---- self-test sequence shape ----

    #[test]
    fn self_test_sequence_has_expected_shape() {
        let seq = self_test_sequence();
        assert_eq!(seq.len(), SELF_TEST_LEN);
        assert_eq!(seq[0], SelfTestExpectation::Char('A'));
        assert_eq!(seq[25], SelfTestExpectation::Char('Z'));
        // H and T land inside A..=Z at their alphabetic positions.
        assert!(seq.contains(&SelfTestExpectation::Char('H')));
        assert!(seq.contains(&SelfTestExpectation::Char('T')));
        assert_eq!(seq[26], SelfTestExpectation::Char('1'));
        assert_eq!(seq[31], SelfTestExpectation::Char('6'));
        assert_eq!(seq[32], SelfTestExpectation::Backspace);
        assert_eq!(seq[33], SelfTestExpectation::Enter);
    }

    #[test]
    fn self_test_sequence_has_no_punctuation() {
        for step in self_test_sequence() {
            if let SelfTestExpectation::Char(c) = step {
                assert!(c.is_ascii_alphanumeric());
            }
        }
    }

    // ---- self-test: pass path ----

    #[test]
    fn self_test_passes_on_exact_matching_keystream() {
        let mut src = ScriptedKeySource::new(valid_self_test_keystream());
        let mut steps_seen = 0usize;
        let result = run_self_test(&mut src, |_i, _total, _expected| steps_seen += 1);
        assert!(result.is_ok());
        assert_eq!(steps_seen, SELF_TEST_LEN);
    }

    #[test]
    fn self_test_accepts_lowercase_letters() {
        let mut events = valid_self_test_keystream();
        // Replace the uppercase 'A' with lowercase 'a'.
        events[0] = InputEvent::Char('a');
        let mut src = ScriptedKeySource::new(events);
        assert!(run_self_test(&mut src, |_, _, _| {}).is_ok());
    }

    // ---- self-test: fail-closed paths ----

    #[test]
    fn self_test_fails_closed_on_wrong_letter() {
        let mut events = valid_self_test_keystream();
        events[3] = InputEvent::Char('X'); // was 'D'
        let mut src = ScriptedKeySource::new(events);
        let err = run_self_test(&mut src, |_, _, _| {}).unwrap_err();
        assert_eq!(err.index, 3);
        assert_eq!(err.expected, SelfTestExpectation::Char('D'));
    }

    #[test]
    fn self_test_fails_closed_on_special_key_instead_of_letter() {
        let mut events = valid_self_test_keystream();
        events[0] = InputEvent::Other;
        let mut src = ScriptedKeySource::new(events);
        let err = run_self_test(&mut src, |_, _, _| {}).unwrap_err();
        assert_eq!(err.index, 0);
    }

    #[test]
    fn self_test_fails_closed_on_missing_backspace() {
        let mut events = valid_self_test_keystream();
        events[32] = InputEvent::Char('X'); // was Backspace
        let mut src = ScriptedKeySource::new(events);
        let err = run_self_test(&mut src, |_, _, _| {}).unwrap_err();
        assert_eq!(err.index, 32);
        assert_eq!(err.expected, SelfTestExpectation::Backspace);
    }

    #[test]
    fn self_test_fails_closed_on_missing_enter() {
        let mut events = valid_self_test_keystream();
        events[33] = InputEvent::Char('X'); // was Enter
        let mut src = ScriptedKeySource::new(events);
        let err = run_self_test(&mut src, |_, _, _| {}).unwrap_err();
        assert_eq!(err.index, 33);
        assert_eq!(err.expected, SelfTestExpectation::Enter);
    }

    #[test]
    fn self_test_stops_at_first_mismatch_does_not_overread() {
        // Only script events up through the first (mismatching) key; if
        // the runner tried to continue past the failure it would panic
        // on ScriptedKeySource's "read past keystream" expect.
        let events = std::vec![InputEvent::Char('Q')]; // expected 'A'
        let mut src = ScriptedKeySource::new(events);
        let err = run_self_test(&mut src, |_, _, _| {}).unwrap_err();
        assert_eq!(err.index, 0);
    }

    // ---- SPEC_PASSPHRASE §8.2 extended printable-ASCII self-test ----

    fn valid_extended_keystream() -> std::vec::Vec<InputEvent> {
        (EXT_ASCII_MIN..=EXT_ASCII_MAX).map(|b| InputEvent::Char(b as char)).collect()
    }

    #[test]
    fn extended_self_test_covers_all_95_printable_ascii_and_passes_exactly() {
        assert_eq!(EXTENDED_SELF_TEST_LEN, 95);
        let mut src = ScriptedKeySource::new(valid_extended_keystream());
        let mut steps = std::vec::Vec::new();
        let result = run_extended_ascii_self_test(&mut src, |c| steps.push(c));
        assert!(result.is_ok());
        assert_eq!(steps.len(), EXTENDED_SELF_TEST_LEN);
        assert_eq!(steps[0], ' ');
        assert_eq!(steps[EXTENDED_SELF_TEST_LEN - 1], '~');
    }

    #[test]
    fn extended_self_test_is_case_sensitive_and_fails_closed() {
        // 'A' is 0x41; supplying lowercase 'a' where 'A' is expected must
        // fail (a passphrase's exact case is load-bearing).
        let mut events = valid_extended_keystream();
        let idx = (b'A' - EXT_ASCII_MIN) as usize;
        events[idx] = InputEvent::Char('a');
        let mut src = ScriptedKeySource::new(events);
        let err = run_extended_ascii_self_test(&mut src, |_| {}).unwrap_err();
        assert_eq!(err.expected, b'A');
    }

    #[test]
    fn extended_self_test_fails_closed_on_missing_punctuation_key() {
        // Drop a punctuation key ('~' at the end) → Enter instead of the
        // char → fail closed.
        let mut events = valid_extended_keystream();
        *events.last_mut().unwrap() = InputEvent::Enter; // was '~'
        let mut src = ScriptedKeySource::new(events);
        let err = run_extended_ascii_self_test(&mut src, |_| {}).unwrap_err();
        assert_eq!(err.expected, b'~');
    }

    // ---- read_hidden ----

    #[test]
    fn read_hidden_accumulates_and_terminates_on_enter() {
        let events = std::vec![
            InputEvent::Char('h'),
            InputEvent::Char('e'),
            InputEvent::Char('l'),
            InputEvent::Char('l'),
            InputEvent::Enter,
        ];
        let mut src = ScriptedKeySource::new(events);
        let mut buf = [0u8; 8];
        let mut counts = std::vec::Vec::new();
        let n = read_hidden(&mut src, &mut buf, 8, |c| counts.push(c));
        assert_eq!(n, 4);
        assert_eq!(&buf[..4], b"hell");
        // Initial 0, then one bump per accepted char.
        assert_eq!(counts, std::vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn read_hidden_backspace_removes_one_char_and_scrubs_it() {
        let events = std::vec![
            InputEvent::Char('a'),
            InputEvent::Char('b'),
            InputEvent::Backspace,
            InputEvent::Enter,
        ];
        let mut src = ScriptedKeySource::new(events);
        let mut buf = [0xFFu8; 8];
        let n = read_hidden(&mut src, &mut buf, 8, |_| {});
        assert_eq!(n, 1);
        assert_eq!(buf[0], b'a');
        // The removed 'b' byte must be scrubbed to 0, not left dangling.
        assert_eq!(buf[1], 0);
    }

    #[test]
    fn read_hidden_backspace_on_empty_buffer_is_a_no_op() {
        let events = std::vec![InputEvent::Backspace, InputEvent::Enter];
        let mut src = ScriptedKeySource::new(events);
        let mut buf = [0u8; 4];
        let n = read_hidden(&mut src, &mut buf, 4, |_| {});
        assert_eq!(n, 0);
    }

    #[test]
    fn read_hidden_enter_on_empty_buffer_returns_zero() {
        let events = std::vec![InputEvent::Enter];
        let mut src = ScriptedKeySource::new(events);
        let mut buf = [0u8; 4];
        let mut counts = std::vec::Vec::new();
        let n = read_hidden(&mut src, &mut buf, 4, |c| counts.push(c));
        assert_eq!(n, 0);
        assert_eq!(counts, std::vec![0]);
    }

    #[test]
    fn read_hidden_rejects_chars_beyond_max_len_silently() {
        // max_len = 4: fifth char must be dropped, not stored, no extra
        // callback fired, buffer position five stays untouched.
        let events = std::vec![
            InputEvent::Char('a'),
            InputEvent::Char('b'),
            InputEvent::Char('c'),
            InputEvent::Char('d'),
            InputEvent::Char('e'), // rejected: over max_len
            InputEvent::Enter,
        ];
        let mut src = ScriptedKeySource::new(events);
        let mut buf = [0u8; 8];
        let mut counts = std::vec::Vec::new();
        let n = read_hidden(&mut src, &mut buf, 4, |c| counts.push(c));
        assert_eq!(n, 4);
        assert_eq!(&buf[..4], b"abcd");
        assert_eq!(buf[4], 0, "byte beyond accepted length must never be written");
        assert_eq!(counts, std::vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn read_hidden_respects_buf_len_shorter_than_max_len() {
        // buf.len() == 2 < max_len == 8: capacity is min(buf.len(), max_len).
        let events = std::vec![
            InputEvent::Char('a'),
            InputEvent::Char('b'),
            InputEvent::Char('c'), // rejected: buf only holds 2
            InputEvent::Enter,
        ];
        let mut src = ScriptedKeySource::new(events);
        let mut buf = [0u8; 2];
        let n = read_hidden(&mut src, &mut buf, 8, |_| {});
        assert_eq!(n, 2);
        assert_eq!(&buf[..], b"ab");
    }

    #[test]
    fn read_hidden_rejects_non_ascii_silently() {
        let events = std::vec![InputEvent::Char('é'), InputEvent::Char('a'), InputEvent::Enter];
        let mut src = ScriptedKeySource::new(events);
        let mut buf = [0u8; 4];
        let n = read_hidden(&mut src, &mut buf, 4, |_| {});
        assert_eq!(n, 1);
        assert_eq!(buf[0], b'a');
    }

    #[test]
    fn read_hidden_ignores_other_keys() {
        let events = std::vec![
            InputEvent::Other,
            InputEvent::Char('a'),
            InputEvent::Other,
            InputEvent::Enter,
        ];
        let mut src = ScriptedKeySource::new(events);
        let mut buf = [0u8; 4];
        let n = read_hidden(&mut src, &mut buf, 4, |_| {});
        assert_eq!(n, 1);
        assert_eq!(buf[0], b'a');
    }

    #[test]
    fn escape_is_distinct_from_other() {
        // Regression for the arch finding: ScanCode::ESCAPE must not be
        // folded into the generic `Other` bucket — callers need to be
        // able to tell "user pressed Escape" apart from "some other,
        // uninteresting special key".
        assert_ne!(InputEvent::Escape, InputEvent::Other);
    }

    #[test]
    fn read_hidden_ignores_escape_key() {
        let events = std::vec![
            InputEvent::Escape,
            InputEvent::Char('a'),
            InputEvent::Escape,
            InputEvent::Enter,
        ];
        let mut src = ScriptedKeySource::new(events);
        let mut buf = [0u8; 4];
        let n = read_hidden(&mut src, &mut buf, 4, |_| {});
        assert_eq!(n, 1);
        assert_eq!(buf[0], b'a');
    }

    #[test]
    fn read_hidden_backspace_then_retype_reaches_full_length() {
        let events = std::vec![
            InputEvent::Char('a'),
            InputEvent::Char('b'),
            InputEvent::Backspace,
            InputEvent::Char('c'),
            InputEvent::Enter,
        ];
        let mut src = ScriptedKeySource::new(events);
        let mut buf = [0u8; 4];
        let n = read_hidden(&mut src, &mut buf, 4, |_| {});
        assert_eq!(n, 2);
        assert_eq!(&buf[..2], b"ac");
    }
}
