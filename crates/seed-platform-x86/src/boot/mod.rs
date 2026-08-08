//! UEFI entry/runtime scaffolding shared by both UEFI binaries (WP-17,
//! SPEC §5, §20.4).
//!
//! This module owns the pieces every UEFI edition needs before any
//! secret-bearing state exists: a firmware-text banner helper (pre-secret
//! only — never call after a mnemonic/seed has been derived) and a
//! `halt_forever` primitive used by the shared panic handler.
//!
//! `main.rs` in each `seed-uefi-*` crate is intentionally a thin shell: it
//! wires `#[entry]`/`#[panic_handler]` to the helpers here so the actual
//! logic is host-testable (via `#[cfg(test)]` doubles) even though the
//! `uefi::system`/`uefi::boot` calls themselves only link on the
//! `x86_64-unknown-uefi` target.

#[cfg(test)]
extern crate std;

#[cfg(test)]
use core::fmt::Write as _;

/// Maximum banner line length this module will print in one
/// [`print_banner_line`] call, in UTF-16 code units including the
/// terminating NUL. Fixed-size buffer only — SPEC §13 (no `alloc`
/// anywhere in the production graph; this module is linked into both
/// editions so it holds itself to the same bound).
pub const MAX_BANNER_LINE_UNITS: usize = 128;

/// Errors [`print_banner_line`] can report.
///
/// SPEC §20.4: pre-secret diagnostics may surface firmware/protocol
/// failures, but nothing here ever carries secret-bearing data, so this
/// type is free to be an ordinary (non-secret) diagnostic value —
/// `Debug`/`Copy`/`Clone` are fine here, unlike the secret-bearing types
/// governed by SPEC §20.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BannerError {
    /// The line (plus NUL terminator) does not fit in
    /// [`MAX_BANNER_LINE_UNITS`] UTF-16 code units.
    LineTooLong,
    /// The underlying UEFI text-output protocol reported a failure code
    /// while converting or emitting the string.
    OutputFailed,
}

/// Backend abstraction over "a place banner text can be written", so the
/// formatting/bounds logic in this module is exercised by host `cargo
/// test` without linking the real `uefi` crate. SPEC §5 / IMPLEMENTATION_MAP
/// WP-17: host-runnable tests are required even for `no_std` platform
/// code.
///
/// The real UEFI text-output protocol implements this via the adapter in
/// [`uefi_backend`] (only compiled for the `uefi` target family).
pub trait TextSink {
    /// Emit `line` verbatim (no implicit newline). Implementations decide
    /// how failures are surfaced; this module only asks for "did it
    /// work".
    fn write_line(&mut self, line: &str) -> Result<(), BannerError>;
}

/// Print `line` to `sink`, pre-secret diagnostics only.
///
/// # SPEC references
/// - §5: pre-secret banner/diagnostic output is explicitly allowed on the
///   firmware text console.
/// - §20.4: production builds must never print secret-bearing text; this
///   function is for the banner path only and callers MUST NOT route
///   secret material through it. It performs no logging or persistence
///   of its input beyond the single write.
///
/// Returns [`BannerError::LineTooLong`] rather than truncating, so a
/// caller can never accidentally split a security-relevant sentence.
pub fn print_banner_line<S: TextSink>(sink: &mut S, line: &str) -> Result<(), BannerError> {
    // UTF-16 code units needed, plus the NUL terminator the firmware
    // string protocol expects. Counted without allocating.
    let units: usize = line.encode_utf16().count() + 1;
    if units > MAX_BANNER_LINE_UNITS {
        return Err(BannerError::LineTooLong);
    }
    sink.write_line(line)
}

/// Halt the CPU forever, never returning to firmware or caller code.
///
/// SPEC §20.4: after a panic, production code must not return to
/// firmware once state might be inconsistent. This is the single
/// halt-loop primitive both the panic handler and any fatal
/// scrub-and-shutdown path should converge on.
///
/// Uses `hlt` in a loop with `nomem, nostack, preserves_flags` — no
/// memory access, so it is safe to call from a panic handler regardless
/// of what else went wrong.
#[cfg(target_arch = "x86_64")]
pub fn halt_forever() -> ! {
    loop {
        // SAFETY: `hlt` with no operands only pauses the CPU until the
        // next interrupt; it touches no memory and preserves all
        // registers/flags, so it is sound to execute in any context,
        // including a panic handler with unknown prior state.
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}

/// Non-x86_64 fallback (host `cargo test` builds this module on the dev
/// machine's native target). Never called there; kept so the crate
/// compiles for `cargo test` without `#[cfg(test)]` gating every caller.
#[cfg(not(target_arch = "x86_64"))]
pub fn halt_forever() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// A [`TextSink`] that records lines into a fixed-size in-memory buffer,
/// for host unit tests. Not compiled into UEFI builds.
#[cfg(test)]
pub(crate) struct RecordingSink {
    pub(crate) lines: std::vec::Vec<std::string::String>,
    pub(crate) fail_next: bool,
}

#[cfg(test)]
impl RecordingSink {
    pub(crate) fn new() -> Self {
        Self { lines: std::vec::Vec::new(), fail_next: false }
    }
}

#[cfg(test)]
impl TextSink for RecordingSink {
    fn write_line(&mut self, line: &str) -> Result<(), BannerError> {
        if self.fail_next {
            return Err(BannerError::OutputFailed);
        }
        let mut owned = std::string::String::new();
        write!(owned, "{line}").expect("String write is infallible");
        self.lines.push(owned);
        Ok(())
    }
}

/// Real UEFI adapter: wires [`TextSink`] to `uefi::proto::console::text::Output`.
/// Only compiled when targeting the `uefi` OS (the `x86_64-unknown-uefi`
/// build), never pulled into host `cargo test` runs.
#[cfg(target_os = "uefi")]
pub mod uefi_backend {
    use super::{BannerError, TextSink};
    use uefi::CStr16;
    use uefi::proto::console::text::Output;

    /// Scratch UTF-16 buffer size, in code units, matching
    /// [`super::MAX_BANNER_LINE_UNITS`].
    const BUF_UNITS: usize = super::MAX_BANNER_LINE_UNITS;

    /// [`TextSink`] backed by the firmware's `SIMPLE_TEXT_OUTPUT_PROTOCOL`.
    ///
    /// SPEC §5: firmware text banner only, pre-secret phase.
    pub struct FirmwareTextSink<'a> {
        output: &'a mut Output,
    }

    impl<'a> FirmwareTextSink<'a> {
        /// Wrap an already-open `Output` protocol instance.
        pub fn new(output: &'a mut Output) -> Self {
            Self { output }
        }
    }

    impl TextSink for FirmwareTextSink<'_> {
        fn write_line(&mut self, line: &str) -> Result<(), BannerError> {
            let mut buf = [0u16; BUF_UNITS];
            let cstr = CStr16::from_str_with_buf(line, &mut buf)
                .map_err(|_| BannerError::LineTooLong)?;
            self.output
                .output_string(cstr)
                .map_err(|_| BannerError::OutputFailed)
        }
    }

    /// Print `line` to the firmware's stdout console. Pre-secret only
    /// (SPEC §5, §20.4) — never route secret-bearing text through this
    /// path.
    pub fn print_banner_to_stdout(line: &str) -> Result<(), BannerError> {
        uefi::system::with_stdout(|out| {
            let mut sink = FirmwareTextSink::new(out);
            super::print_banner_line(&mut sink, line)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_line_is_written_verbatim() {
        let mut sink = RecordingSink::new();
        print_banner_line(&mut sink, "Alea test edition").unwrap();
        assert_eq!(sink.lines.len(), 1);
        assert_eq!(sink.lines[0], "Alea test edition");
    }

    #[test]
    fn empty_line_is_allowed() {
        let mut sink = RecordingSink::new();
        print_banner_line(&mut sink, "").unwrap();
        assert_eq!(sink.lines[0], "");
    }

    #[test]
    fn line_at_exact_capacity_succeeds() {
        // MAX_BANNER_LINE_UNITS - 1 ASCII chars + NUL == capacity exactly.
        let s: std::string::String =
            core::iter::repeat('x').take(MAX_BANNER_LINE_UNITS - 1).collect();
        let mut sink = RecordingSink::new();
        assert!(print_banner_line(&mut sink, &s).is_ok());
    }

    #[test]
    fn line_over_capacity_is_rejected_not_truncated() {
        let s: std::string::String =
            core::iter::repeat('x').take(MAX_BANNER_LINE_UNITS).collect();
        let mut sink = RecordingSink::new();
        let err = print_banner_line(&mut sink, &s).unwrap_err();
        assert_eq!(err, BannerError::LineTooLong);
        assert!(sink.lines.is_empty(), "over-length line must not be partially written");
    }

    #[test]
    fn multi_byte_utf8_is_measured_in_utf16_units() {
        // Each of these code points is 1 UTF-16 unit but multiple UTF-8
        // bytes; make sure the bound is UTF-16-unit-based, not byte-based.
        let s: std::string::String = core::iter::repeat('é')
            .take(MAX_BANNER_LINE_UNITS - 1)
            .collect();
        let mut sink = RecordingSink::new();
        assert!(print_banner_line(&mut sink, &s).is_ok());
    }

    #[test]
    fn sink_failure_propagates() {
        let mut sink = RecordingSink::new();
        sink.fail_next = true;
        let err = print_banner_line(&mut sink, "hi").unwrap_err();
        assert_eq!(err, BannerError::OutputFailed);
    }

    #[test]
    fn halt_forever_type_checks_as_never_returning() {
        // We cannot call `halt_forever()` in a test (it never returns),
        // but we can confirm it type-checks as `fn() -> !` so callers in
        // panic handlers compile against the expected signature.
        let _f: fn() -> ! = halt_forever;
    }
}
