//! Machine-source acquisition (SPEC §15-§16, §18,
//! `AppState::MachineEntropyAcquisition`).
//!
//! Still pre-secret (see `crate::flow_secret::physical`'s doc comment
//! for why `AppState::is_post_secret` governs the firmware-text-vs-GOP
//! boundary, not this state's position in the SPEC §21 diagram): SPEC
//! §18.1 requires the machine source to be "sampled before physical
//! entry so an honest implementation cannot adapt its output to the
//! user's later events", which is exactly the state-machine ordering
//! (`MachineEntropyAcquisition` before `PhysicalCollection` for
//! `EntropyMode::Combined`).
//!
//! [`AcquiredSource`]/[`AcquiredSources`] are this module's own
//! secret-bearing record types, distinct from
//! `seed_platform_x86::rng::record::SourceRecord` (whose constructor is
//! `pub(crate)` to `seed-platform-x86`, so a caller outside that crate —
//! this one — cannot build one directly, including in its own tests).
//! Production wiring (`crates/seed-uefi-test/src/flow_secret/`) copies
//! the real WP-24 drivers' (`seed_platform_x86::rng::{efi_rng, rdseed,
//! rdrand}::sample`) output into an [`AcquiredSource`] via
//! [`MachineSourceGate::acquire`]; host tests implement [`MachineSourceGate`]
//! directly with canned bytes. Same discipline as every other
//! secret-bearing type in this crate: fixed buffers, no `Copy`/`Clone`/
//! `Debug`/`Display`, explicit volatile scrub (SPEC §13, §20.2-§20.3).

use seed_core::arena::scrub_slice;
use seed_core::contracts::{SourceTag, MAX_ALGO_ID, MAX_MACHINE_SOURCE_BYTES};
use seed_platform_x86::rng::progress::AcquisitionObserver;

use crate::entropy_avail::MachineAvailabilityGate;
use crate::output::{LineBuf, TextOutput};
use core::fmt::Write as _;

/// One acquired machine-source record (SPEC §19.1 shape: tag +
/// algorithm identifier + raw bytes). Secret from the moment it exists
/// (SPEC §13, §20.2).
pub struct AcquiredSource {
    tag: SourceTag,
    algo_id: [u8; MAX_ALGO_ID],
    algo_len: u8,
    bytes: [u8; MAX_MACHINE_SOURCE_BYTES],
    bytes_len: u8,
}

impl AcquiredSource {
    /// Builds a record from caller-owned slices, copying both into fixed
    /// internal buffers. Returns `None` if either slice exceeds this
    /// record's fixed capacity.
    #[must_use]
    pub fn new(tag: SourceTag, algo_id: &[u8], bytes: &[u8]) -> Option<Self> {
        if algo_id.len() > MAX_ALGO_ID || bytes.len() > MAX_MACHINE_SOURCE_BYTES {
            return None;
        }
        let mut rec = AcquiredSource {
            tag,
            algo_id: [0u8; MAX_ALGO_ID],
            algo_len: algo_id.len() as u8,
            bytes: [0u8; MAX_MACHINE_SOURCE_BYTES],
            bytes_len: bytes.len() as u8,
        };
        rec.algo_id[..algo_id.len()].copy_from_slice(algo_id);
        rec.bytes[..bytes.len()].copy_from_slice(bytes);
        Some(rec)
    }

    #[must_use]
    pub fn tag(&self) -> SourceTag {
        self.tag
    }
    #[must_use]
    pub fn algo_id(&self) -> &[u8] {
        &self.algo_id[..self.algo_len as usize]
    }
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.bytes_len as usize]
    }

    pub fn scrub(&mut self) {
        scrub_slice(&mut self.algo_id);
        scrub_slice(&mut self.bytes);
        self.algo_len = 0;
        self.bytes_len = 0;
    }
}

impl Drop for AcquiredSource {
    fn drop(&mut self) {
        self.scrub();
    }
}

/// Up to five machine sources acquired in one ceremony (SPEC §19.1:
/// `ApprovedEfiRng` / `X86Rdseed64` / `X86RdrandSupplementary`, plus
/// `Tpm2GetRandom` — SPEC_TPM_ENTROPY.md §6.3 — and `Tpm12GetRandom` —
/// SPEC_TPM12_ENTROPY.md §1; the §6 family-exclusive rule means at most
/// one of the two TPM slots is ever filled in practice, enforced at the
/// gate, not here. `ApprovedUsbTrng` does not flow through this
/// container today; its WP-U4-blocked read path has no gate wiring).
pub struct AcquiredSources {
    slots: [Option<AcquiredSource>; 5],
    len: usize,
}

impl AcquiredSources {
    #[must_use]
    pub const fn new() -> Self {
        Self { slots: [None, None, None, None, None], len: 0 }
    }

    /// Appends `source`. Silently drops it if capacity (5) is already
    /// reached — unreachable given the five machine-source tags this
    /// container can carry, kept as a defensive bound rather than a
    /// panic (SPEC §13/§27.2: no panics on this path).
    pub fn push(&mut self, source: AcquiredSource) {
        if self.len < self.slots.len() {
            self.slots[self.len] = Some(source);
            self.len += 1;
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn iter(&self) -> impl Iterator<Item = &AcquiredSource> {
        self.slots[..self.len].iter().filter_map(Option::as_ref)
    }

    /// Scrubs every acquired record (SPEC §19.4: "raw machine-source
    /// records ... MUST scrub").
    pub fn scrub(&mut self) {
        for slot in self.slots.iter_mut() {
            if let Some(s) = slot {
                s.scrub();
            }
            *slot = None;
        }
        self.len = 0;
    }

    /// SHOULD-FIX #3 (SPEC §18.2): "Machine-only generation is enabled
    /// only when at least one source is approved as a sole source by the
    /// current compiled-in policy." `true` if at least one source actually
    /// present in `self` is sole-source-approved under `avail`'s
    /// *current* answer.
    ///
    /// This is a genuinely different, later check than
    /// `crate::entropy_avail::compute_mode_availability`'s own pre-secret
    /// gate (which only decides whether `MachineOnly` is *offered* as a
    /// choice, before any real acquisition attempt): a runtime
    /// acquisition can succeed via a mechanism that is merely *approved*
    /// (not sole-source-approved) even when a different, sole-source-
    /// approved mechanism was what made `MachineOnly` available a moment
    /// earlier — e.g. EFI RNG succeeds at acquisition time while RDSEED
    /// (the one actually sole-source-approved under the shipped policy)
    /// fails its health check. Callers that only require "acquisition
    /// nominally succeeded" (SPEC §15.3's `assemble_acquired_sources`,
    /// used for `Combined` mode too, where physical entropy also
    /// contributes and no single machine source needs to be sole) MUST
    /// NOT call this; it is meaningful only for `MachineOnly` mode's
    /// specific SPEC §18.2 requirement — see this crate's `flow_secret::
    /// driver` for the one call site, which determines "this is
    /// `MachineOnly`" the same way every other branch there does: from
    /// the state the machine actually lands in, not a locally cached
    /// mode.
    ///
    /// RDRAND is never sole-source-eligible (SPEC §15.3/§18.2: "RDRAND
    /// alone never enables this mode") — always `false` for that tag,
    /// regardless of policy content.
    #[must_use]
    pub fn has_sole_source_approved(&self, avail: &mut dyn MachineAvailabilityGate) -> bool {
        self.iter().any(|s| match s.tag() {
            SourceTag::ApprovedEfiRng => avail.efi_rng().sole_source_allowed,
            SourceTag::X86Rdseed64 => avail.rdseed().sole_source_allowed,
            SourceTag::X86RdrandSupplementary => false,
            // SPEC_USB_TRNG.md §8.3: USB TRNG sole-source participation is
            // a `sole_source_allowed` policy bool, EFI-modelled, default
            // false — but the real device-read path (WP-U4) is
            // §7.4-BLOCKED (`IMPLEMENTATION_MAP_USB_TRNG.md` §4/§7), so
            // `ApprovedUsbTrng` is never actually acquired into
            // `AcquiredSources` on any real path today; `false` here is
            // both the honest current answer and the fail-closed default
            // once WP-U4 lands and wires a real gate query.
            SourceTag::ApprovedUsbTrng => false,
            // SPEC_TPM_ENTROPY.md §8.2: TPM sole-source participation is
            // parser-forbidden absolutely in this version (the policy
            // parser rejects `sole_source_allowed = true` for `[tpm2]`,
            // the same no-override posture as RDRAND above) — pre-boot
            // code cannot distinguish a discrete TPM from an fTPM sharing
            // the CPU package, so "TPM alone" could silently mean "this
            // CPU package alone, twice". Hard `false`, not a policy read.
            SourceTag::Tpm2GetRandom => false,
            // SPEC_TPM12_ENTROPY.md inherits the §8.2 prohibition
            // verbatim: a 1.2 part never stands alone either.
            SourceTag::Tpm12GetRandom => false,
            // Never acquired into `AcquiredSources` (physical sources
            // live in `crate::flow_secret::physical::PhysicalStaging`
            // instead) — exhaustive, not a wildcard, so a future new
            // `SourceTag` variant forces this function to be revisited
            // rather than silently falling through a catch-all.
            SourceTag::DiceRolls | SourceTag::CoinFlips => false,
        })
    }
}

impl Default for AcquiredSources {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for AcquiredSources {
    fn drop(&mut self) {
        self.scrub();
    }
}

/// Why machine-source acquisition failed (SPEC §27.3: no secret
/// content).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineAcquisitionError {
    /// `mode` requires at least one machine source and none could be
    /// acquired.
    NoSourceAvailable,
    /// Real-hardware slow-RDSEED fix: at least one approved primary
    /// mechanism (EFI RNG / RDSEED) hit its wall-clock acquisition
    /// deadline ([`seed_platform_x86::time`]) rather than a plain
    /// exhausted-retry/health-check refusal, and no primary source
    /// otherwise succeeded. Handled identically to `NoSourceAvailable` by
    /// every caller's control flow (the driver's `Event::
    /// MachineEntropyFailed(ExitToFirmware)` fires exactly the same way);
    /// the distinction exists only so the failure screen can tell the
    /// operator "too slow" instead of a generic refusal.
    SourceTimedOut,
}

/// Host-testable acquisition provider seam, reusing WP-24's drivers in
/// production (see module doc comment).
///
/// Takes no `EntropyMode` parameter: `StateMachine` only ever enters
/// `AppState::MachineEntropyAcquisition` for `Combined`/`MachineOnly`
/// (never `DiceOnly`), and — like `entropy_avail::MachineAvailabilityGate`
/// before it — availability/approval is a pure function of the signed
/// policy plus runtime detection, not of which of those two modes was
/// picked (`StateMachine` itself does not expose the chosen mode
/// publicly; only `target_bits()`, by design — see `crate::flow_secret::driver`'s
/// doc comment for why every downstream branch is driven by `sm.state()`
/// instead).
pub trait MachineSourceGate {
    /// Attempt to acquire whichever machine sources the current compiled-in
    /// policy approves, appending each success to `into`. `observer` is
    /// notified once per raw value successfully collected (counts only —
    /// no secret bytes; SPEC §21 progress indication for the acquiring
    /// screen, real-hardware slow-RDSEED fix), so a legitimately slow but
    /// working source does not look frozen.
    ///
    /// `extras` carries the user's §22.5b opt-in selections
    /// (SPEC_TPM_ENTROPY.md §11a): an optional source whose flag is OFF
    /// is not sampled at all — no probe, no record — regardless of policy
    /// approval. The baseline sources (EFI RNG / RDSEED / RDRAND) are not
    /// governed by `extras`; they remain pure policy decisions.
    fn acquire(
        &mut self,
        extras: MachineExtras,
        into: &mut AcquiredSources,
        observer: &mut dyn AcquisitionObserver,
    ) -> Result<(), MachineAcquisitionError>;
}

/// The user's §22.5b machine-extras opt-in selections
/// (SPEC_TPM_ENTROPY.md §11a: "extra choice" model, decision
/// 2026-08-08). Non-secret plain data — which *categories* of optional
/// source the user added, never any sampled bytes. Every flag defaults
/// to OFF: adding a claimed source is an explicit user act.
///
/// `usb_trng` exists now so the §22.5b panel's plumbing is complete the
/// day WP-U4 lands a real read path; no current gate samples USB on any
/// path (`SPEC_USB_TRNG` §7.2 remains BLOCKED).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MachineExtras {
    /// "Add TPM entropy" (SPEC_TPM_ENTROPY.md §11a).
    pub tpm: bool,
    /// "Add USB TRNG" (SPEC_USB_TRNG_DEVICES.md §5a) — plumbed, inert
    /// until WP-U4.
    pub usb_trng: bool,
}

pub const ACQUIRING_LINE: &str = "Sampling approved machine entropy source(s)...";

/// Real-hardware slow-RDSEED fix: additional line shown under
/// [`ACQUIRING_LINE`] so a healthy-but-slow source does not look frozen
/// (SPEC §21 progress indication).
pub const ACQUIRING_DURATION_LINE: &str =
    "This normally takes under a second (up to 5 seconds on some systems). Each dot is progress:";

/// Draw [`ACQUIRING_DURATION_LINE`] (design doc §4 Stage 4: "acquisition
/// ticker inside a panel") as a plain ASCII box hugging the line's own
/// width -- the same `+`/`-`/`|` panel convention this module tree
/// already uses for fixed-art tiles (`dice_coin_art`'s die/coin tiles),
/// applied to a single text line instead. Render-only: the ticker dots
/// themselves are appended separately, on this same visual row, by
/// [`crate::output::TextOutput::write_progress`] (see
/// `crate::flow_secret::driver::ConsoleProgress`) -- this function only
/// draws the panel this screen shows *before* any tick has happened.
fn write_ticker_panel(out: &mut dyn TextOutput, line: &str) {
    let w = line.chars().count();
    let mut border = LineBuf::new();
    let _ = write!(border, "+");
    for _ in 0..w {
        let _ = write!(border, "-");
    }
    let _ = write!(border, "+");
    out.write_line(border.as_str());

    let mut content = LineBuf::new();
    let _ = write!(content, "|{line}|");
    out.write_line(content.as_str());

    out.write_line(border.as_str());
}

/// Render the SPEC §21 machine-acquisition screen. Also carries the SPEC
/// §16 mandatory disclaimer
/// ([`crate::text::MACHINE_HEALTH_CHECK_DISCLAIMER_16`]): this is the one
/// screen shown while [`MachineSourceGate::acquire`] runs, and
/// `seed_platform_x86::rng::health`'s checks (the "these checks" the
/// disclaimer refers to) execute entirely within that call, for both
/// `Combined` and `MachineOnly` modes (see this function's original doc
/// comment above `MachineSourceGate`).
pub fn render_acquiring(out: &mut dyn TextOutput) {
    out.clear();
    out.write_line(ACQUIRING_LINE);
    out.write_line("");
    // SPEC.md amendment 2026-08-06 (GOP-rendered UI): word-wrapped at
    // `crate::text::PROSE_WRAP_COLS` exactly like the SPEC §17.2
    // disclaimer in `crate::flow_secret::physical::render_physical_screen`
    // -- the unwrapped constant is long enough to run off the SPEC §11.4
    // 800x600-floor fixed-layout column budget when drawn as pixels
    // (unlike firmware `SimpleTextOut`, a GOP `put_row` write silently
    // clips at the framebuffer edge rather than wrapping the terminal).
    for line in crate::text::wrap_words(crate::text::MACHINE_HEALTH_CHECK_DISCLAIMER_16, crate::text::PROSE_WRAP_COLS)
    {
        out.write_line(line);
    }
    out.write_line("");
    write_ticker_panel(out, ACQUIRING_DURATION_LINE);
}

/// Wording shown on [`render_machine_failed`] for
/// [`MachineAcquisitionError::SourceTimedOut`] (real-hardware slow-RDSEED
/// fix): distinguishes "the approved source exists but was too slow" from
/// a plain unavailable-source refusal, and directs the operator to
/// physical entry instead of leaving them looking at what would otherwise
/// read as an indefinite hang.
const TIMED_OUT_HEADLINE: &str = "Machine entropy is too slow or unresponsive on this system.";
const TIMED_OUT_DETAIL: &str =
    "The approved hardware source did not deliver entropy within the 5-second budget. \
     No entropy was accepted from it, and nothing was generated.";
const TIMED_OUT_GUIDANCE: &str =
    "Restart the ceremony and choose physical dice or coin entry instead, or retry machine \
     entropy if you believe this system is normally faster.";

/// Wording shown on [`render_machine_failed`] for
/// [`MachineAcquisitionError::NoSourceAvailable`].
const NO_SOURCE_HEADLINE: &str = "No approved machine entropy source could be sampled on this system.";
const NO_SOURCE_GUIDANCE: &str =
    "Restart the ceremony and choose physical dice or coin entry instead.";

const EXIT_LINE: &str = "[Enter] Exit to firmware";

/// Render the SPEC §21 machine-acquisition *failure* screen — shown once,
/// before the driver fires the unchanged `Event::MachineEntropyFailed
/// (ExitToFirmware)` (SPEC §22.1: "Exit before generation"; no in-app
/// retry loop is offered here — restarting the ceremony re-runs every
/// mandatory gate, matching SPEC §22.1's restart semantics, rather than
/// this driver inventing a new state-machine edge). Wording distinguishes
/// [`MachineAcquisitionError::SourceTimedOut`] (real-hardware slow-RDSEED
/// fix) from a plain [`MachineAcquisitionError::NoSourceAvailable`]
/// refusal — see each constant's own doc comment.
pub fn render_machine_failed(out: &mut dyn TextOutput, err: MachineAcquisitionError) {
    out.clear();
    match err {
        MachineAcquisitionError::SourceTimedOut => {
            out.write_line(TIMED_OUT_HEADLINE);
            out.write_line("");
            // SPEC.md amendment 2026-08-06 (GOP-rendered UI): word-wrapped
            // -- unlike firmware `SimpleTextOut`, a GOP `put_row` write
            // silently clips at the framebuffer edge rather than wrapping
            // the terminal, and both of these constants run past the SPEC
            // §11.4 800x600-floor column budget unwrapped.
            for line in crate::text::wrap_words(TIMED_OUT_DETAIL, crate::text::PROSE_WRAP_COLS) {
                out.write_line(line);
            }
            out.write_line("");
            for line in crate::text::wrap_words(TIMED_OUT_GUIDANCE, crate::text::PROSE_WRAP_COLS) {
                out.write_line(line);
            }
        }
        MachineAcquisitionError::NoSourceAvailable => {
            out.write_line(NO_SOURCE_HEADLINE);
            out.write_line("");
            for line in crate::text::wrap_words(NO_SOURCE_GUIDANCE, crate::text::PROSE_WRAP_COLS) {
                out.write_line(line);
            }
        }
    }
    out.write_line("");
    out.write_line(EXIT_LINE);
}

/// Assemble a [`MachineSourceGate::acquire`] result from up to five raw
/// per-mechanism sampling outcomes (SPEC §15, §15.3, §18.2;
/// SPEC_TPM_ENTROPY.md §10; SPEC_TPM12_ENTROPY.md §6 — the gate never
/// passes both TPM families at once, but this pure function does not
/// depend on that). Production
/// wiring (`ProdMachineSourceGate` in `crates/seed-uefi-test/src/
/// flow_secret/mod.rs`, verified only by cross-compilation) delegates
/// the actual pass/fail decision to this pure, host-testable function
/// rather than deciding it inline, per this work package's instruction
/// to keep every bit of flow *logic* host-testable.
///
/// `rdrand` is genuinely supplementary (SPEC §15.3): its bytes are
/// pushed into `into`, and this function only ever returns `Ok`, when at
/// least one non-supplementary source (`efi_rng` and/or `rdseed`) also
/// succeeded in this same call. This is the single choke point that
/// prevents RDRAND alone from being treated as a successful
/// machine-source acquisition — which would otherwise let it silently
/// stand in as "the machine source" whenever EFI RNG/RDSEED fail at
/// *acquisition* time even though a moment earlier, at mode-selection
/// time, one of them looked policy-approved (SPEC §15.3: "MUST NOT
/// enable machine-only generation by itself ... MUST NOT ... be used as
/// a fallback that avoids physical entropy"; SPEC §18.2: "RDRAND alone
/// never enables this mode").
///
/// This is deliberately a *different, later* check from
/// `crate::entropy_avail::compute_mode_availability`'s own pre-secret
/// policy-only gate (which already excludes RDRAND from
/// `machine_only`/`sole_source_allowed` eligibility): that gate decides
/// which *mode* the user is even offered, before acquisition starts;
/// this one decides what a real runtime acquisition attempt is allowed
/// to treat as *successful*, since EFI RNG/RDSEED can still fail at
/// acquisition time (protocol unlocatable, health check failure, CPUID
/// gate miss, ...) after having looked available a moment earlier.
///
/// On the `Err` path any sampled `rdrand` bytes are scrubbed and
/// discarded rather than left reachable through `into`, so a caller
/// cannot accidentally recover them after a failed acquisition.
pub fn assemble_acquired_sources(
    efi_rng: Option<AcquiredSource>,
    rdseed: Option<AcquiredSource>,
    rdrand: Option<AcquiredSource>,
    tpm: Option<AcquiredSource>,
    tpm12: Option<AcquiredSource>,
    into: &mut AcquiredSources,
) -> Result<(), MachineAcquisitionError> {
    let mut primary_succeeded = false;
    if let Some(rec) = efi_rng {
        into.push(rec);
        primary_succeeded = true;
    }
    if let Some(rec) = rdseed {
        into.push(rec);
        primary_succeeded = true;
    }
    // SPEC_TPM_ENTROPY.md §10: a TPM record is a real acquired source
    // (primary here, like EFI RNG) — the *mode* question of whether TPM
    // could ever stand alone for MachineOnly is answered separately, and
    // always "no", by `AcquiredSources::has_sole_source_approved`'s hard
    // `false` arm (§8.2), not by this assembly step.
    if let Some(rec) = tpm {
        into.push(rec);
        primary_succeeded = true;
    }
    // SPEC_TPM12_ENTROPY.md §6: same primary treatment; sole-source for
    // MachineOnly is still hard-denied by `has_sole_source_approved`.
    if let Some(rec) = tpm12 {
        into.push(rec);
        primary_succeeded = true;
    }

    if primary_succeeded {
        // SPEC §15.3: RDRAND is only ever included as a genuine
        // supplement once a primary source has already succeeded.
        if let Some(rec) = rdrand {
            into.push(rec);
        }
        Ok(())
    } else {
        // SPEC §15.3/§18.2: no primary source succeeded this call, so
        // RDRAND bytes (if any were sampled) MUST NOT be treated as a
        // successful acquisition on their own.
        if let Some(mut rec) = rdrand {
            rec.scrub();
        }
        Err(MachineAcquisitionError::NoSourceAvailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy_avail::SourceAvailability;
    use crate::output::test_support::MockTerminal;

    /// SPEC §16: "The UI MUST state" the catastrophic-failures/not-proof
    /// disclaimer wherever machine-source health-check results are
    /// implicated — `render_acquiring` is that screen (see its own doc
    /// comment).
    #[test]
    fn render_acquiring_carries_the_spec_16_disclaimer() {
        let mut term = MockTerminal::new();
        render_acquiring(&mut term);
        assert!(term.contains(ACQUIRING_LINE));
        // SPEC.md amendment 2026-08-06: now word-wrapped (see
        // `render_acquiring`'s own doc comment), so the exact verbatim
        // wording must be recovered from its wrapped fragments rather
        // than found as one contiguous line.
        assert!(term.contains_wrapped(crate::text::MACHINE_HEALTH_CHECK_DISCLAIMER_16, crate::text::PROSE_WRAP_COLS));
    }

    /// Real-hardware slow-RDSEED fix: the acquiring screen must also show
    /// the progress/duration line, so a healthy-but-slow source does not
    /// look frozen.
    #[test]
    fn render_acquiring_carries_the_duration_progress_line() {
        let mut term = MockTerminal::new();
        render_acquiring(&mut term);
        assert!(term.contains(ACQUIRING_DURATION_LINE));
    }

    /// Real-hardware slow-RDSEED fix: the two failure-screen wordings
    /// must be distinguishable, and both must direct the operator to
    /// physical dice/coin entry.
    #[test]
    fn render_machine_failed_distinguishes_timed_out_from_no_source_available() {
        let mut timed_out = MockTerminal::new();
        render_machine_failed(&mut timed_out, MachineAcquisitionError::SourceTimedOut);
        assert!(timed_out.contains(TIMED_OUT_HEADLINE));
        assert!(timed_out.contains("dice") || timed_out.contains("coin"));
        assert!(timed_out.contains(EXIT_LINE));

        let mut no_source = MockTerminal::new();
        render_machine_failed(&mut no_source, MachineAcquisitionError::NoSourceAvailable);
        assert!(no_source.contains(NO_SOURCE_HEADLINE));
        assert!(no_source.contains("dice") || no_source.contains("coin"));
        assert!(no_source.contains(EXIT_LINE));

        // The two screens must not read identically to the operator.
        assert!(!no_source.contains(TIMED_OUT_HEADLINE));
        assert!(!timed_out.contains(NO_SOURCE_HEADLINE));
    }

    /// The progress channel carries no secret content: rendering never
    /// includes anything beyond the fixed wording lines above (the
    /// observer itself is exercised at the raw/rdseed/rdrand layer in
    /// `seed-platform-x86`; here we only pin that this screen's own
    /// static text never varies with what was collected).
    #[test]
    fn render_acquiring_output_is_static_and_secret_free() {
        let mut term = MockTerminal::new();
        render_acquiring(&mut term);
        let screen = term.current_screen();
        // ACQUIRING_LINE, "", disclaimer (word-wrapped -- SPEC.md
        // amendment 2026-08-06 -- into however many lines that takes at
        // `PROSE_WRAP_COLS`), "", then the duration line's 3-row ASCII
        // ticker panel (top border, content, bottom border -- design doc
        // §4 Stage 4 restyle).
        let disclaimer_lines =
            crate::text::wrap_words(crate::text::MACHINE_HEALTH_CHECK_DISCLAIMER_16, crate::text::PROSE_WRAP_COLS)
                .count();
        assert_eq!(screen.len(), 4 + disclaimer_lines + 2);
    }

    /// Design doc §4 Stage 4: "acquisition ticker inside a panel" -- the
    /// duration/ticker line is bracketed by an ASCII panel top/bottom
    /// border immediately above and below it.
    #[test]
    fn render_acquiring_wraps_the_duration_line_in_a_panel() {
        let mut term = MockTerminal::new();
        render_acquiring(&mut term);
        let screen = term.current_screen();
        let content_idx = screen
            .iter()
            .position(|l| l.contains(ACQUIRING_DURATION_LINE))
            .expect("duration line must still be present");
        assert!(content_idx > 0 && content_idx + 1 < screen.len(), "duration line must have a border on each side");
        let top = screen[content_idx - 1];
        let bottom = screen[content_idx + 1];
        assert!(top.starts_with('+') && top.ends_with('+'), "top border malformed: {top:?}");
        assert!(bottom.starts_with('+') && bottom.ends_with('+'), "bottom border malformed: {bottom:?}");
        assert_eq!(top, bottom, "top and bottom borders must match the content width");
        let content = screen[content_idx];
        assert!(content.starts_with('|') && content.ends_with('|'), "content row malformed: {content:?}");
    }

    #[test]
    fn acquired_source_round_trips_and_rejects_oversized_input() {
        let rec = AcquiredSource::new(SourceTag::X86Rdseed64, b"RDSEED64", &[0x11u8; 32]).unwrap();
        assert_eq!(rec.tag(), SourceTag::X86Rdseed64);
        assert_eq!(rec.algo_id(), b"RDSEED64");
        assert_eq!(rec.bytes(), &[0x11u8; 32]);
        assert!(AcquiredSource::new(SourceTag::X86Rdseed64, &[0u8; MAX_ALGO_ID + 1], &[0u8; 4]).is_none());
        assert!(AcquiredSource::new(SourceTag::X86Rdseed64, b"x", &[0u8; MAX_MACHINE_SOURCE_BYTES + 1]).is_none());
    }

    #[test]
    fn acquired_source_scrub_zeroes_and_empties() {
        let mut rec = AcquiredSource::new(SourceTag::X86RdrandSupplementary, b"RDRAND", &[0xAAu8; 32]).unwrap();
        rec.scrub();
        assert_eq!(rec.algo_id(), b"");
        assert_eq!(rec.bytes(), b"");
    }

    #[test]
    fn acquired_sources_collects_and_iterates_in_push_order() {
        let mut all = AcquiredSources::new();
        all.push(AcquiredSource::new(SourceTag::ApprovedEfiRng, b"a", &[1]).unwrap());
        all.push(AcquiredSource::new(SourceTag::X86Rdseed64, b"b", &[2]).unwrap());
        assert_eq!(all.len(), 2);
        let tags: std::vec::Vec<SourceTag> = all.iter().map(AcquiredSource::tag).collect();
        assert_eq!(tags, std::vec![SourceTag::ApprovedEfiRng, SourceTag::X86Rdseed64]);
    }

    #[test]
    fn acquired_sources_scrub_clears_everything() {
        let mut all = AcquiredSources::new();
        all.push(AcquiredSource::new(SourceTag::ApprovedEfiRng, b"a", &[1, 2, 3]).unwrap());
        all.scrub();
        assert_eq!(all.len(), 0);
        assert!(all.iter().next().is_none());
    }

    struct FixedGate {
        result: Result<std::vec::Vec<(SourceTag, std::vec::Vec<u8>)>, MachineAcquisitionError>,
    }
    impl MachineSourceGate for FixedGate {
        fn acquire(
            &mut self,
            _extras: MachineExtras,
            into: &mut AcquiredSources,
            _observer: &mut dyn AcquisitionObserver,
        ) -> Result<(), MachineAcquisitionError> {
            match &self.result {
                Ok(items) => {
                    for (tag, bytes) in items {
                        into.push(AcquiredSource::new(*tag, b"", bytes).unwrap());
                    }
                    Ok(())
                }
                Err(e) => Err(*e),
            }
        }
    }

    #[test]
    fn gate_success_populates_acquired_sources() {
        let mut gate = FixedGate { result: Ok(std::vec![(SourceTag::X86Rdseed64, std::vec![7u8; 32])]) };
        let mut into = AcquiredSources::new();
        let mut obs = seed_platform_x86::rng::progress::NullObserver;
        assert!(gate.acquire(MachineExtras::default(), &mut into, &mut obs).is_ok());
        assert_eq!(into.len(), 1);
    }

    #[test]
    fn gate_failure_propagates() {
        let mut gate = FixedGate { result: Err(MachineAcquisitionError::NoSourceAvailable) };
        let mut into = AcquiredSources::new();
        let mut obs = seed_platform_x86::rng::progress::NullObserver;
        assert_eq!(gate.acquire(MachineExtras::default(), &mut into, &mut obs), Err(MachineAcquisitionError::NoSourceAvailable));
        assert!(into.is_empty());
    }

    /// Real-hardware slow-RDSEED fix: a `SourceTimedOut` failure
    /// propagates through the gate exactly like `NoSourceAvailable` —
    /// same `Err` shape, same empty `into`.
    #[test]
    fn gate_timed_out_failure_propagates_like_no_source_available() {
        let mut gate = FixedGate { result: Err(MachineAcquisitionError::SourceTimedOut) };
        let mut into = AcquiredSources::new();
        let mut obs = seed_platform_x86::rng::progress::NullObserver;
        assert_eq!(gate.acquire(MachineExtras::default(), &mut into, &mut obs), Err(MachineAcquisitionError::SourceTimedOut));
        assert!(into.is_empty());
    }

    // ------------------------------------------------------------------
    // Regression tests for the confirmed WP-26 finding (SPEC §15.3,
    // §18.2): RDRAND succeeding alone must never count as a successful
    // machine-source acquisition.
    // ------------------------------------------------------------------

    /// SPEC_TPM_ENTROPY.md §10: an opted-in, healthy TPM record is a
    /// primary acquisition success on its own — a Combined ceremony whose
    /// baseline machine sources all failed still delivers the TPM mix.
    /// (MachineOnly-mode eligibility is separately, and always, denied
    /// for TPM by `has_sole_source_approved` — tested below.)
    #[test]
    fn assemble_tpm_alone_succeeds() {
        let tpm = AcquiredSource::new(SourceTag::Tpm2GetRandom, b"TPM2/GetRandom", &[0x33u8; 32]).unwrap();
        let mut into = AcquiredSources::new();
        let result = assemble_acquired_sources(None, None, None, Some(tpm), None, &mut into);
        assert!(result.is_ok());
        assert_eq!(into.len(), 1);
    }

    /// SPEC §15.3 unchanged by the TPM: RDRAND supplements a TPM primary
    /// exactly as it supplements EFI RNG/RDSEED.
    #[test]
    fn assemble_rdrand_with_tpm_primary_is_included() {
        let tpm = AcquiredSource::new(SourceTag::Tpm2GetRandom, b"TPM2/GetRandom", &[0x33u8; 32]).unwrap();
        let rdrand = AcquiredSource::new(SourceTag::X86RdrandSupplementary, b"RDRAND", &[0xAAu8; 32]).unwrap();
        let mut into = AcquiredSources::new();
        let result = assemble_acquired_sources(None, None, Some(rdrand), Some(tpm), None, &mut into);
        assert!(result.is_ok());
        assert_eq!(into.len(), 2);
    }

    /// All four mechanisms at once fill the grown 4-slot container.
    #[test]
    fn assemble_all_four_sources_fills_four_slots() {
        let efi = AcquiredSource::new(SourceTag::ApprovedEfiRng, b"CTR-DRBG", &[0x11u8; 32]).unwrap();
        let rdseed = AcquiredSource::new(SourceTag::X86Rdseed64, b"RDSEED64", &[0x22u8; 32]).unwrap();
        let rdrand = AcquiredSource::new(SourceTag::X86RdrandSupplementary, b"RDRAND", &[0xAAu8; 32]).unwrap();
        let tpm = AcquiredSource::new(SourceTag::Tpm2GetRandom, b"TPM2/GetRandom", &[0x33u8; 32]).unwrap();
        let mut into = AcquiredSources::new();
        let result = assemble_acquired_sources(Some(efi), Some(rdseed), Some(rdrand), Some(tpm), None, &mut into);
        assert!(result.is_ok());
        assert_eq!(into.len(), 4);
    }

    /// SPEC_TPM_ENTROPY.md §8.2: an acquired TPM record NEVER counts as
    /// sole-source-approved, regardless of what any gate reports.
    #[test]
    fn tpm_record_never_counts_as_sole_source() {
        struct AllSoleGate;
        impl MachineAvailabilityGate for AllSoleGate {
            fn efi_rng(&mut self) -> crate::entropy_avail::SourceAvailability {
                crate::entropy_avail::SourceAvailability { approved: true, sole_source_allowed: true }
            }
            fn rdseed(&mut self) -> crate::entropy_avail::SourceAvailability {
                crate::entropy_avail::SourceAvailability { approved: true, sole_source_allowed: true }
            }
        }
        let tpm = AcquiredSource::new(SourceTag::Tpm2GetRandom, b"TPM2/GetRandom", &[0x33u8; 32]).unwrap();
        let mut into = AcquiredSources::new();
        into.push(tpm);
        assert!(!into.has_sole_source_approved(&mut AllSoleGate));
    }

    #[test]
    fn assemble_rdrand_alone_is_rejected_never_enables_machine_only() {
        let rdrand = AcquiredSource::new(SourceTag::X86RdrandSupplementary, b"RDRAND", &[0xAAu8; 32]).unwrap();
        let mut into = AcquiredSources::new();
        let result = assemble_acquired_sources(None, None, Some(rdrand), None, None, &mut into);
        assert_eq!(result, Err(MachineAcquisitionError::NoSourceAvailable));
        assert!(into.is_empty(), "RDRAND-only bytes must never be pushed into the acquired set");
    }

    #[test]
    fn assemble_no_sources_is_rejected() {
        let mut into = AcquiredSources::new();
        let result = assemble_acquired_sources(None, None, None, None, None, &mut into);
        assert_eq!(result, Err(MachineAcquisitionError::NoSourceAvailable));
        assert!(into.is_empty());
    }

    #[test]
    fn assemble_efi_rng_alone_succeeds_without_rdrand() {
        let efi_rng = AcquiredSource::new(SourceTag::ApprovedEfiRng, b"CTR-DRBG", &[0x11u8; 32]).unwrap();
        let mut into = AcquiredSources::new();
        let result = assemble_acquired_sources(Some(efi_rng), None, None, None, None, &mut into);
        assert!(result.is_ok());
        assert_eq!(into.len(), 1);
    }

    #[test]
    fn assemble_rdseed_alone_succeeds_without_rdrand() {
        let rdseed = AcquiredSource::new(SourceTag::X86Rdseed64, b"RDSEED64", &[0x22u8; 32]).unwrap();
        let mut into = AcquiredSources::new();
        let result = assemble_acquired_sources(None, Some(rdseed), None, None, None, &mut into);
        assert!(result.is_ok());
        assert_eq!(into.len(), 1);
    }

    #[test]
    fn assemble_rdrand_combined_with_a_primary_source_is_included() {
        // SPEC §15.3: RDRAND bytes are legitimately included as a
        // supplement once a primary source has already succeeded.
        let rdseed = AcquiredSource::new(SourceTag::X86Rdseed64, b"RDSEED64", &[0x22u8; 32]).unwrap();
        let rdrand = AcquiredSource::new(SourceTag::X86RdrandSupplementary, b"RDRAND", &[0xAAu8; 32]).unwrap();
        let mut into = AcquiredSources::new();
        let result = assemble_acquired_sources(None, Some(rdseed), Some(rdrand), None, None, &mut into);
        assert!(result.is_ok());
        assert_eq!(into.len(), 2);
        let tags: std::vec::Vec<SourceTag> = into.iter().map(AcquiredSource::tag).collect();
        assert!(tags.contains(&SourceTag::X86RdrandSupplementary));
        assert!(tags.contains(&SourceTag::X86Rdseed64));
    }

    #[test]
    fn assemble_efi_rng_and_rdseed_fail_rdrand_succeeds_still_rejected() {
        // The exact adversarial-review scenario: EFI RNG locate() failed
        // and RDSEED's health checks failed at runtime, but RDRAND alone
        // sampled successfully -- this must still be a failed
        // acquisition, not a silent RDRAND-only success.
        let rdrand = AcquiredSource::new(SourceTag::X86RdrandSupplementary, b"RDRAND", &[0x55u8; 32]).unwrap();
        let mut into = AcquiredSources::new();
        let result = assemble_acquired_sources(None, None, Some(rdrand), None, None, &mut into);
        assert_eq!(result, Err(MachineAcquisitionError::NoSourceAvailable));
        assert!(into.is_empty());
    }

    // ------------------------------------------------------------------
    // SHOULD-FIX #3 regression tests (SPEC §18.2): `AcquiredSources::
    // has_sole_source_approved`.
    // ------------------------------------------------------------------

    /// A fixed-answer [`MachineAvailabilityGate`] double: reports exactly
    /// the `(approved, sole_source_allowed)` pair configured for each
    /// mechanism, independent of any real policy/CPUID state.
    struct FixedAvailability {
        efi_rng: SourceAvailability,
        rdseed: SourceAvailability,
    }
    impl MachineAvailabilityGate for FixedAvailability {
        fn efi_rng(&mut self) -> SourceAvailability {
            self.efi_rng
        }
        fn rdseed(&mut self) -> SourceAvailability {
            self.rdseed
        }
    }

    #[test]
    fn has_sole_source_approved_true_for_a_sole_source_approved_efi_rng() {
        let mut avail = FixedAvailability {
            efi_rng: SourceAvailability { approved: true, sole_source_allowed: true },
            rdseed: SourceAvailability::default(),
        };
        let mut sources = AcquiredSources::new();
        sources.push(AcquiredSource::new(SourceTag::ApprovedEfiRng, b"CTR-DRBG", &[1u8; 32]).unwrap());
        assert!(sources.has_sole_source_approved(&mut avail));
    }

    #[test]
    fn has_sole_source_approved_true_for_a_sole_source_approved_rdseed() {
        let mut avail = FixedAvailability {
            efi_rng: SourceAvailability::default(),
            rdseed: SourceAvailability { approved: true, sole_source_allowed: true },
        };
        let mut sources = AcquiredSources::new();
        sources.push(AcquiredSource::new(SourceTag::X86Rdseed64, b"RDSEED64", &[2u8; 32]).unwrap());
        assert!(sources.has_sole_source_approved(&mut avail));
    }

    /// The exact SHOULD-FIX #3 adversarial case: EFI RNG succeeded and is
    /// policy-approved, but the current compiled-in policy does not grant it
    /// sole-source status — must be rejected, not treated as sufficient
    /// merely because *a* primary source succeeded.
    #[test]
    fn has_sole_source_approved_false_for_an_approved_but_not_sole_source() {
        let mut avail = FixedAvailability {
            efi_rng: SourceAvailability { approved: true, sole_source_allowed: false },
            rdseed: SourceAvailability::default(),
        };
        let mut sources = AcquiredSources::new();
        sources.push(AcquiredSource::new(SourceTag::ApprovedEfiRng, b"CTR-DRBG", &[3u8; 32]).unwrap());
        assert!(!sources.has_sole_source_approved(&mut avail));
    }

    /// RDRAND is never sole-source-eligible (SPEC §15.3/§18.2), no matter
    /// what a hypothetical policy might otherwise claim about the other
    /// two mechanisms.
    #[test]
    fn has_sole_source_approved_false_for_rdrand_only() {
        let mut avail = FixedAvailability {
            efi_rng: SourceAvailability { approved: true, sole_source_allowed: true },
            rdseed: SourceAvailability { approved: true, sole_source_allowed: true },
        };
        let mut sources = AcquiredSources::new();
        sources.push(AcquiredSource::new(SourceTag::X86RdrandSupplementary, b"RDRAND", &[4u8; 32]).unwrap());
        assert!(!sources.has_sole_source_approved(&mut avail));
    }

    #[test]
    fn has_sole_source_approved_false_for_an_empty_acquisition() {
        let mut avail = FixedAvailability {
            efi_rng: SourceAvailability { approved: true, sole_source_allowed: true },
            rdseed: SourceAvailability { approved: true, sole_source_allowed: true },
        };
        let sources = AcquiredSources::new();
        assert!(!sources.has_sole_source_approved(&mut avail));
    }

    /// Mixed acquisition: RDRAND (never sole) plus a genuinely
    /// sole-source-approved RDSEED record — the presence of the
    /// non-qualifying supplementary source must not mask the qualifying
    /// one.
    #[test]
    fn has_sole_source_approved_true_when_mixed_with_a_non_qualifying_rdrand_record() {
        let mut avail = FixedAvailability {
            efi_rng: SourceAvailability::default(),
            rdseed: SourceAvailability { approved: true, sole_source_allowed: true },
        };
        let mut sources = AcquiredSources::new();
        sources.push(AcquiredSource::new(SourceTag::X86RdrandSupplementary, b"RDRAND", &[5u8; 32]).unwrap());
        sources.push(AcquiredSource::new(SourceTag::X86Rdseed64, b"RDSEED64", &[6u8; 32]).unwrap());
        assert!(sources.has_sole_source_approved(&mut avail));
    }
}
