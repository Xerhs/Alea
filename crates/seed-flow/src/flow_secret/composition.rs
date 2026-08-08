//! SPEC_EDU_UI §4-§6: the counted-vs-claimed entropy-composition panel
//! (SPEC §22.5a), realized inside the existing, frozen
//! `AppState::FinalGenerationConfirmation` state (SPEC_EDU_UI §6 — the
//! SPEC §21 state machine is not modified).
//!
//! This module owns three things (`IMPLEMENTATION_MAP_EDU.md` §3.3/§3.4,
//! WP-E3/WP-E4):
//!
//! - the `EDU_*` verbatim string constants (SPEC_EDU_UI §4.2), each with
//!   a byte-exact test, mirroring `crate::text`'s own verbatim-string
//!   pattern without living in that shared file (ownership stays
//!   disjoint per the map);
//! - [`CompositionModel`]/[`MachineTagSet`], the small plain-data model
//!   the driver assembles from already-present state (`PhysicalStaging`
//!   counts, `AcquiredSources` tags, `target_bits()`, `policy_ver`) —
//!   SPEC_EDU_UI §3.2, frozen at WP-E2;
//! - [`render_composition_panel`], the panel
//!   itself (SPEC_EDU_UI §4.3-§4.6), rendered on the pre-secret
//!   `TextOutput` seam (SPEC §12.1) the same way `flow_secret::confirm`
//!   renders the SPEC §22.6 screen it precedes.
//!
//! No secret byte is ever read or displayed here: only counts (`u32`)
//! and [`seed_core::contracts::SourceTag`] values, both explicitly
//! non-secret per SPEC_EDU_UI §4.1.

use core::fmt::Write as _;

use seed_core::contracts::{SourceTag, TargetBits};
use seed_protocol::accounting::{category_of, counted_milli_bits, fmt_milli_bits_1dp, meets_floor, EntropyCategory};
use seed_protocol::state::EntropyMode;

use crate::output::{LineBuf, TextOutput};
use crate::text::{MACHINE_HEALTH_CHECK_DISCLAIMER_16, MACHINE_ONLY_WARNING_18_2};

// ============================================================================
// SPEC_EDU_UI §4.2: mandated per-method honest phrasings (verbatim, WP-E4)
// ============================================================================

/// SPEC_EDU_UI §4.2, verbatim.
pub const EDU_HEADER: &str =
    "Your entropy is made of these sources. Alea mixes them all, but it can only count the ones you witnessed.";

/// SPEC_EDU_UI §4.2, verbatim: dice physical sentence.
pub const EDU_DICE_PHYS: &str =
    "Dice: you rolled a physical six-sided die; the randomness is the physics of the throw, which you performed and Alea counted.";

/// SPEC_EDU_UI §4.2, verbatim: dice accounting line.
pub const EDU_DICE_COUNT: &str = "WITNESSED -- 2.585 bits per roll (counted toward the floor)";

/// SPEC_EDU_UI §4.2, verbatim: coin physical sentence.
pub const EDU_COIN_PHYS: &str =
    "Coins: you flipped a physical coin; the randomness is the physics of the flip, which you performed and Alea counted.";

/// SPEC_EDU_UI §4.2, verbatim: coin accounting line.
pub const EDU_COIN_COUNT: &str = "WITNESSED -- 1 bit per flip (counted toward the floor)";

/// SPEC_EDU_UI §4.2, verbatim: RDSEED physical sentence.
pub const EDU_RDSEED_PHYS: &str = "RDSEED: a CPU instruction that samples an on-die noise source inside this processor. You cannot watch it work, and Alea cannot prove it is unpredictable.";

/// SPEC_EDU_UI §4.2, verbatim: RDSEED accounting line.
pub const EDU_RDSEED_CLAIM: &str = "CLAIMED -- bytes returned and health-checked, not proven; 0 counted bits";

/// SPEC_EDU_UI §4.2, verbatim: EFI RNG physical sentence.
pub const EDU_EFIRNG_PHYS: &str = "EFI RNG: a random-number service provided by this computer's firmware, backed by hardware the firmware vendor chose. You cannot watch it work.";

/// SPEC_EDU_UI §4.2, verbatim: EFI RNG accounting line.
pub const EDU_EFIRNG_CLAIM: &str = "CLAIMED -- bytes returned and health-checked, not proven; 0 counted bits";

/// SPEC_EDU_UI §4.2, verbatim: RDRAND physical sentence.
pub const EDU_RDRAND_PHYS: &str =
    "RDRAND: a CPU instruction that returns numbers from a generator seeded by the processor's noise source. Supplementary only -- it never stands alone.";

/// SPEC_EDU_UI §4.2, verbatim: RDRAND accounting line.
pub const EDU_RDRAND_CLAIM: &str = "CLAIMED (supplementary) -- health-checked, not proven; 0 counted bits";

/// SPEC_EDU_UI §4.2, verbatim: counted-total line prefix.
pub const EDU_COUNTED_TOTAL_PREFIX: &str = "Counted (witnessed) toward the security floor:";

/// SPEC_EDU_UI §4.2, verbatim: the claimed-section honesty note.
pub const EDU_CLAIMED_NOTE: &str = "Claimed sources are mixed in and can only help -- but they add 0 counted bits, because health checks are not proof of unpredictability.";

/// SPEC_USB_TRNG.md §11, verbatim (WP-U5 hookup): USB TRNG physical
/// sentence, added the same way as the other `EDU_*_PHYS` rows -- see
/// `IMPLEMENTATION_MAP_EDU.md` §8's forward-compatible reservation, now
/// filled in by `IMPLEMENTATION_MAP_USB_TRNG.md` WP-U5.
pub const EDU_USBTRNG_PHYS: &str = "USB TRNG: an external dongle you attached that samples its own physical \
noise source; a separate device, but you cannot watch it work, and Alea \
cannot prove it is honest or that its data arrived unaltered.";

/// SPEC_USB_TRNG.md §11, verbatim (WP-U5 hookup): USB TRNG accounting
/// line -- same `ClaimedUnproven` category and 0 counted bits as
/// RDSEED/EFI RNG/RDRAND (`seed_protocol::accounting::category_of`,
/// SPEC_USB_TRNG.md §10.3), with the reinforcement-only note.
pub const EDU_USBTRNG_CLAIM: &str = "CLAIMED -- health-checked, not proven; 0 counted bits (reinforcement only)";

/// SPEC_EDU_UI §4.6/§4.3: the honest statement shown when the counted
/// section has nothing in it (`MachineOnly` mode has zero witnessed
/// bits) -- the panel MUST say so plainly rather than showing an empty
/// box with no explanation.
pub const EDU_NOTHING_WITNESSED: &str =
    "Nothing on this screen is witnessed -- machine-only mode has no counted bits.";

/// SPEC_EDU_UI §4.5 sample screen prompt (Continue).
pub const PANEL_CONTINUE_PROMPT: &str = "[Enter] Continue to generate";
/// SPEC_EDU_UI §4.5 sample screen prompt (Return).
pub const PANEL_RETURN_PROMPT: &str = "[Esc] Return to entropy entry";

const RULE_LINE: &str = "-------------------------------------------------------------------";

/// Max present machine tags shown on one claimed-section page before a
/// page break (SPEC.md amendment 2026-08-06: pagination). `MachineTagSet`
/// caps at 4 possible tags (its own doc comment), so this ever produces at
/// most two claimed pages in practice.
const MAX_TAGS_PER_CLAIMED_PAGE: usize = 2;

// ============================================================================
// SPEC_EDU_UI §3.2: the composition model, frozen at WP-E2.
// ============================================================================

/// SPEC_EDU_UI §3.2: a fixed-capacity (<=4) set of the present machine
/// [`SourceTag`]s (`0x01`/`0x02`/`0x03`/`0x12`), built by the driver from
/// `AcquiredSources::iter().map(AcquiredSource::tag)`. No dynamic
/// allocation, no secret byte -- tags only.
///
/// Stored as four flags (one per possible machine tag) rather than an
/// insertion-order list, so capacity is trivially bounded at exactly 4
/// and [`Self::iter`] always yields present tags in a fixed canonical
/// (ascending-tag) order regardless of acquisition order --
/// `SPEC_EDU_UI.md` §8 Open Question 4 recommends canonical order for
/// testability. The fourth flag, `usb_trng` (`SourceTag::ApprovedUsbTrng`,
/// `0x12`), is the WP-U5 hookup (`IMPLEMENTATION_MAP_USB_TRNG.md` §4/§11):
/// it renders as one more CLAIMED row, in the same accounting position as
/// RDSEED (SPEC_USB_TRNG.md §10.3), never counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MachineTagSet {
    efi_rng: bool,
    rdseed: bool,
    rdrand: bool,
    usb_trng: bool,
}

impl MachineTagSet {
    /// An empty set.
    #[must_use]
    pub const fn new() -> Self {
        Self { efi_rng: false, rdseed: false, rdrand: false, usb_trng: false }
    }

    /// Marks `tag` present. Dice/coin tags are not machine tags and are
    /// silently ignored (defensive; the driver never passes them here).
    pub fn insert(&mut self, tag: SourceTag) {
        match tag {
            SourceTag::ApprovedEfiRng => self.efi_rng = true,
            SourceTag::X86Rdseed64 => self.rdseed = true,
            SourceTag::X86RdrandSupplementary => self.rdrand = true,
            SourceTag::ApprovedUsbTrng => self.usb_trng = true,
            SourceTag::DiceRolls | SourceTag::CoinFlips => {}
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        !(self.efi_rng || self.rdseed || self.rdrand || self.usb_trng)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.efi_rng as usize + self.rdseed as usize + self.rdrand as usize + self.usb_trng as usize
    }

    #[must_use]
    pub fn contains(&self, tag: SourceTag) -> bool {
        match tag {
            SourceTag::ApprovedEfiRng => self.efi_rng,
            SourceTag::X86Rdseed64 => self.rdseed,
            SourceTag::X86RdrandSupplementary => self.rdrand,
            SourceTag::ApprovedUsbTrng => self.usb_trng,
            SourceTag::DiceRolls | SourceTag::CoinFlips => false,
        }
    }

    /// Present machine tags, in fixed canonical (ascending-tag) order:
    /// `ApprovedEfiRng` (`0x01`), `X86Rdseed64` (`0x02`),
    /// `X86RdrandSupplementary` (`0x03`), `ApprovedUsbTrng` (`0x12`).
    pub fn iter(&self) -> impl Iterator<Item = SourceTag> + '_ {
        [
            (self.efi_rng, SourceTag::ApprovedEfiRng),
            (self.rdseed, SourceTag::X86Rdseed64),
            (self.rdrand, SourceTag::X86RdrandSupplementary),
            (self.usb_trng, SourceTag::ApprovedUsbTrng),
        ]
        .into_iter()
        .filter(|(present, _)| *present)
        .map(|(_, tag)| tag)
    }
}

/// SPEC_EDU_UI §3.2/§4: which mode + what the session actually
/// collected. Built by the driver from `PhysicalStaging` (dice/coin
/// counts), `AcquiredSources` (present machine tags), `sm.target_bits()`
/// and `policy_ver` -- see [`CompositionModel::new`]. No secret byte:
/// counts and tags only.
pub struct CompositionModel {
    /// Derived from which of `dice_rolls`/`coin_flips`/`machine_tags` are
    /// non-empty (SPEC_EDU_UI §4.6's three cases are exhaustive over
    /// exactly this split; `seed_protocol::state::StateMachine` does not
    /// expose the chosen mode publicly, so this is recomputed from the
    /// same data the panel renders from, which by construction always
    /// agrees with the mode actually chosen on every real path).
    pub mode: EntropyMode,
    pub target: TargetBits,
    pub dice_rolls: u32,
    pub coin_flips: u32,
    pub machine_tags: MachineTagSet,
    pub policy_version: u16,
}

impl CompositionModel {
    /// SPEC_EDU_UI §3.2. `dice_rolls`/`coin_flips` come from
    /// `PhysicalStaging::dice_bytes().len()`/`coin_bytes().len()`;
    /// `machine_tags` from iterating `AcquiredSources`; `target` from
    /// `sm.target_bits()`; `policy_version` from the flow's own
    /// `policy_ver`.
    #[must_use]
    pub fn new(dice_rolls: u32, coin_flips: u32, machine_tags: MachineTagSet, target: TargetBits, policy_version: u16) -> Self {
        let has_physical = dice_rolls > 0 || coin_flips > 0;
        let has_machine = !machine_tags.is_empty();
        let mode = match (has_physical, has_machine) {
            (true, true) => EntropyMode::Combined,
            (true, false) => EntropyMode::DiceOnly,
            (false, true) => EntropyMode::MachineOnly,
            // Unreachable on every real path (the SPEC §17.2 physical
            // budget gate and the machine-acquisition gate each
            // guarantee their own side is non-empty before
            // `FinalGenerationConfirmation` is ever reached) -- but a
            // fabricated/defensive `CompositionModel` with nothing in it
            // must still render *something* honest rather than panic;
            // `MachineOnly`'s "empty counted section, nothing witnessed"
            // rendering is exactly the correct honest statement for
            // "nothing was collected at all", and it never claims a
            // floor was met (SPEC_EDU_UI §4.6).
            (false, false) => EntropyMode::MachineOnly,
        };
        Self { mode, target, dice_rolls, coin_flips, machine_tags, policy_version }
    }
}

// ============================================================================
// SPEC_EDU_UI §4.3-§4.6: the panel itself.
// ============================================================================

fn write_line_fmt(out: &mut dyn TextOutput, args: core::fmt::Arguments) {
    let mut line = LineBuf::new();
    let _ = line.write_fmt(args);
    out.write_line(line.as_str());
}

fn target_bits_number(target: TargetBits) -> u32 {
    target as u32
}

fn target_word_count(target: TargetBits) -> u32 {
    match target {
        TargetBits::Bits128 => 12,
        TargetBits::Bits256 => 24,
    }
}

fn render_header(out: &mut dyn TextOutput, m: &CompositionModel) {
    write_line_fmt(
        out,
        core::format_args!(
            "ENTROPY COMPOSITION -- {} words (target {} bits)   policy v{}",
            target_word_count(m.target),
            target_bits_number(m.target),
            m.policy_version
        ),
    );
}

/// Word-wrap `prose` at `crate::text::PROSE_WRAP_COLS` before emitting it
/// (SPEC.md amendment 2026-08-06 / GOP-rendered UI): unlike firmware
/// `SimpleTextOut`, a GOP `put_row` write silently clips at the
/// framebuffer's right edge rather than wrapping the terminal, and several
/// of this panel's SPEC-verbatim `EDU_*`/§16/§18.2 constants run well past
/// the SPEC §11.4 800x600-floor column budget unwrapped -- exactly the
/// same fix already applied to the SPEC §16/§17.2 disclaimers in
/// `crate::flow_secret::machine`/`crate::flow_secret::physical`.
fn write_wrapped(out: &mut dyn TextOutput, prose: &str) {
    for line in crate::text::wrap_words(prose, crate::text::PROSE_WRAP_COLS) {
        out.write_line(line);
    }
}

/// SPEC_EDU_UI §4.3/§4.5: the counted (witnessed) section -- the ONLY
/// section with a right-hand numeric column, and the ONLY place a summed
/// figure is ever shown, computed via
/// `seed_protocol::accounting::counted_milli_bits` +
/// `fmt_milli_bits_1dp` (frozen at WP-E2/E1).
fn render_counted_section(out: &mut dyn TextOutput, m: &CompositionModel) {
    out.write_line("  COUNTED -- WITNESSED   (you performed these; Alea counted them)");
    out.write_line(RULE_LINE);

    if m.dice_rolls > 0 {
        write_wrapped(out, EDU_DICE_PHYS);
        let mut buf = [0u8; 24];
        let row = fmt_milli_bits_1dp(counted_milli_bits(m.dice_rolls, 0), &mut buf);
        write_line_fmt(out, core::format_args!("  {}   {} rolls = {} bits", EDU_DICE_COUNT, m.dice_rolls, row));
    }
    if m.coin_flips > 0 {
        write_wrapped(out, EDU_COIN_PHYS);
        let mut buf = [0u8; 24];
        let row = fmt_milli_bits_1dp(counted_milli_bits(0, m.coin_flips), &mut buf);
        write_line_fmt(out, core::format_args!("  {}   {} flips = {} bits", EDU_COIN_COUNT, m.coin_flips, row));
    }

    out.write_line(RULE_LINE);

    if m.dice_rolls == 0 && m.coin_flips == 0 {
        // SPEC_EDU_UI §4.6: MachineOnly has no witnessed floor -- no
        // total figure at all, just the honest empty statement.
        out.write_line(EDU_NOTHING_WITNESSED);
        return;
    }

    let total_milli = counted_milli_bits(m.dice_rolls, m.coin_flips);
    let mut buf = [0u8; 24];
    let total_str = fmt_milli_bits_1dp(total_milli, &mut buf);
    let target_num = target_bits_number(m.target);
    if meets_floor(total_milli, m.target) {
        write_line_fmt(out, core::format_args!("  {}  {} bits  >= {}", EDU_COUNTED_TOTAL_PREFIX, total_str, target_num));
    } else {
        // Defensive-only (SPEC_EDU_UI §4.4): unreachable on a real path
        // because physical entry already enforces the floor before this
        // panel is ever reached; if a future refactor ever did reach
        // here below floor, this MUST still never claim a passing
        // verdict it did not earn.
        write_line_fmt(out, core::format_args!("  {}  {} bits  < {} (BELOW FLOOR)", EDU_COUNTED_TOTAL_PREFIX, total_str, target_num));
    }
}

fn claimed_row_text(tag: SourceTag) -> (&'static str, &'static str, &'static str) {
    match tag {
        SourceTag::ApprovedEfiRng => (EDU_EFIRNG_PHYS, EDU_EFIRNG_CLAIM, "EFI RNG"),
        SourceTag::X86Rdseed64 => (EDU_RDSEED_PHYS, EDU_RDSEED_CLAIM, "RDSEED"),
        SourceTag::X86RdrandSupplementary => (EDU_RDRAND_PHYS, EDU_RDRAND_CLAIM, "RDRAND"),
        // SPEC_USB_TRNG.md §11/§10.3 CLAIMED row (WP-U5 hookup).
        SourceTag::ApprovedUsbTrng => (EDU_USBTRNG_PHYS, EDU_USBTRNG_CLAIM, "USB TRNG"),
        // `MachineTagSet::iter` only ever yields the four machine tags
        // above -- see its own doc comment.
        SourceTag::DiceRolls | SourceTag::CoinFlips => ("", "", ""),
    }
}

/// Render just the "CLAIMED -- UNPROVEN" section header + rule -- the top
/// of every claimed-section page (SPEC.md amendment 2026-08-06:
/// pagination may split the claimed rows across more than one page; every
/// such page repeats this header so each page is self-describing).
fn render_claimed_page_header(out: &mut dyn TextOutput) {
    out.clear();
    out.write_line("  CLAIMED -- UNPROVEN    (mixed in; health-checked; NOT counted)");
    out.write_line(RULE_LINE);
}

/// SPEC_EDU_UI §4.3/§4.5: one claimed (unproven) row per `tags` entry --
/// NO numeric column, ever; every row's right-hand text is the literal
/// words `claimed, 0 counted` (§4.3, Finding 6), never a `0.0` or any
/// digit that could align under a counted figure.
fn render_claimed_rows(out: &mut dyn TextOutput, tags: impl Iterator<Item = SourceTag>) {
    for tag in tags {
        debug_assert_eq!(
            category_of(tag),
            EntropyCategory::ClaimedUnproven,
            "MachineTagSet must only ever contain claimed-category tags"
        );
        let (phys, claim, short) = claimed_row_text(tag);
        write_wrapped(out, phys);
        out.write_line(claim);
        write_line_fmt(out, core::format_args!("  {}   claimed, 0 counted", short));
    }
}

/// The closing rule + [`EDU_CLAIMED_NOTE`] honesty note -- appended only
/// to the LAST claimed-section page (SPEC.md amendment 2026-08-06:
/// pagination).
fn render_claimed_note(out: &mut dyn TextOutput) {
    out.write_line(RULE_LINE);
    write_wrapped(out, EDU_CLAIMED_NOTE);
}

/// Number of claimed-section pages `len` present machine tags render
/// across, given [`MAX_TAGS_PER_CLAIMED_PAGE`] (SPEC.md amendment
/// 2026-08-06: pagination) -- `0` when `len == 0`. `MachineTagSet::len()`
/// is capped at 4 (that type's own doc comment), so this is always `0`,
/// `1` or `2` in practice.
fn claimed_page_count(len: usize) -> usize {
    if len == 0 {
        0
    } else {
        len.div_ceil(MAX_TAGS_PER_CLAIMED_PAGE)
    }
}

/// Render claimed-section page `page_index` (0-based) of `m.machine_tags`
/// -- a header, up to [`MAX_TAGS_PER_CLAIMED_PAGE`] rows, and (on the
/// LAST such page only) the closing rule + [`EDU_CLAIMED_NOTE`].
fn render_claimed_page(out: &mut dyn TextOutput, m: &CompositionModel, page_index: usize) {
    let len = m.machine_tags.len();
    let start = page_index * MAX_TAGS_PER_CLAIMED_PAGE;
    let end = (start + MAX_TAGS_PER_CLAIMED_PAGE).min(len);
    render_claimed_page_header(out);
    render_claimed_rows(out, m.machine_tags.iter().skip(start).take(end - start));
    if page_index + 1 == claimed_page_count(len) {
        render_claimed_note(out);
    }
}

/// The final "notices" page: the §16 disclaimer (shown whenever any
/// claimed source is present) and/or the §18.2 warning (restated verbatim
/// in `MachineOnly` mode) -- whichever apply. Never both absent when
/// called (see each caller's own `show_notices` guard).
fn render_notices_page(out: &mut dyn TextOutput, m: &CompositionModel, has_claimed: bool) {
    out.clear();
    if has_claimed {
        // SPEC §16, verbatim, reused (not re-declared) -- shown whenever
        // any claimed source is present (SPEC_EDU_UI §4.5/§7.1).
        write_wrapped(out, MACHINE_HEALTH_CHECK_DISCLAIMER_16);
        out.write_line("");
    }
    if matches!(m.mode, EntropyMode::MachineOnly) {
        // SPEC §18.2, verbatim, reused (not re-declared) -- restated in
        // full, never softened or replaced (SPEC_EDU_UI §4.6/§7.1).
        write_wrapped(out, MACHINE_ONLY_WARNING_18_2);
        out.write_line("");
    }
}

/// The panel's first page: composition header, [`EDU_HEADER`], and the
/// counted section (SPEC.md amendment 2026-08-06: pagination -- always
/// page 1 of the panel, on every mode).
fn render_overview_page(out: &mut dyn TextOutput, m: &CompositionModel) {
    out.clear();
    render_header(out, m);
    out.write_line("");
    write_wrapped(out, EDU_HEADER);
    out.write_line("");
    render_counted_section(out, m);
}

/// SPEC_EDU_UI §4: render the §22.5a panel on the pre-secret `TextOutput`
/// seam. ASCII rules only (no box-drawing glyphs, SPEC_EDU_UI §4.5);
/// counted and claimed are two visually separated sections; the §16
/// disclaimer is shown whenever any claimed source is present; the §18.2
/// warning is restated verbatim in `MachineOnly` mode.
///
/// SPEC.md amendment (2026-08-06, GOP-rendered UI): a fully-populated
/// panel (dice + coins + every present machine source) no longer fits the
/// SPEC §11.4 800x600-floor GOP screen as a single page -- `put_row` clips
/// silently rather than scrolling the way firmware `SimpleTextOut` did, so
/// this now renders across as many pages as the content needs (`clear()`
/// between each), always in the same fixed order: overview, then the
/// claimed section (possibly itself split across pages -- see
/// [`claimed_page_count`]), then the closing notices. This function alone
/// never blocks for input (it has no `keys` parameter -- unchanged from
/// before this amendment, and still used standalone by
/// `seed-desktop-test`'s Learn page).
///
/// DEAD IN THE CEREMONY (2026-08-07 redesign, T17): the interactive
/// counterpart that used to pace these pages one blocking key read apart
/// is deleted — the ceremony's Stage-5 GENERATE screen
/// (`crate::screens::generate`) draws this same [`CompositionModel`] as a
/// single GOP page instead. This line-oriented renderer is retained only
/// for the Learn page named above and for the floor fit audit; it has no
/// ceremony call site.
pub fn render_composition_panel(out: &mut dyn TextOutput, m: &CompositionModel) {
    render_overview_page(out, m);

    let has_claimed = !m.machine_tags.is_empty();
    let show_notices = has_claimed || matches!(m.mode, EntropyMode::MachineOnly);

    for i in 0..claimed_page_count(m.machine_tags.len()) {
        render_claimed_page(out, m, i);
    }

    if show_notices {
        render_notices_page(out, m, has_claimed);
    }

    out.write_line(PANEL_CONTINUE_PROMPT);
    out.write_line(PANEL_RETURN_PROMPT);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::test_support::MockTerminal;

    // ------------------------------------------------------------------
    // WP-E4: verbatim-string tests, byte-for-byte, mirroring `text.rs`.
    // ------------------------------------------------------------------

    #[test]
    fn edu_header_verbatim() {
        assert_eq!(
            EDU_HEADER,
            "Your entropy is made of these sources. Alea mixes them all, but it can only count the ones you witnessed."
        );
    }

    #[test]
    fn edu_dice_phys_verbatim() {
        assert_eq!(
            EDU_DICE_PHYS,
            "Dice: you rolled a physical six-sided die; the randomness is the physics of the throw, which you performed and Alea counted."
        );
    }

    #[test]
    fn edu_dice_count_verbatim() {
        assert_eq!(EDU_DICE_COUNT, "WITNESSED -- 2.585 bits per roll (counted toward the floor)");
    }

    #[test]
    fn edu_coin_phys_verbatim() {
        assert_eq!(
            EDU_COIN_PHYS,
            "Coins: you flipped a physical coin; the randomness is the physics of the flip, which you performed and Alea counted."
        );
    }

    #[test]
    fn edu_coin_count_verbatim() {
        assert_eq!(EDU_COIN_COUNT, "WITNESSED -- 1 bit per flip (counted toward the floor)");
    }

    #[test]
    fn edu_rdseed_phys_verbatim() {
        assert_eq!(
            EDU_RDSEED_PHYS,
            "RDSEED: a CPU instruction that samples an on-die noise source inside this processor. You cannot watch it work, and Alea cannot prove it is unpredictable."
        );
    }

    #[test]
    fn edu_rdseed_claim_verbatim() {
        assert_eq!(EDU_RDSEED_CLAIM, "CLAIMED -- bytes returned and health-checked, not proven; 0 counted bits");
    }

    #[test]
    fn edu_efirng_phys_verbatim() {
        assert_eq!(
            EDU_EFIRNG_PHYS,
            "EFI RNG: a random-number service provided by this computer's firmware, backed by hardware the firmware vendor chose. You cannot watch it work."
        );
    }

    #[test]
    fn edu_efirng_claim_verbatim() {
        assert_eq!(EDU_EFIRNG_CLAIM, "CLAIMED -- bytes returned and health-checked, not proven; 0 counted bits");
    }

    #[test]
    fn edu_rdrand_phys_verbatim() {
        assert_eq!(
            EDU_RDRAND_PHYS,
            "RDRAND: a CPU instruction that returns numbers from a generator seeded by the processor's noise source. Supplementary only -- it never stands alone."
        );
    }

    #[test]
    fn edu_rdrand_claim_verbatim() {
        assert_eq!(EDU_RDRAND_CLAIM, "CLAIMED (supplementary) -- health-checked, not proven; 0 counted bits");
    }

    #[test]
    fn edu_counted_total_prefix_verbatim() {
        assert_eq!(EDU_COUNTED_TOTAL_PREFIX, "Counted (witnessed) toward the security floor:");
    }

    #[test]
    fn edu_claimed_note_verbatim() {
        assert_eq!(
            EDU_CLAIMED_NOTE,
            "Claimed sources are mixed in and can only help -- but they add 0 counted bits, because health checks are not proof of unpredictability."
        );
    }

    #[test]
    fn edu_usbtrng_phys_verbatim() {
        assert_eq!(
            EDU_USBTRNG_PHYS,
            "USB TRNG: an external dongle you attached that samples its own physical noise source; a separate device, but you cannot watch it work, and Alea cannot prove it is honest or that its data arrived unaltered."
        );
    }

    #[test]
    fn edu_usbtrng_claim_verbatim() {
        assert_eq!(EDU_USBTRNG_CLAIM, "CLAIMED -- health-checked, not proven; 0 counted bits (reinforcement only)");
    }

    // ------------------------------------------------------------------
    // MachineTagSet
    // ------------------------------------------------------------------

    #[test]
    fn machine_tag_set_starts_empty() {
        let s = MachineTagSet::new();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert_eq!(s.iter().count(), 0);
    }

    #[test]
    fn machine_tag_set_insert_dedupes_and_orders_canonically() {
        let mut s = MachineTagSet::new();
        s.insert(SourceTag::X86RdrandSupplementary);
        s.insert(SourceTag::ApprovedEfiRng);
        s.insert(SourceTag::X86Rdseed64);
        s.insert(SourceTag::ApprovedEfiRng); // duplicate: no-op
        assert_eq!(s.len(), 3);
        let order: std::vec::Vec<SourceTag> = s.iter().collect();
        assert_eq!(order, std::vec![SourceTag::ApprovedEfiRng, SourceTag::X86Rdseed64, SourceTag::X86RdrandSupplementary]);
    }

    /// WP-U5 hookup: `ApprovedUsbTrng` (`0x12`) is accepted, deduped, and
    /// always ordered LAST (its canonical position after the three
    /// register-based sources, matching `CANONICAL_TAG_BYTES`'s
    /// `[0x01, 0x02, 0x03, ..., 0x12]` order) regardless of insertion
    /// order.
    #[test]
    fn machine_tag_set_accepts_usb_trng_and_orders_it_last() {
        let mut s = MachineTagSet::new();
        s.insert(SourceTag::ApprovedUsbTrng);
        s.insert(SourceTag::X86Rdseed64);
        s.insert(SourceTag::ApprovedUsbTrng); // duplicate: no-op
        assert!(s.contains(SourceTag::ApprovedUsbTrng));
        assert_eq!(s.len(), 2);
        let order: std::vec::Vec<SourceTag> = s.iter().collect();
        assert_eq!(order, std::vec![SourceTag::X86Rdseed64, SourceTag::ApprovedUsbTrng]);
    }

    #[test]
    fn machine_tag_set_ignores_dice_and_coin_tags() {
        let mut s = MachineTagSet::new();
        s.insert(SourceTag::DiceRolls);
        s.insert(SourceTag::CoinFlips);
        assert!(s.is_empty());
    }

    #[test]
    fn machine_tag_set_capacity_is_at_most_four() {
        let mut s = MachineTagSet::new();
        for _ in 0..10 {
            s.insert(SourceTag::ApprovedEfiRng);
            s.insert(SourceTag::X86Rdseed64);
            s.insert(SourceTag::X86RdrandSupplementary);
            s.insert(SourceTag::ApprovedUsbTrng);
        }
        assert_eq!(s.len(), 4, "must never exceed 4 (SPEC_EDU_UI §3.2 + SPEC_USB_TRNG.md WP-U5 hookup)");
    }

    // ------------------------------------------------------------------
    // CompositionModel mode inference
    // ------------------------------------------------------------------

    #[test]
    fn model_infers_combined_when_both_physical_and_machine_present() {
        let mut tags = MachineTagSet::new();
        tags.insert(SourceTag::X86Rdseed64);
        let m = CompositionModel::new(128, 40, tags, TargetBits::Bits256, 1);
        assert_eq!(m.mode, EntropyMode::Combined);
    }

    #[test]
    fn model_infers_dice_only_when_no_machine_tags() {
        let m = CompositionModel::new(24, 0, MachineTagSet::new(), TargetBits::Bits128, 1);
        assert_eq!(m.mode, EntropyMode::DiceOnly);
    }

    #[test]
    fn model_infers_machine_only_when_no_physical() {
        let mut tags = MachineTagSet::new();
        tags.insert(SourceTag::X86Rdseed64);
        let m = CompositionModel::new(0, 0, tags, TargetBits::Bits256, 1);
        assert_eq!(m.mode, EntropyMode::MachineOnly);
    }

    // ------------------------------------------------------------------
    // WP-E3 required DoD test 1: Combined 24w + RDSEED renders both
    // sections, counted total 370.9 >= 256, RDSEED row prints
    // "claimed, 0 counted" and NO digit column, the §16 disclaimer
    // present.
    // ------------------------------------------------------------------

    #[test]
    fn combined_renders_both_sections_with_correct_total_and_claimed_row() {
        let mut tags = MachineTagSet::new();
        tags.insert(SourceTag::X86Rdseed64);
        let m = CompositionModel::new(128, 40, tags, TargetBits::Bits256, 1);
        assert_eq!(m.mode, EntropyMode::Combined);

        let mut term = MockTerminal::new();
        render_composition_panel(&mut term, &m);

        // SPEC.md amendment 2026-08-06: these prose sentences are now
        // word-wrapped before rendering (GOP `put_row` clips rather than
        // wraps), so they no longer appear as one contiguous recorded
        // line -- `contains_wrapped` finds their reflowed fragments in
        // sequence instead (see that helper's own doc comment).
        assert!(term.contains_wrapped(EDU_HEADER, crate::text::PROSE_WRAP_COLS));
        assert!(term.contains_wrapped(EDU_DICE_PHYS, crate::text::PROSE_WRAP_COLS));
        assert!(term.contains_wrapped(EDU_COIN_PHYS, crate::text::PROSE_WRAP_COLS));
        assert!(term.contains_wrapped(EDU_RDSEED_PHYS, crate::text::PROSE_WRAP_COLS));
        assert!(term.contains(EDU_RDSEED_CLAIM));
        assert!(term.contains("370.9 bits  >= 256"), "counted total line must show 370.9 >= 256");
        assert!(term.contains_wrapped(MACHINE_HEALTH_CHECK_DISCLAIMER_16, crate::text::PROSE_WRAP_COLS));

        // The RDSEED row prints the literal "claimed, 0 counted" and
        // carries no OTHER digit -- the only digit allowed anywhere on
        // that row is the fixed "0" inside that literal phrase itself
        // (Finding 6/§4.3: never a numeric column that could be misread
        // as adding to the counted total).
        let claimed_row = term
            .lines
            .iter()
            .find(|l| l.contains("RDSEED") && l.contains("claimed, 0 counted"))
            .expect("must render a RDSEED / claimed, 0 counted row");
        assert!(
            !claimed_row.replace("claimed, 0 counted", "").chars().any(|c| c.is_ascii_digit()),
            "claimed row must carry no numeric column beyond the fixed literal: {claimed_row:?}"
        );
    }

    // ------------------------------------------------------------------
    // WP-E3 required DoD test 2: DiceOnly renders counted only, no
    // claimed section, no §16 disclaimer.
    // ------------------------------------------------------------------

    #[test]
    fn dice_only_renders_counted_section_only_no_claimed_no_disclaimer() {
        let m = CompositionModel::new(24, 0, MachineTagSet::new(), TargetBits::Bits128, 1);
        assert_eq!(m.mode, EntropyMode::DiceOnly);

        let mut term = MockTerminal::new();
        render_composition_panel(&mut term, &m);

        assert!(term.contains_wrapped(EDU_DICE_PHYS, crate::text::PROSE_WRAP_COLS));
        assert!(!term.contains("CLAIMED -- UNPROVEN"));
        assert!(!term.contains_wrapped(MACHINE_HEALTH_CHECK_DISCLAIMER_16, crate::text::PROSE_WRAP_COLS));
        assert!(!term.contains_wrapped(MACHINE_ONLY_WARNING_18_2, crate::text::PROSE_WRAP_COLS));
    }

    // ------------------------------------------------------------------
    // WP-E3 required DoD test 3: MachineOnly renders empty counted
    // section + verbatim MACHINE_ONLY_WARNING_18_2 + "nothing witnessed"
    // statement.
    // ------------------------------------------------------------------

    #[test]
    fn machine_only_renders_empty_counted_section_and_warning() {
        let mut tags = MachineTagSet::new();
        tags.insert(SourceTag::ApprovedEfiRng);
        let m = CompositionModel::new(0, 0, tags, TargetBits::Bits256, 3);
        assert_eq!(m.mode, EntropyMode::MachineOnly);

        let mut term = MockTerminal::new();
        render_composition_panel(&mut term, &m);

        assert!(term.contains(EDU_NOTHING_WITNESSED));
        assert!(term.contains("witnessed"), "must state plainly that nothing is witnessed");
        assert!(term.contains_wrapped(MACHINE_ONLY_WARNING_18_2, crate::text::PROSE_WRAP_COLS));
        assert!(term.contains_wrapped(MACHINE_HEALTH_CHECK_DISCLAIMER_16, crate::text::PROSE_WRAP_COLS));
        assert!(!term.contains("bits  >="), "MachineOnly has no floor to meet, so no verdict line");
    }

    // ------------------------------------------------------------------
    // WP-E3 required DoD test 4: THE LOAD-BEARING INVARIANT (§5). Sweep
    // every mode x present-source combination and assert:
    //   (a) no rendered line ever places a claimed marker next to a
    //       digit (so a claimed source can never read as contributing a
    //       counted figure), and
    //   (b) the only "total"/"bits ... >=" figure ever printed equals
    //       exactly the counted-only sum -- never counted+claimed.
    // ------------------------------------------------------------------

    #[test]
    fn invariant_no_claimed_source_ever_appears_beside_a_counted_figure_or_inflates_the_total() {
        let dice_coin_combos: &[(u32, u32)] = &[(0, 0), (1, 0), (0, 1), (128, 40), (24, 0)];
        let machine_combos: &[&[SourceTag]] = &[
            &[],
            &[SourceTag::ApprovedEfiRng],
            &[SourceTag::X86Rdseed64],
            &[SourceTag::X86RdrandSupplementary],
            &[SourceTag::ApprovedUsbTrng],
            &[SourceTag::ApprovedEfiRng, SourceTag::X86Rdseed64],
            &[SourceTag::ApprovedEfiRng, SourceTag::X86Rdseed64, SourceTag::X86RdrandSupplementary],
            &[
                SourceTag::ApprovedEfiRng,
                SourceTag::X86Rdseed64,
                SourceTag::X86RdrandSupplementary,
                SourceTag::ApprovedUsbTrng,
            ],
        ];
        let targets = [TargetBits::Bits128, TargetBits::Bits256];

        let mut cases_checked = 0usize;
        for &(rolls, flips) in dice_coin_combos {
            for machine in machine_combos {
                for &target in &targets {
                    let mut tags = MachineTagSet::new();
                    for &t in *machine {
                        tags.insert(t);
                    }
                    let m = CompositionModel::new(rolls, flips, tags, target, 1);

                    let mut term = MockTerminal::new();
                    render_composition_panel(&mut term, &m);
                    cases_checked += 1;

                    let expected_total_milli = counted_milli_bits(rolls, flips);
                    let mut buf = [0u8; 24];
                    let expected_total_str =
                        std::string::String::from(fmt_milli_bits_1dp(expected_total_milli, &mut buf));

                    for line in &term.lines {
                        let lower = line.to_ascii_lowercase();
                        let has_claimed_marker = lower.contains("claimed");
                        let has_digit = line.chars().any(|c| c.is_ascii_digit());

                        if has_claimed_marker && has_digit {
                            // The only line allowed to contain BOTH the
                            // word "claimed" and a digit is the §16
                            // disclaimer / EDU_*_CLAIM accounting lines
                            // themselves, which are prose sentences, not
                            // a numeric column -- but even those must
                            // never contain the counted total figure.
                            assert!(
                                !line.contains(&expected_total_str) || expected_total_milli == 0,
                                "a claimed-bearing line must never contain the counted total figure: {line:?}"
                            );
                        }

                        // No line may ever print a "bits ... >=" verdict
                        // whose figure is anything other than the exact
                        // counted-only total.
                        if line.contains("bits") && line.contains(">=") {
                            assert!(
                                line.contains(&expected_total_str),
                                "every >= verdict line must show exactly the counted-only total {expected_total_str}: {line:?}"
                            );
                        }
                    }

                    // The compact claimed row (" <NAME>   claimed, 0
                    // counted") must never carry a digit, for every
                    // present machine tag.
                    for &tag in *machine {
                        let (_, _, short) = claimed_row_text(tag);
                        let row = term
                            .lines
                            .iter()
                            .find(|l| l.contains(short) && l.contains("claimed, 0 counted"))
                            .unwrap_or_else(|| panic!("missing claimed row for {short}"));
                        assert!(
                            !row.replace("claimed, 0 counted", "").chars().any(|c| c.is_ascii_digit()),
                            "claimed row for {short} must carry no numeric column beyond the fixed literal: {row:?}"
                        );
                    }
                }
            }
        }
        assert_eq!(cases_checked, dice_coin_combos.len() * machine_combos.len() * targets.len());
    }

    // ------------------------------------------------------------------
    // WP-E3 required DoD test 5/6: Escape / Continue edges.
    // ------------------------------------------------------------------

    // ------------------------------------------------------------------
    // Defensive below-floor gate (SPEC_EDU_UI §4.4 last bullet):
    // unreachable on a real path, but if ever hit, Continue MUST NOT be
    // offered -- only Escape may end the read.
    // ------------------------------------------------------------------

    #[test]
    fn render_never_emits_a_bare_0_0_on_a_claimed_row() {
        // Finding 6, restated directly: a claimed row must never print a
        // "0.0" that could align under a counted figure.
        let mut tags = MachineTagSet::new();
        tags.insert(SourceTag::ApprovedEfiRng);
        tags.insert(SourceTag::X86Rdseed64);
        tags.insert(SourceTag::X86RdrandSupplementary);
        tags.insert(SourceTag::ApprovedUsbTrng);
        let m = CompositionModel::new(128, 40, tags, TargetBits::Bits256, 1);
        let mut term = MockTerminal::new();
        render_composition_panel(&mut term, &m);
        for line in &term.lines {
            if line.contains("claimed, 0 counted") {
                assert!(!line.contains("0.0"), "claimed row must never print 0.0: {line:?}");
            }
        }
    }

    // ------------------------------------------------------------------
    // WP-U5 (IMPLEMENTATION_MAP_USB_TRNG.md §4): a session with a `0x12`
    // source shows the CLAIMED row exactly like the other machine
    // sources -- "claimed, 0 counted", NO number -- and the counted total
    // is completely unaffected by its presence.
    // ------------------------------------------------------------------

    #[test]
    fn usb_trng_source_renders_as_claimed_row_and_never_alters_counted_total() {
        let mut tags = MachineTagSet::new();
        tags.insert(SourceTag::ApprovedUsbTrng);
        let m = CompositionModel::new(128, 40, tags, TargetBits::Bits256, 1);
        assert_eq!(m.mode, EntropyMode::Combined);
        assert_eq!(
            seed_protocol::accounting::category_of(SourceTag::ApprovedUsbTrng),
            EntropyCategory::ClaimedUnproven,
            "SPEC_USB_TRNG.md §10: a USB TRNG is never CountedWitnessed"
        );

        let mut term_with_usb = MockTerminal::new();
        render_composition_panel(&mut term_with_usb, &m);

        // The CLAIMED section is present, carries the exact §11 rows,
        // and the compact row is the literal "claimed, 0 counted" with
        // no other digit on the line.
        assert!(term_with_usb.contains("CLAIMED -- UNPROVEN"));
        assert!(term_with_usb.contains_wrapped(EDU_USBTRNG_PHYS, crate::text::PROSE_WRAP_COLS));
        assert!(term_with_usb.contains(EDU_USBTRNG_CLAIM));
        let claimed_row = term_with_usb
            .lines
            .iter()
            .find(|l| l.contains("USB TRNG") && l.contains("claimed, 0 counted"))
            .expect("must render a USB TRNG / claimed, 0 counted row");
        assert!(
            !claimed_row.replace("claimed, 0 counted", "").chars().any(|c| c.is_ascii_digit()),
            "USB TRNG claimed row must carry no numeric column beyond the fixed literal: {claimed_row:?}"
        );

        // The counted total, computed from dice/coins alone, is
        // byte-identical to a session with NO machine tags at all --
        // the no-summing invariant (SPEC_USB_TRNG.md §10.2 rule 2/4).
        let baseline = CompositionModel::new(128, 40, MachineTagSet::new(), TargetBits::Bits256, 1);
        let mut term_baseline = MockTerminal::new();
        render_composition_panel(&mut term_baseline, &baseline);

        let total_line = |term: &MockTerminal| {
            term.lines
                .iter()
                .find(|l| l.contains("bits") && l.contains(">="))
                .cloned()
                .expect("counted-total verdict line must be present")
        };
        assert_eq!(
            total_line(&term_with_usb),
            total_line(&term_baseline),
            "counted total line must be identical whether or not the 0x12 USB TRNG source is present"
        );
        assert!(total_line(&term_with_usb).contains("370.9 bits  >= 256"));
    }

    #[test]
    fn usb_trng_alongside_efi_rng_adds_one_more_independent_claimed_row() {
        let mut tags = MachineTagSet::new();
        tags.insert(SourceTag::ApprovedEfiRng);
        tags.insert(SourceTag::ApprovedUsbTrng);
        let m = CompositionModel::new(0, 0, tags, TargetBits::Bits128, 2);
        assert_eq!(m.mode, EntropyMode::MachineOnly);

        let mut term = MockTerminal::new();
        render_composition_panel(&mut term, &m);

        assert!(term.contains_wrapped(EDU_EFIRNG_PHYS, crate::text::PROSE_WRAP_COLS));
        assert!(term.contains_wrapped(EDU_USBTRNG_PHYS, crate::text::PROSE_WRAP_COLS));
        assert!(term.contains(EDU_NOTHING_WITNESSED));
        assert!(!term.contains("bits  >="), "MachineOnly has no floor to meet, so no verdict line");
    }
}
