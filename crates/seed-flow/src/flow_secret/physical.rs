//! Physical-entry screen (SPEC §17.4, `AppState::PhysicalCollection`).
//!
//! `AppState::PhysicalCollection` is pre-secret (`AppState::
//! is_post_secret` is `false` for it — the boundary is
//! `AppState::FinalEntropyDerivation`), so — like SPEC §17.4's own plain
//! UI mockup — this screen uses the same firmware-`TextOutput`/
//! `MenuKeySource` seam WP-25's screens use (SPEC §12.1 permits firmware
//! text output "before secret generation"). The rolled/flipped values
//! are themselves shown on screen live (SPEC §17.4's mockup literally
//! displays "Last ten events"), which is the whole point of this screen
//! — the user must be able to see what they just entered.
//!
//! [`seed_protocol::physical::PhysicalSession`] (WP-07) provides
//! budget/undo/capacity bookkeeping but exposes no accessor for its own
//! raw event bytes (`shared_file_needs`: a future WP-07 revision could
//! add `dice_bytes()`/`coin_bytes()` and let this module's own
//! [`PhysicalStaging`] duplicate be removed). Until then, this module
//! keeps its own parallel secret byte history — pushed/undone in
//! lockstep with every [`PhysicalSession`] call this module makes, using
//! [`PhysicalSession::undo`]'s return value to know which side to
//! shrink — so the exact bytes needed for the SPEC §19.1
//! `DiceRolls`/`CoinFlips` transcript records are available once the
//! budget is met. [`PhysicalStaging`] follows this crate's ordinary
//! secret-type discipline: fixed buffers, no `Copy`/`Clone`/`Debug`, and
//! an explicit volatile scrub (via `seed_core::arena::scrub_slice`, the
//! primitive published specifically for secret-bearing state that
//! cannot live inside `SecretArena` itself).

use seed_core::arena::scrub_slice;
use seed_core::contracts::{TargetBits, MAX_PHYSICAL_EVENTS};
use seed_protocol::physical::{CoinFace, PhysicalEvent, PhysicalSession};

use crate::flow_secret::dice_coin_art;
use crate::keys::{read_confirm_or_decline, MenuKey, MenuKeySource};
use crate::output::{LineBuf, TextOutput};
use core::fmt::Write as _;

/// Raw dice/coin byte history for the entropy transcript (SPEC §17.1,
/// §19.1), living alongside (not inside) [`seed_core::arena::SecretArena`].
/// See this module's doc comment for why it duplicates
/// [`PhysicalSession`]'s own bookkeeping instead of reading from it.
pub struct PhysicalStaging {
    dice: [u8; MAX_PHYSICAL_EVENTS],
    dice_len: usize,
    coin: [u8; MAX_PHYSICAL_EVENTS],
    coin_len: usize,
}

impl PhysicalStaging {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            dice: [0u8; MAX_PHYSICAL_EVENTS],
            dice_len: 0,
            coin: [0u8; MAX_PHYSICAL_EVENTS],
            coin_len: 0,
        }
    }

    /// Appends one dice byte. Crate-visible (rather than private) only so
    /// this module's sibling `flow_secret` submodules' own unit tests can
    /// build a populated [`PhysicalStaging`] without driving a full
    /// keystream through [`run_physical_entry`]; the real production
    /// call site is exclusively [`run_physical_entry`] itself, in
    /// lockstep with [`PhysicalSession::push_roll`].
    pub(crate) fn push_dice(&mut self, value: u8) {
        self.dice[self.dice_len] = value;
        self.dice_len += 1;
    }

    /// Appends one coin byte (`0` = tails, `1` = heads, matching SPEC
    /// §19.1's `CoinFlips` convention). See [`Self::push_dice`]'s doc
    /// comment for why this is crate-visible.
    pub(crate) fn push_coin(&mut self, value: u8) {
        self.coin[self.coin_len] = value;
        self.coin_len += 1;
    }

    fn undo_dice(&mut self) {
        debug_assert!(self.dice_len > 0);
        self.dice_len -= 1;
        self.dice[self.dice_len] = 0;
    }

    fn undo_coin(&mut self) {
        debug_assert!(self.coin_len > 0);
        self.coin_len -= 1;
        self.coin[self.coin_len] = 0;
    }

    /// SPEC §19.1 `DiceRolls` `source_bytes`.
    #[must_use]
    pub fn dice_bytes(&self) -> &[u8] {
        &self.dice[..self.dice_len]
    }

    /// SPEC §19.1 `CoinFlips` `source_bytes`.
    #[must_use]
    pub fn coin_bytes(&self) -> &[u8] {
        &self.coin[..self.coin_len]
    }

    /// Scrubs both buffers and resets lengths to zero (SPEC §17.3:
    /// "The history buffer is scrubbed after final entropy derivation";
    /// also used for the SPEC §17.4 clear-with-confirmation path).
    pub fn scrub(&mut self) {
        scrub_slice(&mut self.dice);
        scrub_slice(&mut self.coin);
        self.dice_len = 0;
        self.coin_len = 0;
    }
}

impl Default for PhysicalStaging {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for PhysicalStaging {
    fn drop(&mut self) {
        self.scrub();
    }
}

// ============================================================================
// SPEC_DICE_COIN_VISUAL.md §2/§3.5/§4.3: instrument sub-selection (UI only)
// ============================================================================

/// Which physical instrument's UI *leads* the entry screen layout
/// (SPEC_DICE_COIN_VISUAL.md §2.2/§2.3) — see the type's own doc comment.
///
/// 2026-08-07 ceremony redesign: the enum itself MOVED to
/// `seed_protocol::state` (unchanged — same three variants, same `Both`
/// default, still PRESENTATION ONLY and still deliberately **not** an
/// `EntropyMode`) so that the merged SPEC §22.4/§22.5/§22.5a setup screen's
/// single `Event::SetupCommitted` can name it: `seed-flow` depends on
/// `seed-protocol`, never the reverse. Re-exported here unchanged so every
/// existing `physical::Instrument` path keeps working.
pub use seed_protocol::state::Instrument;

// ============================================================================
// SPEC_DICE_COIN_VISUAL.md §3.2.1: the history-strip backing store
// (SECRET-BEARING -- full scrub discipline, BLOCKER B2)
// ============================================================================

/// Tail-window capacity of the history strip's backing ring
/// (SPEC_DICE_COIN_VISUAL.md §3.2.1). Pinned to the SPEC §9 Q2
/// "UEFI-floor visible window" value: with each tile 3 glyphs wide + a
/// 2-column gutter (5 cols/tile) and the folded strip label consuming a
/// ~25-30-column prefix, this is the number of tiles that fit one 80x25
/// UEFI strip row within the 79-column ceiling. The renderer additionally
/// clamps the *drawn* count to whatever fits after the live label so the
/// widest strip row is always <= 79 cols; both editions draw the same
/// (identical content, §5). Deliberately tiny -- the direct payoff of
/// cutting `[P]` full-history review (§3.3).
pub const STRIP_TAIL_CAP: usize = 11;

/// Ring event-value code for a heads flip (SPEC_DICE_COIN_VISUAL.md
/// §3.2.1 "two reserved codes for heads/tails"; `1`-`6` are die faces).
const CODE_HEADS: u8 = 7;
/// Ring event-value code for a tails flip.
const CODE_TAILS: u8 = 8;

/// The history strip's backing store: a bounded ring of the last
/// [`STRIP_TAIL_CAP`] event-value codes in **interleaved entry order**
/// (SPEC_DICE_COIN_VISUAL.md §3.2.1).
///
/// This ordered interleaved sequence **is entropy in order** and is
/// **secret-bearing**: it cannot be reconstructed from [`PhysicalStaging`]
/// (whose `dice`/`coin` buffers lose the cross-instrument interleave --
/// see `interleaved_dice_and_coin_pushes_stay_independent`), so this ring
/// is the only place the ordered mix lives and MUST carry the same scrub
/// discipline as [`PhysicalStaging`]: **no `Copy`/`Clone`/`Debug`**, a
/// [`Drop`] scrub via [`scrub_slice`], a [`Self::scrub`] called on `[C]`
/// in lockstep with `staging.scrub()`, and (being function-local to
/// [`run_physical_entry`]) it is dropped -- and thus scrubbed -- before
/// final entropy derivation is ever reached (SPEC §17.3). It is never read
/// by `session`/`staging`, never written back into them, and never enters
/// the §19 transcript.
///
/// Deliberately lossy beyond the tail: older values are overwritten in
/// place (and volatile-scrubbed on undo) as new events push them out of
/// the window; the full ordered history is never persisted (§3.2.1).
pub struct StripRing {
    /// Event-value codes: `1`-`6` = die faces; [`CODE_HEADS`]/
    /// [`CODE_TAILS`] = coin sides.
    codes: [u8; STRIP_TAIL_CAP],
    /// Number of valid entries currently in the window (`0..=CAP`).
    len: usize,
    /// Index of the oldest in-window entry (ring start).
    head: usize,
}

impl StripRing {
    #[must_use]
    fn new() -> Self {
        Self { codes: [0u8; STRIP_TAIL_CAP], len: 0, head: 0 }
    }

    /// Number of tiles currently in the tail window (`0..=CAP`).
    fn len(&self) -> usize {
        self.len
    }

    /// The `i`-th oldest in-window event code (`0..len`).
    fn get(&self, i: usize) -> u8 {
        self.codes[(self.head + i) % STRIP_TAIL_CAP]
    }

    /// Append one event code as the new newest tile. Once the window is
    /// full, the oldest tile scrolls off the left (overwritten in place)
    /// and is gone -- it cannot be re-materialised (§3.4 Undo / §9 Q3).
    fn push(&mut self, code: u8) {
        if self.len < STRIP_TAIL_CAP {
            let idx = (self.head + self.len) % STRIP_TAIL_CAP;
            self.codes[idx] = code;
            self.len += 1;
        } else {
            self.codes[self.head] = code;
            self.head = (self.head + 1) % STRIP_TAIL_CAP;
        }
    }

    /// Pop the newest tile (Backspace/undo), volatile-scrubbing its cell.
    /// A tile that had already scrolled off the left is not restored -- the
    /// authoritative undo is the exact `session` counter (§3.4/§9 Q3).
    fn pop(&mut self) {
        if self.len == 0 {
            return;
        }
        let last = (self.head + self.len - 1) % STRIP_TAIL_CAP;
        scrub_slice(core::slice::from_mut(&mut self.codes[last]));
        self.len -= 1;
    }

    /// Volatile-scrub the whole backing array and reset to empty (called
    /// on `[C] Clear all` in lockstep with `staging.scrub()`, and by
    /// [`Drop`]). Mirrors [`PhysicalStaging::scrub`].
    fn scrub(&mut self) {
        scrub_slice(&mut self.codes);
        self.len = 0;
        self.head = 0;
    }
}

impl Drop for StripRing {
    fn drop(&mut self) {
        self.scrub();
    }
}

/// The three tile rows for one event code (`1`-`6` faces,
/// [`CODE_HEADS`]/[`CODE_TAILS`] coins), from the fixed
/// [`dice_coin_art`] tile art.
fn tile_rows(code: u8) -> [&'static str; 3] {
    match code {
        1..=6 => dice_coin_art::DIE_TILE_3X3[(code - 1) as usize],
        c if c == CODE_HEADS => dice_coin_art::COIN_TILE_HEADS_3ROW,
        _ => dice_coin_art::COIN_TILE_TAILS_3ROW,
    }
}

/// The 79-column ceiling every strip row must stay within on the 80x25
/// UEFI floor (SPEC_DICE_COIN_VISUAL.md §5.1).
const STRIP_MAX_COLS: usize = 79;

/// Build the strip's row-1 prefix (folded label + optional `<+K` marker,
/// SPEC_DICE_COIN_VISUAL.md §3.5).
fn strip_prefix(word: &str, total: usize, earlier: usize) -> LineBuf {
    let mut prefix = LineBuf::new();
    let _ = write!(prefix, "Recent {word} ({total}):");
    if earlier > 0 {
        let _ = write!(prefix, "  <+{earlier}");
    }
    prefix
}

/// SPEC_DICE_COIN_VISUAL.md §3.2/§4.2: draw the tail-window history strip
/// (three top-aligned rows; label + `<+N` folded into the top row). `lead`
/// selects only the label word; the tiles are the one interleaved
/// timeline (dice + coin, §4.2/M4) regardless. Fixed-layout -- never
/// routed through `wrap_words` (§7.5).
fn write_history_strip(out: &mut dyn TextOutput, ring: &StripRing, total: usize, lead: Instrument) {
    let word = match lead {
        Instrument::Dice => "rolls",
        Instrument::Coins => "flips",
        Instrument::Both => "picks",
    };
    let shown = ring.len();
    // First pass: assume every in-window tile is drawn; size the prefix.
    let earlier0 = total.saturating_sub(shown);
    let prefix0 = strip_prefix(word, total, earlier0);
    let fit = STRIP_MAX_COLS.saturating_sub(prefix0.as_str().len()) / 5;
    let drawn = shown.min(fit);
    // Second pass: the true `earlier` reflects the clamped `drawn`. Its
    // digit count is stable vs `earlier0` (both are `total` minus <= CAP),
    // so the prefix width -- and hence the <=79 guarantee -- is unchanged.
    let earlier = total.saturating_sub(drawn);
    let prefix = strip_prefix(word, total, earlier);
    let p = prefix.as_str().len();
    let from = shown - drawn;

    for r in 0..3 {
        let mut line = LineBuf::new();
        if r == 0 {
            let _ = write!(line, "{}", prefix.as_str());
        } else {
            for _ in 0..p {
                let _ = write!(line, " ");
            }
        }
        for i in 0..drawn {
            let _ = write!(line, "  {}", tile_rows(ring.get(from + i))[r]);
        }
        out.write_line(line.as_str());
    }
}

// ============================================================================
// Screen rendering + the entry loop
// ============================================================================

/// Recommended margin over the SPEC §17.2 minimum (25%), computed with
/// pure integer arithmetic (SPEC §13: no floats).
fn recommended_bits(target: TargetBits) -> u32 {
    let t = target as u32;
    t + t / 4
}

/// Fixed cell width of the budget progress bar (design doc §4 Stage 4:
/// "`ACCENT` progress bar for the physical budget, replacing the
/// numeric-only count"). The numeric count itself stays on the Progress
/// line above -- this bar is a purely additive visual, not a
/// replacement of any budget/gate value the driver reads.
const BUDGET_BAR_WIDTH: usize = 40;

/// Pure math (SPEC §13: integer-only, no floats): how many of `width`
/// bar cells are "filled" for `done` out of `budget`. Saturates at
/// `width` once `done >= budget` (recommended-margin overshoot still
/// renders as a full bar, never an overflowing one) and also saturates
/// full for `budget == 0` rather than dividing by zero -- defensive only,
/// since every real caller's budget is a fixed positive [`TargetBits`]
/// value.
fn bar_cells(done: u64, budget: u64, width: usize) -> usize {
    if budget == 0 || done >= budget {
        return width;
    }
    ((done * width as u64) / budget) as usize
}

/// Render [`bar_cells`]'s filled count as a fixed-width `[####----]`
/// text progress bar. Carries no information the numeric Progress line
/// above it doesn't already state -- render-only.
fn write_budget_bar(out: &mut dyn TextOutput, done: u64, budget: u64) {
    let filled = bar_cells(done, budget, BUDGET_BAR_WIDTH);
    let mut line = LineBuf::new();
    let _ = write!(line, "[");
    for i in 0..BUDGET_BAR_WIDTH {
        let _ = write!(line, "{}", if i < filled { '#' } else { '-' });
    }
    let _ = write!(line, "]");
    out.write_line(line.as_str());
}

/// Render the SPEC §17.4 physical-entry screen in the committed
/// SPEC_DICE_COIN_VISUAL.md §3.5/§4.3 r1 layout (23 content rows on the
/// 80x25 UEFI floor; widest line 79 cols; nothing scrolls). `session`
/// supplies the live roll/flip counts and integer-milli-bit budget
/// progress; `lead` selects which picker/controls lead (§2.3, layout
/// only); `ring` is the secret-typed tail-window backing the history strip
/// (§3.2). Carries the SPEC §17.2 mandatory fairness/independence
/// disclaimer verbatim (SPEC_DICE_COIN_VISUAL.md §3.4/M2), word-wrapped to
/// two lines at 80 cols by [`crate::text::wrap_words`] (§7).
///
/// There is **no** "current pick" confirmation block and **no** check
/// token (r1 user decision, §3.4): a pick registers via the live
/// Rolls/Flips counter increment plus the strip's rightmost tile.
pub fn render_physical_screen(
    out: &mut dyn TextOutput,
    session: &PhysicalSession,
    target: TargetBits,
    lead: Instrument,
    ring: &StripRing,
) {
    out.clear();
    let target_bits = target as u32;
    let words = match target {
        TargetBits::Bits128 => 12,
        TargetBits::Bits256 => 24,
    };
    // Row 1: title (reflects the leading instrument).
    let lead_desc = match lead {
        Instrument::Dice => "dice",
        Instrument::Coins => "coins",
        Instrument::Both => "dice and coins",
    };
    let mut title = LineBuf::new();
    let _ = write!(title, "Physical entropy -- {lead_desc} -- {words} words");
    out.write_line(title.as_str());

    // Row 2: progress.
    let progress_bits = session.budget_bits_x1000() / 1000;
    let mut progress = LineBuf::new();
    let _ = write!(
        progress,
        "Progress: {progress_bits} of minimum {target_bits} bits   (recommended {})",
        recommended_bits(target)
    );
    out.write_line(progress.as_str());
    write_budget_bar(out, session.budget_bits_x1000() / 1000, u64::from(target_bits)); // 3

    // Row 4: live counts -- the authoritative pick-registration signal (§3.4).
    let mut counts = LineBuf::new();
    let _ = write!(counts, "Rolls: {}   Flips: {}", session.roll_count(), session.flip_count());
    out.write_line(counts.as_str());
    out.write_line(""); // 5

    // Rows 6-12: the always-on picker (§3.1/§4.1) -- subsumes the old `[L]`
    // legend (§3.1/S2).
    match lead {
        Instrument::Coins => {
            out.write_line("Flip a coin -- press H or T:");
            dice_coin_art::write_coin_picker(out);
        }
        Instrument::Dice => {
            out.write_line("Roll a die -- press the number you see:");
            dice_coin_art::write_dice_picker(out);
        }
        Instrument::Both => {
            out.write_line("Roll a die [1-6] or flip a coin [H]/[T]:");
            dice_coin_art::write_dice_picker(out);
        }
    }
    out.write_line(""); // 13

    // Rows 14-16: the sequential locked history strip (§3.2/§4.2).
    let total = session.roll_count() as usize + session.flip_count() as usize;
    write_history_strip(out, ring, total, lead);
    out.write_line(""); // 17

    // Row 18: controls (no `[L]`, no `[P]`; `[K]` only in single-instrument
    // leads -- §3.5/§4.3/§6).
    out.write_line(match lead {
        Instrument::Dice => "[1-6] Roll   [Backspace] Undo   [C] Clear   [K] Switch to coins",
        Instrument::Coins => "[H]/[T] Flip   [Backspace] Undo   [C] Clear   [K] Switch to dice",
        Instrument::Both => "[1-6] Roll   [H]/[T] Flip   [Backspace] Undo   [C] Clear",
    });
    out.write_line(""); // 19

    // Rows 20-21: the SPEC §17.2 disclaimer, verbatim, word-wrapped to two
    // lines at 80 cols (§7/M2).
    for line in crate::text::wrap_words(crate::text::PHYSICAL_FAIRNESS_DISCLAIMER_17_2, 80) {
        out.write_line(line);
    }
    out.write_line(""); // 22

    // Row 23: continue + back on one line (folded to hit 23 rows, §3.5).
    let mut cont = LineBuf::new();
    let _ = write!(
        cont,
        "{}      {}",
        if session.budget_met(target) {
            "[Enter] Continue (minimum reached)"
        } else {
            "[Enter] Continue (minimum not yet reached)"
        },
        crate::text::BACK_PROMPT
    );
    out.write_line(cont.as_str());
}

pub const CLEAR_CONFIRM_LINE: &str = "Clear every entered roll and flip? [Enter] Confirm   [N] Cancel";

/// How [`run_physical_entry`] ended (SPEC.md §21 amendment, 2026-08-04:
/// "pre-secret Back navigation").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhysicalEntryOutcome {
    /// The SPEC §17.2 minimum-entropy budget was met and the user pressed
    /// Enter to continue.
    BudgetMet,
    /// `[Esc]`: go back one step. The caller fires `Event::Back`, whose
    /// legal edge from `PhysicalCollection` is `SetupSelection`;
    /// any events collected so far are the caller's to scrub.
    Back,
}

/// Drive the SPEC §17.4 physical-entry loop until the user presses Enter
/// with the budget met (SPEC §17.2 gate) or Escape (SPEC.md §21
/// amendment: go back one step). `session`/`staging` are mutated in
/// lockstep on every accepted push/undo/clear.
pub fn run_physical_entry(
    out: &mut dyn TextOutput,
    keys: &mut dyn MenuKeySource,
    session: &mut PhysicalSession,
    staging: &mut PhysicalStaging,
    target: TargetBits,
    instrument: Instrument,
) -> PhysicalEntryOutcome {
    // SPEC_DICE_COIN_VISUAL.md §3.2.1: the secret-typed tail-window ring
    // backing the history strip. Function-local, so it is dropped -- and
    // thus [`StripRing::drop`]-scrubbed -- on every return below, before
    // final entropy derivation is ever reached (SPEC §17.3). Never read by
    // `session`/`staging`; never enters the §19 transcript.
    let mut ring = StripRing::new();
    // The on-screen leading instrument for layout (§2.3). `[K]` toggles it
    // between Dice and Coins; in `Both` mode `[K]` is unbound. It gates
    // layout only -- both key families stay accepted regardless, so the
    // pushed bytes/budget/transcript are byte-identical to the pre-feature
    // path (§0 invariant).
    let mut lead = instrument;
    loop {
        render_physical_screen(out, session, target, lead, &ring);
        match keys.read_menu_key() {
            MenuKey::Char(c @ '1'..='6') => {
                let value = c as u8 - b'0';
                if session.push_roll(value).is_ok() {
                    staging.push_dice(value);
                    ring.push(value);
                }
            }
            MenuKey::Char(c) if c.eq_ignore_ascii_case(&'h') => {
                if session.push_flip(CoinFace::Heads).is_ok() {
                    staging.push_coin(1);
                    ring.push(CODE_HEADS);
                }
            }
            MenuKey::Char(c) if c.eq_ignore_ascii_case(&'t') => {
                if session.push_flip(CoinFace::Tails).is_ok() {
                    staging.push_coin(0);
                    ring.push(CODE_TAILS);
                }
            }
            MenuKey::Backspace => match session.undo() {
                Some(PhysicalEvent::Roll(_)) => {
                    staging.undo_dice();
                    ring.pop();
                }
                Some(PhysicalEvent::Flip(_)) => {
                    staging.undo_coin();
                    ring.pop();
                }
                None => {}
            },
            MenuKey::Char(c) if c.eq_ignore_ascii_case(&'c') => {
                out.clear();
                out.write_line(CLEAR_CONFIRM_LINE);
                if read_confirm_or_decline(keys, 'n') {
                    session.clear();
                    staging.scrub();
                    // Scrub the strip ring in lockstep with staging (§3.2.1).
                    ring.scrub();
                }
            }
            // SPEC_DICE_COIN_VISUAL.md §2.3/§3.5/§6: the on-screen
            // instrument switch. Re-render only -- never touches
            // `session`/`staging` or the strip ring (one shared timeline,
            // §4.2/M4). Unbound in `Both` mode.
            MenuKey::Char(c) if c.eq_ignore_ascii_case(&'k') => {
                lead = match lead {
                    Instrument::Dice => Instrument::Coins,
                    Instrument::Coins => Instrument::Dice,
                    Instrument::Both => Instrument::Both,
                };
            }
            MenuKey::Enter => {
                if session.budget_met(target) {
                    return PhysicalEntryOutcome::BudgetMet;
                }
            }
            MenuKey::Escape => return PhysicalEntryOutcome::Back,
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::test_support::ScriptedMenuKeys;
    use crate::output::test_support::MockTerminal;

    /// SPEC §17.2: "The UI MUST state" the rolls/flips-do-not-prove-
    /// fairness-or-independence disclaimer on the physical-entry screen —
    /// present on every render, whether or not the budget has been met
    /// yet.
    /// SPEC §17.2 disclaimer, now routed through `wrap_words` and rendered
    /// as its **two** wrapped fragments (SPEC_DICE_COIN_VISUAL.md §8/M1):
    /// line 1 ends "...dice or coins are fair or" (79 cols), line 2 is 32
    /// cols. Present on every render, budget met or not. A "reflowed join"
    /// of the two fragments reproduces the verbatim const.
    #[test]
    fn render_physical_screen_carries_the_spec_17_2_disclaimer() {
        let frag1 = "The number of rolls or flips does not prove that your dice or coins are fair or";
        let frag2 = "that the events are independent.";
        let ring = StripRing::new();

        let mut term = MockTerminal::new();
        let session = PhysicalSession::new();
        render_physical_screen(&mut term, &session, TargetBits::Bits128, Instrument::Dice, &ring);
        assert!(term.contains(frag1));
        assert!(term.contains(frag2));
        // The full one-line const must NOT appear -- it is wrapped now.
        assert!(!term.contains(crate::text::PHYSICAL_FAIRNESS_DISCLAIMER_17_2));
        // Reflowed join reproduces the verbatim const.
        assert_eq!(
            std::format!("{frag1} {frag2}"),
            crate::text::PHYSICAL_FAIRNESS_DISCLAIMER_17_2
        );

        let mut term2 = MockTerminal::new();
        let mut session2 = PhysicalSession::new();
        for _ in 0..50 {
            session2.push_roll(3).unwrap();
        }
        render_physical_screen(&mut term2, &session2, TargetBits::Bits128, Instrument::Coins, &ring);
        assert!(term2.contains(frag1));
        assert!(term2.contains(frag2));
    }

    /// The verbatim const itself is unchanged (SPEC_DICE_COIN_VISUAL.md
    /// §8/M2): only its *rendering* wraps. (The `text.rs`
    /// `physical_fairness_disclaimer_17_2_is_verbatim` test still pins the
    /// const byte-for-byte; this asserts the render uses that exact const.)
    #[test]
    fn render_uses_the_verbatim_17_2_const_reflowed() {
        let ring = StripRing::new();
        let mut term = MockTerminal::new();
        let session = PhysicalSession::new();
        render_physical_screen(&mut term, &session, TargetBits::Bits128, Instrument::Both, &ring);
        let joined: std::string::String = crate::text::wrap_words(
            crate::text::PHYSICAL_FAIRNESS_DISCLAIMER_17_2,
            80,
        )
        .collect::<std::vec::Vec<_>>()
        .join(" ");
        assert_eq!(joined, crate::text::PHYSICAL_FAIRNESS_DISCLAIMER_17_2);
        for frag in crate::text::wrap_words(crate::text::PHYSICAL_FAIRNESS_DISCLAIMER_17_2, 80) {
            assert!(term.contains(frag));
        }
    }

    #[test]
    fn staging_push_undo_round_trips_dice() {
        let mut s = PhysicalStaging::new();
        s.push_dice(4);
        s.push_dice(2);
        assert_eq!(s.dice_bytes(), &[4, 2]);
        s.undo_dice();
        assert_eq!(s.dice_bytes(), &[4]);
    }

    #[test]
    fn staging_push_undo_round_trips_coin() {
        let mut s = PhysicalStaging::new();
        s.push_coin(1);
        s.push_coin(0);
        assert_eq!(s.coin_bytes(), &[1, 0]);
        s.undo_coin();
        assert_eq!(s.coin_bytes(), &[1]);
    }

    #[test]
    fn staging_scrub_zeroes_and_resets() {
        let mut s = PhysicalStaging::new();
        s.push_dice(3);
        s.push_coin(1);
        s.scrub();
        assert_eq!(s.dice_bytes(), &[] as &[u8]);
        assert_eq!(s.coin_bytes(), &[] as &[u8]);
        assert!(s.dice.iter().all(|&b| b == 0));
        assert!(s.coin.iter().all(|&b| b == 0));
    }

    #[test]
    fn interleaved_dice_and_coin_pushes_stay_independent() {
        let mut s = PhysicalStaging::new();
        s.push_dice(1);
        s.push_coin(1);
        s.push_dice(2);
        s.push_coin(0);
        s.push_dice(3);
        assert_eq!(s.dice_bytes(), &[1, 2, 3]);
        assert_eq!(s.coin_bytes(), &[1, 0]);
    }

    // ---- run_physical_entry ----

    fn drive(events: std::vec::Vec<MenuKey>, target: TargetBits) -> (PhysicalSession, PhysicalStaging, MockTerminal) {
        let (session, staging, term, outcome) = drive_with_outcome(events, target);
        assert_eq!(outcome, PhysicalEntryOutcome::BudgetMet, "drive() is for the budget-met happy path only");
        (session, staging, term)
    }

    fn drive_with_outcome(
        events: std::vec::Vec<MenuKey>,
        target: TargetBits,
    ) -> (PhysicalSession, PhysicalStaging, MockTerminal, PhysicalEntryOutcome) {
        let mut term = MockTerminal::new();
        let mut keys = ScriptedMenuKeys::new(events);
        let mut session = PhysicalSession::new();
        let mut staging = PhysicalStaging::new();
        // The existing byte-behaviour tests are instrument-agnostic (both
        // key families are always accepted, §2.3); `Both` leads.
        let outcome =
            run_physical_entry(&mut term, &mut keys, &mut session, &mut staging, target, Instrument::Both);
        (session, staging, term, outcome)
    }

    // ---- SPEC.md §21 amendment: Back at the physical-entry screen ----

    #[test]
    fn escape_returns_back_without_requiring_budget_met() {
        let (_session, _staging, _term, outcome) =
            drive_with_outcome(std::vec![MenuKey::Char('1'), MenuKey::Escape], TargetBits::Bits128);
        assert_eq!(outcome, PhysicalEntryOutcome::Back);
    }

    #[test]
    fn physical_screen_shows_the_back_prompt() {
        let ring = StripRing::new();
        let mut term = MockTerminal::new();
        let session = PhysicalSession::new();
        render_physical_screen(&mut term, &session, TargetBits::Bits128, Instrument::Dice, &ring);
        assert!(term.contains(crate::text::BACK_PROMPT));
    }

    #[test]
    fn enter_before_budget_met_is_ignored_and_the_loop_keeps_reading() {
        // 3 rolls is far under the 128-bit (12-word) minimum; an Enter
        // there must be silently ignored (not proceed, not panic), and
        // the loop must keep reading further events -- scripting 47 more
        // rolls plus a final Enter (now budget-met) after the ignored
        // Enter proves exactly that: the driver reads all of them and
        // returns rather than stopping early or hanging.
        let mut events = std::vec![MenuKey::Char('1'), MenuKey::Char('2'), MenuKey::Char('3'), MenuKey::Enter];
        for _ in 0..47 {
            events.push(MenuKey::Char('6'));
        }
        events.push(MenuKey::Enter);
        let (session, staging, _term) = drive(events, TargetBits::Bits128);
        assert!(session.budget_met(TargetBits::Bits128));
        assert_eq!(staging.dice_bytes().len(), 50);
    }

    #[test]
    fn dice_only_budget_met_then_enter_proceeds_and_bytes_match_pushes() {
        let mut events = std::vec::Vec::new();
        for _ in 0..50 {
            events.push(MenuKey::Char('4'));
        }
        events.push(MenuKey::Enter);
        let (session, staging, _term) = drive(events, TargetBits::Bits128);
        assert!(session.budget_met(TargetBits::Bits128));
        assert_eq!(staging.dice_bytes().len(), 50);
        assert!(staging.dice_bytes().iter().all(|&b| b == 4));
        assert!(staging.coin_bytes().is_empty());
    }

    #[test]
    fn coin_flip_h_and_t_accepted_case_insensitively() {
        let mut events = std::vec::Vec::new();
        for i in 0..128 {
            events.push(if i % 2 == 0 { MenuKey::Char('h') } else { MenuKey::Char('T') });
        }
        events.push(MenuKey::Enter);
        let (session, staging, _term) = drive(events, TargetBits::Bits128);
        assert!(session.budget_met(TargetBits::Bits128));
        assert_eq!(staging.coin_bytes().len(), 128);
    }

    #[test]
    fn undo_removes_last_event_from_both_session_and_staging_via_the_real_driver() {
        // Roll, flip, undo (removes the flip), then enough further rolls
        // to meet budget and a final Enter to end the bounded driver run.
        let mut events = std::vec![MenuKey::Char('5'), MenuKey::Char('h'), MenuKey::Backspace];
        for _ in 0..50 {
            events.push(MenuKey::Char('6'));
        }
        events.push(MenuKey::Enter);
        let (session, staging, _term) = drive(events, TargetBits::Bits128);
        assert!(session.budget_met(TargetBits::Bits128));
        assert_eq!(staging.dice_bytes()[0], 5);
        assert!(staging.coin_bytes().is_empty(), "the undone flip must not appear in staging");
    }

    #[test]
    fn clear_confirmation_declined_keeps_events_via_the_real_driver() {
        // [C] then [N] (decline) must leave every prior roll intact, and
        // the loop must keep going afterward (bounded here by scripting
        // enough further rolls to meet budget and a final Enter).
        let mut events = std::vec![MenuKey::Char('3'), MenuKey::Char('c'), MenuKey::Char('n')];
        for _ in 0..49 {
            events.push(MenuKey::Char('6'));
        }
        events.push(MenuKey::Enter);
        let (session, staging, _term) = drive(events, TargetBits::Bits128);
        assert!(session.budget_met(TargetBits::Bits128));
        assert_eq!(staging.dice_bytes()[0], 3, "the pre-clear-attempt roll must survive a declined clear");
        assert_eq!(staging.dice_bytes().len(), 50);
    }

    #[test]
    fn clear_confirmation_accepted_wipes_session_and_staging() {
        let mut session = PhysicalSession::new();
        let mut staging = PhysicalStaging::new();
        session.push_roll(3).unwrap();
        staging.push_dice(3);
        session.clear();
        staging.scrub();
        assert_eq!(session.len(), 0);
        assert!(staging.dice_bytes().is_empty());
    }

    #[test]
    fn render_includes_progress_rolls_flips_and_controls() {
        let ring = StripRing::new();
        let mut term = MockTerminal::new();
        let session = PhysicalSession::new();
        render_physical_screen(&mut term, &session, TargetBits::Bits128, Instrument::Dice, &ring);
        assert!(term.contains("Progress:"));
        assert!(term.contains("Rolls: 0"));
        assert!(term.contains("Flips: 0"));
        assert!(term.contains("[1-6]"));
        assert!(term.contains("[Backspace] Undo"));
    }

    #[test]
    fn recommended_bits_is_25_percent_over_minimum_with_pure_integers() {
        assert_eq!(recommended_bits(TargetBits::Bits128), 160);
        assert_eq!(recommended_bits(TargetBits::Bits256), 320);
    }

    // ---- design doc §4 Stage 4: budget progress bar ----

    #[test]
    fn bar_cells_zero_progress_is_empty() {
        assert_eq!(bar_cells(0, 100, 20), 0);
    }

    #[test]
    fn bar_cells_mid_progress_is_proportional() {
        assert_eq!(bar_cells(50, 100, 20), 10);
        assert_eq!(bar_cells(25, 100, 20), 5);
    }

    #[test]
    fn bar_cells_at_or_over_budget_saturates_at_width() {
        assert_eq!(bar_cells(100, 100, 20), 20);
        assert_eq!(bar_cells(150, 100, 20), 20, "overshoot past budget must not overflow the bar");
    }

    #[test]
    fn bar_cells_zero_budget_saturates_full_rather_than_dividing_by_zero() {
        assert_eq!(bar_cells(0, 0, 20), 20);
    }

    #[test]
    fn bar_cells_zero_width_is_always_empty() {
        assert_eq!(bar_cells(50, 100, 0), 0);
        assert_eq!(bar_cells(100, 100, 0), 0);
    }

    #[test]
    fn render_physical_screen_shows_an_empty_budget_bar_at_zero_progress() {
        let ring = StripRing::new();
        let mut term = MockTerminal::new();
        let session = PhysicalSession::new();
        render_physical_screen(&mut term, &session, TargetBits::Bits128, Instrument::Dice, &ring);
        let screen = term.current_screen();
        let bar = screen[2];
        assert!(bar.starts_with('[') && bar.ends_with(']'), "bar row must be bracketed: {bar:?}");
        assert!(!bar.contains('#'), "zero progress must show no filled cells: {bar:?}");
        assert!(bar.contains('-'), "zero progress must show empty cells: {bar:?}");
    }

    #[test]
    fn render_physical_screen_budget_bar_fills_once_budget_is_met() {
        let ring = StripRing::new();
        let mut term = MockTerminal::new();
        let mut session = PhysicalSession::new();
        for _ in 0..50 {
            session.push_roll(6).unwrap();
        }
        assert!(session.budget_met(TargetBits::Bits128));
        render_physical_screen(&mut term, &session, TargetBits::Bits128, Instrument::Dice, &ring);
        let screen = term.current_screen();
        let bar = screen[2];
        assert!(!bar.contains('-'), "budget met must show a fully filled bar: {bar:?}");
    }

    // ---- SPEC_DICE_COIN_VISUAL.md §3.1/§4.1: always-on picker on screen ----

    #[test]
    fn dice_lead_screen_shows_the_six_face_picker_and_switch_to_coins() {
        let ring = StripRing::new();
        let mut term = MockTerminal::new();
        let session = PhysicalSession::new();
        render_physical_screen(&mut term, &session, TargetBits::Bits128, Instrument::Dice, &ring);
        assert!(term.contains("Roll a die -- press the number you see:"));
        assert!(term.contains("   [1]       [2]       [3]       [4]       [5]       [6]"));
        assert!(term.contains("[K] Switch to coins"));
        // The old `[L]` legend line is gone (subsumed by the picker, S2).
        assert!(!term.contains("[L] Show all six faces"));
    }

    #[test]
    fn coin_lead_screen_shows_the_heads_tails_picker_and_switch_to_dice() {
        let ring = StripRing::new();
        let mut term = MockTerminal::new();
        let session = PhysicalSession::new();
        render_physical_screen(&mut term, &session, TargetBits::Bits128, Instrument::Coins, &ring);
        assert!(term.contains("Flip a coin -- press H or T:"));
        assert!(term.contains("  [H]         [T]"));
        assert!(term.contains("[K] Switch to dice"));
    }

    #[test]
    fn both_lead_screen_shows_both_key_families_and_no_switch_key() {
        let ring = StripRing::new();
        let mut term = MockTerminal::new();
        let session = PhysicalSession::new();
        render_physical_screen(&mut term, &session, TargetBits::Bits128, Instrument::Both, &ring);
        assert!(term.contains("[1-6] Roll   [H]/[T] Flip   [Backspace] Undo   [C] Clear"));
        assert!(!term.contains("[K] Switch"), "Both mode hides the instrument switch (§6)");
    }

    /// BLOCKER B1 / §5.1: every instrument variant renders in exactly 23
    /// content rows with the widest line <= 79 cols on the 80x25 UEFI floor.
    #[test]
    fn every_lead_variant_fits_23_rows_and_79_cols() {
        for lead in [Instrument::Dice, Instrument::Coins, Instrument::Both] {
            let mut ring = StripRing::new();
            // A realistic worst-case count (3-digit label + full window).
            for i in 0..200u32 {
                ring.push((i % 6) as u8 + 1);
            }
            let mut term = MockTerminal::new();
            let mut session = PhysicalSession::new();
            for _ in 0..200 {
                session.push_roll(6).unwrap();
            }
            render_physical_screen(&mut term, &session, TargetBits::Bits256, lead, &ring);
            let screen = term.current_screen();
            assert_eq!(screen.len(), 23, "{lead:?} must render exactly 23 content rows");
            for line in &screen {
                assert!(line.len() <= 79, "{lead:?} line exceeds 79 cols ({}): {line:?}", line.len());
            }
        }
    }

    // ---- SPEC_DICE_COIN_VISUAL.md §3.2.1: the secret-typed strip ring ----

    #[test]
    fn strip_ring_grows_one_tile_at_a_time_then_tail_windows() {
        let mut ring = StripRing::new();
        // Below capacity: grows one tile at a time, no roll-off.
        ring.push(1);
        ring.push(5);
        ring.push(6);
        assert_eq!(ring.len(), 3);
        assert_eq!([ring.get(0), ring.get(1), ring.get(2)], [1, 5, 6]);

        // Fill to capacity exactly.
        while ring.len() < STRIP_TAIL_CAP {
            ring.push(2);
        }
        assert_eq!(ring.len(), STRIP_TAIL_CAP);

        // One more push scrolls the oldest off the left; len stays at CAP,
        // the newest is at the right end, and the leftmost is now the
        // second-ever push (5).
        ring.push(3);
        assert_eq!(ring.len(), STRIP_TAIL_CAP);
        assert_eq!(ring.get(0), 5, "the very first tile (1) has scrolled off");
        assert_eq!(ring.get(STRIP_TAIL_CAP - 1), 3, "the newest push is at the right end");
    }

    /// §3.2/§3.4: `earlier_count` = total - tiles shown, derived purely
    /// from the on-screen counts. When the window is not yet full there is
    /// no `<+N` marker; once it scrolls, the marker shows the roll-off.
    #[test]
    fn history_strip_earlier_count_marker_matches_the_roll_off() {
        // Not yet full: no marker.
        let mut ring = StripRing::new();
        for _ in 0..5 {
            ring.push(4);
        }
        let mut term = MockTerminal::new();
        write_history_strip(&mut term, &ring, 5, Instrument::Dice);
        assert!(term.contains("Recent rolls (5):"));
        assert!(!term.contains("<+"), "no roll-off marker before the window fills");

        // Scrolled: total 30, window holds CAP (11), so 19 earlier.
        let mut ring2 = StripRing::new();
        for _ in 0..30 {
            ring2.push(4);
        }
        assert_eq!(ring2.len(), STRIP_TAIL_CAP);
        let mut term2 = MockTerminal::new();
        write_history_strip(&mut term2, &ring2, 30, Instrument::Dice);
        assert!(term2.contains("Recent rolls (30):"));
        assert!(term2.contains("<+19"), "30 total - 11 shown = 19 earlier");
    }

    /// §3.2.1 / §4.2/M4: a mixed dice+coin ring renders as ONE interleaved
    /// timeline of top-aligned 3-row tiles (coin tiles carry `(H)`/`(T)`).
    #[test]
    fn both_mode_strip_renders_one_interleaved_timeline() {
        let mut ring = StripRing::new();
        ring.push(5); // die
        ring.push(CODE_HEADS); // coin H
        ring.push(2); // die
        ring.push(CODE_TAILS); // coin T
        let mut term = MockTerminal::new();
        write_history_strip(&mut term, &ring, 4, Instrument::Both);
        let screen = term.current_screen();
        assert_eq!(screen.len(), 3, "the strip is exactly 3 top-aligned rows");
        assert!(screen[0].starts_with("Recent picks (4):"));
        // The coin tiles' `(H)`/`(T)` appear on the middle strip row.
        assert!(screen[1].contains("(H)"));
        assert!(screen[1].contains("(T)"));
        for line in &screen {
            assert!(line.len() <= 79);
        }
    }

    /// §3.2.1: scrub zeroes the whole backing array and resets the ring --
    /// mirrors `staging_scrub_zeroes_and_resets`. This is the primitive
    /// exercised on `[C]`, by `Drop`, and (function-local) before final
    /// derivation.
    #[test]
    fn strip_ring_scrub_zeroes_and_resets() {
        let mut ring = StripRing::new();
        ring.push(6);
        ring.push(CODE_HEADS);
        ring.push(3);
        ring.scrub();
        assert_eq!(ring.len(), 0);
        assert_eq!(ring.head, 0);
        assert!(ring.codes.iter().all(|&b| b == 0), "every ring byte must be zero after scrub");
    }

    #[test]
    fn strip_ring_pop_scrubs_the_popped_cell() {
        let mut ring = StripRing::new();
        ring.push(6);
        ring.push(4);
        ring.pop();
        assert_eq!(ring.len(), 1);
        // The popped cell (index 1) is volatile-scrubbed to zero; a tile
        // that had already scrolled off cannot be re-materialised (§9 Q3).
        assert_eq!(ring.codes[1], 0);
        assert_eq!(ring.get(0), 6);
    }

    /// §3.2.1: `[C] Clear all` scrubs the strip ring in lockstep with
    /// `staging.scrub()`. Driven through the REAL entry loop: clear a
    /// populated session, then verify (via a fresh identical run) that the
    /// clear path leaves nothing behind in either staging or the counters.
    #[test]
    fn clear_all_scrubs_staging_in_lockstep_via_the_real_driver() {
        let mut events = std::vec![MenuKey::Char('4'), MenuKey::Char('h'), MenuKey::Char('c'), MenuKey::Enter];
        for _ in 0..50 {
            events.push(MenuKey::Char('6'));
        }
        events.push(MenuKey::Enter);
        let (session, staging, _term) = drive(events, TargetBits::Bits128);
        // After [C] wiped the pre-clear roll+flip, only the 50 post-clear
        // rolls remain -- proving staging (and, in lockstep, the ring) were
        // scrubbed. The ring itself is function-local and Drop-scrubbed on
        // return; `strip_ring_scrub_zeroes_and_resets` pins the zeroing.
        assert_eq!(staging.dice_bytes().len(), 50);
        assert!(staging.coin_bytes().is_empty(), "the pre-clear flip must be gone");
        assert_eq!(session.roll_count(), 50);
    }

    // ---- SPEC_DICE_COIN_VISUAL.md §0 / §2.3: presentation neutrality ----

    /// `[K]` (instrument switch) is re-render only: it never changes the
    /// pushed bytes. A run with `[K]` interspersed produces byte-identical
    /// `dice_bytes()`/`coin_bytes()` to the same run without it -- the §0
    /// firewall invariant, exercised through the real driver.
    #[test]
    fn k_switch_never_changes_the_pushed_bytes() {
        let mut base = std::vec![MenuKey::Char('4'), MenuKey::Char('h'), MenuKey::Char('2')];
        for _ in 0..50 {
            base.push(MenuKey::Char('6'));
        }
        base.push(MenuKey::Enter);

        let mut with_k = std::vec![
            MenuKey::Char('4'),
            MenuKey::Char('k'), // switch to coins -- re-render only
            MenuKey::Char('h'),
            MenuKey::Char('k'), // switch back -- re-render only
            MenuKey::Char('2'),
        ];
        for _ in 0..50 {
            with_k.push(MenuKey::Char('6'));
        }
        with_k.push(MenuKey::Enter);

        let (_s1, staging_base, _t1) = drive(base, TargetBits::Bits128);
        let (_s2, staging_k, _t2) = drive(with_k, TargetBits::Bits128);
        assert_eq!(staging_base.dice_bytes(), staging_k.dice_bytes(), "K must not alter dice bytes");
        assert_eq!(staging_base.coin_bytes(), staging_k.coin_bytes(), "K must not alter coin bytes");
    }

    /// The chosen leading `Instrument` never changes the pushed bytes
    /// either -- Dice/Coins/Both over the SAME keystream yield identical
    /// staging (§2.3: layout gating only).
    #[test]
    fn instrument_choice_never_changes_the_pushed_bytes() {
        let keystream = || {
            let mut v = std::vec![MenuKey::Char('3'), MenuKey::Char('h'), MenuKey::Char('t'), MenuKey::Char('5')];
            for _ in 0..50 {
                v.push(MenuKey::Char('6'));
            }
            v.push(MenuKey::Enter);
            v
        };
        let run = |instr: Instrument| {
            let mut term = MockTerminal::new();
            let mut keys = ScriptedMenuKeys::new(keystream());
            let mut session = PhysicalSession::new();
            let mut staging = PhysicalStaging::new();
            let outcome =
                run_physical_entry(&mut term, &mut keys, &mut session, &mut staging, TargetBits::Bits128, instr);
            assert_eq!(outcome, PhysicalEntryOutcome::BudgetMet);
            (std::vec::Vec::from(staging.dice_bytes()), std::vec::Vec::from(staging.coin_bytes()))
        };
        let dice = run(Instrument::Dice);
        let coins = run(Instrument::Coins);
        let both = run(Instrument::Both);
        assert_eq!(dice, coins);
        assert_eq!(coins, both);
    }
}
