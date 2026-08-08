# Desktop rehearsal edition — UX notes (UX-POLISH)

Scope: this file is owned by UX-POLISH. It documents (1) what was changed
inside `crates/seed-desktop-test/` (the only source this work package may
edit) and (2) concrete, non-binding recommendations for the *shared*
`seed-flow` screen code (`crates/seed-flow/src/flow_secret/`,
`crates/seed-flow/src/`), which UX-POLISH does **not** own and
therefore never edited. Nothing below changes, or asks anyone to change,
any SPEC-mandated exact wording, the fixed-layout/no-scroll rules, or the
no-secret-export rules.

## Baseline: what was already solid before this pass

Before making any change, every interactive screen in the desktop
rehearsal was read end to end (`crates/seed-desktop-test/`, and the
reused `seed-flow` screens it calls). The existing implementation already
satisfies nearly everything in the UX-POLISH brief:

- **Key hints on every screen.** `[1-6]`/`[H]/[T]` (physical entry),
  `[Backspace]`/`[C]` (undo/clear), `[Enter]`/`[Esc]` (opening warning,
  confirmations), `[H]`/`[D]` (mnemonic display), `[S]` (verification
  skip), `[1]`/`[2]`/`[3]` (mismatch choice) are all already drawn as
  part of their screens (`seed-flow`'s `physical.rs`, `display.rs`,
  `verification.rs`, `reentry.rs`, `confirm.rs`).
- **Live dice/coin/bit-progress feedback.** `physical::render_physical_screen`
  already shows `Progress: N of minimum M bits (recommended R)` and
  `Rolls: N   Flips: N`, recomputed every keystroke.
- **Undo affordance + confirmation.** `[Backspace]` undoes the last
  physical event; `[C]` clear requires a `[Enter] Confirm / [N] Cancel`
  step (`CLEAR_CONFIRM_LINE`) before anything is wiped.
- **Non-echo dots during re-entry.** `reentry::render_word_prompt` already
  renders a growing run of `*` placeholders and never the typed letters
  (regression-tested by `never_echoes_letters_to_the_framebuffer_only_dot_count_changes`).
- **Permanent, unmissable, non-obscuring watermark.** `crate::window::present_frame`
  composites two high-contrast (`fg 0xFFFF00` on `bg 0x400000`) bands
  above and below the ceremony's own canvas on *every* frame, after the
  ceremony's own drawing — so it survives every screen transition and
  scrub, and never overlaps ceremony content.
- **Readable spacing/contrast.** Every desktop-rendered text screen uses
  `fg 0xFFFFFF` on `bg 0x000000` (maximum contrast) with margin/line
  pitch derived from the embedded font's own glyph metrics
  (`crate::shared_screen::{MARGIN_X, LINE_PITCH}`, mirroring `seed-flow`'s
  own `gop_screen` constants) — reviewed and left unchanged; there was no
  legibility gap to fix.

Because of this, UX-POLISH's actual changes are small and additive.

## Changes made in this pass (`crates/seed-desktop-test/`)

1. **First-run "safe rehearsal" welcome screen** — `src/ceremony.rs`,
   `WELCOME_LINES` / `render_welcome`. Shown exactly once, before
   `seed_flow::run_pre_secret_flow` draws the real SPEC §22.1 opening
   warning. States plainly, in this crate's own words (never a
   restatement of SPEC-owned wording — checked by
   `welcome_screen_does_not_duplicate_the_spec_opening_warning_wording`),
   that this is a safe practice run backed only by a fixed public test
   vector, and gives one consolidated legend of every key convention used
   later (`1-6`, `H`/`T`, `Enter`, `Backspace`, `Esc`, `H`/`D`/`S`), so a
   first-time user has already seen the whole vocabulary once before
   meeting it piecemeal on later screens. Four new unit tests cover
   content, the anti-duplication guarantee, and the clear-before-draw
   behavior.
2. **CLI ergonomics for unrecognized arguments** — `src/main.rs`. The
   argument handling was refactored into a pure `classify(&args) ->
   Action` function (`OpenWindow` / `Check` / `Help` /
   `Unrecognized(String)`), so it's host-testable without touching
   `std::process::exit` or a real window. Behavior change: previously any
   argument other than `check` fell through to silently opening the GUI
   window (surprising on a headless host, and a bad failure mode for a
   typo like `chekc`). Now `--help`/`-h`/`help` print a short usage
   message, and any other unrecognized argument prints the same usage to
   stderr and exits `2` instead of guessing what the user meant. `check`
   and the no-argument (open window) paths are byte-for-byte unchanged.
3. No changes to `window.rs`/`shared_screen.rs` — both reviewed against
   the brief's watermark/contrast/spacing points and already met them
   (see Baseline above); changing working, already-correct rendering
   code for its own sake was judged higher risk than benefit.

Every change lives inside this work package's own files
(`crates/seed-desktop-test/src/{ceremony,main}.rs`); no shared
`seed-flow` file was touched.

## Recommendations for `seed-flow` (not owned by UX-POLISH — for the owning WP to consider)

These are suggestions only. None is a SPEC MUST; none proposes to change
SPEC-mandated exact wording. Filed here per the UX-POLISH brief instead
of edited directly, since `crates/seed-flow/` is out of scope
for this work package.

1. **Physical-entry screen is missing the "Last ten events" line from the
   SPEC §17.4 mockup.** `seed_flow::flow_secret::physical::render_physical_screen`
   currently renders title, progress, roll/flip counts, and the key
   hints, but never the per-event history line the SPEC §17.4 mockup
   shows (`Last ten events: 4 H T 2 6 T H H 1 T`). SPEC §17.4 uses "The
   screen may show", so this is optional, not a gap against a MUST — but
   it is real, concrete, live feedback a user can otherwise only infer
   from the roll/flip counters, and the mockup already establishes the
   exact format. `PhysicalStaging` already retains every pushed byte
   (`dice_bytes()`/`coin_bytes()` in entry order), so rendering the last
   ~10 in combined chronological order would need staging to also record
   *interleaving* order (today dice and coin bytes are two separate
   arrays; the last-N-events line needs one merged, chronologically
   ordered view) — a small addition to `PhysicalStaging`, not a
   redesign.
2. **Hidden re-entry prompt could pre-render its 4 dot placeholders before
   any character is typed.** `reentry::render_word_prompt` currently
   shows `Type the first four letters, then Enter: ` followed by 0-4
   `*` characters that appear only as the user types. Rendering all 4
   slots as an empty/neutral placeholder glyph (e.g. `----`) from the
   very first frame of each word would make the "exactly four
   characters, no more" budget visible before typing starts, rather than
   only becoming apparent once the user hits it. Cosmetic only — no
   change to what is or isn't echoed.
3. **Optional color-coding of dice vs. coin events**, if recommendation 1
   above is adopted: `Framebuffer`/`Style` already carries a per-glyph
   foreground/background pair, so a "Last ten events" line could render
   dice digits and coin letters in two fixed, high-contrast colors purely
   for at-a-glance scanability. Not necessary for correctness; a "nice to
   have" alongside recommendation 1, not a standalone one.

None of the above touches secret-bearing render paths differently than
today (the arena/scrub/no-concatenated-string discipline in
`seed-flow`'s existing code is unaffected either way), and none changes
any SPEC blockquote's exact wording.

## Verification performed

- `cargo build -p seed-desktop-test`: clean.
- `cargo test -p seed-desktop-test`: 32/32 passed (24 pre-existing + 8
  new: 4 in `ceremony::tests`, 4 in `main::tests`), including the
  `guardrails` real-entropy-API structural scan (still passes unchanged)
  and every existing screen/pipeline/vector test.
- `cargo run -p seed-desktop-test -- check`: still reports `23 case(s)
  checked, 23 passed, 0 failed` against `tests/vectors/frozen/`
  (byte-for-byte unchanged from the pre-change baseline run).
- `cargo run -p seed-desktop-test -- --help` / `-- chekc`: manually
  exercised, output shown in the work log; typo path now exits `2` with
  a clear message instead of attempting to open a window.
