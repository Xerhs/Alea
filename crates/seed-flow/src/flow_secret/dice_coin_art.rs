//! SPEC_DICE_COIN_ART.md §3/§8: dice/coin text-art rendered on the
//! pre-secret `TextOutput` seam during physical entropy collection.
//!
//! Presentation-only: this module reads nothing from
//! `seed_protocol::physical::PhysicalSession`/`PhysicalStaging` beyond the
//! single `PhysicalEvent` value passed in by the caller, adds no new
//! state, and makes no protocol change (SPEC_DICE_COIN_ART.md §5). It is
//! deliberately independent of `PhysicalSession` construction so it can be
//! unit-tested in isolation (SPEC_DICE_COIN_ART.md §8).

use core::fmt::Write as _;

use crate::output::{LineBuf, TextOutput};
use seed_protocol::physical::{CoinFace, PhysicalEvent};

/// The six pip-grid die faces, `[face - 1]`, each a fixed 9-column,
/// 5-row ASCII block (SPEC_DICE_COIN_ART.md §3.1, verbatim).
pub const DIE_FACE_ART: [[&str; 5]; 6] = [
    // 1
    [
        "+-------+",
        "|       |",
        "|   o   |",
        "|       |",
        "+-------+",
    ],
    // 2
    [
        "+-------+",
        "| o     |",
        "|       |",
        "|     o |",
        "+-------+",
    ],
    // 3
    [
        "+-------+",
        "| o     |",
        "|   o   |",
        "|     o |",
        "+-------+",
    ],
    // 4
    [
        "+-------+",
        "| o   o |",
        "|       |",
        "| o   o |",
        "+-------+",
    ],
    // 5
    [
        "+-------+",
        "| o   o |",
        "|   o   |",
        "| o   o |",
        "+-------+",
    ],
    // 6
    [
        "+-------+",
        "| o   o |",
        "| o   o |",
        "| o   o |",
        "+-------+",
    ],
];

/// The HEADS coin face, a fixed 9-column, 5-row ASCII block
/// (SPEC_DICE_COIN_ART.md §3.2, verbatim).
pub const COIN_HEADS_ART: [&str; 5] = [
    " ,-----, ",
    "/       \\",
    "|   H   |",
    "\\       /",
    " '-----' ",
];

/// The TAILS coin face, a fixed 9-column, 5-row ASCII block
/// (SPEC_DICE_COIN_ART.md §3.2, verbatim).
pub const COIN_TAILS_ART: [&str; 5] = [
    " ,-----, ",
    "/       \\",
    "|   T   |",
    "\\       /",
    " '-----' ",
];

/// Compact 3x3 pip tiles for the SPEC_DICE_COIN_VISUAL.md §3.2 history
/// strip, `[face - 1]`. Each is 3 rows of exactly 3 characters: `.` = an
/// unlit cell, `o` = a pip, in the same top/middle/bottom-row pip
/// convention as [`DIE_FACE_ART`] (SPEC_DICE_COIN_VISUAL.md §3.2). Small
/// enough to draw hundreds of, unlike the full 9x5 face.
pub const DIE_TILE_3X3: [[&str; 3]; 6] = [
    ["...", ".o.", "..."], // 1
    ["o..", "...", "..o"], // 2
    ["o..", ".o.", "..o"], // 3
    ["o.o", "...", "o.o"], // 4
    ["o.o", ".o.", "o.o"], // 5
    ["o.o", "o.o", "o.o"], // 6
];

/// Compact 3-row heads coin tile for the §4.2 strip, pinned to the same
/// 3-row height as the dice tiles (SPEC_DICE_COIN_VISUAL.md §4.2/M4): row
/// 0 is blank top padding, row 1 is `(H)`, row 2 is the bare letter.
pub const COIN_TILE_HEADS_3ROW: [&str; 3] = ["   ", "(H)", " H "];

/// Compact 3-row tails coin tile (see [`COIN_TILE_HEADS_3ROW`]).
pub const COIN_TILE_TAILS_3ROW: [&str; 3] = ["   ", "(T)", " T "];

/// SPEC_DICE_COIN_VISUAL.md §3.1 always-on dice picker: the six faces in a
/// row followed by their bracketed key labels. This is the existing
/// [`write_legend`] dice row, factored out and *promoted from an on-demand
/// legend to an always-present picker* (§3.1/S2). Emits 6 lines (5 art
/// rows + the `[1]`..`[6]` label row); the caller emits the prompt above
/// it. Fixed-layout art -- never routed through `wrap_words` (§7.5).
pub fn write_dice_picker(out: &mut dyn TextOutput) {
    for row in 0..5 {
        let mut line = LineBuf::new();
        for (face, block) in DIE_FACE_ART.iter().enumerate() {
            if face > 0 {
                let _ = write!(line, " ");
            }
            let _ = write!(line, "{}", block[row]);
        }
        out.write_line(line.as_str());
    }
    out.write_line("   [1]       [2]       [3]       [4]       [5]       [6]");
}

/// SPEC_DICE_COIN_VISUAL.md §4.1 always-on coin picker: heads and tails
/// side by side with their bracketed key labels. Subsumes the old `[L]`
/// legend on the coin screen (§4.1/S2). Emits 6 lines.
pub fn write_coin_picker(out: &mut dyn TextOutput) {
    out.write_line(" ,-----,    ,-----,");
    out.write_line("/       \\  /       \\");
    out.write_line("|   H   |  |   T   |");
    out.write_line("\\       /  \\       /");
    out.write_line(" '-----'    '-----'");
    out.write_line("  [H]         [T]");
}

/// Emits the "Last entered -- ..." label line followed by the five art
/// lines for `event`, via `out.write_line` (SPEC_DICE_COIN_ART.md §4.2).
///
/// Self-contained: takes the already-known most-recent
/// `seed_protocol::physical::PhysicalEvent` directly, so no
/// `PhysicalSession`/`PhysicalStaging` construction is needed to call or
/// test this function.
pub fn write_last_entered(out: &mut dyn TextOutput, event: PhysicalEvent) {
    match event {
        PhysicalEvent::Roll(value) => {
            let mut label = LineBuf::new();
            let _ = write!(label, "Last entered -- roll of {value}:");
            out.write_line(label.as_str());
            let art = &DIE_FACE_ART[(value.saturating_sub(1).min(5)) as usize];
            for line in art {
                out.write_line(line);
            }
        }
        PhysicalEvent::Flip(face) => match face {
            CoinFace::Heads => {
                out.write_line("Last entered -- flip of heads:");
                for line in &COIN_HEADS_ART {
                    out.write_line(line);
                }
            }
            CoinFace::Tails => {
                out.write_line("Last entered -- flip of tails:");
                for line in &COIN_TAILS_ART {
                    out.write_line(line);
                }
            }
        },
    }
}

/// Emits the §4.3 on-demand legend screen: all six die faces followed by
/// both coin sides, each with a centered label under its block
/// (SPEC_DICE_COIN_ART.md §4.3, verbatim layout).
pub fn write_legend(out: &mut dyn TextOutput) {
    out.write_line("Physical entropy -- dice and coin reference");
    out.write_line("");
    for row in 0..5 {
        let mut line = LineBuf::new();
        for (face, block) in DIE_FACE_ART.iter().enumerate() {
            if face > 0 {
                let _ = write!(line, " ");
            }
            let _ = write!(line, "{}", block[row]);
        }
        out.write_line(line.as_str());
    }
    out.write_line("   1         2         3         4         5         6");
    out.write_line("");
    // The coin pair in the legend (SPEC_DICE_COIN_ART.md §4.3) is quoted
    // verbatim here rather than composed from `COIN_HEADS_ART`/
    // `COIN_TAILS_ART`: the legend's two-coin spacing is not a uniform
    // "block + fixed gap + block" layout (unlike the six-die row above),
    // so the individual §3.2 9-column single-coin blocks are not reused
    // byte-for-byte in this wider paired layout.
    out.write_line(" ,-----,    ,-----,");
    out.write_line("/       \\  /       \\");
    out.write_line("|   H   |  |   T   |");
    out.write_line("\\       /  \\       /");
    out.write_line(" '-----'    '-----'");
    out.write_line(" HEADS       TAILS");
    out.write_line("");
    out.write_line("[Enter] or any other key: back to dice/coin entry");
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::output::test_support::MockTerminal;

    #[test]
    fn die_face_art_matches_spec_exactly_for_all_six_faces() {
        assert_eq!(
            DIE_FACE_ART[0],
            ["+-------+", "|       |", "|   o   |", "|       |", "+-------+"]
        );
        assert_eq!(
            DIE_FACE_ART[1],
            ["+-------+", "| o     |", "|       |", "|     o |", "+-------+"]
        );
        assert_eq!(
            DIE_FACE_ART[2],
            ["+-------+", "| o     |", "|   o   |", "|     o |", "+-------+"]
        );
        assert_eq!(
            DIE_FACE_ART[3],
            ["+-------+", "| o   o |", "|       |", "| o   o |", "+-------+"]
        );
        assert_eq!(
            DIE_FACE_ART[4],
            ["+-------+", "| o   o |", "|   o   |", "| o   o |", "+-------+"]
        );
        assert_eq!(
            DIE_FACE_ART[5],
            ["+-------+", "| o   o |", "| o   o |", "| o   o |", "+-------+"]
        );
    }

    #[test]
    fn coin_art_matches_spec_exactly() {
        assert_eq!(
            COIN_HEADS_ART,
            [" ,-----, ", "/       \\", "|   H   |", "\\       /", " '-----' "]
        );
        assert_eq!(
            COIN_TAILS_ART,
            [" ,-----, ", "/       \\", "|   T   |", "\\       /", " '-----' "]
        );
    }

    #[test]
    fn every_die_face_block_is_nine_columns_five_rows() {
        for face in &DIE_FACE_ART {
            assert_eq!(face.len(), 5);
            for line in face {
                assert_eq!(line.len(), 9);
            }
        }
    }

    #[test]
    fn every_coin_block_is_nine_columns_five_rows() {
        for line in &COIN_HEADS_ART {
            assert_eq!(line.len(), 9);
        }
        for line in &COIN_TAILS_ART {
            assert_eq!(line.len(), 9);
        }
        assert_eq!(COIN_HEADS_ART.len(), 5);
        assert_eq!(COIN_TAILS_ART.len(), 5);
    }

    #[test]
    fn write_last_entered_roll_emits_label_then_exact_art() {
        for value in 1u8..=6 {
            let mut term = MockTerminal::new();
            write_last_entered(&mut term, PhysicalEvent::Roll(value));
            let screen = term.current_screen();
            assert_eq!(screen.len(), 6);
            assert_eq!(
                screen[0],
                std::format!("Last entered -- roll of {}:", value)
            );
            for i in 0..5 {
                assert_eq!(screen[1 + i], DIE_FACE_ART[(value - 1) as usize][i]);
            }
        }
    }

    #[test]
    fn write_last_entered_flip_heads_emits_label_then_exact_art() {
        let mut term = MockTerminal::new();
        write_last_entered(&mut term, PhysicalEvent::Flip(CoinFace::Heads));
        let screen = term.current_screen();
        assert_eq!(screen.len(), 6);
        assert_eq!(screen[0], "Last entered -- flip of heads:");
        for i in 0..5 {
            assert_eq!(screen[1 + i], COIN_HEADS_ART[i]);
        }
    }

    #[test]
    fn write_last_entered_flip_tails_emits_label_then_exact_art() {
        let mut term = MockTerminal::new();
        write_last_entered(&mut term, PhysicalEvent::Flip(CoinFace::Tails));
        let screen = term.current_screen();
        assert_eq!(screen.len(), 6);
        assert_eq!(screen[0], "Last entered -- flip of tails:");
        for i in 0..5 {
            assert_eq!(screen[1 + i], COIN_TAILS_ART[i]);
        }
    }

    #[test]
    fn write_legend_emits_exact_content() {
        let mut term = MockTerminal::new();
        write_legend(&mut term);
        let screen = term.current_screen();
        let expected: std::vec::Vec<&str> = std::vec![
            "Physical entropy -- dice and coin reference",
            "",
            "+-------+ +-------+ +-------+ +-------+ +-------+ +-------+",
            "|       | | o     | | o     | | o   o | | o   o | | o   o |",
            "|   o   | |       | |   o   | |       | |   o   | | o   o |",
            "|       | |     o | |     o | | o   o | | o   o | | o   o |",
            "+-------+ +-------+ +-------+ +-------+ +-------+ +-------+",
            "   1         2         3         4         5         6",
            "",
            " ,-----,    ,-----,",
            "/       \\  /       \\",
            "|   H   |  |   T   |",
            "\\       /  \\       /",
            " '-----'    '-----'",
            " HEADS       TAILS",
            "",
            "[Enter] or any other key: back to dice/coin entry",
        ];
        assert_eq!(screen, expected);
    }

    #[test]
    fn write_legend_row_width_is_within_80_columns() {
        let mut term = MockTerminal::new();
        write_legend(&mut term);
        for line in term.current_screen() {
            assert!(line.len() <= 80, "line exceeds 80 cols: {:?}", line);
        }
    }

    // ---- SPEC_DICE_COIN_VISUAL.md §3.2/§4.2: compact strip tiles ----

    #[test]
    fn every_die_tile_is_three_columns_three_rows() {
        for tile in &DIE_TILE_3X3 {
            assert_eq!(tile.len(), 3);
            for row in tile {
                assert_eq!(row.len(), 3, "die tile row must be 3 cols: {row:?}");
                assert!(row.bytes().all(|b| b == b'.' || b == b'o'), "only '.'/'o' cells: {row:?}");
            }
        }
    }

    #[test]
    fn every_coin_tile_is_three_columns_three_rows_top_padded() {
        for tile in [&COIN_TILE_HEADS_3ROW, &COIN_TILE_TAILS_3ROW] {
            assert_eq!(tile.len(), 3);
            for row in tile {
                assert_eq!(row.len(), 3, "coin tile row must be 3 cols: {row:?}");
            }
            assert_eq!(tile[0], "   ", "row 0 of a coin tile is blank top padding (M4)");
        }
        assert_eq!(COIN_TILE_HEADS_3ROW[1], "(H)");
        assert_eq!(COIN_TILE_TAILS_3ROW[1], "(T)");
    }

    #[test]
    fn die_tile_pip_counts_match_the_face_value() {
        for (i, tile) in DIE_TILE_3X3.iter().enumerate() {
            let pips = tile.iter().flat_map(|r| r.bytes()).filter(|&b| b == b'o').count();
            assert_eq!(pips, i + 1, "face {} tile must have {} pips", i + 1, i + 1);
        }
    }

    #[test]
    fn write_dice_picker_emits_the_six_face_row_and_bracketed_labels() {
        let mut term = MockTerminal::new();
        write_dice_picker(&mut term);
        let screen = term.current_screen();
        assert_eq!(screen.len(), 6, "5 art rows + 1 label row");
        assert_eq!(screen[0], "+-------+ +-------+ +-------+ +-------+ +-------+ +-------+");
        assert_eq!(screen[5], "   [1]       [2]       [3]       [4]       [5]       [6]");
        for line in &screen {
            assert!(line.len() <= 79, "picker line exceeds 79 cols: {line:?}");
        }
    }

    #[test]
    fn write_coin_picker_emits_both_sides_and_bracketed_labels() {
        let mut term = MockTerminal::new();
        write_coin_picker(&mut term);
        let screen = term.current_screen();
        assert_eq!(screen.len(), 6);
        assert!(screen[2].contains("H") && screen[2].contains("T"));
        assert_eq!(screen[5], "  [H]         [T]");
        for line in &screen {
            assert!(line.len() <= 79, "coin picker line exceeds 79 cols: {line:?}");
        }
    }
}
