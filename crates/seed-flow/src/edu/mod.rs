//! SPEC_MAIN_MENU.md §17.3 item 3 (Learn) + SPEC.md §34: the shared,
//! backend-neutral education content for the read-only Learn screen, held
//! as fixed `&'static str` page data with a single line-oriented
//! [`render_page`] emitter over the pre-secret [`crate::output::TextOutput`]
//! seam.
//!
//! # Why this lives in `seed-flow`, not in an edition crate
//!
//! `seed-uefi-production` is `#![no_std]` with NO `alloc`. This module is
//! therefore allocation-free by construction: every page is a fixed slice
//! of `&'static str` rows, and [`render_page`] only ever hands those
//! borrowed slices to `write_line` -- no `format!`, `String` or `Vec`
//! anywhere. Holding the data here (rather than in the production
//! launcher) keeps it host-testable in `seed-flow`'s ordinary `std` test
//! harness and reusable by any edition, exactly like
//! [`crate::flow_secret::composition`]'s `EDU_*` constants.
//!
//! # Relationship to `seed-desktop-test`'s `launcher/learn.rs`
//!
//! This is a focused PORT of that desktop module's plain-language content
//! (its `TOPIC_PAGES` + `FEATURE_PAGES`), NOT a dependency on it (SPEC §9/
//! §28 forbid `seed-uefi-production` from pulling `seed-desktop-test`,
//! `SharedFramebuffer`, `ChannelKeys`, `Vec<String>` or `format!`). Three
//! adaptations were made for the production edition:
//!
//! 1. The desktop "this is a REHEARSAL / fixed public test vector"
//!    paragraph is FALSE for the production build (which mints real,
//!    funds-bearing entropy) and is reworded accordingly on the "What Alea
//!    does" page.
//! 2. The desktop page-1 reference to a "composition-panel demo later in
//!    this menu" is retargeted to the composition panel shown before
//!    generation, since the two live demos are not ported here.
//! 3. Page titles use plain-ASCII "SPEC 34.x" instead of the desktop's
//!    `\u{a7}` (§) glyph: the GOP bitmap font renders only 0x20..=0x7E, so
//!    every byte on every Learn page is printable ASCII.
//!
//! # Fixed-layout discipline (SPEC §11.4 800x600 floor)
//!
//! `seed_gop_ui::font::draw_text` CLIPS (never wraps) past the framebuffer
//! edge, so each row here is pre-fit: <= 80 columns wide (well inside the
//! 96-column floor budget, `seed_gop_ui::layout::MAX_COLS_AT_FLOOR`) and
//! emitted DIRECTLY (never through a word-wrapper, which would corrupt the
//! indented/aligned rows). Each page's body is also short enough that the
//! caller's 5 chrome lines ("Learn", title, blank, blank, footer) plus the
//! body fit the 23-line floor budget
//! (`seed_gop_ui::layout::MAX_LINES_AT_FLOOR`) with no in-page scrolling --
//! the fit-audit unit tests below pin both invariants. (Deliberately
//! worded without the literal `cfg` test-attribute text: the leakage
//! suite's `support::split_non_test_code` finds the FIRST occurrence of
//! that literal string in a file to split production code from test
//! code, and this doc comment sits well before this file's real
//! `#[cfg(test)] mod tests` block — see that helper's own doc comment
//! and `tests/leakage/tests/support/mod.rs` for the limitation this
//! phrasing works around.)

use core::fmt::Write as _;

use crate::output::{LineBuf, TextOutput};

/// One read-only Learn page: a title and a fixed set of pre-fit body
/// rows. Mirrors `seed-desktop-test`'s `TopicPage`, but owned here and
/// free of any desktop-only dependency.
pub struct EduPage {
    /// One-line page title (plain ASCII).
    pub title: &'static str,
    /// Pre-fit body rows, emitted verbatim in order (blank string = blank
    /// line).
    pub body: &'static [&'static str],
}

/// The ported Learn pages, in reading order: the twelve SPEC §34
/// plain-language topic pages followed by the five post-§34 per-feature
/// explainers (dice/coin visual entry, `[M]` derivation options, `[B]`
/// custom-path builder, cross-device verification + entropy encodings, and
/// the offline web edition). See the module doc comment for what is
/// deliberately NOT ported (the two live demos and the technical
/// appendix).
pub const LEARN_PAGES: &[EduPage] = &[
    EduPage {
        title: "What is entropy?",
        body: &[
            "Entropy is unpredictability: the raw randomness a wallet's",
            "keys are built from. More entropy means an attacker has to",
            "guess from a bigger space of equally likely secrets.",
            "",
            "Alea gathers entropy from things you do (dice rolls, coin",
            "flips) and, optionally, things the machine offers (EFI RNG,",
            "the CPU's hardware seed instruction). Some of that is",
            "COUNTED toward your target strength; some is only CLAIMED --",
            "the composition panel shown before generation draws the",
            "exact distinction.",
        ],
    },
    EduPage {
        title: "What hardware wallets & signers do",
        body: &[
            "A hardware wallet or signer holds a private key (derived",
            "from your recovery phrase) and uses it to sign transactions",
            "without ever exposing that key to a general-purpose computer.",
            "",
            "It cannot invent a phrase's security by itself -- the",
            "phrase's strength comes entirely from the entropy it was",
            "built from. A signer that displays or reproduces a phrase",
            "you generated elsewhere (a \"cross-device verification\") is",
            "checking its own math against yours, not vouching for it.",
        ],
    },
    EduPage {
        title: "What Alea does",
        body: &[
            "Alea generates a BIP39 recovery phrase offline, from",
            "entropy you can see being collected, and lets you verify it",
            "was re-entered correctly before trusting it. Nothing here",
            "protects you from a compromised machine, malicious firmware,",
            "or a bad choice of what to do with the phrase afterward --",
            "see \"UEFI trust\" and \"Machine randomness\" below for the",
            "honest limits of what an on-screen ceremony can prove.",
            "",
            "This is the production edition: the phrase it generates is",
            "real and security-critical. Guard it accordingly.",
        ],
    },
    EduPage {
        title: "BIP39 (SPEC 34.1)",
        body: &[
            "BIP39 turns raw entropy plus a checksum into a numbered list",
            "of words from a fixed 2048-word list -- the mnemonic. A",
            "wallet then stretches that mnemonic into a longer seed, and",
            "derives many keys from it along standard paths.",
            "",
            "The phrase alone does not fully describe a wallet: the",
            "derivation path and script type also matter, and two",
            "wallets can read the same phrase differently.",
        ],
    },
    EduPage {
        title: "UEFI trust (SPEC 34.2)",
        body: &[
            "During the real ceremony the normal OS is absent, but",
            "firmware itself stays active and still handles your",
            "keyboard, including the hidden re-entry step.",
            "",
            "Rendering through the graphics framebuffer reduces ordinary",
            "console-mirroring risk, but it does not defeat malicious",
            "firmware or remote-management hardware, and the machine is",
            "not a secure element. Pre-boot DMA protections may also be",
            "weaker than a fully hardened running OS.",
        ],
    },
    EduPage {
        title: "Machine randomness (SPEC 34.3)",
        body: &[
            "Machine sources include the EFI RNG protocol and the CPU's",
            "hardware seed instruction; a related, weaker CPU instruction",
            "is used only as a supplementary signal, never counted alone.",
            "",
            "CPUs and firmware can have errata. A health check can catch",
            "an obviously broken source, but it is not a proof of",
            "quality, and there is no guarantee two machine sources are",
            "truly independent of each other -- which is why machine-only",
            "mode is the one mode this ceremony cannot let you witness.",
        ],
    },
    EduPage {
        title: "Dice and coins (SPEC 34.4)",
        body: &[
            "Every physical roll and flip is hashed into a transcript;",
            "Alea does not claim information-theoretic exactness, only",
            "that the transcript matches what you entered.",
            "",
            "Fairness and independence between rolls/flips still matter,",
            "which is why there are recommended entropy-budget margins.",
            "Choosing to \"feel random\" is not the same as being random --",
            "and physical entropy, however good, still cannot defeat",
            "malicious firmware on its own.",
        ],
    },
    EduPage {
        title: "Re-entry verification (SPEC 34.5)",
        body: &[
            "Alea does not use multiple-choice word verification. Hidden",
            "re-entry -- typing the phrase back with nothing echoed --",
            "proves you can reproduce the exact words the ceremony",
            "displayed, on this device, right now.",
            "",
            "It does NOT prove you wrote it down correctly on paper, or",
            "that a different signing device will read it the same way.",
            "Restoring on the actual intended signing device is still",
            "necessary before you trust a backup.",
        ],
    },
    EduPage {
        title: "Derivation verification (SPEC 34.6)",
        body: &[
            "The master fingerprint and the four address standards are",
            "cheap, non-secret checks that a signing device derived the",
            "same wallet from the same phrase.",
            "",
            "Matching values are reassuring; a mismatch means STOP -- it",
            "usually points to a wrong passphrase, a wrong derivation",
            "path, or a faulty or malicious device. These values affect",
            "privacy (they can be linked to your wallet) but are not",
            "themselves secret keys.",
        ],
    },
    EduPage {
        title: "Backup security (SPEC 34.7)",
        body: &[
            "Paper is cheap but burns and soaks; metal survives fire and",
            "water but costs more. Either can be stolen, so consider",
            "geographic separation of copies.",
            "",
            "Never photograph a phrase or let it sync to any cloud",
            "service. Plan for inheritance -- someone else may need to",
            "find and use it. Periodically test that a backup actually",
            "restores, including any derivation path and wallet metadata",
            "it depends on.",
        ],
    },
    EduPage {
        title: "BIP39 passphrases (SPEC 34.8)",
        body: &[
            "Alea IMPLEMENTS an OPTIONAL BIP39 passphrase (the \"25th",
            "word\"), offered once after you re-enter the phrase. Skip it",
            "and generation is byte-for-byte the empty-passphrase",
            "behavior. Every distinct passphrase derives a COMPLETELY",
            "DIFFERENT wallet from the same words.",
            "",
            "To guard against a typo, Alea makes you enter the passphrase",
            "TWICE and both copies must match before it derives. BIP39 has",
            "no passphrase checksum, though: one you misremember still",
            "yields another valid-looking wallet.",
            "",
            "It is printable-ASCII only and is never shown on screen. A",
            "forgotten passphrase loses access just like losing the words,",
            "so it needs its own separate backup, and it never appears in",
            "the verification values.",
        ],
    },
    EduPage {
        title: "Alternatives (SPEC 34.9)",
        body: &[
            "Generating a dice-roll seed directly on a dedicated signing",
            "device is a reasonable alternative with different trade-",
            "offs: less on-screen education, but a smaller, more",
            "purpose-built piece of software handling your entropy end",
            "to end.",
            "",
            "Alea does not disparage that choice. Pick the tool whose",
            "trade-offs you understand and trust.",
        ],
    },
    EduPage {
        title: "Dice or coins, on screen",
        body: &[
            "When you enter physical entropy you can choose dice,",
            "coins, or both -- whichever you have on hand. The",
            "screen shows a picker of all six die faces (and both",
            "coin sides); you choose the one you rolled by looking",
            "at it, instead of recalling which key to press.",
            "",
            "Each locked pick slides into a left-to-right history",
            "strip, so you can see the run of what you entered so",
            "far. This is presentation only: it does NOT change the",
            "entropy encoding, the counting, or the budget -- the",
            "same rolls and flips produce the same bytes as before.",
            "It is a friendlier face on exactly the same math.",
        ],
    },
    EduPage {
        title: "More derivation options",
        body: &[
            "One recovery phrase does not describe a single",
            "address -- it derives a whole tree of them. A",
            "derivation path is the route to one branch, written",
            "like m/84'/0'/0'/0/0.",
            "",
            "After you re-enter your phrase, press [M] for more",
            "derivation options. You can step through the four",
            "standards (BIP44, 49, 84 and 86) and adjust the",
            "account, the external/internal chain, and the address",
            "index within safe bounds -- watching the address",
            "change to match a wallet you already use.",
            "",
            "Only public values are ever shown: the addresses and",
            "the master fingerprint. No private key, seed, or",
            "extended key is displayed or leaves the device.",
        ],
    },
    EduPage {
        title: "Custom derivation path",
        body: &[
            "Some wallets live on a path outside the four standard",
            "shapes. Press [B] to build a custom path step by",
            "step -- choosing each level and a script type -- until",
            "the address on screen matches the unusual wallet you",
            "are checking.",
            "",
            "Like the grid, this is read-only: it shows a public",
            "address and the master fingerprint for the path you",
            "assemble, and never exports a key.",
            "",
            "Multisig and payment-code purposes (48', 45', 47')",
            "are blocked here: a single-signature view of a",
            "multisig path would show a misleading address, so the",
            "builder refuses them rather than mislead you.",
        ],
    },
    EduPage {
        title: "Verifying another device's seed",
        body: &[
            "Menu item [2] verifies a seed that came from ANOTHER",
            "device. It reproduces that device's own math -- for",
            "example Coldcard or SeedSigner dice and coin rules --",
            "and shows the resulting words, fingerprint and",
            "addresses so you can compare them side by side.",
            "",
            "It also offers iancoleman-style entropy encodings:",
            "Binary, Base-6, Dice, Base-10, Hex and Cards. You",
            "pick the encoding your other tool used (no autodetect)",
            "and Alea re-derives the same wallet to cross-check it.",
            "",
            "This is REPRODUCTION, never an Alea seed: it repeats",
            "someone else's result on public or throwaway",
            "material. Do not put real funds on anything a",
            "verification tool merely reproduced.",
        ],
    },
    EduPage {
        title: "The offline web edition",
        body: &[
            "Alea also has an offline web edition: a single HTML",
            "file you download, verify, take offline, and open",
            "from a local file -- the iancoleman model. It runs the",
            "very same Rust core as the other editions, compiled to",
            "run in a browser, and forbids every network path by",
            "construction (no CDN, fonts, analytics, or telemetry).",
            "",
            "Convenience costs security. It is the LOWEST rung of",
            "the trust ladder:",
            "",
            "  air-gapped USB  >  desktop  >  web",
            "",
            "A browser is a hot, untrusted environment. Treat the",
            "web edition as verification-focused: reach for it to",
            "cross-check, not as your most-trusted way to mint a",
            "seed you will guard for years.",
        ],
    },
];

/// Number of Learn pages ([`LEARN_PAGES`]). Used by the caller's paging
/// loop for the `Page N/M` footer and the last-page boundary.
#[must_use]
pub fn page_count() -> usize {
    LEARN_PAGES.len()
}

/// Render one Learn page's header, title and body to `out` (SPEC §12.1
/// line-oriented seam). Does NOT clear the screen or emit the position
/// footer -- the caller (the edition's paging loop) owns the `clear()` and
/// the footer, since footer wording is UI-specific (SPEC_MAIN_MENU.md
/// §17.2 number-key + Esc for the production launcher). `index` is clamped
/// to the last page rather than panicking on an out-of-range value.
pub fn render_page(out: &mut dyn TextOutput, index: usize) {
    if LEARN_PAGES.is_empty() {
        return;
    }
    let clamped = index.min(LEARN_PAGES.len() - 1);
    let page = &LEARN_PAGES[clamped];
    out.write_line("Learn");
    out.write_line(page.title);
    out.write_line("");
    for line in page.body {
        out.write_line(line);
    }
}

// ============================================================================
// Category landing (design doc §5: "category landing (Topics / Features /
// Technical), 'page 3/12' counters") + the Technical deep-dive appendix.
// ============================================================================

/// Number of [`LEARN_PAGES`] that are SPEC §34 plain-language topic pages
/// (the [`Category::Topics`] slice, `LEARN_PAGES[..TOPIC_PAGE_COUNT]`) --
/// the rest of [`LEARN_PAGES`] (`LEARN_PAGES[TOPIC_PAGE_COUNT..]`) are the
/// post-§34 per-feature explainers ([`Category::Features`]). Kept as one
/// named boundary rather than duplicating either slice into its own
/// array, so [`LEARN_PAGES`]'s content and order stay the single source
/// of truth for both the flat [`render_page`]/[`page_count`] API above
/// and the category-scoped API below.
const TOPIC_PAGE_COUNT: usize = 12;

/// Technical deep-dive appendix ([`Category::Technical`]) -- ported from
/// `seed-desktop-test`'s `launcher/learn.rs` `TECH_PAGES` (same titles,
/// same wording, same `[T] ` title prefix), which already shipped this
/// exact content on the desktop edition. Pure protocol arithmetic
/// (entropy bits, the transcript preimage, BIP39/BIP32 formulas, address
/// encodings) with no edition-specific wording of any kind -- unlike
/// [`LEARN_PAGES`]'s three desktop-vs-production adaptations (see the
/// module doc comment), nothing here needed to change for the production
/// edition. One layout-only adjustment WAS needed: the desktop edition
/// renders on a fixed 1024x768 canvas with room to spare, but this port
/// also has to fit the production edition's SPEC §11.4 800x600 floor
/// (`seed_gop_ui::layout::MAX_LINES_AT_FLOOR`, pinned by
/// `tests::every_page_fits_the_800x600_line_budget_with_the_callers_chrome`
/// below); two pages needed blank-spacer lines dropped to fit --
/// "Counted vs claimed entropy" (one spacer, between the `target_bits`
/// example pair and the concluding paragraph) and "The entropy
/// transcript" (four spacers, between otherwise-adjacent formula/label
/// lines that read fine run together). No word of any body line itself
/// changed, only vertical spacing. Same fixed-layout discipline as
/// [`LEARN_PAGES`] otherwise: <= 80 columns, pure printable ASCII,
/// emitted directly (never word-wrapped, which would corrupt the
/// column-aligned formulas).
const TECH_PAGES: &[EduPage] = &[
    EduPage {
        title: "[T] Entropy: bits per symbol",
        body: &[
            "Entropy is measured in bits. A source that emits one",
            "of N equally likely symbols carries, per symbol:",
            "",
            "  H = log2(N) bits",
            "",
            "A fair die (N=6) and a fair coin (N=2) give:",
            "",
            "  dice: H = log2(6) ~= 2.585 bits/roll",
            "  coin: H = log2(2)  =  1     bit/flip",
            "",
            "Alea stores these as integer milli-bits, so it needs",
            "no floating point: 2585 per roll, 1000 per flip.",
            "",
            "Total counted entropy is just the sum over events:",
            "",
            "  counted_mbits = 2585*rolls + 1000*flips",
        ],
    },
    EduPage {
        title: "[T] Counted vs claimed entropy",
        body: &[
            "Alea counts ONLY witnessed physical entropy toward",
            "your target strength: dice rolls and coin flips, the",
            "\"counted\" sources.",
            "",
            "Machine sources -- EFI RNG, rdseed, rdrand, and an",
            "optional USB TRNG -- are health-checked but not",
            "provable, so each contributes ZERO counted bits, no",
            "matter how many bytes it mixes into the transcript.",
            "",
            "Generation is gated by the SPEC 17.2 floor:",
            "",
            "  counted_mbits >= 1000 * target_bits",
            "",
            "  target_bits = 128  (12 words)",
            "  target_bits = 256  (24 words)",
            "So 128 bits needs >= 128000 milli-bits of witnessed",
            "rolls/flips; e.g. 128 rolls + 40 flips = 370880",
            "milli-bits, clearing the 256-bit floor.",
        ],
    },
    EduPage {
        title: "[T] The entropy transcript",
        body: &[
            "Every source is bound into one domain-separated",
            "preimage and reduced with SHA-256:",
            "  DOMAIN = \"Alea/Entropy/v1\" + NUL     (16 bytes)",
            "  preimage = DOMAIN",
            "    || arch_u16 || bits_u16 || policy_ver_u16",
            "    || presence_bitmap_u16 || record_count_u8",
            "    || { per source, in ascending tag order:",
            "         tag_u8 | algo_len_u8 | algo_id",
            "         | data_len_u16 | source_bytes }",
            "  final_entropy = SHA-256(preimage)",
            "",
            "All integers are big-endian. Source tags (hex):",
            "  01 EFI_RNG  02 rdseed  03 rdrand",
            "  10 DICE     11 COIN    12 USB_TRNG",
            "For a 128-bit target the leading 16 bytes of the",
            "digest are used; for 256-bit, all 32. Domain + tags",
            "keep the input unambiguous and collision-free across",
            "protocols -- the basis for auditability.",
        ],
    },
    EduPage {
        title: "[T] Mnemonic encoding (BIP39)",
        body: &[
            "The final entropy ENT is 128 or 256 bits. BIP39",
            "appends a checksum CS taken from its SHA-256 digest:",
            "",
            "  CS = SHA-256(ENT)[0 : ENT/32]     (leading bits)",
            "",
            "  128-bit:  128 + 4 = 132 = 12 * 11",
            "  256-bit:  256 + 8 = 264 = 24 * 11",
            "",
            "The bitstream (ENT || CS) is split into 11-bit",
            "groups; each group is an index 0..2047 into the",
            "fixed 2048-word English list, giving 12 or 24 words.",
            "",
            "Words are DERIVED from the entropy, never chosen",
            "independently. The embedded list's SHA-256 is",
            "self-checked against the published BIP39 digest at",
            "startup.",
        ],
    },
    EduPage {
        title: "[T] Seed stretching (BIP39)",
        body: &[
            "The words are stretched into a 64-byte seed with",
            "PBKDF2 over HMAC-SHA512, 2048 iterations:",
            "",
            "  seed = PBKDF2-HMAC-SHA512(",
            "           password = mnemonic,",
            "           salt = \"mnemonic\" || passphrase,",
            "           c = 2048, dkLen = 64 )",
            "",
            "BIP39 normalizes text as NFKD; Alea's lowercase words",
            "and its printable-ASCII passphrase are already in",
            "that normal form.",
            "",
            "An empty passphrase makes the salt exactly the bytes",
            "\"mnemonic\", byte-identical to the no-passphrase seed.",
            "Any different passphrase derives a COMPLETELY",
            "different wallet -- and BIP39 puts no checksum on it.",
        ],
    },
    EduPage {
        title: "[T] Key derivation (BIP32)",
        body: &[
            "The master key and chain code come from one more",
            "HMAC-SHA512, keyed by the ASCII string Bitcoin seed:",
            "",
            "  (k, c) = HMAC-SHA512(\"Bitcoin seed\", seed)",
            "",
            "Child keys use CKDpriv over secp256k1 (group order",
            "n). The 2^31 boundary separates hardened from normal:",
            "",
            "  hardened: I = HMAC(c, 0x00 || k_par || ser32(i))",
            "  normal:   I = HMAC(c, serP(K_par) || ser32(i))",
            "  k_i = (I_L + k_par) mod n      c_i = I_R",
            "",
            "A key is rejected if I_L >= n or k_i == 0. Alea walks",
            "the four fixed paths:",
            "",
            "  m / {44',49',84',86'} / 0' / 0' / 0 / 0",
        ],
    },
    EduPage {
        title: "[T] Addresses and fingerprint",
        body: &[
            "Each path's public key K is encoded four ways. With",
            "",
            "  HASH160(x) = RIPEMD-160(SHA-256(x))",
            "",
            "  P2PKH  : base58check(0x00 || HASH160(K))",
            "  P2SH-P2WPKH : base58check(0x05 || HASH160(",
            "             0x00 0x14 || HASH160(K)))",
            "  P2WPKH : bech32(\"bc\",  0, HASH160(K))",
            "  P2TR   : bech32m(\"bc\", 1, Q)",
            "",
            "P2TR encodes the BIP341-tweaked output key, not the",
            "raw internal x-only key P:",
            "",
            "  Q = lift_x(P) + tagged_hash(\"TapTweak\", P) * G",
            "",
            "The wallet's identity fingerprint is:",
            "",
            "  fingerprint = HASH160(master_pubkey)[0 : 4]",
        ],
    },
    EduPage {
        title: "[T] What is shown, and what is not",
        body: &[
            "Verification (SPEC 24) displays only PUBLIC values:",
            "the four addresses and the 8-hex master fingerprint.",
            "",
            "A private key, the raw entropy, the 64-byte seed, and",
            "the chain code are NEVER shown and never leave the",
            "device. Every secret buffer is scrubbed on every",
            "return path -- volatile zeroing, a compiler fence, a",
            "memory fence, and a verification read-back.",
            "",
            "Matching addresses + fingerprint on an independent",
            "signer are cheap, non-secret evidence it derived the",
            "SAME wallet. A mismatch means STOP: usually a wrong",
            "passphrase, wrong path, or a faulty device.",
        ],
    },
];

/// Learn's three top-level categories (design doc §5). A caller's
/// landing loop picks one, then pages through only that category's own
/// slice with its own relative `page N/M` counter
/// ([`category_page_count`]) -- unlike [`page_count`]/[`render_page`]'s
/// flat 17-page walk over the whole plain-language section, a category
/// counter never mixes topic/feature/technical page numbers together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    /// SPEC §34 plain-language topic pages (`LEARN_PAGES[..TOPIC_PAGE_COUNT]`).
    Topics,
    /// Post-§34 per-feature explainers (`LEARN_PAGES[TOPIC_PAGE_COUNT..]`).
    Features,
    /// The [`TECH_PAGES`] deep-dive appendix.
    Technical,
}

/// [`Category`]'s three values, in landing-menu order.
pub const CATEGORIES: [Category; 3] = [Category::Topics, Category::Features, Category::Technical];

impl Category {
    /// The landing menu's one-word label for this category.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Category::Topics => "Topics",
            Category::Features => "Features",
            Category::Technical => "Technical",
        }
    }

    /// This category's own page slice.
    #[must_use]
    pub fn pages(self) -> &'static [EduPage] {
        match self {
            Category::Topics => &LEARN_PAGES[..TOPIC_PAGE_COUNT],
            Category::Features => &LEARN_PAGES[TOPIC_PAGE_COUNT..],
            Category::Technical => TECH_PAGES,
        }
    }
}

/// Page count of `category` -- the category-scoped analogue of
/// [`page_count`], used by the caller's paging loop for that category's
/// own `page N/M` footer and last-page boundary.
#[must_use]
pub fn category_page_count(category: Category) -> usize {
    category.pages().len()
}

/// Render one page within `category` (0-based, clamped to the last page
/// rather than panicking) -- the category-scoped analogue of
/// [`render_page`]. Same shape: does NOT clear the screen or emit the
/// position footer, since footer wording (including which category is
/// open) is the caller's job.
pub fn render_category_page(out: &mut dyn TextOutput, category: Category, index: usize) {
    let pages = category.pages();
    if pages.is_empty() {
        return;
    }
    let clamped = index.min(pages.len() - 1);
    let page = &pages[clamped];
    out.write_line("Learn");
    out.write_line(page.title);
    out.write_line("");
    for line in page.body {
        out.write_line(line);
    }
}

/// Render the category-landing screen: a "Learn" header followed by one
/// row per [`CATEGORIES`] entry, numbered `[1]`.."[3]" for the caller's
/// number-key picker, with each category's own page count in
/// parentheses. Alloc-free ([`LineBuf`]/`core::fmt::Write`, no
/// `format!`/`String` -- this module ships in the `#![no_std]`, no-`alloc`
/// production edition). Content-only, exactly like [`render_page`]/
/// [`render_category_page`]: does not clear the screen or read a key.
pub fn render_category_landing(out: &mut dyn TextOutput) {
    out.write_line("Learn");
    out.write_line("");
    for (i, category) in CATEGORIES.iter().enumerate() {
        let mut line = LineBuf::new();
        let _ = write!(
            line,
            "  [{}] {}   ({} page{})",
            i + 1,
            category.label(),
            category_page_count(*category),
            if category_page_count(*category) == 1 { "" } else { "s" }
        );
        out.write_line(line.as_str());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::test_support::MockTerminal;

    /// Chrome lines the production paging loop wraps every page in:
    /// "Learn", title, blank, (body), blank, footer -- five lines that,
    /// with the body, must fit the SPEC §11.4 floor line budget.
    const CHROME_LINES: usize = 5;

    #[test]
    fn ported_the_seventeen_plain_language_pages() {
        // 12 SPEC §34 topic pages + 5 post-§34 feature explainers.
        assert_eq!(LEARN_PAGES.len(), 17);
        assert_eq!(page_count(), 17);
    }

    #[test]
    fn every_page_body_line_is_within_the_floor_width_and_pure_printable_ascii() {
        // draw_text CLIPS past the framebuffer edge, so every row must fit
        // the 96-column 800x600 floor budget; the GOP font renders only
        // 0x20..=0x7E, so every byte must be printable ASCII (a stray
        // non-ASCII byte would render as a blank cell).
        let max_cols = seed_gop_ui::layout::MAX_COLS_AT_FLOOR;
        for page in LEARN_PAGES.iter().chain(TECH_PAGES.iter()) {
            assert!(page.title.chars().count() <= max_cols, "title too wide: {:?}", page.title);
            for b in page.title.bytes() {
                assert!((0x20..=0x7E).contains(&b), "non-ASCII byte in title {:?}", page.title);
            }
            for line in page.body {
                assert!(
                    line.chars().count() <= max_cols,
                    "body line too wide ({} cols): {line:?}",
                    line.chars().count()
                );
                for b in line.bytes() {
                    assert!((0x20..=0x7E).contains(&b), "non-ASCII byte in body line {line:?}");
                }
            }
        }
    }

    #[test]
    fn every_page_fits_the_800x600_line_budget_with_the_callers_chrome() {
        // Body + the caller's 5 chrome lines must not exceed the floor's
        // 23-line budget -- no page may need in-page scrolling.
        let max_lines = seed_gop_ui::layout::MAX_LINES_AT_FLOOR;
        for page in LEARN_PAGES.iter().chain(TECH_PAGES.iter()) {
            let total = page.body.len() + CHROME_LINES;
            assert!(
                total <= max_lines,
                "page {:?} renders {total} lines, exceeds the {max_lines}-line floor budget",
                page.title
            );
        }
    }

    #[test]
    fn render_page_emits_the_learn_header_title_and_body_in_order() {
        let mut term = MockTerminal::new();
        render_page(&mut term, 0);
        assert_eq!(term.lines[0], "Learn");
        assert_eq!(term.lines[1], LEARN_PAGES[0].title);
        assert_eq!(term.lines[2], "");
        // The whole body follows, in order.
        for (i, line) in LEARN_PAGES[0].body.iter().enumerate() {
            assert_eq!(&term.lines[3 + i], line);
        }
    }

    #[test]
    fn every_page_is_reachable_by_index_and_renders_its_own_title() {
        for (i, page) in LEARN_PAGES.iter().enumerate() {
            let mut term = MockTerminal::new();
            render_page(&mut term, i);
            assert!(term.contains(page.title), "page {i} missing title {:?}", page.title);
        }
    }

    #[test]
    fn out_of_range_index_clamps_to_the_last_page_rather_than_panicking() {
        let mut term = MockTerminal::new();
        render_page(&mut term, 9999);
        let last = &LEARN_PAGES[LEARN_PAGES.len() - 1];
        assert!(term.contains(last.title));
    }

    #[test]
    fn production_edition_never_calls_itself_a_rehearsal_or_test_build() {
        // SPEC §4.1: the production content must not carry the desktop's
        // rehearsal/test-vector framing.
        for page in LEARN_PAGES.iter().chain(TECH_PAGES.iter()) {
            for line in page.body {
                let lower = line.to_ascii_lowercase();
                assert!(!lower.contains("rehearsal"), "rehearsal wording leaked: {line:?}");
                assert!(!lower.contains("test vector"), "test-vector wording leaked: {line:?}");
            }
        }
    }

    // -- Category landing (Topics / Features / Technical) --------------

    #[test]
    fn three_categories_in_landing_order() {
        assert_eq!(CATEGORIES, [Category::Topics, Category::Features, Category::Technical]);
        assert_eq!(CATEGORIES[0].label(), "Topics");
        assert_eq!(CATEGORIES[1].label(), "Features");
        assert_eq!(CATEGORIES[2].label(), "Technical");
    }

    #[test]
    fn category_page_counts_match_their_slice_and_sum_to_topics_plus_features_plus_technical() {
        assert_eq!(category_page_count(Category::Topics), TOPIC_PAGE_COUNT);
        assert_eq!(category_page_count(Category::Features), LEARN_PAGES.len() - TOPIC_PAGE_COUNT);
        assert_eq!(category_page_count(Category::Technical), TECH_PAGES.len());
        // Sanity against the flat count this replaces relative counters
        // for: Topics + Features must equal the pre-existing 17-page
        // LEARN_PAGES total exactly (content unchanged -- this is a
        // pure re-slicing, not a re-authoring).
        assert_eq!(
            category_page_count(Category::Topics) + category_page_count(Category::Features),
            LEARN_PAGES.len()
        );
    }

    #[test]
    fn topics_category_is_exactly_the_spec_34_pages_in_the_same_order() {
        let topics = Category::Topics.pages();
        assert_eq!(topics.len(), TOPIC_PAGE_COUNT);
        for (i, page) in topics.iter().enumerate() {
            assert_eq!(page.title, LEARN_PAGES[i].title);
        }
    }

    #[test]
    fn features_category_is_exactly_the_post_34_pages_in_the_same_order() {
        let features = Category::Features.pages();
        assert_eq!(features.len(), LEARN_PAGES.len() - TOPIC_PAGE_COUNT);
        for (i, page) in features.iter().enumerate() {
            assert_eq!(page.title, LEARN_PAGES[TOPIC_PAGE_COUNT + i].title);
        }
    }

    #[test]
    fn technical_category_is_the_eight_ported_tech_pages_with_the_t_title_prefix() {
        let technical = Category::Technical.pages();
        assert_eq!(technical.len(), 8);
        for page in technical {
            assert!(page.title.starts_with("[T] "), "technical page title missing [T] prefix: {:?}", page.title);
        }
    }

    #[test]
    fn render_category_page_emits_the_learn_header_title_and_body_for_each_category() {
        for category in CATEGORIES {
            let mut term = MockTerminal::new();
            render_category_page(&mut term, category, 0);
            let pages = category.pages();
            assert_eq!(term.lines[0], "Learn");
            assert_eq!(term.lines[1], pages[0].title);
            assert_eq!(term.lines[2], "");
            for (i, line) in pages[0].body.iter().enumerate() {
                assert_eq!(&term.lines[3 + i], line);
            }
        }
    }

    #[test]
    fn render_category_page_every_index_is_reachable_and_renders_its_own_title() {
        for category in CATEGORIES {
            for (i, page) in category.pages().iter().enumerate() {
                let mut term = MockTerminal::new();
                render_category_page(&mut term, category, i);
                assert!(term.contains(page.title), "{:?} page {i} missing title {:?}", category, page.title);
            }
        }
    }

    #[test]
    fn render_category_page_out_of_range_index_clamps_to_the_last_page() {
        for category in CATEGORIES {
            let mut term = MockTerminal::new();
            render_category_page(&mut term, category, 9999);
            let pages = category.pages();
            let last = &pages[pages.len() - 1];
            assert!(term.contains(last.title));
        }
    }

    #[test]
    fn render_category_landing_lists_every_category_numbered_with_its_page_count() {
        let mut term = MockTerminal::new();
        render_category_landing(&mut term);
        let joined = term.lines.join("\n");
        assert!(joined.contains("Learn"));
        assert!(joined.contains("[1] Topics"));
        assert!(joined.contains(&std::format!("({} pages)", TOPIC_PAGE_COUNT)));
        assert!(joined.contains("[2] Features"));
        assert!(joined.contains(&std::format!("({} pages)", LEARN_PAGES.len() - TOPIC_PAGE_COUNT)));
        assert!(joined.contains("[3] Technical"));
        assert!(joined.contains(&std::format!("({} pages)", TECH_PAGES.len())));
    }

    #[test]
    fn render_category_landing_fits_the_800x600_floor() {
        // Header + blank + one row per CATEGORIES entry.
        let max_lines = seed_gop_ui::layout::MAX_LINES_AT_FLOOR;
        let max_cols = seed_gop_ui::layout::MAX_COLS_AT_FLOOR;
        let mut term = MockTerminal::new();
        render_category_landing(&mut term);
        assert!(term.lines.len() <= max_lines, "landing renders {} lines, exceeds the {max_lines}-line floor budget", term.lines.len());
        for line in &term.lines {
            assert!(line.chars().count() <= max_cols, "landing line too wide: {line:?}");
        }
    }
}
