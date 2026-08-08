//! Launcher item (3) — Learn (SPEC_MAIN_MENU.md §4.1 item 3): a
//! scrollable, paginated stack of plain-language education screens
//! surfacing SPEC.md §34's topics (entropy, BIP39, what hardware wallets
//! & signers do, what Alea does and does not protect against), followed by
//! a short set of plain-language explainers for features that shipped after
//! §34 was authored (rich dice/coin visual entry, the `[M]` derivation
//! options and `[B]` custom-path builder, cross-device verification +
//! entropy encodings, and the offline web edition -- see [`FEATURE_PAGES`]),
//! plus a **read-only demo** of the `edu-ui` counted/claimed composition panel
//! (SPEC_EDU_UI §22.5a — [`seed_flow::flow_secret::composition::render_composition_panel`])
//! and the `dice-coin-art` all-faces reference screen
//! (SPEC_DICE_COIN_ART §4.3/§17.4 —
//! [`seed_flow::flow_secret::dice_coin_art::write_legend`]). Pure
//! information; returns to the launcher on `Esc` (SPEC_MAIN_MENU.md
//! §4.5). Never reachable mid-ceremony (§8 OQ4: launcher-only).
//!
//! # Page-forward/page-back key mapping
//!
//! SPEC_MAIN_MENU.md §4.1 item 3 asks for "Page Up/Down + Esc"
//! navigation. The desktop-local `KeyMsg` enum (`crate::channel_keys`,
//! SPEC_MAIN_MENU.md §4.2/§6.3, OQ2 resolved §15: "desktop-local
//! arrows") already carries exactly one pair of navigation keys wired
//! through `crate::window::translate_key` — `Up`/`Down` (`ArrowUp`/
//! `ArrowDown`) — and no separate `PageUp`/`PageDown` variant; this
//! module (which owns no key-bridge code) reuses that existing pair as
//! page-back/page-forward rather than adding a second navigation axis
//! the desktop key bridge does not carry. This is a page-*by*-page
//! reader (not per-line scroll), so "next/previous page" is exactly what
//! "Page Up/Down" means here.
//!
//! # Category landing (design doc §5)
//!
//! `run()` is two levels deep, not one flat page walk: a category
//! landing ([`render_category_landing`]) lists [`Category::Topics`] /
//! [`Category::Features`] / [`Category::Technical`] with their own page
//! counts, and picking one (a direct `[1]`/`[2]`/`[3]` number-key press,
//! [`handle_landing_key`]) enters a page loop scoped to that category
//! ([`render_category_page`]/[`category_page_count`]), reusing
//! [`handle_key`]'s existing Up/Down clamping against the category's own
//! page count. `Esc` from inside a category returns to the landing; `Esc`
//! from the landing itself returns from `run()` to the launcher (§4.5) --
//! two levels of "back" where the old flat reader had one. `Category::
//! Features` keeps the two live demo pages ([`DEMO_PAGE_COUNT`])
//! immediately after [`FEATURE_PAGES`], grouped there because both demos
//! (dice/coin art, the composition panel) demonstrate features.
//!
//! # Host-testability (SPEC_MAIN_MENU.md §6.3)
//!
//! [`handle_key`] is a pure function over [`KeyMsg`] and a page count —
//! no I/O, no `TextOutput`, no `ChannelKeys` — exercised directly by
//! `#[cfg(test)]` below, the same discipline `launcher::menu` follows.
//! [`handle_landing_key`] is the same shape for the category landing.
//! [`render_category_page`]/[`render_category_landing`] take
//! `&mut dyn TextOutput`, so every page's rendered content is asserted
//! against a recording double with no display server, matching every
//! other pre-secret screen in this codebase
//! (`seed_flow::output::TextOutput`).

use seed_core::contracts::{SourceTag, TargetBits};
use seed_flow::flow_secret::composition::{self, CompositionModel, MachineTagSet};
use seed_flow::flow_secret::dice_coin_art;
use seed_flow::output::TextOutput;
use seed_flow::text::wrap_words;

use crate::channel_keys::{ChannelKeys, KeyMsg};
use crate::shared_screen::{SharedFramebuffer, WindowTextOutput, CANVAS_WIDTH};

/// One plain-language topic page (SPEC.md §34.1-§34.9, plus three
/// introductory pages this launcher adds: "what is entropy", "what
/// hardware wallets & signers do", and "what Alea does"). Each page is
/// authored short enough to fit the fixed canvas without in-page
/// scrolling (SPEC_MAIN_MENU.md §4.7 fixed-layout discipline, mirroring
/// SPEC_EDU_UI §4.5).
struct TopicPage {
    title: &'static str,
    body: &'static [&'static str],
}

/// Introductory + SPEC §34 topic pages, in reading order. Wording is
/// plain-language paraphrase, not a verbatim SPEC quote (SPEC.md's own
/// §34 text is instructional content for documentation authors --
/// "Offline documentation MUST explain" -- not a screen string to
/// reproduce byte-for-byte the way SPEC §8.4/§18.2/§16 warnings are).
const TOPIC_PAGES: &[TopicPage] = &[
    TopicPage {
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
            "see the composition-panel demo later in this menu for the",
            "exact distinction.",
        ],
    },
    TopicPage {
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
    TopicPage {
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
            "This desktop edition is a REHEARSAL: every phrase it shows",
            "comes from a fixed public test vector, never real entropy.",
        ],
    },
    TopicPage {
        title: "BIP39 (SPEC.md \u{a7}34.1)",
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
    TopicPage {
        title: "UEFI trust (SPEC.md \u{a7}34.2)",
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
    TopicPage {
        title: "Machine randomness (SPEC.md \u{a7}34.3)",
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
    TopicPage {
        title: "Dice and coins (SPEC.md \u{a7}34.4)",
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
    TopicPage {
        title: "Re-entry verification (SPEC.md \u{a7}34.5)",
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
    TopicPage {
        title: "Derivation verification (SPEC.md \u{a7}34.6)",
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
    TopicPage {
        title: "Backup security (SPEC.md \u{a7}34.7)",
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
    TopicPage {
        title: "BIP39 passphrases (SPEC.md \u{a7}34.8)",
        body: &[
            "Alea now IMPLEMENTS an OPTIONAL BIP39 passphrase (the",
            "\"25th word\"), offered once after you re-enter the phrase.",
            "Skip it and generation is byte-for-byte today's",
            "empty-passphrase behavior. Every distinct passphrase",
            "derives a COMPLETELY DIFFERENT wallet from the same words.",
            "",
            "To guard against a typo, Alea makes you enter the",
            "passphrase TWICE and both copies must match before it",
            "derives -- so a slip while typing is caught here, not",
            "discovered later. BIP39 has no passphrase checksum, though:",
            "one you simply misremember still yields another valid-",
            "looking wallet, and a mismatch on a signing device may just",
            "mean a different passphrase was used.",
            "",
            "It is printable-ASCII only and is never shown on screen. A",
            "forgotten passphrase loses access just like losing the",
            "words, so it needs its own separate backup, and it never",
            "appears in the verification values. Those values now",
            "reflect the passphrase you entered (the on-screen caveat",
            "flips to say so); with no passphrase they assume the empty",
            "one.",
        ],
    },
    TopicPage {
        title: "Alternatives (SPEC.md \u{a7}34.9)",
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
];

/// Plain-language explainers for features that shipped AFTER the original
/// §34 topic set was authored, rendered right after [`TOPIC_PAGES`] and
/// before the two demos so the whole plain-language section reads as one
/// block. Each covers a surface a user actually meets on screen: the rich
/// dice/coin visual entry (SPEC_DICE_COIN_VISUAL), the `[M]` bounded-grid
/// derivation options and `[B]` custom-path builder shown after re-entry
/// (SPEC_DERIVATION_OPTIONS / SPEC_DERIVATION_CUSTOM), the menu-item `[2]`
/// cross-device verification + iancoleman-style entropy encodings
/// (SPEC_COMPAT / SPEC_COMPAT_ENTROPY), and the offline web edition
/// (SPEC_WEB_OFFLINE). Same fixed-layout discipline as [`TOPIC_PAGES`]:
/// short, ASCII-only, pre-fit prose. Desktop Learn reference content only;
/// no production-seed-path impact.
const FEATURE_PAGES: &[TopicPage] = &[
    TopicPage {
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
    TopicPage {
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
    TopicPage {
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
    TopicPage {
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
            "rehearsal tool merely reproduced.",
        ],
    },
    TopicPage {
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

/// The extra two read-only demo pages appended after the topic pages
/// (SPEC_MAIN_MENU.md §4.1 item 3: "read-only demos of the
/// counted/claimed panel ... and the dice/coin art").
const DEMO_PAGE_COUNT: usize = 2;

/// Technical deep-dive appendix, rendered AFTER the two demo pages as the
/// final block of the Learn reader. These pages state, precisely and with
/// the actual formulas, exactly what Alea computes from raw physical
/// events to the four displayed addresses -- the executive-technical
/// counterpart to the plain-language [`TOPIC_PAGES`]. Titles carry a
/// `[T] ` prefix so the technical block reads distinctly when paging
/// through. DESKTOP Learn reference content only: production UEFI boots
/// straight into the ceremony, so this menu has no production-seed-path
/// impact.
///
/// Every body line is pre-fit to fixed layout: the formulas are ASCII and
/// column-aligned, so they are rendered DIRECTLY (never through the demo
/// word-wrap path, which would corrupt a formula). Content is reconciled
/// against the shipping implementation cited on each page.
const TECH_PAGES: &[TopicPage] = &[
    TopicPage {
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
    TopicPage {
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
            "",
            "So 128 bits needs >= 128000 milli-bits of witnessed",
            "rolls/flips; e.g. 128 rolls + 40 flips = 370880",
            "milli-bits, clearing the 256-bit floor.",
        ],
    },
    TopicPage {
        title: "[T] The entropy transcript",
        body: &[
            "Every source is bound into one domain-separated",
            "preimage and reduced with SHA-256:",
            "",
            "  DOMAIN = \"Alea/Entropy/v1\" + NUL     (16 bytes)",
            "",
            "  preimage = DOMAIN",
            "    || arch_u16 || bits_u16 || policy_ver_u16",
            "    || presence_bitmap_u16 || record_count_u8",
            "    || { per source, in ascending tag order:",
            "         tag_u8 | algo_len_u8 | algo_id",
            "         | data_len_u16 | source_bytes }",
            "",
            "  final_entropy = SHA-256(preimage)",
            "",
            "All integers are big-endian. Source tags (hex):",
            "  01 EFI_RNG  02 rdseed  03 rdrand",
            "  10 DICE     11 COIN    12 USB_TRNG",
            "",
            "For a 128-bit target the leading 16 bytes of the",
            "digest are used; for 256-bit, all 32. Domain + tags",
            "keep the input unambiguous and collision-free across",
            "protocols -- the basis for auditability.",
        ],
    },
    TopicPage {
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
    TopicPage {
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
    TopicPage {
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
    TopicPage {
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
    TopicPage {
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

/// Learn's three top-level categories (design doc §5: "category landing
/// (Topics / Features / Technical), 'page 3/12' counters"). A landing
/// screen ([`render_category_landing`]) picks one, then a page loop scoped
/// to that category pages through only its own slice ([`category_page_count`]/
/// [`render_category_page`]) -- unlike the old flat walk over the whole
/// plain-language section, a category counter never mixes topic/feature/
/// technical page numbers together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    /// [`TOPIC_PAGES`] -- the SPEC §34 plain-language topic pages.
    Topics,
    /// [`FEATURE_PAGES`] followed by the two live-rendered demo pages
    /// (composition panel, then dice/coin art) -- kept together because
    /// both demos demonstrate features covered in this category.
    Features,
    /// [`TECH_PAGES`] -- the technical deep-dive appendix.
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
}

/// Page count of `category` -- the category-scoped analogue of the old
/// flat `total_pages()`, used by the category page loop's own `Page N/M`
/// footer and last-page clamp boundary.
#[must_use]
pub fn category_page_count(category: Category) -> usize {
    match category {
        Category::Topics => TOPIC_PAGES.len(),
        Category::Features => FEATURE_PAGES.len() + DEMO_PAGE_COUNT,
        Category::Technical => TECH_PAGES.len(),
    }
}

/// A fixed, illustrative [`CompositionModel`] for the read-only panel
/// demo (SPEC_EDU_UI §22.5a) -- not derived from any live session (this
/// screen is reachable outside a running ceremony), so the counts here
/// are a plausible worked example: a `Combined`-mode composition with
/// both counted physical entropy and two claimed machine sources,
/// clearing the SPEC §17.2 floor for a 24-word phrase.
fn demo_composition_model() -> CompositionModel {
    let mut machine_tags = MachineTagSet::new();
    machine_tags.insert(SourceTag::ApprovedEfiRng);
    machine_tags.insert(SourceTag::X86Rdseed64);
    CompositionModel::new(60, 30, machine_tags, TargetBits::Bits256, 1)
}

/// Physical column budget of the desktop Learn reader.
/// [`WindowTextOutput`] draws `GLYPH_WIDTH`-pixel glyph cells starting at
/// a `GLYPH_WIDTH * 2` left margin, and `seed_gop_ui::font::draw_text`
/// silently CLIPS (never wraps) anything past the [`CANVAS_WIDTH`] canvas
/// edge -- so a line longer than this many cells is cut off mid-word on
/// screen. Derived from the same constants `crate::shared_screen` lays the
/// canvas out with: `(1024 - 16) / 8 = 126`.
const LEARN_COLS: usize =
    ((CANVAS_WIDTH - seed_gop_ui::font::GLYPH_WIDTH * 2) / seed_gop_ui::font::GLYPH_WIDTH) as usize;

/// A recording [`TextOutput`] used to buffer one screen's worth of lines
/// so they can be post-processed (word-wrapped) before reaching the real
/// canvas. Used only for the composition-panel demo page (see
/// [`render_page`]).
///
/// SPEC.md amendment (2026-08-06): `clear()` is a deliberate no-op here,
/// NOT a reset. `composition::render_composition_panel` now paginates
/// internally (its own `clear()` call once per page -- see that
/// function's own doc comment) when its worst-case content does not fit
/// the SPEC §11.4 800x600-floor GOP screen as one page; this demo page
/// wants the panel's COMPLETE content concatenated into one continuous,
/// scrollable Learn page (it already has its own Page-N/M mechanism, a
/// different, higher-level pagination than the live ceremony's per-screen
/// one), so a page-boundary `clear()` from the wrapped renderer must never
/// discard what came before. `render_page` itself still calls `clear()`
/// exactly once, on the real output, before ever constructing this type.
struct LineCapture {
    lines: Vec<String>,
}
impl TextOutput for LineCapture {
    fn write_line(&mut self, line: &str) {
        self.lines.push(line.to_string());
    }
    fn clear(&mut self) {}
}

/// Write `line` to `out`, word-wrapping at [`LEARN_COLS`] if -- and only
/// if -- it would overflow the canvas. Lines already within budget
/// (including the panel's space-aligned rows, indented headers and rule
/// strips) pass through BYTE-FOR-BYTE, so only over-long prose is
/// reflowed; running a fixed-layout/aligned row through [`wrap_words`]
/// would collapse its geometry (see that helper's doc comment), which is
/// why the wrap is gated on the length check rather than applied blindly.
fn write_wrapped(out: &mut dyn TextOutput, line: &str) {
    if line.chars().count() <= LEARN_COLS {
        out.write_line(line);
    } else {
        for piece in wrap_words(line, LEARN_COLS) {
            out.write_line(piece);
        }
    }
}

/// One key's effect on the Learn reader (SPEC_MAIN_MENU.md §4.1 item 3:
/// "Page Up/Down + Esc"). Pure function of the current page index, the
/// total page count, and the raw [`KeyMsg`] -- host-testable with no
/// `TextOutput`/`ChannelKeys` (§6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LearnNav {
    /// Move to this (already-clamped) page index.
    GoTo(usize),
    /// `Esc` -- return to the launcher (§4.5).
    Return,
    /// Key with no effect (e.g. `Down` already on the last page).
    None,
}

/// See module doc comment "Page-forward/page-back key mapping":
/// `KeyMsg::Down`/`KeyMsg::Up` (the desktop-local arrow bridge) serve as
/// page-forward/page-back; movement clamps at the first/last page rather
/// than wrapping (this is a linear document, not a cyclic menu).
#[must_use]
pub fn handle_key(current: usize, total: usize, key: KeyMsg) -> LearnNav {
    if total == 0 {
        return LearnNav::Return;
    }
    match key {
        KeyMsg::Down => {
            if current + 1 < total {
                LearnNav::GoTo(current + 1)
            } else {
                LearnNav::None
            }
        }
        KeyMsg::Up => {
            if current > 0 {
                LearnNav::GoTo(current - 1)
            } else {
                LearnNav::None
            }
        }
        KeyMsg::Escape => LearnNav::Return,
        KeyMsg::Char(_) | KeyMsg::Enter | KeyMsg::Backspace | KeyMsg::Other => LearnNav::None,
    }
}

/// One key's effect on the category-landing screen. A direct `[1]`/`[2]`/
/// `[3]` number-key pick (mirroring `crate::launcher::menu::handle_key`'s
/// own `KeyMsg::Char` digit-shortcut pattern) rather than an Up/Down-to-
/// move + Enter-to-select highlight state: with only three fixed items,
/// a direct pick is the smaller diff against this file's existing
/// `KeyMsg` usage and at least as fast for the user as two-key
/// highlight-then-confirm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LandingNav {
    /// Open this category's page loop.
    Open(Category),
    /// `Esc` -- return to the launcher (§4.5).
    Return,
    /// Key with no effect (anything but `1`/`2`/`3`/`Esc`).
    None,
}

/// See [`LandingNav`]: `1`/`2`/`3` open the matching [`CATEGORIES`] entry,
/// `Esc` returns from [`run`] to the launcher.
#[must_use]
pub fn handle_landing_key(key: KeyMsg) -> LandingNav {
    match key {
        KeyMsg::Char('1') => LandingNav::Open(Category::Topics),
        KeyMsg::Char('2') => LandingNav::Open(Category::Features),
        KeyMsg::Char('3') => LandingNav::Open(Category::Technical),
        KeyMsg::Escape => LandingNav::Return,
        _ => LandingNav::None,
    }
}

/// Render page `index` (0-based, within `category`'s own page slice) plus
/// a shared footer showing position and controls. Host-testable against
/// any [`TextOutput`] double. Reproduces exactly what the old flat
/// `render_page` did per page kind, just re-scoped so `index` is relative
/// to `category` instead of a global flat index.
pub fn render_category_page(out: &mut dyn TextOutput, category: Category, index: usize) {
    out.clear();
    let total = category_page_count(category);
    let clamped = index.min(total.saturating_sub(1));
    match category {
        Category::Topics => {
            let page = &TOPIC_PAGES[clamped];
            out.write_line("Learn");
            out.write_line(page.title);
            out.write_line("");
            for line in page.body {
                out.write_line(line);
            }
        }
        Category::Features => {
            if clamped < FEATURE_PAGES.len() {
                // Newer per-feature plain-language explainers, rendered
                // exactly like a topic page (short, pre-fit prose --
                // emitted directly).
                let page = &FEATURE_PAGES[clamped];
                out.write_line("Learn");
                out.write_line(page.title);
                out.write_line("");
                for line in page.body {
                    out.write_line(line);
                }
            } else if clamped - FEATURE_PAGES.len() == 0 {
                // `render_composition_panel` is the SAME renderer the live
                // physical-entry panel uses, and several of its CLAIMED-section
                // prose lines (the machine-source descriptions, the claimed
                // note, and the verbatim SPEC §16 disclaimer) are authored for the
                // firmware text console and run WIDER than this desktop canvas can
                // display -- `draw_text` would clip them mid-word. So render the
                // panel into a buffer and re-emit it here, word-wrapping only the
                // over-long PROSE lines (short/aligned rows pass through
                // untouched). This fixes the Learn demo's wrapping WITHOUT touching
                // the shared live-panel renderer or its verbatim-string contract.
                // (The panel calls `clear()` itself; the buffer absorbs that, and
                // `render_category_page` already cleared `out` above.)
                let mut panel = LineCapture { lines: Vec::new() };
                composition::render_composition_panel(&mut panel, &demo_composition_model());
                for line in &panel.lines {
                    write_wrapped(out, line);
                }
                out.write_line("");
                out.write_line("^ read-only demo of the counted/claimed composition panel");
                out.write_line("  (SPEC_EDU_UI \u{a7}22.5a -- illustrative counts, not a live session)");
            } else {
                out.write_line("Learn -- read-only demo: dice and coin reference");
                out.write_line("(SPEC_DICE_COIN_ART \u{a7}4.3/\u{a7}17.4 -- same art module the physical-entry");
                out.write_line("screen uses, shown here on demand)");
                out.write_line("");
                dice_coin_art::write_legend(out);
            }
        }
        Category::Technical => {
            // Technical deep-dive appendix, rendered exactly like a topic
            // page. Body lines are emitted DIRECTLY (never through
            // `write_wrapped`): the draft pre-fit every line and the
            // formulas are fixed-layout, so wrapping one would corrupt it.
            let page = &TECH_PAGES[clamped];
            out.write_line("Learn");
            out.write_line(page.title);
            out.write_line("");
            for line in page.body {
                out.write_line(line);
            }
        }
    }
    out.write_line("");
    out.write_line(&format!(
        "Page {}/{}   Up/Down page   Esc back to {}",
        clamped + 1,
        total,
        category.label()
    ));
}

/// Render the category-landing screen: a "Learn" header followed by one
/// row per [`CATEGORIES`] entry, numbered `[1]`..`[3]`, with each
/// category's own page count in parentheses, and a footer describing the
/// number-key pick and `Esc` back to the launcher. Host-testable against
/// any [`TextOutput`] double, same as [`render_category_page`].
pub fn render_category_landing(out: &mut dyn TextOutput) {
    out.clear();
    out.write_line("Learn");
    out.write_line("");
    for (i, category) in CATEGORIES.iter().enumerate() {
        let count = category_page_count(*category);
        out.write_line(&format!(
            "  [{}] {}   ({} page{})",
            i + 1,
            category.label(),
            count,
            if count == 1 { "" } else { "s" }
        ));
    }
    out.write_line("");
    out.write_line("Press 1/2/3 to open a category   Esc return to menu");
}

/// The category-scoped page loop entered after picking a category from the
/// landing (see [`run`]). Renders the current page within `category`,
/// blocks for one key, applies [`handle_key`] against
/// [`category_page_count`], and loops until `Esc` (`LearnNav::Return`)
/// returns control to the landing -- NOT all the way out of [`run`].
/// Extracted as its own function (over `&mut dyn TextOutput`, not tied to
/// [`WindowTextOutput`]) so it stays host-testable with a scripted
/// `Vec<KeyMsg>` double, the same discipline [`handle_key`] follows.
fn run_category(out: &mut dyn TextOutput, keys: &mut ChannelKeys, category: Category) {
    let total = category_page_count(category);
    let mut index = 0usize;
    loop {
        render_category_page(out, category, index);
        match handle_key(index, total, keys.recv()) {
            LearnNav::GoTo(next) => index = next,
            LearnNav::Return => return,
            LearnNav::None => {}
        }
    }
}

/// Entry point for launcher item (3) (SPEC_MAIN_MENU.md §6.2 routing:
/// `launcher::learn::run(fb, keys, ...)`). Takes the same
/// [`SharedFramebuffer`]/[`TextOutput`] backend and the same
/// [`ChannelKeys`] key source the ceremony and every other launcher tool
/// use -- no new thread, no new channel (§4.5).
///
/// Two levels deep (design doc §5 category landing): renders the category
/// landing, blocks for one key, and on [`LandingNav::Open`] hands off to
/// [`run_category`]'s own page loop for that category, which returns here
/// (back to the landing) on its own `Esc`. `Esc` from the landing itself
/// (`LandingNav::Return`) returns control to the launcher.
pub fn run(fb: &mut SharedFramebuffer, keys: &mut ChannelKeys) {
    let mut out = WindowTextOutput::new(fb.clone());
    loop {
        render_category_landing(&mut out);
        match handle_landing_key(keys.recv()) {
            LandingNav::Open(category) => run_category(&mut out, keys, category),
            LandingNav::Return => return,
            LandingNav::None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RecordingOutput {
        lines: Vec<String>,
    }
    impl RecordingOutput {
        fn new() -> Self {
            Self { lines: Vec::new() }
        }
    }
    impl TextOutput for RecordingOutput {
        fn write_line(&mut self, line: &str) {
            self.lines.push(line.to_string());
        }
        fn clear(&mut self) {
            self.lines.clear();
        }
    }

    #[test]
    fn composition_demo_page_fits_display_width_and_wraps_prose_at_word_boundaries() {
        let mut out = RecordingOutput::new();
        render_category_page(&mut out, Category::Features, FEATURE_PAGES.len());

        // (1) No emitted line may overflow the canvas -- otherwise
        // `draw_text` clips it mid-word on screen.
        for line in &out.lines {
            assert!(
                line.chars().count() <= LEARN_COLS,
                "line overflows the {LEARN_COLS}-cell canvas ({} cells): {line:?}",
                line.chars().count()
            );
        }

        // (2) The wrap fell on SPACES, never inside a word. Independently
        // render the panel RAW (unwrapped) to recover its source prose,
        // then flatten the page's rendered lines into a single-spaced token
        // stream: every originally over-long panel line must reappear there
        // as a CONTIGUOUS run of whole words (nothing split, dropped, or
        // reordered). Uses `LineCapture` (not `RecordingOutput`) precisely
        // because it must NOT lose earlier pages to the panel's own
        // internal `clear()` calls -- see that type's own doc comment.
        //
        // SPEC.md amendment (2026-08-06): `render_composition_panel`
        // itself now word-wraps its own over-long prose at
        // `crate::text::PROSE_WRAP_COLS` (80, tighter than this desktop
        // canvas's `LEARN_COLS`, 126) before this demo page ever sees it
        // -- see that function's own doc comment. So this specific data
        // source may no longer hand `write_wrapped` anything actually over
        // `LEARN_COLS` to re-wrap; the loop below still checks the
        // no-mid-word-corruption property whenever it DOES find such a
        // line (defensive -- a future wider canvas or a longer verbatim
        // constant could still exercise this path), but no longer asserts
        // that it must. [`write_wrapped_breaks_only_at_word_boundaries`]
        // below is the same property pinned against a synthetic input
        // that always needs wrapping, independent of any panel content.
        let mut raw = LineCapture { lines: Vec::new() };
        composition::render_composition_panel(&mut raw, &demo_composition_model());
        let flat = out
            .lines
            .iter()
            .flat_map(|l| l.split_whitespace())
            .collect::<Vec<_>>()
            .join(" ");
        for src in &raw.lines {
            if src.chars().count() > LEARN_COLS {
                let normalized = src.split_whitespace().collect::<Vec<_>>().join(" ");
                assert!(
                    flat.contains(&normalized),
                    "wrapped prose broke or dropped a word from an over-long panel line: {src:?}"
                );
            }
        }

        // (3) The label prose is present intact (it is within budget, so it
        // is shown whole rather than wrapped).
        let joined = out.lines.join("\n");
        assert!(joined.contains("^ read-only demo of the counted/claimed composition panel"));
    }

    /// Direct, content-independent pin of `write_wrapped`'s own word-
    /// boundary-safe wrapping (companion to the composition-demo test
    /// above, which can no longer rely on the live panel supplying an
    /// over-`LEARN_COLS` line now that `render_composition_panel` wraps
    /// its own prose upstream -- see that test's own updated doc comment).
    #[test]
    fn write_wrapped_breaks_only_at_word_boundaries_and_passes_short_lines_through() {
        let mut out = RecordingOutput::new();
        let long = "the quick brown fox jumps over the lazy dog ".repeat(6);
        let long = long.trim();
        assert!(long.chars().count() > LEARN_COLS, "fixture must actually need wrapping");
        write_wrapped(&mut out, long);

        assert!(out.lines.len() > 1, "an over-long line must produce more than one output line");
        for line in &out.lines {
            assert!(
                line.chars().count() <= LEARN_COLS,
                "wrapped fragment still exceeds the {LEARN_COLS}-cell canvas: {line:?}"
            );
        }
        let flat = out.lines.join(" ");
        let normalized_src = long.split_whitespace().collect::<Vec<_>>().join(" ");
        let normalized_flat = flat.split_whitespace().collect::<Vec<_>>().join(" ");
        assert_eq!(normalized_flat, normalized_src, "wrapping must not drop, split, or reorder any word");

        // Short lines pass through byte-for-byte, unwrapped.
        let mut out2 = RecordingOutput::new();
        write_wrapped(&mut out2, "short line");
        assert_eq!(out2.lines, vec!["short line".to_string()]);
    }

    #[test]
    fn passphrase_page_states_it_is_now_implemented_with_typo_protection() {
        // Category::Topics page 11/12 == TOPIC_PAGES index 10. The stale
        // "not implemented yet / no way to detect a typo" wording must be
        // gone, replaced by the shipped behavior (SPEC.md §34.8 amended,
        // SPEC_PASSPHRASE v0.2).
        let mut out = RecordingOutput::new();
        render_category_page(&mut out, Category::Topics, 10);
        let joined = out.lines.join("\n");
        assert!(joined.contains("BIP39 passphrases"));
        assert!(joined.contains("IMPLEMENTS an OPTIONAL BIP39 passphrase"));
        assert!(joined.contains("TWICE"), "must describe the double-entry typo protection");
        assert!(
            !joined.contains("does not implement"),
            "stale 'does not implement' wording must be gone"
        );
        assert!(
            !joined.contains("no built-in"),
            "stale 'no built-in way to detect the mistake' wording must be gone"
        );
        assert!(joined.contains("Page 11/12"));
    }

    #[test]
    fn there_are_every_spec_34_topic_plus_three_intro_pages_plus_two_demos() {
        // 34.1 .. 34.9 = 9, plus "what is entropy" / "hardware wallets &
        // signers" / "what Alea does" = 3 intro pages, plus 5 newer
        // per-feature explainers, plus 2 demos, plus the 8 technical
        // deep-dive pages -- now counted per category rather than as one
        // flat total.
        assert_eq!(TOPIC_PAGES.len(), 12);
        assert_eq!(FEATURE_PAGES.len(), 5);
        assert_eq!(category_page_count(Category::Topics), 12);
        assert_eq!(category_page_count(Category::Features), 7);
        assert_eq!(category_page_count(Category::Technical), 8);
    }

    #[test]
    fn down_advances_a_page_and_up_returns() {
        assert_eq!(handle_key(0, 27, KeyMsg::Down), LearnNav::GoTo(1));
        assert_eq!(handle_key(1, 27, KeyMsg::Up), LearnNav::GoTo(0));
    }

    #[test]
    fn down_clamps_at_the_last_page() {
        assert_eq!(handle_key(26, 27, KeyMsg::Down), LearnNav::None);
    }

    #[test]
    fn up_clamps_at_the_first_page() {
        assert_eq!(handle_key(0, 27, KeyMsg::Up), LearnNav::None);
    }

    #[test]
    fn escape_returns_from_any_page() {
        assert_eq!(handle_key(0, 27, KeyMsg::Escape), LearnNav::Return);
        assert_eq!(handle_key(7, 27, KeyMsg::Escape), LearnNav::Return);
        assert_eq!(handle_key(26, 27, KeyMsg::Escape), LearnNav::Return);
    }

    #[test]
    fn unrelated_keys_are_a_no_op() {
        assert_eq!(handle_key(2, 27, KeyMsg::Char('x')), LearnNav::None);
        assert_eq!(handle_key(2, 27, KeyMsg::Enter), LearnNav::None);
        assert_eq!(handle_key(2, 27, KeyMsg::Backspace), LearnNav::None);
        assert_eq!(handle_key(2, 27, KeyMsg::Other), LearnNav::None);
    }

    #[test]
    fn first_page_covers_entropy() {
        let mut out = RecordingOutput::new();
        render_category_page(&mut out, Category::Topics, 0);
        let joined = out.lines.join("\n");
        assert!(joined.contains("What is entropy?"));
        assert!(joined.contains("Page 1/12"));
        assert!(joined.contains("Esc back to Topics"));
    }

    #[test]
    fn every_topic_page_renders_its_own_title() {
        for (i, page) in TOPIC_PAGES.iter().enumerate() {
            let mut out = RecordingOutput::new();
            render_category_page(&mut out, Category::Topics, i);
            let joined = out.lines.join("\n");
            assert!(joined.contains(page.title), "page {i} missing title {}", page.title);
        }
    }

    #[test]
    fn every_feature_page_is_reachable_within_the_features_category_and_shows_its_title() {
        // The newer per-feature explainers are Category::Features'
        // indices 0..FEATURE_PAGES.len(), ahead of the two demo pages.
        let total = category_page_count(Category::Features);
        for (i, page) in FEATURE_PAGES.iter().enumerate() {
            let mut out = RecordingOutput::new();
            render_category_page(&mut out, Category::Features, i);
            let joined = out.lines.join("\n");
            assert!(
                joined.contains(page.title),
                "feature page {i} missing title {}",
                page.title
            );
            assert!(joined.contains(&format!("Page {}/{total}", i + 1)));
        }
    }

    #[test]
    fn features_category_reaches_both_demo_pages_at_the_offsets_after_feature_pages() {
        // Category::Features page count is 5 feature explainers + 2 demos
        // = 7, and the demos sit at indices FEATURE_PAGES.len() and
        // FEATURE_PAGES.len() + 1.
        assert_eq!(category_page_count(Category::Features), FEATURE_PAGES.len() + DEMO_PAGE_COUNT);
        assert_eq!(category_page_count(Category::Features), 7);

        let mut composition_out = RecordingOutput::new();
        render_category_page(&mut composition_out, Category::Features, FEATURE_PAGES.len());
        let joined = composition_out.lines.join("\n");
        assert!(joined.contains("counted/claimed composition panel"));
        assert!(joined.contains("Page 6/7"));

        let mut dice_out = RecordingOutput::new();
        render_category_page(&mut dice_out, Category::Features, FEATURE_PAGES.len() + 1);
        let joined = dice_out.lines.join("\n");
        assert!(joined.contains("dice and coin reference"));
        assert!(joined.contains("Page 7/7"));
    }

    #[test]
    fn feature_pages_cover_the_shipped_surfaces() {
        // One sentinel string per new feature page, so a future reorder or
        // deletion that drops a surface is caught.
        let titles: Vec<&str> = FEATURE_PAGES.iter().map(|p| p.title).collect();
        assert!(titles.contains(&"Dice or coins, on screen"));
        assert!(titles.contains(&"More derivation options"));
        assert!(titles.contains(&"Custom derivation path"));
        assert!(titles.contains(&"Verifying another device's seed"));
        assert!(titles.contains(&"The offline web edition"));
    }

    #[test]
    fn every_feature_page_body_line_is_within_width_and_pure_printable_ascii() {
        // Feature prose is emitted DIRECTLY (never wrapped), so guard the
        // fixed-layout budget and ASCII-only font range, same as the tech
        // pages.
        for page in FEATURE_PAGES {
            for line in page.body {
                assert!(
                    line.len() <= 80,
                    "feature line exceeds 80 chars ({}): {line:?}",
                    line.len()
                );
                for b in line.bytes() {
                    assert!(
                        (0x20..=0x7E).contains(&b),
                        "feature line has non-printable-ASCII byte {b:#04x}: {line:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn composition_demo_page_renders_the_counted_claimed_panel() {
        let mut out = RecordingOutput::new();
        render_category_page(&mut out, Category::Features, FEATURE_PAGES.len());
        let joined = out.lines.join("\n");
        assert!(joined.contains("counted/claimed composition panel"));
        // The panel itself renders a COUNTED section header (SPEC_EDU_UI
        // §4.3) -- confirms the real composition renderer ran, not a
        // placeholder.
        assert!(joined.to_uppercase().contains("COUNTED"));
    }

    #[test]
    fn dice_coin_demo_page_renders_the_all_faces_legend() {
        let mut out = RecordingOutput::new();
        render_category_page(&mut out, Category::Features, FEATURE_PAGES.len() + 1);
        let joined = out.lines.join("\n");
        assert!(joined.contains("dice and coin reference"));
        // `write_legend`'s own first line (verbatim from
        // `dice_coin_art.rs`).
        assert!(joined.contains("Physical entropy -- dice and coin reference"));
    }

    #[test]
    fn last_page_of_each_category_is_reachable_and_numbered_correctly() {
        for category in CATEGORIES {
            let total = category_page_count(category);
            let mut out = RecordingOutput::new();
            render_category_page(&mut out, category, total - 1);
            let joined = out.lines.join("\n");
            assert!(joined.contains(&format!("Page {total}/{total}")));
        }
    }

    #[test]
    fn out_of_range_index_clamps_to_the_last_page_rather_than_panicking() {
        for category in CATEGORIES {
            let total = category_page_count(category);
            let mut out = RecordingOutput::new();
            render_category_page(&mut out, category, 999);
            let joined = out.lines.join("\n");
            assert!(joined.contains(&format!("Page {total}/{total}")));
        }
    }

    #[test]
    fn tech_appendix_has_eight_pages() {
        assert_eq!(TECH_PAGES.len(), 8);
        assert_eq!(category_page_count(Category::Technical), 8);
    }

    #[test]
    fn every_tech_page_is_reachable_within_the_technical_category_and_shows_its_prefixed_title() {
        let total = category_page_count(Category::Technical);
        for (i, page) in TECH_PAGES.iter().enumerate() {
            let mut out = RecordingOutput::new();
            render_category_page(&mut out, Category::Technical, i);
            let joined = out.lines.join("\n");
            assert!(page.title.starts_with("[T] "), "tech title missing [T] prefix: {}", page.title);
            assert!(
                joined.contains(page.title),
                "tech page {i} missing title {}",
                page.title
            );
            assert!(joined.contains(&format!("Page {}/{total}", i + 1)));
            assert!(joined.contains("Esc back to Technical"));
        }
    }

    #[test]
    fn every_tech_page_body_line_is_within_width_and_pure_printable_ascii() {
        // Formulas are FIXED-LAYOUT and rendered without wrapping, so a
        // future over-long or non-ASCII line would corrupt the display or
        // render as a blank cell. Guard both here (SPEC font renders only
        // 0x20..=0x7E; the desktop canvas is 126 cols but hold a strict 80
        // to keep every line inside the 98-col UEFI floor too).
        for page in TECH_PAGES {
            for line in page.body {
                assert!(
                    line.len() <= 80,
                    "tech line exceeds 80 chars ({}): {line:?}",
                    line.len()
                );
                for b in line.bytes() {
                    assert!(
                        (0x20..=0x7E).contains(&b),
                        "tech line has non-printable-ASCII byte {b:#04x}: {line:?}"
                    );
                }
            }
        }
    }

    // -- Category landing (Topics / Features / Technical) --------------

    #[test]
    fn render_category_landing_lists_all_three_categories_with_correct_counts() {
        let mut out = RecordingOutput::new();
        render_category_landing(&mut out);
        let joined = out.lines.join("\n");
        assert!(joined.contains("Learn"));
        assert!(joined.contains("[1] Topics"));
        assert!(joined.contains(&format!("({} pages)", category_page_count(Category::Topics))));
        assert!(joined.contains("[2] Features"));
        assert!(joined.contains(&format!("({} pages)", category_page_count(Category::Features))));
        assert!(joined.contains("[3] Technical"));
        assert!(joined.contains(&format!("({} pages)", category_page_count(Category::Technical))));
        assert!(joined.contains("Press 1/2/3"));
        assert!(joined.contains("Esc return to menu"));
    }

    #[test]
    fn landing_number_keys_open_the_matching_category() {
        assert_eq!(handle_landing_key(KeyMsg::Char('1')), LandingNav::Open(Category::Topics));
        assert_eq!(handle_landing_key(KeyMsg::Char('2')), LandingNav::Open(Category::Features));
        assert_eq!(handle_landing_key(KeyMsg::Char('3')), LandingNav::Open(Category::Technical));
    }

    #[test]
    fn landing_escape_returns_and_unrelated_keys_are_a_no_op() {
        assert_eq!(handle_landing_key(KeyMsg::Escape), LandingNav::Return);
        assert_eq!(handle_landing_key(KeyMsg::Char('4')), LandingNav::None);
        assert_eq!(handle_landing_key(KeyMsg::Char('0')), LandingNav::None);
        assert_eq!(handle_landing_key(KeyMsg::Up), LandingNav::None);
        assert_eq!(handle_landing_key(KeyMsg::Down), LandingNav::None);
        assert_eq!(handle_landing_key(KeyMsg::Enter), LandingNav::None);
        assert_eq!(handle_landing_key(KeyMsg::Backspace), LandingNav::None);
        assert_eq!(handle_landing_key(KeyMsg::Other), LandingNav::None);
    }

    /// Two-level Esc (design doc §5 / SPEC_MAIN_MENU.md §4.5): `Esc`
    /// pressed INSIDE a category must return control to the landing, not
    /// exit `run()` outright. `run_category` is `run()`'s own page-loop
    /// extraction, so a plain function return from it (proven here via a
    /// scripted `KeyMsg` stream over a real `ChannelKeys`, the same
    /// channel-backed type `run()` itself reads) IS that landing-return --
    /// as opposed to `run()` returning to the launcher, which only
    /// `LandingNav::Return` (`handle_landing_key(KeyMsg::Escape)`, pinned
    /// above) can trigger.
    #[test]
    fn escape_inside_a_category_returns_to_the_caller_not_out_of_the_process() {
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(KeyMsg::Down).unwrap();
        tx.send(KeyMsg::Down).unwrap();
        tx.send(KeyMsg::Escape).unwrap();
        let mut keys = ChannelKeys::new(rx);
        let mut out = RecordingOutput::new();

        // If `run_category` treated `Esc` as anything other than an
        // ordinary return, this call would hang (no more keys queued) or
        // panic; reaching the assertion below already proves the Esc was
        // handled as a scoped return.
        run_category(&mut out, &mut keys, Category::Topics);

        // Two `Down`s from page 1 land on page 3 before the `Esc`; the
        // last page rendered (RecordingOutput::clear() drops earlier
        // pages) is the one still on screen when control returns to the
        // landing.
        let joined = out.lines.join("\n");
        assert!(joined.contains("Page 3/12"), "expected page 3/12 still on screen, got: {joined:?}");
        assert!(joined.contains("Esc back to Topics"));
    }
}
