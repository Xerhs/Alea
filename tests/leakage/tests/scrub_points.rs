//! WP-34 check class (a) — SPEC §29.6: "secret values in stack and arena
//! regions after scrubbing where observable; residual rendering buffers".
//!
//! Drives the REAL secret-phase ceremony functions
//! (`seed_flow::flow_secret::{derive,display,reentry,verification,
//! shutdown}`, exactly what `crates/seed-flow/src/
//! flow_secret/driver.rs`'s state machine calls) end-to-end using PUBLIC
//! frozen-vector mnemonics (`tests/vectors/frozen/*.json`) as the only
//! secret-shaped input, and inspects the [`seed_core::arena::SecretArena`]
//! + spy [`support::VecFb`] framebuffer test doubles after each SPEC-
//! mandated scrub point to assert the public mnemonic words, BIP39 seed
//! bytes, private keys and chain codes are actually zeroed where SPEC
//! says they must be (SPEC §19.4, §12.4, §24.2/§24.4, §26).
//!
//! Machine-tagged vectors (not dice-only) are used deliberately:
//! [`seed_flow::flow_secret::machine::AcquiredSource::new`] is a public
//! constructor, so this external, standalone-workspace crate can build
//! realistic sources without needing `seed-flow`'s `pub(crate)`
//! `PhysicalStaging::push_dice`/`push_coin` (reserved for that crate's
//! own in-crate unit tests, `crates/seed-flow/src/
//! flow_secret/physical.rs`'s own doc comment). `PhysicalStaging` is used
//! here only in its empty, never-populated form, matching the "no
//! physical component" vector cases.

mod support;

use seed_core::arena::SecretArena;
use seed_core::contracts::{ArchId, PathStandard, SourceTag, TargetBits, WordCount};
use seed_flow::flow_secret::machine::{AcquiredSource, AcquiredSources};
use seed_flow::flow_secret::physical::PhysicalStaging;
use seed_flow::flow_secret::shutdown::{FaultHook, ShutdownFailure, ShutdownProvider};
use seed_flow::flow_secret::{derive, display, reentry, shutdown, verification};
use seed_gop_ui::gop::{scrub_sequence, NEUTRAL_SCRUB_PATTERN};
use seed_platform_x86::input::InputEvent;
use support::{prefix_for_word, load_case, VecFb, VectorCase};

fn tag_from_hex(tag_hex: &str) -> SourceTag {
    match tag_hex {
        "0x01" => SourceTag::ApprovedEfiRng,
        "0x02" => SourceTag::X86Rdseed64,
        "0x03" => SourceTag::X86RdrandSupplementary,
        "0x10" => SourceTag::DiceRolls,
        "0x11" => SourceTag::CoinFlips,
        other => panic!("unknown source tag {other:?}"),
    }
}

fn target_bits(bits: i64) -> TargetBits {
    match bits {
        128 => TargetBits::Bits128,
        256 => TargetBits::Bits256,
        other => panic!("unsupported bits {other}"),
    }
}

fn word_count_of(bits: i64) -> WordCount {
    match bits {
        128 => WordCount::Twelve,
        256 => WordCount::TwentyFour,
        other => panic!("unsupported bits {other}"),
    }
}

/// Builds the real `AcquiredSources`/`PhysicalStaging` inputs for
/// `case` (machine-only cases: no dice/coin bytes) straight from the
/// frozen public vector.
fn build_machine_sources(case: &VectorCase) -> (PhysicalStaging, AcquiredSources) {
    let staging = PhysicalStaging::new();
    let mut machine = AcquiredSources::new();
    for s in &case.sources {
        let tag = tag_from_hex(&s.tag_hex);
        assert!(
            matches!(tag, SourceTag::ApprovedEfiRng | SourceTag::X86Rdseed64 | SourceTag::X86RdrandSupplementary),
            "this suite's scrub-point tests use machine-only vectors (no dice/coin), got tag {tag:?} in case {:?}",
            case.name
        );
        let src = AcquiredSource::new(tag, s.algo.as_bytes(), &s.bytes).expect("vector source bytes fit AcquiredSource's fixed capacity");
        machine.push(src);
    }
    (staging, machine)
}

/// Panics on `halt()` (so `catch_unwind` can observe that
/// `scrub_and_shutdown`'s non-returning tail was reached) and records
/// every `before_*` step it saw, matching the pattern
/// `crates/seed-flow/src/flow_secret/shutdown.rs`'s own test
/// module already establishes for this trait.
struct RecordingFaultHook {
    steps: Vec<&'static str>,
}
impl RecordingFaultHook {
    fn new() -> Self {
        Self { steps: Vec::new() }
    }
}
impl FaultHook for RecordingFaultHook {
    fn before_scrub_reentry(&mut self) {
        self.steps.push("reentry");
    }
    fn before_scrub_mnemonic(&mut self) {
        self.steps.push("mnemonic");
    }
    fn before_scrub_derived_secrets(&mut self) {
        self.steps.push("derived");
    }
    fn before_scrub_arena(&mut self) {
        self.steps.push("all");
    }
    fn before_scrub_framebuffer(&mut self) {
        self.steps.push("framebuffer");
    }
    fn halt(&mut self) -> ! {
        panic!("leakage-suite halt reached: {:?}", self.steps);
    }
}

struct AlwaysOkShutdown;
impl ShutdownProvider for AlwaysOkShutdown {
    fn request_shutdown(&mut self) -> Result<(), ShutdownFailure> {
        Ok(())
    }
}

/// The full secret-phase ceremony, driven with the REAL
/// `seed_flow::flow_secret` functions over one public frozen vector,
/// checking every SPEC-mandated scrub point along the way. Returns
/// nothing — every assertion happens inline, in ceremony order, so a
/// failure's stack trace pinpoints exactly which SPEC scrub point broke.
fn run_full_ceremony_and_check_every_scrub_point(vector_file: &str) {
    let case = load_case(vector_file);
    let bits = target_bits(case.bits);
    let word_count = word_count_of(case.bits);
    let n = word_count as usize;
    let entropy_len = match bits {
        TargetBits::Bits128 => 16,
        TargetBits::Bits256 => 32,
    };

    let mut arena = SecretArena::new();
    let (mut staging, mut machine) = build_machine_sources(&case);

    // ---- Stage: sources -> final entropy -> mnemonic indexes (SPEC §19) ----
    let got_word_count = derive::derive(&mut arena, &mut staging, &mut machine, ArchId::X86_64, bits, case.policy_version)
        .unwrap_or_else(|e| panic!("{}: derive() failed: {e:?}", case.name));
    assert_eq!(got_word_count, word_count, "{}: word count", case.name);

    // Baseline correctness (not itself a leakage check, but proves the
    // "before" state below is genuinely this vector's real public secret
    // material, not a vacuous all-zero starting point).
    assert_eq!(
        &arena.final_entropy()[..entropy_len],
        &case.final_entropy[..],
        "{}: final entropy must match the public vector before any leakage check is meaningful",
        case.name
    );
    assert_eq!(
        &arena.mnemonic_indexes()[..n],
        &case.mnemonic_indexes[..],
        "{}: mnemonic indexes must match the public vector",
        case.name
    );

    // ---- SPEC §19.4 scrub point: "Immediately after final entropy is
    // derived ... scrub: raw machine-source records; dice and coin
    // history; the canonical transcript" ----
    assert!(machine.is_empty(), "{}: AcquiredSources must be scrubbed/cleared immediately after derive()", case.name);
    assert!(staging.dice_bytes().is_empty(), "{}: PhysicalStaging dice bytes must be scrubbed", case.name);
    assert!(staging.coin_bytes().is_empty(), "{}: PhysicalStaging coin bytes must be scrubbed", case.name);
    assert!(arena.machine_sources().iter().all(|&b| b == 0), "{}: arena.machine_sources() must be zero post-derive", case.name);
    assert!(arena.transcript().iter().all(|&b| b == 0), "{}: arena.transcript() must be zero post-derive", case.name);
    // What SPEC §19.4 explicitly says must SURVIVE this scrub point
    // (final entropy + mnemonic indexes are still needed for display and
    // re-entry) — a leakage suite must also catch an *over*-eager scrub
    // that destroys state the ceremony still needs.
    assert!(!arena.final_entropy()[..entropy_len].iter().all(|&b| b == 0), "{}: final_entropy must survive the §19.4 scrub", case.name);
    assert!(!arena.mnemonic_indexes()[..n].iter().all(|&i| i == 0), "{}: mnemonic_indexes must survive the §19.4 scrub", case.name);

    // ---- Mnemonic display (SPEC §22.7) then DisplayScrub (SPEC §12.4) ----
    let mut fb = VecFb::new(1024, 768);
    display::render_mnemonic_display(&mut fb, arena.mnemonic_indexes(), n);
    assert!(
        fb.contains_pixel(display::WORD_STYLE.fg),
        "{}: sanity check failed -- the public mnemonic must actually have been drawn before the scrub is meaningful",
        case.name
    );
    scrub_sequence(&mut fb, NEUTRAL_SCRUB_PATTERN);
    assert!(fb.is_blank(), "{}: framebuffer must be fully blank after SPEC §12.4 DisplayScrub", case.name);
    assert!(
        !fb.contains_pixel(display::WORD_STYLE.fg),
        "{}: no mnemonic-word glyph pixel may survive SPEC §12.4 DisplayScrub",
        case.name
    );

    // ---- Hidden re-entry (SPEC §23.1): every word matches, and the
    // typed prefix never re-displays the previously-shown mnemonic ----
    for i in 0..n {
        let prefix = prefix_for_word(&case.mnemonic_words[i]);
        let mut keys = support::ScriptedKeys::new(support::ScriptedKeys::word_entry(prefix));
        let outcome = reentry::read_and_check_one_word(&mut fb, &mut keys, i, n, &arena.mnemonic_indexes()[i]);
        assert_eq!(outcome, reentry::ReentryOutcome::Matched, "{}: re-entry word {i} ({prefix:?}) must match", case.name);
        // Re-entry's own prompt screen must never contain the mnemonic
        // word's rendered glyphs (SPEC §12.3: no echo) -- reusing the
        // same `WORD_STYLE.fg` foreground color `display::
        // render_mnemonic_display` used above as the telltale signal
        // that *word* content (as opposed to the "****"/"Word NN of MM"
        // prompt chrome, which uses the same style/color) leaked in a
        // position-correlated way is not meaningfully separable by pixel
        // color alone -- so instead this asserts the stronger, already
        // spec-mandated invariant directly below.
    }
    // SPEC §12.3/§27.3 structural guarantee: `reentry::render_word_prompt`
    // does not take the word text as a parameter at all -- it can only
    // ever render `(position, total, dots)`. Prove that two DIFFERENT
    // real public mnemonic words (from two independent frozen vectors)
    // typed at the same position produce byte-identical screens, so no
    // execution path could have let either word's actual letters reach
    // the framebuffer.
    assert_reentry_screen_is_word_independent();
}

/// SPEC §12.3: hidden re-entry must never echo the typed/expected word.
/// Drives two DIFFERENT real public mnemonic words (both >= 4 letters, so
/// both clamp to the same 4-dot prompt state) from two independent frozen
/// vectors through the real `reentry::read_and_check_one_word`, and
/// asserts the resulting framebuffers are pixel-identical -- despite the
/// underlying secret words being completely different values.
fn assert_reentry_screen_is_word_independent() {
    let case_a = load_case("machine_efi_rng_only_12w");
    let case_b = load_case("machine_rdseed_only_24w");

    let word_a = case_a.mnemonic_words.iter().find(|w| w.len() >= 4).expect("some word >= 4 letters exists");
    let word_b = case_b.mnemonic_words.iter().find(|w| w.len() >= 4).expect("some word >= 4 letters exists");
    assert_ne!(word_a, word_b, "the two probe words must actually be different secret values for this to prove anything");

    let mut fb_a = VecFb::new(640, 480);
    let mut keys_a = support::ScriptedKeys::new(support::ScriptedKeys::word_entry(&word_a[..4]));
    // Use a bogus expected index (0) -- outcome (match/mismatch) is
    // irrelevant to this check; only the rendered pixels matter, and
    // `read_and_check_one_word` renders before it ever compares.
    let _ = reentry::read_and_check_one_word(&mut fb_a, &mut keys_a, 0, 12, &0);

    let mut fb_b = VecFb::new(640, 480);
    let mut keys_b = support::ScriptedKeys::new(support::ScriptedKeys::word_entry(&word_b[..4]));
    let _ = reentry::read_and_check_one_word(&mut fb_b, &mut keys_b, 0, 12, &0);

    assert_eq!(fb_a.buf, fb_b.buf, "hidden-entry screen must be identical regardless of which real secret word was typed");
}

#[test]
fn full_ceremony_scrub_points_12w_efi_rng_only() {
    run_full_ceremony_and_check_every_scrub_point("machine_efi_rng_only_12w");
}

#[test]
fn full_ceremony_scrub_points_24w_rdseed_only() {
    run_full_ceremony_and_check_every_scrub_point("machine_rdseed_only_24w");
}

/// SPEC §24.2-§24.4 verification-display scrub point, and the terminal
/// SPEC §26 scrub-and-shutdown sequence, checked on their own vector run
/// (kept separate from the two tests above so a failure here doesn't get
/// masked by having already run the full ceremony inline -- this test
/// re-derives independently).
#[test]
fn verification_display_and_final_shutdown_scrub_public_secrets() {
    let case = load_case("machine_efi_rng_only_12w");
    let bits = target_bits(case.bits);
    let word_count = word_count_of(case.bits);

    let mut arena = SecretArena::new();
    let (mut staging, mut machine) = build_machine_sources(&case);
    derive::derive(&mut arena, &mut staging, &mut machine, ArchId::X86_64, bits, case.policy_version).unwrap();

    // ---- SPEC §24.2-§24.3: compute + render verification values ----
    let values = derive::compute_verification(&mut arena, word_count).unwrap_or_else(|e| panic!("compute_verification failed: {e:?}"));
    assert_eq!(&values.master_fingerprint[..], &case.master_fingerprint[..], "master fingerprint must match the public vector");
    let expected_addr = |standard: PathStandard| match standard {
        PathStandard::Bip44 => case.addr_bip44.as_str(),
        PathStandard::Bip49 => case.addr_bip49.as_str(),
        PathStandard::Bip84 => case.addr_bip84.as_str(),
        PathStandard::Bip86 => case.addr_bip86.as_str(),
    };
    for a in &values.addresses {
        let got = a.address.as_str().unwrap();
        assert_eq!(got, expected_addr(a.standard), "address must match the public vector for {:?}", a.standard);
    }

    // Baseline: the real secret key material is genuinely live in the
    // arena right now (so the scrub check below is not vacuous).
    assert!(!arena.bip39_seed().iter().all(|&b| b == 0), "bip39_seed must be populated before the scrub check is meaningful");
    assert!(!arena.master_key().iter().all(|&b| b == 0), "master_key must be populated before the scrub check is meaningful");
    assert!(!arena.master_chain_code().iter().all(|&b| b == 0), "master_chain_code must be populated before the scrub check is meaningful");

    let mut fb = VecFb::new(1024, 768);
    // No passphrase is committed in this machine-only ceremony, so render
    // the live Stage-7 verify screen in its no-passphrase form
    // (SPEC §24.3 / SPEC_PASSPHRASE §7.3).
    let vst = seed_flow::screens::verify::VerifyState::new();
    seed_flow::screens::verify::render(&mut fb, &vst, &values, false, "leak-test");
    verification::read_acknowledged(&mut support::ScriptedKeys::new(vec![InputEvent::Enter]));

    // ---- SPEC §24.2/§19.4 scrub point: derivation secrets retired once
    // the verification screen has been shown/acknowledged ----
    derive::scrub_after_verification(&mut arena);
    assert!(arena.bip39_seed().iter().all(|&b| b == 0), "bip39_seed must be zero after scrub_after_verification");
    assert!(arena.master_key().iter().all(|&b| b == 0), "master_key must be zero after scrub_after_verification");
    assert!(arena.master_chain_code().iter().all(|&b| b == 0), "master_chain_code must be zero after scrub_after_verification");
    assert!(arena.derive_scratch().iter().all(|&b| b == 0), "derive_scratch must be zero after scrub_after_verification");
    assert!(arena.scratch().iter().all(|&b| b == 0), "scratch must be zero after scrub_after_verification");
    // Mnemonic indexes/final entropy are still needed post-verification
    // (education screen, and the shutdown scrub below still has to scrub
    // them itself) -- must NOT have been wiped early by this call.
    assert!(!arena.mnemonic_indexes().iter().take(12).all(|&i| i == 0), "mnemonic_indexes must survive scrub_after_verification");

    // ---- SPEC §26: full scrub-and-shutdown sequence, driven with the
    // real function, terminal state inspected via `catch_unwind` around
    // the deliberately-panicking `FaultHook::halt` (same technique
    // `crates/seed-flow/src/flow_secret/shutdown.rs`'s own
    // test module uses) ----
    let mut shutdown_provider = AlwaysOkShutdown;
    let mut hook = RecordingFaultHook::new();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        shutdown::scrub_and_shutdown(&mut arena, &mut fb, &mut shutdown_provider, &mut hook);
    }));
    assert!(result.is_err(), "scrub_and_shutdown must never return control (it must reach the non-returning halt)");

    // Full arena, every field, must be zero -- the SPEC §26/§20.1
    // terminal state, checked directly against the arena's own public
    // accessors (a spy read, exactly per SPEC §29.6's "arena regions
    // after scrubbing where observable").
    assert!(arena.machine_sources().iter().all(|&b| b == 0), "machine_sources not zero after scrub_and_shutdown");
    // `physical_history` removed from the arena in fe7740f (dead buffer; the
    // real per-session history is stack-resident with its own Drop scrub).
    assert!(arena.transcript().iter().all(|&b| b == 0), "transcript not zero after scrub_and_shutdown");
    assert!(arena.final_entropy().iter().all(|&b| b == 0), "final_entropy (the public vector's own secret bytes) not zero after scrub_and_shutdown");
    assert!(arena.mnemonic_indexes().iter().all(|&i| i == 0), "mnemonic_indexes (the public vector's own words) not zero after scrub_and_shutdown");
    assert!(arena.reentry_buffer().iter().all(|&b| b == 0), "reentry_buffer not zero after scrub_and_shutdown");
    assert!(arena.bip39_seed().iter().all(|&b| b == 0), "bip39_seed not zero after scrub_and_shutdown");
    assert!(arena.master_key().iter().all(|&b| b == 0), "master_key not zero after scrub_and_shutdown");
    assert!(arena.master_chain_code().iter().all(|&b| b == 0), "master_chain_code not zero after scrub_and_shutdown");
    assert!(arena.derive_scratch().iter().all(|&b| b == 0), "derive_scratch not zero after scrub_and_shutdown");
    assert!(arena.scratch().iter().all(|&b| b == 0), "scratch not zero after scrub_and_shutdown");
    assert!(arena.passphrase().is_empty(), "passphrase not empty after scrub_and_shutdown");
    assert!(arena.passphrase_confirm().is_empty(), "passphrase_confirm not empty after scrub_and_shutdown");

    // Framebuffer must be fully blank after shutdown's own SPEC §26 step
    // 5 (scrub framebuffer / rendering buffers).
    assert!(fb.is_blank(), "framebuffer must be blank after scrub_and_shutdown");

    // Every SPEC §26 step actually ran, in order, before the halt.
    assert_eq!(hook.steps, vec!["reentry", "mnemonic", "derived", "all", "framebuffer"]);
}
