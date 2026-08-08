//! Category B (SPEC §29.5 "during entropy acquisition"): faults injected
//! into machine-source acquisition (SPEC §15-§16, §18), both at the
//! `assemble_acquired_sources` decision-point level and through the real
//! ceremony driver (`seed_flow::flow_secret::run_secret_flow`).

use seed_flow::entropy_avail::{MachineAvailabilityGate, SourceAvailability};
use seed_flow::flow_secret::machine::{
    assemble_acquired_sources, AcquiredSource, AcquiredSources, MachineAcquisitionError,
    MachineSourceGate,
};
use seed_flow::flow_secret::{run_secret_flow, SecretFlowOutcome, SecretProviders};

use seed_fault_injection::{
    coverage, ArchId, CountingWatchdog, MenuKey, MockOut, RecordingHook, ScriptedKeys, ScriptedMenuKeys,
    SourceTag, TestTimer, Watchdog, WordCount,
};

fn src(present: bool, tag: SourceTag) -> Option<AcquiredSource> {
    if present {
        Some(AcquiredSource::new(tag, b"algo", &[0xAB; 8]).unwrap())
    } else {
        None
    }
}

/// SPEC §15.3/§18.2 fault matrix: every present/absent combination of the
/// four machine sources (SPEC_TPM_ENTROPY.md §10 added TPM as a fourth,
/// primary-class source), confirming the "no primary succeeded" rule holds
/// in every case (RDRAND can never stand in alone — not even alongside a
/// failed TPM).
#[test]
fn assemble_acquired_sources_every_presence_combination() {
    let mut checked = 0usize;
    for efi in [false, true] {
        for rdseed in [false, true] {
            for rdrand in [false, true] {
                for tpm in [false, true] {
                    for tpm12 in [false, true] {
                        let mut into = AcquiredSources::new();
                        let result = assemble_acquired_sources(
                            src(efi, SourceTag::ApprovedEfiRng),
                            src(rdseed, SourceTag::X86Rdseed64),
                            src(rdrand, SourceTag::X86RdrandSupplementary),
                            src(tpm, SourceTag::Tpm2GetRandom),
                            src(tpm12, SourceTag::Tpm12GetRandom),
                            &mut into,
                        );
                        let primary = efi || rdseed || tpm || tpm12;
                        if primary {
                            assert!(result.is_ok(), "efi={efi} rdseed={rdseed} rdrand={rdrand} tpm={tpm} tpm12={tpm12}: a primary source succeeded, must be Ok");
                            let expected_len = usize::from(efi)
                                + usize::from(rdseed)
                                + usize::from(rdrand)
                                + usize::from(tpm)
                                + usize::from(tpm12);
                            assert_eq!(into.len(), expected_len);
                        } else {
                            assert_eq!(
                                result,
                                Err(MachineAcquisitionError::NoSourceAvailable),
                                "efi={efi} rdseed={rdseed} rdrand={rdrand} tpm={tpm} tpm12={tpm12}: no primary source, must be rejected regardless of rdrand"
                            );
                            assert!(into.is_empty(), "efi={efi} rdseed={rdseed} rdrand={rdrand} tpm={tpm} tpm12={tpm12}: rejected acquisition must leave nothing pushed");
                        }
                        checked += 1;
                    }
                }
            }
        }
    }
    assert_eq!(checked, coverage::B_ACQUISITION_ASSEMBLE_COMBINATIONS);
}

struct FailingGate;
impl MachineSourceGate for FailingGate {
    fn acquire(
        &mut self,
        _extras: seed_flow::flow_secret::machine::MachineExtras,
        _into: &mut AcquiredSources,
        _observer: &mut dyn seed_platform_x86::rng::progress::AcquisitionObserver,
    ) -> Result<(), MachineAcquisitionError> {
        Err(MachineAcquisitionError::NoSourceAvailable)
    }
}

struct PanicGate;
impl MachineSourceGate for PanicGate {
    fn acquire(
        &mut self,
        _extras: seed_flow::flow_secret::machine::MachineExtras,
        _into: &mut AcquiredSources,
        _observer: &mut dyn seed_platform_x86::rng::progress::AcquisitionObserver,
    ) -> Result<(), MachineAcquisitionError> {
        panic!("PanicGate: simulated hardware fault mid machine-source acquisition");
    }
}

/// `AppState::EntropyModeSelection`/the escape-at-final-confirmation loop
/// are the only branches `run_secret_flow` ever consults this gate from;
/// every test below fast-forwards `StateMachine` straight past
/// `EntropyModeSelection` before calling `run_secret_flow`, so this
/// double's exact values never actually get read here -- it exists only
/// to satisfy `SecretProviders`'s field, matching the pattern
/// `crates/seed-flow/src/flow_secret/driver.rs`'s own tests use.
struct AllApprovedMachineAvailability;
impl MachineAvailabilityGate for AllApprovedMachineAvailability {
    fn efi_rng(&mut self) -> SourceAvailability {
        SourceAvailability { approved: true, sole_source_allowed: true }
    }
    fn rdseed(&mut self) -> SourceAvailability {
        SourceAvailability { approved: true, sole_source_allowed: true }
    }
}

/// Drives `run_secret_flow` from the WP-25 handoff point (`WordCountSelection`)
/// with `mode`, a machine gate that fails, and confirms the SPEC §27.1
/// pre-secret disposition (exit to firmware, never a menu, never routed
/// into the post-secret fatal chain since no secret exists yet).
fn assert_machine_gate_failure_exits_to_firmware(mode: seed_fault_injection::EntropyMode) {
    use seed_fault_injection::{AppState, Event, SecretArena, StateMachine};

    let mut term = MockOut::new();
    // Real-hardware slow-RDSEED fix (SPEC §21): the driver now renders a
    // failure screen and blocks for exactly one `[Enter]` acknowledgment
    // before firing the exit event -- see `crate::flow_secret::driver`'s
    // `MachineEntropyAcquisition` arm.
    let mut menu_keys = ScriptedMenuKeys::new(vec![MenuKey::Enter]);
    let mut fb = seed_fault_injection::VecFb::new(64, 64);
    let mut secret_keys = ScriptedKeys::new(vec![]);
    let mut avail = AllApprovedMachineAvailability;
    let mut mgate = FailingGate;
    let mut shutdown = seed_fault_injection::AlwaysOkShutdown::new();
    let mut hook = RecordingHook::new();

    let mut sm = StateMachine::new();
    let mut w = CountingWatchdog::default();
    for _ in 0..3 {
        sm.transition(Event::Continue, &mut w);
    }
    for _ in 0..4 {
        sm.transition(Event::CheckPassed, &mut w);
    }
    sm.transition(
        Event::SetupCommitted {
            word_count: WordCount::Twelve,
            mode: mode,
            instrument: seed_fault_injection::Instrument::Both,
        },
        &mut w,
    );
    assert_eq!(sm.state(), AppState::MachineEntropyAcquisition);

    let mut arena = SecretArena::new();
    let mut watchdog = Watchdog::new(TestTimer);
    watchdog.disable().unwrap();

    let mut providers = SecretProviders {
        text_out: &mut term,
        menu_keys: &mut menu_keys,
        fb: &mut fb,
        secret_keys: &mut secret_keys,
        machine_availability: &mut avail,
        machine_gate: &mut mgate,
        shutdown: &mut shutdown,
        fault_hook: &mut hook,
        extras: seed_flow::flow_secret::machine::MachineExtras::default(),
        instrument: seed_flow::flow_secret::physical::Instrument::Both,
        passphrase_policy:
            seed_flow::flow_secret::passphrase::PassphraseKeyboardPolicy::HostKeyboardTrusted,
        build_id: "fault-injection-test",
        recap: seed_flow::diagnostics::DiagRecap::unknown(),
    };
    let outcome = run_secret_flow(&mut sm, &mut arena, &mut watchdog, ArchId::X86_64, 1, &mut providers);
    assert_eq!(outcome, SecretFlowOutcome::ExitedToFirmwareBeforeSecret);
    assert_eq!(sm.state(), AppState::ExitToFirmware);
    // No secret ever came into existence: no scrub step should have fired.
    assert!(hook.steps.is_empty(), "a pre-secret acquisition failure must not touch the post-secret scrub chain");
    assert!(arena.final_entropy().iter().all(|&b| b == 0));
}

#[test]
fn machine_gate_failure_combined_mode_exits_to_firmware_not_a_menu() {
    assert_machine_gate_failure_exits_to_firmware(seed_fault_injection::EntropyMode::Combined);
}

#[test]
fn machine_gate_failure_machine_only_mode_exits_to_firmware_not_a_menu() {
    assert_machine_gate_failure_exits_to_firmware(seed_fault_injection::EntropyMode::MachineOnly);
}

/// SPEC §29.5 + §20.4 residual-risk documentation: a machine-source gate
/// that panics mid-call (hardware fault proxy) unwinds out of
/// `run_secret_flow` entirely -- this is still pre-secret (no final
/// entropy exists yet), so nothing secret is exposed, but it documents
/// that this suite does not (and per SPEC §20.4 cannot) claim scrub
/// guarantees for a fault that prevents application code from continuing
/// to run at all.
#[test]
fn machine_gate_panic_mid_acquisition_unwinds_before_any_secret_exists() {
    use seed_fault_injection::{Event, SecretArena, StateMachine};

    let mut term = MockOut::new();
    let mut menu_keys = ScriptedMenuKeys::new(vec![]);
    let mut fb = seed_fault_injection::VecFb::new(64, 64);
    let mut secret_keys = ScriptedKeys::new(vec![]);
    let mut avail2 = AllApprovedMachineAvailability;
    let mut mgate = PanicGate;
    let mut shutdown = seed_fault_injection::AlwaysOkShutdown::new();
    let mut hook = RecordingHook::new();

    let mut sm = StateMachine::new();
    let mut w = CountingWatchdog::default();
    for _ in 0..3 {
        sm.transition(Event::Continue, &mut w);
    }
    for _ in 0..4 {
        sm.transition(Event::CheckPassed, &mut w);
    }
    sm.transition(
        Event::SetupCommitted {
            word_count: WordCount::Twelve,
            mode: seed_fault_injection::EntropyMode::Combined,
            instrument: seed_fault_injection::Instrument::Both,
        },
        &mut w,
    );

    let mut arena = SecretArena::new();
    let mut watchdog = Watchdog::new(TestTimer);
    watchdog.disable().unwrap();

    let mut providers = SecretProviders {
        text_out: &mut term,
        menu_keys: &mut menu_keys,
        fb: &mut fb,
        secret_keys: &mut secret_keys,
        machine_availability: &mut avail2,
        machine_gate: &mut mgate,
        shutdown: &mut shutdown,
        fault_hook: &mut hook,
        extras: seed_flow::flow_secret::machine::MachineExtras::default(),
        instrument: seed_flow::flow_secret::physical::Instrument::Both,
        passphrase_policy:
            seed_flow::flow_secret::passphrase::PassphraseKeyboardPolicy::HostKeyboardTrusted,
        build_id: "fault-injection-test",
        recap: seed_flow::diagnostics::DiagRecap::unknown(),
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_secret_flow(&mut sm, &mut arena, &mut watchdog, ArchId::X86_64, 1, &mut providers)
    }));
    assert!(result.is_err(), "the simulated hardware fault must propagate as a panic, not be swallowed");
    assert!(arena.final_entropy().iter().all(|&b| b == 0), "no secret ever existed at the point of this fault");
}
