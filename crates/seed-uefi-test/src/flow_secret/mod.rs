//! Owned by WP-26 (SPEC §12, §17.4, §22.6-24, §26). Test-edition wiring
//! for [`seed_flow::flow_secret::run_secret_flow`].
//!
//! # STEP B dedup
//!
//! Every real-firmware provider type this ceremony needs
//! (`ProdMachineSourceGate`, `ProdShutdown`, `ProdFaultHook`, and the
//! whole [`seed_flow::firmware_wiring::run_secret_phase`] driver
//! function) now lives in [`seed_flow::firmware_wiring`], shared
//! verbatim with `crates/seed-uefi-production/src/flow_secret/` (see
//! that module's own doc comment for the full rationale). This file is
//! now nothing more than a thin call into that shared driver, passing
//! this edition's own [`crate::flow_pre`]-defined `production_marker`
//! (always `None` here — SPEC §4.2).

use crate::flow_pre::PRODUCTION_MARKER;

/// Run the complete secret-phase ceremony (SPEC §17.4 onward) with real
/// firmware providers. Thin call into
/// [`seed_flow::firmware_wiring::run_secret_phase`], passing this
/// edition's own production marker (see `crate::flow_pre`'s doc
/// comment) — every other behavior is identical to, and defined in, the
/// shared function itself.
pub fn run_secret_phase(
    sm: seed_protocol::state::StateMachine,
    stdin: &mut uefi::proto::console::text::Input,
    fb: &mut seed_gop_ui::gop::framebuffer::LinearFramebuffer,
    instrument: seed_flow::flow_secret::physical::Instrument,
    build_id: &'static str,
    recap: seed_flow::diagnostics::DiagRecap,
) -> seed_flow::flow_secret::SecretFlowOutcome {
    seed_flow::firmware_wiring::run_secret_phase(
        sm,
        stdin,
        fb,
        PRODUCTION_MARKER,
        instrument,
        build_id,
        recap,
    )
}
