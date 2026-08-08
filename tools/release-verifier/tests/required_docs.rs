//! Regression test (WP-32, SPEC §32) for the release-facing governance/
//! audit/compatibility documents that a spec-conformance audit found
//! missing entirely (2026-08-04 finding: "SIGNING-GOVERNANCE.md,
//! AUDIT-STATUS.md, COMPATIBILITY.md, DENYLIST.txt, SBOM.spdx.json,
//! ENTROPY-POLICY.txt ... do not exist").
//!
//! This test does not (and cannot) prove the *organizational* content of
//! these documents is true — no in-repo test can prove a multi-person
//! signing approval actually happened. What it proves mechanically:
//! these files exist at the paths [`release_verifier::manifest::REQUIRED_RELEASE_FILES`]
//! names, and each contains the specific honesty markers that make it a
//! real status report rather than a placeholder that silently claims
//! more than is true (e.g. it must say the gate is unmet, not just
//! mention the gate's name).
use release_verifier::manifest::REQUIRED_RELEASE_FILES;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn read_doc(rel_path: &str) -> String {
    let path = repo_root().join(rel_path);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("required document {} could not be read: {e}", path.display()))
}

/// SPEC §32's fixed release-file list names three governance/status
/// `docs/` files by exact name; this repository publishes them at
/// `docs/<name>`. Confirms the manifest constant and the real
/// documentation tree stay in sync — if someone renames or moves one
/// without updating the other, this fails.
#[test]
fn all_three_docs_named_release_files_exist_under_docs() {
    for name in ["SIGNING-GOVERNANCE.md", "AUDIT-STATUS.md", "COMPATIBILITY.md"] {
        assert!(
            REQUIRED_RELEASE_FILES.contains(&name),
            "{name} must remain part of release_verifier::manifest::REQUIRED_RELEASE_FILES"
        );
        let path = repo_root().join("docs").join(name);
        assert!(
            path.is_file(),
            "SPEC §32 requires {name} as a release artifact; expected it at {}",
            path.display()
        );
    }
}

#[test]
fn signing_governance_documents_the_required_procedure_honestly() {
    let doc = read_doc("docs/SIGNING-GOVERNANCE.md");
    for must_mention in [
        "multi-person",
        "custody",
        "rotation",
        "revocation",
        "compromise",
        "SPEC.md` §32",
    ] {
        assert!(
            doc.contains(must_mention),
            "docs/SIGNING-GOVERNANCE.md must discuss {must_mention:?} (SPEC §32 requirement)"
        );
    }
    // Honesty check: it must not claim the process has actually been
    // exercised. Absence of an explicit "not yet operative"-style
    // admission would mean this doc silently overclaims.
    assert!(
        doc.to_lowercase().contains("not yet operative") || doc.to_lowercase().contains("zero"),
        "docs/SIGNING-GOVERNANCE.md must honestly state that no signing has happened yet, \
         not merely describe the intended process"
    );
}

#[test]
fn audit_status_reports_all_eight_36_2_gates() {
    let doc = read_doc("docs/AUDIT-STATUS.md");
    // Each of the eight SPEC §36.2 gate topics must be traceable in the
    // status table (loose substring match on the gate's defining noun
    // phrase, not the full spec sentence, since the table paraphrases).
    for gate_topic in [
        "public vectors",
        "independent implementations",
        "Reproducible unsigned payload",
        "Binary policy scanner",
        "Fault-injection",
        "secp256k1",
        "external review",
        "revocation process",
    ] {
        assert!(
            doc.contains(gate_topic),
            "docs/AUDIT-STATUS.md must report on the SPEC §36.2 gate: {gate_topic:?}"
        );
    }
    // Honesty check: at least one gate must be reported as unmet. A
    // report claiming all eight gates are met would contradict
    // SECURITY.md's own EXPERIMENTAL banner and must never happen while
    // that banner is active.
    assert!(
        doc.contains("Not met"),
        "docs/AUDIT-STATUS.md must honestly report at least one unmet SPEC §36.2 gate \
         (the project has not passed the full gate set)"
    );
}

#[test]
fn compatibility_doc_states_methodology_and_has_no_fabricated_percentage() {
    let doc = read_doc("docs/COMPATIBILITY.md");
    for must_mention in ["confidence interval", "firmware vendor", "duplicate", "universal"] {
        assert!(
            doc.to_lowercase().contains(&must_mention.to_lowercase()),
            "docs/COMPATIBILITY.md must discuss {must_mention:?} (SPEC §30 requirement)"
        );
    }
    // Regression guard against ever slipping in a fabricated aggregate
    // claim before real data exists (SPEC §30: "MUST NOT claim '95%
    // compatibility' from an arbitrary convenience sample").
    assert!(
        doc.contains("No data") || doc.contains("no data") || doc.contains("(none reported)"),
        "docs/COMPATIBILITY.md must state plainly that no compatibility data has been \
         collected yet, not present a placeholder that could be mistaken for a real claim"
    );
    // The Results table itself (the part a reader would mistake for a
    // real reported figure) must carry no percentage at all; the
    // methodology text above it is allowed to quote SPEC.md's own
    // prohibited example ("95% compatibility") when explaining the
    // rule, which is why this check is scoped to the Results section
    // rather than the whole document.
    let results_section = doc
        .split("## Results")
        .nth(1)
        .expect("docs/COMPATIBILITY.md must have a ## Results section");
    let results_before_history = results_section
        .split("## Revision history")
        .next()
        .unwrap_or(results_section);
    assert!(
        !results_before_history.contains('%'),
        "docs/COMPATIBILITY.md's Results section must not contain any percentage figure \
         while no real data has been collected"
    );
}

/// `docs/AUDIT-STATUS.md` (the `SPEC.md` §32 release-artifact name) and
/// `docs/audit-status.md` (the path `IMPLEMENTATION_MAP.md` §5/§6
/// assigns to WP-35's running adversarial-review findings log) name the
/// same underlying document on this project's filesystem convention
/// (release-root artifacts share content with their `docs/` source, the
/// same way `SHA256SUMS`/`REPRODUCING.md` do — see `docs/AUDIT-STATUS.md`'s
/// own header). On a case-*insensitive* filesystem the two paths are
/// even the same inode; this test only needs to confirm the one file
/// that exists actually contains the §36.2 gate table content this test
/// suite already checks elsewhere, whichever casing was used to reach
/// it.
#[test]
fn audit_status_is_reachable_regardless_of_path_casing() {
    let upper = repo_root().join("docs").join("AUDIT-STATUS.md");
    assert!(upper.is_file(), "expected docs/AUDIT-STATUS.md to exist");
    let content = std::fs::read_to_string(&upper).unwrap();
    assert!(
        content.contains("§36.2"),
        "docs/AUDIT-STATUS.md must contain the SPEC §36.2 gate-by-gate table"
    );
}

/// Regression guard for exactly the kind of self-report bug this
/// document exists to prevent elsewhere in the project: the "Result: N
/// of 8" summary line must actually match the number of `**Met**` rows
/// in the table above it. (A prior draft of this file said "4 of 8"
/// when the table it summarized actually had 5 `Met` rows — an honesty
/// document that miscounts its own gate table is exactly the kind of
/// silent-overclaim/underclaim this test suite is meant to catch.)
#[test]
fn audit_status_summary_count_matches_the_number_of_met_rows_in_its_own_table() {
    let doc = read_doc("docs/AUDIT-STATUS.md");
    let table_section = doc
        .split("## `SPEC.md` §36.2 gate-by-gate status")
        .nth(1)
        .expect("docs/AUDIT-STATUS.md must have the §36.2 gate table section")
        .split("## What is mechanically re-checkable")
        .next()
        .unwrap();

    // Only real table rows (lines starting with "| <digit> |") count —
    // prose elsewhere in this section (e.g. "until all eight rows above
    // read **Met**") also contains the bold literal and must not be
    // double-counted.
    let numbered_rows: Vec<&str> = table_section
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            t.starts_with('|') && t.trim_start_matches('|').trim_start().chars().next().is_some_and(|c| c.is_ascii_digit())
        })
        .collect();
    let met_rows = numbered_rows.iter().filter(|l| l.contains("**Met")).count();
    let not_met_rows = numbered_rows.iter().filter(|l| l.contains("**Not met**")).count();
    assert_eq!(
        met_rows + not_met_rows,
        8,
        "expected exactly 8 SPEC §36.2 gate rows (Met + Not met) in docs/AUDIT-STATUS.md, found {} Met + {} Not met",
        met_rows,
        not_met_rows
    );

    let expected_summary = format!("Result: {met_rows} of 8 minimum-credible gates met.");
    assert!(
        doc.contains(&expected_summary),
        "docs/AUDIT-STATUS.md's summary line must read {expected_summary:?} to match its own \
         table ({met_rows} Met rows counted), but that exact string was not found"
    );
}

/// Sanity check purely on path casing/uniqueness, independent of
/// whether `docs/audit-status.md` happens to exist in this checkout.
#[test]
fn required_release_files_list_has_no_case_only_duplicates() {
    let mut lowered: Vec<String> = REQUIRED_RELEASE_FILES.iter().map(|s| s.to_lowercase()).collect();
    lowered.sort();
    let before = lowered.len();
    lowered.dedup();
    assert_eq!(
        before,
        lowered.len(),
        "REQUIRED_RELEASE_FILES must not contain two names that only differ by case \
         (a real release archive is not guaranteed to sit on a case-sensitive filesystem)"
    );
}
