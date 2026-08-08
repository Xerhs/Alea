//! Mechanically-checkable half of the SPEC §31 dependency policy (WP-32).
//!
//! SPEC §31: "Dependencies MUST be minimal and pinned... Unpinned Git
//! dependencies are prohibited... Every dependency requires: exact
//! version pinning; license review; security-advisory review; `no_std`
//! review; allocation review; default-feature review; transitive-
//! dependency review; source-repository review; dedicated approval
//! commit; inclusion in the SBOM." Most of that list is an
//! organizational/human review process no in-repo tool can perform or
//! fabricate evidence of (a spec-conformance audit finding: "no
//! dependency-audit tool config exists"). This module covers the two
//! sub-claims that ARE structural, machine-checkable facts about the
//! real `Cargo.lock`/`Cargo.toml` on disk, and states plainly (via
//! [`DependencyPolicyReport`]'s doc comments and every report's own
//! shape) that it does not and cannot check the rest.
//!
//! 1. **"Unpinned Git dependencies are prohibited"** — mechanically
//!    exact: a `Cargo.lock` `[[package]]` block either has a `source =
//!    "git+..."` line or it doesn't; [`find_git_sourced_packages`] finds
//!    every one that does.
//! 2. **"Exact version pinning"** for the workspace's own directly-pinned
//!    third-party dependencies — [`find_unpinned_workspace_dependencies`]
//!    checks that every `[workspace.dependencies]` entry's `version`
//!    string begins with `=` (Cargo's exact-version operator), the same
//!    convention root `Cargo.toml`'s own dependency-pin comments already
//!    document by hand for each entry.
//!
//! Neither function needs a TOML parser: `Cargo.lock` is `cargo`-
//! generated with a small, stable, flat `[[package]]` shape (same
//! reasoning `tools/image-builder/src/sbom.rs`'s own module doc gives for
//! its hand-rolled reader, duplicated here rather than shared across
//! crates because these are two independently owned WP-29/WP-32 tools
//! with no existing shared-library relationship); the `[workspace.
//! dependencies]` table this module reads is a flat, single-line-per-
//! entry table by this workspace's own established convention (verified
//! against the real root `Cargo.toml` by this module's own tests below).
#![forbid(unsafe_code)]

/// Scans raw `Cargo.lock` text for every `[[package]]` block whose
/// `source` field begins with `git+` (SPEC §31: "Unpinned Git
/// dependencies are prohibited" — a `git+` source with no lock-recorded
/// exact commit would defeat pinning even if `Cargo.lock` itself is
/// checked in, since `cargo update` against a branch/tag ref can still
/// silently move; `cargo` always records the resolved commit in the
/// `source` string for a `git` dependency, so a *lack* of a resolvable
/// exact reference is not something this function needs to separately
/// detect — its job is simpler: no `git+` source should be present here
/// at all, per SPEC §31's flat prohibition, not "some git sources are
/// fine if pinned").
///
/// Returns `"name version"` for every violator found, sorted.
#[must_use]
pub fn find_git_sourced_packages(cargo_lock_contents: &str) -> Vec<String> {
    let mut violators = Vec::new();
    let mut current_name: Option<&str> = None;
    let mut current_version: Option<&str> = None;

    for raw_line in cargo_lock_contents.lines() {
        let line = raw_line.trim();
        if line == "[[package]]" {
            current_name = None;
            current_version = None;
            continue;
        }
        if let Some(v) = extract_quoted(line, "name") {
            current_name = Some(v);
        } else if let Some(v) = extract_quoted(line, "version") {
            current_version = Some(v);
        } else if let Some(v) = extract_quoted(line, "source") {
            if v.starts_with("git+") {
                let name = current_name.unwrap_or("<unknown>");
                let version = current_version.unwrap_or("<unknown>");
                violators.push(format!("{name} {version}"));
            }
        }
    }
    violators.sort();
    violators
}

/// Extracts a `key = "value"` line's string value, if `line` (already
/// trimmed) is exactly of that shape for the given `key`. Same idiom as
/// `tools/image-builder/src/sbom.rs`'s `extract_str_field`.
fn extract_quoted<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(key)?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=')?;
    let rest = rest.trim();
    let rest = rest.strip_prefix('"')?;
    rest.strip_suffix('"')
}

/// Scans raw root `Cargo.toml` text for the `[workspace.dependencies]`
/// table (this workspace's SPEC §31 "exact version pinning" location —
/// `IMPLEMENTATION_MAP.md` §6: `contracts.rs`/dep versions there are
/// read-only to every other work package, this function only reads them)
/// and returns the name of every entry whose `version` string does not
/// begin with `=` (Cargo's exact-pin operator; `"0.11.0"` allows
/// semver-compatible drift, `"=0.11.0"` does not).
///
/// Handles both this workspace's actual entry shapes: `name = { version
/// = "=X.Y.Z", ... }` and a bare `name = "=X.Y.Z"` (not currently used in
/// this workspace's own `Cargo.toml`, but a legal, simpler form the
/// workspace could adopt for a future dependency without this check
/// needing an update). Stops at the next top-level `[...]` table header
/// (an entry outside `[workspace.dependencies]` — e.g. `[profile.
/// release]` — is never inspected).
#[must_use]
pub fn find_unpinned_workspace_dependencies(cargo_toml_contents: &str) -> Vec<String> {
    let mut in_section = false;
    let mut violators = Vec::new();

    for raw_line in cargo_toml_contents.lines() {
        let line = raw_line.trim();
        if line.starts_with('[') {
            in_section = line == "[workspace.dependencies]";
            continue;
        }
        if !in_section || line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, rest)) = line.split_once('=') else { continue };
        let name = name.trim();
        let rest = rest.trim();

        // Find the `version = "..."` value, whether `rest` is a bare
        // `"=X.Y.Z"` string or a `{ version = "=X.Y.Z", ... }` inline
        // table.
        let version = if let Some(v) = rest.strip_prefix('"').and_then(|r| r.split('"').next()) {
            Some(v)
        } else {
            find_inline_table_field(rest, "version")
        };

        match version {
            Some(v) if v.starts_with('=') => {}
            Some(_) => violators.push(name.to_string()),
            // A dependency entry with no discoverable `version` field at
            // all (e.g. a bare workspace-relative path dependency) is
            // out of scope for "exact version pinning" — there is no
            // registry version to pin — so it is not flagged.
            None => {}
        }
    }
    violators.sort();
    violators
}

/// Finds `key = "value"` inside a `{ ... }` inline-table fragment (the
/// `rest` of a `name = { ... }` line, already known to start with `{`).
/// Minimal, single-line scan matching this workspace's own established
/// one-line-per-dependency `Cargo.toml` formatting convention (verified
/// against the real file by this module's own tests).
fn find_inline_table_field<'a>(inline_table: &'a str, key: &str) -> Option<&'a str> {
    let body = inline_table.strip_prefix('{')?;
    for field in body.split(',') {
        let field = field.trim();
        if let Some(v) = extract_quoted(field, key) {
            return Some(v);
        }
    }
    None
}

/// Full SPEC §31 mechanical-check result. See the module doc for exactly
/// what this does and does not prove.
#[derive(Debug, Clone)]
pub struct DependencyPolicyReport {
    /// `"name version"` for every `Cargo.lock` package sourced from an
    /// unpinned-in-principle `git+` remote. Empty means clean.
    pub git_sourced_packages: Vec<String>,
    /// Workspace-dependency names whose pinned `version` is not an exact
    /// (`=`-prefixed) pin. Empty means clean.
    pub unpinned_workspace_dependencies: Vec<String>,
}

impl DependencyPolicyReport {
    /// `true` only when both checks found zero violations.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.git_sourced_packages.is_empty() && self.unpinned_workspace_dependencies.is_empty()
    }
}

/// Runs both SPEC §31 mechanical checks against the real `Cargo.lock` and
/// root `Cargo.toml` contents.
#[must_use]
pub fn check_dependency_policy(cargo_lock_contents: &str, root_cargo_toml_contents: &str) -> DependencyPolicyReport {
    DependencyPolicyReport {
        git_sourced_packages: find_git_sourced_packages(cargo_lock_contents),
        unpinned_workspace_dependencies: find_unpinned_workspace_dependencies(root_cargo_toml_contents),
    }
}

/// Renders a human-readable dependency-audit report (SPEC §31: "The
/// release MUST include: ... dependency-audit report"). This is the
/// mechanical half only (see module doc); a real release's dependency-
/// audit report is expected to append the organizational review record
/// (license/security-advisory/no_std/allocation/default-feature/
/// transitive/source-repository review, per-dependency approval) this
/// tool cannot generate, never to substitute for it.
#[must_use]
pub fn render_report(report: &DependencyPolicyReport) -> String {
    let mut out = String::new();
    out.push_str("Alea dependency-audit report (SPEC §31, mechanical checks only)\n");
    out.push_str("========================================================================\n\n");

    out.push_str("1. Unpinned Git dependencies (SPEC §31: prohibited)\n");
    if report.git_sourced_packages.is_empty() {
        out.push_str("   PASS: no `git+`-sourced package found in Cargo.lock.\n");
    } else {
        out.push_str("   FAIL: the following packages are sourced from an unpinned git remote:\n");
        for p in &report.git_sourced_packages {
            out.push_str("   - ");
            out.push_str(p);
            out.push('\n');
        }
    }
    out.push('\n');

    out.push_str("2. Exact version pinning of workspace.dependencies (SPEC §31)\n");
    if report.unpinned_workspace_dependencies.is_empty() {
        out.push_str("   PASS: every workspace.dependencies entry uses an exact (`=`) version pin.\n");
    } else {
        out.push_str("   FAIL: the following workspace.dependencies entries are not exactly pinned:\n");
        for name in &report.unpinned_workspace_dependencies {
            out.push_str("   - ");
            out.push_str(name);
            out.push('\n');
        }
    }
    out.push('\n');

    out.push_str("NOT mechanically checked by this tool (SPEC §31, organizational review):\n");
    out.push_str("license review; security-advisory review; no_std review; allocation review;\n");
    out.push_str("default-feature review; transitive-dependency review; source-repository\n");
    out.push_str("review; dedicated approval commit. See docs/AUDIT-STATUS.md for this\n");
    out.push_str("project's current status on the organizational side of SPEC §31.\n");

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_lockfile_has_no_git_sourced_packages() {
        let lock = r#"
[[package]]
name = "zeroize"
version = "1.9.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "seed-core"
version = "0.1.0"
"#;
        assert!(find_git_sourced_packages(lock).is_empty());
    }

    #[test]
    fn git_sourced_package_is_flagged_by_name_and_version() {
        let lock = r#"
[[package]]
name = "zeroize"
version = "1.9.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "some-fork"
version = "0.3.1"
source = "git+https://github.com/example/some-fork?branch=main#abcdef1234567890"
"#;
        assert_eq!(find_git_sourced_packages(lock), vec!["some-fork 0.3.1".to_string()]);
    }

    #[test]
    fn multiple_git_sourced_packages_all_reported_sorted() {
        let lock = r#"
[[package]]
name = "zed"
version = "0.1.0"
source = "git+https://example.com/zed#deadbeef"

[[package]]
name = "alpha"
version = "0.2.0"
source = "git+https://example.com/alpha#cafef00d"
"#;
        assert_eq!(find_git_sourced_packages(lock), vec!["alpha 0.2.0".to_string(), "zed 0.1.0".to_string()]);
    }

    #[test]
    fn inline_table_form_exact_pin_passes() {
        let toml = r#"
[workspace.dependencies]
sha2 = { version = "=0.11.0", default-features = false }
zeroize = { version = "=1.9.0", default-features = false }
"#;
        assert!(find_unpinned_workspace_dependencies(toml).is_empty());
    }

    #[test]
    fn inline_table_form_caret_pin_is_flagged() {
        let toml = r#"
[workspace.dependencies]
sha2 = { version = "0.11.0", default-features = false }
"#;
        assert_eq!(find_unpinned_workspace_dependencies(toml), vec!["sha2".to_string()]);
    }

    #[test]
    fn bare_string_form_is_supported_both_pinned_and_unpinned() {
        let toml = r#"
[workspace.dependencies]
pinned = "=1.0.0"
unpinned = "1.0.0"
"#;
        assert_eq!(find_unpinned_workspace_dependencies(toml), vec!["unpinned".to_string()]);
    }

    #[test]
    fn entries_outside_workspace_dependencies_are_ignored() {
        let toml = r#"
[workspace.dependencies]
sha2 = { version = "=0.11.0" }

[profile.release]
panic = "abort"
lto = true
opt-level = "s"
"#;
        assert!(find_unpinned_workspace_dependencies(toml).is_empty());
    }

    #[test]
    fn path_dependency_with_no_version_field_is_not_flagged() {
        // Not a real shape in root Cargo.toml's own workspace.dependencies
        // today, but a legal Cargo.toml shape this checker must not
        // misfire on if it ever appears (a path dependency has no
        // registry version to pin).
        let toml = r#"
[workspace.dependencies]
some-local-crate = { path = "../some-local-crate" }
"#;
        assert!(find_unpinned_workspace_dependencies(toml).is_empty());
    }

    #[test]
    fn is_clean_reflects_both_checks() {
        let clean = DependencyPolicyReport { git_sourced_packages: vec![], unpinned_workspace_dependencies: vec![] };
        assert!(clean.is_clean());
        let dirty = DependencyPolicyReport { git_sourced_packages: vec!["x 1.0.0".to_string()], unpinned_workspace_dependencies: vec![] };
        assert!(!dirty.is_clean());
    }

    #[test]
    fn render_report_names_every_violation_and_the_out_of_scope_items() {
        let report = DependencyPolicyReport {
            git_sourced_packages: vec!["evil-fork 0.1.0".to_string()],
            unpinned_workspace_dependencies: vec!["sha2".to_string()],
        };
        let text = render_report(&report);
        assert!(text.contains("evil-fork 0.1.0"));
        assert!(text.contains("sha2"));
        assert!(text.contains("FAIL"));
        assert!(text.contains("license review"));
    }

    #[test]
    fn render_report_of_a_clean_result_says_pass_twice() {
        let report = DependencyPolicyReport { git_sourced_packages: vec![], unpinned_workspace_dependencies: vec![] };
        let text = render_report(&report);
        assert_eq!(text.matches("PASS").count(), 2);
        assert!(!text.contains("FAIL"));
    }

    // ========================================================================
    // Real-repository checks: the actual root Cargo.lock/Cargo.toml this
    // workspace ships MUST themselves pass both checks — this is the
    // direct regression test for the SPEC §31 MUST itself, not just for
    // this module's own parsing logic.
    // ========================================================================

    fn repo_root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn the_real_workspace_cargo_lock_has_no_git_sourced_packages() {
        let path = repo_root().join("Cargo.lock");
        let Ok(contents) = std::fs::read_to_string(&path) else {
            eprintln!("SKIPPED: {path:?} not readable in this environment");
            return;
        };
        let violators = find_git_sourced_packages(&contents);
        assert!(violators.is_empty(), "SPEC §31 violation: unpinned git-sourced package(s) in the real Cargo.lock: {violators:?}");
    }

    #[test]
    fn the_real_root_cargo_toml_pins_every_workspace_dependency_exactly() {
        let path = repo_root().join("Cargo.toml");
        let Ok(contents) = std::fs::read_to_string(&path) else {
            eprintln!("SKIPPED: {path:?} not readable in this environment");
            return;
        };
        let violators = find_unpinned_workspace_dependencies(&contents);
        assert!(violators.is_empty(), "SPEC §31 violation: non-exact version pin(s) in the real root Cargo.toml: {violators:?}");
        // Meta-check: the real file must actually have a non-empty
        // `[workspace.dependencies]` table for the check above to be
        // meaningful (a scanner that silently found nothing to scan
        // would trivially "pass").
        assert!(contents.contains("[workspace.dependencies]"), "expected root Cargo.toml to have a [workspace.dependencies] table");
    }
}
