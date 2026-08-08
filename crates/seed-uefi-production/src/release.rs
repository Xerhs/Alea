//! Release identification and the SPEC §2 experimental-software banner.
//!
//! Both are displayed pre-secret, before any generation gate runs (SPEC
//! §4.1: "Display its release version and immutable build identifier
//! before secret generation"; SPEC §2: "Before stable-release gates are
//! satisfied, every production-capable build MUST display" the banner
//! below).

/// SPEC §2, verbatim (the blockquote's bold title line).
pub const EXPERIMENTAL_BANNER_TITLE: &str = "EXPERIMENTAL SECURITY SOFTWARE";

/// SPEC §2, verbatim (the blockquote's body, unwrapped to one logical
/// value via line-continuation — the same convention `seed-flow`'s own
/// `text.rs` uses for its other verbatim SPEC quotes, e.g.
/// `REQUIRED_WARNING_8_4`).
pub const EXPERIMENTAL_BANNER_BODY: &str = "This build has not completed the stable-release security gates. Do not \
use it to protect substantial funds.";

/// SPEC §4.1 "release version" — this crate's own `Cargo.toml` `version`
/// field, set by Cargo at compile time. Always present (Cargo always
/// defines `CARGO_PKG_VERSION`), so a plain `env!` — not `option_env!` —
/// is correct here: a build missing it is not a build that should
/// silently substitute a placeholder, it is a broken build.
pub const RELEASE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// See [`BUILD_ID`]: the fixed value substituted when the release
/// pipeline has not injected a real build identifier.
///
/// Deliberately shaped so it can never be confused with a genuine
/// pipeline-issued identifier: fixed length, an unmistakable `UNSET`
/// prefix, and a run of zeros where a real identifier
/// (`IMPLEMENTATION_MAP.md` WP-32 / `tools/release-verifier/`) would
/// place a content hash or release-tag-derived value.
pub const UNSET_BUILD_ID_PLACEHOLDER: &str = "UNSET-LOCAL-BUILD-0000000000000000";

/// SPEC §4.1 "immutable build identifier".
///
/// # Deterministic placeholder scheme
///
/// The signed-release pipeline (`IMPLEMENTATION_MAP.md` WP-32,
/// `tools/release-verifier/`) is expected to set the
/// `ALEA_BUILD_ID` environment variable at build time — e.g. to a
/// content hash of the reproducible build inputs, or a release-tag-
/// derived identifier — so this constant carries that value verbatim via
/// `option_env!`. A *missing* build-time env var must never fail
/// compilation the way a bare `env!` would: an ordinary
/// `cargo build -p seed-uefi-production` run outside that pipeline (this
/// work package's own DoD check, or any contributor's local build) must
/// still succeed.
///
/// When `ALEA_BUILD_ID` is unset, this deterministically evaluates
/// to [`UNSET_BUILD_ID_PLACEHOLDER`] instead of an empty string, a
/// timestamp, or any other value that could vary build-to-build. The
/// placeholder is fixed and identical across every unofficial build, so
/// it can never be mistaken for a genuine signed-release identifier and
/// never itself breaks build reproducibility — WP-32's two-build
/// determinism check compares two *identically invoked* builds, both of
/// which take this same `None` branch identically whenever the pipeline
/// does not set the variable.
pub const BUILD_ID: &str = match option_env!("ALEA_BUILD_ID") {
    Some(id) => id,
    None => UNSET_BUILD_ID_PLACEHOLDER,
};
