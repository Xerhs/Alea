#!/usr/bin/env bash
# Alea CI. Toolchain/environment provisioning is in
# .github/workflows/ci.yml (global cargo linker config for musl host
# builds; no QEMU).
set -euo pipefail

# Hosted CI runners preinstall rustup system-wide without ~/.cargo/env;
# only source it where it exists (local dev installs), never hard-fail on it.
if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
fi

: "${CARGO_TARGET_DIR:=$HOME/.cache/sf-target/ci}"
export CARGO_TARGET_DIR
echo "== CARGO_TARGET_DIR=$CARGO_TARGET_DIR =="

# The repo's host-build convention is the musl target (static, rust-lld,
# no system-cc dependency). The dev
# machine pins this in its global ~/.cargo/config.toml; a stock clone has
# no such global config, so pin it here for everyone (the scanner_bin
# path below depends on it). Explicit --target flags (x86_64-unknown-uefi,
# wasm32-unknown-unknown) override per invocation as usual. Needs the musl
# target (rust-toolchain.toml pins it) and a musl-capable linker driver
# (Debian/Ubuntu: `apt install musl-tools`).
: "${CARGO_BUILD_TARGET:=x86_64-unknown-linux-musl}"
export CARGO_BUILD_TARGET

cd "$(dirname "${BASH_SOURCE[0]}")"

# seed-uefi-production, seed-uefi-test and alea-verify are
# `#![no_std] #![no_main]` UEFI binaries: they have no host entry point and
# cannot unwind without `std`, so they are structurally unbuildable for the
# default host target (confirmed: building them at the default target fails
# with "unwinding panics are not supported without std", independent of any
# WP logic). They are excluded from the generic host build/test steps below
# and built explicitly for `x86_64-unknown-uefi` further down instead — that
# `--target` build is the real, meaningful check for these three crates.
UEFI_BIN_EXCLUDES=(--exclude seed-uefi-production --exclude seed-uefi-test --exclude alea-verify)

echo "== cargo build --workspace (excluding UEFI-only binaries; see above) =="
cargo build --workspace "${UEFI_BIN_EXCLUDES[@]}"

echo "== cargo test --workspace (excluding UEFI-only binaries; see above) =="
cargo test --workspace "${UEFI_BIN_EXCLUDES[@]}"

echo "== cargo build -p seed-uefi-test --target x86_64-unknown-uefi =="
cargo build -p seed-uefi-test --target x86_64-unknown-uefi

echo "== cargo build -p seed-uefi-production --target x86_64-unknown-uefi =="
cargo build -p seed-uefi-production --target x86_64-unknown-uefi

echo "== cargo build -p alea-verify --target x86_64-unknown-uefi =="
cargo build -p alea-verify --target x86_64-unknown-uefi

# Task 19 review fix: `alea-verify`'s BINARY (`src/main.rs`) is still
# `#![no_std] #![no_main]` with its own `#[panic_handler]` and stays outside
# UEFI_BIN_EXCLUDES's blanket `cargo test --workspace` for the same reason
# as `seed-uefi-production`/`seed-uefi-test` above. But its screen-rendering/
# dispatch logic now lives in a separate, host-testable LIBRARY target
# (`src/lib.rs`, `#![cfg_attr(not(test), no_std)]` -- see that file's own
# doc comment), which `--workspace` doesn't reach either (the whole package
# is excluded, not just its bin target) -- so it needs its own explicit
# `--lib`-scoped invocation here.
echo "== cargo test -p alea-verify --lib (host-testable library target only) =="
cargo test -p alea-verify --lib

echo "== binary-policy-scanner release gate (SPEC §28) =="
# SPEC §28: "release artifacts are scanned for deterministic vectors and
# debug commands" / "binary-policy scanner checks for forbidden symbols,
# strings and sections". Gap-audit finding (spec-conformance audit,
# 2026-08-04): `binary-policy-scanner` existed with real unit + integration
# coverage (`tools/binary-policy-scanner/tests/scan_real_efi.rs`) but was
# never invoked from this script, and that integration test looks for
# artifacts under `.../x86_64-unknown-uefi/release/` while the two builds
# above are debug-profile -- so under the previously-checked-in CI flow the
# integration test always silently SKIPPED and the scanner was never
# actually exercised as a release gate. Fixed by (1) building both UEFI
# targets in `--release` profile (the profile release artifacts actually
# ship in) so the skip-tolerant integration test runs for real, and (2)
# additionally invoking the compiled scanner binary directly against both
# artifacts here with a hard (non-skippable) pass/fail assertion, so a
# regression in either the build step or the scanner itself fails CI
# instead of silently no-op'ing.
echo "-- cargo build -p seed-uefi-test --target x86_64-unknown-uefi --release --"
cargo build -p seed-uefi-test --target x86_64-unknown-uefi --release

echo "-- cargo build -p seed-uefi-production --target x86_64-unknown-uefi --release --"
cargo build -p seed-uefi-production --target x86_64-unknown-uefi --release

echo "-- cargo build -p alea-verify --target x86_64-unknown-uefi --release --"
cargo build -p alea-verify --target x86_64-unknown-uefi --release

echo "-- cargo build -p binary-policy-scanner --release --"
cargo build -p binary-policy-scanner --release

scanner_bin="$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/binary-policy-scanner"
uefi_release_dir="$CARGO_TARGET_DIR/x86_64-unknown-uefi/release"
production_efi="$uefi_release_dir/seed-uefi-production.efi"
test_efi="$uefi_release_dir/seed-uefi-test.efi"

for f in "$scanner_bin" "$production_efi" "$test_efi"; do
    if [ ! -f "$f" ]; then
        echo "FAIL: expected release artifact missing: $f"
        exit 1
    fi
done

echo "-- scanning seed-uefi-production.efi (MUST pass) --"
if ! "$scanner_bin" "$production_efi"; then
    echo "FAIL: seed-uefi-production.efi failed the binary-policy scan (SPEC §28)."
    exit 1
fi
echo "PASS: seed-uefi-production.efi passed the binary-policy scan."

echo "-- scanning seed-uefi-test.efi (MUST fail: it carries the test-edition watermark) --"
if "$scanner_bin" "$test_efi"; then
    echo "FAIL: seed-uefi-test.efi unexpectedly PASSED the binary-policy scan -- the"
    echo "      test-edition watermark/banner is no longer being detected (SPEC §28)."
    exit 1
fi
echo "PASS: seed-uefi-test.efi was correctly rejected by the binary-policy scan."

echo "-- cargo test -p binary-policy-scanner (exercises tests/scan_real_efi.rs for real) --"
cargo test -p binary-policy-scanner

echo "== production/test isolation check (SPEC §9, §28) =="
# seed-uefi-production MUST NOT depend on seed-uefi-test, seed-desktop-test
# or seed-test-vectors, directly or transitively.
#
# WP-27: seed-uefi-production legitimately depends on `seed-flow`
# (`crates/seed-flow/`, the shared host-testable flow-logic library
# WP-25/26 own). This crate lives at a top-level, edition-neutral path
# specifically so no path-sourced dependency of seed-uefi-production ever
# points inside the seed-uefi-test/seed-desktop-test directory trees --
# it used to live nested at `crates/seed-uefi-test/flow/`, which meant
# its own manifest *path* contained the substring "seed-uefi-test" as a
# directory component and could, in principle, have been misreported as
# a forbidden dependency by a naive substring grep against `cargo tree`'s
# human-readable output (which prints each path-sourced package's
# manifest path in parentheses); moving the crate out removed that risk
# at the source rather than only working around it here. The pattern
# below still anchors on "<name> v<digit>" -- the shape `cargo tree`
# always prints immediately after each node's own package name -- as
# defense in depth: it matches a genuine `seed-uefi-test`/
# `seed-desktop-test`/`seed-test-vectors` package node but never an
# unrelated package's manifest-path substring, regardless of where any
# future crate happens to live on disk. See
# `crates/seed-uefi-production/Cargo.toml`'s own doc comment for why the
# `seed-flow` dependency itself is safe (its one `seed-test-vectors`
# reference is a `[dev-dependencies]` entry, never built for a downstream
# crate).
forbidden_pattern='\b(seed-uefi-test|seed-desktop-test|seed-test-vectors) v[0-9]'
tree_output="$(cargo tree -p seed-uefi-production --target x86_64-unknown-uefi)"
echo "$tree_output"
if echo "$tree_output" | grep -E "$forbidden_pattern" >/dev/null; then
    echo "FAIL: seed-uefi-production dependency graph contains a forbidden test crate:"
    echo "$tree_output" | grep -E "$forbidden_pattern"
    exit 1
fi
echo "PASS: seed-uefi-production graph is clean of test crates."

# Compat-surface isolation: mirrors the isolation check directly above,
# for the seed-compat surface instead of
# the test/desktop-test surface. seed-uefi-production MUST NOT depend on
# seed-compat, seed-compat-vectors, or compat-verify, directly or
# transitively -- the entire point of SPEC_COMPAT's scope cut (§9: "Cut
# from v0.6 ... the UEFI test edition compat surface"). Reuses
# `$tree_output` from the check immediately above (same `cargo tree -p
# seed-uefi-production --target x86_64-unknown-uefi` invocation) and the
# same "<name> v<digit>" anchor pattern so a package whose manifest *path*
# merely contains one of these substrings can never produce a false
# positive here either, regardless of where any crate lives on disk.
compat_forbidden_pattern='\b(seed-compat|seed-compat-vectors|compat-verify) v[0-9]'
if echo "$tree_output" | grep -E "$compat_forbidden_pattern" >/dev/null; then
    echo "FAIL: seed-uefi-production dependency graph contains a forbidden seed-compat crate:"
    echo "$tree_output" | grep -E "$compat_forbidden_pattern"
    exit 1
fi
echo "PASS: seed-uefi-production graph is clean of seed-compat crates (SPEC_COMPAT §9)."

# WP-27 (SPEC §4.1-4.2, §28): no feature named "test-edition" (or any
# other test-only/public-vector/watermark feature) may be *enabled* on
# seed-uefi-production's resolved build -- `cargo tree -e features`
# lists each activated feature in brackets next to its owning package;
# grep confirms none of the reserved test-only feature names appear
# there. (`seed-flow`'s own `test-edition` feature -- see its
# `Cargo.toml` -- defaults off and `seed-uefi-production/Cargo.toml`
# never requests it.)
features_output="$(cargo tree -p seed-uefi-production --target x86_64-unknown-uefi -e features)"
if echo "$features_output" | grep -E 'test-edition|public-vector' >/dev/null; then
    echo "FAIL: seed-uefi-production has a forbidden test-only feature enabled:"
    echo "$features_output" | grep -E 'test-edition|public-vector'
    exit 1
fi
echo "PASS: seed-uefi-production has no test-only feature enabled."

echo "== hidden entropy-vector source scan (SPEC §28: no hidden keyboard sequence,"
echo "   CLI param, environment variable, or UEFI variable that changes entropy"
echo "   behavior) =="
# Positive, forward-looking scanner rule for the second half of SPEC §28's
# "the production UI has no hidden keyboard sequence, command-line
# parameter, environment variable or UEFI variable that changes entropy
# behavior" requirement. `binary-policy-scanner` (above) already covers the
# deterministic-vector half (`FORBIDDEN_VECTOR_MARKERS`); this half
# previously had no positive rule at all -- only the current structural
# absence of such code (spec-conformance audit finding, 2026-08-04: "only
# its current absence [was enforced], [not] a positive scanner rule ...
# going forward"). Greps every production-reachable crate's `src/` tree
# (the same crates `seed-uefi-production`'s own dependency graph pulls in
# -- see the isolation check above) for any build-time/runtime
# environment-variable read or UEFI `GetVariable` call, and fails unless
# every hit is one of the two already-reviewed, non-entropy-affecting,
# display-only uses in `seed-uefi-production/src/release.rs`
# (`CARGO_PKG_VERSION` release-version string, `ALEA_BUILD_ID`
# build identifier -- see that file's own doc comments) or lives inside a
# `#[cfg(test)]`-gated test helper (never compiled into the shipped
# binary, regardless of dependency graph, because `#[cfg(test)]` code is
# only ever compiled when its *own* crate is being tested).
PRODUCTION_SRC_DIRS=(
    crates/seed-uefi-production/src
    crates/seed-core/src
    crates/seed-derive/src
    crates/seed-protocol/src
    crates/seed-platform-x86/src
    crates/seed-gop-ui/src
    crates/seed-flow/src
    crates/seed-selftest/src
)
env_hits="$(grep -rnE 'option_env!|env!\(|std::env::|::env::(var|args)' "${PRODUCTION_SRC_DIRS[@]}" || true)"
# Known-reviewed, non-entropy-affecting exception (SPEC §4.1 release
# version + build identifier display).
unreviewed_env_hits="$(echo "$env_hits" | grep -v 'crates/seed-uefi-production/src/release\.rs' || true)"
# `env!("CARGO_MANIFEST_DIR")` is a COMPILE-TIME, cargo-provided build path,
# not a runtime input, and it changes no entropy behavior. In these no_std
# crates it appears ONLY inside `#[cfg(test)]` fixture/source-loading helpers
# (the std path APIs it feeds are unavailable outside `test`), so this one
# build-path env is allowlisted categorically. Every OTHER env read -- any
# `std::env::`, any `option_env!`, or any `env!(...)` of a different
# variable -- still fails the build.
unreviewed_env_hits="$(echo "$unreviewed_env_hits" | grep -v 'CARGO_MANIFEST_DIR' || true)"
if [ -n "$unreviewed_env_hits" ]; then
    echo "FAIL: unreviewed environment-variable read found in the production-reachable"
    echo "      source tree (SPEC §28: no hidden env var may change entropy behavior):"
    echo "$unreviewed_env_hits"
    exit 1
fi
echo "PASS: no unreviewed environment-variable reads in the production-reachable source tree."

uefi_var_hits="$(grep -rnE 'GetVariable|get_variable' "${PRODUCTION_SRC_DIRS[@]}" || true)"
# SPEC §28 reviewed exception (2026-08-09), count-capped like the
# exclusive-open allowlist below: `firmware_wiring.rs` may contain exactly
# TWO `get_variable` calls — the read-only, display-only SecureBoot /
# SetupMode reads feeding the §22.3 recap's Secure Boot line
# (`secure_boot_status()`; full rationale in
# tools/binary-policy-scanner/tests/no_hidden_entropy_toggle_source_audit.rs
# `REVIEWED_EXCEPTIONS`). A third occurrence in that file, or any hit in
# any other file, still fails — and `SetVariable`/`set_variable` are not
# excepted anywhere (that suite's own scan keeps banning them outright).
reviewed_wiring_count="$(echo "$uefi_var_hits" | grep -c 'crates/seed-flow/src/firmware_wiring.rs' || true)"
unreviewed_uefi_var_hits="$(echo "$uefi_var_hits" | grep -v 'crates/seed-flow/src/firmware_wiring.rs' || true)"
if [ "$reviewed_wiring_count" -gt 2 ]; then
    echo "FAIL: firmware_wiring.rs exceeds its reviewed 2-call UEFI-variable-read cap"
    echo "      (SPEC §28); extend the reviewed exception (a re-review), don't just add calls:"
    echo "$uefi_var_hits" | grep 'crates/seed-flow/src/firmware_wiring.rs'
    exit 1
fi
if [ -n "$unreviewed_uefi_var_hits" ]; then
    echo "FAIL: unreviewed UEFI variable read found in the production-reachable source"
    echo "      tree (SPEC §28: no hidden UEFI variable may change entropy behavior):"
    echo "$unreviewed_uefi_var_hits"
    exit 1
fi
echo "PASS: no unreviewed UEFI GetVariable calls in the production-reachable source tree."

echo "== private/machine-data scan (public-repo hygiene) =="
# This is a PUBLIC repository: no tracked file may leak an author-local path,
# username, personal email, or a specific developer machine hostname. The
# GitHub-hosted CI runner path (/home/runner) and generic hardware-vendor
# names (an OEM firmware family the console path documents handling) are
# legitimate and deliberately NOT matched. Scans tracked files only. The
# final character of each sensitive literal below is wrapped in a one-char
# class so this pattern string does not flag itself.
private_hits="$(git grep -nI -E '/mnt/[a-z]|/home/car[r]|[Cc]arro[t]?|fedora-lapto[p]|iwnlaio[s]|limos_buzzer[s]|@(gmail|icloud|yahoo|hotmail|outlook)\.co[m]' -- . || true)"
if [ -n "$private_hits" ]; then
    echo "FAIL: private/machine information found in tracked files — must not ship in a"
    echo "      public repo (remove the path/username/email/hostname before pushing):"
    echo "$private_hits"
    exit 1
fi
echo "PASS: no private/machine information in tracked files."

echo "== exclusive-GOP-open source scan (SPEC §11.4: firmware-console-survival"
echo "   regression guard) =="
# Real-hardware field failure (Phoenix-class OEM firmware, confirmed by a
# step-by-step UEFI probe): `boot::open_protocol_exclusive`/
# `OpenProtocolAttributes::Exclusive` on a GOP-derived handle triggers UEFI
# `DisconnectController` against that handle's `ByDriver` opener -- the
# firmware's own console driver -- which tears the firmware text console
# down for the rest of boot with no error. `seed-gop-ui`'s
# `gop/backend.rs` (the SPEC §11.4 GOP open used by both the pre-secret
# graphics gate and the secret-phase framebuffer open) was fixed to open
# every protocol it touches (`GraphicsOutput`, `DevicePath`,
# `DevicePathToText`) non-exclusively instead -- see that file's module
# doc comment for the full rationale (exclusive access buys no
# confidentiality: console drivers only ever *write* toward the GOP).
# This is a forward-looking scanner rule, same shape as the GetVariable
# gate immediately above: it fails on any *new* `open_protocol_exclusive`
# call in the production-reachable source tree, so the bug class cannot
# silently creep back in through a different call site.
#
# Two pre-existing, already-reviewed, non-GOP uses are unrelated to this
# bug class and stay exclusive deliberately (neither is reachable from a
# console-rendered screen the way the GOP open is): `seed-platform-x86`'s
# `EFI_RNG_PROTOCOL` locate (`rng/efi_rng.rs`, SPEC §15.1 -- exclusive so
# no other agent can interleave calls against the same RNG instance
# mid-sample) and its PCI bus-zero device-ID scan
# (`virt/devpath.rs`, `PciRootBridgeIo` -- a diagnostic-only bus walk, not
# a display/console-adjacent protocol). Any *other* new hit fails the
# build; a reviewer adding a third legitimate exception must extend this
# allowlist explicitly, by file, the same way the env-var scanner above
# does.
# Matches only actual invocation syntax (`open_protocol_exclusive::<...>(`
# or a bare `open_protocol_exclusive(` call) so doc comments that merely
# *discuss* the symbol -- e.g. this file's own explanation above, and the
# rationale comments in gop/backend.rs and console/mod.rs documenting why
# it is deliberately avoided -- do not self-trigger the gate.
exclusive_hits="$(grep -rnE 'open_protocol_exclusive\s*(::<|\()' "${PRODUCTION_SRC_DIRS[@]}" || true)"
unreviewed_exclusive_hits="$(echo "$exclusive_hits" \
    | grep -v 'crates/seed-platform-x86/src/rng/efi_rng\.rs' \
    | grep -v 'crates/seed-platform-x86/src/virt/devpath\.rs' \
    || true)"
if [ -n "$unreviewed_exclusive_hits" ]; then
    echo "FAIL: unreviewed open_protocol_exclusive call found in the production-reachable"
    echo "      source tree (SPEC §11.4: exclusive GOP opens disconnect the firmware"
    echo "      console driver on real hardware -- see gop/backend.rs's module doc"
    echo "      before reintroducing this, and stage any real need at the"
    echo "      MnemonicDisplay boundary only, OEM-hardware-validated first):"
    echo "$unreviewed_exclusive_hits"
    exit 1
fi
echo "PASS: no unreviewed open_protocol_exclusive calls in the production-reachable source tree."

echo "== no FirmwareTextOutput construction on the normal boot path (SPEC.md amendment"
echo "   2026-08-06: GOP-rendered pre-secret + secret-phase UI) =="
# SPEC.md amendment 2026-08-06: both UEFI editions now render the entire
# ceremony (banner, opening warning, acknowledgements, mandatory gates,
# diagnostics, selections, AND every secret-phase screen prior to
# `AppState::MnemonicDisplay`) through the GOP linear framebuffer via
# `seed_flow::output::FbTextOutput`, never `seed_flow::firmware_wiring::
# FirmwareTextOutput`, which now exists only as a defined-but-unconstructed
# type (kept for the crate's own test doubles / any future reviewed
# refusal-path use). The one remaining firmware-text-output call on the
# normal boot path is `seed_platform_x86::boot::uefi_backend::
# print_banner_to_stdout`, used solely by `main.rs`'s `open_session_gop`
# failure arm (no framebuffer exists yet to draw that refusal onto) --
# that call does not construct `FirmwareTextOutput` and is unaffected by
# this gate. This is a forward-looking scanner rule, same shape as the
# two gates immediately above: it fails on ANY `FirmwareTextOutput::new(`
# call site in the production-reachable source tree, so the firmware-
# console-rendered normal path (the exact black-screen-on-Phoenix-class-
# hardware risk this whole amendment removes) cannot silently creep back
# in through a new call site.
# Scanned separately from `PRODUCTION_SRC_DIRS` (which deliberately
# excludes `seed-uefi-test/src` -- see that array's own comment): this
# gate is a UI-rendering/hardware-safety property both UEFI editions must
# share byte-parallel, not a production-only isolation property, so both
# editions' own `main.rs`/`flow_pre`/`flow_secret` wiring are scanned here
# alongside the shared `seed-flow` definition site.
FIRMWARE_TEXT_OUTPUT_SCAN_DIRS=(
    "${PRODUCTION_SRC_DIRS[@]}"
    crates/seed-uefi-test/src
)
firmware_text_output_hits="$(grep -rnE 'FirmwareTextOutput::new\s*\(' "${FIRMWARE_TEXT_OUTPUT_SCAN_DIRS[@]}" || true)"
if [ -n "$firmware_text_output_hits" ]; then
    echo "FAIL: FirmwareTextOutput construction found in the production-reachable source"
    echo "      tree (SPEC.md amendment 2026-08-06: the normal boot path renders"
    echo "      everything through the GOP framebuffer via FbTextOutput; firmware text"
    echo "      output survives only as seed_platform_x86::boot::uefi_backend::"
    echo "      print_banner_to_stdout, used solely for the pre-framebuffer GOP-open"
    echo "      refusal in main.rs):"
    echo "$firmware_text_output_hits"
    exit 1
fi
echo "PASS: no FirmwareTextOutput construction anywhere in the production-reachable source tree."

echo "== standalone security suites: fault-injection (SPEC §29.5) + leakage (SPEC §29.6) =="
# SPEC §29.5 (fault-injection tests, WP-33: tests/fault-injection/) and
# SPEC §29.6 (leakage tests, WP-34: tests/leakage/) are DELIBERATELY their
# own standalone Cargo workspaces, not members of the root workspace: the
# root Cargo.toml members list is owned by WP-00, so each suite carries a
# bare [workspace] table (stopping Cargo's upward workspace search) and its
# own committed Cargo.lock — see the doc comments in
# tests/fault-injection/Cargo.toml and tests/leakage/Cargo.toml. That
# design means `cargo test --workspace` above NEVER runs them; they must
# be invoked against their own manifests, which is what this stage does
# (publish-readiness audit finding, 2026-08-06: both suites existed and
# passed when run by hand, but nothing automated ever ran them — and they
# had silently stopped compiling against API drift).
#
# Same dedicated-target-dir pattern as the web gate below: each suite gets
# its own subdir under $CARGO_TARGET_DIR so the standalone workspaces'
# locks/fingerprints never thrash the root workspace's cache (the leakage
# suite resolves seed-gop-ui with the `uefi-backend` feature — a different
# feature set than the root workspace builds, which would otherwise force
# rebuild churn in a shared target dir).
echo "-- cargo test tests/fault-injection (SPEC §29.5 modeled-failure matrix, WP-33) --"
CARGO_TARGET_DIR="$CARGO_TARGET_DIR/standalone-fault-injection" \
    cargo test --manifest-path tests/fault-injection/Cargo.toml \
    || { echo "FAIL: fault-injection suite failed (SPEC §29.5)."; exit 1; }
echo "PASS: fault-injection suite (SPEC §29.5)."

# The leakage suite locates the --release x86_64-unknown-uefi artifacts it
# scans via the CARGO_TARGET_DIR the test process inherits, and rebuilds
# them itself when they are absent — see find_or_build_release_uefi_artifact
# in tests/leakage/tests/forbidden_uefi_interfaces.rs. With the dedicated
# subdir below that costs one extra UEFI release build on a cold cache —
# accepted, so the suite's own workspace never touches the main cache.
echo "-- cargo test tests/leakage (SPEC §29.6 leakage suite, WP-34) --"
CARGO_TARGET_DIR="$CARGO_TARGET_DIR/standalone-leakage" \
    cargo test --manifest-path tests/leakage/Cargo.toml \
    || { echo "FAIL: leakage suite failed (SPEC §29.6)."; exit 1; }
echo "PASS: leakage suite (SPEC §29.6)."

echo "== supply-chain / dependency-audit gate (SPEC §31) =="
# SPEC §31 requires a dependency-audit report and prohibits unpinned/unreviewed
# dependencies. Two complementary, machine-checkable gates:
#
#  (a) the mechanical §31 policy checker (tools/release-verifier dependency-audit
#      bin): no git-sourced package, and every [workspace.dependencies] entry is
#      pinned with `=`. This tool existed but was never invoked from CI (a real
#      gap); it is wired in here so a regression fails the build.
#  (b) `cargo vet --locked --frozen`: asserts EVERY crate in the resolved graph
#      is either audited in supply-chain/audits.toml or carried as an explicit
#      exemption in supply-chain/config.toml — so an unreviewed new/bumped
#      dependency fails CI instead of entering the build silently. The store
#      imports no external audit sets (supply-chain/imports.lock is empty), so
#      --locked --frozen runs fully offline and deterministically.
echo "-- (a) mechanical §31 policy checker (no git deps; exact-pinned workspace deps) --"
cargo run --quiet -p release-verifier --bin dependency-audit -- Cargo.lock Cargo.toml \
    || { echo "FAIL: SPEC §31 dependency-policy check failed (git-sourced or unpinned dependency)."; exit 1; }

echo "-- (b) cargo vet --locked --frozen (supply-chain audit record) --"
if ! command -v cargo-vet >/dev/null 2>&1; then
    echo "FAIL: cargo-vet not installed — required for the SPEC §31 supply-chain gate."
    echo "      musl-gcc is absent on this host, so install for the gnu target:"
    echo "        CARGO_BUILD_TARGET=x86_64-unknown-linux-gnu cargo install cargo-vet --locked"
    exit 1
fi
# cargo-vet's internal `cargo metadata` needs every manifest in the FULL
# cross-platform dependency graph — including target-gated crates (e.g.
# android-activity via winit) that a Linux build never downloads — so on a
# cold registry cache the frozen run below would die trying to fetch
# (observed on the first hosted-CI run, 2026-08-06). Prefetch the whole
# locked graph explicitly HERE, so the vet run itself stays --frozen
# (fully offline and lockfile-asserting).
cargo fetch --locked
cargo vet --locked --frozen \
    || { echo "FAIL: cargo vet found an unaudited/unexempted dependency (SPEC §31). See supply-chain/README.md."; exit 1; }
echo "PASS: supply-chain dependency-audit gate (mechanical §31 policy + cargo vet)."

echo "== web offline edition: reproducible-build + correctness gate =="
echo "   (SPEC_WEB_OFFLINE §10 reproducible build, §11.8 non-reproducible build is"
echo "    a HARD prohibition)"
# The offline web edition (web/) is a NORMATIVELY reproducible artifact:
# SPEC_WEB_OFFLINE §5.2 pins its toolchain (rustc flags + binaryen version_119 +
# the exact wasm-opt flags + a deterministic inliner) and §11.8 makes a
# non-reproducible / unverifiable build a HARD prohibition. This gate enforces
# that end to end:
#   1. the pinned toolchain is actually present (wasm32 target, wasm-opt
#      version_119, node) — a hard FAIL if any is missing;
#   2. two CLEAN rebuilds produce byte-identical .wasm and alea-web-offline.html
#      (the SPEC §10 reproducible-build assertion — same source => same bytes);
#   3. the freshly built alea-web-offline.html matches the copy committed in the
#      source tree (no drift between source and the shipped, hash-published
#      artifact);
#   4. the OPTIMIZED wasm (the bytes actually embedded in the .html) still
#      derives the frozen public vectors (the node vector harness).
#
# The web build uses its OWN wasm target dir (~/.cache/seedmaker-wasm) — never
# the main $CARGO_TARGET_DIR this script exports above for the UEFI/host builds.
# web/build.sh defaults to that dir, but this script *exports* CARGO_TARGET_DIR,
# which build.sh would otherwise inherit — so each web build below is invoked
# with CARGO_TARGET_DIR overridden back to the dedicated web cache.

# --- toolchain presence (hard gate, §5.2 pins) ---
WASM_OPT_URL="https://github.com/WebAssembly/binaryen/releases/download/version_119/binaryen-version_119-x86_64-linux.tar.gz"
# node runs the vector harness (web/test-wasm.mjs). nvm-managed installs are not
# on a non-login CI PATH by default, so source nvm if node is absent.
if ! command -v node >/dev/null 2>&1 && [ -s "$HOME/.nvm/nvm.sh" ]; then
    # shellcheck disable=SC1091
    . "$HOME/.nvm/nvm.sh"
fi
if ! command -v node >/dev/null 2>&1; then
    echo "FAIL: node not found — required for web/test-wasm.mjs. Install Node (nvm) and retry."
    exit 1
fi
# wasm-opt: reference the pinned install prefix if it is not already on PATH.
if ! command -v wasm-opt >/dev/null 2>&1; then
    export PATH="$HOME/.local/binaryen-version_119/bin:$PATH"
fi
if ! command -v wasm-opt >/dev/null 2>&1; then
    echo "FAIL: wasm-opt (binaryen) not found — required by web/build.sh (SPEC_WEB_OFFLINE §5.2)."
    echo "      Install binaryen version_119 and put its bin/ on PATH:"
    echo "        $WASM_OPT_URL"
    echo "      Verify the download first (from web/, against the downloaded tarball):"
    echo "        sha256sum -c web/binaryen-version_119-x86_64-linux.tar.gz.sha256"
    exit 1
fi
if ! wasm-opt --version | grep -q "version 119"; then
    echo "FAIL: wrong wasm-opt version ($(wasm-opt --version)) — SPEC_WEB_OFFLINE §5.2 pins binaryen version_119."
    echo "        $WASM_OPT_URL"
    exit 1
fi
# wasm32 target must be installed (build.sh cross-compiles seed-web to it).
if ! rustup target list --installed 2>/dev/null | grep -qx wasm32-unknown-unknown; then
    echo "FAIL: rust target wasm32-unknown-unknown is not installed. Run: rustup target add wasm32-unknown-unknown"
    exit 1
fi
echo "PASS: web toolchain present ($(wasm-opt --version), node $(node --version), wasm32 target installed)."

# --- (2) two CLEAN rebuilds -> byte-identical .wasm and .html (SPEC §10) ---
WEB_WASM_DIR="$HOME/.cache/seedmaker-wasm"
WEB_RAW_WASM="$WEB_WASM_DIR/wasm32-unknown-unknown/release/seed_web.wasm"
echo "-- web build #1 (clean) --"
rm -rf "$WEB_WASM_DIR"
CARGO_TARGET_DIR="$WEB_WASM_DIR" bash web/build.sh >/dev/null \
    || { echo "FAIL: web/build.sh failed on build #1."; exit 1; }
web_wasm1="$(sha256sum "$WEB_RAW_WASM" | cut -d' ' -f1)"
web_html1="$(sha256sum web/alea-web-offline.html | cut -d' ' -f1)"

echo "-- web build #2 (clean rebuild — reproducibility assertion) --"
rm -rf "$WEB_WASM_DIR"
CARGO_TARGET_DIR="$WEB_WASM_DIR" bash web/build.sh >/dev/null \
    || { echo "FAIL: web/build.sh failed on build #2."; exit 1; }
web_wasm2="$(sha256sum "$WEB_RAW_WASM" | cut -d' ' -f1)"
web_html2="$(sha256sum web/alea-web-offline.html | cut -d' ' -f1)"

if [ "$web_wasm1" != "$web_wasm2" ]; then
    echo "FAIL: web .wasm is NOT reproducible across clean rebuilds (SPEC §10/§11.8):"
    echo "      build#1 $web_wasm1"
    echo "      build#2 $web_wasm2"
    exit 1
fi
if [ "$web_html1" != "$web_html2" ]; then
    echo "FAIL: alea-web-offline.html is NOT reproducible across clean rebuilds (SPEC §10/§11.8):"
    echo "      build#1 $web_html1"
    echo "      build#2 $web_html2"
    exit 1
fi
echo "PASS: web .wasm and alea-web-offline.html are byte-identical across two clean rebuilds."

# --- (3) source-tree drift: rebuilt .html must equal the committed one ---
# The alea-web-offline.html checked into git IS the shipped artifact — its
# sha256 is published in REPRODUCING.md and in the web edition's signed
# SHA256SUMS. If a rebuild from committed source no longer matches the committed
# file, the shipped artifact is stale and MUST be re-committed.
if ! git diff --quiet HEAD -- web/alea-web-offline.html; then
    echo "FAIL: rebuilt web/alea-web-offline.html differs from the git-committed artifact."
    echo "      The shipped file is out of date with its source. Re-run 'bash web/build.sh'"
    echo "      and commit the regenerated web/alea-web-offline.html."
    exit 1
fi
echo "PASS: committed web/alea-web-offline.html matches a fresh rebuild (no source/artifact drift)."

# --- (4) correctness: optimized wasm still derives the frozen public vectors ---
# Run the harness against the OPTIMIZED wasm (web/seed_web.opt.wasm) — the exact
# bytes embedded in the shipped .html — so this proves the SHIPPED module, not
# just the pre-wasm-opt intermediate, reproduces the frozen vectors.
echo "-- node web/test-wasm.mjs (optimized-wasm vector parity) --"
if ! node web/test-wasm.mjs web/seed_web.opt.wasm; then
    echo "FAIL: web vector harness failed — the optimized wasm no longer reproduces the frozen public vectors."
    exit 1
fi
echo "PASS: optimized web wasm reproduces the frozen public vectors."

echo "== release-governance & workflow-security guards (2026-08-09 audit:"
echo "   ALEA-2026-001/003/004/006/008) =="
# These guards make the release-authorization design (docs/RELEASE-GOVERNANCE.md,
# SPEC_AUDIT_REMEDIATION_2026-08-09) locally checkable on every push, so a
# regression in the GitHub Actions security posture fails the SAME gate a
# developer runs — not silently on a future tag push months later.
WF_DIR=".github/workflows"

# --- (a) action-pin gate (ALEA-2026-006) ---
# Every third-party `uses:` MUST be pinned to a full 40-hex commit SHA; a
# tag/branch ref (`@v4`, `@main`) is a mutable supply-chain input. Local
# reusable workflows (`uses: ./...`) have no SHA to pin and are exempt.
echo "-- (a) workflow action-pin gate: every third-party \`uses:\` is a 40-hex SHA --"
pin_fail=0
while IFS= read -r ref; do
    [ -z "$ref" ] && continue
    case "$ref" in
        ./*) continue ;;                       # local reusable workflow
    esac
    if ! printf '%s' "$ref" | grep -qE '@[0-9a-f]{40}$'; then
        echo "FAIL: unpinned action reference (must be @<40-hex-sha>): $ref"
        pin_fail=1
    fi
done < <(grep -rhE '^[[:space:]]*-?[[:space:]]*uses:' "$WF_DIR" \
            | sed -E 's/^[[:space:]]*-?[[:space:]]*uses:[[:space:]]*//; s/[[:space:]]+#.*$//; s/[[:space:]]*$//')
[ "$pin_fail" -eq 0 ] || { echo "FAIL: workflow action-pin gate (ALEA-2026-006)."; exit 1; }
echo "PASS: all workflow \`uses:\` refs are SHA-pinned or local reusable workflows."

# --- (b) release-workflow parity guard (ALEA-2026-001/004) ---
# The release pipeline's security depends on three structural facts in
# release.yml. Assert each is present so a well-meaning refactor cannot
# quietly drop the full-CI reuse, the job dependency, or the trust gate.
echo "-- (b) release-workflow parity guard: reusable CI + needs + tag-trust gate --"
REL="$WF_DIR/release.yml"
grep -qE 'uses:[[:space:]]*\./\.github/workflows/ci\.yml' "$REL" \
    || { echo "FAIL: release.yml no longer reuses ci.yml via workflow_call (ALEA-2026-004)."; exit 1; }
grep -qE 'needs:[[:space:]]*full-ci' "$REL" \
    || { echo "FAIL: release.yml build/gate job does not \`needs: full-ci\` (ALEA-2026-004)."; exit 1; }
grep -q 'tag-trust-gate.sh' "$REL" \
    || { echo "FAIL: release.yml no longer invokes tag-trust-gate.sh (ALEA-2026-001/004)."; exit 1; }
# The publish job (the sole write-scoped job) must create a DRAFT only.
grep -qE '(--draft\b|--draft=true)' "$REL" \
    || { echo "FAIL: release.yml publish job no longer creates a DRAFT (ALEA-2026-003)."; exit 1; }
echo "PASS: release.yml reuses ci.yml, needs full-ci, runs the trust gate, drafts only."

# --- (c) advisory-db snapshot freshness (ALEA-2026-008) ---
# Fail closed if the pinned RustSec advisory-db snapshot is stale, missing
# or future-dated — the same enforcement release.yml runs, so a stale pin
# is caught on push rather than at release time.
echo "-- (c) advisory-db snapshot freshness gate --"
cargo run --quiet -p release-verifier --bin advisory-db-age -- supply-chain/advisory-db.lock \
    || { echo "FAIL: advisory-db snapshot freshness gate (ALEA-2026-008). See supply-chain/README.md."; exit 1; }

# --- (d) release-authorization gate scripts host test (ALEA-2026-001/003/004) ---
# Exercises tag-trust-gate.sh and release-verify-signature.sh against a
# throwaway git repo + ed25519 key (skips cleanly if ssh-keygen is absent).
echo "-- (d) release gate-scripts host test --"
bash scripts/tests/gate-scripts.test.sh \
    || { echo "FAIL: release gate-scripts host test (scripts/tests/gate-scripts.test.sh)."; exit 1; }

echo "PASS: release-governance & workflow-security guards."

echo "== ci.sh: all checks passed =="
