# Alea supply-chain record (`cargo vet`) — SPEC §31

This directory is Alea's **machine-checkable dependency-audit record** (SPEC §31:
"The release MUST include … a dependency-audit report"). It is a standard
[`cargo vet`](https://mozilla.github.io/cargo-vet/) store:

- **`config.toml`** — the policy plus the **exemptions** baseline: every crate in
  the resolved dependency graph that has not been individually audited is listed
  here explicitly.
- **`audits.toml`** — the **audits** we have actually performed, including the
  custom `provenance-verified` criteria (see below).
- **`imports.lock`** — pinned imported audit sets. **Empty by design:** Alea
  imports no external audit sets, so `cargo vet --locked --frozen` runs fully
  offline and deterministically (no network at CI or release time).

## What the gate proves — and what it does not

`cargo vet --locked --frozen` (run by `ci.sh` and `scripts/build-release.sh`)
asserts that **every** crate in the resolved graph is either audited in
`audits.toml` or carried as an explicit `exemptions` entry in `config.toml`. So a
newly-introduced or version-bumped dependency that nobody has reviewed **fails
the gate** instead of entering the build silently. That is the machine-checkable
guarantee: no unreviewed dependency drift.

**Honesty note.** Most of the graph is recorded as `exemptions`, **not** as
audits. An exemption is an explicit, machine-tracked acknowledgement of a crate
we depend on but have **not** fully audited — it is deliberately *not* an
attestation of safety. A full independent audit of the crypto path is a SPEC §31
/ §36.2 **pre-stable release gate** tracked in `docs/AUDIT-STATUS.md`; this
record does not pretend that gate is met.

## The `provenance-verified` criteria

`audits.toml` defines a custom criteria, `provenance-verified`, and applies it to
the four post-cutoff constant-time helper crates on the production
secp256k1 / k256 path — `cmov`, `cpubits`, `ctutils`, `wnaf`. It records
**exactly** the review Alea's 2026-08-05 security re-audit performed: the
crates.io release was cross-checked to match the authentic upstream author's
published source and confirmed authored/published by the RustCrypto maintainer
(`tarcieri`). It is an **authorship / provenance check, not a line-by-line
security audit**, and it deliberately does **not** imply the built-in
`safe-to-deploy` criteria the policy gates on — which is why those four crates
also remain in `exemptions` for `safe-to-deploy`. The audits add a
machine-readable record of the provenance work that was genuinely done, without
overclaiming.

## Working with the record

```sh
# Install the pinned tool (musl-gcc is absent on this host, so build for gnu):
CARGO_BUILD_TARGET=x86_64-unknown-linux-gnu cargo install cargo-vet --locked

# Run the gate (offline, deterministic):
cargo vet --locked --frozen

# After adding/bumping a dependency, EITHER audit it:
cargo vet certify <crate> <version>        # records a real audit in audits.toml
# OR, if it is acknowledged-but-unaudited, add a baseline exemption:
cargo vet add-exemption <crate> <version>
cargo vet fmt                              # canonicalise the store before commit
```

Never widen the record to make the gate pass without review — that defeats its
only purpose.

## RustSec advisory gate (ALEA-2026-008)

`cargo vet` answers "were these exact dependency versions reviewed / pinned?"
It does **not** answer "did a version in `Cargo.lock` later become the subject
of a newly published RustSec advisory?" A separate, advisory-scoped
`cargo-deny` check covers that, in two tiers that preserve Alea's offline,
deterministic release builds:

- **Scheduled online monitor** (`.github/workflows/audit.yml`, WP4): weekly
  `cargo deny check advisories` against the **live** RustSec DB. Never runs on
  push/PR/tag, so it cannot affect build determinism; a new advisory surfaces
  as a job failure.
- **Deterministic release gate** (`ci.sh`, WP4): `cargo deny --offline check
  advisories` against a **pinned** advisory-db snapshot, so two clean builds of
  the same tag agree. The pin lives in `supply-chain/advisory-db.lock` (commit
  + date + `max_age_days`), and `advisory-db-age` (`tools/release-verifier`)
  fails the release **closed** if the pinned snapshot is older than
  `max_age_days` — a stale pin cannot silently stop catching advisories. The
  online monitor covers the window between snapshot bumps.

Scope: `deny.toml` configures **advisories only** — bans/licenses/sources stay
owned by this `cargo vet` record and the SPEC §31 checker, never duplicated.

Honesty: a green advisory gate proves only "no RustSec-published advisory
matches the pinned graph as of the snapshot date." It is not an audit, not a
safety attestation, and `cargo vet` is not a substitute — both are used.

Bumping the snapshot: set both `commit` and `snapshot_date` in
`advisory-db.lock` to the new pin (no in-repo content to update — see below).

**LANDED (Grok 4.5 Expert audit F-06, 2026-08-11):** the offline advisory gate
now runs. Rather than vendor the advisory-db into the repo (submodule/tarball,
both bloat clones), `tools/release-verifier/scripts/advisory-check.sh` **fetches**
rustsec/advisory-db, **pins** it to `advisory-db.lock`'s `commit` and **verifies
the SHA**, then runs `cargo deny --offline check advisories` against that pinned
snapshot. It is wired into `ci.sh` (guard c) — and therefore into every release
via `release.yml`'s `full-ci` job — and `cargo-deny` is a pinned CI tool
(`ci.yml`, 0.20.2). Determinism comes from the verified pin, not from committing
the database. Any accepted advisory is an explicit, dated `ignore` in `deny.toml`
(e.g. RUSTSEC-2026-0192 `ttf-parser` unmaintained — reachable only via the
desktop-rehearsal GUI stack, absent from the production binary).
