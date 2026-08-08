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
