# Reproducing Alea builds

Owner: WP-32 (`tools/release-verifier/`). See `IMPLEMENTATION_MAP.md` §5
WP-32 and `SPEC.md` §31–32.

This document is about **build reproducibility**: given the published
source, can an independent party rebuild the *unsigned* production
executable and get exactly the same bytes? It is deliberately narrower
than `VERIFYING-MEDIA.md`, which is the end-user ceremony for verifying a
*release you downloaded* (hashes, signature, media read-back). Read this
document if you want to rebuild from source and compare; read
`VERIFYING-MEDIA.md` if you just want to safely write and boot a release
you obtained.

## 1. Three different claims (SPEC §32)

SPEC §32 is explicit that a signed release involves three *distinct*
claims, and documentation must not blur them together:

1. **Reproduction of the unsigned executable payload.** "If I build this
   source tree myself, do I get the same `alea-x86_64-unsigned.efi`
   bytes as the published one?" This is what this document and
   `tools/release-verifier/scripts/reproduce-unsigned.sh` address.
2. **Verification of the signed wrapper and certificate chain.** "Is
   `alea-x86_64-signed.efi` a validly-signed PE/COFF file, and does
   its signing certificate chain to a trust anchor I've decided to
   accept?" This is a question about the *signature*, not about
   rebuilding anything — the signed artifact is expected to differ
   byte-for-byte from the unsigned one purely because of the
   Authenticode signature block appended to it. Nothing in this repo (nor
   in `tools/release-verifier/`) is required to reproduce that block —
   only the project's production signing key can produce it, and it is
   allowed to legitimately vary between signing operations (timestamps in
   the countersignature, etc). Use standard Authenticode/signtool-class
   tooling, or `osslsigncode -verify`, to check the signature itself.
3. **Correspondence between the signed payload and the reproducible
   unsigned payload.** "Does the *code* inside the signed artifact match
   the independently-reproducible unsigned build, i.e. did signing change
   anything other than appending a signature?" This is checked by
   stripping the Authenticode signature from the signed artifact (the
   signed PE format keeps the original unsigned bytes intact except for
   an appended certificate table plus the certificate-table-related PE
   header fields) and comparing what remains against your own
   independently-built unsigned artifact. `release-verifier` does not
   currently automate this stripping step (it has no Authenticode
   parser, deliberately — see `tools/release-verifier/src/lib.rs`'s
   module doc comment on not vendoring signature crypto); use
   `osslsigncode remove-signature` or equivalent, then `sha256sum` the
   result against your own build.

Claim 1 is what "reproducible build" means for this project. Claims 2 and
3 are about the signature and are covered by `VERIFYING-MEDIA.md`
alongside the rest of the SPEC §10 ceremony.

## 2. What "deterministic unsigned payload" requires in practice

SPEC §32 requires "deterministic unsigned EFI payload" and "at least two
independent build attestations." Two builds are only comparable if they
agree on every input that could affect output bytes:

- **Toolchain.** The exact Rust toolchain pinned in `rust-toolchain.toml`
  (`rustc`/`cargo` 1.97.1 at the time of writing) plus the `x86_64-unknown-uefi`
  target component. `rustup` will fetch this automatically from
  `rust-toolchain.toml` if you have `rustup`-managed Rust installed.
- **Dependencies.** The exact `Cargo.lock` checked into the repository —
  always build with `--locked` (both the CI script and
  `reproduce-unsigned.sh`, below, do this) so a build never silently
  resolves a newer transitive dependency version.
- **Build profile.** The workspace's `[profile.release]` in the root
  `Cargo.toml` (`panic = "abort"`, `lto = true`, `opt-level = "s"`) —
  fixed there for the whole workspace; do not override it per-build.
- **`SOURCE_DATE_EPOCH`.** Exported before building. Nothing in this
  workspace's own source currently *reads* this variable (there is no
  build script emitting a timestamp), but it is exported anyway, for two
  reasons: (a) some transitive dependency could start doing so in a
  future version bump, and a documented, exported, fixed value means that
  stays reproducible instead of silently regressing; (b) it is the
  standard reproducible-builds signal
  (<https://reproducible-builds.org/docs/source-date-epoch/>) a release
  pipeline is expected to set to the signed source tag's commit time.
- **Linker flags that suppress non-deterministic linker output.** See
  §3 below — this was the one input that actually needed fixing, found
  by running the harness against the real target.
- **Absolute source path.** Not controlled by this harness. Two builds
  performed from *the same repository checkout path* on the same machine
  (which is what `reproduce-unsigned.sh` does — it builds the same
  working tree twice into two different `CARGO_TARGET_DIR`s) prove that
  the *build process* is deterministic. A from-scratch, independently
  cloned checkout at a different filesystem path is additionally
  affected by whether any embedded string contains an absolute source
  path; this workspace's production crate graph is `no_std`/`no_alloc`
  and does not embed `file!()`/`env!("CARGO_MANIFEST_DIR")`-derived
  absolute paths in its own source (verified by grep across
  `crates/seed-uefi-production/`), and debug info (which does carry
  absolute compiland paths) is stripped entirely by the linker flags in
  §3. A release pipeline building from two genuinely independent clones
  should additionally check this with `diffoscope` or an equivalent
  binary differ if the build ever *does* diverge — this repository's own
  harness cannot itself perform a second clone.

## 3. What actually made this non-reproducible (found empirically)

Building `seed-uefi-production` for `x86_64-unknown-uefi` twice, each time
from a completely clean `CARGO_TARGET_DIR`, initially did **not** produce
identical bytes — a handful of bytes differed between the two builds
every time, always in the same two places:

- The PE/COFF header's `TimeDateStamp` field (the linker's wall-clock
  build time, appearing once in the COFF header and again inside a PE
  debug directory record it also emits by default).
- A PDB signature/age value in that same debug directory record, which is
  not content-derived by default either.

Rust's `x86_64-unknown-uefi` target links through `rust-lld`'s PE/COFF
(`lld-link`-compatible) backend, which supports two flags that fix this:

- `/Brepro` — replaces the timestamp with a hash of the link inputs
  instead of the wall-clock time.
- `/DEBUG:NONE` — omits the PE debug directory entirely. This is a
  `#![no_std] #![no_main]` firmware binary; nothing consumes its
  DWARF/CodeView debug info as a debugger-attach target, so removing it
  loses nothing this project needs.

Passed together as `-C link-arg=/Brepro -C link-arg=/DEBUG:NONE`, two clean
builds of `seed-uefi-production` for `x86_64-unknown-uefi` became
byte-for-byte identical (confirmed with `sha256sum` and `cmp -l`).
Neither flag alone was sufficient — `/Brepro` alone still left a
differing debug-directory PDB value; `/DEBUG:NONE` alone still left the
COFF header timestamp varying build-to-build.

Both flags live in **`.cargo/config.toml`** under
`[target.x86_64-unknown-uefi].rustflags`, alongside the mandatory
`--cfg sha2_backend="soft"` codegen flag. This is deliberately a *single*
flag source shared by everything that builds the payload: the normal
`scripts/build-release.sh --release` build and the
`reproduce-unsigned.sh` harness both pick these flags up from config,
so the shipped binary and the "reproduced" binary are built with
byte-identical flags. Earlier the harness set the two link flags via a
`RUSTFLAGS` environment variable of its own — but a `RUSTFLAGS` env value
*replaces* the target `rustflags` from config wholesale (cargo does not
merge the two), which silently dropped the `sha2_backend="soft"` cfg and
could make the two binaries diverge. That env override has been removed;
config.toml is now the one source of truth.

## 4. Running the reproducibility check

```sh
source "$HOME/.cargo/env"
export CARGO_TARGET_DIR="$HOME/.cache/sf-target/<your-tag>"   # any writable path; not read by the script itself
./tools/release-verifier/scripts/reproduce-unsigned.sh
```

This builds `seed-uefi-production` for `x86_64-unknown-uefi` **twice**,
each into its own freshly created temporary `CARGO_TARGET_DIR` (so
nothing is shared or reused between the two builds — this checks
"two independent build invocations agree," not "incremental rebuild
didn't change anything"), then compares the resulting
`seed-uefi-production.efi` with `sha256sum`. It exits `0` and prints
`PASS` with both hashes if they match; `1` and prints `FAIL` (leaving the
two build trees on disk for inspection with `cmp -l` or `diffoscope`) if
they do not.

Measured in this environment: a from-clean build of the real production
target takes on the order of 6 seconds, so the full two-build check
(~12 seconds of `cargo build` plus dependency compilation, which is
cached per `CARGO_TARGET_DIR` and therefore paid twice) completes in well
under a minute — there was no need to substitute a smaller stand-in
target for speed. If a future dependency addition ever makes the real
target too slow for a particular environment, the same script accepts
`--crate`/`--triple`/`--artifact` overrides to point at a smaller crate
instead, e.g.:

```sh
./tools/release-verifier/scripts/reproduce-unsigned.sh \
  --crate release-verifier --triple x86_64-unknown-linux-musl --artifact release-verifier
```

— this exercises exactly the same clean-build/hash-compare mechanism the
default invocation does; only the thing being built changes. A pipeline
falling back to this must still additionally run the default (real
production target) invocation before any release is cut; the minimal
form is a fast sanity check of the harness, not a substitute for checking
the artifact that actually ships.

## 5. What a release pipeline does beyond this script

`SPEC.md` §32 requires **at least two independent build attestations** —
i.e., two different machines/operators/checkouts, not two builds by the
same invocation on the same machine. `reproduce-unsigned.sh` proves the
build process itself is deterministic (a necessary condition); a real
release additionally needs a second party to run the same script against
their own independent clone of the signed source tag and publish that
they got the same `SHA256SUMS` hash for
`alea-x86_64-unsigned.efi`, per SPEC §32's "at least two
independent build attestations" and "no automatic release from a
developer laptop" requirements. That cross-machine attestation exchange
is a release-governance process, not something a single script run can
demonstrate by itself.

## 6. Verifying the USB image and the signed artifacts

This document only covers the *unsigned executable payload*. The USB disk
image (`alea-x86_64-usb.img`) has its own determinism requirement
("deterministic USB image before external signing effects," SPEC §32) —
that image is built by `tools/image-builder/` (WP-29), not this tool; see
that tool's own documentation for its determinism approach.
`alea-x86_64-signed.efi` is never reproducible in the sense this
document describes (see §1, claim 2) — verify it as described in
`VERIFYING-MEDIA.md` instead.

## 7. Web offline edition (`alea-web-offline.html`)

The offline web edition (`web/`, `SPEC_WEB_OFFLINE.md`) is a **separately
reproducible** artifact with its own pinned toolchain. Like the desktop
rehearsal edition it is a separate download and is never bundled into the
production USB archive (SPEC_WEB_OFFLINE §4.3), but it carries the same
"same source ⇒ same bytes" guarantee (§5.2/§5.3, §10; §11.8 makes a
non-reproducible web build a hard prohibition).

**Pinned toolchain (`web/build.sh`, normative — SPEC_WEB_OFFLINE §5.2):**

- **rustc `1.97.1`** via `rust-toolchain.toml` (the same pin as the rest of
  the workspace), target **`wasm32-unknown-unknown`**.
- **`RUSTFLAGS = -C strip=symbols --remap-path-prefix=$HOME=~
  --remap-path-prefix=<repo>=/alea`** — strips symbols and removes absolute
  build paths from panic-location strings, so no machine-specific path is
  baked into the `.wasm` (`-C panic=abort` + `opt-level` are pinned in the
  crate's `[profile.release]`).
- **`cargo build --locked`** — builds against the committed `Cargo.lock`
  exactly; a build that re-resolves dependencies is refused.
- **binaryen `version_119`** — `wasm-opt` is a **hard requirement**, not an
  optional pass: `web/build.sh` fails unless `wasm-opt --version` reports
  `version 119`. Exact invocation:

  ```
  wasm-opt -Oz --enable-bulk-memory --strip-producers --strip-debug \
    seed_web.wasm -o seed_web.opt.wasm
  ```

  `--enable-bulk-memory` is required: `wasm-opt` 119 rejects the
  rustc-emitted module (which uses bulk-memory ops) without it. It is the
  *only* extra feature flag needed. `--strip-producers`/`--strip-debug`
  remove non-normative toolchain-identifying sections so the bytes are
  stable across machines.
- **Deterministic inliner** (`web/build.py`) — standard base64 (fixed
  alphabet, no wrapping), LF line endings, fixed field order, no
  timestamp / hostname / build path embedded. Given a byte-identical
  optimized `.wasm` and unchanged `web/src/`, it reproduces a
  byte-identical `alea-web-offline.html`.

**Rebuild:**

```bash
# with binaryen version_119 on PATH (and the wasm32 target installed)
bash web/build.sh
```

This writes `web/alea-web-offline.html` (the single-file deliverable, §5.1)
and `web/seed_web.opt.wasm` (the optimized module embedded in it — the
optional standalone secondary form, whose sha256 the in-page Integrity
self-check reports, §5.3). A **clean rebuild yields byte-identical hashes**;
`ci.sh` asserts this by building twice and comparing, and also asserts the
committed `web/alea-web-offline.html` matches a fresh rebuild.

**Expected hashes (SHA-256):**

| Artifact | SHA-256 |
| --- | --- |
| `seed_web.wasm` (pre-`wasm-opt`, `wasm32/release`) | `e9557623434f29d7732926218433cd28d7fafd6a73a3e848f1e1b3e0240344ea` |
| `seed_web.wasm` (optimized — embedded + standalone) | `59ba558a797297cadbaf10f52f698f4ad8289b20d9794cd8f3b832408fd4d000` |
| `alea-web-offline.html` (the deliverable) | `fbdbfd6acee17a1e1fa4fa9ae7fbbc12d5b3a63c9854666b5d76395d763935c1` |

The optimized-`.wasm` hash is the value the offline page's **Integrity**
tab recomputes from its own embedded bytes, and the value recorded in the
web edition's `SHA256SUMS` (`scripts/build-release.sh`). The authoritative
end-user check is hashing the downloaded `alea-web-offline.html` itself
before opening it (see `VERIFYING-MEDIA.md`).

## 8. Reproducing the dependency audit (`DEPENDENCY-AUDIT.txt`, SPEC §31)

Every release bundles `DEPENDENCY-AUDIT.txt`, the SPEC §31 dependency-audit
report (`scripts/build-release.sh`). It records two machine-checkable
results against the pinned `Cargo.lock`: the mechanical policy report (no
unpinned `git+` dependencies; exact `=` version pins on
`workspace.dependencies`) and the `cargo vet --locked --frozen` verdict
(`Vetting Succeeded`) over the committed `cargo-vet` supply-chain store.

That store lives in `supply-chain/` (`config.toml`, `audits.toml`,
`imports.lock`; see `supply-chain/README.md`) and is shipped inside
`alea-source.tar.gz`, so anyone can re-derive the verdict offline from a
clean checkout of the release source, with no network access:

```bash
# cargo-vet 0.10.2 on PATH; from the extracted alea-source.tar.gz root
cargo vet --locked --frozen        # → "Vetting Succeeded (242 exempted)"
```

`--locked --frozen` runs it strictly read-only against the committed store
and lockfile — it never re-resolves dependencies or rewrites the audit
record — so the result reproduces byte-for-byte on any machine. `ci.sh`
runs the same check in its SPEC §31 dependency-audit gate.
