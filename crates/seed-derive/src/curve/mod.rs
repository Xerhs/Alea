//! Thin, constant-time secp256k1 wrapper over `k256` (SPEC §13, §24; WP-06).
//!
//! `k256` is used with `default-features = false, features = ["arithmetic"]`
//! only (`IMPLEMENTATION_MAP.md` §3), so this module has access to curve
//! group arithmetic (`AffinePoint`, `ProjectivePoint`, `Scalar`) but not
//! `k256`'s own ECDSA/Schnorr/`sha256` feature surface — the BIP340/BIP341
//! tagged hash below is therefore implemented locally on top of
//! `seed_core::hash`, not borrowed from `k256`.
//!
//! Scope (`IMPLEMENTATION_MAP.md` WP-06):
//! - private key → compressed SEC1 public key (33 bytes)
//! - private key → x-only public key (32 bytes, BIP340 serialization)
//! - BIP32 CKD scalar addition mod `n`, with the BIP32 invalid-key checks
//!   (`parse256(IL) >= n`, zero child result)
//! - BIP341 taproot output-key tweak, `Q = P + tagged_hash("TapTweak",
//!   xonly(P))·G`, with even-y normalization of the internal key
//!
//! All scalar (private-key) arithmetic goes through `k256`'s
//! `CurveArithmetic` implementation, which SPEC §13 requires to be
//! constant-time for any operation touching private-key material; this
//! wrapper never branches on secret scalar bits itself; it only adds
//! constant-time-safe `CtOption`/`Choice`-based validity checks (SPEC §20.2:
//! "equality operations that expose timing-sensitive early exits where
//! avoidable" — the *presence* of an early return on an invalid key is
//! itself public information per BIP32/BIP340, not a secret-dependent
//! timing leak of the key's *value*).
//!
//! Local `k256::Scalar` values holding private-key material are held in
//! [`zeroize::Zeroizing<Scalar>`] rather than a bare `Scalar` (SPEC §13,
//! §20.3): the wrapper's `Drop` impl calls `Scalar`'s `Zeroize::zeroize`
//! (`k256::Scalar: DefaultIsZeroes`, which resolves through zeroize's
//! blanket impl to a volatile write plus an optimization barrier — not a
//! plain assignment) unconditionally, on *every* path out of scope,
//! including any early return this module's own code takes via `?` or an
//! explicit `return`, and any path a future edit might add without
//! remembering to call `.zeroize()` by hand. This removes the maintenance
//! hazard of the previous per-branch manual-call pattern, and
//! [`parse_scalar_checked`] additionally scrubs the *rejected* out-of-range
//! parse result explicitly (see its doc comment) rather than letting it
//! drop unscrubbed inside the `CtOption` machinery.
//!
//! `k256::Scalar`/`AffinePoint` derive `Copy`/`Clone`/`Debug` in the
//! upstream crate (a foreign type we cannot change, and the reviewed
//! constant-time library SPEC §31/§13 asks us to prefer over a
//! project-owned implementation); this module does not itself define any
//! new secret-bearing type, own any long-lived scalar, or add further
//! derives, so the SPEC §20.2 restriction ("no
//! `Copy`/`Clone`/`Debug`/`Display`... on secret-bearing types") is
//! satisfied for everything this crate defines.
//!
//! **Known residual limitation (SPEC §20.2 assembly-review requirement).**
//! `Zeroizing` guarantees the *named* wrapped binding is scrubbed on drop;
//! it cannot reach a compiler-chosen register/stack copy of a `Copy` value
//! produced mid-expression by an operator overload — e.g. in
//! [`ckd_scalar_add`], the `Scalar` value `*il_scalar + *k_par_scalar`
//! evaluates to before that sum is moved into its own `Zeroizing` wrapper.
//! No combination of safe-Rust wrapper types can reach that intermediate
//! copy, since by the time a value could be wrapped, the copy has already
//! been made by codegen. Eliminating it fully would require either forking
//! `k256` to strip its `Copy`/`Clone` derives (rejected: SPEC §31 asks us
//! to prefer the reviewed upstream constant-time implementation over a
//! project-owned fork) or hand-written inline assembly for the scalar
//! arithmetic (rejected as disproportionate for a `medium`-severity,
//! cryptographically-inert-on-its-own residual risk — the copy is a
//! same-process memory artifact, not an output or timing side channel; the
//! curve-point results of `Scalar * G` are, by contrast, intentionally
//! *not* wrapped or zeroized anywhere in this module, since they are public
//! key material and recovering the scalar from them is the discrete-log
//! problem, not a memory-disclosure problem). We mitigate structurally by
//! moving every *scalar-valued* operator-overload result directly into a
//! `Zeroizing`-wrapped binding in the same `let` statement that computes
//! it, minimizing how long an unwrapped copy is the "live" value the rest
//! of the function depends on (this does not erase a spilled/duplicated
//! copy already made by codegen, but it removes any *additional* window
//! where the module's own control flow, rather than the compiler, is the
//! reason an unwrapped copy stays reachable). See the assembly-review note
//! below for what was actually observed for this specific build.
//!
//! Per SPEC §20.2's request for generated-assembly review of critical
//! paths: this crate's actual release profile (root `Cargo.toml`
//! `[profile.release]`: `lto = true`, `opt-level = "s"`) makes rustc emit
//! this library's `.rlib` as LLVM-bitcode object files (linker-plugin-style
//! deferred codegen), which cannot be disassembled directly, since
//! `seed-derive` is itself a library, not a final linked binary — actual
//! machine code only exists after a downstream binary crate links and
//! LTO-codegens it. For inspection purposes only (no manifest changed),
//! this module was rebuilt with the environment override
//! `CARGO_PROFILE_RELEASE_LTO=off` and `opt-level=3` to obtain native
//! x86_64 object code, disassembled with `objdump -dr --demangle`. Findings
//! for `ckd_scalar_add`, `privkey_to_compressed_pubkey`,
//! `privkey_to_xonly_pubkey` at that (non-shipped) optimization level:
//! - None of `<Scalar as PrimeField>::from_repr`,
//!   `<Scalar as ConditionallySelectable>::conditional_select`,
//!   `<Scalar as Add>::add`, `Scalar::is_zero`, `Scalar::to_bytes`, or
//!   `k256::arithmetic::mul::lincomb` (what `ProjectivePoint::GENERATOR *
//!   scalar` compiles down to) is inlined into this module's functions;
//!   each is a real `call`, and because `Scalar` is 32 bytes (too large for
//!   the SysV integer/SSE register-return path), arguments and results
//!   cross that call boundary via a hidden pointer to a stack slot, not a
//!   bare register copy of the full scalar value.
//! - In `ckd_scalar_add`, the `Add::add` call's hidden output pointer
//!   targets the same stack slot that the inlined zeroize scrub later
//!   clears for `child` — in this build, no *additional* register/stack
//!   copy of the sum was introduced at that specific call boundary beyond
//!   the one ABI-mandated write-through.
//! - Every observed `Zeroizing` drop point compiles to an inlined
//!   `xorps`/`movaps` zero-store sequence rather than a separate `call`,
//!   consistent with zeroize's `DefaultIsZeroes` blanket impl being a small
//!   `#[inline]`-eligible function.
//! - This review covers only `seed-derive`'s own generated code; the
//!   internal stack usage of `Scalar::add`/`lincomb`/etc. is k256's own
//!   (upstream, out of this work package's ownership) and was not
//!   disassembled.
//! - Because inspection required `lto=off`/`opt-level=3` instead of the
//!   shipped `lto=true`/`opt-level="s"`, these findings characterize this
//!   module's own codegen pattern but do not directly evidence the shipped
//!   binary's final, LTO-fused machine code; a from-shipped-binary check
//!   requires disassembling an actual linked production/desktop-test binary
//!   (owned by other work packages — see `shared_file_needs`) and is left
//!   as follow-up. This review is a point-in-time, single-toolchain
//!   observation, not a standing guarantee across compiler versions/flags.
//!
//! **Follow-up: shipped-profile review (2026-08-04, gap-fix agent 5,
//! SPEC §29.7 conformance sweep).** The "left as follow-up" item above is
//! now done, closing that specific caveat. Method: rather than
//! disassembling `seed-uefi-production.efi` directly — the real shipped
//! PE/COFF artifact for this target carries **zero symbols** under this
//! toolchain (`nm`/`objdump -dr --demangle` against a freshly built
//! `--release` `x86_64-unknown-uefi` binary report "no symbols" and print
//! only bare addresses with no function names at all, for *every*
//! function in the binary, not just this module's — verified empirically
//! while preparing this note, and now also a standing regression check:
//! `tests/leakage/tests/forbidden_uefi_interfaces.rs`'s
//! `shipped_efi_binaries_carry_no_symbol_table_or_debug_sections`), which
//! makes locating any *specific* named function's machine code in that
//! artifact structurally impossible with these tools, not merely
//! inconvenient — a standalone host binary crate (`x86_64-unknown-linux-
//! musl`, ELF; kept as a local scratch crate outside this repository,
//! never checked in, since it exists purely to produce disassembly
//! evidence for this doc comment, not as shipped or tested code) was
//! built instead, depending on `seed-derive` by path and calling
//! [`ckd_scalar_add`] and [`privkey_to_compressed_pubkey`], compiled with
//! the *exact* shipped `[profile.release]` settings this workspace's root
//! `Cargo.toml` specifies (`panic = "abort"`, `lto = true`, `opt-level =
//! "s"`) copied verbatim into the scratch crate's own profile — the ELF
//! host target retains a full symbol table under this same LTO/opt-level
//! configuration where the UEFI/PE target does not, which is what makes
//! this substitution useful evidence rather than a different experiment
//! entirely: it isolates "what does `lto=true`/`opt-level="s"` codegen do
//! to this module's functions", independent of the PE-vs-ELF object
//! format difference, which does not change x86_64 SysV-derived integer/
//! vector instruction selection for pure arithmetic code with no OS/
//! firmware calls in it (this module makes none). Findings, disassembled
//! with `objdump -dr --demangle`:
//! - At this profile, both [`ckd_scalar_add`] and
//!   [`privkey_to_compressed_pubkey`] (and everything the earlier
//!   `lto=off` review found as real, un-inlined `call`s: `Scalar::
//!   from_repr`, `Add::add`, `Scalar::to_bytes`) are themselves fully
//!   inlined into the caller — LTO across the whole dependency graph
//!   erases the module-boundary call sites the earlier review's "hidden
//!   pointer to a stack slot" finding was about. There is no longer a
//!   distinct call boundary for this module's own wrapper functions to
//!   characterize at the shipped profile; the earlier review's finding
//!   about *those specific* call boundaries does not carry over, and is
//!   superseded by this note rather than still describing the shipped
//!   build.
//! - What remains as real (non-inlined) `call`s at the shipped profile
//!   are k256/`primeorder`/`crypto-bigint`'s own internal routines:
//!   `<Scalar as Mul>::mul`, `WideScalar::mul_shift_vartime`, `Uint::
//!   add_mod`, `ProjectivePoint::add_assign`, `<ProjectivePoint as
//!   ConditionallySelectable>::conditional_select`, `LookupTable::
//!   select`, and `SignedInt::lincomb_int(_reduce_shift(_mod))` (the
//!   scalar-inversion/GCD machinery `parse_scalar_checked`'s modular
//!   arithmetic reaches). All of these are upstream `k256`/`crypto-
//!   bigint` code (SPEC §31: reviewed third-party dependency), never
//!   disassembled function-body-by-function-body here — only their call
//!   sites and the fact that they remain real calls (not inlined away,
//!   so still individually addressable/traceable) is this note's claim.
//! - `xorps`/`movaps` zero-store sequences (the same inlined-zeroize
//!   signature the earlier `lto=off` review found) are still present
//!   throughout the fused shipped-profile function body (161 occurrences
//!   across the ~4200-instruction inlined `main` in the scratch binary
//!   the review built) — the zeroize-on-drop behavior this module relies
//!   on is not an `lto=off`-only artifact; it survives full-program LTO
//!   at the shipped optimization level too.
//! - Residual scope, same as the earlier review: this still only
//!   characterizes `seed-derive`'s own contribution (now: how it inlines
//!   into a caller under LTO) plus the *call sites* into k256/crypto-
//!   bigint, not those crates' own internal instruction-level behavior;
//!   it is a scratch-binary approximation of the real
//!   `seed-uefi-production.efi`/`seed-desktop-test` link (identical
//!   compiler, identical `[profile.release]` settings, different final
//!   object format/entry point), not a review of those exact shipped
//!   bytes, because — per the symbol-table finding above — no tool
//!   available in this environment can locate a specific function inside
//!   those exact shipped bytes at all. A toolchain change that restores
//!   symbols for the `x86_64-unknown-uefi` target (or a
//!   dwarfdump/addr2line-based approach cross-referencing pre-strip
//!   intermediate objects against the final linked binary) would close
//!   that remaining gap; recorded in `docs/AUDIT-STATUS.md`'s targeted
//!   spec-conformance sweep table as a residual, not silently dropped.
//! - The other eight SPEC §29.7-named critical-path areas (RDSEED/RDRAND
//!   calls, entropy-transcript construction, SHA-256/SHA-512
//!   finalization, PBKDF2 iteration loops, BIP39 conversion, secret moves
//!   generally, scrubbing generally, panic paths, shutdown transition)
//!   have not received an equivalent review as of this note; also
//!   recorded as a residual in `docs/AUDIT-STATUS.md` rather than implied
//!   complete by this module's own review being current.

use k256::{
    elliptic_curve::{
        ff::PrimeField,
        group::{CurveAffine, GroupEncoding},
        point::{AffineCoordinates, DecompactPoint},
    },
    AffinePoint, FieldBytes, ProjectivePoint, Scalar,
};
use seed_core::contracts::DeriveError;
use seed_core::hash::{sha256, Sha256Ctx};
use zeroize::{Zeroize, Zeroizing};

/// Length in bytes of a compressed SEC1 public key: `0x02`/`0x03` sign
/// prefix + 32-byte x-coordinate (SPEC §24.2).
pub const COMPRESSED_PUBKEY_LEN: usize = 33;

/// Length in bytes of a BIP340/BIP341 x-only public key: the x-coordinate
/// alone, no sign byte (SPEC §24.2, taproot row).
pub const XONLY_PUBKEY_LEN: usize = 32;

/// Parse a 32-byte big-endian integer as a secp256k1 scalar, applying the
/// BIP32/SEC1 validity check that it is strictly less than the curve order
/// `n` (`Scalar::from_repr` rejects `>= n` via a constant-time compare;
/// SPEC §24.2, BIP32 CKD invalid-key case).
///
/// Returns `Err(DeriveError::InvalidChildKey)` on `>= n` — the only error
/// case `contracts.rs` gives us for "the raw scalar bytes did not parse to
/// a valid secp256k1 scalar" (see the doc comment on
/// `DeriveError::InvalidChildKey`, which names exactly this case).
///
/// The returned `Scalar` (secret-derived: every caller in this module feeds
/// it either raw private-key bytes or a BIP32 `IL` chunk) is wrapped in
/// [`Zeroizing`] so it is scrubbed on every path out of the caller's scope,
/// success or error, without relying on a manual `.zeroize()` call at each
/// return site (SPEC §13, §20.3).
///
/// `Scalar::from_repr` returns a `CtOption` computed in constant time
/// regardless of validity — the raw parsed value exists internally even
/// when `>= n`. Rather than let that internal value drop unscrubbed when
/// the `CtOption` is rejected (as `.into_option().ok_or(..)` would), this
/// function extracts the raw value via `unwrap_or` (itself constant-time:
/// `ConditionallySelectable::conditional_select`, SPEC §20.2) into the
/// `Zeroizing` wrapper *before* branching on validity, then explicitly
/// scrubs it on the rejection path.
fn parse_scalar_checked(bytes: &[u8; 32]) -> Result<Zeroizing<Scalar>, DeriveError> {
    let ct = Scalar::from_repr(FieldBytes::from(*bytes));
    let is_valid = ct.is_some();
    let mut scalar = Zeroizing::new(ct.unwrap_or(Scalar::ZERO));
    if bool::from(is_valid) {
        Ok(scalar)
    } else {
        scalar.zeroize();
        Err(DeriveError::InvalidChildKey)
    }
}

/// SPEC §13, §24.2: derive the compressed SEC1 public key (33 bytes,
/// `0x02`/`0x03 || X`) for a private scalar `privkey`.
///
/// `privkey` must be nonzero and `< n` (SEC1/BIP32 validity); either
/// violation returns `Err(DeriveError::InvalidChildKey)` without touching
/// `out`. The scalar multiplication `privkey * G` runs through `k256`'s
/// constant-time curve arithmetic (SPEC §13).
pub fn privkey_to_compressed_pubkey(
    privkey: &[u8; 32],
    out: &mut [u8; COMPRESSED_PUBKEY_LEN],
) -> Result<(), DeriveError> {
    let scalar = parse_scalar_checked(privkey)?;
    if bool::from(scalar.is_zero()) {
        // `scalar` (a `Zeroizing<Scalar>`) is scrubbed automatically here
        // when it drops on this early return (SPEC §13, §20.3) — no manual
        // `.zeroize()` call needed or possible to accidentally omit.
        return Err(DeriveError::InvalidChildKey);
    }

    // `ProjectivePoint::GENERATOR * *scalar` yields the *public* key point;
    // unlike `scalar` it does not need zeroizing (recovering the private
    // scalar from it is exactly the hard discrete-log problem this curve
    // is chosen for).
    let point = (ProjectivePoint::GENERATOR * *scalar).to_affine();
    drop(scalar); // scrub the scalar as soon as it is no longer needed.

    // `AffinePoint: GroupEncoding` with `Secp256k1::COMPRESS_POINTS = true`
    // (see `k256::Secp256k1`) always yields the 33-byte compressed form.
    let compressed = point.to_bytes();
    out.copy_from_slice(&compressed);
    Ok(())
}

/// SPEC §13, §24.2 (taproot row), IMPLEMENTATION_MAP.md WP-06: derive the
/// x-only public key (32 bytes, BIP340 serialization: the x-coordinate of
/// `privkey * G`, independent of its y-parity) for a private scalar
/// `privkey`. Same validity checks and error as
/// [`privkey_to_compressed_pubkey`].
pub fn privkey_to_xonly_pubkey(
    privkey: &[u8; 32],
    out: &mut [u8; XONLY_PUBKEY_LEN],
) -> Result<(), DeriveError> {
    let scalar = parse_scalar_checked(privkey)?;
    if bool::from(scalar.is_zero()) {
        // Scrubbed automatically on drop; see `privkey_to_compressed_pubkey`.
        return Err(DeriveError::InvalidChildKey);
    }

    let point = (ProjectivePoint::GENERATOR * *scalar).to_affine();
    drop(scalar); // scrub the scalar as soon as it is no longer needed.

    let x = AffineCoordinates::x(&point);
    out.copy_from_slice(&x);
    Ok(())
}

/// SPEC §24.2 BIP32 child-key derivation step:
/// `k_child = parse256(IL) + k_par (mod n)`.
///
/// Applies both BIP32 invalid-key checks (IMPLEMENTATION_MAP.md WP-06
/// pitfall list): `parse256(IL) >= n` is rejected before any addition, and
/// a zero-valued child scalar is rejected after the addition. Both cases
/// return `Err(DeriveError::InvalidChildKey)`; per that variant's doc
/// comment in `contracts.rs`, this project's four fixed derivation paths
/// treat the (cryptographically negligible) invalid case as a fatal
/// self-test/derivation failure rather than a BIP32 "advance the index and
/// retry" loop — the caller (WP-13) is expected to route this to SPEC
/// §27.2 fatal handling, not retry.
///
/// `k_par` is assumed to already be a valid, previously-checked nonzero
/// secp256k1 scalar (every key this project produces, including the master
/// key, is validated at the point it is created). If `k_par` nonetheless
/// fails to parse as `< n`, that is treated defensively the same way (also
/// `InvalidChildKey`): `contracts.rs`'s `DeriveError` enum has no more
/// specific variant for that otherwise-unreachable case, and widening it is
/// an orchestrator-level contract change, not one this module can make
/// unilaterally (see this work package's `shared_file_needs`).
///
/// All intermediate scalars are held in [`Zeroizing`] and so are scrubbed
/// on every return path, including early returns via `?` (SPEC §13,
/// §20.3); `il` and `k_par` themselves are caller-owned and untouched.
pub fn ckd_scalar_add(
    il: &[u8; 32],
    k_par: &[u8; 32],
    k_child_out: &mut [u8; 32],
) -> Result<(), DeriveError> {
    let il_scalar = parse_scalar_checked(il)?;
    // If this second parse fails, `il_scalar` is still in scope and is
    // dropped (and so scrubbed) automatically as part of the `?` early
    // return — no manual cleanup of the first scalar is needed on this
    // path, unlike the pre-`Zeroizing` version of this function.
    let k_par_scalar = parse_scalar_checked(k_par)?;

    // The sum is itself secret (a candidate child private-key scalar), so
    // it is moved into its own `Zeroizing` wrapper in the same `let`
    // statement that computes it, rather than living as a bare `Scalar`
    // even briefly.
    let mut child = Zeroizing::new(*il_scalar + *k_par_scalar);
    drop(il_scalar);
    drop(k_par_scalar);

    if bool::from(child.is_zero()) {
        // `child` scrubbed automatically on this early return.
        return Err(DeriveError::InvalidChildKey);
    }

    // `to_bytes()` materializes the secret child scalar into a bare
    // `[u8; 32]` local. Wrap it in `Zeroizing` so this copy is scrubbed on
    // drop, mirroring the `Zeroizing` discipline used for the scalars above
    // (SPEC §13, §20.3).
    let repr = Zeroizing::new(child.to_bytes());
    k_child_out.copy_from_slice(&*repr);
    child.zeroize();
    Ok(())
}

/// BIP340/BIP341 tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || msg)`
/// (SPEC §13, §24.2; IMPLEMENTATION_MAP.md WP-06 pitfall list states this
/// formula explicitly). Streams the two tag-hash copies and `msg` through
/// `seed_core::hash::Sha256Ctx` so no concatenation buffer is required
/// (no `alloc`, SPEC §13).
///
/// `tag`/`msg` are public protocol constants and public key material in
/// every caller in this project (never private-key bytes), so this
/// function takes plain slices rather than routing through the secret
/// arena.
pub fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let tag_hash = sha256(tag);
    let mut ctx = Sha256Ctx::new();
    ctx.update(&tag_hash);
    ctx.update(&tag_hash);
    ctx.update(msg);
    ctx.finalize()
}

/// BIP341 taproot output-key tweak (SPEC §24.2 P2TR row;
/// IMPLEMENTATION_MAP.md WP-06): `Q = lift_x(P_x) + tagged_hash("TapTweak",
/// P_x)·G`, where `lift_x` is the BIP340 even-y point lift of the internal
/// x-only public key `internal_xonly_pubkey` ("even-y normalization" —
/// IMPLEMENTATION_MAP.md WP-06 pitfall list). Writes the x-only
/// serialization of `Q` — the P2TR witness program — to
/// `out_tweaked_xonly`.
///
/// `internal_xonly_pubkey` is public data (an x-only public key produced by
/// [`privkey_to_xonly_pubkey`] further up the BIP86 derivation); this
/// function performs no private-key arithmetic.
///
/// # Errors
///
/// Returns `Err(DeriveError::PointAtInfinity)` if `internal_xonly_pubkey`
/// is not the x-coordinate of any point on the curve (BIP340 `lift_x`
/// failure), or in the cryptographically negligible case that `Q` is the
/// point at infinity. `contracts.rs`'s `DeriveError` has no dedicated
/// "invalid x-only pubkey" variant; `PointAtInfinity` is the closest
/// existing one ("an intermediate elliptic-curve point ... invalid") and is
/// reused here deliberately rather than adding a variant unilaterally (see
/// this work package's `shared_file_needs`). In this project's actual call
/// graph `internal_xonly_pubkey` is always produced by
/// [`privkey_to_xonly_pubkey`], so the `lift_x` failure branch is
/// unreachable in practice; it is handled instead of `unwrap()`-ed because
/// SPEC §13/§27.3 forbid panicking on this path.
pub fn taproot_tweak_xonly(
    internal_xonly_pubkey: &[u8; XONLY_PUBKEY_LEN],
    out_tweaked_xonly: &mut [u8; XONLY_PUBKEY_LEN],
) -> Result<(), DeriveError> {
    let field_bytes = FieldBytes::from(*internal_xonly_pubkey);

    // BIP340 `lift_x`: the unique point with this x-coordinate and even y.
    let p_even: AffinePoint = AffinePoint::decompact(&field_bytes)
        .into_option()
        .ok_or(DeriveError::PointAtInfinity)?;

    let t_bytes = tagged_hash(b"TapTweak", internal_xonly_pubkey);
    // `t` is derived from public data (the tagged hash of a public x-only
    // key); zeroizing it is routine hygiene, not a secrecy requirement.
    let mut t_scalar = Scalar::from_repr(FieldBytes::from(t_bytes))
        .into_option()
        .ok_or(DeriveError::InvalidChildKey)?;

    let q = (ProjectivePoint::from(p_even) + ProjectivePoint::GENERATOR * t_scalar).to_affine();
    t_scalar.zeroize();

    if bool::from(CurveAffine::is_identity(&q)) {
        return Err(DeriveError::PointAtInfinity);
    }

    let x = AffineCoordinates::x(&q);
    out_tweaked_xonly.copy_from_slice(&x);
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    fn hex_to_32(hex: &str) -> [u8; 32] {
        assert_eq!(hex.len(), 64);
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    fn hex_to_vec(hex: &str) -> std::vec::Vec<u8> {
        assert_eq!(hex.len() % 2, 0);
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn to_hex(bytes: &[u8]) -> std::string::String {
        const HEXCHARS: &[u8; 16] = b"0123456789abcdef";
        let mut s = std::string::String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push(HEXCHARS[(b >> 4) as usize] as char);
            s.push(HEXCHARS[(b & 0x0f) as usize] as char);
        }
        s
    }

    // ------------------------------------------------------------------
    // Generator-multiple KATs. Expected values were computed by an
    // independent, from-scratch pure-integer secp256k1 point-arithmetic
    // implementation (plain modular exponentiation for field inversion,
    // schoolbook double-and-add), deliberately *not* using k256 or any
    // other elliptic-curve library, so these tests check k256 against an
    // outside ground truth rather than against itself
    // (IMPLEMENTATION_MAP.md WP-06 DoD: "k256-independent KATs (generator
    // multiples, BIP340 test-vector pubkeys)"). k=3 additionally matches
    // the published BIP340 test-vector 0 public key byte-for-byte, cross-
    // checking the independent computation against a well-known external
    // source.
    // ------------------------------------------------------------------

    const GENERATOR_MULTIPLES: [(u64, &str, &str); 7] = [
        (
            1,
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        ),
        (
            2,
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        ),
        (
            // Matches BIP340 (bitcoin/bips test-vectors.csv) index 0:
            // secret key 3 -> public key
            // F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9.
            3,
            "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
            "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
        ),
        (
            4,
            "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
            "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
        ),
        (
            5,
            "022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
            "2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
        ),
        (
            // Odd-y case (exercises the `03` prefix / odd-y branch).
            6,
            "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556",
            "fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556",
        ),
        (
            7,
            "025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc",
            "5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc",
        ),
    ];

    #[test]
    fn generator_multiples_compressed_and_xonly() {
        for (k, compressed_hex, xonly_hex) in GENERATOR_MULTIPLES {
            let mut privkey = [0u8; 32];
            privkey[24..].copy_from_slice(&k.to_be_bytes());

            let mut compressed = [0u8; COMPRESSED_PUBKEY_LEN];
            privkey_to_compressed_pubkey(&privkey, &mut compressed).unwrap();
            assert_eq!(to_hex(&compressed), compressed_hex, "k={k} compressed");

            let mut xonly = [0u8; XONLY_PUBKEY_LEN];
            privkey_to_xonly_pubkey(&privkey, &mut xonly).unwrap();
            assert_eq!(to_hex(&xonly), xonly_hex, "k={k} xonly");
        }
    }

    /// `(n-1) * G == -G`: independently-known identity (adding `G` to it
    /// must reach the identity after one more addition), cross-checks the
    /// implementation's handling of large near-`n` private keys.
    #[test]
    fn privkey_n_minus_one_equals_negated_generator() {
        let n_minus_1 =
            hex_to_32("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140");
        let mut compressed = [0u8; COMPRESSED_PUBKEY_LEN];
        privkey_to_compressed_pubkey(&n_minus_1, &mut compressed).unwrap();
        // -G: same x as G, odd-y (`03`) sign byte, since G's y is even.
        assert_eq!(
            to_hex(&compressed),
            "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
    }

    #[test]
    fn privkey_zero_is_rejected() {
        let zero = [0u8; 32];
        let mut out = [0u8; COMPRESSED_PUBKEY_LEN];
        assert_eq!(
            privkey_to_compressed_pubkey(&zero, &mut out),
            Err(DeriveError::InvalidChildKey)
        );
        let mut xout = [0u8; XONLY_PUBKEY_LEN];
        assert_eq!(
            privkey_to_xonly_pubkey(&zero, &mut xout),
            Err(DeriveError::InvalidChildKey)
        );
    }

    #[test]
    fn privkey_equal_to_order_is_rejected() {
        // n itself: parse256(n) >= n, must be rejected (not the same as a
        // key that just happens to be large but still < n).
        let n = hex_to_32("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        let mut out = [0u8; COMPRESSED_PUBKEY_LEN];
        assert_eq!(
            privkey_to_compressed_pubkey(&n, &mut out),
            Err(DeriveError::InvalidChildKey)
        );
    }

    #[test]
    fn privkey_all_ff_is_rejected() {
        // 2^256 - 1 > n: another >= n case, distinct from the exact-n
        // boundary above.
        let all_ff = [0xffu8; 32];
        let mut out = [0u8; COMPRESSED_PUBKEY_LEN];
        assert_eq!(
            privkey_to_compressed_pubkey(&all_ff, &mut out),
            Err(DeriveError::InvalidChildKey)
        );
    }

    // ------------------------------------------------------------------
    // BIP32 CKD scalar-add KATs (ground truth: plain integer `(il + kpar)
    // mod n`, independent of k256's field/group code).
    // ------------------------------------------------------------------

    #[test]
    fn ckd_scalar_add_simple() {
        let mut il = [0u8; 32];
        il[31] = 5;
        let mut kpar = [0u8; 32];
        kpar[31] = 7;
        let mut child = [0u8; 32];
        ckd_scalar_add(&il, &kpar, &mut child).unwrap();
        let mut expected = [0u8; 32];
        expected[31] = 12;
        assert_eq!(child, expected);
    }

    #[test]
    fn ckd_scalar_add_rejects_il_equal_to_order() {
        let n = hex_to_32("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        let mut kpar = [0u8; 32];
        kpar[31] = 1;
        let mut child = [0u8; 32];
        assert_eq!(
            ckd_scalar_add(&n, &kpar, &mut child),
            Err(DeriveError::InvalidChildKey)
        );
    }

    #[test]
    fn ckd_scalar_add_rejects_il_greater_than_order() {
        let all_ff = [0xffu8; 32];
        let mut kpar = [0u8; 32];
        kpar[31] = 1;
        let mut child = [0u8; 32];
        assert_eq!(
            ckd_scalar_add(&all_ff, &kpar, &mut child),
            Err(DeriveError::InvalidChildKey)
        );
    }

    #[test]
    fn ckd_scalar_add_rejects_zero_result() {
        // il = n - 3, kpar = 3  =>  (il + kpar) mod n == 0.
        let il = hex_to_32("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413e");
        let mut kpar = [0u8; 32];
        kpar[31] = 3;
        let mut child = [0u8; 32];
        assert_eq!(
            ckd_scalar_add(&il, &kpar, &mut child),
            Err(DeriveError::InvalidChildKey)
        );
    }

    #[test]
    fn ckd_scalar_add_wraps_modulo_n() {
        // il = n - 1, kpar = 2  =>  (n - 1 + 2) mod n == 1.
        let il = hex_to_32("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140");
        let mut kpar = [0u8; 32];
        kpar[31] = 2;
        let mut child = [0u8; 32];
        ckd_scalar_add(&il, &kpar, &mut child).unwrap();
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(child, expected);
    }

    // ------------------------------------------------------------------
    // WP-06 v-fix regression tests (adversarial review finding: secret
    // `k256::Scalar` values were held bare with only per-branch manual
    // `.zeroize()` calls, an easy-to-miss/fragile pattern with no verified
    // evidence the scrub actually clears memory). The fix moves every
    // secret scalar into `zeroize::Zeroizing<Scalar>` so scrubbing is
    // automatic (RAII) on every path, including ones a future edit adds
    // without remembering to call `.zeroize()`, and `parse_scalar_checked`
    // now explicitly scrubs a rejected out-of-range parse instead of
    // letting it drop unscrubbed inside `CtOption`. These tests exercise
    // both the previously under-tested "first scalar valid, second
    // rejected" code path and the actual byte-level effect of the scrub.
    // ------------------------------------------------------------------

    #[test]
    fn zeroizing_scalar_scrub_writes_zero_bytes() {
        // Confirms the scrub `Zeroizing<Scalar>` performs on `.zeroize()`
        // (the same call its `Drop` impl makes on every scope exit)
        // actually overwrites the scalar's byte representation with zero,
        // not merely something that happens to satisfy the constant-time
        // `is_zero()` predicate without the underlying bytes being zero.
        // 1337 == 0x0539, as a 32-byte big-endian scalar.
        let bytes =
            hex_to_32("0000000000000000000000000000000000000000000000000000000000000539");
        let mut scalar = parse_scalar_checked(&bytes).expect("1337 is a valid scalar");

        let mut before = [0u8; 32];
        before.copy_from_slice(&scalar.to_bytes());
        assert_ne!(before, [0u8; 32]);

        scalar.zeroize();

        let mut after = [0u8; 32];
        after.copy_from_slice(&scalar.to_bytes());
        assert_eq!(after, [0u8; 32]);
        assert!(bool::from(scalar.is_zero()));
    }

    #[test]
    fn ckd_scalar_add_rejects_invalid_k_par_with_valid_il() {
        // Exercises the "first scalar (`il`) parses successfully, second
        // (`k_par`) is rejected" path: before the v-fix, this path relied
        // on an explicit `il_scalar.zeroize(); return Err(e);` inside a
        // `match` arm; after the v-fix it relies on `il_scalar` (a
        // `Zeroizing<Scalar>`) being dropped, and so scrubbed, as an
        // ordinary consequence of the `?`-propagated early return from
        // parsing `k_par`. This test pins the observable behavior (still
        // `Err(InvalidChildKey)`, output buffer untouched) across that
        // internal refactor.
        let mut il = [0u8; 32];
        il[31] = 5; // valid, small scalar
        // k_par == n: rejected by parse_scalar_checked.
        let bad_k_par =
            hex_to_32("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        let mut child = [0xAAu8; 32]; // sentinel: must stay untouched on error.
        assert_eq!(
            ckd_scalar_add(&il, &bad_k_par, &mut child),
            Err(DeriveError::InvalidChildKey)
        );
        assert_eq!(child, [0xAAu8; 32]);
    }

    // ------------------------------------------------------------------
    // Tagged-hash KAT (ground truth: Python `hashlib.sha256`-based
    // reference implementation of the exact SPEC formula, independent of
    // both k256 and `seed_core::hash`'s own SHA-256 KATs).
    // ------------------------------------------------------------------

    #[test]
    fn tagged_hash_taptweak_empty_message() {
        let digest = tagged_hash(b"TapTweak", b"");
        assert_eq!(
            to_hex(&digest),
            "8aa4229474ab0100b2d6f0687f031d1fc9d8eef92a042ad97d279bff456b15e4"
        );
    }

    #[test]
    fn tagged_hash_matches_definition_directly() {
        // Re-derive the formula independently of `tagged_hash` itself using
        // only `seed_core::hash::sha256` and a plain concatenation buffer,
        // to guard against a bug that happened to cancel out inside the
        // streaming implementation.
        let tag = b"TapTweak";
        let msg = hex_to_vec("00112233445566778899aabbccddeeff00112233445566778899aabbccddee");
        let th = sha256(tag);
        let mut concat = std::vec::Vec::new();
        concat.extend_from_slice(&th);
        concat.extend_from_slice(&th);
        concat.extend_from_slice(&msg);
        let expected = sha256(&concat);
        assert_eq!(tagged_hash(tag, &msg), expected);
    }

    // ------------------------------------------------------------------
    // BIP341 taproot tweak KATs (ground truth: the same independent
    // from-scratch Python secp256k1 implementation used for the generator
    // multiples above, extended with `lift_x`/tagged-hash/point-add).
    // ------------------------------------------------------------------

    #[test]
    fn taproot_tweak_even_y_internal_key() {
        // internal privkey d = 5: xonly(5G) already has even y, so
        // lift_x(xonly(P)) == P and no sign flip occurs.
        let internal_xonly =
            hex_to_32("2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4");
        let mut out = [0u8; XONLY_PUBKEY_LEN];
        taproot_tweak_xonly(&internal_xonly, &mut out).unwrap();
        assert_eq!(
            to_hex(&out),
            "ee713c671c569fbb39901ea3f75195854ba615099ab33a6aecaa5ed539522f93"
        );
    }

    #[test]
    fn taproot_tweak_odd_y_internal_key_normalizes() {
        // internal privkey d = 6: xonly(6G) has odd y, so this exercises
        // the even-y normalization ("lift_x") branch specifically
        // (IMPLEMENTATION_MAP.md WP-06 pitfall: "taproot tweak uses
        // *x-only* pubkey ... even-y normalization").
        let internal_xonly =
            hex_to_32("fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556");
        let mut out = [0u8; XONLY_PUBKEY_LEN];
        taproot_tweak_xonly(&internal_xonly, &mut out).unwrap();
        assert_eq!(
            to_hex(&out),
            "a8e1f6946495d797bda3c3c6a88cf34375130c57a42a966c9a0508bf3cc2fc1a"
        );
    }

    #[test]
    fn taproot_tweak_invalid_x_coordinate_rejected() {
        // All-`0xFF` is not a valid field element/x-coordinate at all
        // (>= field prime p), so `lift_x` must fail cleanly rather than
        // panic.
        let bogus = [0xffu8; 32];
        let mut out = [0u8; XONLY_PUBKEY_LEN];
        assert_eq!(
            taproot_tweak_xonly(&bogus, &mut out),
            Err(DeriveError::PointAtInfinity)
        );
    }

    // ------------------------------------------------------------------
    // End-to-end composition sanity: privkey -> xonly -> taproot tweak,
    // exercised through the public API only (no internal state peeking),
    // matching how WP-13/WP-14 will actually call this module for BIP86.
    // ------------------------------------------------------------------

    #[test]
    fn privkey_to_xonly_then_taproot_tweak_matches_kat() {
        let mut privkey = [0u8; 32];
        privkey[31] = 5;
        let mut xonly = [0u8; XONLY_PUBKEY_LEN];
        privkey_to_xonly_pubkey(&privkey, &mut xonly).unwrap();

        let mut tweaked = [0u8; XONLY_PUBKEY_LEN];
        taproot_tweak_xonly(&xonly, &mut tweaked).unwrap();
        assert_eq!(
            to_hex(&tweaked),
            "ee713c671c569fbb39901ea3f75195854ba615099ab33a6aecaa5ed539522f93"
        );
    }
}
