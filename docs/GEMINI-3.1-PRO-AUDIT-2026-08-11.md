# Alea Security Audit — Gemini 3.1 Pro (2026-08-11)

> **This is the external Gemini 3.1 Pro audit** (`google/gemini-3.1-pro-preview`)
> of Alea — the third independent AI-assisted review, complementing the
> [GPT 5.6 Sol](GPT-5.6-SOL-AUDIT-2026-08-09.md) and
> [Grok 4.5 Expert](GROK-4.5-EXPERT-AUDIT-2026-08-11.md) audits. AI-assisted with
> independent human review of the findings; it is **not** the independent
> professional *human* audit the project's §36.2 gate 7 still requires, and it
> is not a certification.

Date: 2026-08-11  
Repository: https://github.com/Xerhs/Alea  
Audited commit: `391c5cd`  
Model: `google/gemini-3.1-pro-preview`  
Review: findings independently checked against the audited checkout

## Executive Summary

Alea is written with unusually explicit threat-model documentation and strong intent around fail-closed behavior, deterministic releases, no hidden entropy, and post-secret scrubbing. The repository is correctly labeled as experimental security software, and several high-risk architectural limitations are disclosed rather than hidden.

The audit still found release-blocking issues and several security-relevant gaps:

| ID | Severity | Status | Finding |
| --- | --- | --- | --- |
| ALEA-AUDIT-001 | High | Confirmed, config-dependent | Release publish signature verification trusts `allowed_signers` from the tag being published. |
| ALEA-AUDIT-002 | High | Confirmed, conditional | Fixed five-entry derivation staging can panic if future/approved source mixes exceed five records. |
| ALEA-AUDIT-003 | Medium | Confirmed | Compatibility input scrubbers wipe only `String::len()`, leaving deleted bytes in capacity. |
| ALEA-AUDIT-004 | Medium | Confirmed policy risk | Machine-only RDSEED is broadly enabled for any Intel/AMD RDSEED-capable CPU with an empty denylist. |
| ALEA-AUDIT-005 | Medium | Confirmed policy risk | TPM 2.0 and TPM 1.2 are approved while manufacturer allowlists are empty, making vendor review non-enforcing. |
| ALEA-AUDIT-006 | Medium | Confirmed supply-chain gap | CI checks advisory-db freshness but defers actual offline advisory enforcement. |
| ALEA-AUDIT-007 | Informational | Accepted threat-model risk | UEFI Boot Services remain active throughout mnemonic re-entry. |
| ALEA-AUDIT-008 | Informational | Defense in depth | Web verifier uses `innerHTML`; current dynamic output is escaped, but this is a fragile future-maintenance sink. |

No committed private keys, API tokens, or obvious production credentials were identified in the static text scan. I could not run the Rust build, tests, `cargo audit`, `cargo deny`, `semgrep`, `trivy`, or `gitleaks` locally because this workspace does not currently have those tools installed.

## Scope and Method

Reviewed:

- Rust `no_std` seed-generation and verification crates under `crates/`.
- Entropy source policy in `entropy-policy.toml`.
- UEFI/firmware trust documentation in `SECURITY.md` and `docs/`.
- GitHub Actions release and publication workflows.
- Release signing helper scripts and `allowed_signers`.
- Offline web verifier under `web/`.
- High-level supply-chain posture and committed documentation.

Not performed:

- No local Rust compilation or test execution.
- No binary reverse engineering of built `.efi` artifacts.
- No dynamic UEFI, TPM, RDSEED, RDRAND, or hardware testing.
- No dependency advisory resolution from RustSec, since local Cargo tooling is absent.

## Findings

### ALEA-AUDIT-001: Release Publish Verification Trusts Keyring From The Tag Being Published

Severity: High  
Status: Confirmed, config-dependent release-chain vulnerability  
Affected files:

- `.github/workflows/release-publish.yml:38`
- `.github/workflows/release-publish.yml:41`
- `.github/workflows/release-publish.yml:58`
- `.github/workflows/release-publish.yml:72`
- `scripts/release-verify-signature.sh:21`
- `scripts/release-verify-signature.sh:44`
- `allowed_signers:7`
- `allowed_signers:9`

The `release-publish` workflow checks out the tag supplied by workflow dispatch, then verifies the uploaded `SHA256SUMS.sig` against the `allowed_signers` file from that same checkout:

- `.github/workflows/release-publish.yml:38` names the step "Checkout the tag (for the committed allowed_signers keyring)".
- `.github/workflows/release-publish.yml:41` checks out `ref: ${{ inputs.tag }}`.
- `.github/workflows/release-publish.yml:72` runs `bash scripts/release-verify-signature.sh relverify allowed_signers "$EXPECTED_ID"`.
- `scripts/release-verify-signature.sh:44` verifies with `ssh-keygen -Y verify -f "$ALLOWED"`.

This means the second-phase un-draft gate authenticates release checksums against a keyring supplied by the tag being published. The repository documents the weakness in the keyring itself: `allowed_signers:7-14` describes a single-maintainer, same-repository trust-on-first-use model and says an attacker who controls the repository could replace both the file and signatures.

The earlier `release.yml` tag-trust gate partially mitigates this if the protected environment variable `ALEA_TAG_SIGNER_FPR` is configured. However, the gate explicitly allows operation without that fingerprint pin and emits only a warning:

- `tools/release-verifier/scripts/tag-trust-gate.sh:68-73`

The publish workflow also requires `ALEA_TAG_SIGNER_ID`, but an identity string is weaker than a fingerprint because a malicious `allowed_signers` file can bind the same principal to a different key.

Impact:

An attacker with tag/repository modification capability, and enough workflow/environment access to move a draft through the publish workflow, may be able to replace `allowed_signers` in the tag and provide a matching `SHA256SUMS.sig`, causing the workflow to publish artifacts authenticated by the attacker's key. If `ALEA_TAG_SIGNER_FPR` is correctly configured and environment-protected in the first phase, exploitability is reduced, but the second phase remains anchored to tag-local trust material.

Recommended remediation:

- In `release-publish.yml`, fetch `allowed_signers` from a trusted branch, pinned commit, or protected release-governance source, not from `inputs.tag`.
- Add a required out-of-band fingerprint check to `release-publish.yml`, equivalent to the `ALEA_TAG_SIGNER_FPR` defense in the tag-trust gate.
- Fail closed if the fingerprint pin is absent; do not allow a warning-only production path.
- Add a release workflow regression test where the tag changes `allowed_signers` and signs `SHA256SUMS` with an attacker key. Expected result: publish refuses.

### ALEA-AUDIT-002: Derivation Source Staging Can Panic When Source Count Exceeds Five

Severity: High  
Status: Confirmed, conditional robustness and release-blocking issue  
Affected files:

- `crates/seed-flow/src/flow_secret/derive.rs:123`
- `crates/seed-flow/src/flow_secret/derive.rs:126`
- `crates/seed-flow/src/flow_secret/derive.rs:131`
- `crates/seed-flow/src/flow_secret/derive.rs:136`
- `crates/seed-flow/src/flow_secret/machine.rs:93`
- `crates/seed-flow/src/flow_secret/machine.rs:100`
- `crates/seed-flow/src/flow_secret/machine.rs:454`
- `crates/seed-flow/src/flow_secret/machine.rs:463`
- `crates/seed-flow/src/flow_secret/machine.rs:467`
- `crates/seed-flow/src/flow_secret/machine.rs:476`
- `crates/seed-flow/src/flow_secret/machine.rs:482`
- `crates/seed-flow/src/flow_secret/machine.rs:490`
- `crates/seed-core/src/contracts.rs:442`
- `crates/seed-core/src/contracts.rs:448`
- `crates/seed-protocol/src/transcript/mod.rs:63`

`derive()` allocates a fixed local array of five `SourceInput` records:

- `crates/seed-flow/src/flow_secret/derive.rs:123`

It then appends dice, coin, and every acquired machine source without a capacity check:

- Dice append: `crates/seed-flow/src/flow_secret/derive.rs:126-129`
- Coin append: `crates/seed-flow/src/flow_secret/derive.rs:131-134`
- Machine-source loop: `crates/seed-flow/src/flow_secret/derive.rs:136-139`

The machine container itself can hold five machine sources:

- `crates/seed-flow/src/flow_secret/machine.rs:93-101`

The assembly path can append EFI RNG, RDSEED, TPM2, TPM1.2, and supplementary RDRAND if a primary source succeeded:

- `crates/seed-flow/src/flow_secret/machine.rs:454-493`

The current checked-in policy has EFI RNG disabled, and the real firmware path documents TPM family exclusivity. That makes the common current combined path less likely to exceed five records. However, the surrounding contracts already recognize up to eight source records:

- `crates/seed-core/src/contracts.rs:442-448` defines `MAX_SOURCE_RECORDS = 8`.
- `crates/seed-protocol/src/transcript/mod.rs:63` defines eight canonical tag bytes.

If EFI is approved later, if USB TRNG is wired into the same path, if both TPM families reach a pure/test assembly path, or if future policy expands the source mix, dice + coin + machine sources can exceed the five-entry staging array and panic before `derive_final_entropy()` can return a controlled error.

Impact:

For a pre-OS seed ceremony, panics on or near post-secret paths are unacceptable even when panic scrubbing exists. A panic may abort the ceremony, degrade availability, and exercise emergency cleanup rather than the normal fail-closed path. This is a release-blocking robustness issue because the code and constants disagree about the maximum transcript source count.

Recommended remediation:

- Replace the five-entry local array with `[SourceInput; MAX_SOURCE_RECORDS]`.
- Add a checked append helper that returns a `DeriveFlowError` or pipeline error instead of indexing directly.
- Add regression tests for:
  - dice + coin + RDSEED + RDRAND + TPM2
  - dice + coin + EFI + RDSEED + RDRAND + TPM2
  - the maximum canonical eight-source transcript shape
  - an over-capacity path that fails without panic and scrubs staging/machine material

### ALEA-AUDIT-003: Compatibility String Scrubbers Wipe Length, Not Capacity

Severity: Medium  
Status: Confirmed defense-in-depth issue  
Affected files:

- `crates/alea-verify/src/verify.rs:169`
- `crates/alea-verify/src/verify.rs:172`
- `crates/alea-verify/src/verify.rs:177`
- `crates/alea-verify/src/verify.rs:180`
- `crates/alea-verify/src/verify.rs:181`
- `crates/seed-desktop-test/src/launcher/compat.rs:515`
- `crates/seed-desktop-test/src/launcher/compat.rs:521`
- `crates/seed-desktop-test/src/launcher/compat.rs:532`
- `crates/seed-desktop-test/src/launcher/compat.rs:535`
- `crates/seed-desktop-test/src/launcher/compat.rs:536`

Both compatibility surfaces define a `scrub_string()` helper that converts a mutable string to bytes and overwrites the iterator returned by `iter_mut()`:

- `crates/alea-verify/src/verify.rs:177-185`
- `crates/seed-desktop-test/src/launcher/compat.rs:532-540`

That iterator covers only initialized bytes up to `String::len()`. It does not wipe bytes that remain in the allocation's unused capacity. The code pre-sizes event-entry buffers to `EVENT_BUFFER_CAP = 512` to avoid reallocations during canonical valid entry:

- `crates/alea-verify/src/verify.rs:169-172`
- `crates/seed-desktop-test/src/launcher/compat.rs:515-521`

Pre-sizing helps avoid stale bytes in discarded prior allocations, but it does not clear characters that were typed and then deleted via backspace before final scrub. Those bytes can remain above `len` inside the current allocation.

Impact:

This affects compatibility and verifier input buffers rather than the main Alea seed-generation arena. The files describe the surface as throwaway/foreign compatibility material, which lowers severity. Still, users may paste or type sensitive mnemonic-adjacent material into these tools, and the comments promise a "single-allocation wipe" discipline that is incomplete for edited input.

Recommended remediation:

- Wipe the full allocation capacity before clearing:

```rust
let ptr = s.as_mut_ptr();
for i in 0..s.capacity() {
    unsafe { core::ptr::write_volatile(ptr.add(i), 0) };
}
core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
s.clear();
```

- Add a test helper or instrumented buffer type to simulate typing, deletion, and scrub, then assert deleted bytes are overwritten.
- Update comments to distinguish "live initialized bytes" from "full capacity" if full-capacity scrubbing is intentionally not implemented.

### ALEA-AUDIT-004: Machine-Only RDSEED Is Broadly Enabled For Intel/AMD With Empty Denylist

Severity: Medium now, High before stable release  
Status: Confirmed policy risk  
Affected files:

- `entropy-policy.toml:44`
- `entropy-policy.toml:46`
- `entropy-policy.toml:52`
- `entropy-policy.toml:58`
- `entropy-policy.toml:69`
- `entropy-policy.toml:79`
- `crates/seed-flow/src/entropy_avail.rs:174`
- `crates/seed-flow/src/entropy_avail.rs:177`
- `crates/seed-flow/src/entropy_avail.rs:178`
- `crates/seed-flow/src/entropy_avail.rs:193`

The policy approves RDSEED and allows it to stand alone as a sole source:

- `entropy-policy.toml:44-50`

The same policy then broadly allows any `GenuineIntel` or `AuthenticAMD` family/model/stepping:

- `entropy-policy.toml:52-68`
- `entropy-policy.toml:69-87`

The documentation inside the policy is honest that this is "release scaffolding" and not a real security boundary. However, `compute_mode_availability()` enables machine-only mode whenever EFI RNG or RDSEED is approved and sole-source allowed:

- `crates/seed-flow/src/entropy_avail.rs:174-179`
- `crates/seed-flow/src/entropy_avail.rs:193-197`

Impact:

Machine-only generation can be offered on a very broad class of CPUs where the practical trust decision is "the CPU exposes RDSEED and claims Intel/AMD vendor identity." The UI warning helps, and the experimental label matters, but for a funds-bearing seed generator this is not enough for stable-release posture.

Recommended remediation:

- For stable policy, disable machine-only RDSEED by default unless there is a curated, reviewed CPU/microcode allowlist and a real denylist process.
- Prefer requiring a physical witnessed entropy floor for production/stable mode, with RDSEED only as supplemental entropy.
- Add CI policy tests that fail any stable release policy with broad vendor allow-rules, empty denylist, and `sole_source_allowed = true`.

### ALEA-AUDIT-005: TPM Sources Are Approved While Manufacturer Allowlists Are Empty

Severity: Medium  
Status: Confirmed policy risk  
Affected files:

- `entropy-policy.toml:159`
- `entropy-policy.toml:164`
- `entropy-policy.toml:169`
- `entropy-policy.toml:182`
- `entropy-policy.toml:186`
- `entropy-policy.toml:192`
- `crates/seed-platform-x86/src/rng/tpm2.rs:284`
- `crates/seed-platform-x86/src/rng/tpm2.rs:291`
- `crates/seed-platform-x86/src/rng/tpm12.rs:283`
- `crates/seed-platform-x86/src/rng/tpm12.rs:290`

The policy approves TPM 2.0 and TPM 1.2 while leaving `allowed_manufacturers` empty:

- `entropy-policy.toml:159-169`
- `entropy-policy.toml:182-192`

The TPM implementation only applies the manufacturer gate when that list is non-empty:

- `crates/seed-platform-x86/src/rng/tpm2.rs:284-293`
- `crates/seed-platform-x86/src/rng/tpm12.rs:283-292`

The comments explain that TPM sources never count toward the witnessed floor and never stand alone. That materially limits entropy impact. The risk is that "approved" reads as reviewed even though manufacturer selection is non-enforcing.

Impact:

Any present TPM of the enabled family can be sampled as optional claimed entropy. If the TPM implementation, vendor, or firmware path is weak or virtualized in a way not caught earlier, users may see a stronger trust signal than the policy actually justifies.

Recommended remediation:

- Set TPM approval to false for stable releases until at least one manufacturer/device class has been tested and allowlisted.
- Alternatively, keep TPM enabled only under an explicit "hardware testing" or "unreviewed optional sample" profile.
- Add a stable-policy CI rule: `approved = true` for TPM requires a non-empty manufacturer list and a matching review note.

### ALEA-AUDIT-006: Advisory Database Freshness Is Enforced, But Vulnerable Dependencies Are Not

Severity: Medium  
Status: Confirmed supply-chain gap  
Affected files:

- `.github/workflows/release.yml:244`
- `.github/workflows/release.yml:249`
- `.github/workflows/release.yml:254`
- `.github/workflows/release.yml:255`
- `ci.sh:622`
- `ci.sh:627`

The release workflow checks that a pinned RustSec advisory-db snapshot is fresh:

- `.github/workflows/release.yml:244-255`

The local CI script also runs an advisory-db snapshot freshness gate:

- `ci.sh:622-628`

However, the release workflow explicitly states that actual `cargo deny --offline check advisories` enforcement is deferred:

- `.github/workflows/release.yml:249-252`

Impact:

Keeping an advisory database fresh is useful, but it does not fail a build when a vulnerable crate enters the dependency graph. Exact dependency pins help reproducibility, but they do not replace advisory evaluation.

Recommended remediation:

- Vendor or otherwise pin `cargo-deny` for reproducible offline use.
- Run `cargo deny --offline check advisories` in `ci.sh` and release CI.
- Add a regression fixture or policy test proving CI fails on a known advisory in a controlled test dependency.

### ALEA-AUDIT-007: Version 1 Trusts Active UEFI Firmware During Hidden Re-Entry

Severity: Informational  
Status: Confirmed, accepted and well-documented threat-model limitation  
Affected files:

- `SECURITY.md:50`
- `SECURITY.md:60`
- `SECURITY.md:64`
- `SECURITY.md:66`
- `docs/DESIGN.md:33`
- `docs/DESIGN.md:34`
- `docs/DESIGN.md:36`
- `docs/DESIGN.md:37`

Alea v1 keeps UEFI Boot Services active throughout the secret workflow. The documentation is explicit that firmware handles every keystroke, including hidden mnemonic re-entry:

- `SECURITY.md:60-67`
- `docs/DESIGN.md:33-39`

This is not a hidden vulnerability in the current documentation. It is the central architectural trust ceiling for v1.

Impact:

Malicious firmware, option ROMs, or platform management components can observe re-entry keystrokes and reconstruct the mnemonic even if the display path avoids handing firmware the mnemonic as text.

Recommended remediation:

- Keep the experimental status and the current warning language until v2 removes firmware input from the secret phase.
- Treat application-owned USB HID after `ExitBootServices` as a stable-release prerequisite if the project wants to claim meaningful protection against malicious firmware keyboard capture.
- Add a release checklist item that blocks any claim stronger than "removes the desktop OS, not firmware, from the TCB."

### ALEA-AUDIT-008: Offline Web Verifier Uses Fragile `innerHTML` Sinks

Severity: Informational  
Status: Defense-in-depth issue  
Affected files:

- `web/src/app.js:52`
- `web/src/app.js:55`
- `web/src/app.js:67`
- `web/src/app.js:87`
- `web/src/app.js:199`
- `web/src/app.js:229`
- `web/src/app.js:239`
- `web/src/shell.html:45`
- `web/src/shell.html:138`
- `web/src/shell.html:148`
- `web/src/shell.html:153`

The web verifier renders result blocks through `innerHTML`:

- `web/src/app.js:67-69`

The current row helper escapes dynamic key/value output:

- `web/src/app.js:52-56`

The origin warning also escapes the protocol value before using `innerHTML`:

- `web/src/app.js:229-240`

The static HTML contains strong warnings that browser memory cannot be scrubbed and that mnemonics/passphrases entered into the verifier leave copies:

- `web/src/shell.html:45-52`
- `web/src/shell.html:138`
- `web/src/shell.html:148-153`

Impact:

No current exploitable DOM XSS was confirmed in this review. The risk is maintainability: future additions to result rendering could forget `esc()` and turn user-entered mnemonic/passphrase-adjacent data into HTML.

Recommended remediation:

- Prefer DOM construction with `textContent` for dynamic values.
- Keep `innerHTML` only for fixed static templates.
- Add tests that inject HTML-looking mnemonic/error values and assert tags are not interpreted.

## Positive Security Controls Observed

- The repository repeatedly labels Alea as experimental and not externally audited.
- `SECURITY.md` and `docs/DESIGN.md` clearly disclose firmware, hardware, release-chain, and memory-remanence limitations.
- GitHub Actions use commit-pinned third-party actions rather than floating tags in the reviewed workflows.
- Release flow is draft-first and separates build from final publication.
- `release.yml` runs a full CI gate for tag releases and checks signed tag ancestry against `origin/master`.
- `allowed_signers` documents the TOFU/single-maintainer trust model instead of overstating it.
- The project maintains an explicit audit status table; as of this checkout, 5 of 8 minimum credible gates are marked met, with external review and signed stable release gates still not met.
- Web verifier tests assert that private keys, xprv/WIF, seed, and mnemonic echo are not exposed in public-value screens.

## Tooling Limitations

The following tools were unavailable in the local workspace during this audit:

- `cargo`
- `rustc`
- `cargo-audit`
- `cargo-deny`
- `semgrep`
- `trivy`
- `gitleaks`

Because of this, I did not run:

- `cargo build`
- `cargo test`
- `bash ci.sh`
- dependency advisory checks
- semgrep/static-analysis rulesets
- secret-scanning tools beyond local text search
- binary scanners against freshly built UEFI artifacts

The absence of local tool execution means this report should be treated as a source-level audit, not a complete build/release attestation.

## Recommended Fix Order

1. Fix `release-publish.yml` so second-phase release publication uses trusted/pinned signer material and a mandatory fingerprint pin.
2. Fix `derive.rs` source staging to use `MAX_SOURCE_RECORDS` and checked append semantics.
3. Fix compatibility `scrub_string()` helpers to wipe full allocation capacity, or document the narrower guarantee honestly.
4. Decide whether machine-only RDSEED should be disabled for stable policy until a real CPU/microcode review list exists.
5. Decide whether TPM approval should remain enabled while manufacturer allowlists are empty.
6. Add actual offline advisory enforcement with `cargo deny`.
7. Install Rust/security tooling in the audit environment and rerun `bash ci.sh`, dependency audit, and release-verifier checks.

## Suggested Regression Tests

- Release-publish trust-root test: malicious tag changes `allowed_signers`; malicious `SHA256SUMS.sig` must not publish.
- Release-publish missing-fingerprint test: unset signer fingerprint must fail, not warn.
- Source-count capacity test: maximum valid source transcript must not panic.
- Over-capacity source-count test: invalid/future source mix must return a controlled error and scrub.
- String scrub test: type sensitive characters, delete them, call scrub, and verify deleted bytes in capacity are overwritten.
- Stable policy test: broad RDSEED sole-source rules with empty denylist fail stable-release validation.
- TPM policy test: `approved = true` with empty manufacturer allowlist fails stable-release validation unless explicitly marked hardware-test-only.
- Web verifier XSS test: user-controlled strings containing HTML/script syntax render as text only.

## Bottom Line

Alea's documentation is unusually honest and its release pipeline has moved in the right direction, but it should not be treated as production-grade seed-generation software yet. The most urgent concrete fixes are the tag-local release keyring trust issue and the derivation source-count mismatch. The strongest stable-release blockers after that are not hidden code bugs; they are trust-policy decisions around machine-only RDSEED, TPM approval, UEFI firmware input capture, and missing external review.
