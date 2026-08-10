# Alea Security Audit — GPT 5.6 Sol (2026-08-09)

> **This is the external GPT 5.6 Sol audit** of Alea at revision `ad3cc77`.
> For what was changed in response, see the companion
> [After-Audit Remediation Report](AFTER-AUDIT-REMEDIATION-2026-08-09.md).

**Repository:** `Xerhs/Alea`  
**Audited revision:** `ad3cc77960e96d297e565e97f93697dad35a2bc8` (`master`)  
**Audit date:** 2026-08-09  
**Auditor:** OpenAI GPT-5.6 Sol — independent AI-assisted source and release-security review  
**Report status:** Final for the audited revision; static review, not a certification  
**Repository path:** `docs/GPT-5.6-SOL-AUDIT-2026-08-09.md`

---

## 1. Executive Summary

Alea is a security-sensitive, pre-OS UEFI application intended to generate BIP39 recovery phrases from user-observable physical entropy and optional machine entropy. Its design has several unusually strong properties for an early-stage wallet-security project: a narrow pre-OS execution environment, explicit threat-model documentation, exact dependency pinning, `cargo vet` policy, fixed-size secret buffers, zeroization features on core cryptographic dependencies, fail-closed entropy-source logic, separate production/test editions, deterministic test vectors, and explicit disclosure that UEFI firmware remains trusted in v1.

The audit did **not identify a Critical vulnerability or a new cryptographic correctness flaw in the reviewed entropy → SHA-256 → BIP39 → PBKDF2/BIP32 path**. Several previously documented source-level defects appear to have been remediated correctly, including the secret-bearing prefix result type, the crypto-boundary empty-source check, machine-only sole-source validation, panic-path arena scrubbing, passphrase normalization handling, and earlier entropy-source lifecycle defects.

The most serious residual weakness is instead in **release authenticity and supply-chain authorization**. The current release workflow verifies a release tag against an `allowed_signers` trust anchor stored in the same repository checkout whose contents and workflow are being authorized. Unless separate tag protection / environment approval prevents it, a repository compromise can therefore redefine both the code and the key that declares that code authentic. This undermines the security value of having a dedicated signing key and is rated **High**.

Six additional Medium findings affect release completeness, signature atomicity, release-verifier behavior, exact-CI gating, virtualization detection, and GitHub Actions hardening. One Low finding concerns the lack of a RustSec advisory gate. The project should remain classified **pre-production / experimental** for high-value seed generation until the High finding, release-integrity Medium findings, and the project's own independent-review/reproducibility gates are closed.

### Overall risk rating

**HIGH — pre-production use only for substantial funds.**

This rating is driven primarily by release-authority architecture and by an explicitly accepted firmware-trust boundary, not by a demonstrated break in BIP39 derivation.

### Finding count

| Severity | Count |
|---|---:|
| Critical | 0 |
| High | 1 |
| Medium | 6 |
| Low | 1 |
| Informational / accepted architectural risk | 5 |

---

## 2. Audit Objective and Standards Basis

The objective was to assess whether the audited revision provides a defensible security posture for a tool that can create Bitcoin recovery material, and to produce findings in a format suitable for repository publication and remediation tracking.

The review methodology is aligned with the intent of:

- **FIRST CVSS v4.0** for vulnerability severity communication. Numeric CVSS scores are intentionally not fabricated for process/governance findings where exploitability depends on repository policy that could not be observed.
- **CWE** mappings where a meaningful software weakness category exists.
- **NIST SP 800-218 SSDF v1.1** for secure-development, dependency, release, vulnerability-management and integrity controls. NIST SP 800-218 Rev. 1 / SSDF v1.2 was still a draft at the audit date and is treated as informative rather than normative.
- **SLSA v1.2** concepts for source/build provenance, immutable build inputs, artifact provenance and verification.
- **RustSec** as the ecosystem-specific advisory source expected for Rust dependency vulnerability monitoring.
- GitHub's secure-use guidance for immutable action references and least-privilege `GITHUB_TOKEN` permissions.

Severity in this report is **risk-based audit severity**. A High issue can be a release/supply-chain weakness even when a conventional network CVSS vector is a poor model.

---

## 3. Scope

The audit covered the following security-relevant areas of the audited commit:

1. Entropy composition and transcript hashing.
2. Physical and machine-source policy/gating.
3. BIP39 checksum/index generation and mnemonic handling.
4. BIP39 passphrase handling and PBKDF2-HMAC-SHA512 derivation.
5. BIP32 / secp256k1 dependency posture at the architecture and dependency-policy level.
6. Secret-bearing type design, scrubbing and panic behavior.
7. UEFI / firmware trust boundaries and virtualization checks.
8. Production/test-edition isolation controls.
9. Release workflow, tag authentication, artifact hashing and detached signatures.
10. `release-verifier` behavior and release-manifest completeness checks.
11. GitHub Actions permissions and action pinning.
12. Dependency pinning, `cargo vet`, and vulnerability-advisory coverage.
13. Public release metadata for `v0.11.0-beta` as evidence of the release process actually exercised.
14. Security documentation, internal audit records, audit-status declarations and known residual risks.

### Out of scope / not independently executed

This was a **static and control-flow review using the GitHub API plus public release metadata**. The audit environment could not clone the repository over the container network, so the complete workspace, standalone fault-injection suites, leakage suites, UEFI cross-build and reproducibility build were **not independently rerun** by this auditor. CI claims are therefore treated as repository controls, not as results independently reproduced here.

No physical-hardware test, firmware fuzzing, cold-boot test, DMA attack, malicious-firmware exercise, compiler-toolchain compromise simulation, oscilloscope/power side-channel analysis, or third-party dependency line-by-line audit was performed.

The connected GitHub integration did not have permission to read branch-protection settings. Branch/tag rule enforcement is therefore marked **Not Independently Verifiable** rather than assumed secure or insecure.

---

## 4. Architecture and Trust Model Assessment

Alea deliberately moves seed generation out of the daily operating system and into a UEFI application. This materially removes ordinary host-OS services, filesystems, swap, desktop telemetry, browser state and typical user-space malware from the direct ceremony path. The architecture also attempts to refuse virtualization, remote/serial console exposure and certain unsafe platform states before secret generation.

The central architectural limitation is correctly disclosed by the project itself: **UEFI Boot Services remain active throughout the v1 ceremony**. Hidden mnemonic re-entry is therefore hidden from the screen, not from firmware. A malicious firmware implementation or compromised pre-OS input stack can observe the typed seed. This is an unavoidable high-impact residual until the design exits Boot Services and owns the relevant input path, or otherwise establishes a firmware-independent trusted input boundary.

This risk should be treated as an **accepted architectural trust assumption**, not buried as a footnote. The current documentation does this substantially better than most comparable projects.

---

## 5. Positive Security Controls Observed

The following controls were verified at source/configuration level and materially improve the project's posture:

- `seed-core::pipeline` contains a crypto-boundary `InsufficientSources` failure rather than relying only on UI/mode gating.
- Machine-only generation re-checks the **actually acquired** machine-source set for a source allowed to stand alone; RDRAND and TPM inputs cannot accidentally satisfy that rule.
- The earlier secret-bearing prefix-result design has been retired in favor of writing the resolved index into a caller-owned output and returning a non-secret discriminant.
- Secret-bearing acquisition records avoid `Copy`, `Clone`, `Debug` and `Display`, and implement explicit scrub plus `Drop` backstops.
- Production panic handling invokes `SecretArena::panic_scrub_registered_arena()` before halting.
- BIP39 passphrases are restricted to printable ASCII; non-ASCII input is rejected. Because Unicode NFKD is identity over the accepted ASCII range, this avoids silent BIP39 passphrase incompatibility without adding a Unicode normalizer to the UEFI TCB.
- The mnemonic phrase and passphrase salt used by PBKDF2 are scrubbed explicitly after use.
- `sha2` and `hmac` are exact-version pinned with their `zeroize` features enabled.
- The Rust toolchain is explicitly pinned (`1.97.1` at the audited commit).
- `cargo vet` is integrated as a dependency-review drift gate, and the repository explicitly distinguishes real audits from exemptions instead of pretending exemptions are security attestations.
- The repository contains dedicated fault-injection and leakage test workspaces and a binary-policy scanner. These were not independently executed in this audit.
- Release artifacts clearly identify the production EFI as **unsigned** rather than implying Secure Boot authenticity that does not exist.
- Security documentation candidly states that internal AI reviews are not a substitute for independent professional review.

---

# 6. Findings

## ALEA-2026-001 — Release authorization trust root is mutable with the source being authorized

**Severity: HIGH**  
**Category:** Release integrity / supply-chain authorization  
**CWE:** CWE-345 (Insufficient Verification of Data Authenticity), architecture-level mapping  
**Affected components:** `.github/workflows/release.yml`, `allowed_signers`, release-tag process  
**Status:** Open

### Description

The release workflow verifies a `v*` tag against the `allowed_signers` file from the **same checked-out repository state**. The repository correctly documents this as trust-on-first-use, but the automated release gate nevertheless treats that mutable file as the keyring used to authorize the release.

This creates a circular trust relationship: the repository content supplies both the artifact-producing code and the trust anchor that says which signing key is valid for that content.

There is a second layer to the same problem: the release workflow itself is repository-controlled and is executed for a tag push. A write-capable actor who can introduce a releasable tagged commit may be able to alter the workflow as well as the keyring unless separate GitHub tag rules, protected environments, required reviewers or equivalent controls prevent it. Those repository settings could not be read by the audit integration.

### Attack scenario

Assuming the attacker can create/update a release tag and commit repository content:

1. Modify the source to produce attacker-controlled or weakened recovery material.
2. Replace `allowed_signers` with an attacker-controlled public key.
3. Modify or preserve the release workflow so the malicious commit is built.
4. Sign the tag with the attacker's corresponding key.
5. The workflow verifies the tag against the key shipped by the same malicious checkout and can publish the resulting release.

The dedicated signing key therefore does not constitute an independent release authority against this class of repository compromise.

### Impact

A successful malicious release of a seed generator can cause **complete compromise of every wallet generated with that release**, including delayed theft designed to evade detection. Impact is therefore catastrophic at the user-asset layer even though exploitation requires a repository/release-control compromise.

### Evidence

- `.github/workflows/release.yml` — tag verification uses `gpg.ssh.allowedSignersFile=allowed_signers` from the checkout.
- `allowed_signers` — explicitly states that the key is published in the same repository and that an attacker controlling the repository can replace the file and signatures together.
- `.github/workflows/release.yml` — release workflow itself is version-controlled in the same repository and triggered on `push.tags: v*`.

### Recommendation

Establish a release authority that is **not modifiable by an ordinary source-code writer or by the tagged source revision itself**.

A strong design is:

1. Protect `v*` tags so only a dedicated release role can create them.
2. Put the expected release signer identity/fingerprint in a protected GitHub Environment or separate control plane, not in the source being authenticated.
3. Require environment approval by at least one additional human for publication.
4. Run release authorization from a protected reusable workflow or default-branch workflow whose security policy cannot be replaced by the tag being evaluated.
5. Require the tag commit to be an ancestor of the protected release branch and to have passed required CI.
6. Keep the offline signing key separate from GitHub authentication credentials.
7. For a stable release, implement the multi-person signing governance already contemplated by the repository.

### Verification test

Create a test branch that changes `allowed_signers` to a throwaway key and signs a test tag with that key. The production release gate must reject it even though the checkout's local `allowed_signers` accepts it.

---

## ALEA-2026-002 — `alea-verify.efi` is excluded from the signed checksum manifest

**Severity: MEDIUM**  
**Category:** Artifact integrity  
**CWE:** CWE-353 (Missing Support for Integrity Check), approximate mapping  
**Affected components:** `.github/workflows/release.yml`, `tools/release-verifier/src/manifest.rs`, release assets  
**Status:** Open

### Description

The release workflow copies three executable/image artifacts into `release-out`:

- `alea-x86_64-unsigned.efi`
- `alea-x86_64-usb.img`
- `alea-verify.efi`

but generates `SHA256SUMS` for only the first two. The current release-manifest checker also does not include `alea-verify.efi` in `REQUIRED_RELEASE_FILES`.

The public `v0.11.0-beta` release confirms that `alea-verify.efi` is shipped as a standalone asset alongside `SHA256SUMS` and `SHA256SUMS.sig`.

The USB image is covered by the signed checksum and contains a verifier copy, so a user who verifies the entire image before flashing indirectly authenticates the verifier **inside that image**. The standalone `alea-verify.efi` asset, however, is not authenticated by the signed checksum manifest.

### Impact

A consumer downloading the standalone verifier cannot use the project's detached checksum signature to authenticate that binary. Because the verifier is itself a security decision tool, treating it as an unhashed side artifact creates an avoidable verification gap.

### Evidence

- `.github/workflows/release.yml` — `sha256sum alea-x86_64-unsigned.efi alea-x86_64-usb.img > SHA256SUMS`.
- `tools/release-verifier/src/manifest.rs` — `REQUIRED_RELEASE_FILES` does not include `alea-verify.efi`.
- `.github/release-notes.md` — lists `alea-verify.efi` as a released standalone verifier.
- `v0.11.0-beta` release metadata — publishes `alea-verify.efi` as a separate release asset.

### Recommendation

Include **every executable or security-relevant downloadable artifact** in the signed manifest, at minimum:

```sh
sha256sum \
  alea-x86_64-unsigned.efi \
  alea-x86_64-usb.img \
  alea-verify.efi \
  > SHA256SUMS
```

Add `alea-verify.efi` to the release-manifest completeness list and to verifier tests. The same rule should apply to SBOMs and any future signed EFI.

### Verification test

Flip one byte in `alea-verify.efi`. `release-verifier` and the release publication gate must fail on its checksum before publication.

---

## ALEA-2026-003 — Release publication is not atomic with detached checksum signing

**Severity: MEDIUM**  
**Category:** Release integrity / TOCTOU / operational signing  
**Affected components:** `.github/workflows/release.yml`, release publication process  
**Status:** Open

### Description

The GitHub Actions workflow publishes the GitHub Release and its unsigned artifacts without producing `SHA256SUMS.sig`. The detached checksum signature is added later as a manual step.

The actual `v0.11.0-beta` release demonstrates this ordering: the release was published at approximately **23:49:33 UTC**, while `SHA256SUMS.sig` was uploaded at approximately **23:52:06 UTC**, leaving an interval of roughly 153 seconds in which the public release existed without the detached checksum signature that the final release documentation tells users to verify.

The concern is not the length of this particular interval; it is that publication and authentication are **not one fail-closed transaction**. A future signing step can be forgotten, delayed or performed over the wrong checksum file while the release is already public.

### Impact

Consumers or automation can retrieve an unauthenticated release during the publication/signing gap. The process can also leave a permanently incomplete release if the manual signing step fails after publication.

### Evidence

- `.github/workflows/release.yml` — generates `SHA256SUMS` and publishes `release-out/*`; no step produces or validates `SHA256SUMS.sig` before `gh release create` / `gh release upload`.
- Public `v0.11.0-beta` release metadata — detached signature timestamp follows release publication by about 2.5 minutes.

### Recommendation

Use a **draft-first, publish-last** model:

1. CI builds artifacts and checksum manifest.
2. Release remains draft/private.
3. Authorized signer signs the exact checksum manifest.
4. CI or a protected release job independently verifies the signature against an out-of-band trust root.
5. Only then is the release made public.

Alternatively use a protected environment with manual approval and a signing service/HSM, but the fail-closed requirement is the same: **no public release until authentication material is present and verified**.

### Verification test

Remove or corrupt `SHA256SUMS.sig` during a release rehearsal. The release must remain unpublished.

---

## ALEA-2026-004 — Release workflow does not enforce the complete CI/supply-chain gate on the exact tagged commit

**Severity: MEDIUM**  
**Category:** Build/release policy bypass  
**Affected components:** `.github/workflows/release.yml`, `.github/workflows/ci.yml`, `ci.sh`  
**Status:** Open

### Description

Push/PR CI executes the comprehensive `bash ci.sh` path. The tag-triggered release workflow does **not** execute that same full gate. It runs selected standalone security suites, builds the UEFI targets, runs the binary-policy scanner and assembles release artifacts, but it does not itself require the complete `ci.sh` result for the exact tagged commit.

The release workflow also does not visibly enforce that the tagged commit is reachable from the protected `master` branch or query a required successful CI status for that exact SHA.

Therefore, a signed `v*` tag can be a logically different security event from “a commit that passed the project's complete CI.”

### Impact

A release can potentially bypass controls that only exist in `ci.sh`, including dependency/supply-chain and broader workspace checks, if a tag is created at a commit that did not traverse the normal protected-branch CI path.

### Evidence

- `.github/workflows/ci.yml` — runs `bash ci.sh` on `master` pushes and pull requests.
- `.github/workflows/release.yml` — does not invoke `bash ci.sh`; instead runs a selected subset of build/security tasks.
- No release-workflow step was observed that verifies the tag commit is an ancestor of `master` or checks a required full-CI status for the tag SHA.

### Recommendation

Before artifact publication, require both:

1. `bash ci.sh` (or a single shared reusable workflow that is byte-for-byte the same security gate) on the tagged commit; and
2. a source-control assertion that the tagged commit is a permitted release-branch commit.

Do not rely solely on “it probably passed CI when merged.” The release job should fail closed if it cannot prove the exact release revision satisfied all required gates.

### Verification test

Create a signed test tag on a commit that deliberately fails one `ci.sh` gate but still builds the UEFI binary. The release job must fail before artifact publication.

---

## ALEA-2026-005 — PCI/device virtualization detector is implemented but not wired into the production platform gate

**Severity: MEDIUM**  
**Category:** Platform policy enforcement  
**CWE:** CWE-693 (Protection Mechanism Failure), approximate mapping  
**Affected components:** `crates/seed-platform-x86/src/virt/report.rs`, `crates/seed-flow/src/firmware_wiring.rs`  
**Status:** Open / already acknowledged in repository audit status

### Description

`seed_platform_x86::virt::report` provides an `evaluate_with_devices(...)` path that incorporates the PCI/device-path virtualization detector. However, the production `ProdPlatformGate::check()` calls only:

```text
virt::report::evaluate(&cpuid, &firmware)
```

The device-aware evaluator is therefore not part of the actual production ceremony gate at the audited revision.

This finding is consistent with the repository's own `docs/AUDIT-STATUS.md`, which records the detector as implemented but not yet wired into the production/test pre-secret flow.

### Impact

A virtualized environment that hides/suppresses the CPUID hypervisor bit and avoids recognized firmware strings, but still exposes a known virtual graphics/input PCI identifier, can evade a detection signal that Alea already knows how to recognize.

This does **not** mean the detector could make deliberate hypervisor evasion impossible; the project correctly states that virtualization detection is not a cryptographic proof of bare metal. The finding is narrower: a detection mechanism intended by policy currently has no effect on the production path.

### Evidence

- `crates/seed-platform-x86/src/virt/report.rs` — contains `evaluate_with_devices`.
- `crates/seed-flow/src/firmware_wiring.rs` — `ProdPlatformGate::check()` invokes `virt::report::evaluate` without the device sweep.
- `docs/AUDIT-STATUS.md` — records the missing wiring as residual work.

### Recommendation

Wire the real UEFI PCI/device enumerator into `ProdPlatformGate` and invoke `evaluate_with_devices` on both production and test UEFI paths. Keep the logic fail-closed if device enumeration is truncated or fails in a way the threat model treats as unsafe.

### Verification test

Simulate each known virtual GPU/input identifier with CPUID/firmware checks deliberately clean. The production platform gate must still return the virtualization refusal.

---

## ALEA-2026-006 — Security-critical GitHub Actions use mutable action tags; release build job has repository write scope

**Severity: MEDIUM**  
**Category:** CI/CD supply chain / excessive privilege  
**CWE:** CWE-829 (Inclusion of Functionality from Untrusted Control Sphere), CWE-250 (Execution with Unnecessary Privileges), approximate mappings  
**Affected components:** `.github/workflows/ci.yml`, `.github/workflows/release.yml`  
**Status:** Open

### Description

The workflows reference actions by mutable major-version tags such as:

- `actions/checkout@v4`
- `actions/cache@v4`
- `actions/setup-node@v4`
- `actions/upload-artifact@v4`

GitHub's own secure-use guidance states that pinning an action to a **full-length commit SHA** is the only way to consume an action as an immutable release.

The release workflow additionally grants `contents: write` to the entire `build-and-gate` job so the final step can publish the release. GitHub documents that actions can access `github.token` even if it is not explicitly passed as an input, making least-privilege token scope relevant to every action in that job.

### Impact

If an action tag is maliciously moved or an upstream action repository is compromised, the modified action executes inside a security-critical build/release job. In the release job it can receive a token with repository write capability, increasing the potential impact from build contamination to release/repository modification.

The fact that these are GitHub-maintained actions lowers likelihood but does not make mutable references immutable.

### Evidence

- `.github/workflows/ci.yml` and `.github/workflows/release.yml` use `@v4` action references rather than full SHAs.
- `.github/workflows/release.yml` sets `permissions: contents: write` for the complete build-and-gate job.

### Recommendation

1. Pin every `uses:` reference to a verified full commit SHA.
2. Use Dependabot or a controlled update process to refresh action SHAs.
3. Split release into at least two jobs:
   - **build/gate:** `contents: read` only;
   - **publish:** minimal `contents: write`, consuming immutable artifacts/digests from the successful build job.
4. Add artifact attestation/provenance so the publish job can prove which build produced the binaries it is releasing.
5. Set explicit minimal permissions on ordinary CI as well.

### Verification test

Enable repository policy requiring full-SHA action pinning. Both CI and release workflows must continue to pass.

---

## ALEA-2026-007 — `release-verifier` does not authenticate the signature format used by the current release

**Severity: MEDIUM**  
**Category:** Verification-tool mismatch / false sense of authenticity  
**CWE:** CWE-345 (Insufficient Verification of Data Authenticity), approximate mapping  
**Affected components:** `tools/release-verifier`, `VERIFYING-MEDIA.md`, release format  
**Status:** Open

### Description

The published `v0.11.0-beta` release uses an SSH detached signature named `SHA256SUMS.sig` and documents manual verification with `ssh-keygen -Y verify`.

The repository's `release-verifier` CLI, however, is still built around `SHA256SUMS.minisig` and `minisign`. Its documented exit behavior explicitly permits exit code `0` when all hashes match and **no `SHA256SUMS.minisig` is present**.

Because the current official release contains `SHA256SUMS.sig`, not `SHA256SUMS.minisig`, the tool does not authenticate the currently published signature at all. A consumer can therefore run the named release-verification tool on the official release and receive a successful hash result without the tool proving source authenticity.

The documentation partially mitigates this by describing the manual SSH-signature command, but automated verification and actual release format have diverged.

### Impact

A script or user that treats `release-verifier` exit code `0` as “the current release is authenticated” can accept a directory whose files and `SHA256SUMS` were modified together by the same compromised distribution source. This is exactly the threat detached signatures are meant to address.

### Evidence

- `tools/release-verifier/src/main.rs` — accepts `--pubkey` for a minisign key, checks `SHA256SUMS.minisig`, and defines exit `0` when the minisig file is absent and hashes match.
- `VERIFYING-MEDIA.md` — current tag/checksum procedure uses `SHA256SUMS.sig` with SSH verification, while later verifier documentation still describes minisign behavior.
- Public `v0.11.0-beta` release — contains `SHA256SUMS.sig` and no `SHA256SUMS.minisig`.

### Recommendation

Make the verifier support the **actual release signature format** and fail closed under the project's current release policy.

Recommended migration:

1. Add support for `SHA256SUMS.sig` using `ssh-keygen -Y verify` or a carefully reviewed Ed25519/SSHSIG implementation.
2. During transition, detect both `.sig` and `.minisig`, but make the expected format explicit in release metadata/version policy.
3. For an authenticated release mode, **absence of the expected detached signature must be nonzero**.
4. Do not obtain the trusted signer key solely from the release directory being verified; use the out-of-band trust root fixed under ALEA-2026-001.
5. Update `manifest.rs`, CLI help, `VERIFYING-MEDIA.md`, tests and release assembly together in one change.

### Verification test

Run the verifier against these cases:

- valid SSH signature → success;
- missing `.sig` on a release that claims authentication → nonzero;
- modified `SHA256SUMS` → nonzero;
- correct hashes but wrong SSH signer → nonzero;
- malicious replacement `allowed_signers` bundled with release → nonzero when compared with the externally trusted key.

---

## ALEA-2026-008 — No automated RustSec advisory gate was found

**Severity: LOW**  
**Category:** Dependency vulnerability management  
**Affected components:** CI / dependency-security process  
**Status:** Open

### Description

Alea has a meaningful `cargo vet` policy and an additional dependency-pinning audit. These controls answer important questions — whether dependencies are pinned, whether dependency drift was reviewed, and whether an explicit exemption/audit record exists.

They do **not** answer the separate question: “Does the resolved `Cargo.lock` contain a version with a newly published RustSec security advisory?”

Repository search found no `cargo-audit`, `cargo deny` advisory check, or `rustsec` gate in the audited revision.

This finding does **not** assert that a current dependency is known-vulnerable. It states that the project lacks an automated ecosystem-advisory control capable of discovering that condition when an advisory appears after a dependency was reviewed and pinned.

### Impact

A dependency can remain exactly pinned and fully compliant with the local `cargo vet` record while later becoming the subject of a RustSec advisory. Without a scheduled/admission gate, detection depends on manual monitoring.

### Recommendation

Add an independent advisory check, for example `cargo audit` or `cargo deny check advisories`, on a schedule and before release.

Because Alea values deterministic/offline release gates, a good architecture is:

- online scheduled advisory monitoring against the current RustSec DB;
- automated issue/PR creation on new advisories;
- release gate against a pinned/snapshotted advisory DB with an enforced maximum age;
- documented exception process for unmaintained/yanked/advisory-only findings.

Do not treat `cargo vet` as a substitute; use both.

---

# 7. Accepted / Informational Architectural Risks

These are not newly discovered vulnerabilities in the audited revision, but they materially bound what security claims Alea can make.

## AR-01 — Firmware remains inside the secret trust boundary

**Impact: High if firmware is malicious.** UEFI Boot Services remain active and hidden mnemonic re-entry passes through firmware input. A compromised firmware can observe the seed. The repository discloses this clearly. Future mitigation requires a substantially different trusted-input architecture, such as exiting Boot Services and owning the HID path.

## AR-02 — Virtualization refusal is heuristic, not proof of bare metal

Even after ALEA-2026-005 is fixed, a malicious hypervisor can attempt to emulate bare-metal properties. Treat virtualization checks as refusal of obvious unsupported environments, not as a cryptographic attestation of physical execution.

## AR-03 — No independent human/professional security audit gate is met

The repository documents internal AI-assisted audits, including strong fix/re-audit work. Those reviews are useful but are not equivalent to an independent professional source audit, hardware review and release-process assessment. The project's own audit-status document correctly keeps the external-review gate open.

## AR-04 — Reproducibility is designed but not independently demonstrated by this audit

Reproducible-build documentation and deterministic tooling are positive controls, but this auditor did not perform a clean-room rebuild and byte comparison. A stable release should publish independent reproducer results from at least two environments/organizations.

## AR-05 — Branch/tag governance was not independently verifiable

No `.github/CODEOWNERS` file was present. More importantly, the GitHub integration was denied access to branch-protection settings, so required reviews, required status checks, force-push protection and tag rules could not be verified. These controls should be documented in a release-governance record or exported as evidence for future audits.

---

# 8. Cryptographic and Secret-Lifecycle Review Notes

## 8.1 Entropy composition

The reviewed design uses a canonical, domain-separated transcript and SHA-256 conditioning. Physical entropy is the security-floor source; machine-source bytes are conservatively credited zero counted bits. The current pipeline rejects an empty/zero-content source set at the cryptographic boundary.

The machine source is collected before later physical input in combined mode, which reduces adaptive-source concerns: an untrusted machine RNG cannot choose its output after observing later dice/coin events.

No software PRNG fallback was identified in the reviewed source paths. The security of machine-only mode remains dependent on hardware RNG quality and policy; combined/dice-only modes provide a user-controlled alternative.

## 8.2 BIP39

The reviewed BIP39 implementation derives checksum bits from SHA-256 of final entropy and constructs 11-bit indexes from `entropy || checksum`, rather than choosing words independently. The embedded wordlist has a pinned digest self-check.

The previous prefix-resolution secret-copy issue appears closed: secret word indexes are written into caller-owned storage while the returned result is a non-secret outcome enum.

## 8.3 Passphrase / PBKDF2

Passphrase input is deliberately limited to printable ASCII. This is a valid compatibility strategy because NFKD normalization does not change accepted bytes. Non-ASCII is rejected rather than silently derived differently from another wallet.

PBKDF2 uses HMAC-SHA512 with 2048 iterations, and the salt is built as `"mnemonic" || passphrase`. The materialized phrase and salt buffers are explicitly scrubbed after derivation.

## 8.4 Cryptographic dependency handling

The workspace pins exact versions for `sha2`, `hmac`, `pbkdf2`, `k256`, `zeroize`, `uefi` and other security-critical dependencies. `sha2` and `hmac` enable their `zeroize` features. `k256` is used instead of a project-owned secp256k1 implementation, which is the right direction for reducing custom cryptographic code.

The repository's `cargo vet` record is transparent that many packages remain explicit exemptions rather than completed line-by-line audits. That honesty should be preserved; do not convert exemptions into “audited” labels without real review.

## 8.5 Scrubbing and abort paths

Secret containers generally use fixed buffers, explicit scrub methods and `Drop` defense-in-depth. The production panic handler additionally scrubs the registered secret arena before halting, addressing the important fact that `panic = "abort"` does not run ordinary unwinding/destructors.

As with all software zeroization on optimized general-purpose CPUs, this reduces but cannot mathematically prove elimination of every register, cache, compiler spill or microarchitectural copy. The project's claims should remain bounded accordingly.

---

# 9. Release and Supply-Chain Assessment

This is the area with the largest gap between Alea's strong design intent and a production-grade security posture.

### Strong controls

- Exact Rust toolchain pin.
- Exact direct dependency versions.
- `Cargo.lock`-based builds.
- `cargo vet` review/exemption record.
- Signed source tag in the current beta process.
- Binary-policy scanner.
- Deterministic USB-image builder.
- SHA-256 manifest.
- Clear “unsigned EFI” labeling.

### Missing / incomplete controls

- Independent trust root for release authorization.
- Atomic sign-then-publish workflow.
- Signed coverage of every downloadable executable artifact.
- Verifier support for the actual current SSH signature format.
- Full CI gate on the exact release tag SHA.
- Immutable full-SHA pinning for GitHub Actions.
- Least-privilege separation between build and publish jobs.
- SLSA-style build provenance / GitHub artifact attestations.
- Automated RustSec advisory monitoring/gating.
- Independently verifiable branch/tag governance evidence.

The project is close to having the ingredients for a strong release pipeline, but the remaining gaps are security-significant because **release compromise is equivalent to seed compromise** for a seed-generation tool.

---

# 10. Priority Remediation Plan

## P0 — Before the next release intended for real wallet use

1. Fix **ALEA-2026-001**: move release authorization/trust root outside mutable source state and protect release tags/environment.
2. Fix **ALEA-2026-002**: hash/sign `alea-verify.efi` and include it in the manifest.
3. Fix **ALEA-2026-003**: sign and verify before making a GitHub Release public.
4. Fix **ALEA-2026-004**: require the full security CI on the exact tagged commit.
5. Fix **ALEA-2026-007**: make `release-verifier` authenticate the release signature format actually published.
6. Fix **ALEA-2026-005** if release documentation continues to claim production refuses the implemented virtual-device signatures.

## P1 — Before a stable / high-value release

1. Fix **ALEA-2026-006**: full-SHA action pinning and split read-only build from write-capable publication.
2. Fix **ALEA-2026-008**: RustSec advisory monitoring/gate.
3. Add signed build provenance / artifact attestations for every release binary/image and the SBOM.
4. Complete an independent clean-room reproducibility exercise and publish results.
5. Commission at least one independent human security audit covering source, UEFI boundaries, release process and supply chain.
6. Perform a real-hardware matrix across multiple firmware vendors, including negative tests for console redirection, virtualization indicators, TPM modes and RNG failure behavior.

## P2 — Defense-in-depth / maturity

1. Publish repository/tag security-policy evidence (required reviews, required status checks, tag protection, force-push policy).
2. Add CODEOWNERS for security-critical paths and require security-review approval where GitHub governance supports it.
3. Add fuzzing/property tests for policy parsing, BIP39 prefix entry, transcript serialization, release manifest parsing and simulated UEFI topology inputs.
4. Maintain a signed revocation mechanism and documented key-rotation rehearsal before stable release.
5. Consider a future architecture that removes UEFI firmware from the hidden seed-entry path.

---

# 11. Suggested Release Security Architecture

A production-grade future pipeline should look conceptually like this:

```text
protected source branch
        |
        v
full CI / tests / cargo-vet / RustSec / reproducibility gates
        |
        v
build job (contents:read only; pinned actions)
        |
        +--> build provenance / SBOM attestation
        |
        v
immutable artifacts + SHA256SUMS (all executable assets)
        |
        v
offline / protected-environment signer
        |
        v
independent signature verification against out-of-band trust root
        |
        v
required reviewer approval
        |
        v
publish GitHub Release (contents:write only here)
        |
        v
post-publish verification of every asset + attestation + signature
```

The important property is **separation of authority**: source authors, build infrastructure and release signers should not all be represented by mutable files in the same commit.

---

# 12. Regression Tests Recommended for Findings

| Test ID | Required behavior |
|---|---|
| RT-001 | Replacing `allowed_signers` in a tagged source revision must not make a new signer trusted. |
| RT-002 | One-byte corruption of `alea-verify.efi` must fail signed-manifest verification. |
| RT-003 | Missing/corrupt checksum signature must prevent public release. |
| RT-004 | Tagging a commit that fails `ci.sh` must prevent release. |
| RT-005 | Known virtual PCI GPU/input IDs must fail the production platform gate even when CPUID/firmware strings look physical. |
| RT-006 | Workflow policy check rejects every non-full-SHA `uses:` reference. |
| RT-007 | Current `release-verifier` successor must reject correct hashes with missing/incorrect SSH signature. |
| RT-008 | CI/release fails when the RustSec advisory scan reports an unwaived vulnerability. |

---

# 13. Security Claims the Project Can and Cannot Make Today

### Defensible claims at the audited revision

- The application is intentionally pre-OS and designed to avoid normal filesystem/network persistence paths.
- The reviewed core derivation follows the expected BIP39/PBKDF2 structure and uses a reviewed third-party secp256k1 dependency rather than custom curve arithmetic.
- Physical entropy can provide a user-controlled security source independent of the CPU RNG.
- Machine entropy is conservatively not credited toward the counted physical entropy floor.
- The project has unusually explicit known-risk documentation and several meaningful test/supply-chain controls.

### Claims that should not be made yet

- “Externally audited” or “professionally audited.”
- “Firmware-independent” or “safe against malicious firmware.”
- “Guaranteed bare metal.”
- “Secure Boot authenticated.”
- “Release integrity cannot be bypassed by repository compromise.”
- “Every published executable is covered by the signed checksum manifest.”
- “The release-verifier automatically authenticates the signature used by the current release.”
- “Production ready for substantial funds.”

---

# 14. Audit Conclusion

Alea's **core cryptographic/secret-handling architecture is substantially better than its experimental label might suggest**, and the repository shows evidence of repeated adversarial review and meaningful remediation. The audited revision closes several classes of defects that are common in seed-generation tools: weak fallback entropy, secret-bearing debug/copy types, mode-state contamination, panic-path residue, silent Unicode passphrase divergence and casual dependency drift.

However, a seed generator's security boundary includes **how users obtain the binary**. On that dimension, the audited release path is not yet commensurate with the risk of the artifact it distributes. The High release-authorization finding and the Medium manifest/signature/CI findings can allow the distribution process to become the weakest link even if the seed derivation itself remains correct.

The recommended path is therefore not a redesign of the entropy algorithm. It is to harden **release authority, artifact completeness, exact-commit CI enforcement, immutable CI dependencies, signature verification and build provenance**, followed by an independent human review and clean-room reproducibility exercise.

**Final assessment for commit `ad3cc77960e96d297e565e97f93697dad35a2bc8`: HIGH residual risk for production/high-value use; promising core design; release-security remediation required before a stable trust claim.**

---

# Appendix A — Finding Summary

| ID | Severity | Title | Primary remediation |
|---|---|---|---|
| ALEA-2026-001 | **High** | Release authorization trust root is mutable with source | Out-of-band trust root + protected release authority |
| ALEA-2026-002 | **Medium** | `alea-verify.efi` omitted from signed checksum manifest | Hash/sign all executable assets |
| ALEA-2026-003 | **Medium** | Release is public before checksum signature exists | Draft → sign → verify → publish |
| ALEA-2026-004 | **Medium** | Release tag does not require complete CI gate on exact SHA | Run/require full `ci.sh` for release commit |
| ALEA-2026-005 | **Medium** | Device virtualization detector not wired to production | Use device-aware production evaluator |
| ALEA-2026-006 | **Medium** | Mutable action tags + write-capable release build job | Pin full SHAs; split read/write jobs |
| ALEA-2026-007 | **Medium** | Verifier ignores current SSH checksum signature | Support/require `SHA256SUMS.sig` |
| ALEA-2026-008 | **Low** | No automated RustSec advisory gate found | Add scheduled + release advisory checks |

---

# Appendix B — Evidence Index

The following repository locations were central to this review. References are symbol/step based so the report remains useful after line-number drift.

- `README.md`
- `SECURITY.md`
- `docs/DESIGN.md`
- `docs/AUDIT-STATUS.md`
- `docs/PRE-RELEASE-AUDIT.md`
- `docs/ENTROPY-AUDIT.md`
- `VERIFYING-MEDIA.md`
- `allowed_signers`
- `Cargo.toml`
- `Cargo.lock`
- `rust-toolchain.toml`
- `entropy-policy.toml`
- `supply-chain/README.md`
- `supply-chain/config.toml`
- `supply-chain/audits.toml`
- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `.github/release-notes.md`
- `crates/seed-core/src/contracts.rs`
- `crates/seed-core/src/pipeline/mod.rs`
- `crates/seed-core/src/hash/mod.rs`
- `crates/seed-core/src/bip39/mod.rs`
- `crates/seed-core/src/passphrase.rs`
- `crates/seed-flow/src/flow_secret/machine.rs`
- `crates/seed-flow/src/firmware_wiring.rs`
- `crates/seed-platform-x86/src/virt/report.rs`
- `crates/seed-uefi-production/src/main.rs`
- `tools/release-verifier/src/main.rs`
- `tools/release-verifier/src/manifest.rs`
- `tools/release-verifier/src/bin/dependency-audit.rs`
- public GitHub release metadata for `v0.11.0-beta`

---

# Appendix C — Auditor Independence / Provenance Statement

This report was produced by **OpenAI GPT-5.6 Sol** from source and repository metadata retrieved from the audited GitHub revision and current public release metadata. It is an **AI-assisted independent review**, not a human professional penetration test, formal verification, Common Criteria evaluation, FIPS validation, or financial-security certification.

The report should be committed as evidence of an additional adversarial review, but it should **not** be used to mark Alea's own external-human-review gate as complete.
