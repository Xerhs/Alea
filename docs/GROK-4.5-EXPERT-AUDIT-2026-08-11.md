# Alea Security Audit — Grok 4.5 Expert (2026-08-11)

> **This is the external Grok 4.5 Expert (xAI) audit** of Alea. It is the
> second independent AI-assisted review, complementing the
> [GPT 5.6 Sol audit](GPT-5.6-SOL-AUDIT-2026-08-09.md) and its
> [remediation report](AFTER-AUDIT-REMEDIATION-2026-08-09.md). It is AI-assisted,
> **not** the independent *human* professional audit the project's §36.2 gate 7
> still requires (see finding F-02). It is not a certification.

**Project:** Alea (https://github.com/Xerhs/Alea)  
**Repository Owner:** Xerhs  
**Audit Date:** 2026-08-11  
**Auditor:** Grok 4.5 Expert (xAI) — Independent static source and documentation review  
**Audited Revision:** Current `master` (SHA approx. 391c5cdc90024fec649dc8c9a2cd3ce444a85de5)  
**Report Classification:** Confidential / For Project Maintainers & Security Researchers  
**Status:** Experimental Software — Not Production-Ready for Substantial Funds  

---

## 1. Executive Summary

Alea is an air-gapped, pre-operating-system (UEFI) BIP39 mnemonic seed generator that combines user-witnessed physical entropy (dice/coins) with machine entropy sources under a strict, compiled-in policy. It is written primarily in Rust (`no_std` for the UEFI path), emphasizes fail-closed behavior, secret scrubbing, reproducible builds, and extensive self-documentation of its threat model and limitations.

**Overall Risk Rating: HIGH (Pre-Production / Experimental Use Only)**

This rating is driven primarily by:
- Accepted architectural trust in UEFI firmware (Boot Services remain active; keystrokes for hidden re-entry are visible to firmware).
- Absence of an independent professional (human) third-party security audit meeting the project's own external-review gate.
- Residual release-authority and supply-chain governance gaps (even after recent remediations).
- Incomplete real-hardware validation matrix and independent reproducibility confirmation by external parties.

**No Critical (remotely exploitable or deterministic seed-break) vulnerabilities were identified in the reviewed entropy → transcript → SHA-256 → BIP39 → PBKDF2/BIP32 path.** The cryptographic core appears correctly implemented and defended by multiple layers of mechanical tests, frozen vectors, and an independent Python reference implementation.

Prior AI-assisted and internal audits (Entropy Audit 2026-08-08, GPT-5.6 Sol Audit 2026-08-09, Pre-Release Triage 2026-08-04, and related) have already surfaced and largely remediated several Medium/High process and lifecycle issues. This review confirms remediation status where source evidence is available and identifies residual and architectural risks aligned with industry standards (NIST SP 800-218 SSDF, SLSA, CWE, BIP39/BIP32 best practices, RustSec/cargo ecosystem controls).

**Recommendation:** Continue labeling all builds **EXPERIMENTAL**. Do not use for substantial funds until the project's own 8 minimum-credible gates (see `docs/AUDIT-STATUS.md`) are fully met, an independent human audit is completed, and real-hardware evidence is published.

---

## 2. Scope and Methodology

### In Scope
- Entropy collection, policy enforcement, transcript construction, and conditioning.
- BIP39 mnemonic generation, re-entry, passphrase handling, and derivation (fingerprint + addresses).
- Secret lifecycle (arena, scrubbing, panic paths, Drop/zeroize).
- UEFI platform gates (virtualization, console, display, RNG health).
- Supply-chain controls (`Cargo.lock` pinning, `cargo vet`, `deny.toml`, advisory freshness).
- Release, signing, verification, and reproducibility documentation/process.
- Security documentation honesty and prohibited claims.
- Alignment with industry practices for air-gapped crypto seed generators.

### Out of Scope / Limitations
- Full compilation, execution of fault-injection / leakage test suites, or QEMU/UEFI runtime testing (static review only).
- Physical hardware testing, side-channel (power/EM/timing) analysis, DMA attacks, or malicious firmware simulation.
- Line-by-line review of every dependency (k256, sha2, etc.) beyond published provenance notes.
- Branch-protection / GitHub Environment settings (not readable via available integrations).
- Live network or production release artifact verification beyond public documentation.

### Standards & Frameworks Referenced
- NIST SP 800-218 (SSDF) — Secure Software Development Framework.
- SLSA v1.x concepts (provenance, immutable builds, verification).
- CWE (Common Weakness Enumeration) for mapping.
- BIP-0039 / BIP-0032 specifications and community best practices for seed generation.
- Rust ecosystem: RustSec advisories, cargo-deny / cargo-vet, zeroize patterns.
- Industry guidance for air-gapped / dice-based seed generation (observable entropy, fail-closed RNGs, no OS trust).

### Method
Static analysis of repository structure, key source modules, policy files (`entropy-policy.toml`, `deny.toml`), SECURITY.md, DESIGN docs, prior audit reports, and release tooling. Cross-checked claims against code structure and documented remediation. Compared against common failure modes in similar tools (weak entropy fallback, secret leakage via Debug/Copy, mutable release trust roots, missing signature coverage).

---

## 3. Architecture & Threat Model Assessment

Alea correctly removes the general-purpose OS from the seed-generation path, eliminating a large class of desktop malware, clipboard, swap, and telemetry risks. Physical entropy is the counted security floor; machine sources are credited zero bits and fail closed. Ceremony requires write-down + no-echo re-entry + derivation check against a separate signing device.

**Key architectural residual (accepted by design in v1):**
- UEFI Boot Services remain active. Hidden re-entry keystrokes pass through firmware. Malicious or compromised firmware can observe the mnemonic without needing the display. This is explicitly documented and is the primary reason the tool cannot claim “firmware-independent” or “bare-metal trusted input.” Closing it requires ExitBootServices + application-owned HID (planned for a future version).

Virtualization, remote console, and certain platform states are refused, but detection is heuristic (CPUID, firmware strings, PCI device IDs). A sophisticated hypervisor can evade.

**Positive design decisions observed:**
- Domain-separated, length-prefixed transcript + single SHA-256 reduction.
- Explicit policy version and fail-closed source acquisition.
- Fixed-size secret buffers, zeroize features on crypto crates, volatile scrub + Drop backstops, panic-path arena scrub.
- Separate production / test / desktop editions with permanent watermarks and binary policy scanner.
- Independent Python reference + frozen vectors for bit-for-bit cross-checks.
- Conservative machine-source accounting (zero counted bits).
- Prohibited-claims checklist and honest experimental banner on every production-capable build.

---

## 4. Positive Security Controls

| Control | Assessment |
|---------|------------|
| Exact dependency version pinning + Cargo.lock | Strong |
| `cargo vet` with provenance criteria + transparent exemptions | Strong (honest) |
| RustSec advisory freshness gate (`advisory-db-age`) | Present (partial; offline deny check still deferred) |
| Binary policy scanner for production markers / no test watermarks | Strong |
| Fault-injection & leakage test workspaces (mechanically run by `ci.sh`) | Strong design |
| SecretArena + explicit scrub on success/error/panic | Strong |
| No network / no FS / no logs by design in UEFI path | Strong |
| Reproducible image builder + REPRODUCING.md | Strong design |
| Independent Python reference + frozen vectors | Excellent |
| On-screen experimental warnings + prohibited claims | Excellent honesty |

---

## 5. Findings

Findings are risk-based. Prior audit findings that have been remediated (per `docs/AFTER-AUDIT-REMEDIATION-2026-08-09.md` and current tree evidence) are noted as Closed. New or residual items are listed.

### Closed / Remediated (from prior audits, confirmed via documentation & structure)
- ALEA-2026-001 (High) — Mutable release trust root: governance-gated with tag-trust-gate, ancestor-of-master check, optional fingerprint pin.
- ALEA-2026-002 (Medium) — `alea-verify.efi` now in signed SHA256SUMS.
- ALEA-2026-003 (Medium) — Draft-first, sign, verify, then publish.
- ALEA-2026-004 (Medium) — Full `ci.sh` reused on tagged commit.
- ALEA-2026-005 (Medium) — PCI device virtualization detector wired (with non-exclusive open fix for hardware).
- ALEA-2026-006 (Medium) — Full-SHA action pins + job privilege split.
- ALEA-2026-007 (Medium) — release-verifier now supports / requires SSH `.sig`.
- Earlier entropy lifecycle issues (mode re-commit contamination, RDSEED over-collection, EFI repeat-check, secret-bearing PrefixResult, empty-source crypto boundary, etc.).

### Residual / Open Findings

#### F-01 — UEFI Firmware Remains in Secret Trust Boundary (Architectural)
**Severity:** High (if firmware is adversarial)  
**CWE:** CWE-653 (Insufficient Compartmentalization) / CWE-200 (Information Exposure)  
**Status:** Accepted residual (v1 design)  

**Description:** Boot Services stay active. All keystrokes (including no-echo re-entry) are delivered by firmware. A malicious UEFI implementation, option ROM, or BMC can capture the seed.  

**Impact:** Complete compromise of generated wallets if firmware is untrusted.  

**Recommendation:** Document as the headline residual. Pursue v2 ExitBootServices + owned HID keyboard driver. Users must treat firmware as fully trusted.

#### F-02 — No Independent Professional Human Security Audit
**Severity:** High (process / gate)  
**Status:** Open (project’s own §36.2 gate 7 unmet)  

**Description:** All published audits to date are internal or AI-assisted. The project’s minimum-credible gate set correctly requires at least one external review of entropy, derivation, and secret-lifecycle design.  

**Recommendation:** Commission and publish a funded independent human review (source + release process + hardware sampling) before removing the experimental label.

#### F-03 — Release Authority Still Partially Coupled to Repository State
**Severity:** Medium–High  
**CWE:** CWE-345 (Insufficient Verification of Data Authenticity)  
**Status:** Partially mitigated  

**Description:** Remediation raised the bar (tag must be signed, ancestor of master, optional Environment fingerprint). However, full independence of the signing trust root from ordinary repository writers and the tagged revision itself is not yet achieved without the multi-person SIGNING-GOVERNANCE process being exercised.  

**Recommendation:** Complete multi-person key custody, protected Environments with dual approval, and out-of-band trust anchors before stable releases.

#### F-04 — Virtualization / Platform Refusal Is Heuristic Only
**Severity:** Medium  
**CWE:** CWE-693 (Protection Mechanism Failure)  
**Status:** Residual (detector wired)  

**Description:** Even with PCI device sweep, a determined hypervisor can present clean indicators. Project correctly labels this as not proof of bare metal.  

**Recommendation:** Continue treating as “refuse obvious unsafe environments,” never as cryptographic attestation.

#### F-05 — Best-Effort Secret Scrubbing Limitations
**Severity:** Low–Medium  
**CWE:** CWE-226 (Sensitive Information Uncleared Before Release)  
**Status:** Accepted residual (documented)  

**Description:** Volatile writes + fences + Drop/zeroize reduce residue. Compiler spills, registers, microarchitectural buffers, and optimized release builds can leave residual copies. Panic scrub exists; verification read-back is debug-only in release.  

**Recommendation:** Keep claims bounded. Continue arena discipline. Future: stronger barriers or formal memory analysis where feasible.

#### F-06 — Incomplete Automated RustSec Offline Gate
**Severity:** Low  
**Status:** Partially fixed  

**Description:** Freshness of pinned advisory-db is enforced. Full offline `cargo deny check advisories` against vendored snapshot is deferred.  

**Recommendation:** Complete the offline gate and scheduled online monitor.

#### F-07 — Hardware Compatibility & Independent Reproducibility Evidence Incomplete
**Severity:** Medium (gate)  
**Status:** Open  

**Description:** Project’s own gates for third-party reproduction of unsigned payload and physical hardware matrix remain unmet. Schema for hardware reports exists; real multi-vendor data does not.  

**Recommendation:** Engage external reproducers and a hardware test matrix (Intel/AMD, multiple firmware vendors, Secure Boot states, RNG variants) with published per-machine results (no secrets).

### Informational / Positive Observations
- Unsafe blocks are limited and purposeful (volatile scrub, wasm fixed buffers).
- No software PRNG fallback on the seed path.
- Machine-only mode forces strong warnings.
- TPM sources are policy-gated and zero-credited.
- Supply-chain exemptions are transparent rather than over-claimed as “audited.”

---

## 6. Industry Alignment Summary

| Practice | Alea Status |
|----------|-------------|
| Observable / user-controlled entropy | Strong (dice/coin floor) |
| Fail-closed RNG acquisition | Strong |
| No OS trust for generation | Strong (pre-OS) |
| Secret zeroization discipline | Strong (with known CPU limits) |
| Reproducible builds + verification docs | Strong design |
| Dependency pinning + advisory monitoring | Good / improving |
| Independent verification artifacts (Python ref, vectors) | Excellent |
| Honest threat model & residual disclosure | Excellent |
| External professional audit | Missing |
| SLSA-style provenance / dual-control release | Partial |
| Full hardware matrix evidence | Missing |

Alea is among the more carefully engineered experimental air-gapped seed tools reviewed in public sources, particularly in documentation honesty and mechanical test coverage. Its residual risks are typical of the class once the OS is removed: firmware trust, release authenticity, and the impossibility of proving hardware RNG correctness in software.

---

## 7. Recommendations (Prioritized)

### P0 — Before any claim of readiness for real funds
1. Complete external professional audit of entropy path, secret lifecycle, and release process.
2. Fully exercise multi-person signing governance and out-of-band trust roots.
3. Publish independent clean-room reproducibility results.
4. Maintain experimental labeling and on-screen warnings.

### P1 — Defense-in-depth
1. Finish offline RustSec advisory gate + vendoring decision.
2. Expand hardware test matrix and publish results.
3. Continue tightening virtualization / platform gates where low-cost.
4. Pursue v2 trusted-input architecture (ExitBootServices + owned keyboard).

### P2 — Maturity
1. Fuzz policy parser, transcript, BIP39 paths.
2. Formal CODEOWNERS + required reviews for security-critical paths.
3. Signed revocation list process exercised.
4. Consider SBOM + artifact attestation in every release.

---

## 8. Conclusion

Alea demonstrates unusually rigorous engineering and transparency for an experimental BIP39 seed generator. The core cryptographic and entropy-composition design is sound on static review; prior identified defects in lifecycle and release process have been substantially addressed.  

Nevertheless, the combination of an accepted firmware trust boundary, incomplete external audit/reproducibility/hardware evidence, and residual release-authority coupling keeps residual risk **HIGH** for any use protecting substantial value.  

The project’s own documentation and gate table already state this correctly. Users should treat every generated mnemonic as experimental, practice with negligible funds, verify releases independently, and prefer Combined or Dice-only modes when machine RNG trust is undesirable.

This report does **not** constitute a certification, penetration test, or formal evaluation. It is an independent static security review intended to complement the project’s existing audit artifacts.

---

**Report prepared by Grok (xAI)**  
**Date:** 2026-08-11  
**Contact for questions:** Via GitHub issues (non-sensitive) or private security channels per SECURITY.md  

*End of Report*