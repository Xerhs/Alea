# After-Audit Remediation Report — 2026-08-09 GPT 5.6 Sol Audit

This report records what changed in Alea in response to the external
**GPT 5.6 Sol** security audit ([`GPT-5.6-SOL-AUDIT-2026-08-09.md`](GPT-5.6-SOL-AUDIT-2026-08-09.md),
audited revision `ad3cc77`). It is a companion to that audit: the audit
states the problems; this report states the fixes and their verification
status.

**Honesty up front.** None of these fixes change Alea's posture: it remains
**EXPERIMENTAL, unaudited-for-production, and not for substantial funds**. The
audit found **no Critical vulnerability and no cryptographic break** in the
entropy → SHA-256 → BIP39 → PBKDF2/BIP32 path; every finding was in release
authenticity, supply-chain authorization, or defense-in-depth. The
remediation raises the bar on those; it does not constitute an independent
re-audit.

## Finding summary

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| ALEA-2026-001 | High | Release authorization trust root is mutable with the source it authorizes | Fixed (governance-gated) |
| ALEA-2026-002 | Medium | `alea-verify.efi` excluded from the signed checksum manifest | Fixed |
| ALEA-2026-003 | Medium | Release publication not atomic with detached checksum signing | Fixed |
| ALEA-2026-004 | Medium | Release workflow doesn't enforce the full CI gate on the exact tagged commit | Fixed |
| ALEA-2026-005 | Medium | PCI/device virtualization detector implemented but not wired into the gate | Fixed (+ hardware follow-up) |
| ALEA-2026-006 | Medium | Mutable GitHub Action tags; release build job has repo write scope | Fixed |
| ALEA-2026-007 | Medium | `release-verifier` does not authenticate the current release signature format | Fixed |
| ALEA-2026-008 | Low | No automated RustSec advisory gate | Fixed (freshness gate + offline `cargo deny` landed 2026-08-11 — Grok F-06) |

## What was changed, per finding

### ALEA-2026-001 (High) — release authorization trust root
The release tag was verified against the `allowed_signers` keyring shipped in
the same checkout it authorizes — a circular trust root a single repo-write
could redefine. Tag authorization now runs through one fail-closed gate,
`tools/release-verifier/scripts/tag-trust-gate.sh`: the tag must be **signed**
against the committed `allowed_signers`, be an **ancestor of `origin/master`**
(no off-master/side-branch releases), and — when the protected `release`
Environment variable `ALEA_TAG_SIGNER_FPR` is set — match a **pinned
fingerprint** (skip-with-loud-warning when unset, never a silent pass). The
required repository settings that make this meaningful (branch/tag protection,
the protected Environment) are documented in
[`RELEASE-GOVERNANCE.md`](RELEASE-GOVERNANCE.md). This raises the required
attacker capability from repo-write to repository-settings-admin; it does
**not** create an independent trust root (only the multi-person
`SIGNING-GOVERNANCE.md` process would).

### ALEA-2026-002 (Medium) — `alea-verify.efi` unsigned in the manifest
The separately chain-loaded verifier binary was omitted from `SHA256SUMS`. It
is now included in the signed checksum manifest and in the `release-verifier`
required-file list like every other shipped executable.

### ALEA-2026-003 (Medium) — non-atomic publication and signing
`release.yml` now creates the GitHub Release as a **draft only**. The detached
`SHA256SUMS.sig` is produced offline (the private key never enters CI) and a
separate `release-publish.yml` (`workflow_dispatch`) verifies it against
`allowed_signers` via `scripts/release-verify-signature.sh` and only then
un-drafts the release. No public release ever exists without present, verified
signature material.

### ALEA-2026-004 (Medium) — CI gate not enforced on the tagged commit
`ci.yml` gained a `workflow_call` entry; `release.yml` reuses it via a
`full-ci` job that `build-and-gate` `needs:`, so the complete `bash ci.sh`
gate runs on the exact tagged commit before any build or publish — the same
gate a `master` merge runs, not a stale or assumed status.

### ALEA-2026-005 (Medium) — virtualization detector not wired in
The implemented PCI bus-0 device sweep (`scan_bus_zero`) was never called by
the production platform gate. It is now wired into `ProdPlatformGate::check`
(`evaluate_with_devices`). **Hardware follow-up:** first real-hardware boot
revealed the sweep opened the PCI root bridge *exclusively*, which makes
firmware disconnect its own GPU driver and black-screens the display — the
same exclusive-open hazard already documented for this project's GOP and TPM
paths. Fixed to a non-exclusive `GetProtocol` open. The sweep remains a
heuristic ("a malicious hypervisor hides these trivially"), never a security
boundary.

### ALEA-2026-006 (Medium) — mutable action tags; over-scoped build job
Every third-party `uses:` across all workflows is now pinned to a full 40-hex
commit SHA (a `ci.sh` gate fails the build if any is not). The release
pipeline is split into three least-privilege jobs — `full-ci` (read),
`build-and-gate` (read, protected Environment), and `publish` (the only
write-scoped job, which merely attaches the already-gated artifact and drafts
the release) — so a compromised build step cannot also gain repo write.

### ALEA-2026-007 (Medium) — release-verifier didn't authenticate the signature
`release-verifier` verified checksums but not the *authenticity* of the
`SHA256SUMS.sig` format actually shipped. It now verifies the detached SSH
signature (`ssh-keygen -Y verify`) against a caller-supplied
`allowed_signers`/identity, with `--require-signature` failing closed
(distinct exit code) when the signature is absent or invalid.

### ALEA-2026-008 (Low) — no RustSec advisory gate
A pinned RustSec advisory-db snapshot (`supply-chain/advisory-db.lock`) plus a
fail-closed **freshness** enforcer (`advisory-db-age`) run in both `ci.sh` and
the release workflow: a stale, missing, or future-dated snapshot fails the
build. **Completed 2026-08-11** (Grok 4.5 Expert audit finding **F-06**, see
[`GROK-4.5-EXPERT-AUDIT-2026-08-11.md`](GROK-4.5-EXPERT-AUDIT-2026-08-11.md)):
the actual `cargo deny --offline check advisories` now runs.
`tools/release-verifier/scripts/advisory-check.sh` fetches rustsec/advisory-db,
pins it to the locked commit and verifies the SHA, then runs the offline check
against that pinned snapshot — deterministic by the verified pin, with no
advisory-db vendored into the repo. It is wired into `ci.sh` (and every release
via the `full-ci` job); `cargo-deny` is a pinned CI tool (0.20.2). The one
current `ignore` (RUSTSEC-2026-0192, `ttf-parser` unmaintained) is documented in
`deny.toml`: it is reachable only via the desktop-rehearsal GUI stack and is
absent from the production binary.

## Verification status

**Verified locally (green):** the gate scripts' host test
(`scripts/tests/gate-scripts.test.sh`), the `release-verifier` unit tests, the
`ci.sh` workflow-security guards (action-pin, release-workflow parity,
advisory-db freshness), and all workflow YAML parsing.

**Not locally verifiable — exercised only by a real release:** the
`workflow_call` reuse, the protected `release` Environment approvals, the
fingerprint pin activating, and the draft→publish hand-off. These require a
tag push once the `RELEASE-GOVERNANCE.md` repository settings are configured.

## Additional fixes found during hardware remediation testing

While verifying the above on real hardware, two unrelated user-facing defects
were found and fixed in the same cycle (outside the audit scope, recorded here
for completeness):

- **Passphrase keyboard decode:** the firmware key decoder dropped SPACE
  (`0x20`) via `char::is_ascii_graphic()`, which failed the passphrase
  keyboard self-test on its first required key and made SPACE untypeable in a
  passphrase. Fixed to accept the full printable-ASCII charset.
- **Passphrase usability:** the extended 95-key keyboard self-test was made
  **optional and advisory** (it never disables entry; the mandatory
  double-entry confirmation is the real safety net), and a plain-language
  guide was added to the entry screen.
