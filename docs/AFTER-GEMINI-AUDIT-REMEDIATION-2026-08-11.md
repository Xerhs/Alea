# After-Audit Remediation — 2026-08-11 Gemini 3.1 Pro Audit

Companion to [`GEMINI-3.1-PRO-AUDIT-2026-08-11.md`](GEMINI-3.1-PRO-AUDIT-2026-08-11.md):
the audit states the findings; this records the fixes. As with the prior audits
this does **not** change Alea's EXPERIMENTAL / not-for-substantial-funds posture,
and it is not the independent *human* audit §36.2 gate 7 still requires (F-02 /
ALEA-AUDIT F-02 equivalent).

| ID | Sev | Status |
|----|-----|--------|
| ALEA-AUDIT-001 | High | **Fixed** — mandatory out-of-band fingerprint pin in the publish phase |
| ALEA-AUDIT-002 | High | **Fixed** — derive staging uses `MAX_SOURCE_RECORDS` + count guard |
| ALEA-AUDIT-003 | Med | **Fixed** — `scrub_string` wipes full capacity |
| ALEA-AUDIT-004 | Med | **Flagged** — stable-policy lint (RDSEED breadth); flip is a policy decision |
| ALEA-AUDIT-005 | Med | **Flagged** — stable-policy lint (TPM empty allowlist); flip is a policy decision |
| ALEA-AUDIT-006 | Med | **Already fixed** (2026-08-11, Grok F-06): offline `cargo deny` gate landed |
| ALEA-AUDIT-007 | Info | Accepted — documented firmware trust boundary (v2 ExitBootServices) |
| ALEA-AUDIT-008 | Info | **Hardened** — auto-escaping template removes the fragile `innerHTML` sink |

## Fixes

### ALEA-AUDIT-001 (High) — tag-local release keyring trust
The second-phase `release-publish.yml` verified `SHA256SUMS.sig` against
`allowed_signers` taken from the tag being published, with an **identity-only**
check — a rewritten tag could rebind the identity to an attacker key.
`scripts/release-verify-signature.sh` now takes an **expected fingerprint**: the
key `allowed_signers` binds to the signer identity must have exactly that
SHA256 fingerprint, supplied out-of-band from the protected `release`
Environment (`ALEA_TAG_SIGNER_FPR`), **not** the tag. `release-publish.yml`
**requires** it and fails closed if unset (no warning-only path). Regression
test (`scripts/tests/gate-scripts.test.sh`): an attacker keyring+signature that
passes identity-only verify is **rejected** by the fingerprint pin.

### ALEA-AUDIT-002 (High) — derivation source-count panic
`derive()` staged sources into a fixed **five**-entry array while
`MAX_SOURCE_RECORDS = 8`; a future policy expansion could index out of bounds
and panic mid-ceremony. The array is now sized to `MAX_SOURCE_RECORDS`, and the
assembled count is checked up front — over-capacity returns the new controlled
`PipelineError::TooManySources` (the fail-closed *ceiling* dual of
`InsufficientSources`) instead of panicking. Regression test: the widest
assemblable set (dice + coin + the full 5-slot machine container = 7 records)
derives without panic.

### ALEA-AUDIT-003 (Med) — scrub wiped length, not capacity
Both compat/verifier `scrub_string()` helpers overwrote only the live `len`
bytes, leaving backspaced characters above `len` in the allocation. They now
wipe the **full capacity** volatilely behind a fence, then clear. Regression
test asserts deleted bytes above `len` are zeroed.

### ALEA-AUDIT-004 + 005 (Med) — policy breadth (flagged, not flipped)
Machine-only RDSEED is broadly enabled (any Intel/AMD, empty denylist,
sole-source), and TPM 2.0/1.2 are approved with empty manufacturer allowlists
(non-enforcing vendor review — the latter enabled for hardware testing). Both
are intentional EXPERIMENTAL scaffolding, so rather than silently change policy,
a new lint (`tools/release-verifier` `policy-stable-lint`, using the real policy
parser) **flags** these as stable-release blockers. `ci.sh` runs it in **report
mode** (exit 0 — it surfaces the config without failing the experimental build);
a future stable-release gate runs it with `--require-stable` (fail-closed).
The actual flip (TPM `approved = false`, a curated RDSEED allow/deny list, a
required physical-entropy floor) is a deliberate release decision, now visible
in CI.

### ALEA-AUDIT-008 (Info) — fragile `innerHTML` sinks
The offline web verifier escaped all dynamic values, but building result HTML by
string concatenation risked a future maintainer forgetting `esc()`. An
auto-escaping tagged template (`h\`...${value}...\``) now escapes every
interpolated value by construction — the static template text is the only
unescaped HTML. The reproducible artifact (`web/alea-web-offline.html`) was
rebuilt (byte-identical across two clean builds; vector harness passes).

## Not code (unchanged)
- **ALEA-AUDIT-002/F-02 human audit**, **F-03 multi-person signing**,
  **F-07 hardware matrix** (Grok equivalents), and **ALEA-AUDIT-007 firmware
  trust boundary** remain human/process or accepted-by-design, honestly
  documented in `SECURITY.md` / `docs/AUDIT-STATUS.md`.
