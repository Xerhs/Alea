//! policy-stable-lint (Gemini 3.1 Pro audit findings F/004 + F/005).
//!
//! Flags entropy-policy.toml states that are acceptable for EXPERIMENTAL
//! builds but MUST be resolved before a STABLE release — using the SAME
//! parser the firmware uses, so this check can never drift from how the
//! policy is actually interpreted.
//!
//! Two checks:
//!   - F/005: a TPM family is `approved = true` while its
//!     `allowed_manufacturers` list is empty, so the manufacturer gate is
//!     non-enforcing (any TPM of that family is sampled).
//!   - F/004: RDSEED is `approved` AND `sole_source_allowed` AND the CPU
//!     rules admit essentially any modern Intel/AMD part AND the denylist is
//!     empty — machine-only generation offered on an over-broad CPU class.
//!
//! Usage:
//!   policy-stable-lint [entropy-policy.toml] [--require-stable]
//!
//! Default mode REPORTS findings and exits 0 (Alea is experimental; the
//! current config is intentional scaffolding). `--require-stable` exits 1 on
//! any finding — the gate a future stable-release process runs. This never
//! decides the policy; it only surfaces what a stable release would have to
//! change.
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let mut path = String::from("entropy-policy.toml");
    let mut require_stable = false;
    for a in &args[1..] {
        match a.as_str() {
            "--require-stable" => require_stable = true,
            s if !s.starts_with('-') => path = s.to_string(),
            other => {
                eprintln!("usage: policy-stable-lint [entropy-policy.toml] [--require-stable]");
                eprintln!("unknown argument: {other}");
                return ExitCode::from(64);
            }
        }
    }

    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("FAIL: cannot read {path}: {e}");
            return ExitCode::from(1);
        }
    };
    let policy = match seed_protocol::policy::parse(&text) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("FAIL: cannot parse {path}: {e:?}");
            return ExitCode::from(1);
        }
    };

    let mut findings: Vec<String> = Vec::new();

    // F/005 — TPM approved with an empty (non-enforcing) manufacturer allowlist.
    if policy.tpm2.approved && policy.tpm2.allowed_manufacturers().is_empty() {
        findings.push(String::from(
            "[tpm2] approved = true with an EMPTY allowed_manufacturers — vendor review is \
             non-enforcing (any present TPM 2.0 can be sampled). Stable requires a reviewed, \
             non-empty manufacturer list, or approved = false.",
        ));
    }
    if policy.tpm12.approved && policy.tpm12.allowed_manufacturers().is_empty() {
        findings.push(String::from(
            "[tpm12] approved = true with an EMPTY allowed_manufacturers — same non-enforcing \
             risk as [tpm2].",
        ));
    }

    // F/004 — machine-only RDSEED broadly enabled as a sole source. Probe two
    // ordinary modern parts: if BOTH are admitted, the rules are effectively
    // "any Intel/AMD with RDSEED", which combined with sole-source + an empty
    // denylist is the over-broad machine-only posture the audit flags.
    let broad = policy.rdseed.is_cpu_allowed("GenuineIntel", 6, 158, 10)
        && policy.rdseed.is_cpu_allowed("AuthenticAMD", 25, 33, 2);
    if policy.rdseed.approved
        && policy.rdseed.sole_source_allowed
        && broad
        && policy.denylist().is_empty()
    {
        findings.push(String::from(
            "[rdseed] approved + sole_source_allowed with broad Intel/AMD allow-rules and an \
             EMPTY denylist — machine-only generation is offered on essentially any \
             RDSEED-capable CPU. Stable should require a witnessed physical-entropy floor \
             (RDSEED supplemental only) or a curated CPU allow/deny list.",
        ));
    }

    if findings.is_empty() {
        println!("PASS: entropy-policy.toml has no experimental-only stable-release blockers.");
        return ExitCode::SUCCESS;
    }

    let tag = if require_stable {
        "STABLE-BLOCKER"
    } else {
        "STABLE-BLOCKER (experimental: reported, not fatal)"
    };
    for f in &findings {
        println!("{tag}: {f}");
    }
    if require_stable {
        eprintln!(
            "FAIL: {} stable-release policy blocker(s) — refusing (--require-stable).",
            findings.len()
        );
        ExitCode::from(1)
    } else {
        println!(
            "NOTE: {} finding(s) above are acceptable for EXPERIMENTAL builds but MUST be \
             resolved before a stable release. Run with --require-stable to enforce.",
            findings.len()
        );
        ExitCode::SUCCESS
    }
}
