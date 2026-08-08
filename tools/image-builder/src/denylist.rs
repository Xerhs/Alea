//! `DENYLIST.txt` release-artifact generator (WP-29, SPEC §15, §31, §32).
//!
//! SPEC §31: "The release MUST include: ... platform denylist version."
//! SPEC §32 lists `DENYLIST.txt` as one of the fixed release-archive
//! files. Before this module, no tool derived a release-facing denylist
//! artifact from the compiled-in `entropy-policy.toml` at all (spec-
//! conformance audit finding, 2026-08-04).
//!
//! This module extracts the `[[denylist]]` records from
//! `entropy-policy.toml` (SPEC §15: "Known-bad platform denylist
//! entries"; grammar owned by WP-12, `crates/seed-protocol/src/policy/`)
//! into a plain-text, human-readable release artifact. It deliberately
//! does **not** reuse `seed-protocol`'s own parser: that crate is a
//! `no_std` production dependency graph member (SPEC §9, §28 —
//! `seed-uefi-production` must not gain new dependency edges from a
//! release-engineering tool), and this module only ever needs to read
//! seven fixed fields per `[[denylist]]` record, not the full policy
//! grammar (efi_rng/rdseed/rdrand sections, CPU allow-rules, validation
//! rules) that parser is responsible for enforcing at boot time.
use std::fmt::Write as _;

/// One `[[denylist]]` record (SPEC §15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenylistRecord {
    pub vendor: String,
    pub family_min: u32,
    pub family_max: u32,
    pub model_min: u32,
    pub model_max: u32,
    pub stepping_min: u32,
    pub stepping_max: u32,
    pub reason: String,
}

/// Failure parsing an `entropy-policy.toml`-shaped input for its
/// `[[denylist]]` records.
#[derive(Debug)]
pub enum DenylistParseError {
    /// A `[[denylist]]` block is missing a required field.
    MissingField { block_index: usize, field: &'static str },
    /// A required numeric field did not parse as an unsigned integer.
    InvalidNumber { block_index: usize, field: &'static str, value: String },
}

impl std::fmt::Display for DenylistParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DenylistParseError::MissingField { block_index, field } => {
                write!(f, "[[denylist]] block #{block_index} is missing required field `{field}`")
            }
            DenylistParseError::InvalidNumber { block_index, field, value } => {
                write!(f, "[[denylist]] block #{block_index} field `{field}` is not a valid number: {value:?}")
            }
        }
    }
}

impl std::error::Error for DenylistParseError {}

fn extract_str_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(key)?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=')?;
    let rest = rest.trim();
    let rest = rest.strip_prefix('"')?;
    rest.strip_suffix('"')
}

fn extract_num_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(key)?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=')?;
    // Strip a trailing inline comment, if any.
    let rest = rest.split('#').next().unwrap_or(rest);
    Some(rest.trim())
}

/// Parses every `[[denylist]]` block out of `entropy_policy_toml`'s
/// contents (SPEC §15 grammar subset — see module doc for why this is a
/// dedicated minimal reader rather than a reuse of
/// `seed-protocol::policy`'s parser).
///
/// Ignores every other table (`[efi_rng]`, `[rdseed]`, `[[rdseed_cpu_rules]]`,
/// etc.) entirely — only `[[denylist]]` blocks and their seven fields are
/// read.
///
/// # Errors
///
/// [`DenylistParseError`] if a `[[denylist]]` block is missing a
/// required field or has a non-numeric value for a numeric field.
pub fn parse_denylist_records(entropy_policy_toml: &str) -> Result<Vec<DenylistRecord>, DenylistParseError> {
    #[derive(Default)]
    struct Building {
        vendor: Option<String>,
        family_min: Option<String>,
        family_max: Option<String>,
        model_min: Option<String>,
        model_max: Option<String>,
        stepping_min: Option<String>,
        stepping_max: Option<String>,
        reason: Option<String>,
    }

    fn parse_u32(block_index: usize, field: &'static str, raw: &str) -> Result<u32, DenylistParseError> {
        raw.parse::<u32>()
            .map_err(|_| DenylistParseError::InvalidNumber { block_index, field, value: raw.to_string() })
    }

    fn finish(
        b: Building,
        block_index: usize,
    ) -> Result<DenylistRecord, DenylistParseError> {
        macro_rules! req_str {
            ($f:ident, $name:literal) => {
                b.$f.ok_or(DenylistParseError::MissingField { block_index, field: $name })?
            };
        }
        macro_rules! req_num {
            ($f:ident, $name:literal) => {{
                let raw = b.$f.ok_or(DenylistParseError::MissingField { block_index, field: $name })?;
                parse_u32(block_index, $name, &raw)?
            }};
        }
        Ok(DenylistRecord {
            vendor: req_str!(vendor, "vendor"),
            family_min: req_num!(family_min, "family_min"),
            family_max: req_num!(family_max, "family_max"),
            model_min: req_num!(model_min, "model_min"),
            model_max: req_num!(model_max, "model_max"),
            stepping_min: req_num!(stepping_min, "stepping_min"),
            stepping_max: req_num!(stepping_max, "stepping_max"),
            reason: req_str!(reason, "reason"),
        })
    }

    let mut records = Vec::new();
    let mut current: Option<Building> = None;
    let mut in_denylist_block = false;
    let mut block_index = 0usize;

    for raw_line in entropy_policy_toml.lines() {
        let line = raw_line.trim();
        let stripped_comment = line.split('#').next().unwrap_or(line).trim();
        if stripped_comment == "[[denylist]]" {
            if let Some(b) = current.take() {
                records.push(finish(b, block_index)?);
                block_index += 1;
            }
            current = Some(Building::default());
            in_denylist_block = true;
            continue;
        }
        if stripped_comment.starts_with('[') {
            if let Some(b) = current.take() {
                records.push(finish(b, block_index)?);
                block_index += 1;
            }
            in_denylist_block = false;
            continue;
        }
        if !in_denylist_block {
            continue;
        }
        if let Some(b) = current.as_mut() {
            if let Some(v) = extract_str_field(line, "vendor") {
                b.vendor = Some(v.to_string());
            } else if let Some(v) = extract_str_field(line, "reason") {
                b.reason = Some(v.to_string());
            } else if let Some(v) = extract_num_field(line, "family_min") {
                b.family_min = Some(v.to_string());
            } else if let Some(v) = extract_num_field(line, "family_max") {
                b.family_max = Some(v.to_string());
            } else if let Some(v) = extract_num_field(line, "model_min") {
                b.model_min = Some(v.to_string());
            } else if let Some(v) = extract_num_field(line, "model_max") {
                b.model_max = Some(v.to_string());
            } else if let Some(v) = extract_num_field(line, "stepping_min") {
                b.stepping_min = Some(v.to_string());
            } else if let Some(v) = extract_num_field(line, "stepping_max") {
                b.stepping_max = Some(v.to_string());
            }
        }
    }
    if let Some(b) = current.take() {
        records.push(finish(b, block_index)?);
    }

    Ok(records)
}

/// Renders `DENYLIST.txt` (SPEC §31, §32) from the policy's
/// `policy_version` and its `[[denylist]]` records. Deterministic: a
/// pure function of `entropy_policy_toml`'s content.
///
/// # Errors
///
/// [`DenylistParseError`] — see [`parse_denylist_records`].
pub fn generate_denylist_txt(entropy_policy_toml: &str) -> Result<String, DenylistParseError> {
    let records = parse_denylist_records(entropy_policy_toml)?;
    let policy_version = entropy_policy_toml
        .lines()
        .map(str::trim)
        .find_map(|l| extract_num_field(l, "policy_version"))
        .unwrap_or("unknown");

    let mut out = String::new();
    out.push_str("# Alea known-bad-platform denylist (SPEC.md §15, §31, §32)\n");
    let _ = writeln!(out, "# entropy-policy version: {policy_version}");
    let _ = writeln!(out, "# entries: {}", records.len());
    out.push_str("#\n");
    out.push_str("# This is a release artifact, distinct from the signed build-time\n");
    out.push_str("# entropy-policy.toml it is derived from (SPEC.md §32). It restates the\n");
    out.push_str("# known-bad vendor/family/model/stepping ranges the compiled-in policy denies\n");
    out.push_str("# for RDSEED use, in a human-readable form. An empty entry list is not\n");
    out.push_str("# itself a security guarantee: it means no specific errata-affected\n");
    out.push_str("# combination has been reviewed and added yet (see entropy-policy.toml's\n");
    out.push_str("# own header comment), not that none exist.\n");

    if records.is_empty() {
        out.push_str("\n(no denylisted platforms recorded in this policy version)\n");
        return Ok(out);
    }

    out.push('\n');
    for (i, r) in records.iter().enumerate() {
        let _ = writeln!(out, "[{i}] vendor={}", r.vendor);
        let _ = writeln!(out, "    family:   {}-{}", r.family_min, r.family_max);
        let _ = writeln!(out, "    model:    {}-{}", r.model_min, r.model_max);
        let _ = writeln!(out, "    stepping: {}-{}", r.stepping_min, r.stepping_max);
        let _ = writeln!(out, "    reason:   {}", r.reason);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY_POLICY: &str = r#"
policy_version = 1

[efi_rng]
approved = false

[rdseed]
approved = true

[[rdseed_cpu_rules]]
vendor = "GenuineIntel"
family_min = 0
family_max = 65535
model_min = 0
model_max = 255
stepping_min = 0
stepping_max = 255
allow = true
"#;

    const ONE_DENYLIST_POLICY: &str = r#"
policy_version = 2

[rdseed]
approved = true

[[rdseed_cpu_rules]]
vendor = "GenuineIntel"
family_min = 0
family_max = 65535
model_min = 0
model_max = 255
stepping_min = 0
stepping_max = 255
allow = true

[[denylist]]
vendor = "GenuineIntel"
family_min = 6
family_max = 6
model_min = 85
model_max = 85
stepping_min = 0
stepping_max = 3
reason = "erratum XYZ affecting RDSEED output quality"
"#;

    #[test]
    fn no_denylist_blocks_in_current_shipped_policy_yields_empty_list() {
        // Regression-pin: `entropy-policy.toml` as shipped in v1 has
        // zero `[[denylist]]` records (scaffold only). Confirms this
        // parser agrees, not just against a synthetic fixture.
        let real = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../entropy-policy.toml"),
        );
        if let Ok(real) = real {
            let records = parse_denylist_records(&real).unwrap();
            assert!(records.is_empty(), "expected the shipped v1 policy to have no denylist records yet");
        }
        // Also exercise the same shape via an inline fixture, so this
        // test still means something in an environment where the repo
        // root file above is not reachable (e.g. a vendored copy of
        // just this crate).
        let records = parse_denylist_records(EMPTY_POLICY).unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn parses_one_denylist_record_correctly() {
        let records = parse_denylist_records(ONE_DENYLIST_POLICY).unwrap();
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(r.vendor, "GenuineIntel");
        assert_eq!((r.family_min, r.family_max), (6, 6));
        assert_eq!((r.model_min, r.model_max), (85, 85));
        assert_eq!((r.stepping_min, r.stepping_max), (0, 3));
        assert_eq!(r.reason, "erratum XYZ affecting RDSEED output quality");
    }

    #[test]
    fn rdseed_cpu_rules_blocks_are_not_mistaken_for_denylist_blocks() {
        // `[[rdseed_cpu_rules]]` shares every field name with
        // `[[denylist]]` except `reason` -- a parser that doesn't gate
        // strictly on the `[[denylist]]` header would misclassify it.
        let records = parse_denylist_records(EMPTY_POLICY).unwrap();
        assert!(records.is_empty(), "an [[rdseed_cpu_rules]] block must never be read as a denylist entry");
    }

    #[test]
    fn generated_txt_for_empty_policy_says_none_recorded() {
        let txt = generate_denylist_txt(EMPTY_POLICY).unwrap();
        assert!(txt.contains("policy version: 1"));
        assert!(txt.contains("no denylisted platforms recorded"));
    }

    #[test]
    fn generated_txt_for_nonempty_policy_lists_the_record() {
        let txt = generate_denylist_txt(ONE_DENYLIST_POLICY).unwrap();
        assert!(txt.contains("policy version: 2"));
        assert!(txt.contains("vendor=GenuineIntel"));
        assert!(txt.contains("erratum XYZ affecting RDSEED output quality"));
    }

    #[test]
    fn generation_is_deterministic() {
        let a = generate_denylist_txt(ONE_DENYLIST_POLICY).unwrap();
        let b = generate_denylist_txt(ONE_DENYLIST_POLICY).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn missing_required_field_is_reported_not_panicked() {
        let bad = "[[denylist]]\nvendor = \"GenuineIntel\"\n";
        let err = parse_denylist_records(bad).unwrap_err();
        assert!(matches!(err, DenylistParseError::MissingField { field: "family_min", .. }));
    }

    #[test]
    fn non_numeric_field_is_reported_not_panicked() {
        let bad = r#"[[denylist]]
vendor = "GenuineIntel"
family_min = not-a-number
family_max = 6
model_min = 0
model_max = 0
stepping_min = 0
stepping_max = 0
reason = "test"
"#;
        let err = parse_denylist_records(bad).unwrap_err();
        assert!(matches!(err, DenylistParseError::InvalidNumber { field: "family_min", .. }));
    }
}
