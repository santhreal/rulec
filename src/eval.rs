//! Self-contained CPU reference scanner + condition evaluator, the **"ours" verdict**
//! for the differential gate against `yara_x::Scanner`.
//!
//! The condition evaluator deliberately mirrors vyre's `rule::reference_eval`
//! semantics (`pattern_count` + `file_size` over And/Or/Not), so when P1.5 swaps this
//! for the real `vyre_libs::rule`/`scan` path the verdicts are expected to be identical.
//! No silent fallback: a regex string that fails to compile surfaces as an error.

use crate::lower::{Cond, CmpOp, LoweredRule, PatKind};

/// Maximum number of regex/literal matches the CPU reference and vyre engine
/// both report. A larger true count is capped so the two count models agree.
pub const DEFAULT_MAX_MATCHES: u32 = 10_000;

/// An error computing the reference verdict (e.g. a regex string the `regex` crate
/// cannot compile). Surfaced, never swallowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvalError {
    /// Pattern identifier the failure relates to.
    pub pattern: String,
    /// What went wrong.
    pub detail: String,
}

impl std::fmt::Display for EvalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "reference eval failed for pattern `${}`: {}",
            self.pattern, self.detail
        )
    }
}

impl std::error::Error for EvalError {}

/// Per-pattern match counts for `data`, indexed by `pattern_id` (== source order).
///
/// # Errors
/// Returns [`EvalError`] if a regex pattern fails to compile.
pub fn pattern_counts(rule: &LoweredRule, data: &[u8]) -> Result<Vec<u32>, EvalError> {
    let mut counts = vec![0u32; rule.patterns.len()];
    for p in &rule.patterns {
        let c = match &p.kind {
            PatKind::Text(bytes) => count_overlapping(data, bytes, p.nocase),
            PatKind::Hex(bytes) => count_overlapping(data, bytes, false),
            PatKind::Regex(src) => count_regex(src, p.nocase, data).map_err(|e| EvalError {
                pattern: p.name.clone(),
                detail: e,
            })?,
        };
        counts[p.id as usize] = c;
    }
    Ok(counts)
}

/// The rule's boolean verdict on `data`.
///
/// # Errors
/// Returns [`EvalError`] if pattern scanning fails.
pub fn verdict(rule: &LoweredRule, data: &[u8]) -> Result<bool, EvalError> {
    let counts = pattern_counts(rule, data)?;
    let filesize = data.len() as u64;
    Ok(eval(&rule.condition, &counts, filesize))
}

/// Evaluate a lowered condition. Mirror of `vyre_libs::rule::reference_eval`.
#[must_use]
pub fn eval(cond: &Cond, counts: &[u32], filesize: u64) -> bool {
    match cond {
        Cond::Bool(b) => *b,
        Cond::Present(id) => count_at(counts, *id) > 0,
        Cond::Count { id, op, n } => cmp_u64(u64::from(count_at(counts, *id)), *op, *n),
        Cond::FileSize { op, n } => cmp_u64(filesize, *op, *n),
        Cond::And(v) => v.iter().all(|c| eval(c, counts, filesize)),
        Cond::Or(v) => v.iter().any(|c| eval(c, counts, filesize)),
        Cond::Not(inner) => !eval(inner, counts, filesize),
    }
}

fn count_at(counts: &[u32], id: u32) -> u32 {
    counts.get(id as usize).copied().unwrap_or(0)
}

/// Compare `lhs` to a (possibly negative) integer literal `rhs`. Negative thresholds
/// behave per integer semantics: e.g. `count >= -1` is always true.
fn cmp_u64(lhs: u64, op: CmpOp, rhs: i64) -> bool {
    // A negative threshold is handled by constant-folding instead of casting:
    // `u64::try_from` only fails on negative values, which is exactly the case
    // where the comparison against a negative bound is constant.
    let Ok(rhs) = u64::try_from(rhs) else {
        return op.holds_for_negative_rhs();
    };
    match op {
        CmpOp::Lt => lhs < rhs,
        CmpOp::Le => lhs <= rhs,
        CmpOp::Gt => lhs > rhs,
        CmpOp::Ge => lhs >= rhs,
        CmpOp::Eq => lhs == rhs,
        CmpOp::Ne => lhs != rhs,
    }
}

/// Count overlapping occurrences of `needle` in `hay` (YARA counts overlapping matches).
fn count_overlapping(hay: &[u8], needle: &[u8], nocase: bool) -> u32 {
    if needle.is_empty() || needle.len() > hay.len() {
        return 0;
    }
    let mut count = 0u32;
    for window in hay.windows(needle.len()) {
        if bytes_match(window, needle, nocase) {
            count = count.saturating_add(1);
        }
    }
    count
}

fn bytes_match(a: &[u8], b: &[u8], nocase: bool) -> bool {
    if nocase {
        a.iter()
            .zip(b)
            .all(|(x, y)| x.eq_ignore_ascii_case(y))
    } else {
        a == b
    }
}

/// Count non-overlapping regex matches (YARA semantics for `#a` on a regex string).
fn count_regex(src: &str, nocase: bool, data: &[u8]) -> Result<u32, String> {
    let pattern = if nocase {
        format!("(?i){src}")
    } else {
        src.to_string()
    };
    let re = regex::bytes::Regex::new(&pattern).map_err(|e| e.to_string())?;
    let count = re.find_iter(data).count().min(DEFAULT_MAX_MATCHES as usize);
    Ok(u32::try_from(count).unwrap_or(DEFAULT_MAX_MATCHES))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regex_match_count_capped_at_default_max() {
        // A pattern that matches every byte in a buffer would otherwise exceed
        // u32 ranges; both CPU and vyre must agree on the cap.
        let data = vec![b'a'; 100_000];
        let count = count_regex("a", false, &data).unwrap();
        assert_eq!(count, DEFAULT_MAX_MATCHES);
    }

    #[test]
    fn regex_match_count_under_cap_is_exact() {
        let data = b"ababa";
        let count = count_regex("a", false, data).unwrap();
        assert_eq!(count, 3);
    }
}

