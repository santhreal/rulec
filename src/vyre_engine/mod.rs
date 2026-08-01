//! The **product execution path** (feature `vyre-engine`): a lowered YARA rule is scanned
//! and evaluated through the real `vyre` substrate.

#[cfg(feature = "gpu")]
pub mod compiled;

#[cfg(feature = "gpu")]
pub use compiled::{CompiledRuleSet, ResidentSession};

use vyre_libs::rule::{evaluate_formula, RuleCondition, RuleEvaluationContext, RuleFormula};
use vyre_libs::scan::{build_rule_pipeline_from_regex, RulePipeline};

use crate::lower::{CmpOp, Cond, LoweredRule};

/// Failure executing a lowered rule through vyre.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VyreEngineError {
    /// The pattern set could not be compiled onto vyre's byte-NFA.
    Compile(String),
    /// The NFA parity scan failed.
    Scan(String),
}

impl std::fmt::Display for VyreEngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VyreEngineError::Compile(m) => write!(f, "vyre regex-set compile failed: {m}"),
            VyreEngineError::Scan(m) => write!(f, "vyre scan failed: {m}"),
        }
    }
}

impl std::error::Error for VyreEngineError {}

/// Per-pattern match counts + file size context.
struct ScanContext {
    counts: Vec<u32>,
    file_size: u64,
}

impl RuleEvaluationContext for ScanContext {
    fn pattern_count(&self, pattern_id: u32) -> u32 {
        self.counts.get(pattern_id as usize).copied().unwrap_or(0)
    }
    fn file_size(&self) -> u64 {
        self.file_size
    }
}

/// Scan `data` and evaluate `rule` on the CPU parity walk of the real vyre byte-NFA.
///
/// # Errors
/// Returns [`VyreEngineError::Compile`] when the pattern set won't lower onto the byte-NFA,
/// or [`VyreEngineError::Scan`] on a scan failure.
pub fn verdict(rule: &LoweredRule, data: &[u8]) -> Result<bool, VyreEngineError> {
    let counts = pattern_counts(rule, data)?;
    Ok(eval_with_counts(rule, counts, data.len()))
}

/// Scan `data` on the CPU parity walk and return per-pattern match counts.
///
/// # Errors
/// See [`verdict`].
pub fn pattern_counts(rule: &LoweredRule, data: &[u8]) -> Result<Vec<u32>, VyreEngineError> {
    let Some(pipeline) = build_pipeline(rule, data)? else {
        return Ok(vec![0u32; rule.patterns.len()]);
    };
    let matches = pipeline
        .try_reference_scan(data)
        .map_err(|e| VyreEngineError::Scan(e.to_string()))?;
    Ok(tally(matches.iter().map(|m| m.pattern_id), rule.patterns.len()))
}

pub use crate::eval::DEFAULT_MAX_MATCHES;

/// Scan `data` on `backend` and return per-pattern counts.
///
/// # Errors
/// See [`pattern_counts`].
#[cfg(feature = "gpu")]
pub fn pattern_counts_on<B: vyre::VyreBackend + ?Sized>(
    rule: &LoweredRule,
    data: &[u8],
    backend: &B,
    max_matches: u32,
) -> Result<Vec<u32>, VyreEngineError> {
    let Some(pipeline) = build_pipeline(rule, data)? else {
        return Ok(vec![0u32; rule.patterns.len()]);
    };
    let matches = pipeline
        .scan(backend, data, max_matches)
        .map_err(|e| VyreEngineError::Scan(e.to_string()))?;
    if matches.len() as u64 >= u64::from(max_matches) {
        return Err(VyreEngineError::Scan(format!(
            "match buffer saturated at {max_matches}; per-pattern counts may be truncated."
        )));
    }
    Ok(tally(matches.iter().map(|m| m.pattern_id), rule.patterns.len()))
}

/// Evaluate `rule` on `backend`.
///
/// # Errors
/// See [`pattern_counts_on`].
#[cfg(feature = "gpu")]
pub fn verdict_on<B: vyre::VyreBackend + ?Sized>(
    rule: &LoweredRule,
    data: &[u8],
    backend: &B,
    max_matches: u32,
) -> Result<bool, VyreEngineError> {
    let counts = pattern_counts_on(rule, data, backend, max_matches)?;
    Ok(eval_with_counts(rule, counts, data.len()))
}

fn build_pipeline(rule: &LoweredRule, data: &[u8]) -> Result<Option<RulePipeline>, VyreEngineError> {
    if rule.patterns.is_empty() {
        return Ok(None);
    }
    let regexes: Vec<String> = rule.patterns.iter().map(|p| p.to_byte_regex()).collect();
    let refs: Vec<&str> = regexes.iter().map(String::as_str).collect();
    let input_len = u32::try_from(data.len()).map_err(|_| {
        VyreEngineError::Scan("haystack exceeds u32 capacity; split the input".to_string())
    })?;
    build_rule_pipeline_from_regex(&refs, "input", "hits", input_len)
        .map(Some)
        .map_err(|e| VyreEngineError::Compile(e.to_string()))
}

pub(crate) fn tally(pattern_ids: impl Iterator<Item = u32>, n_patterns: usize) -> Vec<u32> {
    let mut counts = vec![0u32; n_patterns];
    for id in pattern_ids {
        if let Some(slot) = counts.get_mut(id as usize) {
            *slot = slot.saturating_add(1);
        }
    }
    counts
}

fn eval_with_counts(rule: &LoweredRule, counts: Vec<u32>, data_len: usize) -> bool {
    let ctx = ScanContext {
        counts,
        file_size: data_len as u64,
    };
    evaluate_formula(&to_formula(&rule.condition), &ctx)
}

pub(crate) fn to_formula(cond: &Cond) -> RuleFormula {
    match cond {
        Cond::Bool(true) => RuleFormula::condition(RuleCondition::LiteralTrue),
        Cond::Bool(false) => RuleFormula::condition(RuleCondition::LiteralFalse),
        Cond::Present(id) => {
            RuleFormula::condition(RuleCondition::PatternExists { pattern_id: *id })
        }
        Cond::Count { id, op, n } => count_formula(*id, *op, *n),
        Cond::FileSize { op, n } => file_size_formula(*op, *n),
        Cond::And(v) => fold(v, true),
        Cond::Or(v) => fold(v, false),
        Cond::Not(inner) => RuleFormula::not(to_formula(inner)),
    }
}

fn lit(b: bool) -> RuleFormula {
    RuleFormula::condition(if b {
        RuleCondition::LiteralTrue
    } else {
        RuleCondition::LiteralFalse
    })
}

fn fold(items: &[Cond], and: bool) -> RuleFormula {
    let mut iter = items.iter().rev().map(to_formula);
    let Some(mut acc) = iter.next() else {
        return lit(and);
    };
    for f in iter {
        acc = if and {
            RuleFormula::and(f, acc)
        } else {
            RuleFormula::or(f, acc)
        };
    }
    acc
}

fn count_formula(id: u32, op: CmpOp, n: i64) -> RuleFormula {
    if n < 0 {
        return lit(op.holds_for_negative_rhs());
    }
    let Ok(t) = u32::try_from(n) else {
        return lit(matches!(op, CmpOp::Lt | CmpOp::Le | CmpOp::Ne));
    };
    let gt = || RuleFormula::condition(RuleCondition::PatternCountGt { pattern_id: id, threshold: t });
    let gte = || RuleFormula::condition(RuleCondition::PatternCountGte { pattern_id: id, threshold: t });
    match op {
        CmpOp::Gt => gt(),
        CmpOp::Ge => gte(),
        CmpOp::Lt => RuleFormula::not(gte()),
        CmpOp::Le => RuleFormula::not(gt()),
        CmpOp::Eq => RuleFormula::and(gte(), RuleFormula::not(gt())),
        CmpOp::Ne => RuleFormula::not(RuleFormula::and(gte(), RuleFormula::not(gt()))),
    }
}

fn file_size_formula(op: CmpOp, n: i64) -> RuleFormula {
    if n < 0 {
        return lit(op.holds_for_negative_rhs());
    }
    let t = n as u64;
    RuleFormula::condition(match op {
        CmpOp::Lt => RuleCondition::FileSizeLt(t),
        CmpOp::Le => RuleCondition::FileSizeLte(t),
        CmpOp::Gt => RuleCondition::FileSizeGt(t),
        CmpOp::Ge => RuleCondition::FileSizeGte(t),
        CmpOp::Eq => RuleCondition::FileSizeEq(t),
        CmpOp::Ne => RuleCondition::FileSizeNe(t),
    })
}
