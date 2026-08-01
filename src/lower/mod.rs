//! YARA AST → lowered IR.
//!
//! Screwdriver discipline: accept *exactly* what lowers onto the live vyre rule
//! model (pattern presence/count + filesize over and/or/not), and reject everything
//! else LOUDLY with an actionable `Fix:` (never a silent subset, that is how the two
//! dead ancestors rotted). The rejected set IS the P3 roadmap.
//!
//! Split by responsibility (Law 5): this module owns the IR types + per-rule orchestration;
//! [`patterns`] lowers the `strings:` section (text/hex/regex/wide → [`PatKind`]) and
//! [`condition`] lowers the `condition:` expression tree (→ [`Cond`]).

mod condition;
mod patterns;
mod transforms;

use std::collections::HashMap;
use std::fmt;

use yara_x_parser::ast::RuleFlags;

/// A comparison operator in a count/filesize condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Ne,
}

impl CmpOp {
    /// Operator with its operands swapped (`a < b` ⇔ `b > a`).
    #[must_use]
    pub fn flipped(self) -> Self {
        match self {
            CmpOp::Lt => CmpOp::Gt,
            CmpOp::Le => CmpOp::Ge,
            CmpOp::Gt => CmpOp::Lt,
            CmpOp::Ge => CmpOp::Le,
            CmpOp::Eq => CmpOp::Eq,
            CmpOp::Ne => CmpOp::Ne,
        }
    }

    /// Result of `lhs <op> n` when `n < 0` and `lhs` is an unsigned quantity (a pattern
    /// count or `filesize`, always `≥ 0`): the comparison is constant. `>`/`>=`/`!=` hold;
    /// `<`/`<=`/`==` do not. The single source of truth for the negative-threshold fold,
    /// shared by the CPU oracle (`eval`) and the vyre formula builder (`vyre_engine`).
    #[must_use]
    pub fn holds_for_negative_rhs(self) -> bool {
        matches!(self, CmpOp::Gt | CmpOp::Ge | CmpOp::Ne)
    }

    /// `.srg` / YARA surface spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            CmpOp::Lt => "<",
            CmpOp::Le => "<=",
            CmpOp::Gt => ">",
            CmpOp::Ge => ">=",
            CmpOp::Eq => "==",
            CmpOp::Ne => "!=",
        }
    }
}

/// The concrete matcher behind a lowered pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatKind {
    /// Literal byte string.
    Text(Vec<u8>),
    /// Regular-expression source (without the surrounding `/`).
    Regex(String),
    /// Plain hex pattern flattened to literal bytes (no wildcards/jumps in v1).
    Hex(Vec<u8>),
}

/// One lowered string/pattern from a rule's `strings:` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoweredPattern {
    /// Index within the rule; the `pattern_id` vyre's scan/rule buffers key on.
    pub id: u32,
    /// Identifier without the leading `$` (e.g. `a` for `$a`).
    pub name: String,
    /// The matcher.
    pub kind: PatKind,
    /// ASCII case-insensitive match (`nocase`).
    pub nocase: bool,
}

/// A lowered condition, the common denominator that emits both `.srg` text (`srg::emit`),
/// the CPU reference verdict (`eval`), and the real `vyre::rule::RuleFormula`
/// (`vyre_engine`). Each consumer is an exhaustive match, so a new variant forces every
/// path to handle it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cond {
    /// Constant.
    Bool(bool),
    /// `$a`: pattern matched at least once.
    Present(u32),
    /// `#a <op> n`.
    Count { id: u32, op: CmpOp, n: i64 },
    /// `filesize <op> n`.
    FileSize { op: CmpOp, n: i64 },
    /// Conjunction.
    And(Vec<Cond>),
    /// Disjunction.
    Or(Vec<Cond>),
    /// Negation.
    Not(Box<Cond>),
}

/// A fully lowered rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoweredRule {
    /// Rule identifier.
    pub name: String,
    /// Patterns in source order; `id` == index.
    pub patterns: Vec<LoweredPattern>,
    /// The lowered `condition:`.
    pub condition: Cond,
}

/// A construct rulec refuses to lower, with the fix the operator needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LowerError {
    /// What was rejected (e.g. `"pattern modifier `xor`"`).
    pub what: String,
    /// Why it cannot lower truthfully.
    pub why: String,
    /// Actionable remediation / roadmap pointer.
    pub fix: String,
}

impl fmt::Display for LowerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rulec cannot lower {}: {}. Fix: {}",
            self.what, self.why, self.fix
        )
    }
}

impl std::error::Error for LowerError {}

/// Build a [`LowerError`]. Shared by both lowering halves.
pub(crate) fn reject(
    what: impl Into<String>,
    why: impl Into<String>,
    fix: impl Into<String>,
) -> LowerError {
    LowerError {
        what: what.into(),
        why: why.into(),
        fix: fix.into(),
    }
}

/// Strip a leading YARA pattern sigil (`$`, `#`, `@`, `!`) so declaration and use
/// resolve to the same bare key (yara-x keeps the sigil on identifiers).
pub(crate) fn strip_sigil(s: &str) -> &str {
    s.trim_start_matches(['$', '#', '@', '!'])
}

/// Lower every rule in `ast`. Returns the first rejection encountered.
///
/// # Errors
/// Returns [`LowerError`] for any construct outside the v1 surface.
pub fn lower_ast(ast: &yara_x_parser::ast::AST<'_>) -> Result<Vec<LoweredRule>, LowerError> {
    ast.rules().map(lower_rule).collect()
}

/// Lower every rule in `ast`, reporting per-rule rejections instead of stopping at the first.
///
/// Returns a tuple of successfully lowered rules and a list of `(rule_name, LowerError)`
/// for rules that could not be lowered. The strict all-or-nothing [`lower_ast`] is kept for
/// callers that want a single rejection.
#[must_use]
pub fn lower_ast_partial(ast: &yara_x_parser::ast::AST<'_>) -> (Vec<LoweredRule>, Vec<(String, LowerError)>) {
    let mut rules = Vec::new();
    let mut errors = Vec::new();
    for rule in ast.rules() {
        let name = rule.identifier.name.to_string();
        match lower_rule(rule) {
            Ok(r) => rules.push(r),
            Err(e) => errors.push((name, e)),
        }
    }
    (rules, errors)
}

/// Lower one rule.
///
/// # Errors
/// Returns [`LowerError`] for unsupported patterns, modifiers, or condition nodes.
pub fn lower_rule(rule: &yara_x_parser::ast::Rule<'_>) -> Result<LoweredRule, LowerError> {
    // A private rule never appears in YARA's scan output: its sole purpose is to be
    // referenced from another rule's condition. v1 does not lower rule-to-rule
    // references, so a private rule has no faithful *standalone* lowering, emitting it
    // as a normal `.srg` rule would self-report when YARA reports nothing (a silent
    // semantic divergence, proven against yara-x on the hatman/Glasses corpus rules).
    if rule.flags.contains(RuleFlags::Private) {
        return Err(reject(
            "private rule",
            "a private rule is never reported on its own; it exists only to be \
             referenced by another rule, and v1 does not lower rule-to-rule references",
            "P3 roadmap: rule references, a private rule lowers as a named sub-formula \
             consumed by referencing rules, never as a self-reporting rule",
        ));
    }

    let mut patterns = Vec::new();
    let mut name_to_id: HashMap<String, u32> = HashMap::new();

    if let Some(pats) = &rule.patterns {
        for (idx, pat) in pats.iter().enumerate() {
            let id = u32::try_from(idx).map_err(|_| {
                reject(
                    "rule",
                    "more than u32::MAX patterns",
                    "split the rule; vyre pattern ids are u32",
                )
            })?;
            let lowered = patterns::lower_pattern(pat, id)?;
            name_to_id.insert(lowered.name.clone(), id);
            patterns.push(lowered);
        }
    }

    let condition = condition::lower_expr(&rule.condition, &name_to_id, &patterns)?;
    Ok(LoweredRule {
        name: rule.identifier.name.to_string(),
        patterns,
        condition,
    })
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lower_ast_partial_lowers_supported_rules_and_reports_rejects() {
        let src = r#"
rule supported { strings: $a = "cmd.exe" condition: $a }
private rule unsupported { strings: $b = "test" condition: $b }
"#;
        let ast = crate::parse(src.as_bytes());
        let (rules, errors) = lower_ast_partial(&ast);
        assert_eq!(rules.len(), 1, "expected exactly one lowered rule");
        assert_eq!(rules[0].name, "supported");
        assert_eq!(errors.len(), 1, "expected exactly one rejected rule");
        assert_eq!(errors[0].0, "unsupported");
        assert!(errors[0].1.what.contains("private rule"), "unexpected rejection: {:?}", errors[0].1);
    }

    #[test]
    fn lower_ast_partial_empty_source_produces_empty_results() {
        let src = "";
        let ast = crate::parse(src.as_bytes());
        let (rules, errors) = lower_ast_partial(&ast);
        assert!(rules.is_empty());
        assert!(errors.is_empty());
    }
}
