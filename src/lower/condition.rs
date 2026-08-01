//! Lower the `condition:` expression tree into [`Cond`]: presence, `#a <op> n`,
//! `filesize <op> n`, `and`/`or`/`not`, and `N/any/all/none of …` quantifier expansion.
//! Everything outside the v1 surface (anchors, modules, arithmetic, `for`) rejects LOUDLY.

use std::collections::HashMap;

use yara_x_parser::ast::{Expr, OfItems, Pattern as _Pattern, PatternSet, Quantifier};

use super::{reject, strip_sigil, CmpOp, Cond, LowerError, LoweredPattern};

// Silence the unused-import lint while keeping the ast path explicit for readers.
#[allow(unused_imports)]
use _Pattern as _;

pub(super) fn lower_expr(
    expr: &Expr<'_>,
    ids: &HashMap<String, u32>,
    patterns: &[LoweredPattern],
) -> Result<Cond, LowerError> {
    match expr {
        Expr::True { .. } => Ok(Cond::Bool(true)),
        Expr::False { .. } => Ok(Cond::Bool(false)),

        Expr::PatternMatch(pm) => {
            if pm.anchor.is_some() {
                return Err(reject(
                    "pattern anchor (`$a at <off>` / `$a in (..)`)",
                    "offset anchoring needs a per-match offset op",
                    "P3 roadmap: vyre uint-at-offset / match-offset extension buffer",
                ));
            }
            Ok(Cond::Present(resolve_id(pm.identifier.name, ids)?))
        }

        Expr::And(nary) => Ok(Cond::And(
            nary.operands()
                .map(|e| lower_expr(e, ids, patterns))
                .collect::<Result<Vec<_>, _>>()?,
        )),
        Expr::Or(nary) => Ok(Cond::Or(
            nary.operands()
                .map(|e| lower_expr(e, ids, patterns))
                .collect::<Result<Vec<_>, _>>()?,
        )),
        Expr::Not(u) => Ok(Cond::Not(Box::new(lower_expr(&u.operand, ids, patterns)?))),

        Expr::Gt(b) => lower_cmp(CmpOp::Gt, &b.lhs, &b.rhs, ids),
        Expr::Ge(b) => lower_cmp(CmpOp::Ge, &b.lhs, &b.rhs, ids),
        Expr::Lt(b) => lower_cmp(CmpOp::Lt, &b.lhs, &b.rhs, ids),
        Expr::Le(b) => lower_cmp(CmpOp::Le, &b.lhs, &b.rhs, ids),
        Expr::Eq(b) => lower_cmp(CmpOp::Eq, &b.lhs, &b.rhs, ids),
        Expr::Ne(b) => lower_cmp(CmpOp::Ne, &b.lhs, &b.rhs, ids),

        Expr::Of(of) => lower_of(of, ids, patterns),

        other => Err(reject(
            format!("condition node `{}`", expr_kind(other)),
            "no truthful lowering onto the v1 vyre rule model",
            "supported v1: $a, #a <op> n, filesize <op> n, and/or/not, N/any/all of them. \
             Modules/for/anchors/arith are P3.",
        )),
    }
}

/// Lower a comparison, recognising `#a <op> n` and `filesize <op> n` (either operand order).
fn lower_cmp(
    op: CmpOp,
    lhs: &Expr<'_>,
    rhs: &Expr<'_>,
    ids: &HashMap<String, u32>,
) -> Result<Cond, LowerError> {
    // Try lhs <op> int, then (flipped) int <op> rhs.
    if let Some(n) = as_int(rhs) {
        if let Some(cond) = countable(lhs, op, n, ids)? {
            return Ok(cond);
        }
    }
    if let Some(n) = as_int(lhs) {
        if let Some(cond) = countable(rhs, op.flipped(), n, ids)? {
            return Ok(cond);
        }
    }
    Err(reject(
        "comparison",
        "only `#a <op> n` and `filesize <op> n` (n an integer literal) lower in v1",
        "rewrite arithmetic/module comparisons; they are P3",
    ))
}

/// If `e` is `#a` (no range) or `filesize`, build the count/filesize condition.
fn countable(
    e: &Expr<'_>,
    op: CmpOp,
    n: i64,
    ids: &HashMap<String, u32>,
) -> Result<Option<Cond>, LowerError> {
    match e {
        Expr::Filesize { .. } => Ok(Some(Cond::FileSize { op, n })),
        Expr::PatternCount(iwr) => {
            if iwr.range.is_some() {
                return Err(reject(
                    "ranged pattern count (`#a in (..)`)",
                    "in-range counting needs a per-match offset op",
                    "P3 roadmap: match-offset extension buffer",
                ));
            }
            Ok(Some(Cond::Count {
                id: resolve_id(iwr.identifier.name, ids)?,
                op,
                n,
            }))
        }
        _ => Ok(None),
    }
}

/// Lower `<quantifier> of <items>` (no anchor).
fn lower_of(
    of: &yara_x_parser::ast::Of<'_>,
    ids: &HashMap<String, u32>,
    patterns: &[LoweredPattern],
) -> Result<Cond, LowerError> {
    if of.anchor.is_some() {
        return Err(reject(
            "anchored `of` (`.. of them at <off>`)",
            "offset anchoring needs a per-match offset op",
            "P3 roadmap: match-offset extension buffer",
        ));
    }

    let members: Vec<Cond> = match &of.items {
        OfItems::PatternSet(PatternSet::Them { .. }) => {
            patterns.iter().map(|p| Cond::Present(p.id)).collect()
        }
        OfItems::PatternSet(PatternSet::Set(items)) => {
            let mut out = Vec::new();
            for it in items {
                if it.wildcard {
                    let prefix = strip_sigil(it.identifier);
                    let mut any = false;
                    for p in patterns {
                        if p.name.starts_with(prefix) {
                            out.push(Cond::Present(p.id));
                            any = true;
                        }
                    }
                    if !any {
                        return Err(reject(
                            format!("pattern set wildcard `${prefix}*`"),
                            "no pattern matched the prefix",
                            "check the identifier prefix against the rule's strings",
                        ));
                    }
                } else {
                    out.push(Cond::Present(resolve_id(it.identifier, ids)?));
                }
            }
            out
        }
        OfItems::BoolExprTuple(exprs) => exprs
            .iter()
            .map(|e| lower_expr(e, ids, patterns))
            .collect::<Result<Vec<_>, _>>()?,
    };

    match &of.quantifier {
        Quantifier::All { .. } => Ok(Cond::And(members)),
        Quantifier::Any { .. } => Ok(Cond::Or(members)),
        Quantifier::None { .. } => Ok(Cond::Not(Box::new(Cond::Or(members)))),
        Quantifier::Expr(e) => {
            let k = as_int(e).ok_or_else(|| {
                reject(
                    "non-literal `of` quantifier",
                    "only an integer-literal count lowers in v1",
                    "use `N of ...` with a literal N; expressions are P3",
                )
            })?;
            at_least_n(&members, k)
        }
        Quantifier::Percentage(_) => Err(reject(
            "percentage `of` quantifier (`N% of them`)",
            "percentage thresholds need a count-of-true primitive",
            "P3 roadmap: vyre dnnf threshold; or rewrite as `N of`",
        )),
    }
}

/// `at least k of <members>`: combinatorial expansion, bounded to keep blow-up sane.
fn at_least_n(members: &[Cond], k: i64) -> Result<Cond, LowerError> {
    let m = members.len();
    let k = usize::try_from(k).unwrap_or(0);
    if k == 0 {
        return Ok(Cond::Bool(true));
    }
    if k > m {
        return Ok(Cond::Bool(false));
    }
    if k == m {
        return Ok(Cond::And(members.to_vec()));
    }
    if k == 1 {
        return Ok(Cond::Or(members.to_vec()));
    }
    // Bound C(m,k) so we don't explode the formula.
    if m > 16 {
        return Err(reject(
            format!("`{k} of` over {m} patterns"),
            "combinatorial expansion is too large",
            "P3 roadmap: vyre dnnf threshold primitive for large `N of`",
        ));
    }
    let mut clauses = Vec::new();
    let mut combo = vec![0usize; k];
    n_choose_k(m, k, 0, 0, &mut combo, &mut |idxs| {
        clauses.push(Cond::And(idxs.iter().map(|&i| members[i].clone()).collect()));
    });
    Ok(Cond::Or(clauses))
}

fn n_choose_k(
    m: usize,
    k: usize,
    start: usize,
    depth: usize,
    combo: &mut Vec<usize>,
    emit: &mut impl FnMut(&[usize]),
) {
    if depth == k {
        emit(combo);
        return;
    }
    for i in start..=m - (k - depth) {
        combo[depth] = i;
        n_choose_k(m, k, i + 1, depth + 1, combo, emit);
    }
}

fn resolve_id(name: &str, ids: &HashMap<String, u32>) -> Result<u32, LowerError> {
    let bare = strip_sigil(name);
    ids.get(bare).copied().ok_or_else(|| {
        reject(
            format!("reference to undefined pattern `${bare}`"),
            "the condition names a string not declared in `strings:`",
            "anonymous `$`/`$*` and out-of-scope names are not lowered in v1",
        )
    })
}

fn as_int(e: &Expr<'_>) -> Option<i64> {
    match e {
        Expr::LiteralInteger(li) => Some(li.value),
        _ => None,
    }
}

fn expr_kind(e: &Expr<'_>) -> &'static str {
    match e {
        Expr::True { .. } => "true",
        Expr::False { .. } => "false",
        Expr::Filesize { .. } => "filesize",
        Expr::Entrypoint { .. } => "entrypoint",
        Expr::LiteralString(_) => "literal-string",
        Expr::LiteralInteger(_) => "literal-integer",
        Expr::LiteralFloat(_) => "literal-float",
        Expr::Regexp(_) => "regexp",
        Expr::Ident(_) => "identifier",
        Expr::PatternMatch(_) => "pattern-match",
        Expr::PatternCount(_) => "pattern-count",
        Expr::PatternOffset(_) => "pattern-offset(@)",
        Expr::PatternLength(_) => "pattern-length(!)",
        Expr::FuncCall(_) => "func-call",
        Expr::FieldAccess(_) => "field-access(module)",
        Expr::Of(_) => "of",
        Expr::ForOf(_) => "for-of",
        Expr::ForIn(_) => "for-in",
        _ => "expression",
    }
}
