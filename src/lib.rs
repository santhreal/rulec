#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::todo,
        clippy::unimplemented,
        clippy::panic
    )
)]

//! `rulec`: a one-way compiler that lowers YARA rules onto the **vyre** GPU rule
//! engine ("forward integration": YARA is pulled *into* our stack, never the reverse).
//!
//! ```text
//! YARA source -> (this crate) -> vyre rule IR -> GPU
//!                             -> .srg text (optional export; see [`srg`])
//! ```
//!
//! The engine path is direct: [`vyre_engine::verdict`] scans + evaluates a lowered rule on
//! the real `vyre` substrate (byte-NFA + `RuleFormula`). The `.srg` emitter ([`srg`]) is a
//! *secondary* text artifact in surge's rule language, surge can carry it to vyre/GPU once
//! surgec ingests the byte-match surface (`SURFACE.md`); nothing in the engine path needs
//! it, so it is an optional output, not the product.
//!
//! Scope discipline (the screwdriver rule that the two dead ancestors `yaragpu` and
//! `rulefire` violated): accept *exactly* what lowers onto the live `vyre::rule`
//! model and reject the rest LOUDLY with an actionable `Fix:`: never a silent subset.
//!
//! Pipeline:
//! 1. [`compile`] parses YARA (yara-x AST) -> lowered IR (+ the optional `.srg` text).
//! 2. [`vyre_engine::verdict`] runs the lowered rule on the real vyre engine (the product
//!    path); [`eval::verdict`] is a CPU reference oracle mirroring vyre's `reference_eval`,
//!    used to prove the lowering against `yara_x::Scanner` (the differential gate).
//!
//! ## Safe defaults
//!
//! - **Input size**: Bounded by available RAM; large YARA sources or byte inputs should be pre-buffered.
//! - **Recursion depth**: AST traversal is non-recursive or bounded by `yara-x-parser` depth limits.
//! - **Outbound network**: None. `rulec` is an offline rule compilation crate with zero network I/O.
//! - **Process spawning**: None. `rulec` spawns no child processes.
//! - **Filesystem writes**: None. `rulec` performs in-memory transformations and does not write files directly.
//! - **Credential exposure**: None. `rulec` does not touch or expose credentials or secrets.

pub mod eval;
pub mod lower;
#[cfg(feature = "differential")]
pub mod oracle;
pub mod srg;
#[cfg(feature = "vyre-engine")]
pub mod vyre_engine;

pub use eval::{pattern_counts, verdict, EvalError};
pub use lower::{CmpOp, Cond, LowerError, LoweredPattern, LoweredRule, PatKind};

use yara_x_parser::{ast, Parser};

/// The result of compiling YARA source: the lowered rules (the engine input) plus the
/// optional emitted `.srg` text.
#[derive(Debug, Clone)]
pub struct Compiled {
    /// Lowered rules, in source order (what [`vyre_engine`] executes).
    pub rules: Vec<LoweredRule>,
    /// The emitted `.srg` source (surge's rule language) (an optional secondary export).
    pub srg: String,
}

/// A failure compiling YARA into the lowered IR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompileError {
    /// YARA source failed to parse (surfaced, never silently dropped).
    Parse(Vec<String>),
    /// A construct outside the v1 lowering surface.
    Lower(LowerError),
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompileError::Parse(errs) => {
                write!(f, "YARA parse error(s): {}", errs.join("; "))
            }
            CompileError::Lower(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CompileError {}

impl From<LowerError> for CompileError {
    fn from(e: LowerError) -> Self {
        CompileError::Lower(e)
    }
}

/// Parse YARA `source` into its AST. Thin seam over the upstream entry.
#[must_use]
pub fn parse(source: &[u8]) -> ast::AST<'_> {
    ast::AST::from(Parser::new(source))
}

/// Compile YARA source bytes into lowered rules + `.srg` text.
///
/// # Errors
/// Returns [`CompileError::Lower`] for any construct outside the v1 surface
/// (with an actionable `Fix:`).
pub fn compile(yara_src: &[u8]) -> Result<Compiled, CompileError> {
    let ast = parse(yara_src);
    // Surface parse errors loudly (never lower a partially-parsed rule set silently).
    let errors = ast.errors();
    if !errors.is_empty() {
        return Err(CompileError::Parse(
            errors.iter().map(|e| format!("{e:?}")).collect(),
        ));
    }
    let rules = lower::lower_ast(&ast)?;
    let srg = srg::emit_rules(&rules);
    Ok(Compiled { rules, srg })
}

/// The result of a best-effort compile: every rule that lowered successfully plus a
/// per-rule list of rejections for constructs outside the v1 surface.
#[derive(Debug, Clone)]
pub struct PartialCompiled {
    /// Lowered rules, in source order.
    pub rules: Vec<LoweredRule>,
    /// The emitted `.srg` source for the successfully lowered rules.
    pub srg: String,
    /// Per-rule lower errors for rules that could not be lowered.
    pub lower_errors: Vec<(String, LowerError)>,
}

/// Compile YARA source bytes into lowered rules + `.srg` text, skipping rules that
/// cannot be lowered instead of failing the whole ruleset.
///
/// # Errors
/// Returns [`CompileError::Parse`] if the YARA source itself does not parse.
/// Per-rule lower rejections are returned in [`PartialCompiled::lower_errors`].
pub fn compile_partial(yara_src: &[u8]) -> Result<PartialCompiled, CompileError> {
    let ast = parse(yara_src);
    let errors = ast.errors();
    if !errors.is_empty() {
        return Err(CompileError::Parse(
            errors.iter().map(|e| format!("{e:?}")).collect(),
        ));
    }
    let (rules, lower_errors) = lower::lower_ast_partial(&ast);
    let srg = srg::emit_rules(&rules);
    Ok(PartialCompiled { rules, srg, lower_errors })
}
