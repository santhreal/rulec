//! Combined resident scanner (feature `gpu`).

use vyre_libs::rule::{evaluate_formula, RuleCondition, RuleEvaluationContext, RuleFormula};
use vyre_libs::scan::{build_rule_pipeline_from_regex, compile_regex_set, RegexCompileError, RegexCompileError::TooManyStates, ResidentRulePipeline, RulePipeline};

use crate::lower::LoweredRule;
use crate::vyre_engine::{tally, to_formula, VyreEngineError};

/// One rule's slot within a shard's pattern space.
struct RuleSlot {
    /// The rule's lowered condition, over rule-LOCAL pattern ids (`0..npat`).
    formula: RuleFormula,
    /// First pattern id this rule's patterns occupy **within its shard**.
    base: usize,
    /// Number of patterns this rule contributed.
    npat: usize,
    /// Index of this rule in the original `rules` slice (what [`CompiledRuleSet::scan_fired`]
    /// returns and [`CompiledRuleSet::rule_name`] resolves).
    orig_index: usize,
}

/// One shard: a subset of rules whose combined pattern set fits in a single byte-NFA
/// (under vyre's per-subgroup state cap), plus that shard's compiled pipeline.
struct Shard {
    /// `None` when the shard holds only pattern-less rules (nothing to scan).
    pipeline: Option<RulePipeline>,
    /// Rules in this shard; `base` is shard-local.
    slots: Vec<RuleSlot>,
    /// Number of patterns in this shard's combined NFA.
    n_patterns: usize,
}

/// Evaluation context that maps a rule's LOCAL pattern id onto its slice (`base..base+npat`)
/// of its shard's per-pattern counts. A pattern id outside the rule's own range reads 0 
/// a rule can never see another rule's matches.
struct SlotContext<'a> {
    counts: &'a [u32],
    base: usize,
    npat: usize,
    file_size: u64,
}

impl RuleEvaluationContext for SlotContext<'_> {
    fn pattern_count(&self, pattern_id: u32) -> u32 {
        let local = pattern_id as usize;
        if local >= self.npat {
            return 0;
        }
        self.counts.get(self.base + local).copied().unwrap_or(0)
    }
    fn file_size(&self) -> u64 {
        self.file_size
    }
}

/// A whole rule set compiled into one or more byte-NFA **shards**, ready to prepare resident.
pub struct CompiledRuleSet {
    shards: Vec<Shard>,
    /// Rule names in original order; `rule_name(i)` / the indices from `scan_fired` key here.
    names: Vec<String>,
}

/// A backend-resident scan session over a [`CompiledRuleSet`], one resident pipeline per
/// shard (parallel to the set's shards; `None` for a pattern-less shard).
pub struct ResidentSession {
    shards: Vec<Option<ResidentRulePipeline>>,
}

/// Build one shard's pipeline from its combined pattern list (`None` if pattern-less).
fn build_shard(
    patterns: &[String],
    slots: Vec<RuleSlot>,
    capacity: u32,
) -> Result<Shard, VyreEngineError> {
    let n_patterns = patterns.len();
    let pipeline = if patterns.is_empty() {
        None
    } else {
        let refs: Vec<&str> = patterns.iter().map(String::as_str).collect();
        Some(
            build_rule_pipeline_from_regex(&refs, "input", "hits", capacity)
                .map_err(|e| VyreEngineError::Compile(e.to_string()))?,
        )
    };
    Ok(Shard { pipeline, slots, n_patterns })
}

impl CompiledRuleSet {
    /// Lower + pack `rules` into byte-NFA shards sized for haystacks up to `capacity_bytes`.
    ///
    /// # Errors
    /// [`VyreEngineError::Compile`] when a single rule's pattern set exceeds the state cap,
    /// when a pattern won't lower onto the byte-NFA, or when `capacity_bytes` overflows `u32`.
    pub fn compile(rules: &[LoweredRule], capacity_bytes: usize) -> Result<Self, VyreEngineError> {
        let names: Vec<String> = rules.iter().map(|r| r.name.clone()).collect();
        let cap = u32::try_from(capacity_bytes).map_err(|_| {
            VyreEngineError::Compile(format!(
                "haystack capacity {capacity_bytes} exceeds u32; lower max_file_size"
            ))
        })?;

        let mut shards: Vec<Shard> = Vec::new();
        let mut cur_pats: Vec<String> = Vec::new();
        let mut cur_slots: Vec<RuleSlot> = Vec::new();

        for (orig, rule) in rules.iter().enumerate() {
            let rule_pats: Vec<String> = rule.patterns.iter().map(|p| p.to_byte_regex()).collect();
            let mut slot = RuleSlot {
                formula: to_formula(&rule.condition),
                base: cur_pats.len(),
                npat: rule_pats.len(),
                orig_index: orig,
            };

            if rule_pats.is_empty() {
                cur_slots.push(slot);
                continue;
            }

            let mut trial = cur_pats.clone();
            trial.extend(rule_pats.iter().cloned());
            let trial_refs: Vec<&str> = trial.iter().map(String::as_str).collect();
            match compile_regex_set(&trial_refs) {
                Ok(_) => {
                    cur_pats = trial;
                    cur_slots.push(slot);
                }
                Err(TooManyStates { .. }) if !cur_pats.is_empty() => {
                    shards.push(build_shard(&cur_pats, std::mem::take(&mut cur_slots), cap)?);
                    let refs: Vec<&str> = rule_pats.iter().map(String::as_str).collect();
                    compile_regex_set(&refs).map_err(|e| {
                        VyreEngineError::Compile(format!(
                            "rule `{}` alone exceeds the NFA state cap: {e}. \
                             Fix: split the rule's patterns.",
                            rule.name
                        ))
                    })?;
                    slot.base = 0;
                    cur_pats = rule_pats;
                    cur_slots = vec![slot];
                }
                Err(e) => {
                    return Err(VyreEngineError::Compile(format!("rule `{}`: {e}", rule.name)))
                }
            }
        }
        if !cur_slots.is_empty() {
            shards.push(build_shard(&cur_pats, cur_slots, cap)?);
        }

        Ok(Self { shards, names })
    }

    /// The rule name at `index`.
    #[must_use]
    pub fn rule_name(&self, index: usize) -> Option<&str> {
        self.names.get(index).map(String::as_str)
    }

    /// Number of rules in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// True when the set holds no rules.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// Number of byte-NFA shards.
    #[must_use]
    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    /// Upload every shard's NFA tables resident on `backend`.
    ///
    /// # Errors
    /// [`VyreEngineError::Scan`] if resident allocation/upload fails on the backend.
    pub fn prepare_session(
        &self,
        backend: &dyn vyre::VyreBackend,
        capacity_bytes: usize,
        max_matches: u32,
    ) -> Result<ResidentSession, VyreEngineError> {
        let mut shards = Vec::with_capacity(self.shards.len());
        for shard in &self.shards {
            let resident = match &shard.pipeline {
                Some(p) => Some(
                    p.prepare_resident(backend, capacity_bytes, max_matches)
                        .map_err(|e| VyreEngineError::Scan(e.to_string()))?,
                ),
                None => None,
            };
            shards.push(resident);
        }
        Ok(ResidentSession { shards })
    }

    /// Scan `data` through `session` and return the original indices of rules that fired.
    ///
    /// # Errors
    /// [`VyreEngineError::Scan`] on backend dispatch failure or capacity overflow.
    pub fn scan_fired(
        &self,
        session: &ResidentSession,
        backend: &dyn vyre::VyreBackend,
        data: &[u8],
    ) -> Result<Vec<usize>, VyreEngineError> {
        let file_size = data.len() as u64;
        let mut fired = Vec::new();
        for (shard, resident_opt) in self.shards.iter().zip(&session.shards) {
            let counts = match resident_opt {
                Some(resident) => {
                    let mut matches = Vec::new();
                    let mut scratch = Vec::new();
                    resident
                        .scan_into(backend, data, &mut matches, &mut scratch)
                        .map_err(|e| VyreEngineError::Scan(e.to_string()))?;
                    tally(matches.iter().map(|m| m.pattern_id), shard.n_patterns)
                }
                None => vec![0u32; shard.n_patterns],
            };
            for slot in &shard.slots {
                let ctx = SlotContext {
                    counts: &counts,
                    base: slot.base,
                    npat: slot.npat,
                    file_size,
                };
                if evaluate_formula(&slot.formula, &ctx) {
                    fired.push(slot.orig_index);
                }
            }
        }
        Ok(fired)
    }
}
