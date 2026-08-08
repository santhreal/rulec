//! Corpus-scale differential oracle (feature `differential`).

pub mod synth;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::lower::lower_rule;
use crate::{verdict, LoweredRule};
use synth::{all_literals_buffer, all_patterns_buffer};

/// One concrete divergence: our verdict disagreed with yara-x on a real rule.
#[derive(Debug, Clone)]
pub struct Divergence {
    /// File the rule came from.
    pub file: PathBuf,
    /// Rule identifier.
    pub rule: String,
    /// Which probe buffer ("empty" | "all-literals" | "all-patterns").
    pub buffer: &'static str,
    /// Our CPU oracle's verdict.
    pub ours: bool,
    /// yara-x's verdict.
    pub theirs: bool,
}

/// Aggregate result of a corpus run.
#[derive(Debug, Default, Clone)]
pub struct CorpusReport {
    pub files: usize,
    pub parse_error_files: usize,
    pub read_errors: usize,
    pub dir_read_errors: usize,
    pub rules_total: usize,
    pub lowered: usize,
    pub rejected: usize,
    pub gap: BTreeMap<String, usize>,
    pub diffed: usize,
    pub no_oracle: usize,
    pub oracle_regex_skipped: usize,
    pub divergences: Vec<Divergence>,
    pub vyre_checked: usize,
    pub vyre_errors: usize,
    pub vyre_skipped_large: usize,
    pub vyre_divergences: Vec<Divergence>,
    pub rulec_accepts_yara_rejects: usize,
    pub yara_reject_examples: Vec<(PathBuf, String)>,
}

impl CorpusReport {
    #[must_use]
    pub fn coverage_pct(&self) -> f64 {
        if self.rules_total == 0 {
            0.0
        } else {
            100.0 * self.lowered as f64 / self.rules_total as f64
        }
    }

    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::new();
        let _ = writeln!(s, "\n================ rulec HAVE/gap map ================");
        let _ = writeln!(s, "files scanned          : {}", self.files);
        let _ = writeln!(s, "  parse-error files    : {}", self.parse_error_files);
        let _ = writeln!(s, "  read-error files     : {}", self.read_errors);
        let _ = writeln!(s, "  read-error dirs      : {}", self.dir_read_errors);
        let _ = writeln!(s, "rules total            : {}", self.rules_total);
        let _ = writeln!(
            s,
            "  LOWERS               : {} ({:.1}%)",
            self.lowered,
            self.coverage_pct()
        );
        let _ = writeln!(s, "  rejected (gap)       : {}", self.rejected);
        let _ = writeln!(s, "differential checks    : {}", self.diffed);
        let _ = writeln!(s, "  no-oracle (yara-x rejected file): {}", self.no_oracle);
        let _ = writeln!(
            s,
            "  rulec-accepts-yara-rejects (soundness gap): {}",
            self.rulec_accepts_yara_rejects
        );
        let _ = writeln!(s, "  cpu-oracle regex-skip: {}", self.oracle_regex_skipped);
        let _ = writeln!(s, "  DIVERGENCES          : {}", self.divergences.len());
        if self.vyre_checked > 0 || self.vyre_errors > 0 || self.vyre_skipped_large > 0 {
            let _ = writeln!(
                s,
                "real-vyre-engine checks: {} (errors {}, skipped-large {})",
                self.vyre_checked, self.vyre_errors, self.vyre_skipped_large
            );
            let _ = writeln!(s, "  E2E DIVERGENCES (vyre != yara-x): {}", self.vyre_divergences.len());
        }

        let _ = writeln!(
            s,
            "\n---- gap histogram (rejection reason × count). P3 roadmap by real frequency ----"
        );
        let mut rows: Vec<(&String, &usize)> = self.gap.iter().collect();
        rows.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        let total_rej = self.rejected.max(1);
        for (reason, count) in rows {
            let pct = 100.0 * *count as f64 / total_rej as f64;
            let _ = writeln!(s, "  {count:>6}  {pct:>5.1}%  {reason}");
        }

        if !self.divergences.is_empty() {
            let _ = writeln!(s, "\n---- DIVERGENCES (semantic findings) ----");
            for d in &self.divergences {
                let _ = writeln!(
                    s,
                    "  {}::{} [{}] ours={} yara-x={}",
                    d.file.display(),
                    d.rule,
                    d.buffer,
                    d.ours,
                    d.theirs
                );
            }
        }
        let _ = writeln!(s, "========================================================");
        s
    }
}

#[must_use]
pub fn run_corpus(dirs: &[PathBuf]) -> CorpusReport {
    let mut files = Vec::new();
    let mut dir_read_errors = 0usize;
    for d in dirs {
        collect_yara_files(d, &mut files, &mut dir_read_errors);
    }
    files.sort();

    let mut report = CorpusReport {
        files: files.len(),
        dir_read_errors,
        ..Default::default()
    };
    for path in &files {
        let Ok(bytes) = std::fs::read(path) else {
            report.read_errors += 1;
            continue;
        };
        scan_file(path, &bytes, &mut report);
    }
    report
}

fn scan_file(path: &Path, bytes: &[u8], report: &mut CorpusReport) {
    let ast = crate::parse(bytes);
    if !ast.errors().is_empty() {
        report.parse_error_files += 1;
        return;
    }

    let src = String::from_utf8_lossy(bytes);
    let oracle = build_oracle(&src);
    let mut yara_reject_error = oracle.as_ref().err().cloned();

    for rule in ast.rules() {
        report.rules_total += 1;
        match lower_rule(rule) {
            Ok(lowered) => {
                report.lowered += 1;
                match &oracle {
                    Ok(Some(rules)) => differential(path, rules, &lowered, report),
                    Ok(None) => report.no_oracle += 1,
                    Err(_) => {
                        report.rulec_accepts_yara_rejects += 1;
                        if report.yara_reject_examples.len() < 3 {
                            if let Some(msg) = yara_reject_error.take() {
                                report.yara_reject_examples.push((path.to_path_buf(), msg));
                            }
                        }
                    }
                }
            }
            Err(e) => {
                report.rejected += 1;
                *report.gap.entry(reason_bucket(&e.what)).or_insert(0) += 1;
            }
        }
    }
}

fn build_oracle(src: &str) -> Result<Option<yara_x::Rules>, String> {
    let mut compiler = yara_x::Compiler::new();
    if let Err(e) = compiler.add_source(src) {
        return Err(e.to_string());
    }
    Ok(Some(compiler.build()))
}

fn differential(path: &Path, oracle: &yara_x::Rules, lowered: &LoweredRule, report: &mut CorpusReport) {
    let probes: [(&'static str, Vec<u8>); 3] = [
        ("empty", Vec::new()),
        ("all-literals", all_literals_buffer(lowered)),
        ("all-patterns", all_patterns_buffer(lowered)),
    ];

    for (tag, buf) in &probes {
        let theirs = yara_x_match(oracle, buf, &lowered.name);

        match verdict(lowered, buf) {
            Ok(ours) => {
                report.diffed += 1;
                if ours != theirs {
                    report.divergences.push(Divergence {
                        file: path.to_path_buf(),
                        rule: lowered.name.clone(),
                        buffer: tag,
                        ours,
                        theirs,
                    });
                }
            }
            Err(_) => report.oracle_regex_skipped += 1,
        }

        #[cfg(feature = "vyre-engine")]
        {
            const VYRE_PROBE_CAP: usize = 8192;
            if buf.len() > VYRE_PROBE_CAP {
                report.vyre_skipped_large += 1;
            } else {
                match crate::vyre_engine::verdict(lowered, buf) {
                    Ok(vv) => {
                        report.vyre_checked += 1;
                        if vv != theirs {
                            report.vyre_divergences.push(Divergence {
                                file: path.to_path_buf(),
                                rule: lowered.name.clone(),
                                buffer: tag,
                                ours: vv,
                                theirs,
                            });
                        }
                    }
                    Err(_) => report.vyre_errors += 1,
                }
            }
        }
    }
}

fn yara_x_match(rules: &yara_x::Rules, data: &[u8], rule_name: &str) -> bool {
    let mut scanner = yara_x::Scanner::new(rules);
    match scanner.scan(data) {
        Ok(results) => results.matching_rules().any(|r| r.identifier() == rule_name),
        Err(_) => false,
    }
}

fn reason_bucket(what: &str) -> String {
    let cut = what.find(['`', '(']).unwrap_or(what.len());
    let head = what[..cut].trim();
    if head.is_empty() {
        what.trim().to_string()
    } else {
        head.to_string()
    }
}

fn collect_yara_files(dir: &Path, out: &mut Vec<PathBuf>, read_errors: &mut usize) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        *read_errors += 1;
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_yara_files(&path, out, read_errors);
        } else if matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("yar" | "yara")
        ) {
            out.push(path);
        }
    }
}

#[cfg(all(test, feature = "differential"))]
mod tests {
    use super::*;
    use synth::synthesize_regex_match;
    const YARA_REJECTED_SRC: &str = r#"
rule test {
    strings:
        $a = /a{0,1/
    condition:
        any of them
}
"#;

    #[test]
    fn build_oracle_reports_yara_compile_error() {
        let result = build_oracle(YARA_REJECTED_SRC);
        assert!(
            result.is_err(),
            "yara-x should reject an invalid regex source, got {:?}",
            result
        );
        let msg = result.unwrap_err();
        assert!(!msg.is_empty(), "error message should not be empty");
    }

    #[test]
    fn scan_file_counts_rulec_accepts_yara_rejects() {
        let path = Path::new("test.yar");
        let mut report = CorpusReport::default();
        scan_file(path, YARA_REJECTED_SRC.as_bytes(), &mut report);

        assert_eq!(report.rules_total, 1, "one rule was seen");
        assert_eq!(report.lowered, 1, "rulec lowered the rule");
        assert_eq!(
            report.no_oracle, 0,
            "yara-x rejection must not be silently counted as no_oracle"
        );
        assert_eq!(
            report.rulec_accepts_yara_rejects, 1,
            "yara-x rejected the file but rulec lowered the rule"
        );
        assert_eq!(report.yara_reject_examples.len(), 1);
        assert_eq!(report.yara_reject_examples[0].0, path);
        assert!(!report.yara_reject_examples[0].1.is_empty());
    }

    #[test]
    fn scan_file_uses_oracle_when_yara_compiles() {
        let src = r#"
rule ok {
    strings:
        $a = "abc" ascii
    condition:
        $a
}
"#;
        let mut report = CorpusReport::default();
        scan_file(Path::new("ok.yar"), src.as_bytes(), &mut report);

        assert_eq!(report.rules_total, 1);
        assert_eq!(report.lowered, 1);
        assert_eq!(report.rulec_accepts_yara_rejects, 0);
        assert!(report.diffed > 0, "differential checks should have run");
    }

    #[test]
    fn synthesize_regex_match_finds_short_match_for_simple_regexes() {
        fn matches(regex: &str, nocase: bool, sample: &[u8]) -> bool {
            let pattern = if nocase { format!("(?i){regex}") } else { regex.to_string() };
            regex::bytes::Regex::new(&pattern).unwrap().is_match(sample)
        }

        let s = synthesize_regex_match("abc", false).unwrap();
        assert!(matches("abc", false, &s), "got {s:?}");
        assert!(synthesize_regex_match("[0-9]+", false).is_some());
        let s = synthesize_regex_match("a|b", false).unwrap();
        assert!(matches("a|b", false, &s), "got {s:?}");
        let s = synthesize_regex_match("^abc$", false).unwrap();
        assert!(matches("^abc$", false, &s), "got {s:?}");
        let s = synthesize_regex_match("ABC", true).unwrap();
        assert!(matches("ABC", true, &s), "got {s:?}");
    }

    #[test]
    fn synthesize_regex_match_bails_fast_on_unsatisfiable_alphabet() {
        let start = std::time::Instant::now();
        let result = synthesize_regex_match("^[A-Z]{5}$", false);
        let elapsed = start.elapsed();
        assert!(result.is_none(), "uppercase-only regex is unsatisfiable here");
        assert!(
            elapsed < std::time::Duration::from_millis(10),
            "brute force must bail within the budget, took {elapsed:?}"
        );
    }

    #[test]
    fn synthesize_regex_match_still_covers_length_four_classes() {
        let s = synthesize_regex_match("[a-z]{4}", false).expect("aaaa satisfies [a-z]{4}");
        let re = regex::bytes::Regex::new("[a-z]{4}").unwrap();
        assert!(re.is_match(&s), "synthesized {s:?} must match [a-z]{{4}}");
    }

    #[test]
    fn run_corpus_counts_unreadable_directory_instead_of_silent_skip() {
        let missing = PathBuf::from("/nonexistent-rulec-corpus-dir/does/not/exist");
        let report = run_corpus(&[missing]);
        assert_eq!(report.files, 0);
        assert_eq!(
            report.dir_read_errors, 1,
            "an unreadable corpus directory must be counted, not silently skipped"
        );
    }

    #[test]
    fn all_patterns_buffer_fires_regex_present_path() {
        let src = r#"
rule regex_present {
    strings:
        $a = /abc[0-9]+/ ascii
    condition:
        $a
}
"#;
        let ast = crate::parse(src.as_bytes());
        let rule = ast.rules().next().expect("one rule");
        let lowered = lower_rule(rule).expect("lower ok");
        let buf = all_patterns_buffer(&lowered);
        assert!(
            verdict(&lowered, &buf).expect("verdict ok"),
            "all-patterns buffer should make the regex rule fire"
        );
    }
}
