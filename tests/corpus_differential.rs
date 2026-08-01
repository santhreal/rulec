//! Corpus-scale differential regression gate (feature `differential`, `#[ignore]` by
//! default (needs the off-NFS corpus mounted and pointed to by `RULEC_CORPUS`)).
//!
//! Run it:
//!   RULEC_CORPUS=/mnt/FlareTraining/santh-archive/yara-corpus \
//!     cargo test --features differential --test corpus_differential -- --ignored --nocapture
//!
//! Asserts a concrete outcome (zero divergences over thousands of real rules), not a
//! shape: for every rule that lowers, our CPU verdict must equal yara-x's on both probe
//! buffers. This is the durable artifact behind the manual `corpus_map` dogfood run 
//! the private-rule finding (apt_hatman / MALW_Glasses) is what it guards against.

#![cfg(feature = "differential")]

use std::path::PathBuf;

#[test]
#[ignore = "needs RULEC_CORPUS pointing at a mounted YARA corpus"]
fn corpus_has_zero_divergences() {
    let Ok(env) = std::env::var("RULEC_CORPUS") else {
        panic!("set RULEC_CORPUS to the corpus dir(s) (':'-separated)");
    };
    let dirs: Vec<PathBuf> = std::env::split_paths(&env).collect();

    let report = rulec::oracle::run_corpus(&dirs);
    eprintln!("{}", report.render());

    assert!(
        report.rules_total > 0,
        "corpus produced no rules, bad RULEC_CORPUS path? ({dirs:?})"
    );
    // A real differential must actually have run (guards against silently checking nothing).
    assert!(
        report.diffed > 0,
        "no differential checks ran, every lowered rule lacked a yara-x oracle"
    );

    if !report.divergences.is_empty() {
        let detail: String = report
            .divergences
            .iter()
            .take(20)
            .map(|d| {
                format!(
                    "\n  {}::{} [{}] ours={} yara-x={}",
                    d.file.display(),
                    d.rule,
                    d.buffer,
                    d.ours,
                    d.theirs
                )
            })
            .collect();
        panic!(
            "{} semantic divergence(s) ours != yara-x over {} checks:{detail}",
            report.divergences.len(),
            report.diffed
        );
    }

    // With `vyre-engine` also enabled, the REAL vyre engine's verdict is checked too 
    // it must equal yara-x for every probe it could execute (the end-to-end gate at scale).
    if report.vyre_checked > 0 && !report.vyre_divergences.is_empty() {
        let detail: String = report
            .vyre_divergences
            .iter()
            .take(20)
            .map(|d| {
                format!(
                    "\n  {}::{} [{}] vyre={} yara-x={}",
                    d.file.display(),
                    d.rule,
                    d.buffer,
                    d.ours,
                    d.theirs
                )
            })
            .collect();
        panic!(
            "{} END-TO-END divergence(s) vyre != yara-x over {} vyre checks:{detail}",
            report.vyre_divergences.len(),
            report.vyre_checked
        );
    }
}
