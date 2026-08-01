//! Dogfood driver: run the lowering across a real YARA corpus and print the HAVE/gap map
//! plus any semantic divergences vs `yara_x::Scanner`. Thin CLI over
//! [`rulec::oracle::run_corpus`] (the engine lives in the lib so the example and the
//! `corpus_differential` regression test share one code path (no duplication)).
//!
//! Requires the `differential` feature (pulls in yara-x as the oracle):
//!   cargo run --release --features differential --example corpus_map -- <dir> [more...]
//!   RULEC_CORPUS=/path cargo run --release --features differential --example corpus_map
//!
//! The corpus lives off-NFS (e.g. /mnt/FlareTraining/santh-archive/yara-corpus); never
//! vendored into the tree. Exits non-zero iff a real divergence is found.

use std::path::PathBuf;

fn main() {
    let dirs: Vec<PathBuf> = {
        let args: Vec<String> = std::env::args().skip(1).collect();
        if !args.is_empty() {
            args.into_iter().map(PathBuf::from).collect()
        } else if let Ok(env) = std::env::var("RULEC_CORPUS") {
            std::env::split_paths(&env).collect()
        } else {
            eprintln!(
                "usage: corpus_map <corpus_dir> [more...]   (or set RULEC_CORPUS)\n\
                 e.g. /mnt/FlareTraining/santh-archive/yara-corpus"
            );
            std::process::exit(2);
        }
    };

    let report = rulec::oracle::run_corpus(&dirs);
    if report.rules_total == 0 {
        eprintln!("no rules found under {dirs:?}");
        std::process::exit(2);
    }
    print!("{}", report.render());

    if !report.divergences.is_empty() {
        std::process::exit(1);
    }
}
