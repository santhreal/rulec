//! Emit the `.srg` text for a YARA rule file, the bridge artifact warpscan/surgec would
//! ingest. Usage: `cargo run --example emit_srg -- <rule.yar>` (prints `.srg` to stdout).

use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: emit_srg <rule.yar>");
        return ExitCode::from(2);
    };
    let src = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read {path}: {e}");
            return ExitCode::from(2);
        }
    };
    match rulec::compile(&src) {
        Ok(compiled) => {
            print!("{}", compiled.srg);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("rulec cannot lower {path}: {e}");
            ExitCode::from(1)
        }
    }
}
