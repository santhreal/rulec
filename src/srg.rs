//! Emit `.srg` text (surge's rule language) from the lowered IR, an **optional secondary
//! export**, not the engine path. The product path runs the lowered IR on vyre directly
//! (`crate::vyre_engine`); this text exists so surge/surgec can carry the same rule to
//! vyre/GPU once it ingests the byte-match surface (shape per `SURFACE.md`). The lowering's
//! correctness is proven by the differential oracle (`eval`) and the real engine, so this
//! emitter only has to render the proven IR faithfully.

use std::fmt::Write as _;

use crate::lower::{Cond, LoweredPattern, LoweredRule, PatKind};

/// Render one lowered rule as `.srg` source text.
#[must_use]
pub fn emit_rule(rule: &LoweredRule) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "rule {} {{", rule.name);
    let _ = writeln!(s, "    input = bytes");
    let _ = writeln!(s, "    tags = [\"yara\"]");
    for p in &rule.patterns {
        let _ = writeln!(s, "    {}", emit_pattern(p));
    }
    let _ = writeln!(s, "    require {}", emit_cond(&rule.condition, &rule.patterns));
    let _ = writeln!(
        s,
        "    report {{ message: \"yara:{}\" }}",
        rule.name
    );
    let _ = writeln!(s, "}}");
    s
}

/// Render all rules.
#[must_use]
pub fn emit_rules(rules: &[LoweredRule]) -> String {
    rules.iter().map(emit_rule).collect::<Vec<_>>().join("\n")
}

fn emit_pattern(p: &LoweredPattern) -> String {
    let mods = if p.nocase { ", nocase: true, ascii: true" } else { ", ascii: true" };
    match &p.kind {
        PatKind::Text(bytes) => format!(
            "let ${} = vyre.scan.text.v1(value: \"{}\"{mods})",
            p.name,
            escape_bytes(bytes)
        ),
        PatKind::Hex(bytes) => format!(
            "let ${} = vyre.scan.hex.v1(value: \"{}\")",
            p.name,
            hex_bytes(bytes)
        ),
        PatKind::Regex(src) => format!(
            "let ${} = vyre.scan.regex.v1(value: \"{}\"{mods})",
            p.name,
            escape_str(src)
        ),
    }
}

fn emit_cond(c: &Cond, patterns: &[LoweredPattern]) -> String {
    match c {
        Cond::Bool(true) => "true".to_string(),
        Cond::Bool(false) => "false".to_string(),
        Cond::Present(id) => format!("present(${})", name_of(*id, patterns)),
        Cond::Count { id, op, n } => {
            format!("count(${}) {} {}", name_of(*id, patterns), op.as_str(), n)
        }
        Cond::FileSize { op, n } => format!("filesize {} {}", op.as_str(), n),
        Cond::And(v) => join(v, "and", patterns),
        Cond::Or(v) => join(v, "or", patterns),
        Cond::Not(inner) => format!("not ({})", emit_cond(inner, patterns)),
    }
}

fn join(v: &[Cond], sep: &str, patterns: &[LoweredPattern]) -> String {
    if v.is_empty() {
        // Empty conjunction = true, empty disjunction = false.
        return if sep == "and" { "true" } else { "false" }.to_string();
    }
    let parts: Vec<String> = v.iter().map(|c| emit_cond(c, patterns)).collect();
    format!("({})", parts.join(&format!(" {sep} ")))
}

fn name_of(id: u32, patterns: &[LoweredPattern]) -> String {
    patterns
        .iter()
        .find(|p| p.id == id)
        .map_or_else(|| format!("p{id}"), |p| p.name.clone())
}

/// Escape bytes for a double-quoted `.srg` string, using `\xNN` for non-printable.
fn escape_bytes(bytes: &[u8]) -> String {
    let mut s = String::new();
    for &b in bytes {
        match b {
            b'"' => s.push_str("\\\""),
            b'\\' => s.push_str("\\\\"),
            0x20..=0x7E => s.push(b as char),
            _ => {
                let _ = write!(s, "\\x{b:02X}");
            }
        }
    }
    s
}

fn escape_str(src: &str) -> String {
    src.replace('\\', "\\\\").replace('"', "\\\"")
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}
