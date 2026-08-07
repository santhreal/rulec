//! Adversarial tests for rulec: malformed input and unsupported constructs.

use rulec::{compile, CompileError};

#[test]
fn test_malformed_yara_syntax() {
    let src = "rule bad { strings: $a = condition: $a }";
    let res = compile(src.as_bytes());
    assert!(matches!(res, Err(CompileError::Parse(_))));
}

#[test]
fn test_unsupported_module_rejected_loudly() {
    let src = r#"
import "pe"
rule pe_rule {
    condition:
        pe.number_of_sections > 3
}
"#;
    let res = compile(src.as_bytes());
    assert!(res.is_err());
}

/// ADVERSARIAL: `yara-x-parser` recurses one stack frame per bracket-nesting
/// level with no bound of its own, so a hostile rule pack with a few thousand
/// nested parentheses in `condition:` overflowed the stack and aborted the
/// whole scanner process (a fatal signal, not a catchable error). `compile`
/// now pre-scans with `validate_source_nesting` and rejects the source before
/// the upstream parser sees it.
#[test]
fn deeply_nested_condition_is_rejected_not_fatal() {
    let mut cond = "$a".to_string();
    for _ in 0..5000 {
        cond = format!("({cond} and $a)");
    }
    let src = format!("rule r {{ strings: $a = \"x\" condition: {cond} }}");
    let err = rulec::compile(src.as_bytes()).expect_err("5000-deep nesting must be rejected");
    assert!(
        err.to_string().contains("nesting exceeds limit"),
        "error should name the nesting limit, got: {err}"
    );
}

/// BOUNDARY: nesting at the limit still compiles, and parens inside string
/// literals and comments never count toward the depth.
#[test]
fn nesting_guard_boundaries() {
    // 255 levels of nesting: under the 256 cap.
    let mut cond = "$a".to_string();
    for _ in 0..255 {
        cond = format!("({cond} and $a)");
    }
    let src = format!("rule r {{ strings: $a = \"x\" condition: {cond} }}");
    assert!(rulec::compile(src.as_bytes()).is_ok());
    // Parens in a string literal and in comments are skipped by the guard.
    let src = "rule r { /* (((((( */ strings: $a = \"((((((\" // ))))\n condition: $a }";
    assert!(rulec::compile(src.as_bytes()).is_ok());
}
