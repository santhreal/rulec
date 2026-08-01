//! Gap tests for rulec: explicit coverage of known gaps and feature boundaries.

use rulec::{compile, CompileError};

#[test]
fn test_gap_anchor_rejected() {
    let src = r#"
rule anchor_rule {
    strings:
        $a = "test"
    condition:
        $a at 0
}
"#;
    let res = compile(src.as_bytes());
    assert!(matches!(res, Err(CompileError::Lower(_))));
}

#[test]
fn test_gap_fullword_rejected() {
    let src = r#"
rule fullword_rule {
    strings:
        $a = "test" fullword
    condition:
        $a
}
"#;
    let res = compile(src.as_bytes());
    assert!(matches!(res, Err(CompileError::Lower(_))));
}
