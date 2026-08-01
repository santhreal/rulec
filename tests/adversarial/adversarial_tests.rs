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
