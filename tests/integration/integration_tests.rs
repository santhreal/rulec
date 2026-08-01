//! Integration tests for rulec: lowering + evaluation.

use rulec::{compile, verdict};

#[test]
fn test_lowered_rule_verdict() {
    let src = r#"
rule integration_test {
    strings:
        $a = "malware" nocase
    condition:
        $a
}
"#;
    let compiled = compile(src.as_bytes()).expect("compiles");
    let rule = &compiled.rules[0];
    assert!(verdict(rule, b"This contains Malware inside").unwrap());
    assert!(!verdict(rule, b"Clean file").unwrap());
}
