//! Property tests for rulec lowering invariants.

use rulec::compile;

#[test]
fn test_empty_yara_source() {
    let src = "";
    let compiled = compile(src.as_bytes()).expect("empty source compiles");
    assert!(compiled.rules.is_empty());
}

#[test]
fn test_multiple_rules_ordering() {
    let src = r#"
rule r1 { strings: $a = "a" condition: $a }
rule r2 { strings: $b = "b" condition: $b }
"#;
    let compiled = compile(src.as_bytes()).expect("compiles");
    assert_eq!(compiled.rules.len(), 2);
    assert_eq!(compiled.rules[0].name, "r1");
    assert_eq!(compiled.rules[1].name, "r2");
}
