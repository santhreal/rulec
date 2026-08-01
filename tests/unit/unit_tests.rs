//! Unit tests for rulec lowering and AST parsing.

use rulec::{compile, parse};

#[test]
fn test_parse_valid_yara() {
    let src = r#"
rule test_rule {
    strings:
        $a = "hello"
    condition:
        $a
}
"#;
    let ast = parse(src.as_bytes());
    assert!(ast.errors().is_empty());
}

#[test]
fn test_compile_basic_rule() {
    let src = r#"
rule test_rule {
    strings:
        $a = "hello" nocase
    condition:
        $a
}
"#;
    let compiled = compile(src.as_bytes()).expect("should compile valid rule");
    assert_eq!(compiled.rules.len(), 1);
    assert_eq!(compiled.rules[0].name, "test_rule");
}
