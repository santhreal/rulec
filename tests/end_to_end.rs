//! End-to-end gate (features `vyre-engine` + `differential`): YARA → lowered IR → the
//! REAL vyre scan + rule engine (`vyre_engine::verdict`, `CpuRefBackend`) → verdict, which
//! must equal `yara_x::Scanner` on concrete bytes. This proves the whole product path 
//! not the CPU mirror, is faithful to YARA. The same `RulePipeline` runs on a GPU
//! `VyreBackend` unchanged; this gate pins the semantics on the portable backend.

#![cfg(all(feature = "vyre-engine", feature = "differential"))]

mod common;

/// Our verdict through the REAL vyre engine.
fn vyre_verdict(src: &str, data: &[u8], rule_name: &str) -> bool {
    let compiled = rulec::compile(src.as_bytes())
        .unwrap_or_else(|e| panic!("rulec failed to lower `{rule_name}`: {e}"));
    let rule = compiled
        .rules
        .iter()
        .find(|r| r.name == rule_name)
        .unwrap_or_else(|| panic!("rule `{rule_name}` not lowered"));
    rulec::vyre_engine::verdict(rule, data)
        .unwrap_or_else(|e| panic!("vyre engine failed for `{rule_name}`: {e}"))
}

/// vyre verdict == yara-x verdict == the fixture's expected outcome.
fn check(src: &str, rule: &str, data: &[u8], expect: bool) {
    let ours = vyre_verdict(src, data, rule);
    common::assert_agrees("E2E-vyre", src, rule, data, expect, ours);
}

#[test]
fn e2e_text_presence() {
    let src = r#"rule r { strings: $a = "cmd.exe" condition: $a }"#;
    check(src, "r", b"please run cmd.exe now", true);
    check(src, "r", b"nothing here", false);
}

#[test]
fn e2e_text_nocase() {
    let src = r#"rule r { strings: $a = "CMD.EXE" nocase condition: $a }"#;
    check(src, "r", b"a cmd.exe call", true);
    check(src, "r", b"a CMD.EXE call", true);
    check(src, "r", b"no match", false);
}

#[test]
fn e2e_hex_magic_bytes() {
    let src = r"rule mz { strings: $m = { 4D 5A } condition: $m }";
    check(src, "mz", b"\x4D\x5A\x90\x00", true);
    check(src, "mz", b"PK\x03\x04", false);
}

#[test]
fn e2e_hex_wildcard() {
    let src = r"rule h { strings: $a = { 41 ?? 43 } condition: $a }";
    check(src, "h", b"AxC", true);
    check(src, "h", b"ABD", false);
}

#[test]
fn e2e_hex_jump() {
    let src = r"rule h { strings: $a = { 41 [2-4] 42 } condition: $a }";
    check(src, "h", b"AxxB", true);
    check(src, "h", b"AxB", false);
}

#[test]
fn e2e_hex_alternative() {
    let src = r"rule h { strings: $a = { ( 41 | 42 ) 43 } condition: $a }";
    check(src, "h", b"AC", true);
    check(src, "h", b"BC", true);
    check(src, "h", b"CC", false);
}

#[test]
fn e2e_regex() {
    let src = r"rule re { strings: $r = /ab[0-9]+/ condition: $r }";
    check(src, "re", b"ab123", true);
    check(src, "re", b"abxyz", false);
}

#[test]
fn e2e_wide() {
    let src = r#"rule w { strings: $a = "cmd" wide condition: $a }"#;
    check(src, "w", b"c\x00m\x00d\x00", true);
    check(src, "w", b"cmd", false);
}

#[test]
fn e2e_any_of_them() {
    let src = r#"rule a { strings: $a = "foo" $b = "bar" condition: any of them }"#;
    check(src, "a", b"xxbarxx", true);
    check(src, "a", b"xxfooxx", true);
    check(src, "a", b"baz", false);
}

#[test]
fn e2e_all_of_them() {
    let src = r#"rule a { strings: $a = "foo" $b = "bar" condition: all of them }"#;
    check(src, "a", b"foo and bar", true);
    check(src, "a", b"foo only", false);
}

#[test]
fn e2e_pattern_count() {
    let src = r#"rule c { strings: $a = "ab" condition: #a >= 3 }"#;
    check(src, "c", b"ababab", true);
    check(src, "c", b"abab", false);
}

#[test]
fn e2e_filesize_bound() {
    let src = r#"rule f { strings: $a = "x" condition: $a and filesize < 5 }"#;
    check(src, "f", b"x", true);
    check(src, "f", b"xxxxxxxx", false);
}

#[test]
fn e2e_boolean_not() {
    let src = r#"rule b { strings: $a = "a" $b = "b" condition: $a and not $b }"#;
    check(src, "b", b"aaa", true);
    check(src, "b", b"ab", false);
}

#[test]
fn e2e_n_of_them() {
    let src = r#"rule n { strings: $a = "a" $b = "b" $c = "c" condition: 2 of them }"#;
    check(src, "n", b"ab", true);
    check(src, "n", b"a", false);
    check(src, "n", b"abc", true);
}

#[test]
fn e2e_xor() {
    // The XORed-variant alternation runs through vyre's byte-NFA (Literal + Alternation).
    let src = r#"rule x { strings: $a = "Mz" xor(0x10-0x10) condition: $a }"#;
    check(src, "x", b"...]j...", true); // "Mz" ^ 0x10
    check(src, "x", b"Mz", false); // plaintext not in the key range
}

#[test]
fn e2e_xor_full_range() {
    let src = r#"rule x { strings: $a = "Mz" xor condition: $a }"#;
    check(src, "x", b"Mz", true); // k = 0x00
    check(src, "x", b"]j", true); // k = 0x10
    check(src, "x", b"AB", false); // no single key maps "Mz" → "AB"
}

#[test]
fn e2e_base64() {
    // The 3 alignment encodings run as an alternation through the real vyre engine.
    let src = r#"rule b { strings: $a = "This program cannot" base64 condition: $a }"#;
    for pre in 0..3usize {
        let mut blob = vec![b'_'; pre];
        blob.extend_from_slice(b"This program cannot");
        blob.extend_from_slice(b"___");
        check(src, "b", &common::b64(&blob), true);
    }
    check(src, "b", b"This program cannot", false);
}
