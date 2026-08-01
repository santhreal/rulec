//! Differential gate: for each rule × byte sample, our lowering's verdict (via the
//! CPU reference oracle) must equal `yara_x::Scanner`'s verdict, yara-x is the
//! reference YARA semantics. Concrete outcomes asserted, never `!is_empty`.

mod common;

/// Our verdict: compile YARA → lowered IR, run the reference oracle.
fn our_verdict(src: &str, data: &[u8], rule_name: &str) -> bool {
    let compiled = rulec::compile(src.as_bytes())
        .unwrap_or_else(|e| panic!("rulec failed to lower `{rule_name}`: {e}"));
    let rule = compiled
        .rules
        .iter()
        .find(|r| r.name == rule_name)
        .unwrap_or_else(|| panic!("rule `{rule_name}` not found in lowered output"));
    rulec::verdict(rule, data)
        .unwrap_or_else(|e| panic!("reference eval failed for `{rule_name}`: {e}"))
}

/// Assert ours == yara-x for a rule on a sample, and that the sample lands the way the
/// fixture claims (so the test proves a real outcome, not just agreement-on-nothing).
fn check(src: &str, rule: &str, data: &[u8], expect: bool) {
    let ours = our_verdict(src, data, rule);
    common::assert_agrees("CPU-oracle", src, rule, data, expect, ours);
}

#[test]
fn text_presence() {
    let src = r#"rule r { strings: $a = "cmd.exe" condition: $a }"#;
    check(src, "r", b"please run cmd.exe now", true);
    check(src, "r", b"nothing here", false);
}

#[test]
fn text_nocase() {
    let src = r#"rule r { strings: $a = "CMD.EXE" nocase condition: $a }"#;
    check(src, "r", b"a cmd.exe call", true);
    check(src, "r", b"a CMD.EXE call", true);
    check(src, "r", b"no match", false);
}

#[test]
fn hex_magic_bytes() {
    let src = r"rule mz { strings: $m = { 4D 5A } condition: $m }";
    check(src, "mz", b"\x4D\x5A\x90\x00", true);
    check(src, "mz", b"PK\x03\x04", false);
}

#[test]
fn any_of_them() {
    let src = r#"rule a { strings: $a = "foo" $b = "bar" condition: any of them }"#;
    check(src, "a", b"xxbarxx", true);
    check(src, "a", b"xxfooxx", true);
    check(src, "a", b"baz", false);
}

#[test]
fn all_of_them() {
    let src = r#"rule a { strings: $a = "foo" $b = "bar" condition: all of them }"#;
    check(src, "a", b"foo and bar", true);
    check(src, "a", b"foo only", false);
}

#[test]
fn pattern_count() {
    let src = r#"rule c { strings: $a = "ab" condition: #a >= 3 }"#;
    check(src, "c", b"ababab", true); // 3 overlapping... "ab" x3 non-overlapping = 3
    check(src, "c", b"abab", false); // 2
}

#[test]
fn filesize_bound() {
    let src = r#"rule f { strings: $a = "x" condition: $a and filesize < 5 }"#;
    check(src, "f", b"x", true); // present + len 1 < 5
    check(src, "f", b"xxxxxxxx", false); // present but len 8 >= 5
}

#[test]
fn boolean_not() {
    let src = r#"rule b { strings: $a = "a" $b = "b" condition: $a and not $b }"#;
    check(src, "b", b"aaa", true);
    check(src, "b", b"ab", false);
}

#[test]
fn regex_string() {
    let src = r"rule re { strings: $r = /ab[0-9]+/ condition: $r }";
    check(src, "re", b"ab123", true);
    check(src, "re", b"abxyz", false);
}

#[test]
fn n_of_them() {
    let src = r#"rule n { strings: $a = "a" $b = "b" $c = "c" condition: 2 of them }"#;
    check(src, "n", b"ab", true); // a,b present → 2
    check(src, "n", b"a", false); // only 1
    check(src, "n", b"abc", true); // 3 ≥ 2
}

// ---- hex wildcards / jumps / alternatives → byte-regex lowering (the biggest gap) ----

#[test]
fn hex_high_nibble_wildcard() {
    // `4?` matches any byte 0x40..=0x4F.
    let src = r"rule h { strings: $a = { 4? } condition: $a }";
    check(src, "h", b"\x4A", true);
    check(src, "h", b"\x5A", false);
}

#[test]
fn hex_low_nibble_wildcard() {
    // `?4` matches any byte whose low nibble is 4.
    let src = r"rule h { strings: $a = { ?4 } condition: $a }";
    check(src, "h", b"\x34", true);
    check(src, "h", b"\x35", false);
}

#[test]
fn hex_full_wildcard() {
    // `41 ?? 43` = 'A' <any> 'C'.
    let src = r"rule h { strings: $a = { 41 ?? 43 } condition: $a }";
    check(src, "h", b"AxC", true);
    check(src, "h", b"ABD", false);
}

#[test]
fn hex_jump() {
    // `41 [2-4] 42` = 'A', then 2..=4 arbitrary bytes, then 'B'.
    let src = r"rule h { strings: $a = { 41 [2-4] 42 } condition: $a }";
    check(src, "h", b"AxxB", true); // gap 2
    check(src, "h", b"AxxxxB", true); // gap 4
    check(src, "h", b"AxB", false); // gap 1 < 2
    check(src, "h", b"AxxxxxB", false); // gap 5 > 4
}

#[test]
fn hex_alternative() {
    // `( 41 | 42 ) 43` = ('A' or 'B') then 'C'.
    let src = r"rule h { strings: $a = { ( 41 | 42 ) 43 } condition: $a }";
    check(src, "h", b"AC", true);
    check(src, "h", b"BC", true);
    check(src, "h", b"CC", false);
}

#[test]
fn hex_not_byte() {
    // `41 ~42 43` = 'A', a byte that is NOT 'B', then 'C'.
    let src = r"rule h { strings: $a = { 41 ~42 43 } condition: $a }";
    check(src, "h", b"AxC", true);
    check(src, "h", b"ABC", false);
}

#[test]
fn hex_wildcard_emits_regex_srg() {
    // Product surface: a wildcard hex lowers to the regex ExternCall, not a literal.
    let src = r"rule h { strings: $a = { 4D 5A ?? 50 } condition: $a }";
    let compiled = rulec::compile(src.as_bytes()).expect("lowers");
    assert!(
        compiled.srg.contains("vyre.scan.regex.v1"),
        "wildcard hex must lower to regex; srg:\n{}",
        compiled.srg
    );
}

// ---- `wide` modifier → byte-interleave transform ----

#[test]
fn wide_only_matches_utf16le_not_ascii() {
    // `wide` alone: matches ONLY the wide (UTF-16LE) form, not the ascii form.
    let src = r#"rule w { strings: $a = "cmd" wide condition: $a }"#;
    check(src, "w", b"c\x00m\x00d\x00", true);
    check(src, "w", b"cmd", false);
}

#[test]
fn ascii_wide_matches_both() {
    // `ascii wide`: matches either encoding.
    let src = r#"rule w { strings: $a = "cmd" ascii wide condition: $a }"#;
    check(src, "w", b"cmd", true);
    check(src, "w", b"c\x00m\x00d\x00", true);
    check(src, "w", b"xyz", false);
}

#[test]
fn wide_nocase() {
    // `nocase wide`: case-insensitive over the wide form.
    let src = r#"rule w { strings: $a = "CMD" nocase wide condition: $a }"#;
    check(src, "w", b"c\x00m\x00d\x00", true);
    check(src, "w", b"C\x00M\x00D\x00", true);
    check(src, "w", b"cmd", false);
}

// ---- `xor` modifier → uniform single-byte-key variant alternation ----

#[test]
fn xor_single_key() {
    // `xor(0x10-0x10)`: ONLY key 0x10. "Mz" = [4D 7A] ^ 0x10 = [5D 6A] = "]j".
    let src = r#"rule x { strings: $a = "Mz" xor(0x10-0x10) condition: $a }"#;
    check(src, "x", b"...]j...", true);
    check(src, "x", b"Mz", false); // plaintext (key 0x00) is NOT in the range
}

#[test]
fn xor_full_range_includes_plaintext() {
    // Bare `xor` = keys 0x00..=0xff, so the plaintext (k=0) matches too.
    let src = r#"rule x { strings: $a = "Mz" xor condition: $a }"#;
    check(src, "x", b"Mz", true); // k = 0x00
    check(src, "x", b"]j", true); // k = 0x10
    // No single key maps "Mz" onto "AB": 0x4D^0x7A = 0x37 but 0x41^0x42 = 0x03.
    check(src, "x", b"AB", false);
}

#[test]
fn xor_wide() {
    // `xor(0x01-0x01) wide`: widen("AB") = [41 00 42 00], each byte ^ 0x01 = [40 01 43 01].
    let src = r#"rule x { strings: $a = "AB" xor(0x01-0x01) wide condition: $a }"#;
    check(src, "x", b"\x40\x01\x43\x01", true);
    check(src, "x", b"AB", false);
}

// ---- `base64` / `base64wide` → alignment-encoding alternation ----

#[test]
fn base64_matches_encoded_form_at_every_alignment() {
    let src = r#"rule b { strings: $a = "This program cannot" base64 condition: $a }"#;
    // Vary the prefix length 0/1/2 so the plaintext lands at each base64 byte-alignment.
    for pre in 0..3usize {
        let mut blob = vec![b'_'; pre];
        blob.extend_from_slice(b"This program cannot");
        blob.extend_from_slice(b"___"); // complete the trailing group with real bytes
        check(src, "b", &common::b64(&blob), true);
    }
    check(src, "b", b"This program cannot", false); // plaintext is not the base64 form
}

#[test]
fn base64wide_matches_widened_encoding() {
    let src = r#"rule b { strings: $a = "This program cannot" base64wide condition: $a }"#;
    let ascii = common::b64(b"__This program cannot___");
    let wide: Vec<u8> = ascii.iter().flat_map(|&c| [c, 0u8]).collect();
    check(src, "b", &wide, true);
    check(src, "b", &ascii, false); // ascii base64, not the wide form
}

#[test]
fn rejects_wide_on_regex_with_fix() {
    let src = r#"rule w { strings: $a = /ab[0-9]/ wide condition: $a }"#;
    let err = rulec::compile(src.as_bytes())
        .expect_err("wide on a regex must be rejected in v1");
    let msg = err.to_string();
    assert!(msg.contains("wide"), "got: {msg}");
    assert!(msg.contains("Fix:"), "rejection must carry a Fix:, got {msg}");
}

// ---- rejection (screwdriver discipline): unsupported constructs fail LOUDLY ----

#[test]
fn rejects_module_field_with_fix() {
    let src = r#"import "pe" rule p { condition: pe.number_of_sections > 0 }"#;
    let err = rulec::compile(src.as_bytes())
        .expect_err("pe module access must be rejected, not silently dropped");
    let msg = err.to_string();
    assert!(msg.contains("Fix:"), "rejection must carry a Fix:, got {msg}");
}

/// `fullword` is the most common unsupported modifier in real corpora. It has no faithful
/// lowering onto live vyre (its zero-width word-boundary assertion needs a vyre regex op),
/// so it must reject LOUDLY and name both the faithful encoding and the exact vyre gap.
#[test]
fn rejects_fullword_modifier_with_fix() {
    let src = r#"rule f { strings: $a = "foo" fullword condition: $a }"#;
    let err = rulec::compile(src.as_bytes())
        .expect_err("fullword must be rejected, not silently or unsoundly approximated");
    let msg = err.to_string();
    assert!(msg.contains("fullword"), "got: {msg}");
    assert!(msg.contains("Fix:"), "rejection must carry a Fix:, got {msg}");
    assert!(
        msg.contains("Look::WordAscii") || msg.contains("word-boundary"),
        "fullword rejection must name the precise vyre gap, got {msg}"
    );
}

#[test]
fn rejects_xor_nocase_combo_with_fix() {
    // YARA itself forbids `xor nocase`; we reject it rather than emit a wrong lowering.
    let src = r#"rule x { strings: $a = "secret" xor nocase condition: $a }"#;
    let err = rulec::compile(src.as_bytes())
        .expect_err("xor + nocase is not a valid combination");
    assert!(err.to_string().contains("Fix:"));
}

/// Regression for the corpus dogfood finding: a `private rule` never appears in YARA's
/// scan output (yara-x's `matching_rules()` excludes it), so lowering it as a normal
/// self-reporting `.srg` rule diverges from yara-x. It must be rejected with a `Fix:`,
/// not emitted. Proven against the apt_hatman / MALW_Glasses private rules.
#[test]
fn rejects_private_rule_with_fix() {
    // The hatman_memcpy shape: private rule, all-literal hex patterns, simple condition.
    let src = r#"private rule p { strings: $a = "mz" condition: $a }"#;

    // yara-x itself never reports a private rule, even when its condition holds.
    assert!(
        !common::yara_x_verdict(src, b"mz", "p"),
        "yara-x must not self-report a private rule"
    );

    // So our compiler must refuse it rather than emit a rule that would fire.
    let err = rulec::compile(src.as_bytes())
        .expect_err("private rule must be rejected, not lowered to a self-reporting rule");
    let msg = err.to_string();
    assert!(msg.contains("private rule"), "got: {msg}");
    assert!(msg.contains("Fix:"), "rejection must carry a Fix:, got {msg}");
}

// ---- product output: the emitted .srg carries the expected surface ----

#[test]
fn emits_srg_surface() {
    let src = r#"rule s { strings: $a = "cmd.exe" condition: $a and filesize < 100 }"#;
    let compiled = rulec::compile(src.as_bytes()).expect("lowers");
    let srg = &compiled.srg;
    assert!(srg.contains("rule s {"), "srg:\n{srg}");
    assert!(srg.contains("input = bytes"), "srg:\n{srg}");
    assert!(
        srg.contains(r#"vyre.scan.text.v1(value: "cmd.exe""#),
        "srg:\n{srg}"
    );
    assert!(srg.contains("present($a)"), "srg:\n{srg}");
    assert!(srg.contains("filesize < 100"), "srg:\n{srg}");
}
