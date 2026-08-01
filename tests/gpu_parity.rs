//! On-device parity gate (features `gpu` + `differential`): the **same** lowered
//! `RulePipeline` that the CPU end-to-end gate proves against `yara_x::Scanner` is here
//! dispatched on a real GPU `VyreBackend` (`vyre-driver-wgpu`). For each fixture we assert a
//! three-way agreement:
//!
//! ```text
//!   verdict_on(rule, data, &gpu)  ==  verdict(rule, data)  ==  yara_x::Scanner
//!        (GPU megakernel)              (CPU parity walk)        (reference YARA)
//! ```
//!
//! plus per-pattern count parity (`pattern_counts_on == pattern_counts`), the proof that
//! swapping the executor (CPU walk → on-device megakernel) preserves rule semantics, the
//! load-bearing invariant for warpscan's GPU malware-scan path.
//!
//! ## Substrate status
//!
//! Every lowering shape now dispatches and matches correctly on-device. Two vyre NFA-scan
//! substrate bugs that previously blocked the full surface are fixed:
//! - `InvalidStoreTypes` naga-validation failure on the `num_states == 4` shape (e.g. the
//!   `{ 4D 5A }` MZ-header hex pipeline), fixed by the block-scoped-local type-staleness guard
//!   in `vyre-emit-naga` (an SSA id reused across a bool→u32 retype left a stale-typed local).
//! - A multi-minute lowering "hang" on the 771-state bare-`xor` pipeline. NOT a GPU bug at all,
//!   but an O(n²) descriptor-optimizer pass (`vyre-lower::verify_then_optimize`) triggered because
//!   the NFA-scan shader unrolled O(num_states) `if_then` nodes. Fixed by making the lane-major
//!   transition + epsilon gather data-driven (a runtime bit-`loop_for` instead of a 32-way unroll),
//!   so the shader is O(1) in state count and the optimizer no longer chokes.
//!
//! Both [`gpu_parity_literals`] (fast literal subset) and [`gpu_parity_all_shapes`] (full surface)
//! run by default and assert GPU == CPU == yara-x. Requires a GPU. The `gpu` feature is opt-in, so
//! compiling this test IS a request for the device; if acquisition fails we panic loudly (never
//! skip silently: Law 8 / Law 10).

#![cfg(all(feature = "gpu", feature = "differential"))]

mod common;

use rulec::vyre_engine::{
    pattern_counts, pattern_counts_on, verdict, verdict_on, CompiledRuleSet, DEFAULT_MAX_MATCHES,
};
use vyre_driver_wgpu::WgpuBackend;

/// One fixture: YARA source, rule name, haystack, and the expected (yara-x) verdict.
struct Case {
    src: &'static str,
    rule: &'static str,
    data: Vec<u8>,
    expect: bool,
}

fn c(src: &'static str, rule: &'static str, data: &[u8], expect: bool) -> Case {
    Case { src, rule, data: data.to_vec(), expect }
}

/// The proven differential corpus, mirroring `tests/end_to_end.rs` across every lowering
/// surface (text/nocase, hex literal/wildcard/jump/alternation, regex, wide, xor, base64,
/// counts, filesize, boolean, quantifiers).
fn cases() -> Vec<Case> {
    let text = r#"rule r { strings: $a = "cmd.exe" condition: $a }"#;
    let nocase = r#"rule r { strings: $a = "CMD.EXE" nocase condition: $a }"#;
    let hexmz = r"rule mz { strings: $m = { 4D 5A } condition: $m }";
    let hexwild = r"rule h { strings: $a = { 41 ?? 43 } condition: $a }";
    let hexjump = r"rule h { strings: $a = { 41 [2-4] 42 } condition: $a }";
    let hexalt = r"rule h { strings: $a = { ( 41 | 42 ) 43 } condition: $a }";
    let re = r"rule re { strings: $r = /ab[0-9]+/ condition: $r }";
    let wide = r#"rule w { strings: $a = "cmd" wide condition: $a }"#;
    let anyof = r#"rule a { strings: $a = "foo" $b = "bar" condition: any of them }"#;
    let allof = r#"rule a { strings: $a = "foo" $b = "bar" condition: all of them }"#;
    let count = r#"rule c { strings: $a = "ab" condition: #a >= 3 }"#;
    let fsize = r#"rule f { strings: $a = "x" condition: $a and filesize < 5 }"#;
    let boolnot = r#"rule b { strings: $a = "a" $b = "b" condition: $a and not $b }"#;
    let nof = r#"rule n { strings: $a = "a" $b = "b" $c = "c" condition: 2 of them }"#;
    let xor = r#"rule x { strings: $a = "Mz" xor(0x10-0x10) condition: $a }"#;
    let xorfull = r#"rule x { strings: $a = "Mz" xor condition: $a }"#;
    let b64rule = r#"rule b { strings: $a = "This program cannot" base64 condition: $a }"#;

    let mut v = vec![
        c(text, "r", b"please run cmd.exe now", true),
        c(text, "r", b"nothing here", false),
        c(nocase, "r", b"a cmd.exe call", true),
        c(nocase, "r", b"a CMD.EXE call", true),
        c(nocase, "r", b"no match", false),
        c(hexmz, "mz", b"\x4D\x5A\x90\x00", true),
        c(hexmz, "mz", b"PK\x03\x04", false),
        c(hexwild, "h", b"AxC", true),
        c(hexwild, "h", b"ABD", false),
        c(hexjump, "h", b"AxxB", true),
        c(hexjump, "h", b"AxB", false),
        c(hexalt, "h", b"AC", true),
        c(hexalt, "h", b"BC", true),
        c(hexalt, "h", b"CC", false),
        c(re, "re", b"ab123", true),
        c(re, "re", b"abxyz", false),
        c(wide, "w", b"c\x00m\x00d\x00", true),
        c(wide, "w", b"cmd", false),
        c(anyof, "a", b"xxbarxx", true),
        c(anyof, "a", b"baz", false),
        c(allof, "a", b"foo and bar", true),
        c(allof, "a", b"foo only", false),
        c(count, "c", b"ababab", true),
        c(count, "c", b"abab", false),
        c(fsize, "f", b"x", true),
        c(fsize, "f", b"xxxxxxxx", false),
        c(boolnot, "b", b"aaa", true),
        c(boolnot, "b", b"ab", false),
        c(nof, "n", b"ab", true),
        c(nof, "n", b"a", false),
        c(nof, "n", b"abc", true),
        c(xor, "x", b"...]j...", true),
        c(xor, "x", b"Mz", false),
        c(xorfull, "x", b"Mz", true),
        c(xorfull, "x", b"]j", true),
        c(xorfull, "x", b"AB", false),
    ];
    // base64 at all three byte-alignments (the encoded form is the haystack).
    for pre in 0..3usize {
        let mut blob = vec![b'_'; pre];
        blob.extend_from_slice(b"This program cannot");
        blob.extend_from_slice(b"___");
        v.push(Case { src: b64rule, rule: "b", data: common::b64(&blob), expect: true });
    }
    v.push(c(b64rule, "b", b"This program cannot", false));
    v
}

/// Lower `src` and return the named rule, or panic with context.
fn lower<'a>(compiled: &'a rulec::Compiled, rule: &str) -> &'a rulec::LoweredRule {
    compiled
        .rules
        .iter()
        .find(|r| r.name == rule)
        .unwrap_or_else(|| panic!("rule `{rule}` not lowered"))
}

/// The literal-pattern subset that vyre's GPU NFA-scan backend executes correctly today
/// (proven: full verdict + count parity on-device). A fast smoke subset of the full
/// [`gpu_parity_all_shapes`] surface, the literal path is the most common shape and the cheapest
/// to dispatch, so this gives a quick on-device signal without the full corpus.
fn literal_cases() -> Vec<Case> {
    let text = r#"rule r { strings: $a = "cmd.exe" condition: $a }"#;
    let nocase = r#"rule r { strings: $a = "CMD.EXE" nocase condition: $a }"#;
    vec![
        c(text, "r", b"please run cmd.exe now", true),
        c(text, "r", b"nothing here", false),
        c(nocase, "r", b"a cmd.exe call", true),
        c(nocase, "r", b"a CMD.EXE call", true),
        c(nocase, "r", b"no match", false),
    ]
}

/// Acquire the device, failing loud (the `gpu` feature IS the request for a GPU (never skip)).
fn acquire() -> WgpuBackend {
    WgpuBackend::acquire().unwrap_or_else(|e| {
        panic!(
            "GPU backend unavailable: {e}. The `gpu` feature requires a real device \
             (Vulkan/Metal/DX12); this gate never silently skips. Fix: run on a GPU host."
        )
    })
}

/// Strict full parity for one case: GPU verdict == CPU verdict == yara-x == fixture, and GPU
/// per-pattern counts == CPU counts. Panics (fails the gate) on any GPU error or divergence.
fn assert_full_parity(backend: &WgpuBackend, case: &Case) {
    let compiled = rulec::compile(case.src.as_bytes())
        .unwrap_or_else(|e| panic!("rulec failed to lower `{}`: {e}", case.rule));
    let rule = lower(&compiled, case.rule);
    let label = format!("{} / {:?}", case.rule, case.data);

    let cpu = verdict(rule, &case.data)
        .unwrap_or_else(|e| panic!("CPU verdict failed for `{label}`: {e}"));
    let gpu = verdict_on(rule, &case.data, backend, DEFAULT_MAX_MATCHES)
        .unwrap_or_else(|e| panic!("GPU verdict failed for `{label}`: {e}"));

    common::assert_agrees("GPU-vyre", case.src, case.rule, &case.data, case.expect, gpu);
    assert_eq!(gpu, cpu, "executor divergence on `{label}`: GPU={gpu}, CPU={cpu}");

    let cpu_counts = pattern_counts(rule, &case.data).expect("cpu counts");
    let gpu_counts = pattern_counts_on(rule, &case.data, backend, DEFAULT_MAX_MATCHES)
        .expect("gpu counts");
    assert_eq!(
        cpu_counts, gpu_counts,
        "count divergence on `{label}`: CPU={cpu_counts:?}, GPU={gpu_counts:?}"
    );
}

/// Fast on-device smoke gate: literal patterns run with full verdict + count parity vs the CPU
/// walk and yara-x. The full lowering surface (hex/regex/wide/xor/base64/…) is covered by
/// [`gpu_parity_all_shapes`]; this is the quick subset for a fast GPU-path signal.
#[test]
fn gpu_parity_literals() {
    let backend = acquire();
    for case in literal_cases() {
        assert_full_parity(&backend, &case);
    }
}

/// The vyre substrate-block signature: shapes whose NFA-scan shader fails naga validation
/// (`InvalidStoreTypes` / `Entry point main at Compute is invalid`). Distinguishes an upstream
/// vyre codegen bug from a real rulec fault (any *other* error fails the gate).
fn is_vyre_codegen_block(err: &str) -> bool {
    err.contains("Entry point main at Compute is invalid")
        || err.contains("InvalidStoreTypes")
        || err.contains("target builder validation failed")
}

/// FULL on-device surface across every lowering shape: text, nocase, hex (literal/wildcard/jump/
/// alternation), regex, wide, any/all-of, counts, filesize, boolean, quantifiers, xor (bounded +
/// bare 256-key), base64 at every alignment. Each shape is asserted GPU == CPU == yara-x with
/// per-pattern count parity. This is the load-bearing executor-parity gate for warpscan's GPU
/// malware-scan path.
///
/// Previously `#[ignore]`d behind two vyre NFA-scan substrate bugs (both fixed):
/// (1) `InvalidStoreTypes` naga-validation failure on `num_states == 4`: fixed by the
/// block-scoped-local type-staleness guard in `vyre-emit-naga`; (2) a multi-minute lowering
/// "hang" on the 771-state bare-`xor` pipeline, root-caused to an O(n²) descriptor-optimizer
/// pass triggered by the NFA-scan shader unrolling O(num_states) ops, fixed by making the
/// transition + epsilon gather data-driven (runtime bit-loop) so the shader is O(1) in state
/// count. If any shape now reports a codegen block, that is a REGRESSION, not an expected gap.
#[test]
fn gpu_parity_all_shapes() {
    let backend = acquire();
    let mut proven: Vec<String> = Vec::new();
    let mut blocked: Vec<String> = Vec::new();

    for case in cases() {
        let compiled = rulec::compile(case.src.as_bytes())
            .unwrap_or_else(|e| panic!("rulec failed to lower `{}`: {e}", case.rule));
        let rule = lower(&compiled, case.rule);
        let label = format!("{} / {:?}", case.rule, case.data);
        let cpu = verdict(rule, &case.data)
            .unwrap_or_else(|e| panic!("CPU verdict failed for `{label}`: {e}"));

        match verdict_on(rule, &case.data, &backend, DEFAULT_MAX_MATCHES) {
            Ok(gpu) => {
                common::assert_agrees("GPU-vyre", case.src, case.rule, &case.data, case.expect, gpu);
                assert_eq!(gpu, cpu, "executor divergence on `{label}`: GPU={gpu}, CPU={cpu}");
                let cpu_counts = pattern_counts(rule, &case.data).expect("cpu counts");
                let gpu_counts = pattern_counts_on(rule, &case.data, &backend, DEFAULT_MAX_MATCHES)
                    .expect("gpu counts");
                assert_eq!(
                    cpu_counts, gpu_counts,
                    "count divergence on `{label}`: CPU={cpu_counts:?}, GPU={gpu_counts:?}"
                );
                proven.push(label);
            }
            Err(e) => {
                // The vyre substrate is fixed: every shape must dispatch. A codegen block here
                // is a REGRESSION (the `is_vyre_codegen_block` classifier just sharpens the
                // message (codegen regression vs a genuine rulec fault). Either way, fail).
                let msg = e.to_string();
                let kind = if is_vyre_codegen_block(&msg) {
                    "a vyre NFA-scan codegen REGRESSION (InvalidStoreTypes / validation failure. \
                     the substrate fix has been undone)"
                } else {
                    "a rulec dispatch fault"
                };
                blocked.push(format!("{label}: {msg}"));
                panic!("`{label}` failed GPU dispatch: {kind}: {msg}");
            }
        }
    }

    eprintln!(
        "GPU full-surface: {} proven (GPU==CPU==yara-x), {} blocked.\n  proven: {proven:?}",
        proven.len(),
        blocked.len(),
    );
    assert!(!proven.is_empty(), "no shape achieved GPU parity, on-device path fully broken");
    assert!(
        blocked.is_empty(),
        "every lowering shape must dispatch on-device now that the vyre substrate is fixed; \
         blocked: {blocked:?}"
    );
}

/// The combined resident scanner ([`CompiledRuleSet`]) folds every rule into ONE byte-NFA and
/// evaluates them all from a single dispatch. It MUST give each rule the same verdict as the
/// single-rule [`verdict_on`], and, because patterns share one global id space, a haystack
/// matching one rule must never bleed into another (correct per-rule base offsetting). The
/// rule set mixes presence, multi-pattern all-of, a count threshold, and filesize so the base
/// offsets and the local→global count slicing are exercised, not just single-pattern rules.
#[test]
fn combined_resident_scanner_matches_per_rule() {
    let backend = acquire();
    let src = r#"
        rule alpha { strings: $a = "cmd.exe" condition: $a }
        rule beta  { strings: $b = "foo" $c = "bar" condition: all of them }
        rule gamma { strings: $d = "ab" condition: #d >= 3 }
        rule delta { strings: $e = { 4D 5A } condition: $e and filesize < 16 }
    "#;
    let compiled = rulec::compile(src.as_bytes()).expect("lower combined rules");
    let cap = 4096;
    let set = CompiledRuleSet::compile(&compiled.rules, cap).expect("combine into one byte-NFA");
    assert_eq!(set.len(), 4);
    let session = set
        .prepare_session(&backend, cap, DEFAULT_MAX_MATCHES)
        .expect("prepare resident session");

    let haystacks: &[&[u8]] = &[
        b"run cmd.exe now",
        b"foo and bar",
        b"abababx",
        b"\x4D\x5A\x90\x00",
        b"cmd.exe foo bar ababab \x4D\x5A",
        b"nothing relevant here at all",
    ];

    for data in haystacks {
        // Oracle: the proven single-rule on-device verdict, per rule.
        let mut expected: Vec<&str> = compiled
            .rules
            .iter()
            .filter(|r| {
                verdict_on(r, data, &backend, DEFAULT_MAX_MATCHES).expect("per-rule verdict")
            })
            .map(|r| r.name.as_str())
            .collect();
        // Combined: one dispatch → fired indices → names.
        let mut got: Vec<&str> = set
            .scan_fired(&session, &backend, data)
            .expect("combined scan")
            .into_iter()
            .map(|i| set.rule_name(i).expect("fired index has a name"))
            .collect();
        expected.sort_unstable();
        got.sort_unstable();
        assert_eq!(
            got, expected,
            "combined scanner diverged from per-rule verdict on {:?}",
            String::from_utf8_lossy(data)
        );
    }
}

/// A rule set too large for one byte-NFA must split into multiple shards and still route
/// each finding to the right rule (cross-shard correctness + per-shard base offsetting).
/// Builds many long-literal rules so the combined NFA exceeds vyre's per-subgroup state cap.
#[test]
fn compiled_rule_set_shards_large_corpus_and_routes_each_rule() {
    let backend = acquire();

    // 60 rules, each a unique ~50-byte literal → ~3000 NFA states ≫ the per-subgroup cap,
    // forcing several shards.
    let n: usize = 60;
    let mut src = String::new();
    let mut needles: Vec<Vec<u8>> = Vec::with_capacity(n);
    for i in 0..n {
        let lit = format!("NEEDLE_{i:03}_{}", "x".repeat(40));
        src.push_str(&format!("rule r{i} {{ strings: $a = \"{lit}\" condition: $a }}\n"));
        needles.push(lit.into_bytes());
    }

    let cap = 65_536;
    let set = CompiledRuleSet::compile(
        &rulec::compile(src.as_bytes()).expect("lower many rules").rules,
        cap,
    )
    .expect("pack into shards");
    assert_eq!(set.len(), n);
    assert!(
        set.shard_count() > 1,
        "corpus should exceed one shard; got {} shard(s)",
        set.shard_count()
    );
    let session = set
        .prepare_session(&backend, cap, DEFAULT_MAX_MATCHES)
        .expect("prepare resident session");

    // Each needle in isolation must fire exactly its own rule, across whichever shard it
    // landed in.
    for k in [0usize, 1, n / 2, n - 2, n - 1] {
        let mut data = b"prefix junk ".to_vec();
        data.extend_from_slice(&needles[k]);
        data.extend_from_slice(b" suffix junk");
        let mut names: Vec<String> = set
            .scan_fired(&session, &backend, &data)
            .expect("scan")
            .into_iter()
            .map(|i| set.rule_name(i).expect("name").to_string())
            .collect();
        names.sort();
        assert_eq!(names, vec![format!("r{k}")], "needle {k} must fire only r{k}");
    }

    // Two needles from opposite ends of the corpus (different shards) both fire.
    let mut both = needles[0].clone();
    both.extend_from_slice(b" --- ");
    both.extend_from_slice(&needles[n - 1]);
    let mut names: Vec<String> = set
        .scan_fired(&session, &backend, &both)
        .expect("scan two")
        .into_iter()
        .map(|i| set.rule_name(i).expect("name").to_string())
        .collect();
    names.sort();
    assert_eq!(names, vec!["r0".to_string(), format!("r{}", n - 1)]);
}
