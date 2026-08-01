//! Shared test helpers for the differential gates. Compiled into each integration test
//! binary that declares `mod common;` (the `tests/common/mod.rs` form keeps it from being
//! treated as its own test target).

/// Ground truth: does the named rule match `data` under yara-x's own engine?
pub fn yara_x_verdict(src: &str, data: &[u8], rule_name: &str) -> bool {
    let mut compiler = yara_x::Compiler::new();
    compiler
        .add_source(src)
        .unwrap_or_else(|e| panic!("yara-x rejected source for `{rule_name}`: {e}"));
    let rules = compiler.build();
    let mut scanner = yara_x::Scanner::new(&rules);
    let results = scanner
        .scan(data)
        .unwrap_or_else(|e| panic!("yara-x scan failed for `{rule_name}`: {e}"));
    results.matching_rules().any(|r| r.identifier() == rule_name)
}

/// Independent standard-base64 encoder, the differential REFERENCE for `base64` tests, not
/// the code under test. Building probe buffers from a real encoding (rather than a recalled
/// constant) lets yara-x judge ground truth; our lowering must then agree on the same bytes.
#[must_use]
pub fn b64(data: &[u8]) -> Vec<u8> {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        out.push(A[((n >> 18) & 0x3f) as usize]);
        out.push(A[((n >> 12) & 0x3f) as usize]);
        out.push(if c.len() > 1 { A[((n >> 6) & 0x3f) as usize] } else { b'=' });
        out.push(if c.len() > 2 { A[(n & 0x3f) as usize] } else { b'=' });
    }
    out
}

/// Assert the fixture lands where it claims under yara-x (proving a real outcome, not
/// agreement-on-nothing), then that `ours` matches yara-x. `engine` labels the divergence.
pub fn assert_agrees(engine: &str, src: &str, rule: &str, data: &[u8], expect: bool, ours: bool) {
    let theirs = yara_x_verdict(src, data, rule);
    assert_eq!(
        theirs, expect,
        "fixture wrong: yara-x verdict for `{rule}` on {data:?} was {theirs}, fixture said {expect}"
    );
    assert_eq!(
        ours, theirs,
        "{engine} DIVERGENCE: `{rule}` on {data:?}, ours={ours}, yara-x={theirs}"
    );
}
