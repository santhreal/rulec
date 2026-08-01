//! Regression guard for the data-driven NFA-scan shader (task #17).
//!
//! The vyre-libs NFA-scan shader emits the inner per-bit walk of its lane-major transition +
//! epsilon gather as a runtime bit-`loop_for` rather than unrolling 32 `if_then` nodes per peer
//! lane. The per-lane (`k`) loop stays unrolled: `subgroup_shuffle` needs a compile-time peer
//! lane (so the shader still emits one gather block per peer lane that owns live states, i.e).
//! `ceil(num_states / LANES)` blocks. Net scaling is therefore **O(num_states / 32)** (bounded at
//! 32 blocks, since `num_states <= MAX_STATES_PER_SUBGROUP = 1024`), versus the old form's
//! **O(num_states)** from also unrolling the 32 inner bit positions.
//!
//! That ~32x slope reduction is what matters: the old unrolled form grew the shader ~4.7 KB per
//! state and, worse, fed an O(n²) descriptor optimizer in `vyre-lower` that turned a 771-state
//! bare-`xor` pipeline into a multi-minute "GPU hang" before any dispatch.
//!
//! This test lowers single-accept patterns of growing state count (so the still-unrolled accept
//! region, one node per accept state, is held at one accept and cannot mask a regression) and
//! asserts the WGSL grows at the reduced O(num_states/32) slope, not the old per-state slope. If
//! the inner bit-unroll is reintroduced, the slope jumps ~32x and this fails. Correctness across
//! every shape is covered by `gpu_parity.rs`; this guards the *size/scaling* property.
//!
//! Run: `cargo test --features gpu,differential --test nfa_shader_scaling`

#![cfg(feature = "gpu")]

use vyre_driver_wgpu::emit;
use vyre_libs::scan::build_rule_pipeline_from_regex;

/// `\xNN` regex chain for an `n`-byte literal (one pattern, one accept state, `n+`-ish states).
fn nbyte_regex(n: usize) -> String {
    (0..n).map(|i| format!(r"\x{:02x}", 0x41 + (i % 26) as u8)).collect()
}

/// Lower the single-pattern NFA-scan pipeline for `regex` and return `(num_states, wgsl_len)`.
fn lower_size(regex: &str) -> (u32, usize) {
    let pipeline = build_rule_pipeline_from_regex(&[regex], "input", "hits", 64)
        .unwrap_or_else(|e| panic!("pipeline build failed for {regex:?}: {e}"));
    let states = pipeline.plan.num_states;
    let wgsl = emit::lower(&pipeline.program)
        .unwrap_or_else(|e| panic!("WGSL lowering failed at num_states={states}: {e:?}"));
    (states, wgsl.len())
}

#[test]
fn nfa_scan_shader_size_is_flat_in_state_count() {
    // 1 byte (3 states) through 200 bytes (~200 states), single accept throughout.
    let sizes: Vec<(u32, usize)> = [1usize, 8, 50, 100, 200]
        .iter()
        .map(|&n| lower_size(&nbyte_regex(n)))
        .collect();

    // Sanity: state count really does grow across the sample (so flatness is meaningful).
    let max_states = sizes.iter().map(|(s, _)| *s).max().unwrap();
    let min_states = sizes.iter().map(|(s, _)| *s).min().unwrap();
    assert!(
        max_states >= min_states + 150,
        "state count did not grow across the sample (min={min_states}, max={max_states}); \
         the flatness assertion below would be vacuous"
    );

    // The load-bearing property: WGSL must grow at the reduced O(num_states / LANES) slope (one
    // gather block per peer lane), NOT the old O(num_states) slope (also unrolling 32 inner bit
    // positions). We bound the bytes-per-state slope: the current data-driven form measures
    // ~480 B/state; the old inner-bit unroll measured ~4700 B/state. A threshold of 1500 B/state
    // sits ~3x above the data-driven form and ~3x below the unrolled form, so it catches a
    // reintroduced bit-unroll without being flaky on emitter constant-factor drift.
    let min_wgsl = sizes.iter().map(|(_, w)| *w).min().unwrap();
    let max_wgsl = sizes.iter().map(|(_, w)| *w).max().unwrap();
    let slope = (max_wgsl - min_wgsl) as f64 / (max_states - min_states) as f64;
    assert!(
        slope < 1500.0,
        "NFA-scan shader WGSL grew ~{slope:.0} bytes/state, an inner-bit per-state unrolling \
         regression (data-driven form is ~480 B/state, old unroll ~4700 B/state). \
         sizes (num_states, wgsl_bytes) = {sizes:?}. \
         Fix: keep the inner bit walk a runtime loop (push_lane_major_gather), not a per-bit unroll."
    );
}
