//! Helper synthesis logic for differential testing probe buffers.

use crate::{LoweredRule, PatKind};

pub(crate) const MAX_BRUTE_FORCE_ATTEMPTS: usize = 50_000;

/// Try to synthesise a short byte buffer that matches `regex`.
pub(crate) fn synthesize_regex_match(regex: &str, nocase: bool) -> Option<Vec<u8>> {
    let pattern = if nocase {
        format!("(?i){regex}")
    } else {
        regex.to_string()
    };
    let re = regex::bytes::Regex::new(&pattern).ok()?;

    let mut heuristic: Vec<u8> = regex
        .trim_start_matches('^')
        .trim_end_matches('$')
        .bytes()
        .map(|b| if b.is_ascii_alphanumeric() { b } else { b'0' })
        .collect();
    while !heuristic.is_empty() && !re.is_match(&heuristic) {
        heuristic.pop();
    }
    if !heuristic.is_empty() && re.is_match(&heuristic) {
        return Some(heuristic);
    }

    let alphabet: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut attempts = 0usize;
    for len in 1..=5 {
        let mut buf = vec![alphabet[0]; len];
        attempts += 1;
        if re.is_match(&buf) {
            return Some(buf);
        }
        while next_regex_candidate(&mut buf, alphabet) {
            attempts += 1;
            if attempts > MAX_BRUTE_FORCE_ATTEMPTS {
                return None;
            }
            if re.is_match(&buf) {
                return Some(buf);
            }
        }
    }
    None
}

fn next_regex_candidate(buf: &mut [u8], alphabet: &[u8]) -> bool {
    for i in (0..buf.len()).rev() {
        let pos = alphabet.iter().position(|&b| b == buf[i]).unwrap();
        if pos + 1 < alphabet.len() {
            buf[i] = alphabet[pos + 1];
            for j in i + 1..buf.len() {
                buf[j] = alphabet[0];
            }
            return true;
        }
        buf[i] = alphabet[0];
    }
    false
}

/// Concatenate every literal (Text/Hex) pattern's bytes with separators.
pub(crate) fn all_literals_buffer(rule: &LoweredRule) -> Vec<u8> {
    let mut buf = Vec::new();
    for p in &rule.patterns {
        match &p.kind {
            PatKind::Text(b) | PatKind::Hex(b) => {
                buf.extend_from_slice(b);
                buf.extend_from_slice(b"\x00__SEP__\x00");
            }
            PatKind::Regex(_) => {}
        }
    }
    if buf.is_empty() {
        buf.extend_from_slice(b"placeholder");
    }
    buf
}

/// Concatenate literal/hex pattern bytes and synthesised matching input for regexes.
pub(crate) fn all_patterns_buffer(rule: &LoweredRule) -> Vec<u8> {
    let mut buf = Vec::new();
    for p in &rule.patterns {
        match &p.kind {
            PatKind::Text(b) | PatKind::Hex(b) => {
                buf.extend_from_slice(b);
                buf.extend_from_slice(b"\x00__SEP__\x00");
            }
            PatKind::Regex(src) => {
                if let Some(sample) = synthesize_regex_match(src, p.nocase) {
                    buf.extend_from_slice(&sample);
                } else {
                    buf.extend_from_slice(src.as_bytes());
                }
                buf.extend_from_slice(b"\x00__SEP__\x00");
            }
        }
    }
    if buf.is_empty() {
        buf.extend_from_slice(b"placeholder");
    }
    buf
}
