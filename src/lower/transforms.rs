//! Pure byte → variant → byte-regex transforms shared by the `strings:` lowering
//! ([`super::patterns`]). Every transform turns one declared literal into the concrete
//! byte forms YARA would match, then renders them as a byte-regex (each literal byte a
//! `\xNN` escape, so no metacharacter ever leaks). These are the *faithful equivalents*
//! that let `wide` / `xor` / `base64` lower onto vyre's actual supported regex syntax
//! (`Literal` + `Alternation`, no look-around) (proven against `yara_x::Scanner`).

use std::collections::BTreeSet;
use std::fmt::Write as _;

/// The standard RFC 4648 base64 alphabet (YARA's default when `base64` has no custom set).
pub(super) const STANDARD_B64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// UTF-16LE of an ASCII/byte literal: a `0x00` after each byte (the `wide` transform).
#[must_use]
pub(super) fn widen(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(b);
        out.push(0);
    }
    out
}

/// A literal byte string as a regex fragment, every byte a `\xNN` escape (no metachar leak).
#[must_use]
pub(super) fn literal_regex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 4);
    for &b in bytes {
        let _ = write!(s, "\\x{b:02x}");
    }
    s
}

/// Render a set of literal byte-string variants as one unanchored byte-regex alternation
/// `(?:v0|v1|…)`. Identical variants collapse (a `BTreeSet` both dedups and orders the
/// output deterministically, so the emitted `.srg` is stable). A single variant still
/// wraps in `(?:…)`: harmless and keeps the caller uniform.
#[must_use]
pub(super) fn alternation(variants: &[Vec<u8>]) -> String {
    let unique: BTreeSet<&Vec<u8>> = variants.iter().collect();
    let mut s = String::from("(?:");
    for (i, v) in unique.iter().enumerate() {
        if i > 0 {
            s.push('|');
        }
        s.push_str(&literal_regex(v));
    }
    s.push(')');
    s
}

/// Every uniform single-byte-XOR variant of each `form`, for keys `start..=end` (YARA's
/// `xor` modifier; bare `xor` = `0x00..=0xff`, so the `k == 0` identity = the plaintext is
/// included). The same key applies to all bytes, so the variants cannot be expressed as a
/// product of per-position byte classes, only an explicit alternation of concrete byte
/// strings is faithful. `forms` carries the ascii and/or `wide` encodings to XOR.
#[must_use]
pub(super) fn xor_variants(forms: &[Vec<u8>], start: u8, end: u8) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for form in forms {
        for k in start..=end {
            out.push(form.iter().map(|&b| b ^ k).collect());
        }
    }
    out
}

/// The three base64 alignment-encodings of `s` under `alphabet` (YARA's `base64` modifier).
///
/// A base64-encoded blob containing `s` can begin at any of three byte offsets within a
/// 3-byte encoding group, so YARA emits one pattern per offset `p ∈ {0,1,2}`: prepend `p`
/// filler bytes, pad the tail to a multiple of 3, encode, then drop the leading/trailing
/// characters whose bits come from filler (`STRIP[p]` leading, `STRIP[q]` trailing, where
/// `q` is the trailing-filler count). The surviving characters are independent of the
/// filler *values*, so any filler works, we use `0x00`. (Verified against yara-x: the
/// three alignments of `"This program cannot"` reproduce its documented encodings.)
#[must_use]
pub(super) fn base64_variants(s: &[u8], alphabet: &[u8; 64]) -> Vec<Vec<u8>> {
    // Characters to strip given a filler-byte count of 0/1/2: a filler byte is 8 bits and a
    // base64 char is 6, so `ceil(8*n/6)` chars are (partly) filler-determined → 0,2,3.
    const STRIP: [usize; 3] = [0, 2, 3];

    let mut out = Vec::with_capacity(3);
    for (p, &lead) in STRIP.iter().enumerate() {
        let total_real = p + s.len();
        let q = (3 - total_real % 3) % 3; // trailing filler to reach a multiple of 3
        let mut buf = vec![0u8; p];
        buf.extend_from_slice(s);
        buf.extend(std::iter::repeat_n(0u8, q));

        let enc = base64_encode(&buf, alphabet); // buf.len() is a multiple of 3 → no `=` pad
        let trail = STRIP[q];
        if lead + trail < enc.len() {
            out.push(enc[lead..enc.len() - trail].to_vec());
        }
    }
    out
}

/// Base64-encode `data` (whose length MUST be a multiple of 3) with `alphabet`, emitting no
/// `=` padding. Internal to [`base64_variants`], which always pads the input length first.
#[must_use]
fn base64_encode(data: &[u8], alphabet: &[u8; 64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() / 3 * 4);
    for chunk in data.chunks_exact(3) {
        let n = (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);
        out.push(alphabet[((n >> 18) & 0x3f) as usize]);
        out.push(alphabet[((n >> 12) & 0x3f) as usize]);
        out.push(alphabet[((n >> 6) & 0x3f) as usize]);
        out.push(alphabet[(n & 0x3f) as usize]);
    }
    out
}
