//! Lower the `strings:` section: text / hex / regex patterns and their modifiers into
//! [`PatKind`]. Hex wildcards/jumps/alternatives/not-bytes, the `wide` modifier, and the
//! `xor` / `base64` / `base64wide` modifiers all become equivalent byte-regexes (every
//! literal byte a `\xNN` escape, so no metacharacter leaks) over vyre's supported syntax
//! (`Literal` + `Alternation`, no look-around); plain literals keep the fast path. The
//! pure byte→variant transforms live in [`super::transforms`]. Modifiers with no faithful
//! lowering onto live vyre (`fullword`, and illegal combinations) reject LOUDLY.

use yara_x_parser::ast::{HexSubPattern, HexToken, Pattern, PatternModifier};

use super::transforms::{
    alternation, base64_variants, literal_regex, widen, xor_variants, STANDARD_B64_ALPHABET,
};
use super::{reject, strip_sigil, LowerError, LoweredPattern, PatKind};

impl LoweredPattern {
    /// This pattern as a single byte-oriented regex string, every literal byte rendered
    /// as a `\xNN` escape so no regex metacharacter leaks. Text/Hex literals become exact
    /// byte sequences; wildcard-hex, wide, xor and base64 patterns are already regex; a
    /// `/re/` passes through. `nocase` becomes a leading `(?i)`. This is the uniform form
    /// vyre's byte-mode regex frontend (`compile_regex_set`, `unicode(false).utf8(false)`)
    /// scans.
    #[must_use]
    pub fn to_byte_regex(&self) -> String {
        let body = match &self.kind {
            PatKind::Text(b) | PatKind::Hex(b) => literal_regex(b),
            PatKind::Regex(src) => src.clone(),
        };
        if self.nocase {
            format!("(?i){body}")
        } else {
            body
        }
    }
}

/// Parsed string modifiers. `ascii`/`wide` select which encodings of the literal match
/// (YARA default = ascii only). `xor` carries its inclusive key range; `base64`/
/// `base64wide` carry an optional custom 64-byte alphabet.
#[derive(Default)]
struct Mods {
    nocase: bool,
    wide: bool,
    ascii: bool,
    /// `xor` key range `start..=end` (bare `xor` → `0x00..=0xff`).
    xor: Option<(u8, u8)>,
    /// `base64` present, with its alphabet (`None` → the standard alphabet).
    base64: Option<[u8; 64]>,
    /// `base64wide` present, with its alphabet.
    base64wide: Option<[u8; 64]>,
}

fn read_mods(mods: &yara_x_parser::ast::PatternModifiers<'_>) -> Result<Mods, LowerError> {
    let mut m = Mods::default();
    for tok in mods.iter() {
        match tok {
            PatternModifier::Nocase { .. } => m.nocase = true,
            PatternModifier::Wide { .. } => m.wide = true,
            PatternModifier::Ascii { .. } => m.ascii = true,
            // `private` only affects reporting, not matching.
            PatternModifier::Private { .. } => {}
            PatternModifier::Xor { start, end, .. } => m.xor = Some((*start, *end)),
            PatternModifier::Base64 { alphabet, .. } => m.base64 = Some(read_alphabet(alphabet.as_ref())?),
            PatternModifier::Base64Wide { alphabet, .. } => {
                m.base64wide = Some(read_alphabet(alphabet.as_ref())?);
            }
            PatternModifier::Fullword { .. } => return Err(reject_fullword()),
        }
    }
    // YARA default when neither encoding is named: ascii.
    if !m.wide && !m.ascii {
        m.ascii = true;
    }
    Ok(m)
}

/// Resolve a base64 alphabet: the custom 64-byte set if given, else the standard alphabet.
fn read_alphabet(
    alphabet: Option<&yara_x_parser::ast::LiteralString<'_>>,
) -> Result<[u8; 64], LowerError> {
    let Some(lit) = alphabet else {
        return Ok(*STANDARD_B64_ALPHABET);
    };
    let bytes: Vec<u8> = lit.value.iter().copied().collect();
    <[u8; 64]>::try_from(bytes.as_slice()).map_err(|_| {
        reject(
            "base64 custom alphabet",
            "a base64 alphabet must be exactly 64 bytes",
            "give a 64-character alphabet (YARA requires this too)",
        )
    })
}

pub(super) fn lower_pattern(pat: &Pattern<'_>, id: u32) -> Result<LoweredPattern, LowerError> {
    match pat {
        Pattern::Text(t) => {
            let m = read_mods(&t.modifiers)?;
            let bytes: Vec<u8> = t.text.value.iter().copied().collect();
            let kind = lower_text_kind(&bytes, &m)?;
            Ok(LoweredPattern {
                id,
                name: strip_sigil(t.identifier.name).to_string(),
                kind,
                // base64 / xor produce concrete byte variants; `nocase` is rejected for
                // those combos, so a `(?i)` would never be wanted there.
                nocase: m.nocase && m.base64.is_none() && m.base64wide.is_none() && m.xor.is_none(),
            })
        }
        Pattern::Regexp(r) => {
            let m = read_mods(&r.modifiers)?;
            reject_text_only_mods(&m, "regex")?;
            if m.wide {
                return Err(reject(
                    "`wide` modifier on a regex string",
                    "widening a regex (interleaving 0x00 through classes/quantifiers) is not \
                     a simple byte transform",
                    "P3 roadmap: regex-widen transform via vyre::scan::regex_dfa; for now keep \
                     the regex ascii or pre-widen it",
                ));
            }
            Ok(LoweredPattern {
                id,
                name: strip_sigil(r.identifier.name).to_string(),
                kind: PatKind::Regex(r.regexp.src.to_string()),
                nocase: m.nocase,
            })
        }
        Pattern::Hex(h) => {
            let m = read_mods(&h.modifiers)?;
            reject_text_only_mods(&m, "hex")?;
            if m.wide {
                return Err(reject(
                    "`wide` modifier on a hex string",
                    "widening a hex pattern (interleaving 0x00 through wildcards/jumps) is not \
                     a simple byte transform",
                    "P3 roadmap: hex-widen transform via vyre::scan::regex_dfa",
                ));
            }
            // Plain `{ 4D 5A }` stays a literal (the fast AC path); any wildcard / jump /
            // alternative / not-byte lowers to an equivalent byte-regex (vyre::scan::regex_dfa)
            //: faithful, and proven against yara-x by the differential gate.
            let kind = match plain_hex_bytes(h) {
                Some(bytes) => PatKind::Hex(bytes),
                None => PatKind::Regex(hex_sub_to_regex(&h.sub_patterns)),
            };
            Ok(LoweredPattern {
                id,
                name: strip_sigil(h.identifier.name).to_string(),
                kind,
                nocase: m.nocase,
            })
        }
    }
}

/// Decide the matcher for a text string from its bytes + modifiers. base64 and xor produce
/// an alternation of concrete byte variants; otherwise the ascii/`wide` encodings (a plain
/// literal when only one encoding applies, else an alternation).
fn lower_text_kind(bytes: &[u8], m: &Mods) -> Result<PatKind, LowerError> {
    // base64 / base64wide: the encoded text (optionally widened) is what appears on disk.
    if m.base64.is_some() || m.base64wide.is_some() {
        if m.xor.is_some() || m.nocase {
            return Err(reject(
                "`base64` combined with `xor`/`nocase`",
                "YARA forbids these combinations (the encodings are byte-exact)",
                "drop `xor`/`nocase`; use `base64` (or `base64wide`) on its own",
            ));
        }
        let mut variants = Vec::new();
        if let Some(alph) = &m.base64 {
            variants.extend(base64_variants(bytes, alph));
        }
        if let Some(alph) = &m.base64wide {
            for v in base64_variants(bytes, alph) {
                variants.push(widen(&v));
            }
        }
        if variants.is_empty() {
            return Err(reject(
                "`base64` on an empty / too-short string",
                "no stable base64 characters survive the alignment strip",
                "base64-match a longer literal",
            ));
        }
        return Ok(PatKind::Regex(alternation(&variants)));
    }

    // xor: every uniform single-byte-key XOR of the ascii and/or wide encodings.
    if let Some((start, end)) = m.xor {
        if m.nocase {
            return Err(reject(
                "`xor` combined with `nocase`",
                "YARA forbids `xor nocase` (the XORed bytes are exact)",
                "drop `nocase`; `xor` already enumerates the key range",
            ));
        }
        let forms = encodings(bytes, m);
        let variants = xor_variants(&forms, start, end);
        return Ok(PatKind::Regex(alternation(&variants)));
    }

    // Plain text: one literal per requested encoding.
    let forms = encodings(bytes, m);
    Ok(if forms.len() == 1 {
        PatKind::Text(forms.into_iter().next().unwrap_or_else(|| {
            // `encodings` always yields at least one form because `read_mods`
            // defaults to ascii, so this arm is genuinely unreachable.
            unreachable!("encodings guarantees >=1 form")
        }))
    } else {
        PatKind::Regex(alternation(&forms))
    })
}

/// The requested byte encodings of `bytes`: ascii (raw) and/or `wide` (UTF-16LE). At least
/// one is always present (`read_mods` defaults to ascii).
fn encodings(bytes: &[u8], m: &Mods) -> Vec<Vec<u8>> {
    let mut forms = Vec::new();
    if m.ascii {
        forms.push(bytes.to_vec());
    }
    if m.wide {
        forms.push(widen(bytes));
    }
    forms
}

/// Reject the text-only modifiers (`xor`/`base64`/`base64wide`) when they appear on a hex
/// or regex string, where YARA does not allow them (and there is no faithful lowering).
fn reject_text_only_mods(m: &Mods, kind: &str) -> Result<(), LowerError> {
    if m.xor.is_some() || m.base64.is_some() || m.base64wide.is_some() {
        return Err(reject(
            format!("`xor`/`base64` modifier on a {kind} string"),
            "these modifiers apply only to text strings in YARA",
            "move the bytes into a text string, or drop the modifier",
        ));
    }
    Ok(())
}

/// The loud, precise rejection for `fullword`: the single most common unsupported modifier
/// in real corpora. Its faithful lowering is a zero-width ASCII word-boundary assertion,
/// which vyre's regex frontend does not yet carry; this names the exact equivalent and the
/// exact vyre op to add (never a silent or unsound approximation).
fn reject_fullword() -> LowerError {
    reject(
        "`fullword` modifier",
        "fullword means the bytes adjacent to the match are not `[0-9A-Za-z_]`; the faithful \
         zero-width encoding wraps the pattern with `\\b` when its edge byte is a word char \
         and `\\B` when it is not. vyre's regex frontend (vyre-libs/src/scan/regex_compile.rs) \
         supports only `^`/`$` look-around (Look::Start/End) and rejects Look::WordAscii / \
         Look::WordAsciiNegate, so there is no faithful lowering onto live vyre yet, and \
         consuming a boundary byte instead would corrupt match counts and buffer-edge cases",
        "vyre op: add ASCII word-boundary (\\b = Look::WordAscii, \\B = Look::WordAsciiNegate) \
         to regex_compile.rs::build_hir and the NFA executor; rulec then wraps the \
         pattern with \\b/\\B per edge byte",
    )
}

/// `Some(bytes)` iff the hex pattern is entirely plain full-mask bytes (no wildcards,
/// jumps, alternatives, or not-bytes) (the literal fast path. `None` otherwise).
fn plain_hex_bytes(h: &yara_x_parser::ast::HexPattern<'_>) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    for tok in h.sub_patterns.iter() {
        match tok {
            HexToken::Byte(b) if b.mask == 0xFF => bytes.push(b.value),
            _ => return None,
        }
    }
    Some(bytes)
}

/// Translate a hex sub-pattern token sequence into an equivalent unanchored byte-regex
/// (every byte emitted as `\xNN`, so no regex metacharacter ever leaks). YARA hex
/// semantics: wildcard nibbles → byte class, `??` → any byte, `[n-m]` → bounded any-byte
/// repetition, `( .. | .. )` → alternation, `~XX` → negated byte class.
fn hex_sub_to_regex(sub: &HexSubPattern) -> String {
    let mut out = String::new();
    for tok in sub.iter() {
        match tok {
            HexToken::Byte(b) => out.push_str(&masked_byte_class(b.value, b.mask, false)),
            HexToken::NotByte(b) => out.push_str(&masked_byte_class(b.value, b.mask, true)),
            HexToken::Jump(j) => out.push_str(&jump_regex(j.start, j.end)),
            HexToken::Alternative(alt) => {
                let parts: Vec<String> = alt.alternatives.iter().map(hex_sub_to_regex).collect();
                out.push_str("(?:");
                out.push_str(&parts.join("|"));
                out.push(')');
            }
        }
    }
    out
}

/// Byte matcher for `(b & mask) == (value & mask)` (or its negation when `negate`).
/// `mask == 0xFF` → a single `\xNN`; otherwise a `[...]` / `[^...]` class.
fn masked_byte_class(value: u8, mask: u8, negate: bool) -> String {
    use std::fmt::Write as _;
    if mask == 0xFF && !negate {
        return format!("\\x{value:02x}");
    }
    if mask == 0x00 {
        // Any byte matches the predicate; negation matches nothing.
        return if negate {
            "[^\\x00-\\xff]".into()
        } else {
            "[\\x00-\\xff]".into()
        };
    }
    let mut s = String::from(if negate { "[^" } else { "[" });
    for b in 0u8..=u8::MAX {
        if (b & mask) == (value & mask) {
            let _ = write!(s, "\\x{b:02x}");
        }
    }
    s.push(']');
    s
}

/// `[n-m]` style jump → bounded repetition of any byte.
fn jump_regex(start: Option<u32>, end: Option<u32>) -> String {
    let any = "[\\x00-\\xff]";
    match (start, end) {
        (Some(a), Some(b)) if a == b => format!("{any}{{{a}}}"),
        (Some(a), Some(b)) => format!("{any}{{{a},{b}}}"),
        (Some(a), None) => format!("{any}{{{a},}}"),
        (None, Some(b)) => format!("{any}{{0,{b}}}"),
        (None, None) => format!("{any}*"),
    }
}
