# P0: the byte-match `.srg` surface (what YARA compiles *into*)

This is the contract `rulec` emits and that surge must accept for YARA to compile
one-way into the surge language. It is a **proposal**: the *semantics* and the *vyre
mapping* are fixed (they must match YARA + the live `vyre::rule`/`scan` API); the
*concrete syntax* is adjustable to fit surge's grammar during the rewrite.

surge today is dataflow/signal-shaped (`flows_to`, `taint_flow`) over a source
ProgramGraph. Byte scanning needs two additions, both already latent in the stack:
1. a **raw-bytes input mode** (scan a file's bytes, not a parsed graph), and
2. **byte-pattern bindings + presence/count/filesize conditions**, realized as
   ExternCall (CAP-2) to `vyre::scan`: surge already has ExternCall + a `lexer_regex`.

## Proposed syntax

```srg
rule yara_suspicious_pe {
    input = bytes                       // raw-bytes mode (vs default source-graph)
    tags = ["yara"]

    // Pattern bindings → the scan stage. Each returns a pattern handle.
    let $mz  = vyre.scan.hex.v1(value: "4D 5A")
    let $pe  = vyre.scan.text.v1(value: "PE\x00\x00")
    let $cmd = vyre.scan.text.v1(value: "cmd.exe", nocase: true, ascii: true)
    let $re  = vyre.scan.regex.v1(value: "ab[0-9]+")

    // Condition → the RuleFormula stage. Queries handles + filesize.
    require present($mz)
        and count($cmd) > 3
        and filesize < 1000
        and (present($pe) or present($re))

    report { message: "suspicious PE-ish bytes" }
}
```

## Required vocabulary → vyre mapping (fixed)

| `.srg` construct | YARA source | vyre lowering (live API) |
|---|---|---|
| `vyre.scan.text.v1(value, nocase, ascii)` | `$a = "txt" nocase ascii` | `scan::literal_set` pattern; sets `rule_bitmaps`/`rule_counts[id]` |
| `vyre.scan.hex.v1(value)` | `$a = { 4D 5A ?? }` | `scan::literal_set` (+ `regex_dfa` for `??`/jumps) |
| `vyre.scan.regex.v1(value)` | `$a = /re/` | `scan::regex_dfa` |
| `present($a)` | `$a` | `RuleCondition::PatternExists { pattern_id }` |
| `count($a) > n` / `>= n` | `#a > n` / `>= n` | `RuleCondition::PatternCountGt` / `PatternCountGte` |
| `filesize <op> n` | `filesize <op> n` | `RuleCondition::FileSize{Lt,Lte,Gt,Gte,Eq,Ne}` |
| `and` / `or` / `not` | `and` / `or` / `not` | `RuleFormula::{And,Or,Not}` |
| `any_of([..])` / `all_of([..])` | `any of them` / `all of them` | Or / And expansion over `PatternExists` |
| `n_of(k, [..])` | `k of (...)` | threshold (combinatorial for small M; `dnnf` for large) |

The `vyre.scan.*` ExternCalls populate the `rule_bitmaps` + `rule_counts` buffers; the
`require` clause lowers to a `RuleFormula` over `RuleCondition` producing `verdicts`
(`vyre-libs/src/rule/builder.rs`). Both stages already exist and are parity-tested
(`reference_eval.rs`).

## Out of scope for the v1 surface (rejected loudly, on the P3 roadmap)

`wide`/`xor`/`base64`/`fullword` modifiers, `uintN(offset)`, `pe`/`elf`/`math.entropy`/
`hash.*` modules, `for..in`/`for..of`, match anchors (`$a at 0`, `$a in (0..10)`),
offsets `@a`/lengths `!a`. Each becomes a generic vyre op (pattern transform or an
extension buffer via `required_extension_buffers()`), mapped in the transpiler later.

**Private rules** (`private rule ...`) are also out of scope for v1: in YARA a private
rule never appears in scan output, it exists only to be referenced by another rule's
condition. With no rule-to-rule references yet, it has no faithful *standalone* lowering,
so it is rejected (lowering it as a normal `.srg` rule would self-report when YARA
reports nothing). It lands with rule references in P3, as a named sub-formula consumed by
referencing rules.

## Open question for the surge rewrite (ties to decision #1)

Does the `input = bytes` mode + `vyre.scan.*` ExternCall family land as: (a) first-class
surge predicates, or (b) pure ExternCall with no new keywords? Either satisfies this
contract; the transpiler emits whichever the rewrite chooses.
