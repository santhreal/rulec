# rulec

![Status: alpha](https://img.shields.io/badge/status-alpha-blue.svg)

A one-way compiler lowering detection-rule dialects (YARA today, Sigma next) onto the vyre GPU rule engine substrate.

## What it does

`rulec` lowers detection rules into byte-NFA patterns and boolean condition formulas for execution on the `vyre` substrate (both CPU parity walk and GPU megakernel).

- Parses YARA using `yara-x-parser` AST.
- Lowers text, hex, wildcards, jumps, alternations, `nocase`, `ascii`, `wide`, `xor`, and `base64` modifiers.
- Evaluates conditions (`and`, `or`, `not`, counts, `filesize`, set quantifiers) via `vyre_libs::rule::RuleFormula`.
- Provides an optional export to `.srg` text format.
- Includes a differential testing oracle that validates lowering against `yara-x`.

## Quick start

Add `rulec` to your `Cargo.toml`:

```toml
[dependencies]
rulec = "0.1.0"
```

Compile YARA rules into lowered IR:

```rust
use rulec::compile;

let yara_src = r#"
rule example {
    strings:
        $a = "cmd.exe" nocase
    condition:
        $a
}
"#;

let compiled = compile(yara_src.as_bytes()).expect("failed to compile rule");
println!("Lowered {} rules", compiled.rules.len());
```

Run tests:

```bash
cargo test
```

## When to use / when not

**When to use:**
- High-throughput rule compilation for the `vyre` GPU/CPU matching engine.
- Forward-integration of YARA detection signatures without reimplementing rule engine execution.
- Differential verification of rule lowering against reference YARA semantics.

**When not to use:**
- Features relying on complex YARA modules (`pe.*`, `elf.*`, `math.*`) that are not yet lowered onto `vyre`.
- Full YARA evaluation requiring unconstrained process memory or non-byte matching lookups.

## Compared to alternatives

- **`yara-x`**: `yara-x` is a full CPU reference YARA implementation in Rust. `rulec` uses `yara-x-parser` for AST parsing and `yara-x` for differential testing, but targets high-throughput GPU/CPU execution via `vyre`.
- **Legacy compilers (`yaragpu`, `rulefire`)**: Legacy compilers relied on silent feature truncation. `rulec` strictly enforces explicit rejection with actionable diagnostics whenever a rule construct is unsupported.

## How it fits in Santh

`rulec` sits in `libs/scanner/rulec/` as the rule compiler front-end within the Santh detection infrastructure. It lowers rules onto `libs/performance/matching/vyre` (the vyre substrate) for high-performance scanning.

```
YARA source -> (rulec) -> vyre rule IR -> vyre GPU engine
                       -> .srg text (optional export)
```

## Contributing

Contributions must maintain standard compliance and keep zero silent fallbacks. Run conformance checks with:

```bash
cargo run -p santh-conform -- check libs/scanner/rulec
```

## License

Dual-licensed under either of:

- Apache License, Version 2.0 (`LICENSE-APACHE`)
- MIT License (`LICENSE-MIT`)
