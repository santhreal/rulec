# Changelog

All notable changes to `rulec` will be documented in this file.

## [0.1.1] - 2026-07-31

### Fixed
- `cmp_u64` no longer casts a possibly negative `i64` threshold to `u64`;
  negative bounds are now constant-folded via `u64::try_from` failure, which
  removes any path where the cast could wrap a negative threshold into a huge
  unsigned value.
- `at_least_n` clamps negative counts with `usize::try_from` instead of a
  manual sign check plus cast.
- `read_alphabet` takes `Option<&LiteralString>` instead of `&Option<_>`;
  base64 variant generation iterates the strip table by value and uses
  `std::iter::repeat_n`.
- `lower_ast_partial` is now `#[must_use]`.
- Toolchain pinned to Rust 1.97.1 and `rust-version` set to 1.91 to match the
  `yara-x-parser` 1.17 / `wasmtime` 43 requirement; `regex` pinned to
  `=1.13.1` in line with `vyre-libs`.

## [0.1.0] - 2026-07-23

### Added
- Initial release of `rulec` detection-rule compiler.
- Lowering YARA AST constructs onto the `vyre` GPU rule engine substrate.
- Differential testing oracle vs `yara-x`.
