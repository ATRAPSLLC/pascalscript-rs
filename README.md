# pascalscript

Read-only parser + symbolic disassembler for the
**RemObjects PascalScript III** binary container format (`IFPS`
magic). Inno Setup `[Code]` sections are the most prominent
embedding, but the format is general: any Delphi application
that vendors RemObjects PascalScript can produce these blobs.

## What it does

- Validates the 28-byte fixed `TPSHeader` (magic, build number,
  table counts, main-proc index).
- Walks the variable-length **type**, **proc**, **var**, and
  build-21+ **attribute** tables into typed Rust views with
  borrowed string slices (no allocation outside the small
  per-table `Vec`s).
- Decodes the bytecode stream (27 documented opcodes plus
  `cm_nop`) into typed `Instruction`s, with PC-relative branches
  resolved to absolute offsets.
- Renders a symbolic disassembly via `Container::display(...)`
  with operand indices resolved against the symbol tables
  (`g#7` → `g_AppId`, `proc#12` → `RegSetValueEx`, etc.).

## What it doesn't do

- **No execution.** This is a read-only parser; no interpreter,
  no JIT.
- **No re-encoding.** No serializer.
- **No decompilation to Pascal source.** The output is an
  annotated linear listing of opcodes, not reconstructed Pascal.
- **No host-API name mapping.** Imported externals appear as
  the names the host application registered them under
  (e.g. Inno's `SHELLEXEC`, `EXPANDCONSTANT`); semantic
  descriptions of those names are the host's responsibility.

## Wire-format reference

Every parser file cites the upstream Pascal line range it
mirrors. Canonical anchors:

- `IFPS` magic: `Components/UniPs/Source/uPSUtils.pas:20`
- Header: `uPSRuntime.pas:1204-1212`
- BaseType constants: `uPSUtils.pas:46-118`
- Container deserializer (`TPSExec.LoadData`): `uPSRuntime.pas:2318-3033`
- Opcode set: `uPSUtils.pas:122-297`
- Operand wire form (`TPSExec.ReadVariable`): `uPSRuntime.pas:6700+`

Pinned upstream revision: see `Components/UniPs/rev.txt` in any
recent issrc checkout.

## Adversarial-input safety

`unsafe_code`, `clippy::unwrap_used`, `expect_used`, `panic`,
`arithmetic_side_effects`, and `indexing_slicing` are all denied
at crate level. Every read goes through an internal cursor that
surfaces truncation as an `Error::Truncated` rather than
panicking.

## License

Copyright 2026 ATRAPS LLC. Licensed under the Apache License,
Version 2.0. See `LICENSE` and `NOTICE`.
