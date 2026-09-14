# Changelog

All notable changes to this crate are documented here.

## 0.1.3

- Replaced em-dashes and en-dashes in rustdoc comments and the changelog with plain ASCII hyphens, so generated documentation renders consistently.
- Updated CI and publish workflows from `actions/checkout@v4` to `actions/checkout@v7` (Node 24 runtime). The crate still has no external Rust dependencies.

## 0.1.2

- Fixed PC-relative branch resolution for backward branches. The IFPS VM adds the branch delta to the current position in wrapping `Cardinal` arithmetic, so the compiler encodes a backward jump as a large unsigned delta. `Instruction::branch_target()` / `branch_targets()` resolved `condgoto` / `condnotgoto` with a checked add and therefore returned `None` for every backward conditional branch - losing the back edge of every loop - while the disassembly display saturated and printed `0xffffffff`.
- Unified the four separate copies of the branch-delta arithmetic (two in `bytecode`, two in `disasm`) onto a single `relative_target` helper, so `goto` and `condgoto` can no longer disagree about the same wire delta.
- Fixed the coordinate system of absolute branch targets. `flaggoto` and the four `PushExceptionHandler` regions store *procedure-local* positions, but relative branch targets and `Instruction::offset` are IFPS-blob offsets, so a listing mixed two coordinate systems and handler targets did not resolve against the listing they appeared in for any proc but the first. Disassembly output now rebases them onto the proc's `bytecode_offset`, and new `ProcDisasm::branch_target()` / `ProcDisasm::branch_targets()` return every form in blob coordinates. The `Instruction`-level helpers keep their raw behaviour and now document the caveat.

## 0.1.1

- Added IFPS control-flow helpers: `FlowType`, `Opcode::flow_type()`, `Opcode::is_branch()`, and `Opcode::is_terminator()`.
- Added instruction branch-target helpers: `Instruction::branch_target()` and `Instruction::branch_targets()`.
- Added safe procedure accessors: `Container::proc_count()` and `Container::proc(idx)`.
- Added literal payload helpers: `Literal::as_string()`, `Literal::as_f64()`, and `Literal::as_currency()`.
- Moved adversarial-input safety lints into `Cargo.toml` so they are enforced consistently by Cargo.

## 0.1.0

- Initial read-only IFPS parser and disassembler.
- Parsed headers, types, procedures, variables, attributes, operands, literals, and bytecode instructions.
- Exposed symbolic container summary and per-procedure disassembly display helpers.
