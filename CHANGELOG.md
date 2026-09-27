# Changelog

All notable changes to this crate are documented here.

## 0.2.0

This release changes the public API: `ProcDisasm::branch_target()` / `branch_targets()` are removed, `FlagGoto`'s field is renamed, and `SetStackPointerToCopy` now carries two operands. Hence the minor version bump.

- Added `signature`: `Signature` parses an internal procedure's export declaration (`InternalProc::signature()`) and an external one's bit string, and `ExternalDecl` a DLL import's library, function, calling convention and loading flags (`ExternalProc::declaration()`). `Signature::slot` says what a stack slot holds inside the procedure: the return address, the result reference, a parameter, or a local.
- Added `frame`: `StackMap` (`ProcDisasm::stack_map()`) gives the stack height before every instruction, following the body's control flow and restoring the height a `try` saved at each of its handler sections, and refuses a body whose paths disagree about it (`Error::StackImbalance`). `StackMap::call_slots` gives the slots a call consumes, from the callee's declaration or, for the compiler's intrinsics that declare no parameters, from the pops that follow the call. Checked on a compiled script: the two agree on every call to an internal procedure.
- Added `Opcode::operands()` and `Operand::var_refs()`: every operand an instruction carries, and every variable an operand names.
- Fixed `cm_spc` (`SetStackPointerToCopy`, opcode 22). It carries two variables, a destination pointer and the value it is made to point at a copy of, as the runtime reads them and the compiler writes them. It was decoded as a `u32`, which left the decoder mid-operand, so any procedure containing it failed to decode. The variant is now `SetStackPointerToCopy { dest, src }`.
- Fixed the coordinates of `flaggoto` and the four `PushExceptionHandler` sections. Like every other IFPS branch, they are deltas from the end of the instruction (the runtime adds the position after the operands), not procedure-local absolutes. On `imagemagick-setup.exe` the 0.1.2 reading put 10 of 14 `flaggoto` targets between instructions, and on a compiled `try` fixture all 4 exception sections. `Instruction::branch_targets()` now returns every form in IFPS-blob coordinates, so `ProcDisasm::branch_target()` / `branch_targets()` have no rebasing left to do and are removed. `FlagGoto`'s field is renamed `offset` to say it is a delta.
- An exception-handler section the `try` does not have (`INVALID_VAL` on the wire) is now `None` rather than a target one byte before the instruction.
- `FlagGoto` is a conditional branch in `Opcode::flow_type()`: it branches only when the saved flag is set.
- An unknown opcode byte is `Error::UnknownOpcode` and an unknown calculation, comparison or exception-section byte is `Error::UnknownSubOp`, both of which previously reported `Error::UnknownBaseType`.

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
