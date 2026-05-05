# Changelog

All notable changes to this crate are documented here.

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
