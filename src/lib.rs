//! Read-only parser for the RemObjects PascalScript III binary
//! container format (`IFPS` magic).
//!
//! RemObjects PascalScript is a Pascal-syntax scripting library
//! widely embedded in Delphi applications (Inno Setup's `[Code]`
//! sections being one of the most prominent users). This crate
//! parses the on-disk binary form - header, type / proc / var
//! / attribute tables, and the bytecode stream - into typed
//! Rust views, plus surfaces a symbolic disassembly via
//! [`Container::display`].
//!
//! Wire-format reference: the upstream `Components/UniPs/Source/`
//! tree (Carlo Kok's RemObjects PS III, `stable` branch). Every
//! parser file cites the specific upstream `uPSRuntime.pas` /
//! `uPSUtils.pas` line range it mirrors so reviewers can diff.
//!
//! Supported binary range: `PSLowBuildSupport = 12` through
//! `PSCurrentBuildNo = 23` (`uPSUtils.pas:14, 16`).
//!
//! # Wire-format anchors
//!
//! - Magic `PSValidHeader = 0x53504649` (LE bytes `b"IFPS"`),
//!   `uPSUtils.pas:20`.
//! - Header layout `TPSHeader` packed record,
//!   `uPSRuntime.pas:1204-1212`.
//! - `BaseType` constants `btU8 = 1` … `btType = 130`,
//!   `uPSUtils.pas:46-118`.
//! - Container deserializer `TPSExec.LoadData`,
//!   `uPSRuntime.pas:2318-3033`.
//! - Opcode constants `CM_A = 0` … `Cm_P2G = 26`, `cm_nop = 255`,
//!   `uPSUtils.pas:122-297`.
//! - Operand wire form `TPSExec.ReadVariable`,
//!   `uPSRuntime.pas:6700+`.
//!
//! # Adversarial-input safety
//!
//! `clippy::unwrap_used`, `expect_used`, `panic`,
//! `arithmetic_side_effects`, `indexing_slicing` are denied at
//! crate level, plus a no-`unsafe` posture. Every read goes
//! through an internal `Reader` cursor that surfaces truncation
//! as an [`Error`].

// The `missing_docs`, `unsafe_code`, `clippy::unwrap_used`,
// `clippy::expect_used`, `clippy::panic`,
// `clippy::arithmetic_side_effects`, and `clippy::indexing_slicing`
// lints are declared in `Cargo.toml` under `[lints]` so they enforce on
// every build regardless of the consuming workspace. pascalscript is used
// in malware-analysis pipelines where every input byte is adversarial and
// the parser must not panic.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing
    )
)]

mod reader;

pub mod attribute;
pub mod bytecode;
pub mod container;
pub mod disasm;
pub mod error;
pub mod frame;
pub mod header;
pub mod literal;
pub mod opcode;
pub mod operand;
pub mod proc;
pub mod signature;
pub mod ty;
pub mod var;

pub use attribute::{Attribute, AttributeField, AttributeFieldValue};
pub use bytecode::{Instruction, ProcDisasm};
pub use container::Container;
pub use disasm::{ContainerSummary, DisasmDisplay};
pub use error::Error;
pub use frame::{CallSlots, StackMap};
pub use header::{Header, IFPS_MAGIC, INVALID_VAL, PS_CURRENT_BUILD_NO, PS_LOW_BUILD_SUPPORT};
pub use literal::Literal;
pub use opcode::{CalcOp, CompareOp, ExceptionHandlerEnd, FlowType, Opcode};
pub use operand::{Operand, VarRef};
pub use proc::{ExternalProc, InternalProc, Proc, ProcKind};
pub use signature::{DllImport, ExternalDecl, FrameSlot, Param, Signature};
pub use ty::{BaseType, Type, TypeBody};
pub use var::Var;
