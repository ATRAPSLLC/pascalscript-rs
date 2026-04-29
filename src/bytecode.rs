//! Per-procedure bytecode disassembly.
//!
//! Walks the bytecode body of an
//! [`InternalProc`](crate::InternalProc), decoding one opcode
//! at a time until the proc's `bytecode_len` window is
//! exhausted. Each instruction records its byte offset within
//! the IFPS blob (not within the proc body) so callers can map
//! disassembly lines back to wire positions for
//! cross-referencing.

use crate::{
    error::Error,
    opcode::{Opcode, parse_opcode},
    reader::Reader,
    ty::Type,
};

/// One decoded bytecode instruction with its byte offset in the
/// IFPS blob.
#[derive(Clone, Debug, PartialEq)]
pub struct Instruction<'a> {
    /// Offset of this instruction's leading byte within the
    /// IFPS blob — same coordinate system as
    /// [`crate::InternalProc::bytecode_offset`].
    /// Useful when chasing PC-relative branches: a `Goto`
    /// instruction's `offset` is relative to the byte
    /// immediately AFTER the instruction; combine with
    /// [`Self::next_offset`].
    pub offset: u32,
    /// Decoded opcode + operands.
    pub opcode: Opcode<'a>,
    /// Offset of the byte immediately after this instruction's
    /// last operand byte. Equivalent to "PC after fetch+decode".
    pub next_offset: u32,
}

/// Disassembly of one [`crate::InternalProc`].
#[derive(Clone, Debug)]
pub struct ProcDisasm<'a> {
    /// Index into [`crate::Container::procs`] of the
    /// disassembled proc.
    pub proc_index: u32,
    /// Byte offset where the proc's bytecode starts inside the
    /// IFPS blob — copied verbatim from
    /// [`crate::InternalProc::bytecode_offset`] for
    /// cross-reference.
    pub bytecode_offset: u32,
    /// Decoded instructions in source order.
    pub instructions: Vec<Instruction<'a>>,
}

/// Decodes the bytecode body for an internal proc.
///
/// `blob` is the entire IFPS byte buffer; `bytecode_offset` and
/// `bytecode_len` are the proc's window into that buffer
/// (validated up-front by [`crate::proc::parse_proc`]).
/// `types` is the parsed type table — needed for typed-literal
/// operand payloads.
///
/// # Errors
///
/// - [`Error::BytecodeOutOfRange`] when the window falls outside
///   `blob`.
/// - Any error from the per-opcode decoder — bad opcode byte,
///   malformed operand, truncated payload.
pub(crate) fn disassemble_proc<'a>(
    blob: &'a [u8],
    proc_index: u32,
    bytecode_offset: u32,
    bytecode_len: u32,
    types: &[Type<'a>],
) -> Result<ProcDisasm<'a>, Error> {
    let start = bytecode_offset as usize;
    let end = (bytecode_offset as u64)
        .checked_add(u64::from(bytecode_len))
        .ok_or(Error::Overflow {
            what: "bytecode end offset",
        })?;
    let end = usize::try_from(end).map_err(|_| Error::Overflow {
        what: "bytecode end offset",
    })?;
    let body = blob.get(start..end).ok_or(Error::BytecodeOutOfRange {
        offset: bytecode_offset,
        length: bytecode_len,
    })?;
    let mut reader = Reader::new(body);
    let mut instructions = Vec::new();
    while reader.pos() < reader.len() {
        let local_offset = reader.pos();
        let opcode = parse_opcode(&mut reader, types)?;
        let absolute_offset = bytecode_offset
            .checked_add(u32::try_from(local_offset).unwrap_or(u32::MAX))
            .ok_or(Error::Overflow {
                what: "instruction absolute offset",
            })?;
        let next_offset = bytecode_offset
            .checked_add(u32::try_from(reader.pos()).unwrap_or(u32::MAX))
            .ok_or(Error::Overflow {
                what: "instruction next offset",
            })?;
        instructions.push(Instruction {
            offset: absolute_offset,
            opcode,
            next_offset,
        });
    }
    Ok(ProcDisasm {
        proc_index,
        bytecode_offset,
        instructions,
    })
}
