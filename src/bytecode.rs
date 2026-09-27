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
    header::INVALID_VAL,
    opcode::{Opcode, parse_opcode},
    reader::Reader,
    ty::Type,
};

/// One decoded bytecode instruction with its byte offset in the
/// IFPS blob.
#[derive(Clone, Debug, PartialEq)]
pub struct Instruction<'a> {
    /// Offset of this instruction's leading byte within the
    /// IFPS blob - same coordinate system as
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

impl Instruction<'_> {
    /// Returns this instruction's primary branch target, if any.
    ///
    /// Conditional opcodes return their taken target. Exception-handler
    /// setup opcodes carry multiple targets, so callers that need all of
    /// them should use [`Self::branch_targets`].
    pub fn branch_target(&self) -> Option<u32> {
        self.branch_targets().into_iter().flatten().next()
    }

    /// Returns all explicit control-flow targets carried by this instruction,
    /// in IFPS-blob coordinates - the same coordinate system as
    /// [`Self::offset`], so a target can be compared directly against the
    /// instruction stream.
    ///
    /// Every IFPS branch stores a delta from the end of its instruction, and
    /// the runtime adds it to the position after the operands: the gotos, the
    /// pop-and-gotos, `flaggoto`, and each of the four exception-handler
    /// sections. A delta is coordinate-independent, so resolving it against
    /// [`Self::next_offset`] is exact. An exception-handler section the `try`
    /// does not have is [`INVALID_VAL`] on the wire and `None` here.
    ///
    /// The four slots are the handler's finally, except, second-finally and
    /// end-of-block sections; a branch uses the first.
    pub fn branch_targets(&self) -> [Option<u32>; 4] {
        let at = |delta: u32| Some(relative_target(self.next_offset, delta));
        let section =
            |delta: u32| (delta != INVALID_VAL).then(|| relative_target(self.next_offset, delta));
        match &self.opcode {
            Opcode::Goto { offset }
            | Opcode::PopAndGoto { offset }
            | Opcode::Pop2AndGoto { offset } => [at(*offset as u32), None, None, None],
            Opcode::CondGoto { offset, .. }
            | Opcode::CondNotGoto { offset, .. }
            | Opcode::FlagGoto { offset } => [at(*offset), None, None, None],
            Opcode::PushExceptionHandler {
                finally_offset,
                exception_offset,
                finally2_offset,
                end_of_block,
            } => [
                section(*finally_offset),
                section(*exception_offset),
                section(*finally2_offset),
                section(*end_of_block),
            ],
            _ => [None, None, None, None],
        }
    }
}

/// Resolves a PC-relative branch delta against the position it is relative to.
///
/// Every IFPS branch (`Cm_G`, `Cm_CG`, `Cm_CNG`, `cm_fg`, the two
/// pop-and-goto forms and the exception-handler sections) encodes the same
/// thing: a four-byte little-endian delta
/// added to the position after the instruction. The VM performs that addition
/// on Delphi `Cardinal`s (`CurrentPosition := CurrentPosition + NewPosition`),
/// which wraps - so the compiler emits a **backward** branch as a large
/// unsigned delta that wraps back around. Modelling the addition as
/// checked or saturating therefore loses exactly the backward branches, i.e.
/// every loop.
///
/// `Goto` is decoded as `i32` and the conditionals as `u32` purely because that
/// is the friendlier type at each use site; the bit patterns are identical, so
/// both reach this function as a raw `u32` delta.
///
/// The result can land outside the owning procedure when the input is
/// malformed - IFPS producers are untrusted. Validating that is the caller's
/// job (the VM itself bounds-checks the new position against the proc length),
/// which is why this returns a plain `u32` rather than an `Option`.
pub(crate) fn relative_target(base: u32, delta: u32) -> u32 {
    base.wrapping_add(delta)
}

/// Disassembly of one [`crate::InternalProc`].
#[derive(Clone, Debug)]
pub struct ProcDisasm<'a> {
    /// Index into [`crate::Container::procs`] of the
    /// disassembled proc.
    pub proc_index: u32,
    /// Byte offset where the proc's bytecode starts inside the
    /// IFPS blob - copied verbatim from
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
/// `types` is the parsed type table - needed for typed-literal
/// operand payloads.
///
/// # Errors
///
/// - [`Error::BytecodeOutOfRange`] when the window falls outside
///   `blob`.
/// - Any error from the per-opcode decoder - bad opcode byte,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operand::{Operand, VarRef};

    /// Builds an [`Instruction`] positioned so that `next_offset` is the
    /// position the branch delta is relative to.
    fn at(next_offset: u32, opcode: Opcode<'static>) -> Instruction<'static> {
        Instruction {
            offset: next_offset.saturating_sub(1),
            opcode,
            next_offset,
        }
    }

    /// A forward conditional branch adds its delta directly.
    #[test]
    fn forward_conditional_branch_resolves_ahead_of_the_instruction() {
        let inst = at(
            0x0100,
            Opcode::CondGoto {
                offset: 0x20,
                cond: Operand::Var(VarRef::Stack(-4)),
            },
        );
        assert_eq!(inst.branch_target(), Some(0x0120));
    }

    /// A backward conditional branch is encoded as a wrapping `Cardinal`
    /// delta, exactly like the unconditional `goto` - resolving it with
    /// checked or saturating arithmetic loses every loop in the program.
    #[test]
    fn backward_conditional_branch_wraps_to_a_target_behind_the_instruction() {
        // 0x0100 + (-0x40 as u32) == 0x00C0 after the wrap.
        let inst = at(
            0x0100,
            Opcode::CondGoto {
                offset: (-0x40i32) as u32,
                cond: Operand::Var(VarRef::Stack(-4)),
            },
        );
        assert_eq!(inst.branch_target(), Some(0x00C0));

        let inst = at(
            0x0100,
            Opcode::CondNotGoto {
                offset: (-0x40i32) as u32,
                cond: Operand::Var(VarRef::Stack(-4)),
            },
        );
        assert_eq!(inst.branch_target(), Some(0x00C0));
    }

    /// `goto` and `condgoto` carry the same wire delta, so the same backward
    /// jump must resolve identically through either opcode.
    #[test]
    fn signed_and_unsigned_branch_forms_agree_on_the_same_delta() {
        let unconditional = at(0x0100, Opcode::Goto { offset: -0x40 });
        let conditional = at(
            0x0100,
            Opcode::CondGoto {
                offset: (-0x40i32) as u32,
                cond: Operand::Var(VarRef::Stack(-4)),
            },
        );
        assert_eq!(unconditional.branch_target(), conditional.branch_target());
    }

    /// `flaggoto` carries a delta from the end of the instruction, like every
    /// other branch: the runtime adds it to the position after the operand.
    /// Read as a procedure-local absolute (the 0.1.2 reading) it resolved to a
    /// boundary for 4 of the 14 in `imagemagick-setup.exe`; as a delta, 14.
    #[test]
    fn flag_goto_target_is_relative_to_the_next_instruction() {
        let inst = at(0x1100, Opcode::FlagGoto { offset: 0x40 });
        assert_eq!(inst.branch_target(), Some(0x1140));
        let back = at(
            0x1100,
            Opcode::FlagGoto {
                offset: (-0x40i32) as u32,
            },
        );
        assert_eq!(back.branch_target(), Some(0x10C0), "a backward delta wraps");
    }

    /// Non-branch opcodes carry no targets at all.
    #[test]
    fn non_branch_opcodes_have_no_targets() {
        let inst = at(0x0100, Opcode::Return);
        assert_eq!(inst.branch_target(), None);
        assert_eq!(inst.branch_targets(), [None, None, None, None]);
    }

    /// The exception-handler setup opcode carries four targets, each a delta
    /// from the end of the instruction; `branch_target` surfaces the first.
    #[test]
    fn exception_handler_carries_every_region_target() {
        let inst = at(
            0x0100,
            Opcode::PushExceptionHandler {
                finally_offset: 0x10,
                exception_offset: 0x20,
                finally2_offset: 0x30,
                end_of_block: 0x40,
            },
        );
        assert_eq!(
            inst.branch_targets(),
            [Some(0x0110), Some(0x0120), Some(0x0130), Some(0x0140)],
        );
        assert_eq!(inst.branch_target(), Some(0x0110));
    }

    /// A section the `try` does not have is `INVALID_VAL` on the wire, which
    /// the runtime skips rather than adds; it is no target at all, where
    /// resolving it as a delta would land one byte before the instruction.
    #[test]
    fn an_absent_handler_section_is_no_target() {
        let inst = at(
            0x0100,
            Opcode::PushExceptionHandler {
                finally_offset: INVALID_VAL,
                exception_offset: 0x20,
                finally2_offset: INVALID_VAL,
                end_of_block: 0x40,
            },
        );
        assert_eq!(
            inst.branch_targets(),
            [None, Some(0x0120), None, Some(0x0140)],
        );
        assert_eq!(inst.branch_target(), Some(0x0120));
    }
}
