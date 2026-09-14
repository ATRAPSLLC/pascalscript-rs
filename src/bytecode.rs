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
    ///
    /// Carries the same coordinate caveat as [`Self::branch_targets`] - prefer
    /// [`ProcDisasm::branch_target`], which normalizes every form to IFPS-blob
    /// coordinates.
    pub fn branch_target(&self) -> Option<u32> {
        self.branch_targets().into_iter().flatten().next()
    }

    /// Returns all explicit control-flow targets carried by this instruction.
    ///
    /// # Coordinates
    ///
    /// **The returned values are not all in the same coordinate system**, because
    /// an [`Instruction`] does not know which procedure owns it:
    ///
    /// - Relative branches (`goto`, `condgoto`, `condnotgoto`, the pop-and-goto
    ///   forms) resolve against [`Self::next_offset`], which is an IFPS-blob
    ///   offset - so these come back **blob-absolute**. A delta is
    ///   coordinate-independent, so this is exact.
    /// - `flaggoto` and the four `PushExceptionHandler` regions store an
    ///   *absolute* position, and IFPS positions are **procedure-local** (the VM
    ///   indexes into the proc's own bytecode body). These come back exactly as
    ///   stored, i.e. relative to the owning proc's `bytecode_offset`.
    ///
    /// Use [`ProcDisasm::branch_targets`] to get every form in blob
    /// coordinates; it knows the proc base and applies it to the absolute forms
    /// only.
    pub fn branch_targets(&self) -> [Option<u32>; 4] {
        match &self.opcode {
            Opcode::Goto { offset }
            | Opcode::PopAndGoto { offset }
            | Opcode::Pop2AndGoto { offset } => [
                Some(relative_target(self.next_offset, *offset as u32)),
                None,
                None,
                None,
            ],
            Opcode::CondGoto { offset, .. } | Opcode::CondNotGoto { offset, .. } => [
                Some(relative_target(self.next_offset, *offset)),
                None,
                None,
                None,
            ],
            Opcode::FlagGoto { target } => [Some(*target), None, None, None],
            Opcode::PushExceptionHandler {
                finally_offset,
                exception_offset,
                finally2_offset,
                end_of_block,
            } => [
                Some(*finally_offset),
                Some(*exception_offset),
                Some(*finally2_offset),
                Some(*end_of_block),
            ],
            _ => [None, None, None, None],
        }
    }
}

/// Resolves a PC-relative branch delta against the position it is relative to.
///
/// Every relative branch in IFPS (`Cm_G`, `Cm_CG`, `Cm_CNG`, and the two
/// pop-and-goto forms) encodes the same thing: a four-byte little-endian delta
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

impl ProcDisasm<'_> {
    /// Returns `instruction`'s primary control-flow target in IFPS-blob
    /// coordinates, or `None` for a non-branch opcode.
    ///
    /// See [`Self::branch_targets`] for why this exists alongside
    /// [`Instruction::branch_target`].
    pub fn branch_target(&self, instruction: &Instruction<'_>) -> Option<u32> {
        self.branch_targets(instruction)
            .into_iter()
            .flatten()
            .next()
    }

    /// Returns every control-flow target `instruction` carries, all of them in
    /// **IFPS-blob coordinates** - the same coordinate system as
    /// [`Instruction::offset`], so a target can be compared directly against
    /// the instruction stream.
    ///
    /// [`Instruction::branch_targets`] cannot do this: `flaggoto` and the
    /// `PushExceptionHandler` regions store procedure-local positions, and an
    /// instruction does not know its procedure. This method adds
    /// [`Self::bytecode_offset`] to exactly those forms and leaves the
    /// already-blob-absolute relative branches alone.
    ///
    /// `instruction` is expected to belong to this procedure; passing a foreign
    /// one rebases its absolute targets against the wrong proc.
    pub fn branch_targets(&self, instruction: &Instruction<'_>) -> [Option<u32>; 4] {
        let raw = instruction.branch_targets();
        if !matches!(
            instruction.opcode,
            Opcode::FlagGoto { .. } | Opcode::PushExceptionHandler { .. }
        ) {
            return raw;
        }
        raw.map(|target| target.map(|t| self.bytecode_offset.wrapping_add(t)))
    }
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

    /// `flaggoto` carries an absolute position, not a delta - and on the bare
    /// instruction it comes back procedure-local, as stored.
    #[test]
    fn flag_goto_target_is_absolute() {
        let inst = at(0x0100, Opcode::FlagGoto { target: 0x40 });
        assert_eq!(inst.branch_target(), Some(0x40));
    }

    /// Builds a single-instruction [`ProcDisasm`] based at `bytecode_offset`.
    fn proc(bytecode_offset: u32, inst: Instruction<'static>) -> ProcDisasm<'static> {
        ProcDisasm {
            proc_index: 0,
            bytecode_offset,
            instructions: vec![inst],
        }
    }

    /// The proc-level resolver rebases procedure-local absolute targets onto
    /// the proc's blob offset, so they can be compared against instruction
    /// offsets from the same listing.
    #[test]
    fn proc_level_resolution_rebases_absolute_targets() {
        let inst = at(0x1100, Opcode::FlagGoto { target: 0x40 });
        let disasm = proc(0x1000, inst.clone());
        assert_eq!(inst.branch_target(), Some(0x40), "raw form stays as stored");
        assert_eq!(disasm.branch_target(&inst), Some(0x1040));
    }

    /// All four exception-handler regions are rebased.
    #[test]
    fn proc_level_resolution_rebases_every_handler_region() {
        let inst = at(
            0x1100,
            Opcode::PushExceptionHandler {
                finally_offset: 0x10,
                exception_offset: 0x20,
                finally2_offset: 0x30,
                end_of_block: 0x40,
            },
        );
        let disasm = proc(0x1000, inst.clone());
        assert_eq!(
            disasm.branch_targets(&inst),
            [Some(0x1010), Some(0x1020), Some(0x1030), Some(0x1040)],
        );
    }

    /// Relative branches are already blob-absolute, so the proc-level resolver
    /// must leave them untouched rather than double-adding the proc base.
    #[test]
    fn proc_level_resolution_leaves_relative_targets_alone() {
        let inst = at(0x1100, Opcode::Goto { offset: -0x40 });
        let disasm = proc(0x1000, inst.clone());
        assert_eq!(disasm.branch_target(&inst), inst.branch_target());
        assert_eq!(disasm.branch_target(&inst), Some(0x10C0));
    }

    /// Non-branch opcodes carry no targets at all.
    #[test]
    fn non_branch_opcodes_have_no_targets() {
        let inst = at(0x0100, Opcode::Return);
        assert_eq!(inst.branch_target(), None);
        assert_eq!(inst.branch_targets(), [None, None, None, None]);
    }

    /// The exception-handler setup opcode carries four targets; `branch_target`
    /// surfaces the first.
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
            [Some(0x10), Some(0x20), Some(0x30), Some(0x40)],
        );
        assert_eq!(inst.branch_target(), Some(0x10));
    }
}
