//! The value stack a procedure's body works on: how deep it is before each
//! instruction, and which slots each call consumes.
//!
//! Every local, temporary and call argument lives on one stack, addressed from
//! the procedure's frame base: the body's own slots are `s+1` upward. Its
//! height changes by rule (`uPSRuntime.pas`): `PushType`, `Push` and `PushVar`
//! add a slot, `Pop` removes one, and the pop-and-goto forms remove one or two
//! before jumping. A call changes nothing: the caller pushes its arguments,
//! and pops them itself afterwards. The compiler keeps the height the same on
//! every path into an instruction, which is what lets a slot be named by its
//! offset at all - so a path that disagrees is a malformed procedure, not one
//! to guess about.
//!
//! An exception handler section runs at the height its `try` recorded: the
//! runtime saves the stack size at `PushExceptionHandler` and restores it on
//! entering the finally or except code (`uPSRuntime.pas`, `cm_puexh`).

use std::collections::VecDeque;

use crate::{
    bytecode::{Instruction, ProcDisasm},
    error::Error,
    opcode::Opcode,
};

/// The stack height before each instruction of one procedure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StackMap {
    /// Height before instruction `i` (the number of the body's own slots
    /// live), or `None` for an instruction no path reaches.
    heights: Vec<Option<u32>>,
}

/// The stack slots one call consumes: the top `count` of the caller's.
///
/// The callee sees them from its own frame base downward, the topmost as
/// `s-1` ([`Signature::slot`](crate::signature::Signature::slot) says what
/// each is to it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallSlots {
    /// The lowest slot the call consumes, as the caller addresses it (`s+n`).
    pub first: u32,
    /// How many slots, up to the top of the caller's stack.
    pub count: u32,
}

impl CallSlots {
    /// The caller's offset of the slot the callee addresses as `s-depth`
    /// (`depth` from 1), or `None` below the call's slots.
    #[must_use]
    pub fn caller_offset(&self, depth: u32) -> Option<u32> {
        if depth == 0 || depth > self.count {
            return None;
        }
        self.first.checked_add(self.count)?.checked_sub(depth)
    }
}

impl StackMap {
    /// Computes the height before each instruction of `disasm`.
    ///
    /// # Errors
    ///
    /// [`Error::StackImbalance`] when two paths reach an instruction at
    /// different heights, or a pop would take the stack below the frame base.
    pub fn of(disasm: &ProcDisasm<'_>) -> Result<Self, Error> {
        let instructions = &disasm.instructions;
        let index_of = |offset: u32| instructions.iter().position(|i| i.offset == offset);
        let mut heights: Vec<Option<u32>> = vec![None; instructions.len()];
        let mut work = VecDeque::new();
        if !instructions.is_empty() {
            work.push_back((0usize, 0u32));
        }
        while let Some((index, height)) = work.pop_front() {
            let Some(slot) = heights.get_mut(index) else {
                continue;
            };
            match *slot {
                Some(known) if known == height => continue,
                Some(_) => {
                    return Err(imbalance(instructions.get(index)));
                }
                None => *slot = Some(height),
            }
            let Some(instruction) = instructions.get(index) else {
                continue;
            };
            let after = height_after(instruction, height)?;
            let fallthrough = index
                .checked_add(1)
                .filter(|next| *next < instructions.len());
            let mut go = |target: Option<u32>, height: u32| {
                if let Some(target) = target.and_then(index_of) {
                    work.push_back((target, height));
                }
            };
            match &instruction.opcode {
                Opcode::Return => {}
                Opcode::Goto { .. } | Opcode::PopAndGoto { .. } | Opcode::Pop2AndGoto { .. } => {
                    go(instruction.branch_target(), after);
                }
                Opcode::CondGoto { .. } | Opcode::CondNotGoto { .. } | Opcode::FlagGoto { .. } => {
                    go(instruction.branch_target(), after);
                    if let Some(next) = fallthrough {
                        work.push_back((next, after));
                    }
                }
                Opcode::PushExceptionHandler { .. } => {
                    // Each section starts at the height the `try` saved.
                    for target in instruction.branch_targets() {
                        go(target, height);
                    }
                    if let Some(next) = fallthrough {
                        work.push_back((next, after));
                    }
                }
                _ => {
                    if let Some(next) = fallthrough {
                        work.push_back((next, after));
                    }
                }
            }
        }
        Ok(Self { heights })
    }

    /// The height before instruction `index`, or `None` when no path reaches
    /// it.
    #[must_use]
    pub fn height_before(&self, index: usize) -> Option<u32> {
        self.heights.get(index).copied().flatten()
    }

    /// The slots the call at `index` consumes.
    ///
    /// `exact` is the count when the callee's declaration states every
    /// parameter - an internal procedure's
    /// ([`Signature::slot_count`](crate::signature::Signature::slot_count)). An
    /// external one's cannot: the compiler's own intrinsics (`Length`,
    /// `SetArrayLength` and the like) accept any type and list no parameters,
    /// which reads the same as a host function that takes none. For those the
    /// pops that follow the call decide, since the caller pops exactly what it
    /// pushed for the call, and nothing else, right after it
    /// (`uPSCompiler.pas`, `ProcessVarFunction`). `None` when the instruction
    /// is not a call, is unreachable, or the count exceeds the stack.
    #[must_use]
    pub fn call_slots(
        &self,
        disasm: &ProcDisasm<'_>,
        index: usize,
        exact: Option<usize>,
    ) -> Option<CallSlots> {
        let instruction = disasm.instructions.get(index)?;
        if !matches!(
            instruction.opcode,
            Opcode::Call { .. } | Opcode::CallVar { .. }
        ) {
            return None;
        }
        let height = self.height_before(index)?;
        let count = match exact {
            Some(count) => count,
            None => disasm
                .instructions
                .iter()
                .skip(index.checked_add(1)?)
                .take_while(|next| matches!(next.opcode, Opcode::Pop))
                .count(),
        };
        let count = u32::try_from(count).ok()?;
        let first = height.checked_sub(count)?.checked_add(1)?;
        Some(CallSlots { first, count })
    }
}

/// The height after `instruction` runs at `height`.
fn height_after(instruction: &Instruction<'_>, height: u32) -> Result<u32, Error> {
    let pop = |n: u32| {
        height
            .checked_sub(n)
            .ok_or_else(|| imbalance(Some(instruction)))
    };
    match instruction.opcode {
        Opcode::PushType { .. } | Opcode::Push { .. } | Opcode::PushVar { .. } => height
            .checked_add(1)
            .ok_or_else(|| imbalance(Some(instruction))),
        Opcode::Pop | Opcode::PopAndGoto { .. } => pop(1),
        Opcode::Pop2AndGoto { .. } => pop(2),
        _ => Ok(height),
    }
}

fn imbalance(instruction: Option<&Instruction<'_>>) -> Error {
    Error::StackImbalance {
        offset: instruction.map_or(0, |i| i.offset),
    }
}

impl ProcDisasm<'_> {
    /// The stack height before each instruction ([`StackMap`]).
    ///
    /// # Errors
    ///
    /// [`Error::StackImbalance`] when the body's paths disagree about it.
    pub fn stack_map(&self) -> Result<StackMap, Error> {
        StackMap::of(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        operand::{Operand, VarRef},
        signature::Signature,
    };

    /// A body of `opcodes`, one byte each, from offset 0x100.
    fn body(opcodes: Vec<Opcode<'static>>) -> ProcDisasm<'static> {
        let instructions = opcodes
            .into_iter()
            .zip(0x100u32..)
            .map(|(opcode, offset)| Instruction {
                offset,
                opcode,
                next_offset: offset + 1,
            })
            .collect();
        ProcDisasm {
            proc_index: 0,
            bytecode_offset: 0x100,
            instructions,
        }
    }

    fn slot(n: i64) -> Operand<'static> {
        Operand::Var(VarRef::Stack(n))
    }

    /// `SCALE(6, 7)` as `code.iss` compiles it: two argument temporaries and a
    /// result reference above one local, the call, then three pops.
    #[test]
    fn a_call_consumes_the_slots_its_declaration_names() {
        let disasm = body(vec![
            Opcode::PushType { type_no: 11 }, // s+1 Total
            Opcode::PushType { type_no: 11 }, // s+2 Factor = 7
            Opcode::PushType { type_no: 11 }, // s+3 Value = 6
            Opcode::PushVar { var: slot(1) }, // s+4 -> result into Total
            Opcode::Call { proc_no: 2 },
            Opcode::Pop,
            Opcode::Pop,
            Opcode::Pop,
            Opcode::Return,
        ]);
        let map = disasm.stack_map().unwrap();
        assert_eq!(map.height_before(4), Some(4));
        assert_eq!(map.height_before(8), Some(1));
        let scale = Signature::of_internal(b"11 @11 @11").unwrap();
        let call = map
            .call_slots(&disasm, 4, Some(scale.slot_count()))
            .unwrap();
        assert_eq!(call, CallSlots { first: 2, count: 3 });
        // The callee's s-1 is the result reference, s-2 the first parameter.
        assert_eq!(call.caller_offset(1), Some(4));
        assert_eq!(call.caller_offset(2), Some(3));
        assert_eq!(call.caller_offset(3), Some(2));
        assert_eq!(call.caller_offset(4), None);
    }

    /// An intrinsic declares no parameters; the pops after it count them.
    #[test]
    fn an_intrinsics_slots_are_the_pops_after_it() {
        let disasm = body(vec![
            Opcode::PushType { type_no: 11 },
            Opcode::PushType { type_no: 0 },
            Opcode::Call { proc_no: 7 },
            Opcode::Pop,
            Opcode::Pop,
            Opcode::Return,
        ]);
        let map = disasm.stack_map().unwrap();
        assert_eq!(
            map.call_slots(&disasm, 2, None),
            Some(CallSlots { first: 1, count: 2 })
        );
    }

    /// Two paths reaching one instruction at different heights are a malformed
    /// body, never averaged: a slot's offset would name two variables.
    #[test]
    fn paths_that_disagree_about_the_height_are_refused() {
        let disasm = body(vec![
            Opcode::CondGoto {
                offset: 1, // to 0x102, skipping the push
                cond: slot(-1),
            },
            Opcode::PushType { type_no: 11 },
            Opcode::Nop,
            Opcode::Return,
        ]);
        assert_eq!(
            disasm.stack_map(),
            Err(Error::StackImbalance { offset: 0x102 })
        );
        let underflow = body(vec![Opcode::Pop, Opcode::Return]);
        assert_eq!(
            underflow.stack_map(),
            Err(Error::StackImbalance { offset: 0x100 })
        );
    }
}
