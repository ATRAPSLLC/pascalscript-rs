//! IFPS opcode set + per-opcode wire decoder.
//!
//! Source: `uPSUtils.pas:122-297` (one constant per opcode, with
//! the wire layout in the leading comment) and the
//! `case Cmd of …` dispatcher in `TPSExec.RunScript`
//! (`uPSRuntime.pas:7980+`). The format defines 27 documented
//! opcodes (0-26) plus the no-op (255).

use crate::{
    error::Error,
    operand::{Operand, parse_operand},
    reader::Reader,
    ty::Type,
};

/// CalcType byte for [`Opcode::CalculateAssign`]. Source:
/// `uPSUtils.pas:131-145`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum CalcOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Shl,
    Shr,
    And,
    Or,
    Xor,
}

impl CalcOp {
    fn from_byte(b: u8) -> Result<Self, Error> {
        match b {
            0 => Ok(Self::Add),
            1 => Ok(Self::Sub),
            2 => Ok(Self::Mul),
            3 => Ok(Self::Div),
            4 => Ok(Self::Mod),
            5 => Ok(Self::Shl),
            6 => Ok(Self::Shr),
            7 => Ok(Self::And),
            8 => Ok(Self::Or),
            9 => Ok(Self::Xor),
            other => Err(Error::UnknownBaseType { byte: other }),
        }
    }
}

/// CompareType byte for [`Opcode::Compare`]. Source:
/// `uPSUtils.pas:202-211`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum CompareOp {
    GreaterEq,
    LessEq,
    Greater,
    Less,
    NotEqual,
    Equal,
}

impl CompareOp {
    fn from_byte(b: u8) -> Result<Self, Error> {
        match b {
            0 => Ok(Self::GreaterEq),
            1 => Ok(Self::LessEq),
            2 => Ok(Self::Greater),
            3 => Ok(Self::Less),
            4 => Ok(Self::NotEqual),
            5 => Ok(Self::Equal),
            other => Err(Error::UnknownBaseType { byte: other }),
        }
    }
}

/// Position byte for [`Opcode::PopExceptionHandler`]. Source:
/// `uPSUtils.pas:256-262`. `0` = end of try/finally/exception
/// block, `1` = end of first finally, `2` = end of except,
/// `3` = end of second finally.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum ExceptionHandlerEnd {
    EndOfBlock,
    EndOfFirstFinally,
    EndOfExcept,
    EndOfSecondFinally,
}

impl ExceptionHandlerEnd {
    fn from_byte(b: u8) -> Result<Self, Error> {
        match b {
            0 => Ok(Self::EndOfBlock),
            1 => Ok(Self::EndOfFirstFinally),
            2 => Ok(Self::EndOfExcept),
            3 => Ok(Self::EndOfSecondFinally),
            other => Err(Error::UnknownBaseType { byte: other }),
        }
    }
}

/// One decoded IFPS instruction.
///
/// Variants and their operand layout mirror `uPSUtils.pas:122-297`
/// one-for-one. Each variant's doc cites the upstream constant
/// name and any extra-payload bytes beyond the opcode byte
/// itself.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum Opcode<'a> {
    /// `CM_A = 0` — `dest := src`. Two operands.
    Assign { dest: Operand<'a>, src: Operand<'a> },
    /// `CM_CA = 1` — `dest := dest <op> src`. CalcType byte +
    /// two operands.
    CalculateAssign {
        op: CalcOp,
        dest: Operand<'a>,
        src: Operand<'a>,
    },
    /// `CM_P = 2` — push variable.
    Push { var: Operand<'a> },
    /// `CM_PV = 3` — push var-by-reference.
    PushVar { var: Operand<'a> },
    /// `CM_PO = 4` — pop top of stack. No operands.
    Pop,
    /// `Cm_C = 5` — call procedure by index.
    Call { proc_no: u32 },
    /// `Cm_G = 6` — unconditional goto, signed PC-relative
    /// offset from end-of-instruction.
    Goto { offset: i32 },
    /// `Cm_CG = 7` — `if pop() then goto`. Unsigned PC-relative
    /// offset + condition operand.
    CondGoto { offset: u32, cond: Operand<'a> },
    /// `Cm_CNG = 8` — `if not pop() then goto`. Same shape as
    /// `CondGoto`.
    CondNotGoto { offset: u32, cond: Operand<'a> },
    /// `Cm_R = 9` — return from procedure.
    Return,
    /// `Cm_ST = 10` — set stack type at offset.
    SetStackType {
        new_type: u32,
        offset_from_base: u32,
    },
    /// `Cm_Pt = 11` — push a typed temporary onto the stack.
    PushType { type_no: u32 },
    /// `CM_CO = 12` — compare two operands and store the
    /// boolean result into `into`.
    Compare {
        op: CompareOp,
        into: Operand<'a>,
        lhs: Operand<'a>,
        rhs: Operand<'a>,
    },
    /// `Cm_cv = 13` — call procedure whose index is the
    /// runtime value of `var`.
    CallVar { var: Operand<'a> },
    /// `cm_sp = 14` — `dest := @src` (set pointer).
    SetPointer { dest: Operand<'a>, src: Operand<'a> },
    /// `cm_bn = 15` — boolean NOT in place.
    BoolNot { var: Operand<'a> },
    /// `cm_vm = 16` — arithmetic negation in place.
    Negate { var: Operand<'a> },
    /// `cm_sf = 17` — set the saved compare flag from `var`,
    /// optionally inverted.
    SetFlag { var: Operand<'a>, invert: bool },
    /// `cm_fg = 18` — unconditional goto if the saved compare
    /// flag is set. Absolute target offset.
    FlagGoto { target: u32 },
    /// `cm_puexh = 19` — push a four-section exception handler
    /// frame (try/finally/except/finally2).
    PushExceptionHandler {
        finally_offset: u32,
        exception_offset: u32,
        finally2_offset: u32,
        end_of_block: u32,
    },
    /// `cm_poexh = 20` — pop one section of an exception
    /// handler frame.
    PopExceptionHandler { position: ExceptionHandlerEnd },
    /// `cm_in = 21` — bitwise NOT in place.
    IntegerNot { var: Operand<'a> },
    /// `cm_spc = 22` — copy stack-pointer state.
    SetStackPointerToCopy { target: u32 },
    /// `cm_inc = 23` — increment in place.
    Inc { var: Operand<'a> },
    /// `cm_dec = 24` — decrement in place.
    Dec { var: Operand<'a> },
    /// `Cm_PG = 25` — pop one stack slot then goto.
    PopAndGoto { offset: i32 },
    /// `Cm_P2G = 26` — pop two stack slots then goto.
    Pop2AndGoto { offset: i32 },
    /// `cm_nop = 255` — no operation.
    Nop,
}

impl Opcode<'_> {
    /// Numeric opcode byte (the leading byte of the wire form).
    pub fn raw_byte(&self) -> u8 {
        match self {
            Self::Assign { .. } => 0,
            Self::CalculateAssign { .. } => 1,
            Self::Push { .. } => 2,
            Self::PushVar { .. } => 3,
            Self::Pop => 4,
            Self::Call { .. } => 5,
            Self::Goto { .. } => 6,
            Self::CondGoto { .. } => 7,
            Self::CondNotGoto { .. } => 8,
            Self::Return => 9,
            Self::SetStackType { .. } => 10,
            Self::PushType { .. } => 11,
            Self::Compare { .. } => 12,
            Self::CallVar { .. } => 13,
            Self::SetPointer { .. } => 14,
            Self::BoolNot { .. } => 15,
            Self::Negate { .. } => 16,
            Self::SetFlag { .. } => 17,
            Self::FlagGoto { .. } => 18,
            Self::PushExceptionHandler { .. } => 19,
            Self::PopExceptionHandler { .. } => 20,
            Self::IntegerNot { .. } => 21,
            Self::SetStackPointerToCopy { .. } => 22,
            Self::Inc { .. } => 23,
            Self::Dec { .. } => 24,
            Self::PopAndGoto { .. } => 25,
            Self::Pop2AndGoto { .. } => 26,
            Self::Nop => 255,
        }
    }
}

/// Reads one instruction at `reader`'s cursor, returning the
/// decoded [`Opcode`].
pub(crate) fn parse_opcode<'a>(
    reader: &mut Reader<'a>,
    types: &[Type<'a>],
) -> Result<Opcode<'a>, Error> {
    let raw = reader.u8("opcode byte")?;
    let op = match raw {
        0 => Opcode::Assign {
            dest: parse_operand(reader, types)?,
            src: parse_operand(reader, types)?,
        },
        1 => {
            let calc = CalcOp::from_byte(reader.u8("CalcType")?)?;
            let dest = parse_operand(reader, types)?;
            let src = parse_operand(reader, types)?;
            Opcode::CalculateAssign {
                op: calc,
                dest,
                src,
            }
        }
        2 => Opcode::Push {
            var: parse_operand(reader, types)?,
        },
        3 => Opcode::PushVar {
            var: parse_operand(reader, types)?,
        },
        4 => Opcode::Pop,
        5 => Opcode::Call {
            proc_no: reader.u32_le("Call ProcNo")?,
        },
        6 => Opcode::Goto {
            offset: reader.i32_le("Goto offset")?,
        },
        7 => Opcode::CondGoto {
            offset: reader.u32_le("CondGoto offset")?,
            cond: parse_operand(reader, types)?,
        },
        8 => Opcode::CondNotGoto {
            offset: reader.u32_le("CondNotGoto offset")?,
            cond: parse_operand(reader, types)?,
        },
        9 => Opcode::Return,
        10 => Opcode::SetStackType {
            new_type: reader.u32_le("SetStackType NewType")?,
            offset_from_base: reader.u32_le("SetStackType OffsetFromBase")?,
        },
        11 => Opcode::PushType {
            type_no: reader.u32_le("PushType FType")?,
        },
        12 => {
            let cmp = CompareOp::from_byte(reader.u8("CompareType")?)?;
            let into = parse_operand(reader, types)?;
            let lhs = parse_operand(reader, types)?;
            let rhs = parse_operand(reader, types)?;
            Opcode::Compare {
                op: cmp,
                into,
                lhs,
                rhs,
            }
        }
        13 => Opcode::CallVar {
            var: parse_operand(reader, types)?,
        },
        14 => Opcode::SetPointer {
            dest: parse_operand(reader, types)?,
            src: parse_operand(reader, types)?,
        },
        15 => Opcode::BoolNot {
            var: parse_operand(reader, types)?,
        },
        16 => Opcode::Negate {
            var: parse_operand(reader, types)?,
        },
        17 => {
            let var = parse_operand(reader, types)?;
            let invert = reader.u8("SetFlag DoNot")? != 0;
            Opcode::SetFlag { var, invert }
        }
        18 => Opcode::FlagGoto {
            target: reader.u32_le("FlagGoto Where")?,
        },
        19 => Opcode::PushExceptionHandler {
            finally_offset: reader.u32_le("ExceptionHandler FinallyOffset")?,
            exception_offset: reader.u32_le("ExceptionHandler ExceptionOffset")?,
            finally2_offset: reader.u32_le("ExceptionHandler Finally2Offset")?,
            end_of_block: reader.u32_le("ExceptionHandler EndOfBlock")?,
        },
        20 => Opcode::PopExceptionHandler {
            position: ExceptionHandlerEnd::from_byte(reader.u8("PopExceptionHandler Position")?)?,
        },
        21 => Opcode::IntegerNot {
            var: parse_operand(reader, types)?,
        },
        22 => Opcode::SetStackPointerToCopy {
            target: reader.u32_le("SetStackPointerToCopy Where")?,
        },
        23 => Opcode::Inc {
            var: parse_operand(reader, types)?,
        },
        24 => Opcode::Dec {
            var: parse_operand(reader, types)?,
        },
        25 => Opcode::PopAndGoto {
            offset: reader.i32_le("PopAndGoto NewPosition")?,
        },
        26 => Opcode::Pop2AndGoto {
            offset: reader.i32_le("Pop2AndGoto NewPosition")?,
        },
        255 => Opcode::Nop,
        other => return Err(Error::UnknownBaseType { byte: other }),
    };
    Ok(op)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operand::VarRef;

    fn put_le32(out: &mut Vec<u8>, v: u32) {
        out.extend_from_slice(&v.to_le_bytes());
    }

    fn put_var(out: &mut Vec<u8>, vt: u8, param: u32) {
        out.push(vt);
        put_le32(out, param);
    }

    #[test]
    fn parses_pop_and_return() {
        let buf = vec![4u8];
        let mut r = Reader::new(&buf);
        assert_eq!(parse_opcode(&mut r, &[]).unwrap(), Opcode::Pop);

        let buf = vec![9u8];
        let mut r = Reader::new(&buf);
        assert_eq!(parse_opcode(&mut r, &[]).unwrap(), Opcode::Return);

        let buf = vec![255u8];
        let mut r = Reader::new(&buf);
        assert_eq!(parse_opcode(&mut r, &[]).unwrap(), Opcode::Nop);
    }

    #[test]
    fn parses_call() {
        let mut buf = vec![5u8];
        put_le32(&mut buf, 42);
        let mut r = Reader::new(&buf);
        assert_eq!(
            parse_opcode(&mut r, &[]).unwrap(),
            Opcode::Call { proc_no: 42 },
        );
    }

    #[test]
    fn parses_assign_with_two_var_operands() {
        let mut buf = vec![0u8]; // CM_A
        put_var(&mut buf, 0, 1); // dest = global #1
        put_var(&mut buf, 0, 2); // src  = global #2
        let mut r = Reader::new(&buf);
        let op = parse_opcode(&mut r, &[]).unwrap();
        assert_eq!(
            op,
            Opcode::Assign {
                dest: Operand::Var(VarRef::Global(1)),
                src: Operand::Var(VarRef::Global(2)),
            },
        );
    }

    #[test]
    fn parses_calc_assign() {
        let mut buf = vec![1u8, 2u8]; // CM_CA, CalcType=Mul
        put_var(&mut buf, 0, 0);
        put_var(&mut buf, 0, 1);
        let mut r = Reader::new(&buf);
        let op = parse_opcode(&mut r, &[]).unwrap();
        assert!(matches!(
            op,
            Opcode::CalculateAssign {
                op: CalcOp::Mul,
                ..
            },
        ));
    }

    #[test]
    fn parses_compare() {
        let mut buf = vec![12u8, 5u8]; // CM_CO, CompareType=Equal
        put_var(&mut buf, 0, 0); // into
        put_var(&mut buf, 0, 1); // lhs
        put_var(&mut buf, 0, 2); // rhs
        let mut r = Reader::new(&buf);
        let op = parse_opcode(&mut r, &[]).unwrap();
        assert!(matches!(
            op,
            Opcode::Compare {
                op: CompareOp::Equal,
                ..
            },
        ));
    }

    #[test]
    fn parses_exception_handler() {
        let mut buf = vec![19u8];
        put_le32(&mut buf, 100);
        put_le32(&mut buf, 200);
        put_le32(&mut buf, 300);
        put_le32(&mut buf, 400);
        let mut r = Reader::new(&buf);
        let op = parse_opcode(&mut r, &[]).unwrap();
        assert_eq!(
            op,
            Opcode::PushExceptionHandler {
                finally_offset: 100,
                exception_offset: 200,
                finally2_offset: 300,
                end_of_block: 400,
            },
        );

        let buf = vec![20u8, 2u8];
        let mut r = Reader::new(&buf);
        assert_eq!(
            parse_opcode(&mut r, &[]).unwrap(),
            Opcode::PopExceptionHandler {
                position: ExceptionHandlerEnd::EndOfExcept,
            },
        );
    }

    #[test]
    fn rejects_unknown_opcode() {
        let buf = vec![100u8];
        let mut r = Reader::new(&buf);
        assert!(parse_opcode(&mut r, &[]).is_err());
    }
}
