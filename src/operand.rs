//! Operand (`TPSVariable`) wire decoding.
//!
//! Source: `TPSExec.ReadVariable` in `uPSRuntime.pas:6700-6960`.
//! Wire form is `VarType: u8 + Param: u32` followed by extra
//! bytes that vary per `VarType`:
//!
//! - **0** - direct global / stack variable reference. 5 bytes.
//! - **1** - typed temporary or literal. 5 bytes (type ref) plus
//!   per-`BaseType` payload (see [`crate::Literal`]).
//! - **2** - `base[const_index]` for record fields and
//!   compile-time-fixed array indices. 9 bytes (5 + 4).
//! - **3** - `base[var_index]` for dynamic array indices that
//!   read another variable's value at runtime. 9 bytes (5 + 4).
//!
//! The `Param` value of a `VarType=0`/`2`/`3` outer reference
//! splits at `PSAddrStackStart = 0x60000000`
//! (`uPSUtils.pas:22`):
//!
//! - `Param < 0x40000000` (`PSAddrNegativeStackStart`) - global
//!   var index.
//! - `Param >= 0x60000000` - stack-relative offset, with the
//!   actual offset = `Param - 0x60000000` (the runtime adds
//!   `FCurrStackBase` and subtracts `PSAddrStackStart`).
//! - The `0x40000000..0x60000000` window is treated as
//!   stack-relative by upstream too - same formula. We surface
//!   anything `>= 0x40000000` as [`VarRef::Stack`].

use crate::{
    error::Error,
    literal::{self, Literal},
    reader::Reader,
    ty::Type,
};

/// `PSAddrStackStart` from `uPSUtils.pas:22`.
const PS_ADDR_STACK_START: u32 = 0x6000_0000;

/// `PSAddrNegativeStackStart` from `uPSUtils.pas:24`. The
/// boundary at which a `Param` switches from "global var index"
/// to "stack-relative offset". Anything `>= 0x40000000` is
/// stack-relative.
const PS_ADDR_NEGATIVE_STACK_START: u32 = 0x4000_0000;

/// A direct variable reference resolved into either the global
/// table or a stack slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VarRef {
    /// Index into the global-variable table. The runtime
    /// validates `index < FGlobalVars.Count` at execute time -
    /// we don't validate at parse time because the global count
    /// is fixed by the `VarCount` header field, not the operand
    /// stream.
    Global(u32),
    /// Stack-relative offset. The wire form stored
    /// `PS_ADDR_STACK_START + offset`; we surface the offset
    /// directly. Negative offsets address parameters; positive
    /// offsets address locals.
    Stack(i64),
}

impl VarRef {
    /// Decodes a raw `Param` value into `Global` or `Stack`.
    pub fn from_param(param: u32) -> Self {
        if param < PS_ADDR_NEGATIVE_STACK_START {
            Self::Global(param)
        } else {
            // Upstream computes
            // `-PSAddrStackStart + FCurrStackBase + Param` to get
            // the actual stack index. The portion we know at
            // parse time is `Param - PS_ADDR_STACK_START`; the
            // runtime adds `FCurrStackBase`.
            Self::Stack(i64::from(param).wrapping_sub(i64::from(PS_ADDR_STACK_START)))
        }
    }
}

/// One wire-decoded operand.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Operand<'a> {
    /// Direct variable reference (`VarType=0`).
    Var(VarRef),
    /// Typed temporary / literal (`VarType=1`). The `type_no`
    /// is the type-table index and `value` carries the decoded
    /// per-`BaseType` payload.
    Literal {
        /// Type-table index of the literal's static type.
        type_no: u32,
        /// Decoded payload.
        value: Literal<'a>,
    },
    /// `base[const_index]` (`VarType=2`) - compile-time-fixed
    /// record-field or static-array index.
    Indexed {
        /// Base var being indexed.
        base: VarRef,
        /// Constant index into the base's record fields or
        /// array elements, depending on the base's resolved
        /// type. We don't resolve which kind here - the index
        /// is always 4 wire bytes.
        sub_index: u32,
    },
    /// `base[var_index]` (`VarType=3`) - dynamic array index
    /// read at runtime from another variable.
    DynamicIndexed {
        /// Base var being indexed.
        base: VarRef,
        /// Var ref whose runtime u32 value supplies the actual
        /// index.
        index_var: VarRef,
    },
}

impl Operand<'_> {
    /// Every variable the operand names: the variable itself, an indexed
    /// operand's base, and a dynamic index's index variable. A literal names
    /// none.
    pub fn var_refs(&self) -> impl Iterator<Item = VarRef> {
        let (first, second) = match *self {
            Self::Var(var) => (Some(var), None),
            Self::Indexed { base, .. } => (Some(base), None),
            Self::DynamicIndexed { base, index_var } => (Some(base), Some(index_var)),
            Self::Literal { .. } => (None, None),
        };
        first.into_iter().chain(second)
    }
}

/// Reads one operand at `reader`'s cursor, advancing past it.
pub(crate) fn parse_operand<'a>(
    reader: &mut Reader<'a>,
    types: &[Type<'a>],
) -> Result<Operand<'a>, Error> {
    let var_type = reader.u8("operand VarType")?;
    let param = reader.u32_le("operand Param")?;
    let operand = match var_type {
        0 => Operand::Var(VarRef::from_param(param)),
        1 => {
            let count = u32::try_from(types.len()).unwrap_or(u32::MAX);
            let ty = types
                .get(param as usize)
                .ok_or(Error::TypeIndexOutOfRange {
                    index: param,
                    count,
                })?;
            let value = literal::parse_literal(reader, ty)?;
            Operand::Literal {
                type_no: param,
                value,
            }
        }
        2 => {
            let sub_index = reader.u32_le("operand sub_index")?;
            Operand::Indexed {
                base: VarRef::from_param(param),
                sub_index,
            }
        }
        3 => {
            let inner = reader.u32_le("operand dynamic-index Param")?;
            Operand::DynamicIndexed {
                base: VarRef::from_param(param),
                index_var: VarRef::from_param(inner),
            }
        }
        // Upstream's `ReadVariable` falls through to `else False`
        // for any VarType outside [0..3].
        other => return Err(Error::UnknownBaseType { byte: other }),
    };
    Ok(operand)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ty::{BaseType, Type, TypeBody};

    fn put_le32(out: &mut Vec<u8>, v: u32) {
        out.extend_from_slice(&v.to_le_bytes());
    }

    fn ty(base_type: BaseType, body: TypeBody<'static>) -> Type<'static> {
        Type {
            base_type,
            body,
            export_name: None,
            attributes: Vec::new(),
        }
    }

    #[test]
    fn parses_global_var_ref() {
        let mut buf = vec![0u8]; // VarType=0
        put_le32(&mut buf, 7);
        let mut r = Reader::new(&buf);
        let op = parse_operand(&mut r, &[]).unwrap();
        assert_eq!(op, Operand::Var(VarRef::Global(7)));
    }

    #[test]
    fn parses_stack_var_ref() {
        let mut buf = vec![0u8];
        put_le32(&mut buf, PS_ADDR_STACK_START + 4);
        let mut r = Reader::new(&buf);
        let op = parse_operand(&mut r, &[]).unwrap();
        assert_eq!(op, Operand::Var(VarRef::Stack(4)));
    }

    #[test]
    fn parses_typed_literal_u32() {
        let mut buf = vec![1u8];
        put_le32(&mut buf, 0); // type ref
        put_le32(&mut buf, 0xCAFE_BABE);
        let types = [ty(BaseType::U32, TypeBody::Bare)];
        let mut r = Reader::new(&buf);
        let op = parse_operand(&mut r, &types).unwrap();
        assert!(matches!(
            op,
            Operand::Literal {
                type_no: 0,
                value: Literal::U32(0xCAFE_BABE),
            },
        ));
    }

    #[test]
    fn parses_indexed_record_field() {
        let mut buf = vec![2u8];
        put_le32(&mut buf, 3); // base = global #3
        put_le32(&mut buf, 1); // sub_index = field 1
        let mut r = Reader::new(&buf);
        let op = parse_operand(&mut r, &[]).unwrap();
        assert_eq!(
            op,
            Operand::Indexed {
                base: VarRef::Global(3),
                sub_index: 1,
            },
        );
    }

    #[test]
    fn parses_dynamic_indexed() {
        let mut buf = vec![3u8];
        put_le32(&mut buf, 5); // base = global #5
        put_le32(&mut buf, PS_ADDR_STACK_START + 8); // index = stack +8
        let mut r = Reader::new(&buf);
        let op = parse_operand(&mut r, &[]).unwrap();
        assert_eq!(
            op,
            Operand::DynamicIndexed {
                base: VarRef::Global(5),
                index_var: VarRef::Stack(8),
            },
        );
    }

    #[test]
    fn rejects_unknown_var_type() {
        let mut buf = vec![9u8];
        put_le32(&mut buf, 0);
        let mut r = Reader::new(&buf);
        assert!(parse_operand(&mut r, &[]).is_err());
    }
}
