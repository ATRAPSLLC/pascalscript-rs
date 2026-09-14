//! Typed-literal payload decoding.
//!
//! Two callers share this module: attribute fields
//! (`uPSRuntime.pas:2370-2497`) and operand decoding for
//! `VarType=1` typed temporaries (`uPSRuntime.pas:6753-6900+`).
//! Both interpret a 4-byte type-table reference followed by a
//! per-`BaseType` payload using the same encoding rules.
//!
//! Variants here cover every `BaseType` upstream actually
//! serializes; the rest (Record, Array, Pointer, Variant, Class,
//! Interface, etc.) trigger `erInvalidType` on the wire and are
//! mapped to [`Error::UnknownBaseType`] at parse time.

use crate::{
    error::Error,
    reader::Reader,
    ty::{BaseType, Type, TypeBody},
};

/// Decoded payload of a typed-value slot.
///
/// Every variant pairs with a specific `BaseType` from the
/// referenced type-table entry. See the doc on each variant for
/// the wire size.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Literal<'a> {
    /// `btSet` - `ceil(bit_size / 8)` bytes (size derived from
    /// the referenced type's [`TypeBody::Set`]).
    Set(&'a [u8]),
    /// `btU8` (1 byte).
    U8(u8),
    /// `btS8` (1 byte, signed).
    S8(i8),
    /// `btChar` (1 byte, ANSI).
    Char(u8),
    /// `btU16` (2 bytes).
    U16(u16),
    /// `btS16` (2 bytes, signed).
    S16(i16),
    /// `btWideChar` (2 bytes, UTF-16 code unit).
    WideChar(u16),
    /// `btU32` (4 bytes).
    U32(u32),
    /// `btS32` (4 bytes, signed).
    S32(i32),
    /// `btProcPtr` (4 bytes - proc-table index).
    ProcPtr(u32),
    /// `btSingle` (4 bytes IEEE-754 binary32, raw).
    Single([u8; 4]),
    /// `btU64` (8 bytes).
    U64(u64),
    /// `btS64` (8 bytes, signed).
    S64(i64),
    /// `btDouble` (8 bytes IEEE-754 binary64, raw).
    Double([u8; 8]),
    /// `btCurrency` (8 bytes - Delphi `Currency`, scaled by 1e4).
    Currency([u8; 8]),
    /// `btExtended` (10 bytes - Delphi `Extended`, x86 80-bit).
    Extended([u8; 10]),
    /// `btString` / `btPChar` - ANSI / Windows-1252 bytes
    /// (length-prefixed on the wire; we surface the bytes only).
    String(&'a [u8]),
    /// `btWideString` - UTF-16LE bytes. The on-disk length is
    /// the count of UTF-16 code units; the byte slice has length
    /// `2 * count`.
    WideString(&'a [u8]),
    /// `btUnicodeString` - UTF-16LE bytes. Same encoding as
    /// `WideString`; PascalScript distinguishes the type but the
    /// wire form is identical.
    UnicodeString(&'a [u8]),
}

impl Literal<'_> {
    /// Returns an ANSI string literal as UTF-8 when the payload is valid UTF-8.
    pub fn as_string(&self) -> Option<&str> {
        match self {
            Self::String(bytes) => core::str::from_utf8(bytes).ok(),
            _ => None,
        }
    }

    /// Returns a floating-point literal as `f64` when representable.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Single(bytes) => Some(f64::from(f32::from_le_bytes(*bytes))),
            Self::Double(bytes) => Some(f64::from_le_bytes(*bytes)),
            _ => None,
        }
    }

    /// Returns a Delphi `Currency` literal's raw scaled integer value.
    pub fn as_currency(&self) -> Option<i64> {
        match self {
            Self::Currency(bytes) => Some(i64::from_le_bytes(*bytes)),
            _ => None,
        }
    }
}

const MAX_LEN: u32 = 0x4000_0000;

/// Reads a typed-literal payload for the given referenced type,
/// advancing `reader`.
///
/// Caller is responsible for having already consumed the 4-byte
/// type-table index that selects `ty`.
pub(crate) fn parse_literal<'a>(
    reader: &mut Reader<'a>,
    ty: &Type<'a>,
) -> Result<Literal<'a>, Error> {
    let value = match ty.base_type {
        BaseType::Set => {
            let bit_size = match ty.body {
                TypeBody::Set { bit_size } => bit_size,
                _ => {
                    return Err(Error::UnknownBaseType {
                        byte: BaseType::Set as u8,
                    });
                }
            };
            let byte_size = bit_size.checked_add(7).ok_or(Error::Overflow {
                what: "literal Set byte size",
            })? / 8;
            let bytes = reader.take(byte_size as usize, "literal Set bytes")?;
            Literal::Set(bytes)
        }
        BaseType::U8 => Literal::U8(reader.u8("literal U8")?),
        BaseType::S8 => {
            let raw = reader.u8("literal S8")?;
            #[allow(clippy::cast_possible_wrap)]
            {
                Literal::S8(raw as i8)
            }
        }
        BaseType::Char => Literal::Char(reader.u8("literal Char")?),
        BaseType::U16 => {
            let bytes = reader.array::<2>("literal U16")?;
            Literal::U16(u16::from_le_bytes(bytes))
        }
        BaseType::S16 => {
            let bytes = reader.array::<2>("literal S16")?;
            Literal::S16(i16::from_le_bytes(bytes))
        }
        BaseType::WideChar => {
            let bytes = reader.array::<2>("literal WideChar")?;
            Literal::WideChar(u16::from_le_bytes(bytes))
        }
        BaseType::U32 => Literal::U32(reader.u32_le("literal U32")?),
        BaseType::S32 => Literal::S32(reader.i32_le("literal S32")?),
        BaseType::ProcPtr => Literal::ProcPtr(reader.u32_le("literal ProcPtr")?),
        BaseType::Single => Literal::Single(reader.array::<4>("literal Single")?),
        BaseType::U64 => {
            let bytes = reader.array::<8>("literal U64")?;
            Literal::U64(u64::from_le_bytes(bytes))
        }
        BaseType::S64 => {
            let bytes = reader.array::<8>("literal S64")?;
            Literal::S64(i64::from_le_bytes(bytes))
        }
        BaseType::Double => Literal::Double(reader.array::<8>("literal Double")?),
        BaseType::Currency => Literal::Currency(reader.array::<8>("literal Currency")?),
        BaseType::Extended => Literal::Extended(reader.array::<10>("literal Extended")?),
        BaseType::PChar | BaseType::String => {
            let len = reader.u32_le("literal String length")?;
            if len > MAX_LEN {
                return Err(Error::Overflow {
                    what: "literal String length",
                });
            }
            let bytes = reader.take(len as usize, "literal String bytes")?;
            Literal::String(bytes)
        }
        BaseType::WideString => {
            let len = reader.u32_le("literal WideString length")?;
            let byte_count = (len as usize).checked_mul(2).ok_or(Error::Overflow {
                what: "literal WideString byte count",
            })?;
            let bytes = reader.take(byte_count, "literal WideString bytes")?;
            Literal::WideString(bytes)
        }
        BaseType::UnicodeString => {
            let len = reader.u32_le("literal UnicodeString length")?;
            let byte_count = (len as usize).checked_mul(2).ok_or(Error::Overflow {
                what: "literal UnicodeString byte count",
            })?;
            let bytes = reader.take(byte_count, "literal UnicodeString bytes")?;
            Literal::UnicodeString(bytes)
        }
        // Record / Array / Pointer / Variant / Class / Interface
        // / NotificationVariant / ReturnAddress: erInvalidType
        // upstream.
        other => return Err(Error::UnknownBaseType { byte: other as u8 }),
    };
    Ok(value)
}
