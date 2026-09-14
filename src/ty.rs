//! Type-table walker - `LoadTypes` in
//! `uPSRuntime.pas:2538-2799`.
//!
//! Each `TypeCount` slot starts with a 1-byte
//! `BaseType`-plus-flag byte. Bit 7 of the byte signals "has
//! export name"; the low 7 bits are the actual `BaseType`
//! constant (`uPSUtils.pas:46-118`). The on-disk constants only
//! reach `btU64 = 29` - `btType = 130`, `btEnum = 129`, and
//! `btExtClass = 131` are runtime-only sentinels and never appear
//! in serialized data.
//!
//! Per-`BaseType` payload follows the leading byte. After the
//! payload, a 4-byte-prefixed export name (when the flag is set)
//! and a build-21+ attribute block round out the entry.

use crate::{attribute::Attribute, error::Error, reader::Reader};

/// PascalScript on-disk `BaseType` constant set.
///
/// Source: `uPSUtils.pas:46-112` (constants 0-29). The runtime
/// sentinels `btType = 130`, `btEnum = 129`, `btExtClass = 131`
/// are excluded - they never appear in serialized data per
/// `LoadTypes`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum BaseType {
    ReturnAddress,
    U8,
    S8,
    U16,
    S16,
    U32,
    S32,
    Single,
    Double,
    Extended,
    String,
    Record,
    Array,
    Pointer,
    PChar,
    ResourcePointer,
    Variant,
    S64,
    Char,
    WideString,
    WideChar,
    ProcPtr,
    StaticArray,
    Set,
    Currency,
    Class,
    Interface,
    NotificationVariant,
    UnicodeString,
    U64,
}

impl BaseType {
    /// Decodes the on-disk byte. Bit 7 ("has export name") must
    /// be stripped by the caller before invocation.
    fn from_byte(byte: u8) -> Result<Self, Error> {
        let bt = match byte {
            0 => Self::ReturnAddress,
            1 => Self::U8,
            2 => Self::S8,
            3 => Self::U16,
            4 => Self::S16,
            5 => Self::U32,
            6 => Self::S32,
            7 => Self::Single,
            8 => Self::Double,
            9 => Self::Extended,
            10 => Self::String,
            11 => Self::Record,
            12 => Self::Array,
            13 => Self::Pointer,
            14 => Self::PChar,
            15 => Self::ResourcePointer,
            16 => Self::Variant,
            17 => Self::S64,
            18 => Self::Char,
            19 => Self::WideString,
            20 => Self::WideChar,
            21 => Self::ProcPtr,
            22 => Self::StaticArray,
            23 => Self::Set,
            24 => Self::Currency,
            25 => Self::Class,
            26 => Self::Interface,
            27 => Self::NotificationVariant,
            28 => Self::UnicodeString,
            29 => Self::U64,
            other => return Err(Error::UnknownBaseType { byte: other }),
        };
        Ok(bt)
    }
}

/// Per-entry payload that varies by [`BaseType`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TypeBody<'a> {
    /// No type-specific payload (numeric primitives, strings,
    /// pointers, variants).
    Bare,
    /// `btClass` - class-name string (≤ 255 bytes).
    Class {
        /// Raw class-name bytes (ASCII / Windows-1252 in
        /// upstream).
        name: &'a [u8],
    },
    /// `btProcPtr` - variable-length parameter-info string.
    ProcPtr {
        /// Raw param-info bytes.
        param_info: &'a [u8],
    },
    /// `btInterface` - 16-byte interface GUID.
    Interface {
        /// Raw GUID bytes (Microsoft byte order - this struct
        /// does NOT canonicalize to RFC 4122).
        guid: [u8; 16],
    },
    /// `btSet` - bit count (≤ 256).
    Set {
        /// Number of bits the set carries on the wire.
        bit_size: u32,
    },
    /// `btArray` - dynamic array; element-type index.
    Array {
        /// Index into the type table for the element type.
        element_type: u32,
    },
    /// `btStaticArray` - fixed-length array.
    StaticArray {
        /// Index into the type table for the element type.
        element_type: u32,
        /// Element count.
        size: u32,
        /// Starting index of the array (Pascal arrays may begin
        /// at non-zero indices).
        start_offset: u32,
    },
    /// `btRecord` - list of field-type indices.
    Record {
        /// One type-table index per field, in declaration order.
        field_types: Vec<u32>,
    },
}

/// One entry in the type table.
#[derive(Clone, Debug)]
pub struct Type<'a> {
    /// Decoded base type.
    pub base_type: BaseType,
    /// Type-specific payload.
    pub body: TypeBody<'a>,
    /// Export name if the entry has one (high bit of the leading
    /// byte was set), else `None`.
    pub export_name: Option<&'a [u8]>,
    /// Build-21+ attributes attached to this type, or empty when
    /// the block was absent or `count == 0`.
    pub attributes: Vec<Attribute<'a>>,
}

const HAS_EXPORT_NAME: u8 = 0x80;
const MAX_NAME_LEN: u32 = 255;
const MAX_SET_BIT_SIZE: u32 = 256;

/// Parses one type-table entry's body + export name (no
/// attribute block), advancing `reader`. The caller is expected
/// to push the resulting [`Type`] onto the type table and
/// **then** invoke
/// [`crate::attribute::parse_block`] for builds
/// ≥ 21 - matching upstream's `LoadTypes` push-then-attr order
/// (`uPSRuntime.pas:2789-2798`).
pub(crate) fn parse_type<'a>(reader: &mut Reader<'a>, so_far: u32) -> Result<Type<'a>, Error> {
    let raw = reader.u8("type BaseType")?;
    let has_name = (raw & HAS_EXPORT_NAME) != 0;
    let base_byte = raw & !HAS_EXPORT_NAME;
    let base_type = BaseType::from_byte(base_byte)?;
    let body = parse_body(reader, base_type, so_far)?;
    let export_name = if has_name {
        let len = reader.u32_le("type export-name length")?;
        if len > MAX_NAME_LEN.saturating_mul(1024) {
            return Err(Error::Overflow {
                what: "type export-name length",
            });
        }
        let bytes = reader.take(len as usize, "type export-name bytes")?;
        Some(bytes)
    } else {
        None
    };
    Ok(Type {
        base_type,
        body,
        export_name,
        attributes: Vec::new(),
    })
}

fn parse_body<'a>(
    reader: &mut Reader<'a>,
    base_type: BaseType,
    so_far: u32,
) -> Result<TypeBody<'a>, Error> {
    let body = match base_type {
        BaseType::Class => {
            let len = reader.u32_le("class name length")?;
            if len > MAX_NAME_LEN {
                return Err(Error::Overflow {
                    what: "class name length",
                });
            }
            let name = reader.take(len as usize, "class name bytes")?;
            TypeBody::Class { name }
        }
        BaseType::ProcPtr => {
            let len = reader.u32_le("proc-ptr param-info length")?;
            if len > MAX_NAME_LEN {
                return Err(Error::Overflow {
                    what: "proc-ptr param-info length",
                });
            }
            let param_info = reader.take(len as usize, "proc-ptr param-info bytes")?;
            TypeBody::ProcPtr { param_info }
        }
        BaseType::Interface => {
            let guid = reader.array::<16>("interface GUID")?;
            TypeBody::Interface { guid }
        }
        BaseType::Set => {
            let bit_size = reader.u32_le("set bit size")?;
            if bit_size > MAX_SET_BIT_SIZE {
                return Err(Error::Overflow {
                    what: "set bit size",
                });
            }
            TypeBody::Set { bit_size }
        }
        BaseType::Array => {
            let element_type = reader.u32_le("array element type ref")?;
            check_type_ref(element_type, so_far)?;
            TypeBody::Array { element_type }
        }
        BaseType::StaticArray => {
            let element_type = reader.u32_le("static-array element type ref")?;
            check_type_ref(element_type, so_far)?;
            let size = reader.u32_le("static-array size")?;
            let start_offset = reader.u32_le("static-array start offset")?;
            TypeBody::StaticArray {
                element_type,
                size,
                start_offset,
            }
        }
        BaseType::Record => {
            let count = reader.u32_le("record field count")?;
            if count == 0 {
                return Err(Error::Overflow {
                    what: "record field count must be > 0",
                });
            }
            // Cap to prevent malformed input from forcing huge
            // allocations.
            if count > MAX_NAME_LEN.saturating_mul(64) {
                return Err(Error::Overflow {
                    what: "record field count",
                });
            }
            let mut field_types = Vec::with_capacity(count as usize);
            for _ in 0..count {
                let ref_idx = reader.u32_le("record field type ref")?;
                check_type_ref(ref_idx, so_far)?;
                field_types.push(ref_idx);
            }
            TypeBody::Record { field_types }
        }
        _ => TypeBody::Bare,
    };
    Ok(body)
}

fn check_type_ref(idx: u32, so_far: u32) -> Result<(), Error> {
    // Upstream rejects forward references too - a type can only
    // refer to entries that have already been defined.
    if idx >= so_far {
        return Err(Error::TypeIndexOutOfRange {
            index: idx,
            count: so_far,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_le32(out: &mut Vec<u8>, v: u32) {
        out.extend_from_slice(&v.to_le_bytes());
    }

    #[test]
    fn parses_bare_u32() {
        let buf = vec![5]; // btU32
        let mut r = Reader::new(&buf);
        let ty = parse_type(&mut r, 0).unwrap();
        assert_eq!(ty.base_type, BaseType::U32);
        assert!(matches!(ty.body, TypeBody::Bare));
        assert!(ty.export_name.is_none());
    }

    #[test]
    fn parses_array_with_export_name() {
        let mut buf = Vec::new();
        buf.push(12 | HAS_EXPORT_NAME); // btArray + name flag
        put_le32(&mut buf, 0); // element type ref → so_far = 1
        put_le32(&mut buf, 5); // export-name length
        buf.extend_from_slice(b"Items");
        let mut r = Reader::new(&buf);
        let ty = parse_type(&mut r, 1).unwrap();
        assert_eq!(ty.base_type, BaseType::Array);
        assert!(matches!(ty.body, TypeBody::Array { element_type: 0 }));
        assert_eq!(ty.export_name, Some(&b"Items"[..]));
    }

    #[test]
    fn rejects_forward_type_ref() {
        let mut buf = Vec::new();
        buf.push(12); // btArray
        put_le32(&mut buf, 99); // unresolved forward ref
        let mut r = Reader::new(&buf);
        let err = parse_type(&mut r, 1).unwrap_err();
        assert!(matches!(err, Error::TypeIndexOutOfRange { .. }));
    }

    #[test]
    fn parses_record() {
        let mut buf = Vec::new();
        buf.push(11); // btRecord
        put_le32(&mut buf, 2); // 2 fields
        put_le32(&mut buf, 0);
        put_le32(&mut buf, 1);
        let mut r = Reader::new(&buf);
        let ty = parse_type(&mut r, 2).unwrap();
        match ty.body {
            TypeBody::Record { field_types } => assert_eq!(field_types, vec![0, 1]),
            other => panic!("expected Record, got {other:?}"),
        }
    }
}
