//! Attribute-block walker — `ReadAttributes` in
//! `uPSRuntime.pas:2333-2532`.
//!
//! Build-21+ attaches an inline attribute block at the end of
//! every type and proc entry (vars do not carry attributes — see
//! `LoadVars`, `uPSRuntime.pas:2936-2989`). The block layout is:
//!
//! ```text
//! count: u32
//! attribute[count]:
//!     name_len: u32 + name_bytes (ASCII identifier)
//!     field_count: u32
//!     field[field_count]:
//!         type_no: u32 (must be < types.len())
//!         payload: per-BaseType (see `AttributeFieldValue`)
//! ```
//!
//! Reading an attribute requires the type table parsed so far —
//! the per-field payload's size depends on the referenced type's
//! `BaseType` (and its body, in the `Set` case).

use crate::{
    error::Error,
    literal::{self, Literal},
    reader::Reader,
    ty::Type,
};

/// Backward-compat alias for the shared [`Literal`] enum.
///
/// Kept under the `attribute` module because callers think of
/// attribute fields in terms of "values", not "literals". Both
/// names point at the same enum.
pub type AttributeFieldValue<'a> = Literal<'a>;

/// One parsed attribute.
#[derive(Clone, Debug)]
pub struct Attribute<'a> {
    /// ASCII identifier — the attribute "name" the script
    /// declared, e.g. `Description`.
    pub name: &'a [u8],
    /// Field values in declaration order.
    pub fields: Vec<AttributeField<'a>>,
}

/// One field of an [`Attribute`].
#[derive(Clone, Debug)]
pub struct AttributeField<'a> {
    /// Index into the type table — describes the field's type.
    pub type_no: u32,
    /// Decoded wire value.
    pub value: Literal<'a>,
}

const MAX_NAME_LEN: u32 = 0x4000_0000;

/// Parses the attribute block at `reader`'s cursor into a vec of
/// [`Attribute`]s.
///
/// `types` is the type table parsed so far — including the
/// current entry, since upstream pushes the type onto `FTypes`
/// before reading its attribute block (`uPSRuntime.pas:2789-2798`).
/// Empty blocks (count == 0) return `Ok(vec![])`.
pub(crate) fn parse_block<'a>(
    reader: &mut Reader<'a>,
    types: &[Type<'a>],
) -> Result<Vec<Attribute<'a>>, Error> {
    let count = reader.u32_le("attribute block count")?;
    if count == 0 {
        return Ok(Vec::new());
    }
    if count > MAX_NAME_LEN {
        return Err(Error::Overflow {
            what: "attribute block count",
        });
    }
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        out.push(parse_attribute(reader, types)?);
    }
    Ok(out)
}

fn parse_attribute<'a>(
    reader: &mut Reader<'a>,
    types: &[Type<'a>],
) -> Result<Attribute<'a>, Error> {
    let name_len = reader.u32_le("attribute name length")?;
    if name_len > MAX_NAME_LEN {
        return Err(Error::Overflow {
            what: "attribute name length",
        });
    }
    let name = reader.take(name_len as usize, "attribute name bytes")?;
    let field_count = reader.u32_le("attribute field count")?;
    if field_count > MAX_NAME_LEN {
        return Err(Error::Overflow {
            what: "attribute field count",
        });
    }
    let mut fields = Vec::with_capacity(field_count as usize);
    for _ in 0..field_count {
        fields.push(parse_field(reader, types)?);
    }
    Ok(Attribute { name, fields })
}

fn parse_field<'a>(
    reader: &mut Reader<'a>,
    types: &[Type<'a>],
) -> Result<AttributeField<'a>, Error> {
    let type_no = reader.u32_le("attribute field TypeNo")?;
    let count = u32::try_from(types.len()).unwrap_or(u32::MAX);
    let ty = types
        .get(type_no as usize)
        .ok_or(Error::TypeIndexOutOfRange {
            index: type_no,
            count,
        })?;
    let value = literal::parse_literal(reader, ty)?;
    Ok(AttributeField { type_no, value })
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
    fn empty_block() {
        let buf = 0u32.to_le_bytes();
        let mut r = Reader::new(&buf);
        let attrs = parse_block(&mut r, &[]).unwrap();
        assert!(attrs.is_empty());
    }

    #[test]
    fn parses_single_attribute_with_u32_field() {
        let mut buf = Vec::new();
        put_le32(&mut buf, 1); // 1 attribute
        put_le32(&mut buf, 4); // name len
        buf.extend_from_slice(b"Test");
        put_le32(&mut buf, 1); // 1 field
        put_le32(&mut buf, 0); // type_no = 0
        put_le32(&mut buf, 0xDEAD_BEEF); // U32 payload
        let types = [ty(BaseType::U32, TypeBody::Bare)];
        let mut r = Reader::new(&buf);
        let attrs = parse_block(&mut r, &types).unwrap();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].name, b"Test");
        assert_eq!(attrs[0].fields.len(), 1);
        assert_eq!(
            attrs[0].fields[0].value,
            AttributeFieldValue::U32(0xDEAD_BEEF),
        );
    }

    #[test]
    fn parses_string_field() {
        let mut buf = Vec::new();
        put_le32(&mut buf, 1);
        put_le32(&mut buf, 4);
        buf.extend_from_slice(b"Desc");
        put_le32(&mut buf, 1);
        put_le32(&mut buf, 0); // type_no = 0
        put_le32(&mut buf, 5); // string len
        buf.extend_from_slice(b"hello");
        let types = [ty(BaseType::String, TypeBody::Bare)];
        let mut r = Reader::new(&buf);
        let attrs = parse_block(&mut r, &types).unwrap();
        assert_eq!(
            attrs[0].fields[0].value,
            AttributeFieldValue::String(b"hello")
        );
    }

    #[test]
    fn parses_set_field_with_correct_byte_size() {
        // 17-bit set → ceil(17/8) = 3 bytes.
        let mut buf = Vec::new();
        put_le32(&mut buf, 1);
        put_le32(&mut buf, 1);
        buf.push(b'S');
        put_le32(&mut buf, 1);
        put_le32(&mut buf, 0);
        buf.extend_from_slice(&[0xAA, 0xBB, 0x01]);
        let types = [ty(BaseType::Set, TypeBody::Set { bit_size: 17 })];
        let mut r = Reader::new(&buf);
        let attrs = parse_block(&mut r, &types).unwrap();
        assert_eq!(
            attrs[0].fields[0].value,
            AttributeFieldValue::Set(&[0xAA, 0xBB, 0x01][..]),
        );
    }

    #[test]
    fn rejects_unsupported_basetype() {
        // Record fields are erInvalidType in upstream.
        let mut buf = Vec::new();
        put_le32(&mut buf, 1);
        put_le32(&mut buf, 1);
        buf.push(b'X');
        put_le32(&mut buf, 1);
        put_le32(&mut buf, 0); // refers to record type
        let types = [ty(
            BaseType::Record,
            TypeBody::Record {
                field_types: vec![],
            },
        )];
        let mut r = Reader::new(&buf);
        let err = parse_block(&mut r, &types).unwrap_err();
        assert!(matches!(err, Error::UnknownBaseType { .. }));
    }

    #[test]
    fn rejects_out_of_range_type_ref() {
        let mut buf = Vec::new();
        put_le32(&mut buf, 1);
        put_le32(&mut buf, 1);
        buf.push(b'X');
        put_le32(&mut buf, 1);
        put_le32(&mut buf, 99); // way past types.len()
        let types: [Type<'static>; 0] = [];
        let mut r = Reader::new(&buf);
        let err = parse_block(&mut r, &types).unwrap_err();
        assert!(matches!(err, Error::TypeIndexOutOfRange { .. }));
    }
}
