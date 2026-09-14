//! Var-table walker - `LoadVars` in
//! `uPSRuntime.pas:2936-2989`.
//!
//! Each `VarCount` slot is a `TPSVar = packed record TypeNo:
//! Cardinal; Flags: Byte end;` (5 bytes,
//! `uPSRuntime.pas:1227-1230`) optionally followed by a 4-byte-
//! prefixed export name when `Flags & 1` is set.

use crate::{error::Error, reader::Reader};

const FLAG_EXPORTED: u8 = 0x01;

/// One entry in the global-variable table.
#[derive(Clone, Debug)]
pub struct Var<'a> {
    /// Index into the type table.
    pub type_no: u32,
    /// Raw flag byte (bit 0 = exported; higher bits are
    /// preserved verbatim for forward compatibility).
    pub flags_raw: u8,
    /// Export name when `Flags & 1` is set.
    pub export_name: Option<&'a [u8]>,
}

const MAX_NAME_LEN: u32 = 0x4000_0000;

/// Parses one var-table entry, advancing `reader`.
pub(crate) fn parse_var<'a>(reader: &mut Reader<'a>, type_count: u32) -> Result<Var<'a>, Error> {
    let type_no = reader.u32_le("var TypeNo")?;
    let flags = reader.u8("var Flags")?;
    if type_no >= type_count {
        return Err(Error::TypeIndexOutOfRange {
            index: type_no,
            count: type_count,
        });
    }
    let export_name = if (flags & FLAG_EXPORTED) != 0 {
        let len = reader.u32_le("var export-name length")?;
        if len > MAX_NAME_LEN {
            return Err(Error::Overflow {
                what: "var export-name length",
            });
        }
        Some(reader.take(len as usize, "var export-name bytes")?)
    } else {
        None
    };
    Ok(Var {
        type_no,
        flags_raw: flags,
        export_name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_le32(out: &mut Vec<u8>, v: u32) {
        out.extend_from_slice(&v.to_le_bytes());
    }

    #[test]
    fn parses_unexported_var() {
        let mut buf = Vec::new();
        put_le32(&mut buf, 7);
        buf.push(0);
        let mut r = Reader::new(&buf);
        let v = parse_var(&mut r, 8).unwrap();
        assert_eq!(v.type_no, 7);
        assert!(v.export_name.is_none());
    }

    #[test]
    fn parses_exported_var() {
        let mut buf = Vec::new();
        put_le32(&mut buf, 0);
        buf.push(1);
        put_le32(&mut buf, 4);
        buf.extend_from_slice(b"name");
        let mut r = Reader::new(&buf);
        let v = parse_var(&mut r, 1).unwrap();
        assert_eq!(v.type_no, 0);
        assert_eq!(v.export_name, Some(&b"name"[..]));
    }

    #[test]
    fn rejects_type_ref_out_of_range() {
        let mut buf = Vec::new();
        put_le32(&mut buf, 99);
        buf.push(0);
        let mut r = Reader::new(&buf);
        let err = parse_var(&mut r, 5).unwrap_err();
        assert!(matches!(
            err,
            Error::TypeIndexOutOfRange {
                index: 99,
                count: 5
            }
        ));
    }
}
